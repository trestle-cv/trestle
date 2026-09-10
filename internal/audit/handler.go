package audit

import (
	"context"
	"encoding/json"
	"github.com/trestle-cv/trestle/internal/adminauth"
	"github.com/trestle-cv/trestle/internal/store"
	"net/http"
	"strconv"
	"strings"
	"time"
)

type Handler struct {
	db       store.Executor
	admin    *adminauth.Handler
	now      func() time.Time
	provider string
}
type Fact struct {
	ID         int64  `json:"id"`
	OccurredAt string `json:"occurredAt"`
	ActorKind  string `json:"actorKind"`
	ActorID    string `json:"actorId,omitempty"`
	Action     string `json:"action"`
	Target     string `json:"target,omitempty"`
	Outcome    string `json:"outcome"`
	RequestID  string `json:"requestId,omitempty"`
	Details    any    `json:"details"`
}

func New(db any, admin *adminauth.Handler, provider ...string) *Handler {
	name := "sqlite"
	if len(provider) > 0 && provider[0] != "" {
		name = provider[0]
	}
	return &Handler{db: store.Adapt(db), admin: admin, now: time.Now, provider: name}
}
func (h *Handler) Emit(ctx context.Context, tx store.Transaction, actorKind, actorID, action, target, outcome, requestID string, details any) error {
	encoded, _ := json.Marshal(redact(details))
	_, err := tx.ExecContext(ctx, "INSERT INTO _trestle_audit(occurred_at,actor_kind,actor_id,action,target,outcome,request_id,details_json) VALUES(?,?,?,?,?,?,?,?)", h.now().UTC().Format(time.RFC3339Nano), actorKind, null(actorID), action, null(target), outcome, null(requestID), string(encoded))
	return err
}
func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if _, ok := h.admin.AuthorizeCapability(r, false, "audit.read"); !ok {
		http.Error(w, "forbidden", 403)
		return
	}
	switch r.URL.Path {
	case "/admin/v1/audit":
		h.list(w, r)
	case "/admin/v1/operations":
		h.operations(w, r)
	default:
		http.NotFound(w, r)
	}
}
func (h *Handler) list(w http.ResponseWriter, r *http.Request) {
	after, _ := strconv.ParseInt(r.URL.Query().Get("after"), 10, 64)
	query := "SELECT id,occurred_at,actor_kind,coalesce(actor_id,''),action,coalesce(target,''),outcome,coalesce(request_id,''),details_json FROM _trestle_audit WHERE id>?"
	args := []any{after}
	if action := strings.TrimSpace(r.URL.Query().Get("action")); action != "" {
		query += " AND action=?"
		args = append(args, action)
	}
	query += " ORDER BY id DESC LIMIT 200"
	rows, err := h.db.QueryContext(r.Context(), query, args...)
	if err != nil {
		http.Error(w, "query failed", 500)
		return
	}
	defer rows.Close()
	items := []Fact{}
	for rows.Next() {
		var f Fact
		var detail string
		rows.Scan(&f.ID, &f.OccurredAt, &f.ActorKind, &f.ActorID, &f.Action, &f.Target, &f.Outcome, &f.RequestID, &detail)
		json.Unmarshal([]byte(detail), &f.Details)
		items = append(items, f)
	}
	writeJSON(w, map[string]any{"items": items})
}
func (h *Handler) operations(w http.ResponseWriter, r *http.Request) {
	counts := map[string]int64{}
	for name, table := range map[string]string{"collections": "_trestle_collections", "files": "_trestle_files", "sessions": "_trestle_admin_sessions", "events": "_trestle_events"} {
		var count int64
		h.db.QueryRowContext(r.Context(), "SELECT count(*) FROM "+table).Scan(&count)
		counts[name] = count
	}
	var databaseBytes any
	if h.provider == "sqlite" {
		var pageCount, pageSize int64
		h.db.QueryRowContext(r.Context(), "PRAGMA page_count").Scan(&pageCount)
		h.db.QueryRowContext(r.Context(), "PRAGMA page_size").Scan(&pageSize)
		databaseBytes = pageCount * pageSize
	} else if h.provider == "postgres" {
		var size int64
		h.db.QueryRowContext(r.Context(), "SELECT pg_database_size(current_database())").Scan(&size)
		databaseBytes = size
	}
	writeJSON(w, map[string]any{"provider": h.provider, "counts": counts, "databaseBytes": databaseBytes, "auditBoundary": "append-oriented, not tamper-proof"})
}
func redact(value any) any {
	object, ok := value.(map[string]any)
	if !ok {
		return value
	}
	clean := map[string]any{}
	for key, item := range object {
		lower := strings.ToLower(key)
		if strings.Contains(lower, "secret") || strings.Contains(lower, "password") || strings.Contains(lower, "token") {
			clean[key] = "[redacted]"
		} else {
			clean[key] = item
		}
	}
	return clean
}
func null(v string) any {
	if v == "" {
		return nil
	}
	return v
}
func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(v)
}
