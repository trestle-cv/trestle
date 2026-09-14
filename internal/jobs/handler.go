package jobs

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"github.com/trestle-cv/trestle/internal/adminauth"
	"github.com/trestle-cv/trestle/internal/httperr"
	"github.com/trestle-cv/trestle/internal/store"
	"net/http"
	"strings"
	"sync"
	"time"
)

type Executor func(context.Context, json.RawMessage) error
type Handler struct {
	db        store.Executor
	admin     *adminauth.Handler
	now       func() time.Time
	mu        sync.RWMutex
	executors map[string]Executor
}
type Job struct {
	ID          string          `json:"id"`
	Kind        string          `json:"kind"`
	Payload     json.RawMessage `json:"payload"`
	Status      string          `json:"status"`
	Attempts    int             `json:"attempts"`
	MaxAttempts int             `json:"maxAttempts"`
	AvailableAt string          `json:"availableAt"`
	LeaseUntil  string          `json:"leaseUntil,omitempty"`
	LastError   string          `json:"lastError,omitempty"`
	CreatedAt   string          `json:"createdAt"`
	UpdatedAt   string          `json:"updatedAt"`
}

func New(db any, admin *adminauth.Handler) *Handler {
	return &Handler{db: store.Adapt(db), admin: admin, now: time.Now, executors: map[string]Executor{"noop": func(context.Context, json.RawMessage) error { return nil }}}
}
func (h *Handler) Register(kind string, executor Executor) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.executors[kind] = executor
}
func (h *Handler) Enqueue(ctx context.Context, tx store.Transaction, kind string, payload any, idempotency string) (string, bool, error) {
	encoded, err := json.Marshal(payload)
	if err != nil {
		return "", false, err
	}
	id := "job_" + token(15)
	now := h.now().UTC().Format(time.RFC3339Nano)
	result, err := tx.ExecContext(ctx, "INSERT INTO _trestle_jobs(id,kind,payload_json,status,available_at,idempotency_key,created_at,updated_at) VALUES(?,?,?,'pending',?,?,?,?) ON CONFLICT(idempotency_key) DO NOTHING", id, kind, string(encoded), now, null(idempotency), now, now)
	if err != nil {
		return "", false, err
	}
	n, _ := result.RowsAffected()
	if n == 1 {
		return id, true, nil
	}
	if idempotency == "" {
		return "", false, errors.New("job could not be enqueued")
	}
	// The idempotency key already produced a job; return the existing job so a
	// retried submission never fabricates a fresh id that does not exist.
	var existing string
	if err = tx.QueryRowContext(ctx, "SELECT id FROM _trestle_jobs WHERE idempotency_key=?", idempotency).Scan(&existing); err != nil {
		return "", false, errors.New("existing idempotent job unavailable")
	}
	return existing, false, nil
}
func (h *Handler) Start(ctx context.Context) {
	go func() {
		ticker := time.NewTicker(500 * time.Millisecond)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				h.runOne(ctx)
			}
		}
	}()
}
func (h *Handler) runOne(ctx context.Context) {
	now := h.now().UTC()
	h.db.ExecContext(ctx, "UPDATE _trestle_jobs SET status='pending',lease_until=NULL,updated_at=? WHERE status='running' AND lease_until<?", now.Format(time.RFC3339Nano), now.Format(time.RFC3339Nano))
	tx, err := h.db.BeginTx(ctx, nil)
	if err != nil {
		return
	}
	defer tx.Rollback()
	claim := "SELECT id,kind,payload_json FROM _trestle_jobs WHERE status='pending' AND available_at<=? ORDER BY available_at,id LIMIT 1"
	if h.db.Dialect().Provider() == store.Postgres {
		// PostgreSQL MVCC needs deliberate claiming: lock exactly one pending
		// row and skip rows already locked by other workers so each job is
		// claimed by exactly one worker without wasted re-reads.
		claim += " FOR UPDATE SKIP LOCKED"
	}
	var id, kind, payload string
	err = tx.QueryRowContext(ctx, claim, now.Format(time.RFC3339Nano)).Scan(&id, &kind, &payload)
	if err != nil {
		return
	}
	lease := now.Add(30 * time.Second).Format(time.RFC3339Nano)
	result, _ := tx.ExecContext(ctx, "UPDATE _trestle_jobs SET status='running',attempts=attempts+1,lease_until=?,updated_at=? WHERE id=? AND status='pending'", lease, now.Format(time.RFC3339Nano), id)
	n, _ := result.RowsAffected()
	if n != 1 || tx.Commit() != nil {
		return
	}
	h.mu.RLock()
	executor := h.executors[kind]
	h.mu.RUnlock()
	runErr := errors.New("no executor registered")
	if executor != nil {
		runErr = executor(ctx, json.RawMessage(payload))
	}
	h.finish(ctx, id, runErr)
}
func (h *Handler) finish(ctx context.Context, id string, runErr error) {
	now := h.now().UTC()
	if runErr == nil {
		h.db.ExecContext(ctx, "UPDATE _trestle_jobs SET status='succeeded',lease_until=NULL,last_error=NULL,updated_at=? WHERE id=?", now.Format(time.RFC3339Nano), id)
		return
	}
	var attempts, max int
	h.db.QueryRowContext(ctx, "SELECT attempts,max_attempts FROM _trestle_jobs WHERE id=?", id).Scan(&attempts, &max)
	status := "pending"
	if attempts >= max {
		status = "dead"
	}
	delay := time.Duration(1<<min(attempts, 8)) * time.Second
	message := runErr.Error()
	if len(message) > 500 {
		message = message[:500]
	}
	h.db.ExecContext(ctx, "UPDATE _trestle_jobs SET status=?,available_at=?,lease_until=NULL,last_error=?,updated_at=? WHERE id=?", status, now.Add(delay).Format(time.RFC3339Nano), message, now.Format(time.RFC3339Nano), id)
}
func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	mutation := r.Method != http.MethodGet
	if _, ok := h.admin.Authorize(r, mutation); !ok {
		http.Error(w, "forbidden", 403)
		return
	}
	id := strings.TrimPrefix(r.URL.Path, "/admin/v1/jobs/")
	switch {
	case r.Method == http.MethodGet && r.URL.Path == "/admin/v1/jobs":
		h.list(w, r)
	case r.Method == http.MethodPost && r.URL.Path == "/admin/v1/jobs":
		var in struct {
			Kind           string `json:"kind"`
			Payload        any    `json:"payload"`
			IdempotencyKey string `json:"idempotencyKey"`
		}
		if json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20)).Decode(&in) != nil || in.Kind == "" {
			http.Error(w, "invalid job", 400)
			return
		}
		tx, err := h.db.BeginTx(r.Context(), nil)
		if err != nil {
			writeError(w, 500, "internal_error", "The request could not be completed.")
			return
		}
		defer tx.Rollback()
		id, created, err := h.Enqueue(r.Context(), tx, in.Kind, in.Payload, in.IdempotencyKey)
		if err != nil {
			writeError(w, 409, "enqueue_failed", "The job could not be enqueued.")
			return
		}
		if err := tx.Commit(); err != nil {
			writeError(w, 500, "internal_error", "The request could not be completed.")
			return
		}
		status := 201
		if !created {
			status = 200
		}
		writeJSON(w, status, map[string]string{"id": id})
	case r.Method == http.MethodPost && id != "":
		h.action(w, r, id)
	default:
		http.NotFound(w, r)
	}
}
func (h *Handler) list(w http.ResponseWriter, r *http.Request) {
	query := "SELECT id,kind,payload_json,status,attempts,max_attempts,available_at,coalesce(lease_until,''),coalesce(last_error,''),created_at,updated_at FROM _trestle_jobs"
	args := []any{}
	if status := r.URL.Query().Get("status"); status != "" {
		query += " WHERE status=?"
		args = append(args, status)
	}
	query += " ORDER BY created_at DESC LIMIT 200"
	rows, err := h.db.QueryContext(r.Context(), query, args...)
	if err != nil {
		writeError(w, 500, "internal_error", "The request could not be completed.")
		return
	}
	defer rows.Close()
	items := []Job{}
	for rows.Next() {
		var j Job
		var payload string
		if err := rows.Scan(&j.ID, &j.Kind, &payload, &j.Status, &j.Attempts, &j.MaxAttempts, &j.AvailableAt, &j.LeaseUntil, &j.LastError, &j.CreatedAt, &j.UpdatedAt); err != nil {
			writeError(w, 500, "internal_error", "The request could not be completed.")
			return
		}
		j.Payload = json.RawMessage(payload)
		items = append(items, j)
	}
	if err := rows.Err(); err != nil {
		writeError(w, 500, "internal_error", "The request could not be completed.")
		return
	}
	writeJSON(w, 200, map[string]any{"items": items})
}
func (h *Handler) action(w http.ResponseWriter, r *http.Request, id string) {
	var in struct {
		Action string `json:"action"`
	}
	json.NewDecoder(r.Body).Decode(&in)
	now := h.now().UTC().Format(time.RFC3339Nano)
	var err error
	switch in.Action {
	case "cancel":
		_, err = h.db.ExecContext(r.Context(), "UPDATE _trestle_jobs SET status='cancelled',lease_until=NULL,updated_at=? WHERE id=? AND status IN ('pending','running')", now, id)
	case "retry":
		_, err = h.db.ExecContext(r.Context(), "UPDATE _trestle_jobs SET status='pending',attempts=0,available_at=?,lease_until=NULL,last_error=NULL,updated_at=? WHERE id=? AND status IN ('dead','cancelled')", now, now, id)
	default:
		http.Error(w, "invalid action", 400)
		return
	}
	if err != nil {
		writeError(w, 500, "internal_error", "The request could not be completed.")
		return
	}
	w.WriteHeader(204)
}
func token(n int) string {
	b := make([]byte, n)
	rand.Read(b)
	return base64.RawURLEncoding.EncodeToString(b)
}
func null(v string) any {
	if v == "" {
		return nil
	}
	return v
}
func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}
func writeError(w http.ResponseWriter, status int, code, message string) {
	writeJSON(w, status, httperr.New(code, message, w.Header().Get("X-Request-ID")))
}
