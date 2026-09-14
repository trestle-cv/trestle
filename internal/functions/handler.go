package functions

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/trestle-cv/trestle/internal/adminauth"
	"github.com/trestle-cv/trestle/internal/httperr"
	"github.com/trestle-cv/trestle/internal/jobs"
	"github.com/trestle-cv/trestle/internal/store"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"
)

type Options struct{ Region, AccessKey, SecretKey string }
type Handler struct {
	db      store.Executor
	admin   *adminauth.Handler
	jobs    *jobs.Handler
	options Options
	now     func() time.Time
	client  *http.Client
}
type invocation struct {
	TargetID, Topic, Collection, RecordID, InvocationID string
	Payload                                             any
}

var regionPattern = regexp.MustCompile(`^[a-z]{2}(?:-gov)?-[a-z]+-\d$`)

func New(db any, admin *adminauth.Handler, queue *jobs.Handler, options Options) *Handler {
	h := &Handler{db: store.Adapt(db), admin: admin, jobs: queue, options: options, now: time.Now, client: &http.Client{Timeout: 15 * time.Second}}
	queue.Register("aws-lambda", h.execute)
	return h
}
func (h *Handler) Dispatch(ctx context.Context, tx store.Transaction, topic, collection, recordID string, payload any) error {
	rows, err := tx.QueryContext(ctx, "SELECT id,topics FROM _trestle_functions WHERE enabled=?", h.db.Dialect().Boolean(true))
	if err != nil {
		return err
	}
	defer rows.Close()
	for rows.Next() {
		var id, topics string
		rows.Scan(&id, &topics)
		if !contains(strings.Split(topics, ","), topic) {
			continue
		}
		_, _, err = h.jobs.Enqueue(ctx, tx, "aws-lambda", invocation{TargetID: id, Topic: topic, Collection: collection, RecordID: recordID, Payload: payload, InvocationID: "inv_" + token(12)}, "")
		if err != nil {
			return err
		}
	}
	return rows.Err()
}
func (h *Handler) execute(ctx context.Context, raw json.RawMessage) error {
	if h.options.AccessKey == "" || h.options.SecretKey == "" {
		return errors.New("AWS credentials unavailable")
	}
	var in invocation
	if json.Unmarshal(raw, &in) != nil {
		return errors.New("invalid invocation")
	}
	var target, region, scopes string
	var enabledRaw any
	if h.db.QueryRowContext(ctx, "SELECT target,region,callback_scopes,enabled FROM _trestle_functions WHERE id=?", in.TargetID).Scan(&target, &region, &scopes, &enabledRaw) != nil {
		return errors.New("function unavailable")
	}
	enabled, decodeErr := h.db.Dialect().DecodeBoolean(enabledRaw)
	if decodeErr != nil || !enabled {
		return errors.New("function unavailable")
	}
	if validateTarget(target, region) != nil {
		return errors.New("function target refused")
	}
	body, _ := json.Marshal(map[string]any{"version": "1", "id": in.InvocationID, "topic": in.Topic, "collection": in.Collection, "recordId": in.RecordID, "payload": in.Payload, "callbackScopes": split(scopes)})
	endpoint := "https://lambda." + region + ".amazonaws.com/2015-03-31/functions/" + url.PathEscape(target) + "/invocations"
	request, _ := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(body))
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("X-Amz-Invocation-Type", "Event")
	h.sign(request, body, region, h.now().UTC())
	response, err := h.client.Do(request)
	if err != nil {
		return err
	}
	defer response.Body.Close()
	io.Copy(io.Discard, io.LimitReader(response.Body, 64<<10))
	if response.StatusCode != 202 {
		return fmt.Errorf("lambda acceptance status %d", response.StatusCode)
	}
	return nil
}
func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	mutation := r.Method != http.MethodGet
	if _, ok := h.admin.Authorize(r, mutation); !ok {
		http.Error(w, "forbidden", 403)
		return
	}
	id := strings.TrimPrefix(r.URL.Path, "/admin/v1/functions/")
	switch {
	case r.Method == http.MethodGet && r.URL.Path == "/admin/v1/functions":
		h.list(w, r)
	case r.Method == http.MethodPost && r.URL.Path == "/admin/v1/functions":
		h.create(w, r)
	case r.Method == http.MethodPost && id != "":
		h.action(w, r, id)
	default:
		http.NotFound(w, r)
	}
}
func (h *Handler) create(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Name, Target, Region   string
		Topics, CallbackScopes []string
	}
	if json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20)).Decode(&in) != nil || in.Name == "" || len(in.Topics) == 0 || validateTarget(in.Target, in.Region) != nil {
		http.Error(w, "invalid function", 422)
		return
	}
	id := "fn_" + token(12)
	now := h.now().UTC().Format(time.RFC3339Nano)
	_, err := h.db.ExecContext(r.Context(), "INSERT INTO _trestle_functions(id,name,provider,target,region,topics,callback_scopes,created_at,updated_at) VALUES(?,?,'aws-lambda',?,?,?,?,?,?)", id, in.Name, in.Target, in.Region, strings.Join(in.Topics, ","), strings.Join(in.CallbackScopes, ","), now, now)
	if err != nil {
		http.Error(w, "create failed", 409)
		return
	}
	writeJSON(w, 201, map[string]string{"id": id})
}
func (h *Handler) list(w http.ResponseWriter, r *http.Request) {
	rows, _ := h.db.QueryContext(r.Context(), "SELECT id,name,provider,target,region,topics,callback_scopes,enabled,created_at,updated_at FROM _trestle_functions ORDER BY created_at DESC")
	defer rows.Close()
	items := []map[string]any{}
	dialect := h.db.Dialect()
	for rows.Next() {
		var id, name, provider, target, region, topics, scopes, created, updated string
		var enabledRaw any
		rows.Scan(&id, &name, &provider, &target, &region, &topics, &scopes, &enabledRaw, &created, &updated)
		enabled, _ := dialect.DecodeBoolean(enabledRaw)
		items = append(items, map[string]any{"id": id, "name": name, "provider": provider, "target": target, "region": region, "topics": split(topics), "callbackScopes": split(scopes), "enabled": enabled, "createdAt": created, "updatedAt": updated})
	}
	writeJSON(w, 200, map[string]any{"items": items, "credentialsConfigured": h.options.AccessKey != "" && h.options.SecretKey != ""})
}
func (h *Handler) action(w http.ResponseWriter, r *http.Request, id string) {
	var in struct{ Action string }
	json.NewDecoder(r.Body).Decode(&in)
	if in.Action != "enable" && in.Action != "disable" {
		http.Error(w, "invalid action", 400)
		return
	}
	result, err := h.db.ExecContext(r.Context(), "UPDATE _trestle_functions SET enabled=?,updated_at=? WHERE id=?", h.db.Dialect().Boolean(in.Action == "enable"), h.now().UTC().Format(time.RFC3339Nano), id)
	if err != nil {
		writeError(w, 500, "internal_error", "The request could not be completed.")
		return
	}
	if n, _ := result.RowsAffected(); n == 0 {
		writeError(w, 404, "function_not_found", "The function was not found.")
		return
	}
	w.WriteHeader(204)
}
func validateTarget(target, region string) error {
	if !regionPattern.MatchString(region) {
		return errors.New("invalid region")
	}
	parts := strings.Split(target, ":")
	if len(parts) < 7 || parts[0] != "arn" || parts[2] != "lambda" || parts[3] != region || parts[5] != "function" {
		return errors.New("invalid Lambda ARN")
	}
	return nil
}
func (h *Handler) sign(request *http.Request, body []byte, region string, now time.Time) {
	sum := sha256.Sum256(body)
	payload := hex.EncodeToString(sum[:])
	stamp := now.Format("20060102T150405Z")
	date := now.Format("20060102")
	request.Header.Set("X-Amz-Date", stamp)
	request.Header.Set("X-Amz-Content-Sha256", payload)
	headers := "content-type:" + request.Header.Get("Content-Type") + "\n" + "host:" + request.URL.Host + "\n" + "x-amz-content-sha256:" + payload + "\n" + "x-amz-date:" + stamp + "\n" + "x-amz-invocation-type:Event\n"
	signed := "content-type;host;x-amz-content-sha256;x-amz-date;x-amz-invocation-type"
	canonical := request.Method + "\n" + request.URL.EscapedPath() + "\n\n" + headers + "\n" + signed + "\n" + payload
	hash := sha256.Sum256([]byte(canonical))
	scope := date + "/" + region + "/lambda/aws4_request"
	toSign := "AWS4-HMAC-SHA256\n" + stamp + "\n" + scope + "\n" + hex.EncodeToString(hash[:])
	key := mac(mac(mac(mac([]byte("AWS4"+h.options.SecretKey), date), region), "lambda"), "aws4_request")
	signature := hex.EncodeToString(mac(key, toSign))
	request.Header.Set("Authorization", "AWS4-HMAC-SHA256 Credential="+h.options.AccessKey+"/"+scope+", SignedHeaders="+signed+", Signature="+signature)
}
func mac(key []byte, value string) []byte {
	h := hmac.New(sha256.New, key)
	h.Write([]byte(value))
	return h.Sum(nil)
}
func contains(values []string, want string) bool {
	for _, v := range values {
		if strings.TrimSpace(v) == want {
			return true
		}
	}
	return false
}
func split(v string) []string {
	if strings.TrimSpace(v) == "" {
		return []string{}
	}
	return strings.Split(v, ",")
}
func token(n int) string {
	b := make([]byte, n)
	rand.Read(b)
	return base64.RawURLEncoding.EncodeToString(b)
}
func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}
func writeError(w http.ResponseWriter, status int, code, message string) {
	writeJSON(w, status, httperr.New(code, message, w.Header().Get("X-Request-ID")))
}
