package webhooks

import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/gantry-tools/gantry-core/replication"
	"github.com/trestle-cv/trestle/internal/adminauth"
	"github.com/trestle-cv/trestle/internal/httperr"
	"github.com/trestle-cv/trestle/internal/jobs"
	"github.com/trestle-cv/trestle/internal/replpayload"
	"github.com/trestle-cv/trestle/internal/store"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// WebhookAuthority routes webhook definition mutations through the replicated
// authority in clustered mode. It is nil in standalone mode.
type WebhookAuthority interface {
	PutWebhook(context.Context, replpayload.WebhookPayload) (*replication.ApplyResult, error)
	DeleteWebhook(context.Context, string) (*replication.ApplyResult, error)
}

type Handler struct {
	db        store.Executor
	admin     *adminauth.Handler
	jobs      *jobs.Handler
	aead      cipher.AEAD
	now       func() time.Time
	client    *http.Client
	authority WebhookAuthority
}
type target struct {
	ID        string   `json:"id"`
	Name      string   `json:"name"`
	URL       string   `json:"url"`
	Topics    []string `json:"topics"`
	Enabled   bool     `json:"enabled"`
	CreatedAt string   `json:"createdAt"`
	UpdatedAt string   `json:"updatedAt"`
}
type delivery struct {
	TargetID   string `json:"targetId"`
	Topic      string `json:"topic"`
	Collection string `json:"collection"`
	RecordID   string `json:"recordId"`
	Payload    any    `json:"payload"`
	DeliveryID string `json:"deliveryId"`
}

func New(db any, admin *adminauth.Handler, queue *jobs.Handler, dataDir string) (*Handler, error) {
	key, err := loadKey(filepath.Join(dataDir, "webhook.key"))
	if err != nil {
		return nil, err
	}
	block, _ := aes.NewCipher(key)
	aead, _ := cipher.NewGCM(block)
	h := &Handler{db: store.Adapt(db), admin: admin, jobs: queue, aead: aead, now: time.Now, client: &http.Client{Timeout: 12 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return errors.New("redirects refused") }}}
	queue.Register("webhook", h.execute)
	return h, nil
}
func (h *Handler) SetMutationAuthority(a WebhookAuthority) { h.authority = a }
func (h *Handler) Dispatch(ctx context.Context, tx store.Transaction, topic, collection, recordID string, payload any) error {
	rows, err := tx.QueryContext(ctx, "SELECT id,topics FROM _trestle_webhooks WHERE enabled=?", h.db.Dialect().Boolean(true))
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
		_, _, err = h.jobs.Enqueue(ctx, tx, "webhook", delivery{TargetID: id, Topic: topic, Collection: collection, RecordID: recordID, Payload: payload, DeliveryID: "del_" + token(12)}, "")
		if err != nil {
			return err
		}
	}
	return rows.Err()
}
func (h *Handler) execute(ctx context.Context, raw json.RawMessage) error {
	var d delivery
	if json.Unmarshal(raw, &d) != nil {
		return errors.New("invalid webhook payload")
	}
	var endpoint string
	var cipherText []byte
	var enabledRaw any
	if err := h.db.QueryRowContext(ctx, "SELECT url,secret_cipher,enabled FROM _trestle_webhooks WHERE id=?", d.TargetID).Scan(&endpoint, &cipherText, &enabledRaw); err != nil {
		return errors.New("webhook unavailable")
	}
	enabled, decodeErr := h.db.Dialect().DecodeBoolean(enabledRaw)
	if decodeErr != nil || !enabled {
		return errors.New("webhook unavailable")
	}
	if err := safeDestination(endpoint); err != nil {
		return err
	}
	secret, err := h.decrypt(cipherText)
	if err != nil {
		return err
	}
	body, _ := json.Marshal(map[string]any{"version": "1", "id": d.DeliveryID, "topic": d.Topic, "collection": d.Collection, "recordId": d.RecordID, "payload": d.Payload})
	stamp := strconvTime(h.now())
	request, _ := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(body))
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Trestle-Delivery", d.DeliveryID)
	request.Header.Set("Trestle-Timestamp", stamp)
	request.Header.Set("Trestle-Signature", signWebhook(secret, stamp, body))
	response, err := h.client.Do(request)
	if err != nil {
		return err
	}
	defer response.Body.Close()
	io.Copy(io.Discard, io.LimitReader(response.Body, 64<<10))
	if response.StatusCode/100 != 2 {
		return fmt.Errorf("webhook status %d", response.StatusCode)
	}
	return nil
}
func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	mutation := r.Method != http.MethodGet
	if _, ok := h.admin.Authorize(r, mutation); !ok {
		http.Error(w, "forbidden", 403)
		return
	}
	id := strings.TrimPrefix(r.URL.Path, "/admin/v1/webhooks/")
	switch {
	case r.Method == http.MethodGet && r.URL.Path == "/admin/v1/webhooks":
		h.list(w, r)
	case r.Method == http.MethodPost && r.URL.Path == "/admin/v1/webhooks":
		h.create(w, r)
	case r.Method == http.MethodPost && id != "":
		h.action(w, r, id)
	default:
		http.NotFound(w, r)
	}
}
func (h *Handler) create(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Name, URL string
		Topics    []string
	}
	decodeErr := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20)).Decode(&in)
	_, targetErr := validateTargetURL(in.URL)
	if decodeErr != nil || in.Name == "" || len(in.Topics) == 0 || targetErr != nil {
		http.Error(w, "invalid webhook", 422)
		return
	}
	secret := []byte(token(32))
	encrypted, _ := h.encrypt(secret)
	id := "wh_" + token(12)
	now := h.now().UTC().Format(time.RFC3339Nano)
	if h.authority != nil {
		wp := replpayload.WebhookPayload{ID: id, Name: in.Name, URL: in.URL, Topics: strings.Join(in.Topics, ","), SecretCipher: encrypted, Enabled: true, CreatedAt: now, UpdatedAt: now}
		if _, err := h.authority.PutWebhook(r.Context(), wp); err == nil {
			writeJSON(w, 201, map[string]any{"id": id, "secret": string(secret), "warning": "copy this signing secret now"})
			return
		} else if !errors.Is(err, replication.ErrStandalone) {
			writeError(w, 503, "replication_unavailable", err.Error())
			return
		}
	}
	_, err := h.db.ExecContext(r.Context(), "INSERT INTO _trestle_webhooks(id,name,url,topics,secret_cipher,created_at,updated_at) VALUES(?,?,?,?,?,?,?)", id, in.Name, in.URL, strings.Join(in.Topics, ","), encrypted, now, now)
	if err != nil {
		http.Error(w, "create failed", 409)
		return
	}
	writeJSON(w, 201, map[string]any{"id": id, "secret": string(secret), "warning": "copy this signing secret now"})
}
func (h *Handler) list(w http.ResponseWriter, r *http.Request) {
	rows, _ := h.db.QueryContext(r.Context(), "SELECT id,name,url,topics,enabled,created_at,updated_at FROM _trestle_webhooks ORDER BY created_at DESC")
	defer rows.Close()
	dialect := h.db.Dialect()
	items := []target{}
	for rows.Next() {
		var item target
		var topics string
		var enabledRaw any
		rows.Scan(&item.ID, &item.Name, &item.URL, &topics, &enabledRaw, &item.CreatedAt, &item.UpdatedAt)
		item.Topics = strings.Split(topics, ",")
		item.Enabled, _ = dialect.DecodeBoolean(enabledRaw)
		items = append(items, item)
	}
	writeJSON(w, 200, map[string]any{"items": items})
}
func (h *Handler) action(w http.ResponseWriter, r *http.Request, id string) {
	var in struct{ Action string }
	json.NewDecoder(r.Body).Decode(&in)
	if in.Action != "enable" && in.Action != "disable" {
		http.Error(w, "invalid action", 400)
		return
	}
	if h.authority != nil {
		var wp replpayload.WebhookPayload
		var enabledRaw any
		err := h.db.QueryRowContext(r.Context(), "SELECT id,name,url,topics,secret_cipher,enabled,created_at,updated_at FROM _trestle_webhooks WHERE id=?", id).Scan(&wp.ID, &wp.Name, &wp.URL, &wp.Topics, &wp.SecretCipher, &enabledRaw, &wp.CreatedAt, &wp.UpdatedAt)
		if errors.Is(err, sql.ErrNoRows) {
			writeError(w, 404, "webhook_not_found", "The webhook was not found.")
			return
		} else if err != nil {
			writeError(w, 500, "internal_error", "The request could not be completed.")
			return
		}
		wp.Enabled = in.Action == "enable"
		wp.UpdatedAt = h.now().UTC().Format(time.RFC3339Nano)
		if _, err := h.authority.PutWebhook(r.Context(), wp); err == nil {
			w.WriteHeader(204)
			return
		} else if !errors.Is(err, replication.ErrStandalone) {
			writeError(w, 503, "replication_unavailable", err.Error())
			return
		}
	}
	result, err := h.db.ExecContext(r.Context(), "UPDATE _trestle_webhooks SET enabled=?,updated_at=? WHERE id=?", h.db.Dialect().Boolean(in.Action == "enable"), h.now().UTC().Format(time.RFC3339Nano), id)
	if err != nil {
		writeError(w, 500, "internal_error", "The request could not be completed.")
		return
	}
	if n, _ := result.RowsAffected(); n == 0 {
		writeError(w, 404, "webhook_not_found", "The webhook was not found.")
		return
	}
	w.WriteHeader(204)
}
func (h *Handler) encrypt(value []byte) ([]byte, error) {
	nonce := make([]byte, h.aead.NonceSize())
	rand.Read(nonce)
	return h.aead.Seal(nonce, nonce, value, nil), nil
}
func (h *Handler) decrypt(value []byte) ([]byte, error) {
	n := h.aead.NonceSize()
	if len(value) < n {
		return nil, errors.New("invalid secret")
	}
	return h.aead.Open(nil, value[:n], value[n:], nil)
}
func safeDestination(raw string) error {
	u, err := validateTargetURL(raw)
	if err != nil {
		return err
	}
	ips, err := net.LookupIP(u.Hostname())
	if err != nil {
		return err
	}
	for _, ip := range ips {
		if ip.IsLoopback() || ip.IsPrivate() || ip.IsUnspecified() || ip.IsLinkLocalUnicast() {
			return errors.New("private webhook destination refused")
		}
	}
	return nil
}

func validateTargetURL(raw string) (*url.URL, error) {
	u, err := url.Parse(raw)
	if err != nil || u.Scheme != "https" || u.User != nil || u.Hostname() == "" {
		return nil, errors.New("webhook URL must use HTTPS")
	}
	return u, nil
}
func loadKey(path string) ([]byte, error) {
	if value, err := os.ReadFile(path); err == nil && len(value) == 32 {
		return value, nil
	}
	value := make([]byte, 32)
	rand.Read(value)
	if err := os.WriteFile(path, value, 0600); err != nil {
		return nil, err
	}
	return value, nil
}

// KeyFingerprint returns the SHA-256 fingerprint of the node's webhook.key, or
// an error when the key file is absent. The fingerprint is a non-secret
// identity used to enforce cluster-uniform webhook decrypt material across a
// replicated cluster: only the fingerprint crosses the network or enters
// replication capabilities, never the key itself. An absent key means the node
// has no webhook secret material and advertises no fingerprint constraint.
func KeyFingerprint(dataDir string) (string, error) {
	raw, err := os.ReadFile(filepath.Join(dataDir, "webhook.key"))
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(raw)
	return hex.EncodeToString(sum[:]), nil
}
func contains(values []string, want string) bool {
	for _, v := range values {
		if strings.TrimSpace(v) == want {
			return true
		}
	}
	return false
}
func token(n int) string {
	b := make([]byte, n)
	rand.Read(b)
	return base64.RawURLEncoding.EncodeToString(b)
}
func strconvTime(t time.Time) string { return fmt.Sprintf("%d", t.Unix()) }
func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}
func writeError(w http.ResponseWriter, status int, code, message string) {
	writeJSON(w, status, httperr.New(code, message, w.Header().Get("X-Request-ID")))
}

// signWebhook signs a delivery body with the webhook secret using the
// documented envelope scheme: SHA-256 HMAC over "timestamp.body", prefixed
// with "v1=". Receivers verify the Trestle-Timestamp and Trestle-Signature
// headers against the same scheme.
func signWebhook(secret []byte, stamp string, body []byte) string {
	mac := hmac.New(sha256.New, secret)
	mac.Write([]byte(stamp + "." + string(body)))
	return "v1=" + hex.EncodeToString(mac.Sum(nil))
}
