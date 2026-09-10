package adminauth

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/mail"
	"strings"
	"sync"
	"time"

	coreauth "github.com/gantry-tools/gantry-core/auth"
	"github.com/trestle-cv/trestle/internal/httperr"
	"github.com/trestle-cv/trestle/internal/requestmeta"
	"github.com/trestle-cv/trestle/internal/store"
)

const cookieName = "trestle_admin_session"

type Handler struct {
	db              store.Executor
	provider        string
	now             func() time.Time
	limiter         *limiter
	passwordLimiter *limiter
	setupGuard      func(context.Context) error
}
type credentials struct {
	Email                         string `json:"email"`
	Password                      string `json:"password"`
	ApplicationRegistrationPolicy string `json:"applicationRegistrationPolicy"`
}
type passwordChange struct {
	CurrentPassword string `json:"currentPassword"`
	NewPassword     string `json:"newPassword"`
	ConfirmPassword string `json:"confirmPassword"`
}
type sessionResponse struct {
	Authenticated bool   `json:"authenticated"`
	AdminID       string `json:"adminId,omitempty"`
	Email         string `json:"email,omitempty"`
	CSRFToken     string `json:"csrfToken,omitempty"`
	Provider      string `json:"provider,omitempty"`
}

type Principal struct {
	AdminID   string
	Email     string
	SessionID string
}

func New(db any, provider ...string) *Handler {
	name := ""
	if len(provider) > 0 {
		name = provider[0]
	}
	return &Handler{db: store.Adapt(db), provider: name, now: time.Now, limiter: newLimiter(10, time.Minute), passwordLimiter: newLimiter(10, time.Minute)}
}

func (h *Handler) SetSetupGuard(guard func(context.Context) error) {
	h.setupGuard = guard
}

func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	switch {
	case r.Method == http.MethodGet && r.URL.Path == "/admin/v1/setup/status":
		h.setupStatus(w, r)
	case r.Method == http.MethodPost && r.URL.Path == "/admin/v1/setup":
		h.setup(w, r)
	case r.Method == http.MethodPost && r.URL.Path == "/admin/v1/session":
		h.login(w, r)
	case r.Method == http.MethodGet && r.URL.Path == "/admin/v1/session":
		h.current(w, r)
	case r.Method == http.MethodDelete && r.URL.Path == "/admin/v1/session":
		h.logout(w, r)
	case r.Method == http.MethodPost && r.URL.Path == "/admin/v1/password":
		h.changePassword(w, r)
	case r.URL.Path == "/admin/v1/manage/users":
		h.manageUsers(w, r)
	case r.URL.Path == "/admin/v1/manage/roles":
		h.manageRoles(w, r)
	default:
		http.NotFound(w, r)
	}
}

func (h *Handler) changePassword(w http.ResponseWriter, r *http.Request) {
	principal, ok := h.Authorize(r, true)
	if !ok {
		writeError(w, 403, "authorization_denied", "Authentication and a valid CSRF token are required.")
		return
	}
	key := principal.AdminID + ":" + clientKey(r)
	if !h.passwordLimiter.Allow(key, h.now()) {
		writeError(w, 429, "rate_limited", "Too many attempts. Try again later.")
		return
	}
	var input passwordChange
	if !decodeJSON(w, r, &input) {
		return
	}
	if input.NewPassword != input.ConfirmPassword {
		writeError(w, 422, "validation_failed", "The new passwords do not match.")
		return
	}
	hash, err := hashPassword(input.NewPassword)
	if err != nil {
		writeError(w, 422, "validation_failed", err.Error())
		return
	}
	tx, err := h.db.BeginTx(r.Context(), nil)
	if err != nil {
		writeError(w, 500, "internal_error", "The request could not be completed.")
		return
	}
	defer tx.Rollback()
	var currentHash string
	if err := tx.QueryRowContext(r.Context(), "SELECT password_hash FROM _trestle_admins WHERE id=?", principal.AdminID).Scan(&currentHash); err != nil || !verifyPassword(currentHash, input.CurrentPassword) {
		writeError(w, 401, "invalid_credentials", "The current password is incorrect.")
		return
	}
	now := h.now().UTC().Format(time.RFC3339Nano)
	if _, err := tx.ExecContext(r.Context(), "UPDATE _trestle_admins SET password_hash=? WHERE id=?", hash, principal.AdminID); err != nil {
		writeError(w, 500, "internal_error", "The request could not be completed.")
		return
	}
	if _, err := tx.ExecContext(r.Context(), "UPDATE _trestle_admin_sessions SET revoked_at=? WHERE admin_id=? AND id<>? AND revoked_at IS NULL", now, principal.AdminID, principal.SessionID); err != nil {
		writeError(w, 500, "internal_error", "The request could not be completed.")
		return
	}
	if err := tx.Commit(); err != nil {
		writeError(w, 500, "internal_error", "The request could not be completed.")
		return
	}
	h.passwordLimiter.Clear(key)
	w.WriteHeader(http.StatusNoContent)
}

func (h *Handler) setupStatus(w http.ResponseWriter, r *http.Request) {
	required, err := h.SetupRequired(r.Context())
	if err != nil {
		writeError(w, 500, "internal_error", "The request could not be completed.")
		return
	}
	writeJSON(w, 200, map[string]bool{"setupRequired": required})
}

func (h *Handler) SetupRequired(ctx context.Context) (bool, error) {
	var count int
	if err := h.db.QueryRowContext(ctx, "SELECT count(*) FROM _trestle_admins").Scan(&count); err != nil {
		return false, err
	}
	return count == 0, nil
}

func (h *Handler) setup(w http.ResponseWriter, r *http.Request) {
	if h.setupGuard != nil {
		if err := h.setupGuard(r.Context()); err != nil {
			writeError(w, 409, "database_restart_required", "Restart Trestle to activate the configured database before creating the administrator.")
			return
		}
	}
	if !sameOrigin(r) {
		writeError(w, 403, "origin_denied", "The request origin is not allowed.")
		return
	}
	var input credentials
	if !decodeJSON(w, r, &input) {
		return
	}
	email, ok := normalizeEmail(input.Email)
	if !ok {
		writeError(w, 422, "validation_failed", "The request could not be applied.")
		return
	}
	hash, err := hashPassword(input.Password)
	if err != nil {
		writeError(w, 422, "validation_failed", err.Error())
		return
	}
	tx, err := h.db.BeginTx(r.Context(), nil)
	if err != nil {
		writeError(w, 500, "internal_error", "The request could not be completed.")
		return
	}
	defer tx.Rollback()
	if h.provider == string(store.Postgres) {
		// PostgreSQL READ COMMITTED does not serialize count-then-insert, so
		// competing setup transactions would both observe zero administrators.
		// A transaction-scoped advisory lock makes exactly one setup winner.
		if _, err := tx.ExecContext(r.Context(), "SELECT pg_advisory_xact_lock(839201347562)"); err != nil {
			writeError(w, 500, "internal_error", "The request could not be completed.")
			return
		}
	}
	var count int
	if err := tx.QueryRowContext(r.Context(), "SELECT count(*) FROM _trestle_admins").Scan(&count); err != nil || count != 0 {
		writeError(w, 409, "setup_complete", "Initial setup has already been completed.")
		return
	}
	id, _ := randomToken(18)
	now := h.now().UTC().Format(time.RFC3339Nano)
	adminID := "adm_" + id
	if _, err := tx.ExecContext(r.Context(), "INSERT INTO _trestle_admins(id,email,password_hash,created_at) VALUES(?,?,?,?)", adminID, email, hash, now); err != nil {
		writeError(w, 409, "setup_complete", "Initial setup has already been completed.")
		return
	}
	if _, err := tx.ExecContext(r.Context(), "INSERT INTO _trestle_admin_roles(admin_id,role_id) VALUES(?,?)", adminID, "administrator"); err != nil {
		writeError(w, 500, "internal_error", "The request could not be completed.")
		return
	}
	// The initial application registration policy is selected atomically with
	// the first administrator. A failed admin insert rolls back the policy and
	// vice versa, so no partially selected policy can exist.
	policy := input.ApplicationRegistrationPolicy
	if policy == "" {
		writeError(w, 422, "registration_policy_required", "Choose an application registration policy.")
		return
	}
	if !validRegistrationPolicy(policy) {
		writeError(w, 422, "invalid_registration_policy", "The application registration policy is invalid.")
		return
	}
	if _, err := tx.ExecContext(r.Context(), "UPDATE _trestle_app_registration_policy SET policy=?,set_at=? WHERE id=1", policy, now); err != nil {
		writeError(w, 500, "internal_error", "The request could not be completed.")
		return
	}
	if err := tx.Commit(); err != nil {
		writeError(w, 409, "setup_complete", "Initial setup has already been completed.")
		return
	}
	h.issueSession(w, r, adminID, email)
}

func (h *Handler) login(w http.ResponseWriter, r *http.Request) {
	if !sameOrigin(r) {
		writeError(w, 403, "origin_denied", "The request origin is not allowed.")
		return
	}
	key := clientKey(r)
	if !h.limiter.Allow(key, h.now()) {
		writeError(w, 429, "rate_limited", "Too many attempts. Try again later.")
		return
	}
	var input credentials
	if !decodeJSON(w, r, &input) {
		return
	}
	email, _ := normalizeEmail(input.Email)
	var id, storedEmail, hash string
	var disabled sql.NullString
	err := h.db.QueryRowContext(r.Context(), "SELECT id,email,password_hash,disabled_at FROM _trestle_admins WHERE email=?", email).Scan(&id, &storedEmail, &hash, &disabled)
	if err != nil || disabled.Valid || !verifyPassword(hash, input.Password) {
		writeError(w, 401, "invalid_credentials", "The email or password is incorrect.")
		return
	}
	h.limiter.Clear(key)
	h.issueSession(w, r, id, storedEmail)
}

func (h *Handler) issueSession(w http.ResponseWriter, r *http.Request, adminID, email string) {
	token, _ := randomToken(32)
	csrf, _ := randomToken(24)
	id, _ := randomToken(18)
	now := h.now().UTC()
	expires := now.Add(12 * time.Hour)
	tokenHash := sha256.Sum256([]byte(token))
	csrfHash := sha256.Sum256([]byte(csrf))
	if _, err := h.db.ExecContext(r.Context(), "INSERT INTO _trestle_admin_sessions(id,admin_id,token_hash,csrf_hash,created_at,expires_at) VALUES(?,?,?,?,?,?)", "ses_"+id, adminID, tokenHash[:], csrfHash[:], now.Format(time.RFC3339Nano), expires.Format(time.RFC3339Nano)); err != nil {
		writeError(w, 500, "internal_error", "The request could not be completed.")
		return
	}
	http.SetCookie(w, &http.Cookie{Name: cookieName, Value: token, Path: "/", HttpOnly: true, Secure: requestmeta.Scheme(r) == "https", SameSite: http.SameSiteStrictMode, Expires: expires, MaxAge: int((12 * time.Hour).Seconds())})
	writeJSON(w, 200, sessionResponse{Authenticated: true, AdminID: adminID, Email: email, CSRFToken: csrf, Provider: h.provider})
}

func (h *Handler) current(w http.ResponseWriter, r *http.Request) {
	id, email, sessionID, ok := h.authenticate(r)
	if !ok {
		writeJSON(w, 200, sessionResponse{})
		return
	}
	csrf, _ := randomToken(24)
	sum := sha256.Sum256([]byte(csrf))
	if _, err := h.db.ExecContext(r.Context(), "UPDATE _trestle_admin_sessions SET csrf_hash=? WHERE id=?", sum[:], sessionID); err != nil {
		writeError(w, 500, "internal_error", "The request could not be completed.")
		return
	}
	writeJSON(w, 200, sessionResponse{Authenticated: true, AdminID: id, Email: email, CSRFToken: csrf, Provider: h.provider})
}

func (h *Handler) Authorize(r *http.Request, mutation bool) (Principal, bool) {
	id, email, sessionID, ok := h.authenticate(r)
	if !ok {
		return Principal{}, false
	}
	if mutation && !h.validCSRF(r, sessionID) {
		return Principal{}, false
	}
	return Principal{AdminID: id, Email: email, SessionID: sessionID}, true
}

func (h *Handler) AuthorizeCapability(r *http.Request, mutation bool, capability string) (Principal, bool) {
	principal, ok := h.Authorize(r, mutation)
	if !ok {
		return Principal{}, false
	}
	rows, err := h.db.QueryContext(r.Context(), "SELECT r.capabilities_json FROM _trestle_roles r JOIN _trestle_admin_roles ar ON ar.role_id=r.id WHERE ar.admin_id=?", principal.AdminID)
	if err != nil {
		return Principal{}, false
	}
	defer rows.Close()
	var effective []string
	for rows.Next() {
		var raw string
		if rows.Scan(&raw) != nil {
			return Principal{}, false
		}
		var caps []string
		if json.Unmarshal([]byte(raw), &caps) != nil {
			return Principal{}, false
		}
		effective = append(effective, caps...)
	}
	if rows.Err() != nil || !coreauth.HasCapability(effective, capability) {
		return Principal{}, false
	}
	return principal, true
}

func NewID(prefix string) string { value, _ := randomToken(18); return prefix + "_" + value }
func (h *Handler) logout(w http.ResponseWriter, r *http.Request) {
	_, _, sessionID, ok := h.authenticate(r)
	if !ok {
		writeError(w, 401, "authentication_required", "Authentication is required.")
		return
	}
	if !h.validCSRF(r, sessionID) {
		writeError(w, 403, "csrf_denied", "The CSRF token is invalid.")
		return
	}
	if _, err := h.db.ExecContext(r.Context(), "UPDATE _trestle_admin_sessions SET revoked_at=? WHERE id=?", h.now().UTC().Format(time.RFC3339Nano), sessionID); err != nil {
		writeError(w, 500, "internal_error", "The request could not be completed.")
		return
	}
	http.SetCookie(w, &http.Cookie{Name: cookieName, Value: "", Path: "/", HttpOnly: true, Secure: requestmeta.Scheme(r) == "https", SameSite: http.SameSiteStrictMode, MaxAge: -1})
	w.WriteHeader(204)
}

func (h *Handler) authenticate(r *http.Request) (string, string, string, bool) {
	cookie, err := r.Cookie(cookieName)
	if err != nil {
		return "", "", "", false
	}
	sum := sha256.Sum256([]byte(cookie.Value))
	var id, email, sessionID, expires string
	var revoked, disabled sql.NullString
	err = h.db.QueryRowContext(r.Context(), `SELECT a.id,a.email,s.id,s.expires_at,s.revoked_at,a.disabled_at FROM _trestle_admin_sessions s JOIN _trestle_admins a ON a.id=s.admin_id WHERE s.token_hash=?`, sum[:]).Scan(&id, &email, &sessionID, &expires, &revoked, &disabled)
	if err != nil || revoked.Valid || disabled.Valid {
		return "", "", "", false
	}
	expiry, err := time.Parse(time.RFC3339Nano, expires)
	if err != nil || !expiry.After(h.now()) {
		return "", "", "", false
	}
	return id, email, sessionID, true
}
func (h *Handler) validCSRF(r *http.Request, sessionID string) bool {
	if !sameOrigin(r) {
		return false
	}
	sum := sha256.Sum256([]byte(r.Header.Get("X-Trestle-CSRF")))
	var stored []byte
	if h.db.QueryRowContext(r.Context(), "SELECT csrf_hash FROM _trestle_admin_sessions WHERE id=?", sessionID).Scan(&stored) != nil {
		return false
	}
	return string(stored) == string(sum[:])
}

func normalizeEmail(value string) (string, bool) {
	value = strings.ToLower(strings.TrimSpace(value))
	parsed, err := mail.ParseAddress(value)
	return value, err == nil && parsed.Address == value && len(value) <= 254
}
func randomToken(size int) (string, error) {
	b := make([]byte, size)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}
func decodeJSON(w http.ResponseWriter, r *http.Request, out any) bool {
	r.Body = http.MaxBytesReader(w, r.Body, 64<<10)
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	if err := dec.Decode(out); err != nil {
		writeError(w, 400, "invalid_json", "The request body is invalid.")
		return false
	}
	return true
}
func sameOrigin(r *http.Request) bool {
	origin := r.Header.Get("Origin")
	if origin == "" {
		return true
	}
	scheme := requestmeta.Scheme(r)
	return origin == scheme+"://"+r.Host
}
func clientKey(r *http.Request) string {
	return requestmeta.ClientIP(r)
}
func writeJSON(w http.ResponseWriter, status int, value any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(value)
}
func writeError(w http.ResponseWriter, status int, code, message string) {
	writeJSON(w, status, httperr.New(code, message, w.Header().Get("X-Request-ID")))
}

type limiter struct {
	mu       sync.Mutex
	max      int
	window   time.Duration
	attempts map[string][]time.Time
}

func newLimiter(max int, window time.Duration) *limiter {
	return &limiter{max: max, window: window, attempts: map[string][]time.Time{}}
}
func (l *limiter) Allow(key string, now time.Time) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	cut := now.Add(-l.window)
	items := l.attempts[key][:0]
	for _, at := range l.attempts[key] {
		if at.After(cut) {
			items = append(items, at)
		}
	}
	if len(items) >= l.max {
		l.attempts[key] = items
		return false
	}
	l.attempts[key] = append(items, now)
	return true
}
func (l *limiter) Clear(key string) { l.mu.Lock(); delete(l.attempts, key); l.mu.Unlock() }

func validRegistrationPolicy(policy string) bool {
	switch policy {
	case "open", "invite", "approval", "closed":
		return true
	}
	return false
}
