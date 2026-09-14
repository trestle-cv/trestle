package authaudit

import (
	"bytes"
	"context"
	"crypto/tls"
	"database/sql"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/trestle-cv/trestle/internal/adminauth"
	"github.com/trestle-cv/trestle/internal/apidocs"
	"github.com/trestle-cv/trestle/internal/appauth"
	"github.com/trestle-cv/trestle/internal/audit"
	"github.com/trestle-cv/trestle/internal/collections"
	"github.com/trestle-cv/trestle/internal/events"
	"github.com/trestle-cv/trestle/internal/files"
	"github.com/trestle-cv/trestle/internal/functions"
	"github.com/trestle-cv/trestle/internal/identities"
	"github.com/trestle-cv/trestle/internal/jobs"
	"github.com/trestle-cv/trestle/internal/records"
	"github.com/trestle-cv/trestle/internal/rules"
	"github.com/trestle-cv/trestle/internal/server"
	"github.com/trestle-cv/trestle/internal/store"
	"github.com/trestle-cv/trestle/internal/storetest"
	"github.com/trestle-cv/trestle/internal/webhooks"
)

// buildApp wires the full handler stack (mirroring cmd/trestle) over one
// store so route protection can be exercised end to end.
func buildApp(t *testing.T, provider string) (http.Handler, *store.Store, adminSession) {
	t.Helper()
	s := storetest.Open(t, provider)
	admin := adminauth.New(s.DB(), string(s.Provider()))
	sess := setupAdmin(t, admin)
	if _, err := s.DB().Exec("UPDATE _trestle_app_registration_policy SET policy='open' WHERE id=1"); err != nil {
		t.Fatal(err)
	}
	collectionsAPI := collections.New(s.DB(), admin)
	credentials := identities.New(s.DB(), admin)
	recordAPI := records.New(s.DB(), admin, credentials)
	applicationAuth := appauth.New(s.DB(), admin)
	applicationAuth.SetAudit(audit.New(s.DB(), admin, string(s.Provider())))
	accessRules := rules.New(s.DB(), admin)
	recordAPI.ConfigureAccess(applicationAuth, accessRules)
	eventAPI := events.New(s.DB(), admin, credentials)
	recordAPI.ConfigureEvents(eventAPI)
	auditAPI := audit.New(s.DB(), admin, string(s.Provider()))
	recordAPI.ConfigureAudit(auditAPI)
	jobAPI := jobs.New(s.DB(), admin)
	webhookAPI := mustWebhooks(webhooks.New(s.DB(), admin, jobAPI, t.TempDir()))
	eventAPI.ConfigureDispatcher(webhookAPI)
	functionAPI := functions.New(s.DB(), admin, jobAPI, functions.Options{})
	eventAPI.ConfigureDispatcher(functionAPI)
	apiDocs := apidocs.New(s.DB(), admin)
	fileAPI, err := files.New(s.DB(), admin, credentials, t.TempDir())
	if err != nil {
		t.Fatal(err)
	}

	mux := http.NewServeMux()
	mux.Handle("/api/v1/auth/", applicationAuth)
	mux.Handle("/api/v1/collections/", recordAPI)
	mux.Handle("/api/v1/files", fileAPI)
	mux.Handle("/api/v1/files/", fileAPI)
	mux.Handle("/api/v1/realtime", eventAPI)
	mux.Handle("/api/v1/openapi.json", apiDocs)
	mux.Handle("/admin/v1/collections", collectionsAPI)
	mux.Handle("/admin/v1/collections/", collectionsAPI)
	mux.Handle("/admin/v1/data/", recordAPI)
	mux.Handle("/admin/v1/app-users", applicationAuth)
	mux.Handle("/admin/v1/app-users/", applicationAuth)
	mux.Handle("/admin/v1/credentials", credentials)
	mux.Handle("/admin/v1/credentials/", credentials)
	mux.Handle("/admin/v1/collection-rules/", accessRules)
	mux.Handle("/admin/v1/files", fileAPI)
	mux.Handle("/admin/v1/files/", fileAPI)
	mux.Handle("/admin/v1/events", eventAPI)
	mux.Handle("/admin/v1/audit", auditAPI)
	mux.Handle("/admin/v1/jobs", jobAPI)
	mux.Handle("/admin/v1/jobs/", jobAPI)
	mux.Handle("/admin/v1/webhooks", webhookAPI)
	mux.Handle("/admin/v1/webhooks/", webhookAPI)
	mux.Handle("/admin/v1/functions", functionAPI)
	mux.Handle("/admin/v1/functions/", functionAPI)
	mux.Handle("/admin/v1/api/schema", apiDocs)
	mux.Handle("/admin/v1/", admin)
	return mux, s, sess
}

// loadProtectedRoutes loads the machine-readable protected-route inventory.
func loadProtectedRoutes(t *testing.T) []struct {
	Method, Path, Family string
	Status               int
} {
	t.Helper()
	root := "."
	for i := 0; i < 6; i++ {
		if _, err := os.Stat(filepath.Join(root, "go.mod")); err == nil {
			break
		}
		root = filepath.Join("..", root)
	}
	raw, err := os.ReadFile(filepath.Join(root, "docs", "hardening", "protected-routes.json"))
	if err != nil {
		t.Fatal(err)
	}
	var inv struct {
		Routes []struct {
			Method, Path, Family string
			Status               int
		} `json:"routes"`
	}
	if err := json.Unmarshal(raw, &inv); err != nil {
		t.Fatal(err)
	}
	if len(inv.Routes) == 0 {
		t.Fatal("protected-route inventory is empty")
	}
	return inv.Routes
}

// bodies maps mutation routes to valid request bodies so a denied request is
// rejected for authentication, not for malformed input.
func bodyFor(path, method string) string {
	switch {
	case method == "PATCH" && strings.Contains(path, "/collections"):
		return `{"name":"x","fields":[{"name":"t","type":"text"}]}`
	case method == "POST" && strings.Contains(path, "/collections") && !strings.Contains(path, "/records"):
		return `{"name":"x","fields":[{"name":"t","type":"text"}]}`
	case strings.Contains(path, "/credentials"):
		return `{"kind":"service","name":"x","scopes":["records:read"]}`
	case strings.Contains(path, "/collection-rules") && method == "PUT":
		return `{"rules":{"view":"actor.id == record.owner"}}`
	case strings.Contains(path, "/explain"):
		return `{"expression":"actor.id == record.owner"}`
	case strings.Contains(path, "/jobs") && !strings.Contains(path, "/jobs/"):
		return `{"kind":"noop","payload":{}}`
	case strings.Contains(path, "/jobs/") && method == "POST":
		return `{"action":"cancel"}`
	case strings.Contains(path, "/webhooks") && !strings.Contains(path, "/webhooks/"):
		return `{"name":"x","url":"https://receiver.invalid/x","topics":["record.created"]}`
	case strings.Contains(path, "/webhooks/") && method == "POST":
		return `{"action":"disable"}`
	case strings.Contains(path, "/functions") && !strings.Contains(path, "/functions/"):
		return `{"name":"x","target":"arn:aws:lambda:us-east-1:1:function:x","region":"us-east-1","topics":["record.created"]}`
	case strings.Contains(path, "/functions/") && method == "POST":
		return `{"action":"disable"}`
	case strings.Contains(path, "/records") && method == "POST":
		return `{"values":{"t":"v"}}`
	case strings.Contains(path, "/records") && method == "PATCH":
		return `{"values":{"t":"v"}}`
	}
	return ""
}

// TestUnauthenticatedRoutesAreRejected iterates the complete protected-route
// inventory: every route and its relevant methods must reject an
// unauthenticated request with the exact expected status, with valid request
// bodies, and no durable mutation may occur in any security-sensitive family.
func TestUnauthenticatedRoutesAreRejected(t *testing.T) {
	routes := loadProtectedRoutes(t)
	for _, provider := range storetest.Providers(t) {
		t.Run(provider, func(t *testing.T) {
			app, s, _ := buildApp(t, provider)
			for _, route := range routes {
				body := bodyFor(route.Path, route.Method)
				r := httptest.NewRequest(route.Method, "http://example.test"+route.Path, bytes.NewBufferString(body))
				r.Host = "example.test"
				if body != "" {
					r.Header.Set("Content-Type", "application/json")
				}
				w := httptest.NewRecorder()
				app.ServeHTTP(w, r)
				if w.Code != route.Status {
					t.Errorf("%s %s unauthenticated returned %d, want %d", route.Method, route.Path, w.Code, route.Status)
				}
				if strings.Contains(strings.ToLower(w.Body.String()), "password") {
					t.Errorf("%s %s leaked a password: %s", route.Method, route.Path, w.Body.String())
				}
			}
			// No durable mutation in any security-sensitive family.
			for _, family := range []string{"_trestle_collections", "_trestle_credentials", "_trestle_collection_rules", "_trestle_files", "_trestle_events", "_trestle_audit", "_trestle_jobs", "_trestle_webhooks", "_trestle_functions"} {
				var n int
				s.DB().QueryRow("SELECT count(*) FROM " + family).Scan(&n)
				if n != 0 {
					t.Errorf("denied requests created durable rows in %s: %d", family, n)
				}
			}
		})
	}
}

// TestCookieFlagsAndCSRFEnforcement proves the admin cookie is HttpOnly and
// SameSite=Strict, and that browser mutations without a valid CSRF token or
// with a foreign origin are rejected.
func TestCookieFlagsAndCSRFEnforcement(t *testing.T) {
	for _, provider := range storetest.Providers(t) {
		t.Run(provider, func(t *testing.T) {
			app, _, sess := buildApp(t, provider)
			if sess.cookie.Name != "trestle_admin_session" {
				t.Fatalf("cookie name %q", sess.cookie.Name)
			}
			if !sess.cookie.HttpOnly {
				t.Error("admin cookie is not HttpOnly")
			}
			if sess.cookie.SameSite != http.SameSiteStrictMode {
				t.Error("admin cookie is not SameSite=Strict")
			}
			noCSRF := httptest.NewRequest("POST", "http://example.test/admin/v1/collections", bytes.NewBufferString(`{"name":"x","fields":[]}`))
			noCSRF.Host = "example.test"
			noCSRF.Header.Set("Origin", "http://example.test")
			noCSRF.AddCookie(sess.cookie)
			w := httptest.NewRecorder()
			app.ServeHTTP(w, noCSRF)
			if w.Code != 403 {
				t.Fatalf("mutation without CSRF returned %d, want 403", w.Code)
			}
			foreign := httptest.NewRequest("POST", "http://example.test/admin/v1/collections", bytes.NewBufferString(`{"name":"x","fields":[]}`))
			foreign.Host = "example.test"
			foreign.Header.Set("Origin", "http://evil.example")
			foreign.Header.Set("X-Trestle-CSRF", sess.csrf)
			foreign.AddCookie(sess.cookie)
			w = httptest.NewRecorder()
			app.ServeHTTP(w, foreign)
			if w.Code != 403 {
				t.Fatalf("mutation with foreign origin returned %d, want 403", w.Code)
			}
		})
	}
}

// failBeginExecutor fails BeginTx; failCommitExecutor fails Commit.
type failBeginExecutor struct {
	store.Executor
}
type failCommitExecutor struct {
	store.Executor
}
type failCommitTx struct {
	store.Transaction
}

func (f *failBeginExecutor) BeginTx(ctx context.Context, o *sql.TxOptions) (store.Transaction, error) {
	return nil, errors.New("injected begin failure")
}
func (f *failCommitExecutor) BeginTx(ctx context.Context, o *sql.TxOptions) (store.Transaction, error) {
	tx, err := f.Executor.BeginTx(ctx, o)
	if err != nil {
		return nil, err
	}
	return &failCommitTx{Transaction: tx}, nil
}
func (t *failCommitTx) Commit() error { return errors.New("injected commit failure") }

// TestSecuritySensitiveBeginAndCommitFailures proves the transactional
// app-user disable path fails closed on begin and commit failures, not only on
// Exec failures.
func TestSecuritySensitiveBeginAndCommitFailures(t *testing.T) {
	for _, provider := range storetest.Providers(t) {
		t.Run(provider, func(t *testing.T) {
			s := storetest.Open(t, provider)
			admin := adminauth.New(s.DB(), string(s.Provider()))
			sess := setupAdmin(t, admin)
			if _, err := s.DB().Exec("UPDATE _trestle_app_registration_policy SET policy='open' WHERE id=1"); err != nil {
				t.Fatal(err)
			}

			beginApp := appauth.New(&failBeginExecutor{Executor: s.DB()}, admin)
			if w := do(beginApp, sess, "POST", "/admin/v1/app-users/usr_none/disable", nil); w.Code != 500 {
				t.Fatalf("disable begin failure returned %d, want 500", w.Code)
			}
			commitApp := appauth.New(&failCommitExecutor{Executor: s.DB()}, admin)
			if w := do(commitApp, sess, "POST", "/admin/v1/app-users/usr_none/disable", nil); w.Code != 500 {
				t.Fatalf("disable commit failure returned %d, want 500", w.Code)
			}

			// Rules update is transactional: begin and commit failures must
			// return 500 and leave the prior rules intact.
			rulesReal := rules.New(s.DB(), admin)
			schemas := collections.New(s.DB(), admin)
			if w := do(schemas, sess, "POST", "/admin/v1/collections", map[string]any{"name": "issues", "fields": []map[string]any{{"name": "t", "type": "text"}}}); w.Code != 201 {
				t.Fatalf("collection create %d", w.Code)
			}
			if w := do(rulesReal, sess, "PUT", "/admin/v1/collection-rules/issues", map[string]any{"rules": map[string]string{"view": "actor.id == record.owner"}}); w.Code != 200 {
				t.Fatalf("rules put %d", w.Code)
			}
			beginRules := rules.New(&failBeginExecutor{Executor: s.DB()}, admin)
			if w := do(beginRules, sess, "PUT", "/admin/v1/collection-rules/issues", map[string]any{"rules": map[string]string{"view": "actor.id == input.owner"}}); w.Code != 500 {
				t.Fatalf("rules put begin failure returned %d, want 500", w.Code)
			}
			commitRules := rules.New(&failCommitExecutor{Executor: s.DB()}, admin)
			if w := do(commitRules, sess, "PUT", "/admin/v1/collection-rules/issues", map[string]any{"rules": map[string]string{"view": "actor.id == input.owner"}}); w.Code != 500 {
				t.Fatalf("rules put commit failure returned %d, want 500", w.Code)
			}
			var expr string
			s.DB().QueryRow("SELECT expression FROM _trestle_collection_rules WHERE collection_id=(SELECT id FROM _trestle_collections WHERE name='issues') AND operation='view'").Scan(&expr)
			if expr != "actor.id == record.owner" {
				t.Fatalf("rules changed after begin/commit failure: %q", expr)
			}
		})
	}
}

// TestAuthAdversarialIdentity covers disabled users, revoked sessions, token
// replay, session fixation (distinct cookies per login) and credential
// leakage in responses.
func TestAuthAdversarialIdentity(t *testing.T) {
	for _, provider := range storetest.Providers(t) {
		t.Run(provider, func(t *testing.T) {
			s := storetest.Open(t, provider)
			admin := adminauth.New(s.DB(), string(s.Provider()))
			sess := setupAdmin(t, admin)
			if _, err := s.DB().Exec("UPDATE _trestle_app_registration_policy SET policy='open' WHERE id=1"); err != nil {
				t.Fatal(err)
			}
			appUser := appauth.New(s.DB(), admin)
			appUser.SetAudit(audit.New(s.DB(), admin, string(s.Provider())))

			if w := do(appUser, sess, "POST", "/api/v1/auth/register", map[string]any{"email": "u@example.com", "password": "1234567"}); w.Code != 201 {
				t.Fatalf("register %d", w.Code)
			}
			login1 := do(appUser, sess, "POST", "/api/v1/auth/login", map[string]any{"email": "u@example.com", "password": "1234567"})
			var tok struct {
				UserID       string `json:"userId"`
				AccessToken  string `json:"accessToken"`
				RefreshToken string `json:"refreshToken"`
			}
			json.Unmarshal(login1.Body.Bytes(), &tok)
			if strings.Contains(login1.Body.String(), "1234567") {
				t.Fatal("password leaked in login response")
			}

			// Session fixation: a second login issues a different refresh token.
			login2 := do(appUser, sess, "POST", "/api/v1/auth/login", map[string]any{"email": "u@example.com", "password": "1234567"})
			var tok2 struct {
				RefreshToken string `json:"refreshToken"`
			}
			json.Unmarshal(login2.Body.Bytes(), &tok2)
			if tok2.RefreshToken == tok.RefreshToken {
				t.Fatal("login reissued the same refresh token (fixation)")
			}

			// Logout revokes the session; the access token must no longer work.
			if w := do(appUser, sess, "POST", "/api/v1/auth/logout", map[string]any{"refreshToken": tok.RefreshToken}); w.Code != 204 {
				t.Fatalf("logout %d", w.Code)
			}
			authReq := httptest.NewRequest("GET", "http://example.test/api/v1/x", nil)
			authReq.Header.Set("Authorization", "Bearer "+tok.AccessToken)
			if _, ok := appUser.Authenticate(authReq); ok {
				t.Fatal("revoked session still authenticates")
			}
			// Token replay: the consumed refresh token is rejected on refresh.
			if w := do(appUser, sess, "POST", "/api/v1/auth/refresh", map[string]any{"refreshToken": tok.RefreshToken}); w.Code != 401 {
				t.Fatalf("refresh token replay returned %d, want 401", w.Code)
			}

			// Disabled user: login is rejected with a generic error.
			if w := do(appUser, sess, "POST", "/admin/v1/app-users/"+tok.UserID+"/disable", nil); w.Code != 204 {
				t.Fatalf("disable user %d %s", w.Code, w.Body.String())
			}
			denied := do(appUser, sess, "POST", "/api/v1/auth/login", map[string]any{"email": "u@example.com", "password": "1234567"})
			if denied.Code != 401 || strings.Contains(denied.Body.String(), "disabled") {
				t.Fatalf("disabled-user login returned %d %s", denied.Code, denied.Body.String())
			}
		})
	}
}

// TestRateLimiterThrottlesAbuse proves repeated failed logins from one client
// address are throttled while a distinct address is unaffected.
func TestRateLimiterThrottlesAbuse(t *testing.T) {
	for _, provider := range storetest.Providers(t) {
		t.Run(provider, func(t *testing.T) {
			s := storetest.Open(t, provider)
			admin := adminauth.New(s.DB(), string(s.Provider()))
			sess := setupAdmin(t, admin)
			if _, err := s.DB().Exec("UPDATE _trestle_app_registration_policy SET policy='open' WHERE id=1"); err != nil {
				t.Fatal(err)
			}
			appUser := appauth.New(s.DB(), admin)
			for i := 0; i < 11; i++ {
				w := do(appUser, sess, "POST", "/api/v1/auth/login", map[string]any{"email": "missing@example.com", "password": "wrong"})
				if i < 10 && w.Code != 401 {
					t.Fatalf("attempt %d returned %d, want 401", i, w.Code)
				}
				if i == 10 && w.Code != 429 {
					t.Fatalf("attempt %d returned %d, want 429 (throttled)", i, w.Code)
				}
			}
			// A different client address is not throttled.
			r := httptest.NewRequest("POST", "http://example.test/api/v1/auth/login", bytes.NewBufferString(`{"email":"missing@example.com","password":"wrong"}`))
			r.Host = "example.test"
			r.RemoteAddr = "10.0.0.99:1234"
			w := httptest.NewRecorder()
			appUser.ServeHTTP(w, r)
			if w.Code != 401 {
				t.Fatalf("distinct-address login returned %d, want 401 (not throttled)", w.Code)
			}
		})
	}
}

// issueAdminCookie creates one administrator over a fresh store and returns
// the issued session cookie, using the given scheme (http or https).
func issueAdminCookie(t *testing.T, provider string, secure bool) *http.Cookie {
	t.Helper()
	s := storetest.Open(t, provider)
	admin := adminauth.New(s.DB(), string(s.Provider()))
	origin := "http://example.test"
	if secure {
		origin = "https://example.test"
	}
	r := httptest.NewRequest("POST", origin+"/admin/v1/setup", bytes.NewBufferString(`{"username":"admin","email":"admin@example.com","password":"correct horse battery staple","applicationRegistrationPolicy":"closed"}`))
	r.Host = "example.test"
	r.Header.Set("Origin", origin)
	if secure {
		r.TLS = &tls.ConnectionState{}
	}
	w := httptest.NewRecorder()
	admin.ServeHTTP(w, r)
	if w.Code != 200 {
		t.Fatalf("setup over secure=%v returned %d %s", secure, w.Code, w.Body.String())
	}
	return w.Result().Cookies()[0]
}

func TestAdminCookieNotSecureOverHttp(t *testing.T) {
	for _, provider := range storetest.Providers(t) {
		t.Run(provider, func(t *testing.T) {
			if c := issueAdminCookie(t, provider, false); c.Secure {
				t.Error("cookie is Secure over plain HTTP")
			}
		})
	}
}

func TestAdminCookieSecureOverHttps(t *testing.T) {
	for _, provider := range storetest.Providers(t) {
		t.Run(provider, func(t *testing.T) {
			if c := issueAdminCookie(t, provider, true); !c.Secure {
				t.Error("cookie is not Secure over HTTPS")
			}
		})
	}
}

// TestAppTokenVsAdminRoutes proves a scoped application credential is not
// accepted on administrator routes, while an administrator session is.
func TestAppTokenVsAdminRoutes(t *testing.T) {
	for _, provider := range storetest.Providers(t) {
		t.Run(provider, func(t *testing.T) {
			app, s, sess := buildApp(t, provider)
			// Create a service credential and capture its secret.
			credentials := identities.New(s.DB(), adminauth.New(s.DB(), string(s.Provider())))
			created := do(credentials, sess, "POST", "/admin/v1/credentials", map[string]any{"kind": "service", "name": "svc", "scopes": []string{"records:read"}})
			var out struct {
				Secret string `json:"secret"`
			}
			json.Unmarshal(created.Body.Bytes(), &out)
			if out.Secret == "" {
				t.Fatal("no credential secret issued")
			}
			// A service token on an admin route must be rejected (403).
			req := httptest.NewRequest("GET", "http://example.test/admin/v1/collections", nil)
			req.Host = "example.test"
			req.Header.Set("Authorization", "Bearer "+out.Secret)
			w := httptest.NewRecorder()
			app.ServeHTTP(w, req)
			if w.Code != 401 {
				t.Fatalf("service token on admin GET returned %d, want 401 (admin sessions are distinct from application credentials)", w.Code)
			}
			// The admin session works on admin routes.
			okReq := httptest.NewRequest("GET", "http://example.test/admin/v1/collections", nil)
			okReq.Host = "example.test"
			okReq.AddCookie(sess.cookie)
			w = httptest.NewRecorder()
			app.ServeHTTP(w, okReq)
			if w.Code != 200 {
				t.Fatalf("admin session on admin route returned %d, want 200", w.Code)
			}
		})
	}
}

// TestProxyRateLimitAddressHandling proves the rate limiter keys on the
// forwarded client address only behind a trusted proxy; an untrusted proxy's
// forwarded header is ignored and the socket address is used.
func TestProxyRateLimitAddressHandling(t *testing.T) {
	for _, provider := range storetest.Providers(t) {
		t.Run(provider, func(t *testing.T) {
			s := storetest.Open(t, provider)
			admin := adminauth.New(s.DB(), string(s.Provider()))
			appa := appauth.New(s.DB(), admin)
			_ = setupAdmin(t, admin)

			trusted := server.NewWithOptions(slog.New(slog.NewTextHandler(io.Discard, nil)), nil, appa, nil, server.Options{TrustedProxies: []netip.Prefix{netip.MustParsePrefix("127.0.0.1/32")}})
			failLogin := func(h http.Handler, forwarded string) int {
				r := httptest.NewRequest("POST", "http://example.test/api/v1/auth/login", bytes.NewBufferString(`{"email":"missing@example.com","password":"wrong"}`))
				r.Host = "example.test"
				r.RemoteAddr = "127.0.0.1:9999"
				r.Header.Set("X-Forwarded-For", forwarded)
				w := httptest.NewRecorder()
				h.ServeHTTP(w, r)
				return w.Code
			}
			// Trusted proxy: two distinct forwarded clients each get their own
			// window, so 10 attempts per client are all 401.
			for i := 0; i < 10; i++ {
				if code := failLogin(trusted.Handler(), "10.0.0.1"); code != 401 {
					t.Fatalf("trusted client A attempt %d returned %d", i, code)
				}
			}
			for i := 0; i < 10; i++ {
				if code := failLogin(trusted.Handler(), "10.0.0.2"); code != 401 {
					t.Fatalf("trusted client B attempt %d returned %d (shared window across forwarded clients)", i, code)
				}
			}

			// Untrusted proxy: forwarded headers are ignored, so all requests
			// share the socket address and the 11th is throttled.
			untrusted := server.NewWithOptions(slog.New(slog.NewTextHandler(io.Discard, nil)), nil, appa, nil, server.Options{})
			for i := 0; i < 11; i++ {
				code := failLogin(untrusted.Handler(), "10.0.0.99")
				if i < 10 && code != 401 {
					t.Fatalf("untrusted attempt %d returned %d, want 401", i, code)
				}
				if i == 10 && code != 429 {
					t.Fatalf("untrusted attempt %d returned %d, want 429 (forwarded ignored)", i, code)
				}
			}
		})
	}
}
