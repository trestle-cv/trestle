package authaudit

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/trestle-cv/trestle/internal/adminauth"
	"github.com/trestle-cv/trestle/internal/appauth"
	"github.com/trestle-cv/trestle/internal/audit"
	"github.com/trestle-cv/trestle/internal/collections"
	"github.com/trestle-cv/trestle/internal/functions"
	"github.com/trestle-cv/trestle/internal/identities"
	"github.com/trestle-cv/trestle/internal/jobs"
	"github.com/trestle-cv/trestle/internal/rules"
	"github.com/trestle-cv/trestle/internal/store"
	"github.com/trestle-cv/trestle/internal/storetest"
	"github.com/trestle-cv/trestle/internal/webhooks"
)

// faultingExecutor fails the first ExecContext (including inside a
// transaction) whose SQL contains the target substring, so a durable write in
// a security-sensitive mutation can be forced to fail after earlier statements
// already ran.
type faultingExecutor struct {
	store.Executor
	target  string
	matched bool
}

func (f *faultingExecutor) ExecContext(ctx context.Context, q string, a ...any) (sql.Result, error) {
	if !f.matched && strings.Contains(q, f.target) {
		f.matched = true
		return nil, errors.New("injected durable-write failure")
	}
	return f.Executor.ExecContext(ctx, q, a...)
}

func (f *faultingExecutor) BeginTx(ctx context.Context, o *sql.TxOptions) (store.Transaction, error) {
	tx, err := f.Executor.BeginTx(ctx, o)
	if err != nil {
		return nil, err
	}
	return &faultingTx{Transaction: tx, f: f}, nil
}

type faultingTx struct {
	store.Transaction
	f *faultingExecutor
}

func (t *faultingTx) ExecContext(ctx context.Context, q string, a ...any) (sql.Result, error) {
	if !t.f.matched && strings.Contains(q, t.f.target) {
		t.f.matched = true
		return nil, errors.New("injected durable-write failure")
	}
	return t.Transaction.ExecContext(ctx, q, a...)
}

type adminSession struct {
	cookie *http.Cookie
	csrf   string
}

func setupAdmin(t *testing.T, admin *adminauth.Handler) adminSession {
	t.Helper()
	body := strings.NewReader(`{"username":"admin","email":"admin@example.com","password":"correct horse battery staple","applicationRegistrationPolicy":"closed"}`)
	r := httptest.NewRequest("POST", "http://example.test/admin/v1/setup", body)
	r.Host = "example.test"
	r.Header.Set("Origin", "http://example.test")
	w := httptest.NewRecorder()
	admin.ServeHTTP(w, r)
	if w.Code != 200 {
		t.Fatalf("setup %d %s", w.Code, w.Body.String())
	}
	var out struct {
		CSRF string `json:"csrfToken"`
	}
	json.Unmarshal(w.Body.Bytes(), &out)
	return adminSession{w.Result().Cookies()[0], out.CSRF}
}

func do(h http.Handler, sess adminSession, method, path string, body any) *httptest.ResponseRecorder {
	var b bytes.Buffer
	if body != nil {
		json.NewEncoder(&b).Encode(body)
	}
	r := httptest.NewRequest(method, "http://example.test"+path, &b)
	r.Host = "example.test"
	r.Header.Set("Origin", "http://example.test")
	r.Header.Set("X-Trestle-CSRF", sess.csrf)
	r.AddCookie(sess.cookie)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	return w
}

func mustWebhooks(v *webhooks.Handler, err error) *webhooks.Handler {
	if err != nil {
		panic(err)
	}
	return v
}

// TestSecuritySensitiveMutationsFailClosed proves a security-sensitive
// mutation never returns success when its durable write fails, on both
// providers: the failure surfaces as a 500 and the prior state is unchanged.
func TestSecuritySensitiveMutationsFailClosed(t *testing.T) {
	for _, provider := range storetest.Providers(t) {
		t.Run(provider, func(t *testing.T) {
			s := storetest.Open(t, provider)
			admin := adminauth.New(s.DB(), string(s.Provider()))
			sess := setupAdmin(t, admin)
			if _, err := s.DB().Exec("UPDATE _trestle_app_registration_policy SET policy='open' WHERE id=1"); err != nil {
				t.Fatal(err)
			}

			// 1. Admin logout: a failed revocation must return 500 and leave
			// the session valid.
			faultAdmin := adminauth.New(&faultingExecutor{Executor: s.DB(), target: "UPDATE _trestle_admin_sessions SET revoked_at"}, string(s.Provider()))
			if w := do(faultAdmin, sess, "DELETE", "/admin/v1/session", nil); w.Code != 500 {
				t.Fatalf("admin logout durable-write failure=%d, want 500", w.Code)
			}
			r := httptest.NewRequest("GET", "http://example.test/admin/v1/session", nil)
			r.Host = "example.test"
			r.AddCookie(sess.cookie)
			if _, ok := faultAdmin.Authorize(r, false); !ok {
				t.Fatal("admin session revoked despite durable-write failure")
			}

			// 2. Application logout: register + login, then a failed
			// revocation must return 500 and leave the session live.
			appReal := appauth.New(s.DB(), admin)
			appReal.SetAudit(audit.New(s.DB(), admin, string(s.Provider())))
			if w := do(appReal, sess, "POST", "/api/v1/auth/register", map[string]any{"email": "user@example.com", "password": "1234567"}); w.Code != 201 {
				t.Fatalf("register %d", w.Code)
			}
			login := do(appReal, sess, "POST", "/api/v1/auth/login", map[string]any{"email": "user@example.com", "password": "1234567"})
			var out struct {
				AccessToken  string `json:"accessToken"`
				RefreshToken string `json:"refreshToken"`
			}
			json.Unmarshal(login.Body.Bytes(), &out)
			faultApp := appauth.New(&faultingExecutor{Executor: s.DB(), target: "UPDATE _trestle_app_sessions SET revoked_at"}, admin)
			if w := do(faultApp, sess, "POST", "/api/v1/auth/logout", map[string]any{"refreshToken": out.RefreshToken}); w.Code != 500 {
				t.Fatalf("app logout durable-write failure=%d, want 500", w.Code)
			}
			authReq := httptest.NewRequest("GET", "http://example.test/api/v1/x", nil)
			authReq.Header.Set("Authorization", "Bearer "+out.AccessToken)
			if _, ok := appReal.Authenticate(authReq); !ok {
				t.Fatal("app session revoked despite durable-write failure")
			}

			// 3. Webhook enable/disable.
			queue := jobs.New(s.DB(), admin)
			whReal := mustWebhooks(webhooks.New(s.DB(), admin, queue, t.TempDir()))
			if w := do(whReal, sess, "POST", "/admin/v1/webhooks", map[string]any{"name": "h", "url": "https://receiver.invalid/x", "topics": []string{"record.created"}}); w.Code != 201 {
				t.Fatalf("webhook create %d %s", w.Code, w.Body.String())
			}
			var whID string
			s.DB().QueryRow("SELECT id FROM _trestle_webhooks LIMIT 1").Scan(&whID)
			faultWh := mustWebhooks(webhooks.New(&faultingExecutor{Executor: s.DB(), target: "UPDATE _trestle_webhooks SET enabled"}, admin, queue, t.TempDir()))
			if w := do(faultWh, sess, "POST", "/admin/v1/webhooks/"+whID, map[string]any{"action": "disable"}); w.Code != 500 {
				t.Fatalf("webhook disable durable-write failure=%d, want 500", w.Code)
			}
			var enabled any
			s.DB().QueryRow("SELECT enabled FROM _trestle_webhooks WHERE id=?", whID).Scan(&enabled)
			if on, _ := s.Dialect().DecodeBoolean(enabled); !on {
				t.Fatal("webhook disabled despite durable-write failure")
			}

			// 4. Function enable/disable.
			fnReal := functions.New(s.DB(), admin, queue, functions.Options{})
			if w := do(fnReal, sess, "POST", "/admin/v1/functions", map[string]any{"name": "fn", "target": "arn:aws:lambda:us-east-1:1:function:x", "region": "us-east-1", "topics": []string{"record.created"}}); w.Code != 201 {
				t.Fatalf("function create %d", w.Code)
			}
			var fnID string
			s.DB().QueryRow("SELECT id FROM _trestle_functions LIMIT 1").Scan(&fnID)
			faultFn := functions.New(&faultingExecutor{Executor: s.DB(), target: "UPDATE _trestle_functions SET enabled"}, admin, queue, functions.Options{})
			if w := do(faultFn, sess, "POST", "/admin/v1/functions/"+fnID, map[string]any{"action": "disable"}); w.Code != 500 {
				t.Fatalf("function disable durable-write failure=%d, want 500", w.Code)
			}
			var fnEnabled any
			s.DB().QueryRow("SELECT enabled FROM _trestle_functions WHERE id=?", fnID).Scan(&fnEnabled)
			if on, _ := s.Dialect().DecodeBoolean(fnEnabled); !on {
				t.Fatal("function disabled despite durable-write failure")
			}

			// 5. Credential revocation.
			credReal := identities.New(s.DB(), admin)
			if w := do(credReal, sess, "POST", "/admin/v1/credentials", map[string]any{"kind": "service", "name": "svc", "scopes": []string{"records:read"}}); w.Code != 201 {
				t.Fatalf("credential create %d", w.Code)
			}
			var credID string
			s.DB().QueryRow("SELECT id FROM _trestle_credentials LIMIT 1").Scan(&credID)
			faultCred := identities.New(&faultingExecutor{Executor: s.DB(), target: "UPDATE _trestle_credentials SET revoked_at"}, admin)
			if w := do(faultCred, sess, "DELETE", "/admin/v1/credentials/"+credID, nil); w.Code != 500 {
				t.Fatalf("credential revoke durable-write failure=%d, want 500", w.Code)
			}
			var revoked sql.NullString
			s.DB().QueryRow("SELECT revoked_at FROM _trestle_credentials WHERE id=?", credID).Scan(&revoked)
			if revoked.Valid {
				t.Fatal("credential revoked despite durable-write failure")
			}

			// 6. Job cancel.
			tx, err := s.DB().BeginTx(context.Background(), nil)
			if err != nil {
				t.Fatal(err)
			}
			if _, _, err := queue.Enqueue(context.Background(), tx, "noop", map[string]any{}, ""); err != nil {
				t.Fatal(err)
			}
			if err := tx.Commit(); err != nil {
				t.Fatal(err)
			}
			var jobID string
			s.DB().QueryRow("SELECT id FROM _trestle_jobs LIMIT 1").Scan(&jobID)
			faultJobs := jobs.New(&faultingExecutor{Executor: s.DB(), target: "SET status='cancelled'"}, admin)
			if w := do(faultJobs, sess, "POST", "/admin/v1/jobs/"+jobID, map[string]any{"action": "cancel"}); w.Code != 500 {
				t.Fatalf("job cancel durable-write failure=%d, want 500", w.Code)
			}
			var jobStatus string
			s.DB().QueryRow("SELECT status FROM _trestle_jobs WHERE id=?", jobID).Scan(&jobStatus)
			if jobStatus == "cancelled" {
				t.Fatal("job cancelled despite durable-write failure")
			}

			// 7. Rules put: a failed rule insert must roll back the delete and
			// leave the previous rules intact.
			rulesReal := rules.New(s.DB(), admin)
			schemas := collections.New(s.DB(), admin)
			if w := do(schemas, sess, "POST", "/admin/v1/collections", map[string]any{"name": "issues", "fields": []map[string]any{{"name": "t", "type": "text"}}}); w.Code != 201 {
				t.Fatalf("collection create %d %s", w.Code, w.Body.String())
			}
			if w := do(rulesReal, sess, "PUT", "/admin/v1/collection-rules/issues", map[string]any{"rules": map[string]string{"view": "actor.id == record.owner"}}); w.Code != 200 {
				t.Fatalf("rules put %d %s", w.Code, w.Body.String())
			}
			faultRules := rules.New(&faultingExecutor{Executor: s.DB(), target: "INSERT INTO _trestle_collection_rules"}, admin)
			if w := do(faultRules, sess, "PUT", "/admin/v1/collection-rules/issues", map[string]any{"rules": map[string]string{"view": "actor.id == input.owner"}}); w.Code != 500 {
				t.Fatalf("rules put durable-write failure=%d, want 500", w.Code)
			}
			var expr string
			s.DB().QueryRow("SELECT expression FROM _trestle_collection_rules WHERE collection_id=(SELECT id FROM _trestle_collections WHERE name='issues') AND operation='view'").Scan(&expr)
			if expr != "actor.id == record.owner" {
				t.Fatalf("rules changed despite durable-write failure: %q", expr)
			}
		})
	}
}
