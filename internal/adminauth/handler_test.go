package adminauth

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/trestle-cv/trestle/internal/requestmeta"
	"github.com/trestle-cv/trestle/internal/storetest"
)

func TestSetupGuardBlocksAdministratorCreationUntilDatabaseRestart(t *testing.T) {
	h := testHandler(t, "sqlite")
	h.SetSetupGuard(func(context.Context) error { return errors.New("restart required") })
	r := httptest.NewRequest(http.MethodPost, "/admin/v1/setup", strings.NewReader(`{"email":"admin@example.com","password":"mudblood","applicationRegistrationPolicy":"closed"}`))
	r.Host = "example.test"
	r.Header.Set("Origin", "http://example.test")
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if w.Code != http.StatusConflict || !strings.Contains(w.Body.String(), "database_restart_required") {
		t.Fatalf("status=%d body=%s", w.Code, w.Body.String())
	}
}

func testHandler(t *testing.T, provider string) *Handler {
	t.Helper()
	s := storetest.Open(t, provider)
	return New(s.DB(), string(s.Provider()))
}

func TestTrustedHTTPSIssuesSecureCookie(t *testing.T) {
	for _, provider := range storetest.Providers(t) {
		t.Run(provider, func(t *testing.T) {
			h := testHandler(t, provider)
			r := httptest.NewRequest(http.MethodPost, "/admin/v1/setup", strings.NewReader(`{"email":"admin@example.com","password":"mudblood","applicationRegistrationPolicy":"closed"}`))
			r.Host = "example.test"
			r.Header.Set("Origin", "https://example.test")
			r = requestmeta.With(r, "https", "203.0.113.9")
			w := httptest.NewRecorder()
			h.ServeHTTP(w, r)
			if w.Code != 200 {
				t.Fatalf("setup: %d %s", w.Code, w.Body.String())
			}
			if cookies := w.Result().Cookies(); len(cookies) != 1 || !cookies[0].Secure {
				t.Fatalf("expected secure cookie: %#v", cookies)
			}
		})
	}
}
func request(t *testing.T, h http.Handler, method, path string, body any, cookie *http.Cookie, csrf string) *httptest.ResponseRecorder {
	t.Helper()
	var data bytes.Buffer
	if body != nil {
		if err := json.NewEncoder(&data).Encode(body); err != nil {
			t.Fatal(err)
		}
	}
	r := httptest.NewRequest(method, path, &data)
	r.Host = "example.test"
	r.Header.Set("Origin", "http://example.test")
	r.RemoteAddr = "192.0.2.1:1234"
	if cookie != nil {
		r.AddCookie(cookie)
	}
	if csrf != "" {
		r.Header.Set("X-Trestle-CSRF", csrf)
	}
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	return w
}
func rawRequest(h http.Handler, method, path string, body any) int {
	var data bytes.Buffer
	if body != nil {
		json.NewEncoder(&data).Encode(body)
	}
	r := httptest.NewRequest(method, path, &data)
	r.Host = "example.test"
	r.Header.Set("Origin", "http://example.test")
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	return w.Code
}

func TestSetupLoginLogoutLifecycle(t *testing.T) {
	for _, provider := range storetest.Providers(t) {
		t.Run(provider, func(t *testing.T) {
			h := testHandler(t, provider)
			w := request(t, h, "GET", "/admin/v1/setup/status", nil, nil, "")
			if !strings.Contains(w.Body.String(), "true") {
				t.Fatal(w.Body.String())
			}
			w = request(t, h, "POST", "/admin/v1/setup", credentials{Email: "Admin@Example.com", Password: "correct horse battery staple", ApplicationRegistrationPolicy: "closed"}, nil, "")
			if w.Code != 200 {
				t.Fatalf("setup: %d %s", w.Code, w.Body.String())
			}
			setupCookie := w.Result().Cookies()[0]
			var session sessionResponse
			if err := json.NewDecoder(w.Body).Decode(&session); err != nil {
				t.Fatal(err)
			}
			w = request(t, h, "POST", "/admin/v1/setup", credentials{Email: "other@example.com", Password: "correct horse battery staple", ApplicationRegistrationPolicy: "closed"}, nil, "")
			if w.Code != 409 {
				t.Fatalf("second setup: %d", w.Code)
			}
			w = request(t, h, "DELETE", "/admin/v1/session", nil, setupCookie, "")
			if w.Code != 403 {
				t.Fatalf("logout without csrf: %d", w.Code)
			}
			w = request(t, h, "DELETE", "/admin/v1/session", nil, setupCookie, session.CSRFToken)
			if w.Code != 204 {
				t.Fatalf("logout: %d %s", w.Code, w.Body.String())
			}
			w = request(t, h, "GET", "/admin/v1/session", nil, setupCookie, "")
			if !strings.Contains(w.Body.String(), "false") {
				t.Fatal("revoked session remained active")
			}
			w = request(t, h, "POST", "/admin/v1/session", credentials{Email: "admin@example.com", Password: "wrong password"}, nil, "")
			if w.Code != 401 || !strings.Contains(w.Body.String(), "invalid_credentials") {
				t.Fatalf("bad login: %d %s", w.Code, w.Body.String())
			}
			w = request(t, h, "POST", "/admin/v1/session", credentials{Email: "admin@example.com", Password: "correct horse battery staple"}, nil, "")
			if w.Code != 200 {
				t.Fatalf("login: %d %s", w.Code, w.Body.String())
			}
		})
	}
}

func TestSetupAdministratorGetsSharedCapabilitiesAndManageRequiresCSRF(t *testing.T) {
	h := testHandler(t, "sqlite")
	setup := request(t, h, http.MethodPost, "/admin/v1/setup", credentials{Email: "admin@example.com", Password: "correct horse battery staple", ApplicationRegistrationPolicy: "closed"}, nil, "")
	if setup.Code != http.StatusOK {
		t.Fatalf("setup: %d %s", setup.Code, setup.Body.String())
	}
	var session sessionResponse
	if err := json.NewDecoder(setup.Body).Decode(&session); err != nil {
		t.Fatal(err)
	}
	cookie := setup.Result().Cookies()[0]
	r := httptest.NewRequest(http.MethodGet, "/admin/v1/manage/users", nil)
	r.AddCookie(cookie)
	if _, ok := h.AuthorizeCapability(r, false, "accounts.manage"); !ok {
		t.Fatal("setup administrator lacks shared wildcard capability")
	}
	if got := request(t, h, http.MethodPost, "/admin/v1/manage/users", userMutation{Action: "create", Email: "user@example.com", Password: "another secure password", Roles: []string{"administrator"}}, cookie, ""); got.Code != http.StatusForbidden {
		t.Fatalf("mutation without CSRF=%d", got.Code)
	}
	if got := request(t, h, http.MethodPost, "/admin/v1/manage/users", userMutation{Action: "create", Email: "user@example.com", Password: "another secure password", Roles: []string{"administrator"}}, cookie, session.CSRFToken); got.Code != http.StatusNoContent {
		t.Fatalf("create=%d %s", got.Code, got.Body.String())
	}
	if got := request(t, h, http.MethodGet, "/admin/v1/manage/users", nil, cookie, ""); got.Code != http.StatusOK || !strings.Contains(got.Body.String(), "user@example.com") {
		t.Fatalf("list=%d %s", got.Code, got.Body.String())
	}
}

func TestAdministratorCanChangeOwnPassword(t *testing.T) {
	for _, provider := range storetest.Providers(t) {
		t.Run(provider, func(t *testing.T) {
			h := testHandler(t, provider)
			setup := request(t, h, "POST", "/admin/v1/setup", credentials{Email: "admin@example.com", Password: "old password", ApplicationRegistrationPolicy: "closed"}, nil, "")
			cookie := setup.Result().Cookies()[0]
			var session sessionResponse
			if err := json.NewDecoder(setup.Body).Decode(&session); err != nil {
				t.Fatal(err)
			}

			second := request(t, h, "POST", "/admin/v1/session", credentials{Email: "admin@example.com", Password: "old password"}, nil, "")
			secondCookie := second.Result().Cookies()[0]
			withoutCSRF := request(t, h, "POST", "/admin/v1/password", passwordChange{CurrentPassword: "old password", NewPassword: "new password", ConfirmPassword: "new password"}, cookie, "")
			if withoutCSRF.Code != http.StatusForbidden {
				t.Fatalf("missing csrf: %d %s", withoutCSRF.Code, withoutCSRF.Body.String())
			}
			mismatch := request(t, h, "POST", "/admin/v1/password", passwordChange{CurrentPassword: "old password", NewPassword: "new password", ConfirmPassword: "different password"}, cookie, session.CSRFToken)
			if mismatch.Code != http.StatusUnprocessableEntity {
				t.Fatalf("confirmation mismatch: %d %s", mismatch.Code, mismatch.Body.String())
			}
			bad := request(t, h, "POST", "/admin/v1/password", passwordChange{CurrentPassword: "wrong", NewPassword: "new password", ConfirmPassword: "new password"}, cookie, session.CSRFToken)
			if bad.Code != http.StatusUnauthorized {
				t.Fatalf("wrong current password: %d %s", bad.Code, bad.Body.String())
			}
			changed := request(t, h, "POST", "/admin/v1/password", passwordChange{CurrentPassword: "old password", NewPassword: "new password", ConfirmPassword: "new password"}, cookie, session.CSRFToken)
			if changed.Code != http.StatusNoContent {
				t.Fatalf("change: %d %s", changed.Code, changed.Body.String())
			}
			if current := request(t, h, "GET", "/admin/v1/session", nil, cookie, ""); !strings.Contains(current.Body.String(), "true") {
				t.Fatal("current session was revoked")
			}
			if other := request(t, h, "GET", "/admin/v1/session", nil, secondCookie, ""); !strings.Contains(other.Body.String(), "false") {
				t.Fatal("other session remained active")
			}
			if oldLogin := request(t, h, "POST", "/admin/v1/session", credentials{Email: "admin@example.com", Password: "old password"}, nil, ""); oldLogin.Code != http.StatusUnauthorized {
				t.Fatalf("old password login: %d", oldLogin.Code)
			}
			if newLogin := request(t, h, "POST", "/admin/v1/session", credentials{Email: "admin@example.com", Password: "new password"}, nil, ""); newLogin.Code != http.StatusOK {
				t.Fatalf("new password login: %d %s", newLogin.Code, newLogin.Body.String())
			}
		})
	}
}

func TestCompetingSetupCreatesOneAdministrator(t *testing.T) {
	for _, provider := range storetest.Providers(t) {
		t.Run(provider, func(t *testing.T) {
			s := storetest.Open(t, provider)
			h := New(s.DB(), string(s.Provider()))
			start := make(chan struct{})
			codes := make(chan int, 8)
			for i := 0; i < 8; i++ {
				go func(n int) {
					<-start
					codes <- rawRequest(h, "POST", "/admin/v1/setup", credentials{Email: fmt.Sprintf("admin%d@example.com", n), Password: "correct horse battery staple", ApplicationRegistrationPolicy: "closed"})
				}(i)
			}
			close(start)
			ok, denied := 0, 0
			for i := 0; i < 8; i++ {
				switch <-codes {
				case 200:
					ok++
				case 409:
					denied++
				}
			}
			if ok != 1 || denied != 7 {
				t.Fatalf("200=%d 409=%d, want exactly one winner", ok, denied)
			}
			var count int
			if err := s.DB().QueryRow("SELECT count(*) FROM _trestle_admins").Scan(&count); err != nil || count != 1 {
				t.Fatalf("admins=%d err=%v", count, err)
			}
		})
	}
}

func TestSetupValidationAndOrigin(t *testing.T) {
	for _, provider := range storetest.Providers(t) {
		t.Run(provider, func(t *testing.T) {
			h := testHandler(t, provider)
			w := request(t, h, "POST", "/admin/v1/setup", credentials{Email: "bad", Password: "short", ApplicationRegistrationPolicy: "closed"}, nil, "")
			if w.Code != 422 {
				t.Fatalf("got %d", w.Code)
			}
			r := httptest.NewRequest("POST", "/admin/v1/setup", strings.NewReader(`{"email":"a@example.com","password":"correct horse battery staple","applicationRegistrationPolicy":"closed"}`))
			r.Host = "example.test"
			r.Header.Set("Origin", "https://evil.test")
			w = httptest.NewRecorder()
			h.ServeHTTP(w, r)
			if w.Code != 403 {
				t.Fatalf("origin got %d", w.Code)
			}
		})
	}
}

func TestPasswordEncoding(t *testing.T) {
	encoded, err := hashPassword("correct horse battery staple")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(encoded, "$argon2id$") || !verifyPassword(encoded, "correct horse battery staple") || verifyPassword(encoded, "wrong password") {
		t.Fatal("password verification contract failed")
	}
	if _, err := hashPassword("short"); err == nil {
		t.Fatal("short password accepted")
	}
}
