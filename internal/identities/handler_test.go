package identities

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/trestle-cv/trestle/internal/adminauth"
	"github.com/trestle-cv/trestle/internal/storetest"
)

type session struct {
	cookie *http.Cookie
	csrf   string
}

func setup(t *testing.T, provider string) (*Handler, session) {
	t.Helper()
	s := storetest.Open(t, provider)
	admin := adminauth.New(s.DB(), string(s.Provider()))
	w := request(t, admin, session{}, "POST", "/admin/v1/setup", map[string]any{"username": "admin", "email": "admin@example.com", "password": "1234567", "applicationRegistrationPolicy": "closed"})
	var out struct {
		CSRF string `json:"csrfToken"`
	}
	json.Unmarshal(w.Body.Bytes(), &out)
	return New(s.DB(), admin), session{w.Result().Cookies()[0], out.CSRF}
}
func request(t *testing.T, h http.Handler, s session, method, path string, body any) *httptest.ResponseRecorder {
	t.Helper()
	var b bytes.Buffer
	if body != nil {
		json.NewEncoder(&b).Encode(body)
	}
	r := httptest.NewRequest(method, "http://example.test"+path, &b)
	r.Host = "example.test"
	r.Header.Set("Origin", "http://example.test")
	r.Header.Set("X-Trestle-CSRF", s.csrf)
	if s.cookie != nil {
		r.AddCookie(s.cookie)
	}
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	return w
}
func TestCreateOnceScopeExpiryRevocation(t *testing.T) {
	for _, provider := range storetest.Providers(t) {
		t.Run(provider, func(t *testing.T) {
			h, s := setup(t, provider)
			w := request(t, h, s, "POST", "/admin/v1/credentials", map[string]any{"kind": "service", "name": "worker", "scopes": []string{"records:read"}, "expiresAt": time.Now().Add(time.Hour).UTC().Format(time.RFC3339)})
			if w.Code != 201 {
				t.Fatal(w.Body.String())
			}
			var created struct{ ID, Secret string }
			json.Unmarshal(w.Body.Bytes(), &created)
			if !strings.HasPrefix(created.Secret, "tr_") {
				t.Fatal("secret missing")
			}
			w = request(t, h, s, "GET", "/admin/v1/credentials", nil)
			if strings.Contains(w.Body.String(), created.Secret) {
				t.Fatal("secret leaked from list")
			}
			r := httptest.NewRequest("GET", "/", nil)
			r.Header.Set("Authorization", "Bearer "+created.Secret)
			if _, ok := h.Authenticate(r, "records:read"); !ok {
				t.Fatal("valid scope denied")
			}
			if _, ok := h.Authenticate(r, "records:write"); ok {
				t.Fatal("ungranted scope allowed")
			}
			w = request(t, h, s, "DELETE", "/admin/v1/credentials/"+created.ID, nil)
			if w.Code != 204 {
				t.Fatal(w.Code)
			}
			if _, ok := h.Authenticate(r, "records:read"); ok {
				t.Fatal("revoked token accepted")
			}
		})
	}
}
func TestRejectsUnknownScopesAndExpiredCreation(t *testing.T) {
	for _, provider := range storetest.Providers(t) {
		t.Run(provider, func(t *testing.T) {
			h, s := setup(t, provider)
			w := request(t, h, s, "POST", "/admin/v1/credentials", map[string]any{"kind": "service", "name": "bad", "scopes": []string{"admin:all"}})
			if w.Code != 422 {
				t.Fatal(w.Code)
			}
			w = request(t, h, s, "POST", "/admin/v1/credentials", map[string]any{"kind": "personal", "name": "old", "scopes": []string{"records:read"}, "expiresAt": "2020-01-01T00:00:00Z"})
			if w.Code != 422 {
				t.Fatal(w.Code)
			}
		})
	}
}
