package audit

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/trestle-cv/trestle/internal/adminauth"
	"github.com/trestle-cv/trestle/internal/storetest"
)

func adminSession(t *testing.T, admin *adminauth.Handler) (*http.Cookie, string) {
	t.Helper()
	r := httptest.NewRequest("POST", "http://example.test/admin/v1/setup", strings.NewReader(`{"username":"admin","email":"admin@example.com","password":"1234567","applicationRegistrationPolicy":"closed"}`))
	r.Host = "example.test"
	r.Header.Set("Origin", "http://example.test")
	w := httptest.NewRecorder()
	admin.ServeHTTP(w, r)
	var body struct {
		CSRF string `json:"csrfToken"`
	}
	json.Unmarshal(w.Body.Bytes(), &body)
	return w.Result().Cookies()[0], body.CSRF
}

func TestAuditFactsFilterRedactionAndCounts(t *testing.T) {
	for _, provider := range storetest.Providers(t) {
		t.Run(provider, func(t *testing.T) {
			s := storetest.Open(t, provider)
			admin := adminauth.New(s.DB(), string(s.Provider()))
			h := New(s.DB(), admin, string(s.Provider()))
			cookie, csrf := adminSession(t, admin)
			tx, err := s.DB().BeginTx(context.Background(), nil)
			if err != nil {
				t.Fatal(err)
			}
			defer tx.Rollback()
			if err := h.Emit(context.Background(), tx, "admin", "adm_1", "record.delete", "issues/rec_x", "success", "req_1", map[string]any{"password": "super-secret", "token": "tok-secret", "version": 2}); err != nil {
				t.Fatal(err)
			}
			if err := tx.Commit(); err != nil {
				t.Fatal(err)
			}
			get := func(path string) *httptest.ResponseRecorder {
				r := httptest.NewRequest("GET", "http://example.test"+path, nil)
				r.Host = "example.test"
				r.Header.Set("Origin", "http://example.test")
				r.AddCookie(cookie)
				w := httptest.NewRecorder()
				h.ServeHTTP(w, r)
				return w
			}
			list := get("/admin/v1/audit")
			if list.Code != 200 || !strings.Contains(list.Body.String(), "record.delete") {
				t.Fatalf("list %d %s", list.Code, list.Body.String())
			}
			if strings.Contains(list.Body.String(), "super-secret") || strings.Contains(list.Body.String(), "tok-secret") {
				t.Fatalf("secret leaked: %s", list.Body.String())
			}
			filtered := get("/admin/v1/audit?action=record.update")
			if filtered.Code != 200 || strings.Contains(filtered.Body.String(), "record.delete") {
				t.Fatalf("action filter %d %s", filtered.Code, filtered.Body.String())
			}
			ops := get("/admin/v1/operations")
			if ops.Code != 200 {
				t.Fatalf("operations %d", ops.Code)
			}
			var body struct {
				Provider      string `json:"provider"`
				DatabaseBytes any    `json:"databaseBytes"`
			}
			if err := json.Unmarshal(ops.Body.Bytes(), &body); err != nil {
				t.Fatal(err)
			}
			if body.Provider != provider {
				t.Fatalf("provider=%q", body.Provider)
			}
			if _, ok := body.DatabaseBytes.(float64); !ok {
				t.Fatalf("%s databaseBytes=%v", provider, body.DatabaseBytes)
			}
			_ = csrf
		})
	}
}
