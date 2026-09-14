package rules

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/trestle-cv/trestle/internal/adminauth"
	"github.com/trestle-cv/trestle/internal/collections"
	"github.com/trestle-cv/trestle/internal/storetest"
)

func TestRuleValidationAndEvaluation(t *testing.T) {
	valid := []string{"true", "false", `actor.kind == "user"`, `actor.kind == "service"`, "actor.id == record.owner", "actor.id == input.owner"}
	for _, expr := range valid {
		if err := Validate(expr); err != nil {
			t.Fatalf("%q: %v", expr, err)
		}
	}
	if Validate("actor.id == record.owner; DROP TABLE x") == nil {
		t.Fatal("injection-like rule accepted")
	}
	actor := Actor{ID: "usr_123", Kind: "user"}
	if !Evaluate(`actor.kind == "user"`, actor, nil) || Evaluate(`actor.kind == "service"`, actor, nil) {
		t.Fatal("kind evaluation")
	}
	if !Evaluate("actor.id == record.owner", actor, map[string]any{"owner": "usr_123"}) || Evaluate("actor.id == record.owner", actor, map[string]any{"owner": "usr_other"}) {
		t.Fatal("owner evaluation")
	}
}
func TestExplanationRedaction(t *testing.T) {
	if got := redact("usr_sensitive_identifier"); got == "usr_sensitive_identifier" || got != "usr…er" {
		t.Fatalf("redaction %q", got)
	}
}

func TestRulesStorageAndSimulation(t *testing.T) {
	for _, provider := range storetest.Providers(t) {
		t.Run(provider, func(t *testing.T) {
			s := storetest.Open(t, provider)
			admin := adminauth.New(s.DB(), string(s.Provider()))
			var cookie *http.Cookie
			var csrf string
			{
				var b bytes.Buffer
				json.NewEncoder(&b).Encode(map[string]any{"username": "admin", "email": "admin@example.com", "password": "1234567", "applicationRegistrationPolicy": "closed"})
				r := httptest.NewRequest("POST", "http://example.test/admin/v1/setup", &b)
				r.Host = "example.test"
				r.Header.Set("Origin", "http://example.test")
				w := httptest.NewRecorder()
				admin.ServeHTTP(w, r)
				cookie = w.Result().Cookies()[0]
				var body struct {
					CSRF string `json:"csrfToken"`
				}
				json.Unmarshal(w.Body.Bytes(), &body)
				csrf = body.CSRF
			}
			do := func(h http.Handler, method, path string, body any) *httptest.ResponseRecorder {
				var b bytes.Buffer
				if body != nil {
					json.NewEncoder(&b).Encode(body)
				}
				r := httptest.NewRequest(method, "http://example.test"+path, &b)
				r.Host = "example.test"
				r.Header.Set("Origin", "http://example.test")
				r.Header.Set("X-Trestle-CSRF", csrf)
				r.AddCookie(cookie)
				w := httptest.NewRecorder()
				h.ServeHTTP(w, r)
				return w
			}
			schemas := collections.New(s.DB(), admin)
			if w := do(schemas, "POST", "/admin/v1/collections", map[string]any{"name": "tasks", "fields": []map[string]any{{"name": "owner", "type": "text"}}}); w.Code != 201 {
				t.Fatalf("collection %d %s", w.Code, w.Body.String())
			}
			rh := New(s.DB(), admin)
			if w := do(rh, "PUT", "/admin/v1/collection-rules/tasks", map[string]any{"rules": map[string]string{"view": "actor.id == record.owner"}}); w.Code != 200 {
				t.Fatalf("put rules %d %s", w.Code, w.Body.String())
			}
			if w := do(rh, "GET", "/admin/v1/collection-rules/tasks", nil); w.Code != 200 || !strings.Contains(w.Body.String(), "actor.id == record.owner") {
				t.Fatalf("get rules %d %s", w.Code, w.Body.String())
			}
			if w := do(rh, "POST", "/admin/v1/collection-rules/tasks/explain", map[string]any{"operation": "view", "actor": map[string]any{"id": "usr_1", "kind": "user"}, "values": map[string]any{"owner": "usr_1"}}); w.Code != 200 || !strings.Contains(w.Body.String(), `"allowed":true`) {
				t.Fatalf("explain %d %s", w.Code, w.Body.String())
			}
			allowed, expr, err := rh.Allowed(httptest.NewRequest("GET", "/", nil), "tasks", "view", Actor{ID: "usr_1", Kind: "user"}, map[string]any{"owner": "usr_1"})
			if err != nil || !allowed || !strings.Contains(expr, "record.owner") {
				t.Fatalf("allowed owner err=%v allowed=%v expr=%q", err, allowed, expr)
			}
			if allowed, _, _ := rh.Allowed(httptest.NewRequest("GET", "/", nil), "tasks", "view", Actor{ID: "usr_1", Kind: "user"}, map[string]any{"owner": "usr_other"}); allowed {
				t.Fatal("cross-owner rule allowed")
			}
		})
	}
}
