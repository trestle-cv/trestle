package events

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/trestle-cv/trestle/internal/adminauth"
	"github.com/trestle-cv/trestle/internal/identities"
	"github.com/trestle-cv/trestle/internal/storetest"
)

func emitOne(t *testing.T, h *Handler, n int) {
	t.Helper()
	tx, err := h.db.BeginTx(context.Background(), nil)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback()
	if err := h.Emit(context.Background(), tx, "record.created", "issues", "rec_x", map[string]any{"n": n}); err != nil {
		t.Fatal(err)
	}
	if err := tx.Commit(); err != nil {
		t.Fatal(err)
	}
}

func TestEventSequencingAndGapTolerantReplay(t *testing.T) {
	for _, provider := range storetest.Providers(t) {
		t.Run(provider, func(t *testing.T) {
			s := storetest.Open(t, provider)
			admin := adminauth.New(s.DB(), string(s.Provider()))
			h := New(s.DB(), admin, identities.New(s.DB(), admin))
			for i := 0; i < 5; i++ {
				emitOne(t, h, i)
			}
			items, err := h.read(context.Background(), 0, 100, "")
			if err != nil || len(items) != 5 {
				t.Fatalf("replay len=%d err=%v", len(items), err)
			}
			for i, item := range items {
				if item.Sequence != int64(i+1) {
					t.Fatalf("sequence %d, want %d", item.Sequence, i+1)
				}
			}
			// A numeric gap (deleted event) is not treated as a missing
			// committed event; replay returns the remaining events in order.
			if _, err := s.DB().Exec("DELETE FROM _trestle_events WHERE sequence=3"); err != nil {
				t.Fatal(err)
			}
			items, err = h.read(context.Background(), 2, 100, "")
			if err != nil || len(items) != 2 || items[0].Sequence != 4 {
				t.Fatalf("gap replay len=%d first=%v err=%v", len(items), items[0].Sequence, err)
			}
			// Topic filter.
			items, err = h.read(context.Background(), 0, 100, "record.created")
			if err != nil || len(items) != 4 {
				t.Fatalf("topic filter len=%d err=%v", len(items), err)
			}
		})
	}
}

func TestHeartbeatIsObservableEvent(t *testing.T) {
	var buf strings.Builder
	writeHeartbeat(&buf)
	got := buf.String()
	if !strings.Contains(got, "event: heartbeat") {
		t.Fatalf("heartbeat must be a named SSE event so browser EventSource can observe it, got %q", got)
	}
	if !strings.Contains(got, "data: {}") {
		t.Fatalf("heartbeat must carry a JSON data payload, got %q", got)
	}
	if strings.HasPrefix(got, ": ") {
		t.Fatalf("heartbeat must not be an SSE comment frame (EventSource hides comments), got %q", got)
	}
	if !strings.HasSuffix(got, "\n\n") {
		t.Fatalf("heartbeat must terminate with a blank line, got %q", got)
	}
}

func TestReadyIsObservableEvent(t *testing.T) {
	var buf strings.Builder
	writeReady(&buf)
	got := buf.String()
	if got != "event: ready\ndata: {}\n\n" {
		t.Fatalf("ready must be an immediately observable named SSE event, got %q", got)
	}
}

func TestAuthorizedEventVisibility(t *testing.T) {
	for _, provider := range storetest.Providers(t) {
		t.Run(provider, func(t *testing.T) {
			s := storetest.Open(t, provider)
			admin := adminauth.New(s.DB(), string(s.Provider()))
			h := New(s.DB(), admin, identities.New(s.DB(), admin))
			emitOne(t, h, 1)
			// Unauthenticated list is forbidden.
			w := httptest.NewRecorder()
			h.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/admin/v1/events", nil))
			if w.Code != http.StatusForbidden {
				t.Fatalf("unauthorized list %d", w.Code)
			}
			// Unauthenticated realtime stream is forbidden before streaming.
			w = httptest.NewRecorder()
			h.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/api/v1/realtime", nil))
			if w.Code != http.StatusForbidden {
				t.Fatalf("unauthorized stream %d", w.Code)
			}
			// A service credential with records:read can list.
			credentials := identities.New(s.DB(), admin)
			var setup struct {
				Cookie *http.Cookie
				CSRF   string
			}
			{
				r := httptest.NewRequest("POST", "http://example.test/admin/v1/setup", strings.NewReader(`{"username":"admin","email":"admin@example.com","password":"1234567","applicationRegistrationPolicy":"closed"}`))
				r.Host = "example.test"
				r.Header.Set("Origin", "http://example.test")
				w := httptest.NewRecorder()
				admin.ServeHTTP(w, r)
				var body struct {
					CSRF string `json:"csrfToken"`
				}
				json.Unmarshal(w.Body.Bytes(), &body)
				setup.Cookie = w.Result().Cookies()[0]
				setup.CSRF = body.CSRF
			}
			create := func(method, path string, body any) *httptest.ResponseRecorder {
				var payload []byte
				if body != nil {
					payload, _ = json.Marshal(body)
				}
				r := httptest.NewRequest(method, "http://example.test"+path, strings.NewReader(string(payload)))
				r.Host = "example.test"
				r.Header.Set("Origin", "http://example.test")
				r.Header.Set("X-Trestle-CSRF", setup.CSRF)
				r.AddCookie(setup.Cookie)
				w := httptest.NewRecorder()
				credentials.ServeHTTP(w, r)
				return w
			}
			cred := create("POST", "/admin/v1/credentials", map[string]any{"kind": "service", "name": "realtime", "scopes": []string{"records:read"}})
			var out struct{ Secret string }
			json.Unmarshal(cred.Body.Bytes(), &out)
			r := httptest.NewRequest(http.MethodGet, "/admin/v1/events", nil)
			r.Header.Set("Authorization", "Bearer "+out.Secret)
			w = httptest.NewRecorder()
			h.ServeHTTP(w, r)
			if w.Code != 200 || !strings.Contains(w.Body.String(), "record.created") {
				t.Fatalf("credential list %d %s", w.Code, w.Body.String())
			}
		})
	}
}
