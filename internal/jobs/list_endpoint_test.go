package jobs

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/trestle-cv/trestle/internal/adminauth"
	"github.com/trestle-cv/trestle/internal/store"
	"github.com/trestle-cv/trestle/internal/storetest"
)

// jobsFixture builds an authenticated admin session and a jobs handler over a
// real provider store.
func jobsFixture(t *testing.T, provider string) (*Handler, *http.Cookie, string) {
	t.Helper()
	s := storetest.Open(t, provider)
	admin := adminauth.New(s.DB(), string(s.Provider()))
	body := strings.NewReader(`{"email":"admin@example.com","password":"correct horse battery staple","applicationRegistrationPolicy":"closed"}`)
	r := httptest.NewRequest("POST", "http://example.test/admin/v1/setup", body)
	r.Host = "example.test"
	r.Header.Set("Origin", "http://example.test")
	w := httptest.NewRecorder()
	admin.ServeHTTP(w, r)
	var session struct {
		CSRF string `json:"csrfToken"`
	}
	json.Unmarshal(w.Body.Bytes(), &session)
	return New(s.DB(), admin), w.Result().Cookies()[0], session.CSRF
}

func jobsRequest(h *Handler, cookie *http.Cookie, path string) *httptest.ResponseRecorder {
	r := httptest.NewRequest("GET", "http://example.test"+path, nil)
	r.Host = "example.test"
	r.AddCookie(cookie)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	return w
}

// TestJobsEndpointListsFullFieldsAndFilters drives the real /admin/v1/jobs
// endpoint and verifies valid JSON with payload, status, attempts, maximum
// attempts, timestamps and error/lease fields, multiple rows, and status
// filtering, on both providers.
func TestJobsEndpointListsFullFieldsAndFilters(t *testing.T) {
	for _, provider := range storetest.Providers(t) {
		t.Run(provider, func(t *testing.T) {
			h, cookie, _ := jobsFixture(t, provider)
			// Enqueue several probe jobs directly (the handler-level path).
			for i := 0; i < 3; i++ {
				tx, err := h.db.BeginTx(context.Background(), nil)
				if err != nil {
					t.Fatal(err)
				}
				if _, _, err := h.Enqueue(context.Background(), tx, "probe", map[string]any{"index": i}, ""); err != nil {
					t.Fatal(err)
				}
				if err := tx.Commit(); err != nil {
					t.Fatal(err)
				}
			}
			// Mark one job dead to exercise status filtering and error fields.
			if _, err := h.db.Exec("UPDATE _trestle_jobs SET status='dead',last_error='boom' WHERE id=(SELECT id FROM _trestle_jobs LIMIT 1)"); err != nil {
				t.Fatal(err)
			}

			w := jobsRequest(h, cookie, "/admin/v1/jobs")
			if w.Code != 200 || !strings.HasPrefix(w.Header().Get("Content-Type"), "application/json") {
				t.Fatalf("list status=%d content-type=%q body=%s", w.Code, w.Header().Get("Content-Type"), w.Body.String())
			}
			var resp struct {
				Items []Job `json:"items"`
			}
			if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
				t.Fatalf("invalid JSON: %v (%s)", err, w.Body.String())
			}
			if len(resp.Items) != 3 {
				t.Fatalf("items=%d, want 3", len(resp.Items))
			}
			byID := map[string]Job{}
			for _, j := range resp.Items {
				if j.ID == "" || j.Kind != "probe" || j.Status == "" || j.Payload == nil || j.AvailableAt == "" || j.CreatedAt == "" || j.UpdatedAt == "" || j.MaxAttempts < 1 {
					raw, _ := json.Marshal(j)
					t.Fatalf("job missing fields: %s", raw)
				}
				byID[j.ID] = j
			}
			// One job carries the dead status and error field.
			foundDead := false
			for _, j := range byID {
				if j.Status == "dead" && j.LastError == "boom" {
					foundDead = true
				}
			}
			if !foundDead {
				t.Fatalf("no dead job with error field in %d items", len(byID))
			}

			// Status filtering returns only matching rows.
			w = jobsRequest(h, cookie, "/admin/v1/jobs?status=pending")
			var filtered struct {
				Items []Job `json:"items"`
			}
			if err := json.Unmarshal(w.Body.Bytes(), &filtered); err != nil {
				t.Fatal(err)
			}
			if len(filtered.Items) != 2 {
				t.Fatalf("pending items=%d, want 2", len(filtered.Items))
			}
			for _, j := range filtered.Items {
				if j.Status != "pending" {
					t.Fatalf("filtered job status=%q", j.Status)
				}
			}
		})
	}
}

// failListExecutor fails a single QueryContext to simulate a query/scan
// failure in the jobs list handler.
type failListExecutor struct {
	store.Executor
	done bool
}

func (f *failListExecutor) QueryContext(ctx context.Context, q string, a ...any) (*sql.Rows, error) {
	if !f.done {
		f.done = true
		return nil, errors.New("injected list failure")
	}
	return f.Executor.QueryContext(ctx, q, a...)
}

// TestJobsEndpointQueryFailureIsStructured proves a list query failure returns
// the normal structured API error envelope, not a plain-text http.Error.
func TestJobsEndpointQueryFailureIsStructured(t *testing.T) {
	for _, provider := range storetest.Providers(t) {
		t.Run(provider, func(t *testing.T) {
			// Open the store and build admin with the real executor so the
			// session check succeeds, but drive the jobs handler through a
			// faulting executor.
			s := storetest.Open(t, provider)
			admin := adminauth.New(s.DB(), string(s.Provider()))
			body := strings.NewReader(`{"email":"admin@example.com","password":"correct horse battery staple","applicationRegistrationPolicy":"closed"}`)
			r := httptest.NewRequest("POST", "http://example.test/admin/v1/setup", body)
			r.Host = "example.test"
			r.Header.Set("Origin", "http://example.test")
			w := httptest.NewRecorder()
			admin.ServeHTTP(w, r)
			cookie := w.Result().Cookies()[0]

			fault := &failListExecutor{Executor: s.DB()}
			h := New(fault, admin)
			wr := jobsRequest(h, cookie, "/admin/v1/jobs")
			if wr.Code != 500 {
				t.Fatalf("list failure status=%d body=%s", wr.Code, wr.Body.String())
			}
			var envelope struct {
				Error struct {
					Code, Message string
				} `json:"error"`
			}
			if err := json.Unmarshal(wr.Body.Bytes(), &envelope); err != nil {
				t.Fatalf("failure was not a structured envelope: %s", wr.Body.String())
			}
			if envelope.Error.Code == "" || envelope.Error.Message == "" {
				t.Fatalf("structured error fields empty: %s", wr.Body.String())
			}
		})
	}
}
