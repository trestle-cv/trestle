package jobs

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
	"github.com/trestle-cv/trestle/internal/store"
	"github.com/trestle-cv/trestle/internal/storetest"
)

type failBegin struct{ store.Executor }
type failCommit struct{ store.Executor }
type failCommitTx struct{ store.Transaction }

func (f *failBegin) BeginTx(ctx context.Context, o *sql.TxOptions) (store.Transaction, error) {
	return nil, errors.New("injected begin failure")
}
func (f *failCommit) BeginTx(ctx context.Context, o *sql.TxOptions) (store.Transaction, error) {
	tx, err := f.Executor.BeginTx(ctx, o)
	if err != nil {
		return nil, err
	}
	return &failCommitTx{tx}, nil
}
func (t *failCommitTx) Commit() error { return errors.New("injected commit failure") }

func enqueueJob(h *Handler, cookie *http.Cookie, csrf, payload string) *httptest.ResponseRecorder {
	r := httptest.NewRequest("POST", "http://example.test/admin/v1/jobs", bytes.NewBufferString(payload))
	r.Host = "example.test"
	r.Header.Set("Origin", "http://example.test")
	r.Header.Set("X-Trestle-CSRF", csrf)
	r.AddCookie(cookie)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	return w
}

// TestJobCreationTransactionPaths proves job creation handles begin, enqueue
// and commit failures: a begin failure returns 500 and nothing is written; a
// commit failure returns 500 and rolls back; a successful creation returns 201
// with a durable job row.
func TestJobCreationTransactionPaths(t *testing.T) {
	for _, provider := range storetest.Providers(t) {
		t.Run(provider, func(t *testing.T) {
			s := storetest.Open(t, provider)
			admin := adminauth.New(s.DB(), string(s.Provider()))
			body := strings.NewReader(`{"username":"admin","email":"admin@example.com","password":"correct horse battery staple","applicationRegistrationPolicy":"closed"}`)
			r := httptest.NewRequest("POST", "http://example.test/admin/v1/setup", body)
			r.Host = "example.test"
			r.Header.Set("Origin", "http://example.test")
			w := httptest.NewRecorder()
			admin.ServeHTTP(w, r)
			cookie := w.Result().Cookies()[0]
			var setupResp struct {
				CSRF string `json:"csrfToken"`
			}
			json.Unmarshal(w.Body.Bytes(), &setupResp)

			hBegin := New(&failBegin{s.DB()}, admin)
			if w := enqueueJob(hBegin, cookie, setupResp.CSRF, `{"kind":"noop","payload":{}}`); w.Code != 500 {
				t.Fatalf("begin failure returned %d, want 500", w.Code)
			}
			hCommit := New(&failCommit{s.DB()}, admin)
			if w := enqueueJob(hCommit, cookie, setupResp.CSRF, `{"kind":"noop","payload":{}}`); w.Code != 500 {
				t.Fatalf("commit failure returned %d, want 500", w.Code)
			}
			hOK := New(s.DB(), admin)
			if w := enqueueJob(hOK, cookie, setupResp.CSRF, `{"kind":"noop","payload":{}}`); w.Code != 201 {
				t.Fatalf("success returned %d, want 201", w.Code)
			}
			var count int
			if err := s.DB().QueryRow("SELECT count(*) FROM _trestle_jobs").Scan(&count); err != nil {
				t.Fatal(err)
			}
			if count != 1 {
				t.Fatalf("job rows=%d, want exactly 1 (begin/commit failures must not write)", count)
			}
		})
	}
}

func TestIdempotencyKeyReturnsExistingJob(t *testing.T) {
	for _, provider := range storetest.Providers(t) {
		t.Run(provider, func(t *testing.T) {
			s := storetest.Open(t, provider)
			admin := adminauth.New(s.DB(), string(s.Provider()))
			body := strings.NewReader(`{"username":"admin","email":"admin@example.com","password":"correct horse battery staple","applicationRegistrationPolicy":"closed"}`)
			r := httptest.NewRequest("POST", "http://example.test/admin/v1/setup", body)
			r.Host = "example.test"
			r.Header.Set("Origin", "http://example.test")
			w := httptest.NewRecorder()
			admin.ServeHTTP(w, r)
			cookie := w.Result().Cookies()[0]
			var setupResp struct {
				CSRF string `json:"csrfToken"`
			}
			json.Unmarshal(w.Body.Bytes(), &setupResp)

			h := New(s.DB(), admin)
			first := enqueueJob(h, cookie, setupResp.CSRF, `{"kind":"noop","payload":{},"idempotencyKey":"key-1"}`)
			if first.Code != 201 {
				t.Fatalf("first enqueue returned %d, want 201", first.Code)
			}
			var firstID string
			if err := json.NewDecoder(first.Body).Decode(&struct {
				ID *string `json:"id"`
			}{ID: &firstID}); err != nil {
				t.Fatalf("decode first id: %v", err)
			}
			var rows int
			if err := s.DB().QueryRow("SELECT count(*) FROM _trestle_jobs").Scan(&rows); err != nil || rows != 1 {
				t.Fatalf("rows=%d err=%v", rows, err)
			}

			second := enqueueJob(h, cookie, setupResp.CSRF, `{"kind":"noop","payload":{},"idempotencyKey":"key-1"}`)
			if second.Code != 200 {
				t.Fatalf("idempotent re-enqueue returned %d, want 200", second.Code)
			}
			var secondID string
			if err := json.NewDecoder(second.Body).Decode(&struct {
				ID *string `json:"id"`
			}{ID: &secondID}); err != nil {
				t.Fatalf("decode second id: %v", err)
			}
			if secondID != firstID {
				t.Fatalf("idempotent re-enqueue returned a different id: first=%q second=%q", firstID, secondID)
			}
			if err := s.DB().QueryRow("SELECT count(*) FROM _trestle_jobs").Scan(&rows); err != nil || rows != 1 {
				t.Fatalf("rows after replay=%d err=%v", rows, err)
			}
		})
	}
}
