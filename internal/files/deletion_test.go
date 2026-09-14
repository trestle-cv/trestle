package files

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/trestle-cv/trestle/internal/adminauth"
	"github.com/trestle-cv/trestle/internal/identities"
	"github.com/trestle-cv/trestle/internal/store"
	"github.com/trestle-cv/trestle/internal/storetest"
)

// faultingExecutor fails a chosen boundary: transaction begin, one ExecContext
// matching a substring, or transaction commit.
type faultingExecutor struct {
	store.Executor
	failBegin   bool
	failExec    string
	failCommit  bool
	matchedExec bool
}

func (f *faultingExecutor) BeginTx(ctx context.Context, o *sql.TxOptions) (store.Transaction, error) {
	if f.failBegin {
		return nil, errors.New("injected begin failure")
	}
	tx, err := f.Executor.BeginTx(ctx, o)
	if err != nil {
		return nil, err
	}
	return &faultingTx{Transaction: tx, f: f}, nil
}

func (f *faultingExecutor) ExecContext(ctx context.Context, q string, a ...any) (sql.Result, error) {
	if !f.matchedExec && f.failExec != "" && strings.Contains(q, f.failExec) {
		f.matchedExec = true
		return nil, errors.New("injected exec failure")
	}
	return f.Executor.ExecContext(ctx, q, a...)
}

type faultingTx struct {
	store.Transaction
	f *faultingExecutor
}

func (t *faultingTx) ExecContext(ctx context.Context, q string, a ...any) (sql.Result, error) {
	if !t.f.matchedExec && t.f.failExec != "" && strings.Contains(q, t.f.failExec) {
		t.f.matchedExec = true
		return nil, errors.New("injected exec failure")
	}
	return t.Transaction.ExecContext(ctx, q, a...)
}

func (t *faultingTx) Commit() error {
	if t.f.failCommit {
		return errors.New("injected commit failure")
	}
	return t.Transaction.Commit()
}

// faultingStorage wraps the local object storage and can fail Delete while
// recording which keys were actually removed.
type faultingStorage struct {
	local      objectStorage
	failDelete bool
	deleted    []string
}

func (s *faultingStorage) Put(ctx context.Context, key, staged, contentType string) error {
	return s.local.Put(ctx, key, staged, contentType)
}
func (s *faultingStorage) Serve(w http.ResponseWriter, r *http.Request, key string, m Metadata) error {
	return s.local.Serve(w, r, key, m)
}
func (s *faultingStorage) Delete(ctx context.Context, key string) error {
	if s.failDelete {
		return errors.New("injected storage failure")
	}
	s.deleted = append(s.deleted, key)
	return s.local.Delete(ctx, key)
}
func (s *faultingStorage) Cleanup(ctx context.Context, known map[string]bool) (int, error) {
	return s.local.Cleanup(ctx, known)
}

// openStoreFixture opens one provider store, creates the administrator, and
// returns a fixture bound to a handler over that exact store plus the store and
// data directory (so a restart can be modelled over the same database).
func openStoreFixture(t *testing.T, provider string) (fixture, *store.Store, string) {
	t.Helper()
	dir := t.TempDir()
	s := storetest.Open(t, provider)
	admin := adminauth.New(s.DB(), string(s.Provider()))
	body := strings.NewReader(`{"username":"admin","email":"admin@example.com","password":"1234567","applicationRegistrationPolicy":"closed"}`)
	r := httptest.NewRequest("POST", "http://example.test/admin/v1/setup", body)
	r.Host = "example.test"
	r.Header.Set("Origin", "http://example.test")
	w := httptest.NewRecorder()
	admin.ServeHTTP(w, r)
	var session struct {
		CSRF string `json:"csrfToken"`
	}
	json.Unmarshal(w.Body.Bytes(), &session)
	h, err := New(s.DB(), admin, identities.New(s.DB(), admin), dir)
	if err != nil {
		t.Fatal(err)
	}
	return fixture{h, w.Result().Cookies()[0], session.CSRF}, s, dir
}

// handlerOn builds a handler over an existing store and data directory with an
// optional executor and storage, sharing the same administrator/session.
func handlerOn(t *testing.T, s *store.Store, admin *adminauth.Handler, dir string, executor store.Executor, storage objectStorage) *Handler {
	t.Helper()
	var db store.Executor = s.DB()
	if executor != nil {
		db = executor
	}
	h, err := New(db, admin, identities.New(db, admin), dir)
	if err != nil {
		t.Fatal(err)
	}
	if storage != nil {
		h.storage = storage
	}
	return h
}

func deletionRows(t *testing.T, h *Handler, query string) int {
	t.Helper()
	var count int
	if err := h.db.QueryRow(query).Scan(&count); err != nil {
		t.Fatal(err)
	}
	return count
}

func objectExists(t *testing.T, h *Handler, key string) bool {
	t.Helper()
	_, err := os.Stat(filepath.Join(h.root, key))
	return err == nil
}

// TestFileDeletionDurableStateMachine proves the happy path and idempotence:
// deletion durably unavails the file, removes the object, finalizes the intent,
// and repeated deletion stays idempotent.
func TestFileDeletionDurableStateMachine(t *testing.T) {
	for _, provider := range storetest.Providers(t) {
		t.Run(provider, func(t *testing.T) {
			f, s, _ := openStoreFixture(t, provider)
			m := f.upload(t, "a.txt", "content")
			var key string
			if err := s.DB().QueryRow("SELECT storage_key FROM _trestle_files WHERE id=?", m.ID).Scan(&key); err != nil {
				t.Fatal(err)
			}
			w := f.request("DELETE", "/api/v1/files/"+m.ID, nil, "")
			if w.Code != 204 {
				t.Fatalf("delete %d %s", w.Code, w.Body.String())
			}
			if deletionRows(t, f.h, "SELECT count(*) FROM _trestle_file_deletions WHERE id='"+m.ID+"' AND status='done'") != 1 {
				t.Fatal("deletion intent was not finalized")
			}
			if objectExists(t, f.h, key) {
				t.Fatal("storage object still exists after deletion")
			}
			if w := f.request("GET", "/api/v1/files/"+m.ID, nil, ""); w.Code != 404 {
				t.Fatalf("download after delete %d", w.Code)
			}
			if w := f.request("DELETE", "/api/v1/files/"+m.ID, nil, ""); w.Code != 204 {
				t.Fatalf("repeated delete %d %s", w.Code, w.Body.String())
			}
			if deletionRows(t, f.h, "SELECT count(*) FROM _trestle_file_deletions WHERE id='"+m.ID+"'") != 1 {
				t.Fatal("repeated deletion duplicated the intent")
			}
		})
	}
}

// TestFileDeletionBoundaryFailures covers begin, intent-write and commit
// failures with the faulting executor: each must return an error and change
// nothing externally (file still downloadable, object intact, no intent row).
func TestFileDeletionBoundaryFailures(t *testing.T) {
	cases := []struct {
		name string
		mut  func(*faultingExecutor)
	}{
		{"begin", func(f *faultingExecutor) { f.failBegin = true }},
		{"intent write", func(f *faultingExecutor) { f.failExec = "INSERT INTO _trestle_file_deletions" }},
		{"commit", func(f *faultingExecutor) { f.failCommit = true }},
	}
	for _, provider := range storetest.Providers(t) {
		for _, tc := range cases {
			t.Run(provider+"/"+tc.name, func(t *testing.T) {
				normal, s, dir := openStoreFixture(t, provider)
				admin := adminauth.New(s.DB(), string(s.Provider()))
				m := normal.upload(t, "x.txt", "payload")
				var key string
				if err := s.DB().QueryRow("SELECT storage_key FROM _trestle_files WHERE id=?", m.ID).Scan(&key); err != nil {
					t.Fatal(err)
				}

				fault := &faultingExecutor{Executor: s.DB()}
				tc.mut(fault)
				faultHandler := handlerOn(t, s, admin, dir, fault, nil)
				del := (&fixture{faultHandler, normal.cookie, normal.csrf}).request("DELETE", "/api/v1/files/"+m.ID, nil, "")
				if del.Code != 500 {
					t.Fatalf("injected %s: status=%d body=%s", tc.name, del.Code, del.Body.String())
				}
				if w := normal.request("GET", "/api/v1/files/"+m.ID, nil, ""); w.Code != 200 {
					t.Fatalf("file not downloadable after %s: %d", tc.name, w.Code)
				}
				if deletionRows(t, normal.h, "SELECT count(*) FROM _trestle_file_deletions") != 0 {
					t.Fatalf("%s left a deletion intent", tc.name)
				}
				if !objectExists(t, normal.h, key) {
					t.Fatalf("%s deleted the object without durable intent", tc.name)
				}
			})
		}
	}
}

// TestFileDeletionStorageFailureLeavesPendingAndResumes models a storage
// deletion failure after durable intent (and therefore an interruption between
// intent and storage deletion). The deletion stays pending and unavailable, and
// a restart-time resume finalizes it; duplicate resume runs are idempotent.
func TestFileDeletionStorageFailureLeavesPendingAndResumes(t *testing.T) {
	for _, provider := range storetest.Providers(t) {
		t.Run(provider, func(t *testing.T) {
			f, s, dir := openStoreFixture(t, provider)
			admin := adminauth.New(s.DB(), string(s.Provider()))
			m := f.upload(t, "y.txt", "bytes")
			var key string
			if err := s.DB().QueryRow("SELECT storage_key FROM _trestle_files WHERE id=?", m.ID).Scan(&key); err != nil {
				t.Fatal(err)
			}

			original := f.h.storage
			bad := &faultingStorage{local: original, failDelete: true}
			f.h.storage = bad
			del := f.request("DELETE", "/api/v1/files/"+m.ID, nil, "")
			if del.Code != 500 || !strings.Contains(del.Body.String(), "deletion_pending") {
				t.Fatalf("storage failure status=%d body=%s", del.Code, del.Body.String())
			}
			if deletionRows(t, f.h, "SELECT count(*) FROM _trestle_file_deletions WHERE id='"+m.ID+"' AND status='pending'") != 1 {
				t.Fatal("deletion intent missing after storage failure")
			}
			if w := f.request("GET", "/api/v1/files/"+m.ID, nil, ""); w.Code != 404 {
				t.Fatalf("file still served after durable intent: %d", w.Code)
			}
			if !objectExists(t, f.h, key) {
				t.Fatal("object was deleted before storage success")
			}

			// "Restart": a fresh handler over the same database and storage
			// resumes pending deletions.
			restarted := handlerOn(t, s, admin, dir, nil, &faultingStorage{local: original})
			processed, err := restarted.ResumePendingDeletions(context.Background())
			if err != nil || processed != 1 {
				t.Fatalf("resume processed=%d err=%v", processed, err)
			}
			if objectExists(t, restarted, key) {
				t.Fatal("object still exists after resume")
			}
			if deletionRows(t, restarted, "SELECT count(*) FROM _trestle_file_deletions WHERE id='"+m.ID+"' AND status='done'") != 1 {
				t.Fatal("intent not finalized after resume")
			}
			again, err := restarted.ResumePendingDeletions(context.Background())
			if err != nil || again != 0 {
				t.Fatalf("duplicate resume processed=%d err=%v", again, err)
			}
		})
	}
}

// TestFileDeletionFinalizeFailureRecovers models a crash between storage
// deletion and finalization: the object is gone but the intent is still
// pending, and resume converges (idempotent storage delete + finalize).
func TestFileDeletionFinalizeFailureRecovers(t *testing.T) {
	for _, provider := range storetest.Providers(t) {
		t.Run(provider, func(t *testing.T) {
			normal, s, dir := openStoreFixture(t, provider)
			admin := adminauth.New(s.DB(), string(s.Provider()))
			m := normal.upload(t, "z.txt", "final")
			var key string
			if err := s.DB().QueryRow("SELECT storage_key FROM _trestle_files WHERE id=?", m.ID).Scan(&key); err != nil {
				t.Fatal(err)
			}

			// Handler whose storage succeeds but whose finalize UPDATE fails.
			fault := &faultingExecutor{Executor: s.DB(), failExec: "SET status='done'"}
			faultHandler := handlerOn(t, s, admin, dir, fault, nil)
			faultFixture := fixture{faultHandler, normal.cookie, normal.csrf}
			del := faultFixture.request("DELETE", "/api/v1/files/"+m.ID, nil, "")
			if del.Code != 500 {
				t.Fatalf("finalize failure status=%d body=%s", del.Code, del.Body.String())
			}
			if objectExists(t, faultHandler, key) {
				t.Fatal("object was not deleted before finalize failure")
			}
			if deletionRows(t, faultHandler, "SELECT count(*) FROM _trestle_file_deletions WHERE id='"+m.ID+"' AND status='pending'") != 1 {
				t.Fatal("intent should still be pending after finalize failure")
			}

			restarted := handlerOn(t, s, admin, dir, nil, nil)
			processed, err := restarted.ResumePendingDeletions(context.Background())
			if err != nil || processed != 1 {
				t.Fatalf("resume processed=%d err=%v", processed, err)
			}
			if deletionRows(t, restarted, "SELECT count(*) FROM _trestle_file_deletions WHERE id='"+m.ID+"' AND status='done'") != 1 {
				t.Fatal("intent not finalized after resume")
			}
		})
	}
}

// TestResumeCleansRestoredDeletedFiles: a file whose deletion was pending in an
// archive (metadata deleted_at set, no intent row, bytes restored) is cleaned
// up by the resume sweep without touching any live file.
func TestResumeCleansRestoredDeletedFiles(t *testing.T) {
	for _, provider := range storetest.Providers(t) {
		t.Run(provider, func(t *testing.T) {
			f, s, _ := openStoreFixture(t, provider)
			live := f.upload(t, "live.txt", "live")
			var liveKey string
			if err := s.DB().QueryRow("SELECT storage_key FROM _trestle_files WHERE id=?", live.ID).Scan(&liveKey); err != nil {
				t.Fatal(err)
			}
			deletedKey := "restored-deleted-key"
			if err := os.WriteFile(filepath.Join(f.h.root, deletedKey), []byte("orphan"), 0o600); err != nil {
				t.Fatal(err)
			}
			if _, err := s.DB().Exec("INSERT INTO _trestle_files(id,storage_key,original_name,content_type,size,sha256,collection_name,record_id,created_at,deleted_at) VALUES(?,?,?,?,?,?,?,?,?,?)", "fil_restored", deletedKey, "old.txt", "text/plain", 6, "x", nil, nil, "2026-01-01T00:00:00Z", "2026-01-02T00:00:00Z"); err != nil {
				t.Fatal(err)
			}

			processed, err := f.h.ResumePendingDeletions(context.Background())
			if err != nil {
				t.Fatal(err)
			}
			if processed != 1 {
				t.Fatalf("resume processed=%d, want 1", processed)
			}
			if objectExists(t, f.h, deletedKey) {
				t.Fatal("restored deleted object not cleaned")
			}
			if !objectExists(t, f.h, liveKey) {
				t.Fatal("live object was deleted by the sweep")
			}
		})
	}
}

// TestFileDeletionSweepNeverDeletesLiveMetadata proves the fail-closed target
// selection: a pending deletion intent paired with live metadata never deletes
// the storage object, whether the live reference is the same file id or any
// other live file sharing the storage key.
func TestFileDeletionSweepNeverDeletesLiveMetadata(t *testing.T) {
	for _, provider := range storetest.Providers(t) {
		t.Run(provider, func(t *testing.T) {
			f, s, _ := openStoreFixture(t, provider)

			// Case A: pending intent for a file whose metadata is still live
			// (same id). Case B: a pending intent under another id that
			// references the same live storage key.
			m := f.upload(t, "a.txt", "same-id")
			var key string
			if err := s.DB().QueryRow("SELECT storage_key FROM _trestle_files WHERE id=?", m.ID).Scan(&key); err != nil {
				t.Fatal(err)
			}
			if _, err := s.DB().Exec("INSERT INTO _trestle_file_deletions(id,storage_key,status,attempts,created_at) VALUES(?,?,'pending',0,'2026-01-01T00:00:00Z') ON CONFLICT(id) DO NOTHING", m.ID, key); err != nil {
				t.Fatal(err)
			}
			if _, err := s.DB().Exec("INSERT INTO _trestle_file_deletions(id,storage_key,status,attempts,created_at) VALUES(?,?,'pending',0,'2026-01-01T00:00:00Z') ON CONFLICT(id) DO NOTHING", "fil_cross", key); err != nil {
				t.Fatal(err)
			}

			processed, err := f.h.ResumePendingDeletions(context.Background())
			if err != nil {
				t.Fatal(err)
			}
			if processed != 0 {
				t.Fatalf("sweep processed %d targets, want 0", processed)
			}
			if !objectExists(t, f.h, key) {
				t.Fatal("object deleted despite live metadata (same id or cross-file key reference)")
			}
			if deletionRows(t, f.h, "SELECT count(*) FROM _trestle_file_deletions WHERE status='pending'") != 2 {
				t.Fatal("conflicted intents were finalized")
			}
		})
	}
}

// TestFileDeletionSweepProceedsForDeletedOrAbsentMetadata proves that pending
// intents with deleted metadata or absent metadata are processed.
func TestFileDeletionSweepProceedsForDeletedOrAbsentMetadata(t *testing.T) {
	for _, provider := range storetest.Providers(t) {
		t.Run(provider, func(t *testing.T) {
			f, s, _ := openStoreFixture(t, provider)

			// Deleted metadata: object removed and intent finalized.
			m := f.upload(t, "d.txt", "deleted")
			var key string
			if err := s.DB().QueryRow("SELECT storage_key FROM _trestle_files WHERE id=?", m.ID).Scan(&key); err != nil {
				t.Fatal(err)
			}
			if _, err := s.DB().Exec("UPDATE _trestle_files SET deleted_at=? WHERE id=?", "2026-01-01T00:00:00Z", m.ID); err != nil {
				t.Fatal(err)
			}
			if _, err := s.DB().Exec("INSERT INTO _trestle_file_deletions(id,storage_key,status,attempts,created_at) VALUES(?,?,'pending',0,'2026-01-01T00:00:00Z') ON CONFLICT(id) DO NOTHING", m.ID, key); err != nil {
				t.Fatal(err)
			}

			// Absent metadata: an orphan object with a pending intent only.
			orphanKey := "orphan-key"
			if err := os.WriteFile(filepath.Join(f.h.root, orphanKey), []byte("orphan"), 0o600); err != nil {
				t.Fatal(err)
			}
			if _, err := s.DB().Exec("INSERT INTO _trestle_file_deletions(id,storage_key,status,attempts,created_at) VALUES('fil_orphan',?,'pending',0,'2026-01-01T00:00:00Z') ON CONFLICT(id) DO NOTHING", orphanKey); err != nil {
				t.Fatal(err)
			}

			processed, err := f.h.ResumePendingDeletions(context.Background())
			if err != nil {
				t.Fatal(err)
			}
			if processed != 2 {
				t.Fatalf("sweep processed %d, want 2", processed)
			}
			if objectExists(t, f.h, key) || objectExists(t, f.h, orphanKey) {
				t.Fatal("objects with deleted/absent metadata were not removed")
			}
			if deletionRows(t, f.h, "SELECT count(*) FROM _trestle_file_deletions WHERE status='done'") != 2 {
				t.Fatal("intents not finalized")
			}
		})
	}
}

// TestFileDeletionConflictRemainsRecoverable proves a conflicted intent stays
// pending and is processed once the live reference is deliberately resolved.
func TestFileDeletionConflictRemainsRecoverable(t *testing.T) {
	for _, provider := range storetest.Providers(t) {
		t.Run(provider, func(t *testing.T) {
			f, s, _ := openStoreFixture(t, provider)
			live := f.upload(t, "live.txt", "live")
			var liveKey string
			if err := s.DB().QueryRow("SELECT storage_key FROM _trestle_files WHERE id=?", live.ID).Scan(&liveKey); err != nil {
				t.Fatal(err)
			}
			// Conflicted intent referencing the live file's key under another id.
			if _, err := s.DB().Exec("INSERT INTO _trestle_file_deletions(id,storage_key,status,attempts,created_at) VALUES('fil_conflict',?,'pending',0,'2026-01-01T00:00:00Z') ON CONFLICT(id) DO NOTHING", liveKey); err != nil {
				t.Fatal(err)
			}

			processed, err := f.h.ResumePendingDeletions(context.Background())
			if err != nil || processed != 0 {
				t.Fatalf("initial resume processed=%d err=%v, want 0", processed, err)
			}
			if deletionRows(t, f.h, "SELECT count(*) FROM _trestle_file_deletions WHERE id='fil_conflict' AND status='pending'") != 1 {
				t.Fatal("conflicted intent was not left pending")
			}

			// Resolve the live reference, then recovery proceeds.
			if w := f.request("DELETE", "/api/v1/files/"+live.ID, nil, ""); w.Code != 204 {
				t.Fatalf("resolve delete %d %s", w.Code, w.Body.String())
			}
			processed, err = f.h.ResumePendingDeletions(context.Background())
			if err != nil || processed != 1 {
				t.Fatalf("post-resolution resume processed=%d err=%v, want 1", processed, err)
			}
			if deletionRows(t, f.h, "SELECT count(*) FROM _trestle_file_deletions WHERE id='fil_conflict' AND status='done'") != 1 {
				t.Fatal("conflicted intent not finalized after resolution")
			}
		})
	}
}

// TestFileDeletionConcurrentRecoveryHarmless proves duplicate or concurrent
// recovery runs are harmless: the object is removed once and the intent is
// finalized once.
func TestFileDeletionConcurrentRecoveryHarmless(t *testing.T) {
	for _, provider := range storetest.Providers(t) {
		t.Run(provider, func(t *testing.T) {
			f, s, _ := openStoreFixture(t, provider)
			m := f.upload(t, "c.txt", "concurrent")
			var key string
			if err := s.DB().QueryRow("SELECT storage_key FROM _trestle_files WHERE id=?", m.ID).Scan(&key); err != nil {
				t.Fatal(err)
			}
			if _, err := s.DB().Exec("UPDATE _trestle_files SET deleted_at=? WHERE id=?", "2026-01-01T00:00:00Z", m.ID); err != nil {
				t.Fatal(err)
			}
			if _, err := s.DB().Exec("INSERT INTO _trestle_file_deletions(id,storage_key,status,attempts,created_at) VALUES(?,?,'pending',0,'2026-01-01T00:00:00Z') ON CONFLICT(id) DO NOTHING", m.ID, key); err != nil {
				t.Fatal(err)
			}

			var wg sync.WaitGroup
			errs := make(chan error, 2)
			for i := 0; i < 2; i++ {
				wg.Add(1)
				go func() {
					defer wg.Done()
					_, err := f.h.ResumePendingDeletions(context.Background())
					errs <- err
				}()
			}
			wg.Wait()
			close(errs)
			for err := range errs {
				if err != nil {
					t.Fatal(err)
				}
			}
			if objectExists(t, f.h, key) {
				t.Fatal("object still exists after concurrent recovery")
			}
			if deletionRows(t, f.h, "SELECT count(*) FROM _trestle_file_deletions WHERE id='"+m.ID+"' AND status='done'") != 1 {
				t.Fatal("intent finalized more than once")
			}
		})
	}
}

// TestDeletionRecoveryWorkerProcessesPending proves the bounded periodic worker
// resumes pending deletion during a continuously running process and stops on
// shutdown.
func TestDeletionRecoveryWorkerProcessesPending(t *testing.T) {
	for _, provider := range storetest.Providers(t) {
		t.Run(provider, func(t *testing.T) {
			f, s, _ := openStoreFixture(t, provider)
			m := f.upload(t, "w.txt", "worker")
			var key string
			if err := s.DB().QueryRow("SELECT storage_key FROM _trestle_files WHERE id=?", m.ID).Scan(&key); err != nil {
				t.Fatal(err)
			}
			if _, err := s.DB().Exec("UPDATE _trestle_files SET deleted_at=? WHERE id=?", "2026-01-01T00:00:00Z", m.ID); err != nil {
				t.Fatal(err)
			}
			if _, err := s.DB().Exec("INSERT INTO _trestle_file_deletions(id,storage_key,status,attempts,created_at) VALUES(?,?,'pending',0,'2026-01-01T00:00:00Z') ON CONFLICT(id) DO NOTHING", m.ID, key); err != nil {
				t.Fatal(err)
			}

			ctx, cancel := context.WithCancel(context.Background())
			done := make(chan struct{})
			go func() {
				f.h.RunDeletionRecovery(ctx, 20*time.Millisecond)
				close(done)
			}()

			deadline := time.Now().Add(3 * time.Second)
			for time.Now().Before(deadline) {
				if deletionRows(t, f.h, "SELECT count(*) FROM _trestle_file_deletions WHERE id='"+m.ID+"' AND status='done'") == 1 {
					break
				}
				time.Sleep(20 * time.Millisecond)
			}
			if deletionRows(t, f.h, "SELECT count(*) FROM _trestle_file_deletions WHERE id='"+m.ID+"' AND status='done'") != 1 {
				t.Fatal("worker did not finalize the pending deletion")
			}
			if objectExists(t, f.h, key) {
				t.Fatal("worker did not remove the object")
			}

			cancel()
			select {
			case <-done:
			case <-time.After(2 * time.Second):
				t.Fatal("recovery worker did not stop on shutdown")
			}
		})
	}
}
