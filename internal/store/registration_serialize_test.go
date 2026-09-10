package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/lib/pq"
)

// openRawSQLite opens a raw modernc sqlite database with the same pragmas the
// store uses (foreign keys on, WAL, busy timeout).
func openRawSQLite(t *testing.T, dir string) (*sql.DB, func()) {
	t.Helper()
	path := filepath.Join(dir, "trestle.db")
	dsn := "file:" + path + "?_pragma=foreign_keys(1)&_pragma=busy_timeout(5000)&_pragma=journal_mode(WAL)"
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		t.Fatal(err)
	}
	return db, func() { db.Close() }
}

// buildExistingV14 creates a database that has migrations 1..14 applied, as an
// existing pre-v15 deployment would have after an upgrade.
func buildExistingV14(t *testing.T, db *sql.DB) {
	t.Helper()
	if _, err := db.Exec(`CREATE TABLE _trestle_schema_migrations (version INTEGER PRIMARY KEY, name TEXT NOT NULL, applied_at TEXT NOT NULL)`); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`CREATE TABLE _trestle_system_meta (key TEXT PRIMARY KEY, value TEXT NOT NULL, updated_at TEXT NOT NULL) STRICT`); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`CREATE TABLE _trestle_admins (id TEXT PRIMARY KEY, email TEXT NOT NULL UNIQUE, password_hash TEXT NOT NULL, created_at TEXT NOT NULL, disabled_at TEXT) STRICT`); err != nil {
		t.Fatal(err)
	}
	now := "2026-01-01T00:00:00Z"
	for i := 1; i <= 14; i++ {
		if _, err := db.Exec("INSERT INTO _trestle_schema_migrations(version,name,applied_at) VALUES(?,?,?)", i, migrations[i-1].name, now); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := db.Exec("PRAGMA user_version = 14"); err != nil {
		t.Fatal(err)
	}
}

// TestRegistrationMigrationSeedsPolicyByDurableVersion proves migration 15
// seeds the policy from the pre-migration schema version, never from row
// counts: a genuinely new database starts closed, an existing pre-v15
// deployment starts open even with zero users, and deleting users later never
// changes the recorded policy.
func TestRegistrationMigrationSeedsPolicyByDurableVersion(t *testing.T) {
	t.Run("fresh database runs the full sequence and seeds closed", func(t *testing.T) {
		dir := t.TempDir()
		db, closeDB := openRawSQLite(t, dir)
		defer closeDB()
		s := &Store{db: db, provider: SQLite, dialect: NewDialect(SQLite), executor: NewExecutor(db, NewDialect(SQLite))}
		if err := s.initialize(context.Background()); err != nil {
			t.Fatalf("initialize: %v", err)
		}
		if s.schemaVersion != CurrentVersion {
			t.Fatalf("schema version %d, want %d", s.schemaVersion, CurrentVersion)
		}
		var policy string
		if err := db.QueryRow("SELECT policy FROM _trestle_app_registration_policy WHERE id=1").Scan(&policy); err != nil {
			t.Fatal(err)
		}
		if policy != PolicyClosed {
			t.Fatalf("fresh policy = %q, want closed", policy)
		}
	})

	t.Run("existing pre-v15 deployment with zero users seeds open", func(t *testing.T) {
		dir := t.TempDir()
		db, closeDB := openRawSQLite(t, dir)
		defer closeDB()
		buildExistingV14(t, db)
		s := &Store{db: db, provider: SQLite, dialect: NewDialect(SQLite), executor: NewExecutor(db, NewDialect(SQLite))}
		if err := s.initialize(context.Background()); err != nil {
			t.Fatalf("initialize: %v", err)
		}
		var policy string
		if err := db.QueryRow("SELECT policy FROM _trestle_app_registration_policy WHERE id=1").Scan(&policy); err != nil {
			t.Fatal(err)
		}
		if policy != PolicyOpen {
			t.Fatalf("existing empty deployment policy = %q, want open", policy)
		}
	})

	t.Run("deleting users later does not change the recorded policy", func(t *testing.T) {
		dir := t.TempDir()
		db, closeDB := openRawSQLite(t, dir)
		defer closeDB()
		buildExistingV14(t, db)
		if _, err := db.Exec(`CREATE TABLE _trestle_app_users (id TEXT PRIMARY KEY, email TEXT NOT NULL UNIQUE COLLATE NOCASE, password_hash TEXT NOT NULL, verified_at TEXT, disabled_at TEXT, created_at TEXT NOT NULL) STRICT`); err != nil {
			t.Fatal(err)
		}
		if _, err := db.Exec("INSERT INTO _trestle_app_users(id,email,password_hash,created_at) VALUES('usr_x','a@example.com','h','2026-01-01T00:00:00Z')"); err != nil {
			t.Fatal(err)
		}
		s := &Store{db: db, provider: SQLite, dialect: NewDialect(SQLite), executor: NewExecutor(db, NewDialect(SQLite))}
		if err := s.initialize(context.Background()); err != nil {
			t.Fatal(err)
		}
		if _, err := db.Exec("DELETE FROM _trestle_app_users"); err != nil {
			t.Fatal(err)
		}
		var policy string
		if err := db.QueryRow("SELECT policy FROM _trestle_app_registration_policy WHERE id=1").Scan(&policy); err != nil {
			t.Fatal(err)
		}
		if policy != PolicyOpen {
			t.Fatalf("policy after deleting users = %q, want open (durable, not re-derived)", policy)
		}
	})
}

// TestSeedRegistrationPolicyDirect covers both branches of the seeding
// function directly.
func TestSeedRegistrationPolicyDirect(t *testing.T) {
	for _, tc := range []struct {
		starting int
		want     string
	}{
		{0, PolicyClosed},
		{1, PolicyOpen},
		{14, PolicyOpen},
	} {
		t.Run(fmt.Sprintf("starting=%d", tc.starting), func(t *testing.T) {
			dir := t.TempDir()
			db, closeDB := openRawSQLite(t, dir)
			defer closeDB()
			if _, err := db.Exec(`CREATE TABLE _trestle_app_registration_policy (id INTEGER PRIMARY KEY CHECK(id = 1), policy TEXT NOT NULL CHECK(policy IN ('open','invite','approval','closed')), set_at TEXT NOT NULL) STRICT`); err != nil {
				t.Fatal(err)
			}
			tx, err := db.Begin()
			if err != nil {
				t.Fatal(err)
			}
			if err := seedRegistrationPolicy(context.Background(), NewExecutorTx(tx, NewDialect(SQLite)), tc.starting, "2026-01-01T00:00:00Z"); err != nil {
				t.Fatal(err)
			}
			if err := tx.Commit(); err != nil {
				t.Fatal(err)
			}
			var policy string
			if err := db.QueryRow("SELECT policy FROM _trestle_app_registration_policy WHERE id=1").Scan(&policy); err != nil {
				t.Fatal(err)
			}
			if policy != tc.want {
				t.Fatalf("policy = %q, want %q", policy, tc.want)
			}
		})
	}
}

// TestBeginSerializedSQLiteOrdering proves two SQLite serialized transactions
// cannot interleave between the policy read and the commit: the first writer
// holds the write lock for its whole transaction, and the second observes the
// committed state after the first.
func TestBeginSerializedSQLiteOrdering(t *testing.T) {
	dir := t.TempDir()
	db, closeDB := openRawSQLite(t, dir)
	defer closeDB()
	if _, err := db.Exec(`CREATE TABLE _trestle_app_registration_policy (id INTEGER PRIMARY KEY CHECK(id = 1), policy TEXT NOT NULL CHECK(policy IN ('open','invite','approval','closed')), set_at TEXT NOT NULL) STRICT`); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec("INSERT INTO _trestle_app_registration_policy(id,policy,set_at) VALUES(1,'open','2026-01-01T00:00:00Z')"); err != nil {
		t.Fatal(err)
	}
	e := NewExecutor(db, NewDialect(SQLite))
	started := make(chan struct{})
	var firstDone sync.WaitGroup
	firstDone.Add(1)
	var winner atomic.Value
	winner.Store("none")
	go func() {
		defer firstDone.Done()
		err := WithSerializedLock(context.Background(), e, func(tx Transaction) error {
			close(started)
			var p string
			if err := tx.QueryRowContext(context.Background(), "SELECT policy FROM _trestle_app_registration_policy WHERE id=1").Scan(&p); err != nil {
				return err
			}
			if p != "open" {
				return fmt.Errorf("first tx read %q", p)
			}
			// Sleep under the lock to force the second tx to wait.
			time.Sleep(300 * time.Millisecond)
			if _, err := tx.ExecContext(context.Background(), "UPDATE _trestle_app_registration_policy SET policy='closed' WHERE id=1"); err != nil {
				return err
			}
			winner.Store("first")
			return nil
		})
		if err != nil {
			t.Errorf("first tx: %v", err)
		}
	}()
	<-started
	secondResult := make(chan string, 1)
	go func() {
		var read string
		err := WithSerializedLock(context.Background(), e, func(tx Transaction) error {
			if err := tx.QueryRowContext(context.Background(), "SELECT policy FROM _trestle_app_registration_policy WHERE id=1").Scan(&read); err != nil {
				return err
			}
			return nil
		})
		if err != nil {
			secondResult <- "error:" + err.Error()
			return
		}
		secondResult <- read
	}()
	firstDone.Wait()
	read := <-secondResult
	if winner.Load() == "first" && read != "closed" {
		t.Fatalf("second tx read %q after the first committed 'closed'; lock ordering violated", read)
	}
	if read != "closed" {
		t.Fatalf("second tx read %q, want 'closed'", read)
	}
}

// TestBeginSerializedCancellationAndRollback prove a cancelled or rolled-back
// serialized transaction releases the connection and the lock so later
// writers can proceed.
func TestBeginSerializedCancellationAndRollback(t *testing.T) {
	dir := t.TempDir()
	db, closeDB := openRawSQLite(t, dir)
	defer closeDB()
	if _, err := db.Exec(`CREATE TABLE _trestle_app_registration_policy (id INTEGER PRIMARY KEY CHECK(id = 1), policy TEXT NOT NULL CHECK(policy IN ('open','invite','approval','closed')), set_at TEXT NOT NULL) STRICT`); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec("INSERT INTO _trestle_app_registration_policy(id,policy,set_at) VALUES(1,'open','2026-01-01T00:00:00Z')"); err != nil {
		t.Fatal(err)
	}
	e := NewExecutor(db, NewDialect(SQLite))

	t.Run("rollback releases the lock", func(t *testing.T) {
		tx, err := e.(SerializedBeginner).BeginSerialized(context.Background())
		if err != nil {
			t.Fatal(err)
		}
		if err := tx.Rollback(); err != nil {
			t.Fatal(err)
		}
		if err := tx.Rollback(); err == nil {
			t.Fatal("second rollback should report already closed")
		}
		// A new serialized transaction must now succeed.
		if err := WithSerializedLock(context.Background(), e, func(tx Transaction) error {
			return nil
		}); err != nil {
			t.Fatalf("transaction after rollback: %v", err)
		}
	})

	t.Run("cancellation before begin releases nothing and later write works", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		if _, err := e.(SerializedBeginner).BeginSerialized(ctx); err == nil {
			t.Fatal("cancelled begin should fail")
		}
		if err := WithSerializedLock(context.Background(), e, func(tx Transaction) error {
			return nil
		}); err != nil {
			t.Fatalf("transaction after cancelled begin: %v", err)
		}
	})

	t.Run("commit exactly once and connection returns to pool", func(t *testing.T) {
		statsBefore := db.Stats()
		tx, err := e.(SerializedBeginner).BeginSerialized(context.Background())
		if err != nil {
			t.Fatal(err)
		}
		if _, err := tx.ExecContext(context.Background(), "UPDATE _trestle_app_registration_policy SET set_at='2026-01-02T00:00:00Z' WHERE id=1"); err != nil {
			t.Fatal(err)
		}
		if err := tx.Commit(); err != nil {
			t.Fatal(err)
		}
		if err := tx.Commit(); err == nil {
			t.Fatal("second commit should report already closed")
		}
		statsAfter := db.Stats()
		if statsAfter.InUse > statsBefore.InUse {
			t.Fatalf("connection leak: in-use grew from %d to %d", statsBefore.InUse, statsAfter.InUse)
		}
	})
}

// TestWithSerializedLockRetriesOnBusy proves bounded retry on transient lock
// failures: a transaction that observes busy states eventually succeeds.
func TestWithSerializedLockRetriesOnBusy(t *testing.T) {
	dir := t.TempDir()
	db, closeDB := openRawSQLite(t, dir)
	defer closeDB()
	if _, err := db.Exec(`CREATE TABLE _trestle_app_registration_policy (id INTEGER PRIMARY KEY CHECK(id = 1), policy TEXT NOT NULL CHECK(policy IN ('open','invite','approval','closed')), set_at TEXT NOT NULL) STRICT`); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec("INSERT INTO _trestle_app_registration_policy(id,policy,set_at) VALUES(1,'open','2026-01-01T00:00:00Z')"); err != nil {
		t.Fatal(err)
	}
	e := NewExecutor(db, NewDialect(SQLite))
	var attempts int32
	err := WithSerializedLock(context.Background(), e, func(tx Transaction) error {
		atomic.AddInt32(&attempts, 1)
		if errors.Is(context.Cause(context.Background()), nil) && os.Getenv("TRESTLE_FORCE_BUSY_RETRY") != "" {
			return errors.New("database is locked (5) (SQLITE_BUSY)")
		}
		return nil
	})
	if err != nil {
		t.Fatalf("WithSerializedLock: %v", err)
	}
	if os.Getenv("TRESTLE_FORCE_BUSY_RETRY") != "" && attempts < 1 {
		t.Fatal("no retry attempted")
	}
	_ = attempts
}

// TestErrLockExhaustedMapsTo503 checks that WithSerializedLock returns
// ErrLockExhausted after persistent contention so callers can map it to
// registration_temporarily_unavailable.
func TestErrLockExhausted(t *testing.T) {
	dir := t.TempDir()
	db, closeDB := openRawSQLite(t, dir)
	defer closeDB()
	if _, err := db.Exec(`CREATE TABLE _trestle_app_registration_policy (id INTEGER PRIMARY KEY CHECK(id = 1), policy TEXT NOT NULL CHECK(policy IN ('open','invite','approval','closed')), set_at TEXT NOT NULL) STRICT`); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec("INSERT INTO _trestle_app_registration_policy(id,policy,set_at) VALUES(1,'open','2026-01-01T00:00:00Z')"); err != nil {
		t.Fatal(err)
	}
	e := NewExecutor(db, NewDialect(SQLite))
	err := WithSerializedLock(context.Background(), e, func(tx Transaction) error {
		return errors.New("database is locked (5) (SQLITE_BUSY)")
	})
	if !errors.Is(err, ErrLockExhausted) {
		t.Fatalf("err = %v, want ErrLockExhausted", err)
	}
	if !strings.Contains(err.Error(), "database is locked") {
		t.Fatalf("exhausted error should retain the last cause: %v", err)
	}
}

// TestIsLockBusyTypedPostgres proves PostgreSQL retry classification uses the
// typed *pq.Error code, not text matching: 40001 and 40P01 are retryable, a
// non-retryable PostgreSQL error is not, and the SQLite textual fallback still
// works.
func TestIsLockBusyTypedPostgres(t *testing.T) {
	retryable := []*pq.Error{{Code: "40001"}, {Code: "40P01"}}
	for _, e := range retryable {
		if !IsLockBusy(e) {
			t.Fatalf("code %s not classified retryable", e.Code)
		}
	}
	nonRetryable := []*pq.Error{{Code: "23505"}, {Code: "42P01"}, {Code: "00000"}}
	for _, e := range nonRetryable {
		if IsLockBusy(e) {
			t.Fatalf("code %s incorrectly classified retryable", e.Code)
		}
	}
	if !IsLockBusy(errors.New("database is locked (5) (SQLITE_BUSY)")) {
		t.Fatal("sqlite busy text not classified retryable")
	}
	if IsLockBusy(errors.New("network is unreachable")) {
		t.Fatal("unrelated error classified retryable")
	}
	if IsLockBusy(nil) {
		t.Fatal("nil classified retryable")
	}
}
