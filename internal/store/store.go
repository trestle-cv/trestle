package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"time"

	_ "github.com/lib/pq"
	_ "modernc.org/sqlite"
)

const CurrentVersion = 17

type Store struct {
	db                    *sql.DB
	path                  string
	provider              Provider
	dialect               Dialect
	executor              Executor
	schemaVersion         int
	startingSchemaVersion int
	initConn              *sql.Conn
}

// queryer, dbWorker and txBeginner abstract the shared *sql.DB and *sql.Conn
// methods so initialization can pin one PostgreSQL connection for the whole
// advisory-lock, migration and identity sequence.
type queryer interface {
	QueryContext(context.Context, string, ...any) (*sql.Rows, error)
	QueryRowContext(context.Context, string, ...any) *sql.Row
}
type dbWorker interface {
	queryer
	ExecContext(context.Context, string, ...any) (sql.Result, error)
}
type txBeginner interface {
	BeginTx(context.Context, *sql.TxOptions) (*sql.Tx, error)
}

type Options struct {
	DataDir         string
	Provider        Provider
	URL             string
	MaxOpen         int
	MaxIdle         int
	ConnMaxLifetime time.Duration
	ConnectTimeout  time.Duration
}

func Probe(ctx context.Context, provider Provider, url string, connectTimeout time.Duration) (string, error) {
	if provider == SQLite {
		return "sqlite", nil
	}
	if provider != Postgres {
		return "", errors.New("unsupported database provider")
	}
	dsn, err := withConnectTimeout(url, connectTimeout)
	if err != nil {
		return "", err
	}
	db, err := sql.Open("postgres", dsn)
	if err != nil {
		return "", errors.New("open postgres connection")
	}
	defer db.Close()
	if err := db.PingContext(ctx); err != nil {
		return "", errors.New("postgres connection failed")
	}
	var version string
	if err := db.QueryRowContext(ctx, "SHOW server_version").Scan(&version); err != nil {
		return "", errors.New("postgres version check failed")
	}
	return version, nil
}

// withConnectTimeout rewrites a PostgreSQL URL so the driver enforces the
// Trestle-owned connection timeout through lib/pq's whole-second
// connect_timeout parameter. Query parameters are modified through structured
// URL handling, preserving escaping and credentials. A timeout that cannot be
// represented as a whole number of seconds is rejected rather than rounded.
func withConnectTimeout(rawURL string, timeout time.Duration) (string, error) {
	if timeout <= 0 {
		return rawURL, nil
	}
	seconds := timeout / time.Second
	if seconds == 0 || time.Duration(seconds)*time.Second != timeout {
		return "", errors.New("postgres connect timeout must be a whole number of seconds")
	}
	u, err := url.Parse(rawURL)
	if err != nil || (u.Scheme != "postgres" && u.Scheme != "postgresql") {
		return "", errors.New("invalid postgres connection URL")
	}
	query := u.Query()
	query.Set("connect_timeout", strconv.FormatInt(int64(seconds), 10))
	u.RawQuery = query.Encode()
	return u.String(), nil
}

type migration struct {
	version   int
	name, sql string
}

// migrationRecoveryHint is appended to fail-closed migration errors so an
// operator receives an actionable next step rather than a bare diagnostic.
const migrationRecoveryHint = ". Recovery: restore this database from a backup before starting Trestle again"

func withMigrationRecoveryHint(err error) error {
	if err == nil {
		return nil
	}
	return fmt.Errorf("%w%s", err, migrationRecoveryHint)
}

var migrations = []migration{{1, "system foundation", `
CREATE TABLE _trestle_schema_migrations (
  version INTEGER PRIMARY KEY,
  name TEXT NOT NULL,
  applied_at TEXT NOT NULL
) STRICT;
CREATE TABLE _trestle_system_meta (
  key TEXT PRIMARY KEY,
  value TEXT NOT NULL,
  updated_at TEXT NOT NULL
) STRICT;
CREATE TABLE _trestle_audit (
  id INTEGER PRIMARY KEY,
  occurred_at TEXT NOT NULL,
  actor_kind TEXT NOT NULL,
  actor_id TEXT,
  action TEXT NOT NULL,
  target TEXT,
  outcome TEXT NOT NULL,
  request_id TEXT
) STRICT;
`}, {2, "administrator identity", `
CREATE TABLE _trestle_admins (
  id TEXT PRIMARY KEY,
  email TEXT NOT NULL UNIQUE COLLATE NOCASE,
  password_hash TEXT NOT NULL,
  created_at TEXT NOT NULL,
  disabled_at TEXT
) STRICT;
CREATE TABLE _trestle_admin_sessions (
  id TEXT PRIMARY KEY,
  admin_id TEXT NOT NULL REFERENCES _trestle_admins(id) ON DELETE CASCADE,
  token_hash BLOB NOT NULL UNIQUE,
  csrf_hash BLOB NOT NULL,
  created_at TEXT NOT NULL,
  expires_at TEXT NOT NULL,
  revoked_at TEXT
) STRICT;
CREATE INDEX _trestle_admin_sessions_admin ON _trestle_admin_sessions(admin_id);
`}, {3, "collection metadata", `
CREATE TABLE _trestle_collections (
  id TEXT PRIMARY KEY,
  name TEXT NOT NULL UNIQUE COLLATE NOCASE,
  kind TEXT NOT NULL CHECK(kind IN ('base')),
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL
) STRICT;
CREATE TABLE _trestle_fields (
  id TEXT PRIMARY KEY,
  collection_id TEXT NOT NULL REFERENCES _trestle_collections(id) ON DELETE CASCADE,
  position INTEGER NOT NULL,
  name TEXT NOT NULL,
  type TEXT NOT NULL,
  required INTEGER NOT NULL CHECK(required IN (0,1)),
  is_unique INTEGER NOT NULL CHECK(is_unique IN (0,1)),
  default_json TEXT,
  created_at TEXT NOT NULL,
  UNIQUE(collection_id,name),
  UNIQUE(collection_id,position)
) STRICT;
`}, {4, "record idempotency", `
CREATE TABLE _trestle_record_idempotency (
  collection_id TEXT NOT NULL REFERENCES _trestle_collections(id) ON DELETE CASCADE,
  idempotency_key TEXT NOT NULL,
  record_id TEXT NOT NULL,
  created_at TEXT NOT NULL,
  PRIMARY KEY(collection_id,idempotency_key)
) STRICT;
`}, {5, "application user identity", `
CREATE TABLE _trestle_app_users (
  id TEXT PRIMARY KEY,
  email TEXT NOT NULL UNIQUE COLLATE NOCASE,
  password_hash TEXT NOT NULL,
  verified_at TEXT,
  disabled_at TEXT,
  created_at TEXT NOT NULL
) STRICT;
CREATE TABLE _trestle_app_sessions (
  id TEXT PRIMARY KEY,
  user_id TEXT NOT NULL REFERENCES _trestle_app_users(id) ON DELETE CASCADE,
  refresh_hash BLOB NOT NULL UNIQUE,
  created_at TEXT NOT NULL,
  expires_at TEXT NOT NULL,
  revoked_at TEXT,
  replaced_by TEXT
) STRICT;
CREATE INDEX _trestle_app_sessions_user ON _trestle_app_sessions(user_id);
`}, {6, "scoped backend credentials", `
CREATE TABLE _trestle_credentials (
  id TEXT PRIMARY KEY,
  kind TEXT NOT NULL CHECK(kind IN ('service','personal')),
  name TEXT NOT NULL,
  owner_admin_id TEXT REFERENCES _trestle_admins(id) ON DELETE CASCADE,
  secret_hash BLOB NOT NULL UNIQUE,
  scopes TEXT NOT NULL,
  created_at TEXT NOT NULL,
  expires_at TEXT,
  revoked_at TEXT,
  last_used_at TEXT
) STRICT;
CREATE INDEX _trestle_credentials_kind ON _trestle_credentials(kind);
`}, {7, "collection access rules", `
CREATE TABLE _trestle_app_access (
  token_hash BLOB PRIMARY KEY,
  session_id TEXT NOT NULL REFERENCES _trestle_app_sessions(id) ON DELETE CASCADE,
  user_id TEXT NOT NULL REFERENCES _trestle_app_users(id) ON DELETE CASCADE,
  expires_at TEXT NOT NULL
) STRICT;
CREATE TABLE _trestle_collection_rules (
  collection_id TEXT NOT NULL REFERENCES _trestle_collections(id) ON DELETE CASCADE,
  operation TEXT NOT NULL CHECK(operation IN ('list','view','create','update','delete')),
  expression TEXT NOT NULL,
  updated_at TEXT NOT NULL,
  PRIMARY KEY(collection_id,operation)
) STRICT;
`}, {8, "local file storage", `
CREATE TABLE _trestle_files (
  id TEXT PRIMARY KEY,
  storage_key TEXT NOT NULL UNIQUE,
  original_name TEXT NOT NULL,
  content_type TEXT NOT NULL,
  size INTEGER NOT NULL CHECK(size >= 0),
  sha256 TEXT NOT NULL,
  collection_name TEXT,
  record_id TEXT,
  created_at TEXT NOT NULL
) STRICT;
CREATE INDEX _trestle_files_record ON _trestle_files(collection_name,record_id);
`}, {9, "durable event journal", `
CREATE TABLE _trestle_events (
  sequence INTEGER PRIMARY KEY AUTOINCREMENT,
  occurred_at TEXT NOT NULL,
  topic TEXT NOT NULL,
  collection_name TEXT,
  record_id TEXT,
  payload_json TEXT NOT NULL
) STRICT;
CREATE INDEX _trestle_events_topic_sequence ON _trestle_events(topic,sequence);
`}, {10, "audit administration", `
ALTER TABLE _trestle_audit ADD COLUMN details_json TEXT NOT NULL DEFAULT '{}';
CREATE INDEX _trestle_audit_occurred ON _trestle_audit(occurred_at DESC,id DESC);
CREATE INDEX _trestle_audit_action ON _trestle_audit(action,id DESC);
`}, {11, "durable jobs", `
CREATE TABLE _trestle_jobs (
  id TEXT PRIMARY KEY,
  kind TEXT NOT NULL,
  payload_json TEXT NOT NULL,
  status TEXT NOT NULL CHECK(status IN ('pending','running','succeeded','cancelled','dead')),
  attempts INTEGER NOT NULL DEFAULT 0,
  max_attempts INTEGER NOT NULL DEFAULT 5,
  available_at TEXT NOT NULL,
  lease_until TEXT,
  idempotency_key TEXT UNIQUE,
  last_error TEXT,
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL
) STRICT;
CREATE INDEX _trestle_jobs_claim ON _trestle_jobs(status,available_at,id);
`}, {12, "signed webhooks", `
CREATE TABLE _trestle_webhooks (
 id TEXT PRIMARY KEY, name TEXT NOT NULL, url TEXT NOT NULL,
 topics TEXT NOT NULL, secret_cipher BLOB NOT NULL,
 enabled INTEGER NOT NULL DEFAULT 1 CHECK(enabled IN (0,1)),
 created_at TEXT NOT NULL, updated_at TEXT NOT NULL
) STRICT;
`}, {13, "function targets", `
CREATE TABLE _trestle_functions (
 id TEXT PRIMARY KEY, name TEXT NOT NULL, provider TEXT NOT NULL CHECK(provider='aws-lambda'),
 target TEXT NOT NULL, region TEXT NOT NULL, topics TEXT NOT NULL,
 callback_scopes TEXT NOT NULL DEFAULT '', enabled INTEGER NOT NULL DEFAULT 1 CHECK(enabled IN (0,1)),
 created_at TEXT NOT NULL, updated_at TEXT NOT NULL
) STRICT;
`}, {14, "durable file deletion", `
CREATE TABLE _trestle_file_deletions (
 id TEXT PRIMARY KEY,
 storage_key TEXT NOT NULL,
 status TEXT NOT NULL CHECK(status IN ('pending','done')),
 attempts INTEGER NOT NULL DEFAULT 0,
 created_at TEXT NOT NULL,
 finalized_at TEXT
) STRICT;
ALTER TABLE _trestle_files ADD COLUMN deleted_at TEXT;
`}, {15, "application registration policy", `
CREATE TABLE _trestle_app_registration_policy (
  id INTEGER PRIMARY KEY CHECK(id = 1),
  policy TEXT NOT NULL CHECK(policy IN ('open','invite','approval','closed')),
  set_at TEXT NOT NULL
) STRICT;
CREATE TABLE _trestle_app_invitations (
  id TEXT PRIMARY KEY,
  kind TEXT NOT NULL CHECK(kind IN ('self_register','activate')),
  email TEXT NOT NULL,
  token_hash BLOB NOT NULL UNIQUE,
  created_at TEXT NOT NULL,
  expires_at TEXT NOT NULL,
  used_at TEXT,
  revoked_at TEXT,
  created_by_admin_id TEXT,
  user_id TEXT,
  access_request_id TEXT
) STRICT;
CREATE INDEX _trestle_app_invitations_email ON _trestle_app_invitations(email);
CREATE TABLE _trestle_app_access_requests (
  id TEXT PRIMARY KEY,
  email TEXT NOT NULL,
  status TEXT NOT NULL CHECK(status IN ('pending','approved','rejected','expired')),
  created_at TEXT NOT NULL,
  decided_at TEXT,
  decided_by_admin_id TEXT
) STRICT;
CREATE UNIQUE INDEX _trestle_app_access_requests_pending_email ON _trestle_app_access_requests(email) WHERE status = 'pending';
`}, {16, "gantry authorization roles", `
CREATE TABLE _trestle_roles (
  id TEXT PRIMARY KEY,
  name TEXT NOT NULL,
  capabilities_json TEXT NOT NULL,
  built_in INTEGER NOT NULL CHECK(built_in IN (0,1))
) STRICT;
CREATE TABLE _trestle_admin_roles (
  admin_id TEXT NOT NULL REFERENCES _trestle_admins(id) ON DELETE CASCADE,
  role_id TEXT NOT NULL REFERENCES _trestle_roles(id) ON DELETE RESTRICT,
  PRIMARY KEY(admin_id,role_id)
) STRICT;
INSERT INTO _trestle_roles(id,name,capabilities_json,built_in) VALUES('administrator','Administrator','["*"]',1);
INSERT INTO _trestle_admin_roles(admin_id,role_id) SELECT id,'administrator' FROM _trestle_admins;
`}, {17, "embedded instance launcher", `
CREATE TABLE _trestle_launcher_instances (
  id TEXT PRIMARY KEY,
  position INTEGER NOT NULL UNIQUE,
  name TEXT NOT NULL,
  domain TEXT NOT NULL,
  port INTEGER CHECK(port BETWEEN 1 AND 65535)
) STRICT;
`}}

func Open(ctx context.Context, dataDir string) (*Store, error) {
	return OpenWith(ctx, Options{DataDir: dataDir, Provider: SQLite, MaxOpen: 1})
}

func OpenWith(ctx context.Context, options Options) (*Store, error) {
	if options.Provider == "" {
		options.Provider = SQLite
	}
	if options.MaxOpen < 1 {
		options.MaxOpen = 10
	}
	if options.MaxIdle < 0 {
		options.MaxIdle = 0
	}
	if err := os.MkdirAll(options.DataDir, 0o700); err != nil {
		return nil, fmt.Errorf("create data directory: %w", err)
	}
	if err := os.Chmod(options.DataDir, 0o700); err != nil {
		return nil, fmt.Errorf("secure data directory: %w", err)
	}
	var err error
	path := "external-postgres"
	driver, dsn := "postgres", options.URL
	if options.Provider == SQLite {
		path = filepath.Join(options.DataDir, "trestle.db")
		driver = "sqlite"
		dsn = "file:" + filepath.ToSlash(path) + "?_pragma=foreign_keys(1)&_pragma=busy_timeout(5000)&_pragma=journal_mode(WAL)"
	} else {
		dsn, err = withConnectTimeout(options.URL, options.ConnectTimeout)
		if err != nil {
			return nil, err
		}
	}
	db, err := sql.Open(driver, dsn)
	if err != nil {
		return nil, fmt.Errorf("open %s database: %w", options.Provider, err)
	}
	db.SetMaxOpenConns(1)
	db.SetConnMaxLifetime(0)
	dialect := NewDialect(options.Provider)
	s := &Store{db: db, path: path, provider: options.Provider, dialect: dialect, executor: NewExecutor(db, dialect)}
	if err := s.initialize(ctx); err != nil {
		_ = db.Close()
		return nil, err
	}
	if options.Provider == Postgres {
		db.SetMaxOpenConns(options.MaxOpen)
		db.SetMaxIdleConns(options.MaxIdle)
		db.SetConnMaxLifetime(options.ConnMaxLifetime)
	}
	return s, nil
}

func (s *Store) initialize(ctx context.Context) error {
	if err := s.db.PingContext(ctx); err != nil {
		return fmt.Errorf("ping %s database: %w", s.provider, err)
	}
	if s.provider == Postgres {
		return s.initializePostgres(ctx)
	}
	var foreignKeys int
	if err := s.db.QueryRowContext(ctx, "PRAGMA foreign_keys").Scan(&foreignKeys); err != nil || foreignKeys != 1 {
		return errors.New("sqlite foreign keys are not enabled")
	}
	version, err := s.sqliteVersion(ctx)
	if err != nil {
		return err
	}
	s.startingSchemaVersion = version
	for _, m := range migrations {
		if m.version > version {
			if err := s.apply(ctx, m); err != nil {
				return err
			}
		}
	}
	return s.ensureIdentity(ctx, s.db)
}

func (s *Store) initializePostgres(ctx context.Context) error {
	// Pin one dedicated connection so the session-level advisory lock, the
	// migration-history reads, the migrations and the identity initialization
	// all share connection ownership instead of relying on the temporary
	// one-connection pool.
	conn, err := s.db.Conn(ctx)
	if err != nil {
		return fmt.Errorf("acquire postgres connection: %w", err)
	}
	defer conn.Close()
	if _, err := conn.ExecContext(ctx, "SELECT pg_advisory_lock(839201347561)"); err != nil {
		return fmt.Errorf("lock postgres migrations: %w", err)
	}
	defer conn.ExecContext(context.Background(), "SELECT pg_advisory_unlock(839201347561)")
	s.initConn = conn
	defer func() { s.initConn = nil }()
	history, err := s.readHistory(ctx, conn)
	if err != nil {
		return err
	}
	s.schemaVersion = history.version
	s.startingSchemaVersion = history.version
	for _, m := range migrations {
		if m.version > history.version {
			if err := s.apply(ctx, m); err != nil {
				return err
			}
		}
	}
	return s.ensureIdentity(ctx, conn)
}

type migrationHistory struct {
	exists  bool
	version int
}

// readHistory returns the highest contiguous applied migration version derived
// from the validated _trestle_schema_migrations history. A database without the
// history table is treated as blank. Damaged, non-contiguous, future or
// misnamed history fails closed instead of guessing.
func (s *Store) readHistory(ctx context.Context, q queryer) (migrationHistory, error) {
	var exists bool
	var err error
	if s.provider == Postgres {
		err = q.QueryRowContext(ctx, "SELECT to_regclass('_trestle_schema_migrations') IS NOT NULL").Scan(&exists)
	} else {
		var count int
		err = q.QueryRowContext(ctx, "SELECT count(*) FROM sqlite_master WHERE type='table' AND name='_trestle_schema_migrations'").Scan(&count)
		exists = count > 0
	}
	if err != nil {
		return migrationHistory{}, fmt.Errorf("inspect migration history: %w", err)
	}
	if !exists {
		return migrationHistory{}, nil
	}
	rows, err := q.QueryContext(ctx, "SELECT version,name FROM _trestle_schema_migrations ORDER BY version")
	if err != nil {
		return migrationHistory{}, fmt.Errorf("read migration history: %w", err)
	}
	defer rows.Close()
	history := migrationHistory{exists: true}
	expected := 1
	for rows.Next() {
		var version int
		var name string
		if err := rows.Scan(&version, &name); err != nil {
			return migrationHistory{}, fmt.Errorf("read migration history: %w", err)
		}
		if version > CurrentVersion {
			return migrationHistory{}, withMigrationRecoveryHint(fmt.Errorf("database schema version %d is newer than supported version %d", version, CurrentVersion))
		}
		if version != expected {
			return migrationHistory{}, withMigrationRecoveryHint(fmt.Errorf("database migration history is not contiguous (expected version %d, found %d)", expected, version))
		}
		if name != migrations[version-1].name {
			return migrationHistory{}, withMigrationRecoveryHint(fmt.Errorf("database migration %d has an unexpected name", version))
		}
		history.version = version
		expected++
	}
	if err := rows.Err(); err != nil {
		return migrationHistory{}, fmt.Errorf("read migration history: %w", err)
	}
	return history, nil
}

// sqliteVersion derives the applied SQLite version from validated migration
// history, treating PRAGMA user_version only as a compatibility mirror and
// reconciliation signal. A blank database may initialize; an absent mirror is
// restored; disagreement fails closed rather than reconstructing history.
func (s *Store) sqliteVersion(ctx context.Context) (int, error) {
	history, err := s.readHistory(ctx, s.db)
	if err != nil {
		return 0, err
	}
	var mirror int
	if err := s.db.QueryRowContext(ctx, "PRAGMA user_version").Scan(&mirror); err != nil {
		return 0, fmt.Errorf("read schema version mirror: %w", err)
	}
	if mirror > CurrentVersion {
		return 0, withMigrationRecoveryHint(fmt.Errorf("database schema version %d is newer than supported version %d", mirror, CurrentVersion))
	}
	if history.version == 0 {
		if mirror != 0 {
			return 0, withMigrationRecoveryHint(errors.New("database has a schema version marker but no migration history"))
		}
		return 0, nil
	}
	if mirror == 0 {
		if _, err := s.db.ExecContext(ctx, fmt.Sprintf("PRAGMA user_version = %d", history.version)); err != nil {
			return 0, fmt.Errorf("restore schema version mirror: %w", err)
		}
	} else if mirror != history.version {
		return 0, withMigrationRecoveryHint(fmt.Errorf("database schema version marker %d does not match migration history version %d", mirror, history.version))
	}
	s.schemaVersion = history.version
	return history.version, nil
}

func (s *Store) ensureIdentity(ctx context.Context, w dbWorker) error {
	provider := string(s.provider)
	_, err := w.ExecContext(ctx, Bind(s.dialect, "INSERT INTO _trestle_system_meta(key,value,updated_at) VALUES(?,?,?) ON CONFLICT(key) DO NOTHING"), "database_provider", provider, time.Now().UTC().Format(time.RFC3339Nano))
	if err != nil {
		return fmt.Errorf("record database identity: %w", err)
	}
	var stored string
	if err := w.QueryRowContext(ctx, Bind(s.dialect, "SELECT value FROM _trestle_system_meta WHERE key=?"), "database_provider").Scan(&stored); err != nil {
		return fmt.Errorf("read database identity: %w", err)
	}
	if stored != provider {
		return fmt.Errorf("database identity is %s, not configured provider %s", stored, provider)
	}
	return nil
}

func (s *Store) apply(ctx context.Context, m migration) error {
	if s.provider == "" {
		s.provider = SQLite
	}
	if s.dialect == nil {
		s.dialect = NewDialect(s.provider)
	}
	if s.executor == nil {
		s.executor = NewExecutor(s.db, s.dialect)
	}
	var db txBeginner = s.db
	if s.initConn != nil {
		db = s.initConn
	}
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin migration %d: %w", m.version, err)
	}
	defer tx.Rollback()
	sqlText := m.sql
	if s.provider == Postgres {
		sqlText = postgresMigrations[m.version]
	}
	if sqlText == "" {
		return fmt.Errorf("migration %d has no %s definition", m.version, s.provider)
	}
	if _, err := tx.ExecContext(ctx, sqlText); err != nil {
		return fmt.Errorf("apply migration %d (%s): %w", m.version, m.name, err)
	}
	exec := NewExecutorTx(tx, s.dialect)
	if m.version == registrationMigrationVersion {
		if err := seedRegistrationPolicy(ctx, exec, s.startingSchemaVersion, time.Now().UTC().Format(time.RFC3339Nano)); err != nil {
			return fmt.Errorf("seed application registration policy: %w", err)
		}
	}
	if _, err := exec.ExecContext(ctx, "INSERT INTO _trestle_schema_migrations(version,name,applied_at) VALUES(?,?,?)", m.version, m.name, time.Now().UTC().Format(time.RFC3339Nano)); err != nil {
		return fmt.Errorf("record migration %d: %w", m.version, err)
	}
	if s.provider == SQLite {
		if _, err := tx.ExecContext(ctx, fmt.Sprintf("PRAGMA user_version = %d", m.version)); err != nil {
			return fmt.Errorf("set schema version %d: %w", m.version, err)
		}
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit migration %d: %w", m.version, err)
	}
	s.schemaVersion = m.version
	return nil
}

func (s *Store) Close() error                   { return s.db.Close() }
func (s *Store) Ping(ctx context.Context) error { return s.db.PingContext(ctx) }
func (s *Store) Path() string                   { return s.path }
func (s *Store) DB() Executor                   { return s.executor }
func (s *Store) Provider() Provider             { return s.provider }
func (s *Store) Dialect() Dialect               { return s.dialect }
func (s *Store) Diagnostics() Diagnostics {
	return Diagnostics{Provider: s.provider, SchemaVersion: s.schemaVersion, MaxOpen: s.db.Stats().MaxOpenConnections}
}

// ValidateMigrationHistory verifies the complete migration history of an open
// database without running any migration, metadata repair or write, and returns
// the applied version. It requires every version 1..CurrentVersion to exist
// exactly once with an authoritative name, and rejects future, gapped or
// malformed history. Offline tooling uses it so a source is never written.
func ValidateMigrationHistory(ctx context.Context, db Executor) (int, error) {
	dialect := db.Dialect()
	var exists bool
	if dialect.Provider() == Postgres {
		if err := db.QueryRowContext(ctx, "SELECT to_regclass('_trestle_schema_migrations') IS NOT NULL").Scan(&exists); err != nil {
			return 0, fmt.Errorf("inspect migration history: %w", err)
		}
	} else {
		var count int
		if err := db.QueryRowContext(ctx, "SELECT count(*) FROM sqlite_master WHERE type='table' AND name='_trestle_schema_migrations'").Scan(&count); err != nil {
			return 0, fmt.Errorf("inspect migration history: %w", err)
		}
		exists = count > 0
	}
	if !exists {
		return 0, withMigrationRecoveryHint(errors.New("database has no migration history"))
	}
	rows, err := db.QueryContext(ctx, "SELECT version,name FROM _trestle_schema_migrations ORDER BY version")
	if err != nil {
		return 0, fmt.Errorf("read migration history: %w", err)
	}
	defer rows.Close()
	expected := 1
	applied := 0
	for rows.Next() {
		var version int
		var name string
		if err := rows.Scan(&version, &name); err != nil {
			return 0, fmt.Errorf("read migration history: %w", err)
		}
		if version > CurrentVersion {
			return 0, withMigrationRecoveryHint(fmt.Errorf("database schema version %d is newer than supported version %d", version, CurrentVersion))
		}
		if version != expected {
			return 0, withMigrationRecoveryHint(fmt.Errorf("database migration history is not contiguous (expected version %d, found %d)", expected, version))
		}
		if name != migrations[version-1].name {
			return 0, withMigrationRecoveryHint(fmt.Errorf("database migration %d has an unexpected name", version))
		}
		applied = version
		expected++
	}
	if err := rows.Err(); err != nil {
		return 0, fmt.Errorf("read migration history: %w", err)
	}
	if applied != CurrentVersion {
		return 0, fmt.Errorf("database migration history is incomplete (applied %d of %d)", applied, CurrentVersion)
	}
	return applied, nil
}
