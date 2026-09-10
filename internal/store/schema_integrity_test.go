package store

import (
	"context"
	"database/sql"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
	"time"

	_ "github.com/lib/pq"
)

// TestUpgradeFromEveryRetainedSchemaVersionProvider proves that a database
// created at every retained logical schema version upgrades cleanly to the
// current version on both providers: the applied version reaches CurrentVersion,
// exactly CurrentVersion migration-history rows exist (migrations never
// re-apply), and prior data survives. Historical fixtures are built from the
// authoritative per-version DDL, not only from a new database.
func TestUpgradeFromEveryRetainedSchemaVersionProvider(t *testing.T) {
	for _, provider := range []Provider{SQLite, Postgres} {
		provider := provider
		if provider == Postgres && os.Getenv("TRESTLE_TEST_POSTGRES_URL") == "" {
			continue
		}
		t.Run(string(provider), func(t *testing.T) {
			var url string
			var reset func()
			if provider == Postgres {
				url = ownedURL(t)
				reset = func() {
					raw, err := sql.Open("postgres", url)
					if err != nil {
						t.Fatal(err)
					}
					defer raw.Close()
					resetPostgres(t, raw)
				}
			}
			for from := 0; from <= CurrentVersion; from++ {
				t.Run(fmt.Sprintf("v%d", from), func(t *testing.T) {
					if provider == Postgres {
						reset()
					}
					var s *Store
					var err error
					if provider == Postgres {
						buildPostgresFixture(t, url, from)
						if from > 0 {
							seedProbePostgres(t, url, from)
						}
						s, err = OpenWith(context.Background(), Options{DataDir: t.TempDir(), Provider: Postgres, URL: url, MaxOpen: 4, MaxIdle: 1, ConnectTimeout: 5 * time.Second, ConnMaxLifetime: time.Hour})
					} else {
						dir := buildSQLiteFixture(t, from)
						if from > 0 {
							seedProbeSQLite(t, dir, from)
						}
						s, err = Open(context.Background(), dir)
					}
					if err != nil {
						t.Fatalf("upgrade v%d -> v%d: %v", from, CurrentVersion, err)
					}
					defer s.Close()
					if got := s.Diagnostics().SchemaVersion; got != CurrentVersion {
						t.Fatalf("schema version=%d, want %d", got, CurrentVersion)
					}
					var applied int
					if err := s.DB().QueryRowContext(context.Background(), "SELECT count(*) FROM _trestle_schema_migrations").Scan(&applied); err != nil {
						t.Fatal(err)
					}
					if applied != CurrentVersion {
						t.Fatalf("migration rows=%d, want %d (no re-application)", applied, CurrentVersion)
					}
					if from > 0 {
						var probe string
						if provider == Postgres {
							if err := s.DB().QueryRowContext(context.Background(), "SELECT value FROM _trestle_system_meta WHERE key='upgrade-probe'").Scan(&probe); err != nil {
								t.Fatal(err)
							}
						} else {
							if err := s.DB().QueryRowContext(context.Background(), "SELECT value FROM _trestle_system_meta WHERE key='upgrade-probe'").Scan(&probe); err != nil {
								t.Fatal(err)
							}
						}
						if probe != fmt.Sprintf("from-v%d", from) {
							t.Fatalf("preserved probe=%q", probe)
						}
					}
				})
			}
		})
	}
}

// buildPostgresFixture applies migrations 1..from against a blank PostgreSQL
// database using the authoritative per-version PostgreSQL DDL and records
// migration history exactly as the store does.
func buildPostgresFixture(t *testing.T, url string, from int) {
	t.Helper()
	db, err := sql.Open("postgres", url)
	if err != nil {
		t.Fatal(err)
	}
	dialect := NewDialect(Postgres)
	s := &Store{db: db, path: "external-postgres", provider: Postgres, dialect: dialect, executor: NewExecutor(db, dialect)}
	for _, m := range migrations {
		if m.version > from {
			break
		}
		if err := s.apply(context.Background(), m); err != nil {
			t.Fatalf("build postgres v%d fixture: %v", from, err)
		}
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}
}

func seedProbePostgres(t *testing.T, url string, from int) {
	t.Helper()
	db, err := sql.Open("postgres", url)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if _, err := db.Exec("INSERT INTO _trestle_system_meta(key,value,updated_at) VALUES('upgrade-probe',$1,$2)", fmt.Sprintf("from-v%d", from), "2026-01-01T00:00:00Z"); err != nil {
		t.Fatal(err)
	}
}

func seedProbeSQLite(t *testing.T, dir string, from int) {
	t.Helper()
	execFixtureSQL(t, dir, fmt.Sprintf("INSERT INTO _trestle_system_meta(key,value,updated_at) VALUES('upgrade-probe','from-v%d','2026-01-01T00:00:00Z')", from))
}

// TestBootstrapSchemaIntegrity introspects a freshly bootstrapped database on
// both providers and asserts the retained schema: exactly the expected system
// tables, cascade foreign keys, uniqueness constraints, and named indexes.
func TestBootstrapSchemaIntegrity(t *testing.T) {
	expectedTables := map[string]bool{
		"_trestle_schema_migrations":       true,
		"_trestle_system_meta":             true,
		"_trestle_audit":                   true,
		"_trestle_admins":                  true,
		"_trestle_admin_sessions":          true,
		"_trestle_collections":             true,
		"_trestle_fields":                  true,
		"_trestle_record_idempotency":      true,
		"_trestle_app_users":               true,
		"_trestle_app_sessions":            true,
		"_trestle_credentials":             true,
		"_trestle_app_access":              true,
		"_trestle_collection_rules":        true,
		"_trestle_files":                   true,
		"_trestle_events":                  true,
		"_trestle_jobs":                    true,
		"_trestle_webhooks":                true,
		"_trestle_functions":               true,
		"_trestle_file_deletions":          true,
		"_trestle_app_registration_policy": true,
		"_trestle_app_invitations":         true,
		"_trestle_app_access_requests":     true,
		"_trestle_roles":                   true,
		"_trestle_admin_roles":             true,
		"_trestle_launcher_instances":      true,
	}
	expectedIndexes := map[string]bool{
		"_trestle_admin_sessions_admin":              true,
		"_trestle_app_sessions_user":                 true,
		"_trestle_credentials_kind":                  true,
		"_trestle_files_record":                      true,
		"_trestle_events_topic_sequence":             true,
		"_trestle_audit_occurred":                    true,
		"_trestle_audit_action":                      true,
		"_trestle_jobs_claim":                        true,
		"_trestle_app_invitations_email":             true,
		"_trestle_app_access_requests_pending_email": true,
	}

	for _, provider := range []Provider{SQLite, Postgres} {
		provider := provider
		if provider == Postgres && os.Getenv("TRESTLE_TEST_POSTGRES_URL") == "" {
			continue
		}
		t.Run(string(provider), func(t *testing.T) {
			ctx := context.Background()
			var s *Store
			var err error
			var introspect *sql.DB
			if provider == Postgres {
				url := ownedURL(t)
				raw, openErr := sql.Open("postgres", url)
				if openErr != nil {
					t.Fatal(openErr)
				}
				resetPostgres(t, raw)
				s, err = OpenWith(ctx, Options{DataDir: t.TempDir(), Provider: Postgres, URL: url, MaxOpen: 4, MaxIdle: 1, ConnectTimeout: 5 * time.Second, ConnMaxLifetime: time.Hour})
				if err == nil {
					introspect = raw
				}
			} else {
				dir := t.TempDir()
				s, err = Open(ctx, dir)
				if err == nil {
					introspect, err = sql.Open("sqlite", "file:"+filepath.Join(dir, "trestle.db"))
					if err != nil {
						t.Fatal(err)
					}
				}
			}
			if err != nil {
				t.Fatal(err)
			}
			defer s.Close()
			defer introspect.Close()

			// Exact table set: no unexpected tables, none missing.
			tables := listTables(t, introspect, provider)
			for _, table := range tables {
				if !expectedTables[table] {
					t.Errorf("unexpected table %q in bootstrap schema", table)
				}
			}
			for table := range expectedTables {
				found := false
				for _, existing := range tables {
					if existing == table {
						found = true
					}
				}
				if !found {
					t.Errorf("expected table %q missing", table)
				}
			}

			// Cascade foreign keys on the identity and schema tables.
			requireCascadeFK(t, introspect, provider, "_trestle_admin_sessions", "_trestle_admins")
			requireCascadeFK(t, introspect, provider, "_trestle_fields", "_trestle_collections")
			requireCascadeFK(t, introspect, provider, "_trestle_collection_rules", "_trestle_collections")

			// Uniqueness: fields(collection_id,name) and token hashes.
			if cols := uniqueColumns(t, introspect, provider, "_trestle_fields"); !containsColumns(cols, []string{"collection_id", "name"}) {
				t.Errorf("_trestle_fields lacks UNIQUE(collection_id,name); uniques=%v", cols)
			}
			if !hasUniqueColumn(t, introspect, provider, "_trestle_admin_sessions", "token_hash") {
				t.Errorf("_trestle_admin_sessions lacks a UNIQUE on token_hash")
			}
			if !hasUniqueColumn(t, introspect, provider, "_trestle_app_sessions", "refresh_hash") {
				t.Errorf("_trestle_app_sessions lacks a UNIQUE on refresh_hash")
			}

			// Named operational indexes.
			indexes := listIndexes(t, introspect, provider)
			for name := range expectedIndexes {
				if !indexes[name] {
					t.Errorf("expected index %q missing", name)
				}
			}
		})
	}
}

// TestMigrationFailuresCarryRecoveryInstructions proves that fail-closed
// migration errors include an actionable recovery step for the operator rather
// than a bare diagnostic, on both providers.
func TestMigrationFailuresCarryRecoveryInstructions(t *testing.T) {
	for _, provider := range []Provider{SQLite, Postgres} {
		provider := provider
		if provider == Postgres && os.Getenv("TRESTLE_TEST_POSTGRES_URL") == "" {
			continue
		}
		t.Run(string(provider), func(t *testing.T) {
			openCorrupt := func() error {
				var s *Store
				var err error
				if provider == Postgres {
					url := ownedURL(t)
					raw, openErr := sql.Open("postgres", url)
					if openErr != nil {
						t.Fatal(openErr)
					}
					resetPostgres(t, raw)
					buildPostgresFixture(t, url, CurrentVersion)
					if _, execErr := raw.Exec("DELETE FROM _trestle_schema_migrations WHERE version=5"); execErr != nil {
						t.Fatal(execErr)
					}
					raw.Close()
					s, err = OpenWith(context.Background(), Options{DataDir: t.TempDir(), Provider: Postgres, URL: url, MaxOpen: 4, MaxIdle: 1, ConnectTimeout: 5 * time.Second})
				} else {
					dir := buildSQLiteFixture(t, CurrentVersion)
					execFixtureSQL(t, dir, "DELETE FROM _trestle_schema_migrations WHERE version=5")
					s, err = Open(context.Background(), dir)
				}
				if s != nil {
					s.Close()
				}
				return err
			}
			err := openCorrupt()
			if err == nil {
				t.Fatal("corrupt migration history opened without error")
			}
			if !strings.Contains(err.Error(), "not contiguous") {
				t.Fatalf("expected a contiguity diagnostic, got %q", err.Error())
			}
			if !strings.Contains(err.Error(), "Recovery: restore this database from a backup") {
				t.Fatalf("fail-closed error lacks actionable recovery instructions: %q", err.Error())
			}
		})
	}
}

func listTables(t *testing.T, db *sql.DB, provider Provider) []string {
	t.Helper()
	var rows *sql.Rows
	var err error
	if provider == Postgres {
		rows, err = db.QueryContext(context.Background(), "SELECT tablename FROM pg_tables WHERE schemaname='public' ORDER BY tablename")
	} else {
		rows, err = db.QueryContext(context.Background(), "SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%' ORDER BY name")
	}
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var name string
		if err := rows.Scan(&name); err != nil {
			t.Fatal(err)
		}
		out = append(out, name)
	}
	return out
}

func requireCascadeFK(t *testing.T, db *sql.DB, provider Provider, table, refTable string) {
	t.Helper()
	if provider == Postgres {
		var count int
		if err := db.QueryRowContext(context.Background(), "SELECT count(*) FROM pg_constraint c JOIN pg_class r ON r.oid=c.confrelid WHERE c.contype='f' AND c.conrelid=$1::regclass AND r.relname=$2 AND c.confdeltype='c'", table, refTable).Scan(&count); err != nil {
			t.Fatal(err)
		}
		if count != 1 {
			t.Errorf("%s has %d cascade FKs to %s, want 1", table, count, refTable)
		}
		return
	}
	rows, err := db.QueryContext(context.Background(), "PRAGMA foreign_key_list('"+table+"')")
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	found := false
	for rows.Next() {
		var id, seq int
		var ref, fromCol, to, onUpdate, onDelete, match string
		if err := rows.Scan(&id, &seq, &ref, &fromCol, &to, &onUpdate, &onDelete, &match); err != nil {
			t.Fatal(err)
		}
		if ref == refTable && onDelete == "CASCADE" {
			found = true
		}
	}
	if !found {
		t.Errorf("%s lacks a cascade FK to %s", table, refTable)
	}
}

func uniqueColumns(t *testing.T, db *sql.DB, provider Provider, table string) [][]string {
	t.Helper()
	var out [][]string
	if provider == Postgres {
		rows, err := db.QueryContext(context.Background(), `SELECT c.conname, a.attname
			FROM pg_constraint c
			JOIN pg_attribute a ON a.attrelid = c.conrelid AND a.attnum = ANY(c.conkey)
			WHERE c.contype='u' AND c.conrelid=$1::regclass
			ORDER BY c.conname, a.attnum`, table)
		if err != nil {
			t.Fatal(err)
		}
		defer rows.Close()
		var current string
		var cols []string
		flush := func() {
			if current != "" {
				out = append(out, cols)
			}
		}
		for rows.Next() {
			var name, col string
			if err := rows.Scan(&name, &col); err != nil {
				t.Fatal(err)
			}
			if name != current {
				flush()
				current = name
				cols = nil
			}
			cols = append(cols, col)
		}
		flush()
		if err := rows.Err(); err != nil {
			t.Fatal(err)
		}
		return out
	}
	// SQLite: unique autoindexes exposed by PRAGMA index_list.
	rows, err := db.QueryContext(context.Background(), "PRAGMA index_list('"+table+"')")
	if err != nil {
		t.Fatal(err)
	}
	var names []string
	for rows.Next() {
		var seq int
		var name, origin string
		var isUnique, partial int
		if err := rows.Scan(&seq, &name, &isUnique, &origin, &partial); err != nil {
			t.Fatal(err)
		}
		if isUnique == 1 && origin == "u" { // origin 'u' == unique constraint
			names = append(names, name)
		}
	}
	rows.Close()
	for _, name := range names {
		info, err := db.QueryContext(context.Background(), "PRAGMA index_info('"+name+"')")
		if err != nil {
			t.Fatal(err)
		}
		var cols []string
		for info.Next() {
			var seqno, cid int
			var col string
			if err := info.Scan(&seqno, &cid, &col); err != nil {
				t.Fatal(err)
			}
			cols = append(cols, col)
		}
		info.Close()
		out = append(out, cols)
	}
	return out
}

func containsColumns(uniques [][]string, want []string) bool {
	sort.Strings(want)
	for _, cols := range uniques {
		sorted := append([]string(nil), cols...)
		sort.Strings(sorted)
		if strings.Join(sorted, ",") == strings.Join(want, ",") {
			return true
		}
	}
	return false
}

func hasUniqueColumn(t *testing.T, db *sql.DB, provider Provider, table, column string) bool {
	t.Helper()
	for _, cols := range uniqueColumns(t, db, provider, table) {
		for _, col := range cols {
			if col == column {
				return true
			}
		}
	}
	return false
}

func listIndexes(t *testing.T, db *sql.DB, provider Provider) map[string]bool {
	t.Helper()
	out := map[string]bool{}
	if provider == Postgres {
		rows, err := db.QueryContext(context.Background(), "SELECT indexname FROM pg_indexes WHERE schemaname='public'")
		if err != nil {
			t.Fatal(err)
		}
		defer rows.Close()
		for rows.Next() {
			var name string
			if err := rows.Scan(&name); err != nil {
				t.Fatal(err)
			}
			out[name] = true
		}
		return out
	}
	rows, err := db.QueryContext(context.Background(), "SELECT name FROM sqlite_master WHERE type='index' AND name NOT LIKE 'sqlite_%'")
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	for rows.Next() {
		var name string
		if err := rows.Scan(&name); err != nil {
			t.Fatal(err)
		}
		out[name] = true
	}
	return out
}
