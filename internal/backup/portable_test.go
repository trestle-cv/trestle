package backup

import (
	"archive/zip"
	"bytes"
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/json"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/trestle-cv/trestle/internal/adminauth"
	"github.com/trestle-cv/trestle/internal/collections"
	"github.com/trestle-cv/trestle/internal/store"
	"github.com/trestle-cv/trestle/internal/storetest"
)

func adminCookieCSRF(t *testing.T, admin *adminauth.Handler) (*httptest.ResponseRecorder, string) {
	t.Helper()
	body := strings.NewReader(`{"username":"admin","email":"admin@example.com","password":"1234567","applicationRegistrationPolicy":"closed"}`)
	r := httptest.NewRequest("POST", "http://example.test/admin/v1/setup", body)
	r.Host = "example.test"
	r.Header.Set("Origin", "http://example.test")
	w := httptest.NewRecorder()
	admin.ServeHTTP(w, r)
	var out struct {
		CSRF string `json:"csrfToken"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &out); err != nil {
		t.Fatal(err)
	}
	return w, out.CSRF
}

func populatePortableFixture(t *testing.T, s *store.Store) {
	t.Helper()
	provider := string(s.Provider())
	admin := adminauth.New(s.DB(), provider)
	setup, csrf := adminCookieCSRF(t, admin)

	schemas := collections.New(s.DB(), admin)
	payload, _ := json.Marshal(map[string]any{"name": "issues", "fields": []map[string]any{
		{"name": "title", "type": "text", "required": true},
		{"name": "done", "type": "boolean"},
		{"name": "score", "type": "number"},
		{"name": "meta", "type": "json"},
	}})
	cr := httptest.NewRequest("POST", "http://example.test/admin/v1/collections", bytes.NewReader(payload))
	cr.Host = "example.test"
	cr.Header.Set("Origin", "http://example.test")
	cr.Header.Set("X-Trestle-CSRF", csrf)
	cr.AddCookie(setup.Result().Cookies()[0])
	w := httptest.NewRecorder()
	schemas.ServeHTTP(w, cr)
	if w.Code != 201 {
		t.Fatalf("collection fixture %d %s", w.Code, w.Body.String())
	}

	now := time.Now().UTC().Format(time.RFC3339Nano)
	if _, err := s.DB().Exec("INSERT INTO _trestle_system_meta(key,value,updated_at) VALUES(?,?,?)", "restore-probe", "preserved", now); err != nil {
		t.Fatal(err)
	}
	blob := []byte("hash-material")
	inserts := []struct {
		stmt string
		args []any
	}{
		{"INSERT INTO _trestle_app_users(id,email,password_hash,created_at) VALUES(?,?,?,?)", []any{"usr_1", "user@example.com", "$argon2id$dummy", now}},
		{"INSERT INTO _trestle_credentials(id,kind,name,secret_hash,scopes,created_at) VALUES(?,?,?,?,?,?)", []any{"cred_1", "service", "svc", blob, "records:read", now}},
		{"INSERT INTO _trestle_collection_rules(collection_id,operation,expression,updated_at) VALUES((SELECT id FROM _trestle_collections WHERE name='issues'),?,?,?)", []any{"view", "actor.id == record.owner", now}},
		{"INSERT INTO _trestle_events(occurred_at,topic,collection_name,record_id,payload_json) VALUES(?,?,?,?,?)", []any{now, "record.created", "issues", "rec_1", `{"n":1}`}},
		{"INSERT INTO _trestle_audit(occurred_at,actor_kind,actor_id,action,target,outcome,request_id,details_json) VALUES(?,?,?,?,?,?,?,?)", []any{now, "admin", "adm_x", "credential.use", "x", "allowed", "req", "{}"}},
		{"INSERT INTO _trestle_jobs(id,kind,payload_json,status,available_at,created_at,updated_at) VALUES(?,?,?,?,?,?,?)", []any{"job_1", "noop", "{}", "pending", now, now, now}},
		{"INSERT INTO _trestle_webhooks(id,name,url,topics,secret_cipher,created_at,updated_at) VALUES(?,?,?,?,?,?,?)", []any{"wh_1", "hook", "https://example.invalid/hook", "record.created", blob, now, now}},
		{"INSERT INTO _trestle_functions(id,name,provider,target,region,topics,created_at,updated_at) VALUES(?,?,?,?,?,?,?,?)", []any{"fn_1", "fn", "aws-lambda", "arn:x", "us-east-1", "record.created", now, now}},
		{"INSERT INTO _trestle_files(id,storage_key,original_name,content_type,size,sha256,created_at) VALUES(?,?,?,?,?,?,?)", []any{"file_1", "key/1", "a.txt", "text/plain", 3, "abc", now}},
	}
	for _, item := range inserts {
		if _, err := s.DB().Exec(item.stmt, item.args...); err != nil {
			t.Fatalf("%s: %v", item.stmt[:60], err)
		}
	}

	var colID string
	if err := s.DB().QueryRow("SELECT id FROM _trestle_collections WHERE name='issues'").Scan(&colID); err != nil {
		t.Fatal(err)
	}
	// Role catalog and per-admin assignments must survive the portable
	// round-trip; the fixture exercises a custom role beyond the built-in
	// administrator seed.
	if _, err := s.DB().Exec(`INSERT INTO _trestle_roles(id,name,capabilities_json,built_in) VALUES('auditor','Auditor','["records.read"]',?)`, s.Dialect().Boolean(false)); err != nil {
		t.Fatal(err)
	}
	var adminID string
	if err := s.DB().QueryRow("SELECT id FROM _trestle_admins ORDER BY id LIMIT 1").Scan(&adminID); err != nil {
		t.Fatal(err)
	}
	if _, err := s.DB().Exec(`INSERT INTO _trestle_admin_roles(admin_id,role_id) VALUES(?,?)`, adminID, "auditor"); err != nil {
		t.Fatal(err)
	}
	var fieldIDs []string
	rows, err := s.DB().Query("SELECT id FROM _trestle_fields WHERE collection_id=? ORDER BY position", colID)
	if err != nil {
		t.Fatal(err)
	}
	for rows.Next() {
		var id string
		rows.Scan(&id)
		fieldIDs = append(fieldIDs, id)
	}
	rows.Close()

	table := `"` + collections.PhysicalTableName(colID) + `"`
	cols := []string{`_id`, `_version`, `_created`, `_updated`}
	marks := []string{"?", "?", "?", "?"}
	args := []any{"rec_1", 1, now, now}
	fieldValues := []any{"hello", s.Dialect().Boolean(true), 3, `{"n":1}`}
	for i, fid := range fieldIDs {
		cols = append(cols, `"`+collections.PhysicalColumnName(fid)+`"`)
		marks = append(marks, "?")
		args = append(args, fieldValues[i])
	}
	if _, err := s.DB().Exec("INSERT INTO "+table+" ("+strings.Join(cols, ",")+") VALUES ("+strings.Join(marks, ",")+")", args...); err != nil {
		t.Fatal(err)
	}

}

func buildPortableFixture(t *testing.T, provider string) string {
	t.Helper()
	s := storetest.Open(t, provider)
	populatePortableFixture(t, s)
	var buf bytes.Buffer
	if err := Export(context.Background(), s.DB(), s.Dialect(), &buf); err != nil {
		t.Fatal(err)
	}
	return buf.String()
}

func TestPortableRoundTripAcrossProviders(t *testing.T) {
	for _, src := range storetest.Providers(t) {
		src := src
		var portable string
		t.Run("export-"+src, func(t *testing.T) {
			portable = buildPortableFixture(t, src)
		})
		for _, dst := range storetest.Providers(t) {
			dst := dst
			t.Run(src+"->"+dst, func(t *testing.T) {
				s := storetest.Open(t, dst)
				if err := Import(context.Background(), s.DB(), s.Dialect(), strings.NewReader(portable)); err != nil {
					t.Fatal(err)
				}
				var admins, users, credentials, rules, events, audit, jobs, webhooks, functions, files int
				for name, dstCount := range map[string]*int{
					"_trestle_admins": &admins, "_trestle_app_users": &users, "_trestle_credentials": &credentials,
					"_trestle_collection_rules": &rules, "_trestle_events": &events, "_trestle_audit": &audit,
					"_trestle_jobs": &jobs, "_trestle_webhooks": &webhooks, "_trestle_functions": &functions, "_trestle_files": &files,
				} {
					if err := s.DB().QueryRow("SELECT count(*) FROM " + name).Scan(dstCount); err != nil {
						t.Fatal(err)
					}
				}
				if admins != 1 || users != 1 || credentials != 1 || rules != 1 || events != 1 || audit != 1 || jobs != 1 || webhooks != 1 || functions != 1 || files != 1 {
					t.Fatalf("counts admins=%d users=%d creds=%d rules=%d events=%d audit=%d jobs=%d wh=%d fn=%d files=%d", admins, users, credentials, rules, events, audit, jobs, webhooks, functions, files)
				}
				var roles, adminRoles int
				if err := s.DB().QueryRow("SELECT count(*) FROM _trestle_roles").Scan(&roles); err != nil {
					t.Fatal(err)
				}
				if err := s.DB().QueryRow("SELECT count(*) FROM _trestle_admin_roles").Scan(&adminRoles); err != nil {
					t.Fatal(err)
				}
				if roles != 2 || adminRoles != 2 {
					t.Fatalf("roles=%d admin_roles=%d, want 2 and 2 (role catalog and assignments must survive)", roles, adminRoles)
				}
				var auditorAssignment int
				if err := s.DB().QueryRow("SELECT count(*) FROM _trestle_admin_roles ar JOIN _trestle_roles r ON r.id=ar.role_id WHERE r.id='auditor'").Scan(&auditorAssignment); err != nil || auditorAssignment != 1 {
					t.Fatalf("auditor assignment=%d err=%v", auditorAssignment, err)
				}
				var collectionsCount int
				if err := s.DB().QueryRow("SELECT count(*) FROM _trestle_collections").Scan(&collectionsCount); err != nil || collectionsCount != 1 {
					t.Fatalf("collections=%d err=%v", collectionsCount, err)
				}
				var colID string
				if err := s.DB().QueryRow("SELECT id FROM _trestle_collections WHERE name='issues'").Scan(&colID); err != nil {
					t.Fatal(err)
				}
				var fieldIDs []string
				var fieldNames []string
				fieldRows, err := s.DB().Query("SELECT id,name FROM _trestle_fields WHERE collection_id=? ORDER BY position", colID)
				if err != nil {
					t.Fatal(err)
				}
				for fieldRows.Next() {
					var id, name string
					fieldRows.Scan(&id, &name)
					fieldIDs = append(fieldIDs, id)
					fieldNames = append(fieldNames, name)
				}
				fieldRows.Close()
				selectParts := []string{`_id`}
				for _, fid := range fieldIDs {
					selectParts = append(selectParts, `"`+collections.PhysicalColumnName(fid)+`"`)
				}
				raw := make([]any, len(fieldIDs))
				dest := make([]any, len(fieldIDs))
				for i := range raw {
					dest[i] = &raw[i]
				}
				var recID string
				if err := s.DB().QueryRow("SELECT " + strings.Join(selectParts, ",") + " FROM " + `"` + collections.PhysicalTableName(colID) + `"` + " WHERE _id='rec_1'").Scan(append([]any{&recID}, dest...)...); err != nil {
					t.Fatal(err)
				}
				if recID != "rec_1" {
					t.Fatalf("record id %q", recID)
				}
				for i, name := range fieldNames {
					if name == "done" {
						if b, ok := decodeAny(s.Dialect(), raw[i]).(bool); !ok || !b {
							t.Fatalf("boolean round trip got %v", raw[i])
						}
					}
					if name == "meta" {
						if v, ok := raw[i].(string); !ok || !strings.Contains(v, `"n"`) {
							t.Fatalf("json round trip got %v", raw[i])
						}
					}
				}
				_ = store.CurrentVersion
			})
		}
	}
}

func decodeAny(dialect store.Dialect, v any) any {
	if b, err := dialect.DecodeBoolean(v); err == nil {
		return b
	}
	return v
}

func TestRestoreLogicalArchive(t *testing.T) {
	for _, provider := range storetest.Providers(t) {
		portable := buildPortableFixture(t, provider)
		t.Run(provider, func(t *testing.T) {
			archive := filepath.Join(t.TempDir(), "logical.zip")
			var buffer bytes.Buffer
			zw := zip.NewWriter(&buffer)
			mw, _ := zw.Create("manifest.json")
			json.NewEncoder(mw).Encode(Manifest{Format: "trestle-backup-v1", SchemaVersion: 13, IncludesDatabase: false})
			pw, _ := zw.Create("portable.json")
			pw.Write([]byte(portable))
			zw.Close()
			os.WriteFile(archive, buffer.Bytes(), 0o600)
			target := filepath.Join(t.TempDir(), "restored")
			if err := Restore(context.Background(), archive, target); err != nil {
				t.Fatal(err)
			}
			s, err := store.Open(context.Background(), target)
			if err != nil {
				t.Fatal(err)
			}
			defer s.Close()
			var probe string
			if err := s.DB().QueryRow("SELECT value FROM _trestle_system_meta WHERE key='restore-probe'").Scan(&probe); err != nil || probe != "preserved" {
				t.Fatalf("probe=%q err=%v", probe, err)
			}
			var collectionsCount int
			if err := s.DB().QueryRow("SELECT count(*) FROM _trestle_collections").Scan(&collectionsCount); err != nil || collectionsCount != 1 {
				t.Fatalf("collections=%d err=%v", collectionsCount, err)
			}
			var admins int
			if err := s.DB().QueryRow("SELECT count(*) FROM _trestle_admins").Scan(&admins); err != nil || admins != 1 {
				t.Fatalf("admins=%d err=%v", admins, err)
			}
		})
	}
}

func TestExportSnapshotConsistency(t *testing.T) {
	for _, provider := range storetest.Providers(t) {
		t.Run(provider, func(t *testing.T) {
			s := storetest.Open(t, provider)
			populatePortableFixture(t, s)
			tx, err := beginSnapshot(context.Background(), s.DB())
			if err != nil {
				t.Fatal(err)
			}
			defer tx.Rollback()
			var before int
			if err := tx.QueryRow("SELECT count(*) FROM _trestle_admins").Scan(&before); err != nil {
				t.Fatal(err)
			}
			done := make(chan struct{})
			go func() {
				defer close(done)
				s.DB().Exec("INSERT INTO _trestle_admins(id,username,email,password_hash,created_at) VALUES('adm_extra','extra@example.com','extra@example.com','h','2026-01-01T00:00:00Z')")
			}()
			time.Sleep(100 * time.Millisecond)
			var after int
			if err := tx.QueryRow("SELECT count(*) FROM _trestle_admins").Scan(&after); err != nil {
				t.Fatal(err)
			}
			if before != after {
				t.Fatalf("snapshot inconsistent: before=%d after=%d", before, after)
			}
			tx.Rollback()
			<-done
		})
	}
}

func TestRestorePolicyRevokesSessionsAndIntegrationSecrets(t *testing.T) {
	for _, provider := range storetest.Providers(t) {
		provider := provider
		var portable string
		t.Run("export-"+provider, func(t *testing.T) {
			portable = buildPortableFixture(t, provider)
		})
		t.Run(provider, func(t *testing.T) {
			s := storetest.Open(t, provider)
			if err := Import(context.Background(), s.DB(), s.Dialect(), strings.NewReader(portable)); err != nil {
				t.Fatal(err)
			}
			var enabled bool
			var cipher []byte
			if err := s.DB().QueryRow("SELECT enabled, secret_cipher FROM _trestle_webhooks WHERE id='wh_1'").Scan(&enabled, &cipher); err != nil {
				t.Fatal(err)
			}
			if enabled || len(cipher) != 0 {
				t.Fatalf("webhook not disabled/cleared: enabled=%v cipherLen=%d", enabled, len(cipher))
			}
			var revoked int
			if err := s.DB().QueryRow("SELECT count(*) FROM _trestle_admin_sessions WHERE revoked_at IS NULL").Scan(&revoked); err != nil || revoked != 0 {
				t.Fatalf("admin sessions not revoked: %d err=%v", revoked, err)
			}
			var appAccess int
			if err := s.DB().QueryRow("SELECT count(*) FROM _trestle_app_access").Scan(&appAccess); err != nil || appAccess != 0 {
				t.Fatalf("app access not cleared: %d err=%v", appAccess, err)
			}
			var credentialHashes int
			if err := s.DB().QueryRow("SELECT count(*) FROM _trestle_credentials WHERE secret_hash IS NOT NULL").Scan(&credentialHashes); err != nil || credentialHashes != 1 {
				t.Fatalf("credential hashes lost: %d err=%v", credentialHashes, err)
			}
		})
	}
}

func TestRestorePortableArchiveToPostgres(t *testing.T) {
	url := storetest.PostgresURL(t)
	release := storetest.Lock(t, url)
	defer release()
	storetest.ResetPostgres(t, url)
	fixtureDir := t.TempDir()
	fixtureStore := openStoreAt(t, fixtureDir, "postgres", url)
	populatePortableFixture(t, fixtureStore)
	var portable bytes.Buffer
	if err := Export(context.Background(), fixtureStore.DB(), fixtureStore.Dialect(), &portable); err != nil {
		t.Fatal(err)
	}
	fixtureStore.Close()
	storetest.ResetPostgres(t, url)
	// Pre-initialize the empty destination at the current schema (start once),
	// then leave it empty.
	init := openStoreAt(t, t.TempDir(), "postgres", url)
	init.Close()
	t.Run("restore-to-postgres", func(t *testing.T) {
		archive := filepath.Join(t.TempDir(), "pg-backup.zip")
		var buffer bytes.Buffer
		zw := zip.NewWriter(&buffer)
		mw, _ := zw.Create("manifest.json")
		json.NewEncoder(mw).Encode(Manifest{Format: "trestle-backup-v1", SchemaVersion: 13, IncludesDatabase: false})
		pw, _ := zw.Create("portable.json")
		pw.Write(portable.Bytes())
		zw.Close()
		os.WriteFile(archive, buffer.Bytes(), 0o600)
		if err := Restore(context.Background(), archive, "", RestoreOptions{Provider: store.Postgres, URL: url}); err != nil {
			t.Fatal(err)
		}
		s := openStoreAt(t, t.TempDir(), "postgres", url)
		defer s.Close()
		var admins int
		if err := s.DB().QueryRow("SELECT count(*) FROM _trestle_admins").Scan(&admins); err != nil || admins != 1 {
			t.Fatalf("admins=%d err=%v", admins, err)
		}
		var enabled bool
		if err := s.DB().QueryRow("SELECT enabled FROM _trestle_webhooks WHERE id='wh_1'").Scan(&enabled); err != nil || enabled {
			t.Fatalf("webhook enabled after restore: %v err=%v", enabled, err)
		}
	})
}

func buildArchive(t *testing.T, entries map[string][]byte) string {
	t.Helper()
	archive := filepath.Join(t.TempDir(), "hostile.zip")
	var buffer bytes.Buffer
	zw := zip.NewWriter(&buffer)
	for name, data := range entries {
		w, _ := zw.Create(name)
		w.Write(data)
	}
	zw.Close()
	os.WriteFile(archive, buffer.Bytes(), 0o600)
	return archive
}

func TestPostgresRestorePreflightsHostileArchives(t *testing.T) {
	url := storetest.PostgresURL(t)
	release := storetest.Lock(t, url)
	defer release()
	validManifest := []byte(`{"format":"trestle-backup-v1","schemaVersion":13}`)
	futureManifest := []byte(`{"format":"trestle-backup-v1","schemaVersion":999}`)
	cases := []struct {
		name    string
		entries map[string][]byte
		want    string
	}{
		{"missing manifest", map[string][]byte{"portable.json": []byte("{}")}, "manifest"},
		{"future schema", map[string][]byte{"manifest.json": futureManifest, "portable.json": []byte("{}")}, "newer"},
		{"traversal", map[string][]byte{"manifest.json": validManifest, "../escape": []byte("x"), "portable.json": []byte("{}")}, "unsafe archive path"},
		{"unexpected entry", map[string][]byte{"manifest.json": validManifest, "portable.json": []byte("{}"), "evil.txt": []byte("x")}, "unexpected"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			storetest.ResetPostgres(t, url)
			init := openStoreAt(t, t.TempDir(), "postgres", url)
			init.Close()
			archive := buildArchive(t, tc.entries)
			err := Restore(context.Background(), archive, "", RestoreOptions{Provider: store.Postgres, URL: url})
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("error=%v, want %q", err, tc.want)
			}
		})
	}
	// Symlink and duplicate entries are rejected too.
	t.Run("symlink", func(t *testing.T) {
		storetest.ResetPostgres(t, url)
		init := openStoreAt(t, t.TempDir(), "postgres", url)
		init.Close()
		archive := filepath.Join(t.TempDir(), "symlink.zip")
		var buffer bytes.Buffer
		zw := zip.NewWriter(&buffer)
		mw, _ := zw.Create("manifest.json")
		mw.Write(validManifest)
		hdr := &zip.FileHeader{Name: "portable.json"}
		hdr.SetMode(os.ModeSymlink | 0o777)
		pw, _ := zw.CreateHeader(hdr)
		pw.Write([]byte("{}"))
		zw.Close()
		os.WriteFile(archive, buffer.Bytes(), 0o600)
		if err := Restore(context.Background(), archive, "", RestoreOptions{Provider: store.Postgres, URL: url}); err == nil || !strings.Contains(err.Error(), "symlink") {
			t.Fatalf("error=%v, want symlink", err)
		}
	})
	t.Run("duplicate", func(t *testing.T) {
		storetest.ResetPostgres(t, url)
		init := openStoreAt(t, t.TempDir(), "postgres", url)
		init.Close()
		archive := filepath.Join(t.TempDir(), "dup.zip")
		var buffer bytes.Buffer
		zw := zip.NewWriter(&buffer)
		for i := 0; i < 2; i++ {
			w, _ := zw.Create("portable.json")
			w.Write([]byte("{}"))
		}
		zw.Close()
		os.WriteFile(archive, buffer.Bytes(), 0o600)
		if err := Restore(context.Background(), archive, "", RestoreOptions{Provider: store.Postgres, URL: url}); err == nil || !strings.Contains(err.Error(), "duplicate") {
			t.Fatalf("error=%v, want duplicate", err)
		}
	})
}

func TestPostgresRestoreRequiresEmptyInitializedDestination(t *testing.T) {
	url := storetest.PostgresURL(t)
	release := storetest.Lock(t, url)
	defer release()
	portable := buildPortableFixture(t, "sqlite")
	// Raw destination: not initialized -> refused.
	storetest.ResetPostgres(t, url)
	archive := filepath.Join(t.TempDir(), "pg.zip")
	writeArchive(t, archive, Manifest{Format: "trestle-backup-v1", SchemaVersion: 13}, map[string][]byte{"portable.json": []byte(portable)})
	if err := Restore(context.Background(), archive, "", RestoreOptions{Provider: store.Postgres, URL: url}); err == nil || !strings.Contains(err.Error(), "initialized") {
		t.Fatalf("raw destination error=%v", err)
	}
	// Initialized but non-empty destination: refused, unchanged.
	init := openStoreAt(t, t.TempDir(), "postgres", url)
	init.DB().Exec("INSERT INTO _trestle_admins(id,username,email,password_hash,created_at) VALUES('adm_occ','occ@example.com','occ@example.com','h','2026-01-01T00:00:00Z')")
	init.Close()
	before := digestPostgresTables(t, url)
	if err := Restore(context.Background(), archive, "", RestoreOptions{Provider: store.Postgres, URL: url}); err == nil || !strings.Contains(err.Error(), "not empty") {
		t.Fatalf("non-empty destination error=%v", err)
	}
	after := digestPostgresTables(t, url)
	if before != after {
		t.Fatal("failed restore changed the non-empty destination")
	}
}

func digestPostgresTables(t *testing.T, url string) string {
	t.Helper()
	db, err := store.OpenWith(context.Background(), store.Options{DataDir: t.TempDir(), Provider: store.Postgres, URL: url, MaxOpen: 2, MaxIdle: 1})
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	var admins int
	db.DB().QueryRow("SELECT count(*) FROM _trestle_admins").Scan(&admins)
	return strconv.Itoa(admins)
}

// TestRestoreRegistrationPolicyAndInvitations proves restore semantics for the
// registration policy and invitations:
//   - a v15+ archive restores its saved policy, replacing the fresh-install seed;
//   - a pre-v15 archive (SchemaVersion < 15) restores open (the historical era);
//   - restore revokes only genuinely outstanding invitations (used and
//     already-revoked and expired states are preserved);
//   - no raw token is ever exported.
func TestRestoreRegistrationPolicyAndInvitations(t *testing.T) {
	for _, provider := range storetest.Providers(t) {
		provider := provider
		var raw string
		t.Run("export-"+provider, func(t *testing.T) {
			src := storetest.Open(t, provider)
			if _, err := src.DB().Exec("UPDATE _trestle_app_registration_policy SET policy='invite' WHERE id=1"); err != nil {
				t.Fatal(err)
			}
			now := time.Now().UTC().Format(time.RFC3339Nano)
			hash := func(v string) []byte { h := sha256.Sum256([]byte(v)); return h[:] }
			seed := [][4]string{
				{"inv_used", "activate", "used@example.com", "2026-01-01T00:00:00Z"},
				{"inv_revoked", "activate", "revoked@example.com", ""},
				{"inv_expired", "activate", "expired@example.com", ""},
				{"inv_open", "activate", "open@example.com", ""},
			}
			for _, row := range seed {
				if _, err := src.DB().Exec("INSERT INTO _trestle_app_invitations(id,kind,email,token_hash,created_at,expires_at,used_at,revoked_at) VALUES(?,?,?,?,?,?,?,?)",
					row[0], row[1], row[2], hash(row[0]), now, now, nullRow(row[3]), nullRow(row[3])); err != nil {
					t.Fatal(err)
				}
			}
			if _, err := src.DB().Exec("UPDATE _trestle_app_invitations SET used_at=? WHERE id='inv_used'", now); err != nil {
				t.Fatal(err)
			}
			if _, err := src.DB().Exec("UPDATE _trestle_app_invitations SET revoked_at=? WHERE id='inv_revoked'", now); err != nil {
				t.Fatal(err)
			}
			if _, err := src.DB().Exec("UPDATE _trestle_app_invitations SET expires_at='2000-01-01T00:00:00Z' WHERE id='inv_expired'"); err != nil {
				t.Fatal(err)
			}
			future := time.Now().UTC().Add(24 * time.Hour).Format(time.RFC3339Nano)
			if _, err := src.DB().Exec("UPDATE _trestle_app_invitations SET expires_at=? WHERE id='inv_open'", future); err != nil {
				t.Fatal(err)
			}
			var buf bytes.Buffer
			if err := Export(context.Background(), src.DB(), src.Dialect(), &buf); err != nil {
				t.Fatal(err)
			}
			raw = buf.String()
			for _, tok := range []string{"inv_used", "inv_revoked", "inv_expired", "inv_open"} {
				if strings.Contains(raw, "raw-token-"+tok) {
					t.Fatalf("raw token for %s exported", tok)
				}
			}
		})
		t.Run(provider, func(t *testing.T) {
			dst := storetest.Open(t, provider)
			if err := Import(context.Background(), dst.DB(), dst.Dialect(), strings.NewReader(raw)); err != nil {
				t.Fatal(err)
			}
			var policy string
			if err := dst.DB().QueryRow("SELECT policy FROM _trestle_app_registration_policy WHERE id=1").Scan(&policy); err != nil {
				t.Fatal(err)
			}
			if policy != "invite" {
				t.Fatalf("restored policy %q, want invite", policy)
			}
			status := map[string]string{}
			rows, err := dst.DB().Query("SELECT id,used_at,revoked_at,expires_at FROM _trestle_app_invitations")
			if err != nil {
				t.Fatal(err)
			}
			for rows.Next() {
				var id, used, revoked, expires sql.NullString
				if err := rows.Scan(&id, &used, &revoked, &expires); err != nil {
					t.Fatal(err)
				}
				_ = expires
				switch {
				case used.Valid:
					status[id.String] = "used"
				case revoked.Valid:
					status[id.String] = "revoked"
				default:
					status[id.String] = "outstanding-or-expired"
				}
			}
			rows.Close()
			if status["inv_used"] != "used" {
				t.Fatalf("used invitation reclassified: %v", status)
			}
			if status["inv_revoked"] != "revoked" {
				t.Fatalf("revoked invitation lost its original state: %v", status)
			}
			if status["inv_expired"] != "outstanding-or-expired" {
				t.Fatalf("expired invitation changed state: %v", status)
			}
			var openRevoked string
			if err := dst.DB().QueryRow("SELECT revoked_at FROM _trestle_app_invitations WHERE id='inv_open'").Scan(&openRevoked); err != nil || openRevoked == "" {
				t.Fatalf("outstanding invitation not revoked on restore: %q err=%v", openRevoked, err)
			}
		})
	}
}

func TestRestorePrePolicyArchiveUsesOpen(t *testing.T) {
	for _, provider := range storetest.Providers(t) {
		provider := provider
		var rewritten []byte
		t.Run("export-"+provider, func(t *testing.T) {
			src := storetest.Open(t, provider)
			var buf bytes.Buffer
			if err := Export(context.Background(), src.DB(), src.Dialect(), &buf); err != nil {
				t.Fatal(err)
			}
			var bundle PortableBundle
			if err := json.Unmarshal(buf.Bytes(), &bundle); err != nil {
				t.Fatal(err)
			}
			bundle.SchemaVersion = 14
			bundle.System.RegistrationPolicy = nil
			var err error
			rewritten, err = json.Marshal(bundle)
			if err != nil {
				t.Fatal(err)
			}
		})
		t.Run(provider, func(t *testing.T) {
			dst := storetest.Open(t, provider)
			var seed string
			if err := dst.DB().QueryRow("SELECT policy FROM _trestle_app_registration_policy WHERE id=1").Scan(&seed); err != nil {
				t.Fatal(err)
			}
			if seed != "closed" {
				t.Fatalf("fresh seed %q, want closed", seed)
			}
			if err := Import(context.Background(), dst.DB(), dst.Dialect(), bytes.NewReader(rewritten)); err != nil {
				t.Fatal(err)
			}
			var policy string
			if err := dst.DB().QueryRow("SELECT policy FROM _trestle_app_registration_policy WHERE id=1").Scan(&policy); err != nil {
				t.Fatal(err)
			}
			if policy != "open" {
				t.Fatalf("pre-policy restore policy %q, want open", policy)
			}
		})
	}
}

func nullRow(v string) any {
	if v == "" {
		return nil
	}
	return v
}

// seedClusterAndPropagation installs cluster identity, one member, propagation
// profiles (including last_run_at) and propagation history on the source store
// so the portable restore policy can be exercised.
func seedClusterAndPropagation(t *testing.T, s *store.Store) {
	t.Helper()
	now := time.Now().UTC().Format(time.RFC3339Nano)
	if _, err := s.DB().Exec(`INSERT INTO _trestle_cluster_identity(singleton,node_id,installation_id,display_name,public_endpoint,public_key,private_key,capabilities_json,protocol_version,product_version,created_at) VALUES(1,'tr_node_a','tr_install_a','Node A','https://node-a.example',?,?,'["cluster.health"]',1,'test',?)`, []byte{0x01}, []byte{0x02}, now); err != nil {
		t.Fatal(err)
	}
	if _, err := s.DB().Exec(`INSERT INTO _trestle_cluster_members(node_id,installation_id,display_name,public_endpoint,public_key,capabilities_json,protocol_version,product_version,state,outbound_secret,inbound_secret_hash,credential_version,created_at,paired_at) VALUES('tr_node_b','tr_install_b','Node B','https://node-b.example',?,'["cluster.health"]',1,'test','active','plaintext-secret-must-not-leak',?,1,?,?)`, []byte{0x03}, []byte{0x04}, now, now); err != nil {
		t.Fatal(err)
	}
	if _, err := s.DB().Exec(`INSERT INTO _trestle_propagation_profiles(id,name,selector_json,kinds_json,mode,schedule,maintenance_window,enabled,created_at,updated_at,last_run_at) VALUES('prof_1','prod','{"members":true}','["request-definition"]','automatic','15m','',?,?,?,?)`, s.Dialect().Boolean(true), now, now, now); err != nil {
		t.Fatal(err)
	}
	if _, err := s.DB().Exec(`INSERT INTO _trestle_propagation_history(id,plan_id,actor,target,status,applied,failed,rolled_back,detail,created_at) VALUES('hist_1','plan_1','system:1','all','applied',2,0,0,'',?)`, now); err != nil {
		t.Fatal(err)
	}
}

// TestPortableRestorePolicyForClusterAndPropagationState verifies the portable
// format's explicit cluster/propagation restore policy across every provider
// pair: cluster identity and membership are deliberately excluded (they carry
// credentials) and this is recorded as a fail-visible notice; propagation
// profiles are restored with transient last_run_at cleared; history is
// restored; authorization roles remain intact.
func TestPortableRestorePolicyForClusterAndPropagationState(t *testing.T) {
	providers := storetest.Providers(t)
	for _, src := range providers {
		src := src
		var portable string
		t.Run("export-"+src, func(t *testing.T) {
			s := storetest.Open(t, src)
			populatePortableFixture(t, s)
			seedClusterAndPropagation(t, s)
			var buf bytes.Buffer
			if err := Export(context.Background(), s.DB(), s.Dialect(), &buf); err != nil {
				t.Fatal(err)
			}
			portable = buf.String()
		})
		for _, dst := range providers {
			dst := dst
			t.Run(src+"->"+dst, func(t *testing.T) {
				s := storetest.Open(t, dst)
				if err := Import(context.Background(), s.DB(), s.Dialect(), strings.NewReader(portable)); err != nil {
					t.Fatal(err)
				}
				// Cluster identity and membership must NOT be restored.
				var identity, members int
				if err := s.DB().QueryRow("SELECT count(*) FROM _trestle_cluster_identity").Scan(&identity); err != nil {
					t.Fatal(err)
				}
				if err := s.DB().QueryRow("SELECT count(*) FROM _trestle_cluster_members").Scan(&members); err != nil {
					t.Fatal(err)
				}
				if identity != 0 || members != 0 {
					t.Fatalf("cluster state restored: identity=%d members=%d", identity, members)
				}
				// Propagation profile restored with last_run_at cleared.
				var profileID, lastRun interface{}
				if err := s.DB().QueryRow("SELECT id,last_run_at FROM _trestle_propagation_profiles WHERE id='prof_1'").Scan(&profileID, &lastRun); err != nil {
					t.Fatalf("profile not restored: %v", err)
				}
				if lastRun != nil {
					t.Fatalf("last_run_at must be cleared on restore, got %v", lastRun)
				}
				var hist int
				if err := s.DB().QueryRow("SELECT count(*) FROM _trestle_propagation_history WHERE id='hist_1'").Scan(&hist); err != nil || hist != 1 {
					t.Fatalf("history not restored: hist=%d err=%v", hist, err)
				}
				// Fail-visible notices carried as system metadata.
				var notices int
				if err := s.DB().QueryRow("SELECT count(*) FROM _trestle_system_meta WHERE key LIKE 'restore_notice_%'").Scan(&notices); err != nil {
					t.Fatal(err)
				}
				if notices < 2 {
					t.Fatalf("expected cluster identity+membership restore notices, got %d", notices)
				}
				// Roles must remain preserved alongside the new tables.
				var roles, adminRoles int
				if err := s.DB().QueryRow("SELECT count(*) FROM _trestle_roles").Scan(&roles); err != nil {
					t.Fatal(err)
				}
				if err := s.DB().QueryRow("SELECT count(*) FROM _trestle_admin_roles").Scan(&adminRoles); err != nil {
					t.Fatal(err)
				}
				if roles != 2 || adminRoles != 2 {
					t.Fatalf("roles=%d admin_roles=%d, want 2 and 2", roles, adminRoles)
				}
				// The plaintext member secret must not appear anywhere in the archive.
				if strings.Contains(portable, "plaintext-secret-must-not-leak") {
					t.Fatal("plaintext cluster credential leaked into the portable archive")
				}
			})
		}
	}
}

// TestPortableRestoreRefusesNonEmptyClusterDestination proves a restore refuses
// a destination that already holds cluster identity or membership rather than
// silently merging topology state.
func TestPortableRestoreRefusesNonEmptyClusterDestination(t *testing.T) {
	ctx := context.Background()
	for _, provider := range storetest.Providers(t) {
		provider := provider
		t.Run(provider, func(t *testing.T) {
			var url string
			var release func()
			if provider == "postgres" {
				url = storetest.PostgresURL(t)
				release = storetest.Lock(t, url)
				storetest.ResetPostgres(t, url)
			}
			defer func() {
				if release != nil {
					release()
				}
			}()
			srcDir := t.TempDir()
			src := openStoreAt(t, srcDir, provider, url)
			populatePortableFixture(t, src)
			seedClusterAndPropagation(t, src)
			var buf bytes.Buffer
			if err := Export(ctx, src.DB(), src.Dialect(), &buf); err != nil {
				t.Fatal(err)
			}
			if err := src.Close(); err != nil {
				t.Fatal(err)
			}
			if provider == "postgres" {
				storetest.ResetPostgres(t, url)
			}
			portable := buf.String()

			dstDir := t.TempDir()
			dst := openStoreAt(t, dstDir, provider, url)
			defer dst.Close()
			if _, err := dst.DB().Exec(`INSERT INTO _trestle_cluster_identity(singleton,node_id,installation_id,display_name,public_endpoint,public_key,private_key,capabilities_json,protocol_version,product_version,created_at) VALUES(1,'other','other_i','Other','https://other.example',?,?,'[]',1,'test','now')`, []byte{0x01}, []byte{0x02}); err != nil {
				t.Fatal(err)
			}
			if err := Import(ctx, dst.DB(), dst.Dialect(), strings.NewReader(portable)); err == nil {
				t.Fatal("restore into a destination with cluster identity succeeded")
			}
		})
	}
}
