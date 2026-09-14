package databasesetup

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/trestle-cv/trestle/internal/adminauth"
	"github.com/trestle-cv/trestle/internal/config"
	"github.com/trestle-cv/trestle/internal/store"
	"github.com/trestle-cv/trestle/internal/storetest"
)

// TestFirstRunPostgresWorkflow drives the ordinary-user first-run lifecycle
// against each provider (SQLite always; real PostgreSQL when
// TRESTLE_TEST_POSTGRES_URL is configured): fresh state, choose provider,
// test+persist the connection, simulate the required restart (the provider
// becomes fixed), create the first administrator, and sign in. It asserts the
// CP2 contract transitions: the provider is fixed after restart, setup closes
// after the first administrator, the seven-character password minimum holds,
// configuration writes are atomic and 0600, and no connection material leaks.
func TestFirstRunPostgresWorkflow(t *testing.T) {
	for _, provider := range storetest.Providers(t) {
		t.Run(provider, func(t *testing.T) {
			ctx := context.Background()
			dataDir := t.TempDir()
			var url string
			var release func()
			if provider == "postgres" {
				url = storetest.PostgresURL(t)
				release = storetest.Lock(t, url)
				storetest.ResetPostgres(t, url)
				t.Cleanup(func() {
					storetest.ResetPostgres(t, url)
					release()
				})
			}
			database, err := store.OpenWith(ctx, store.Options{DataDir: dataDir, Provider: store.Provider(provider), URL: url, MaxOpen: 8, MaxIdle: 2, ConnectTimeout: 5 * time.Second, ConnMaxLifetime: time.Hour})
			if err != nil {
				t.Fatal(err)
			}
			defer database.Close()
			admin := adminauth.New(database.DB(), provider)
			admin.SetSetupGuard(func(context.Context) error {
				stored, found, err := config.ReadDatabaseBootstrap(dataDir)
				if err != nil {
					return err
				}
				if found && stored.Provider != provider {
					return errors.New("configured database is pending restart")
				}
				return nil
			})
			h := New(admin, Options{DataDir: dataDir, Current: store.SQLite, MaxOpen: 8, MaxIdle: 2, ConnectTimeout: 5 * time.Second, ConnMaxLifetime: time.Hour})

			var status struct {
				SetupRequired bool `json:"setupRequired"`
			}
			var setup struct {
				Provider   string `json:"provider"`
				Explicit   bool   `json:"explicit"`
				Selectable bool   `json:"selectable"`
			}
			serve := func(target any, method, path, body, origin string) *httptest.ResponseRecorder {
				r := httptest.NewRequest(method, path, strings.NewReader(body))
				r.Host = "example.test"
				if origin != "" {
					r.Header.Set("Origin", origin)
				}
				if method == http.MethodPost {
					r.Header.Set("Content-Type", "application/json")
				}
				w := httptest.NewRecorder()
				if path == "/admin/v1/database/setup" {
					h.ServeHTTP(w, r)
				} else {
					admin.ServeHTTP(w, r)
				}
				if target != nil && w.Code == http.StatusOK {
					if err := json.Unmarshal(w.Body.Bytes(), target); err != nil {
						t.Fatalf("decode %s: %v", path, err)
					}
				}
				return w
			}

			// 1. Fresh state: setup is required and the database is selectable.
			serve(&status, http.MethodGet, "/admin/v1/setup/status", "", "")
			if !status.SetupRequired {
				t.Fatal("fresh instance must require first-run setup")
			}
			serve(&setup, http.MethodGet, "/admin/v1/database/setup", "", "")
			if !setup.Selectable || setup.Provider != "sqlite" {
				t.Fatalf("fresh setup=%#v, want selectable running provider sqlite", setup)
			}

			// 2. Test and persist the connection. Restart is required when the
			// provider differs from the currently running one.
			var applied struct {
				Provider        string `json:"provider"`
				Version         string `json:"version"`
				RestartRequired bool   `json:"restartRequired"`
			}
			resp := serve(&applied, http.MethodPost, "/admin/v1/database/setup", `{"provider":"`+provider+`","url":"`+url+`"}`, "http://example.test")
			if resp.Code != http.StatusOK {
				t.Fatalf("persist status=%d body=%s", resp.Code, resp.Body.String())
			}
			if applied.RestartRequired != (provider != "sqlite") {
				t.Fatalf("restartRequired=%v provider=%s", applied.RestartRequired, provider)
			}
			if provider == "postgres" && applied.Version == "" {
				t.Fatal("postgres probe must report a server version")
			}
			if url != "" && strings.Contains(resp.Body.String(), url) {
				t.Fatal("connection URL leaked in setup response")
			}
			stored, found, err := config.ReadDatabaseBootstrap(dataDir)
			if err != nil || !found || stored.Provider != provider || stored.URL != url {
				t.Fatalf("stored=%#v found=%v err=%v", stored, found, err)
			}
			info, err := os.Stat(filepath.Join(dataDir, "database.json"))
			if err != nil {
				t.Fatal(err)
			}
			if info.Mode().Perm() != 0o600 {
				t.Fatalf("database.json perms=%o, want 600", info.Mode().Perm())
			}
			// Atomic write: no temporary file may remain after publication.
			if _, err := os.Stat(filepath.Join(dataDir, "database.json.new")); !os.IsNotExist(err) {
				t.Fatalf("atomic persistence left a temporary file behind (err=%v)", err)
			}

			// 3. Restart: the provider is fixed (explicit, not selectable) and
			// setup is still required so the first administrator can be created.
			restarted := New(admin, Options{DataDir: dataDir, Current: store.Provider(provider), Explicit: true, MaxOpen: 8, MaxIdle: 2, ConnectTimeout: 5 * time.Second, ConnMaxLifetime: time.Hour})
			var after struct {
				Provider   string `json:"provider"`
				Explicit   bool   `json:"explicit"`
				Selectable bool   `json:"selectable"`
			}
			w := httptest.NewRecorder()
			restarted.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/admin/v1/database/setup", nil))
			if err := json.Unmarshal(w.Body.Bytes(), &after); err != nil {
				t.Fatal(err)
			}
			if !after.Explicit || after.Selectable || after.Provider != provider {
				t.Fatalf("after restart=%#v, want explicit non-selectable provider %s", after, provider)
			}
			serve(&status, http.MethodGet, "/admin/v1/setup/status", "", "")
			if !status.SetupRequired {
				t.Fatal("setup must still be required after restart (no administrator yet)")
			}

			// 4. The seven-character password minimum is enforced.
			short := serve(nil, http.MethodPost, "/admin/v1/setup", `{"username":"admin","email":"admin@example.com","password":"123456","applicationRegistrationPolicy":"closed"}`, "http://example.test")
			if short.Code != http.StatusUnprocessableEntity {
				t.Fatalf("short password status=%d body=%s", short.Code, short.Body.String())
			}

			// 5. Create the first administrator and confirm setup closes.
			created := serve(nil, http.MethodPost, "/admin/v1/setup", `{"username":"admin","email":"admin@example.com","password":"sevenchars","applicationRegistrationPolicy":"closed"}`, "http://example.test")
			if created.Code != http.StatusOK {
				t.Fatalf("setup status=%d body=%s", created.Code, created.Body.String())
			}
			serve(&status, http.MethodGet, "/admin/v1/setup/status", "", "")
			if status.SetupRequired {
				t.Fatal("setup must be complete after the first administrator")
			}
			if second := serve(nil, http.MethodPost, "/admin/v1/setup", `{"username":"admin","email":"other@example.com","password":"sevenchars","applicationRegistrationPolicy":"closed"}`, "http://example.test"); second.Code != http.StatusConflict {
				t.Fatalf("second setup status=%d body=%s", second.Code, second.Body.String())
			}
			if closed := serve(nil, http.MethodGet, "/admin/v1/database/setup", "", ""); closed.Code != http.StatusConflict {
				t.Fatalf("database setup after completion status=%d body=%s", closed.Code, closed.Body.String())
			}

			// 6. Sign in succeeds with the created administrator.
			var session struct {
				Authenticated bool `json:"authenticated"`
			}
			login := serve(&session, http.MethodPost, "/admin/v1/session", `{"email":"admin@example.com","password":"sevenchars"}`, "http://example.test")
			if login.Code != http.StatusOK || !session.Authenticated {
				t.Fatalf("sign in status=%d body=%s", login.Code, login.Body.String())
			}
			if strings.Contains(login.Body.String(), "sevenchars") {
				t.Fatal("password leaked in sign-in response")
			}
		})
	}
}
