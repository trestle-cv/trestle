package backup

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/trestle-cv/trestle/internal/adminauth"
	"github.com/trestle-cv/trestle/internal/store"
)

func testHandler(t *testing.T) (*Handler, string, *http.Cookie) {
	t.Helper()
	dataDir := t.TempDir()
	database, err := store.Open(context.Background(), dataDir)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { database.Close() })
	token, csrf := "test-session-token", "test-csrf-token"
	tokenHash, csrfHash := sha256.Sum256([]byte(token)), sha256.Sum256([]byte(csrf))
	now := time.Now().UTC()
	if _, err := database.DB().Exec(`INSERT INTO _trestle_admins(id,email,password_hash,created_at) VALUES('adm_test','admin@example.test','unused',?)`, now.Format(time.RFC3339Nano)); err != nil {
		t.Fatal(err)
	}
	if _, err := database.DB().Exec(`INSERT INTO _trestle_admin_roles(admin_id,role_id) VALUES('adm_test','administrator')`); err != nil {
		t.Fatal(err)
	}
	if _, err := database.DB().Exec(`INSERT INTO _trestle_admin_sessions(id,admin_id,token_hash,csrf_hash,created_at,expires_at) VALUES('ses_test','adm_test',?,?,?,?)`, tokenHash[:], csrfHash[:], now.Format(time.RFC3339Nano), now.Add(time.Hour).Format(time.RFC3339Nano)); err != nil {
		t.Fatal(err)
	}
	handler, err := New(database.DB(), adminauth.New(database.DB()), dataDir, "local")
	if err != nil {
		t.Fatal(err)
	}
	return handler, csrf, &http.Cookie{Name: "trestle_admin_session", Value: token}
}

func authorizedRequest(t *testing.T, handler http.Handler, method, path, body, csrf string, cookie *http.Cookie) *httptest.ResponseRecorder {
	t.Helper()
	request := httptest.NewRequest(method, path, strings.NewReader(body))
	request.Host = "example.test"
	request.Header.Set("Origin", "http://example.test")
	request.Header.Set("X-Trestle-CSRF", csrf)
	request.AddCookie(cookie)
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	return response
}

func TestCreateAndListBackup(t *testing.T) {
	handler, csrf, cookie := testHandler(t)
	response := authorizedRequest(t, handler, http.MethodPost, "/admin/v1/backups", `{}`, csrf, cookie)
	if response.Code != http.StatusCreated {
		t.Fatalf("create: %d %s", response.Code, response.Body.String())
	}
	var created struct {
		ID string `json:"id"`
	}
	if err := json.NewDecoder(response.Body).Decode(&created); err != nil {
		t.Fatal(err)
	}
	if info, err := os.Stat(filepath.Join(handler.dataDir, "backups", created.ID)); err != nil || info.Size() == 0 {
		t.Fatalf("archive: %v", err)
	}
	response = authorizedRequest(t, handler, http.MethodGet, "/admin/v1/backups", "", "", cookie)
	if response.Code != http.StatusOK || !strings.Contains(response.Body.String(), created.ID) {
		t.Fatalf("list: %d %s", response.Code, response.Body.String())
	}
}

func TestImportDryRunNeverWrites(t *testing.T) {
	handler, csrf, cookie := testHandler(t)
	response := authorizedRequest(t, handler, http.MethodPost, "/admin/v1/imports/dry-run", `{"format":"trestle-export-v1","schemaVersion":13,"collections":[{"name":"notes","fields":[]}]}`, csrf, cookie)
	if response.Code != http.StatusOK || !strings.Contains(response.Body.String(), `"writes":0`) {
		t.Fatalf("dry run: %d %s", response.Code, response.Body.String())
	}
	var count int
	if err := handler.db.QueryRow(`SELECT count(*) FROM _trestle_collections`).Scan(&count); err != nil || count != 0 {
		t.Fatalf("dry run changed collections: count=%d err=%v", count, err)
	}
}
