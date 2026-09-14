package files

import (
	"bytes"
	"encoding/json"
	"github.com/trestle-cv/trestle/internal/adminauth"
	"github.com/trestle-cv/trestle/internal/identities"
	"github.com/trestle-cv/trestle/internal/storetest"
	"io"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

type fixture struct {
	h      *Handler
	cookie *http.Cookie
	csrf   string
}

func setup(t *testing.T, provider string) fixture {
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
	return fixture{h, w.Result().Cookies()[0], session.CSRF}
}
func (f fixture) request(method, path string, body io.Reader, contentType string) *httptest.ResponseRecorder {
	r := httptest.NewRequest(method, "http://example.test"+path, body)
	r.Host = "example.test"
	r.Header.Set("Origin", "http://example.test")
	r.Header.Set("X-Trestle-CSRF", f.csrf)
	r.Header.Set("Content-Type", contentType)
	r.AddCookie(f.cookie)
	w := httptest.NewRecorder()
	f.h.ServeHTTP(w, r)
	return w
}
func (f fixture) upload(t *testing.T, name, content string) Metadata {
	var body bytes.Buffer
	writer := multipart.NewWriter(&body)
	part, _ := writer.CreateFormFile("file", name)
	io.WriteString(part, content)
	writer.Close()
	w := f.request("POST", "/api/v1/files", &body, writer.FormDataContentType())
	if w.Code != 201 {
		t.Fatalf("upload %d %s", w.Code, w.Body.String())
	}
	var m Metadata
	json.Unmarshal(w.Body.Bytes(), &m)
	return m
}
func TestUploadGeneratedPathRangeAndDelete(t *testing.T) {
	for _, provider := range storetest.Providers(t) {
		t.Run(provider, func(t *testing.T) {
			f := setup(t, provider)
			m := f.upload(t, "../../evil.txt", "abcdefghij")
			if m.Name != "evil.txt" || m.Size != 10 {
				t.Fatalf("metadata %#v", m)
			}
			w := f.request("GET", "/api/v1/files/"+m.ID, nil, "")
			if w.Code != 200 || w.Body.String() != "abcdefghij" {
				t.Fatal(w.Code)
			}
			r := httptest.NewRequest("GET", "http://example.test/api/v1/files/"+m.ID, nil)
			r.Header.Set("Range", "bytes=2-5")
			r.AddCookie(f.cookie)
			w = httptest.NewRecorder()
			f.h.ServeHTTP(w, r)
			if w.Code != 206 || w.Body.String() != "cdef" {
				t.Fatalf("range %d %q", w.Code, w.Body.String())
			}
			w = f.request("DELETE", "/api/v1/files/"+m.ID, nil, "")
			if w.Code != 204 {
				t.Fatal(w.Code)
			}
		})
	}
}

func TestDownloadRejectsSymlinkAndUnknownCaller(t *testing.T) {
	for _, provider := range storetest.Providers(t) {
		t.Run(provider, func(t *testing.T) {
			f := setup(t, provider)
			m := f.upload(t, "safe.txt", "secret")
			var key string
			if err := f.h.db.QueryRow("SELECT storage_key FROM _trestle_files WHERE id=?", m.ID).Scan(&key); err != nil {
				t.Fatal(err)
			}
			path := filepath.Join(f.h.root, key)
			os.Remove(path)
			outside := filepath.Join(t.TempDir(), "outside")
			os.WriteFile(outside, []byte("outside secret"), 0600)
			if err := os.Symlink(outside, path); err != nil {
				t.Skip("symlinks unavailable")
			}
			w := f.request("GET", "/api/v1/files/"+m.ID, nil, "")
			if w.Code != 404 || strings.Contains(w.Body.String(), "outside secret") {
				t.Fatalf("symlink %d %q", w.Code, w.Body.String())
			}
			r := httptest.NewRequest("GET", "/api/v1/files/"+m.ID, nil)
			w = httptest.NewRecorder()
			f.h.ServeHTTP(w, r)
			if w.Code != 403 {
				t.Fatalf("unknown caller %d", w.Code)
			}
		})
	}
}
func TestQuotaSymlinkAndCleanup(t *testing.T) {
	for _, provider := range storetest.Providers(t) {
		t.Run(provider, func(t *testing.T) {
			f := setup(t, provider)
			f.h.quota = 3
			var body bytes.Buffer
			writer := multipart.NewWriter(&body)
			part, _ := writer.CreateFormFile("file", "large.bin")
			part.Write([]byte("four"))
			writer.Close()
			w := f.request("POST", "/api/v1/files", &body, writer.FormDataContentType())
			if w.Code != 413 {
				t.Fatal(w.Code)
			}
			orphan := filepath.Join(f.h.root, "orphan")
			os.WriteFile(orphan, []byte("x"), 0600)
			w = f.request("POST", "/admin/v1/files/cleanup", nil, "")
			if w.Code != 200 {
				t.Fatal(w.Code)
			}
			if _, err := os.Stat(orphan); !os.IsNotExist(err) {
				t.Fatal("orphan survived")
			}
		})
	}
}
