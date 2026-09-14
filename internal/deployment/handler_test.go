package deployment

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/trestle-cv/trestle/internal/adminauth"
	"github.com/trestle-cv/trestle/internal/store"
)

func TestDiagnosticsAreAuthenticatedAndRedacted(t *testing.T) {
	database, err := store.Open(context.Background(), t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close()
	admin := adminauth.New(database.DB())
	setup := httptest.NewRequest(http.MethodPost, "/admin/v1/setup", strings.NewReader(`{"username":"admin","email":"admin@example.com","password":"mudblood","applicationRegistrationPolicy":"closed"}`))
	setup.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	admin.ServeHTTP(w, setup)
	if w.Code != 200 {
		t.Fatalf("setup: %d %s", w.Code, w.Body.String())
	}
	cookie := w.Result().Cookies()[0]

	h := New(admin, Options{Listen: "127.0.0.1:8090", StorageBackend: "s3", TrustedProxies: []netip.Prefix{netip.MustParsePrefix("127.0.0.1/32")}, ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 5 * time.Minute, IdleTimeout: time.Minute, MaxHeaderBytes: 1 << 20})
	w = httptest.NewRecorder()
	h.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/admin/v1/deployment", nil))
	if w.Code != 403 {
		t.Fatalf("unauthenticated status %d", w.Code)
	}
	r := httptest.NewRequest(http.MethodGet, "/admin/v1/support-bundle", nil)
	r.AddCookie(cookie)
	w = httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if w.Code != 200 {
		t.Fatalf("support: %d %s", w.Code, w.Body.String())
	}
	var result map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &result); err != nil {
		t.Fatal(err)
	}
	if result["secretsIncluded"] != false || !strings.Contains(w.Header().Get("Content-Disposition"), "support") {
		t.Fatalf("unsafe response: %#v", result)
	}
}
