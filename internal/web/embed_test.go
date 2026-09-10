package web

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestEmbeddedDashboardAndSPAFallback(t *testing.T) {
	h, err := New("")
	if err != nil {
		t.Fatal(err)
	}
	for _, route := range []string{"/", "/collections/example", "/assets/css/style.css"} {
		w := httptest.NewRecorder()
		h.ServeHTTP(w, httptest.NewRequest(http.MethodGet, route, nil))
		if w.Code != 200 {
			t.Fatalf("%s returned %d", route, w.Code)
		}
		if w.Header().Get("Content-Security-Policy") == "" {
			t.Fatal("missing CSP")
		}
	}
}

func TestDashboardAssetsAreContentVersionedAndUnversionedRequestsRevalidate(t *testing.T) {
	h, err := New("")
	if err != nil {
		t.Fatal(err)
	}
	page := httptest.NewRecorder()
	h.ServeHTTP(page, httptest.NewRequest(http.MethodGet, "/", nil))
	body := page.Body.String()
	if strings.Contains(body, "__TRESTLE_ASSET_VERSION__") || !strings.Contains(body, "/assets/js/script.js?v=") || !strings.Contains(body, "/assets/css/style.css?v=") {
		t.Fatalf("dashboard does not contain resolved asset versions: %s", body)
	}
	unversioned := httptest.NewRecorder()
	h.ServeHTTP(unversioned, httptest.NewRequest(http.MethodGet, "/assets/js/script.js", nil))
	if unversioned.Header().Get("Cache-Control") != "no-cache" {
		t.Fatalf("unversioned cache policy=%q", unversioned.Header().Get("Cache-Control"))
	}
}

func TestLauncherIncludesConfigurationSurfaceAndFavicon(t *testing.T) {
	h, err := New("")
	if err != nil { t.Fatal(err) }
	w := httptest.NewRecorder()
	h.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/launcher.html", nil))
	body:=w.Body.String()
	for _,required:=range []string{"/assets/images/favicon.svg","data-config-view","data-import","data-export","data-add-instance","data-delete-selected","/assets/css/launcher.css?v="}{if !strings.Contains(body,required){t.Errorf("launcher is missing %q",required)}}
	for _,asset:=range []string{"/assets/css/launcher.css","/assets/js/launcher.js","/assets/images/favicon.svg"}{assetResponse:=httptest.NewRecorder();h.ServeHTTP(assetResponse,httptest.NewRequest(http.MethodGet,asset,nil));if assetResponse.Code!=http.StatusOK{t.Errorf("%s returned %d",asset,assetResponse.Code)}}
}

func TestStaticOverride(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "index.html"), []byte("override-marker"), 0o600); err != nil {
		t.Fatal(err)
	}
	h, err := New(dir)
	if err != nil {
		t.Fatal(err)
	}
	w := httptest.NewRecorder()
	h.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/", nil))
	if !strings.Contains(w.Body.String(), "override-marker") {
		t.Fatal("override not served")
	}
}

func TestMissingAssetDoesNotFallback(t *testing.T) {
	h, _ := New("")
	w := httptest.NewRecorder()
	h.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/missing.js", nil))
	if w.Code != http.StatusNotFound {
		t.Fatalf("got %d", w.Code)
	}
}

func TestDashboardRetainsTopLevelAndCollectionRoutes(t *testing.T) {
	script, err := embedded.ReadFile("public/assets/js/script.js")
	if err != nil {
		t.Fatal(err)
	}
	source := string(script)
	for _, required := range []string{"restoreDashboardRoute", "openCollectionRoute", "/collections/${encodeURIComponent(collection)}", "trestle:authenticated", "popstate"} {
		if !strings.Contains(source, required) {
			t.Errorf("dashboard routing is missing %q", required)
		}
	}
}
