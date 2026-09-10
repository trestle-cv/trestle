package launcher

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/trestle-cv/trestle/internal/store"
)

func testHandler(t *testing.T) *Handler {
	t.Helper()
	s, err := store.Open(context.Background(), t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.Close() })
	return &Handler{db: s.DB(), static: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { _, _ = w.Write([]byte(r.URL.Path)) })}
}

func TestAdaptiveRoot(t *testing.T) {
	h := testHandler(t)
	request := func() *httptest.ResponseRecorder {
		w := httptest.NewRecorder()
		h.Root(w, httptest.NewRequest(http.MethodGet, "/", nil))
		return w
	}
	if w := request(); w.Code != 302 || w.Header().Get("Location") != "/app/" {
		t.Fatalf("zero instances: %d %q", w.Code, w.Header().Get("Location"))
	}
	port := 7333
	if err := h.replace(context.Background(), []Instance{{ID: "one", Name: "Local", Domain: "localhost", Port: &port}}); err != nil {
		t.Fatal(err)
	}
	if w := request(); w.Code != 302 || w.Header().Get("Location") != "http://localhost:7333/app/" {
		t.Fatalf("one instance: %d %q", w.Code, w.Header().Get("Location"))
	}
	if err := h.replace(context.Background(), []Instance{{ID: "one", Name: "Local", Domain: "localhost", Port: &port}, {ID: "two", Name: "Cloud", Domain: "trestle.example"}}); err != nil {
		t.Fatal(err)
	}
	if w := request(); w.Code != 200 || strings.TrimSpace(w.Body.String()) != "/launcher.html" {
		t.Fatalf("two instances: %d %q", w.Code, w.Body.String())
	}
	unknown := httptest.NewRecorder()
	h.Root(unknown, httptest.NewRequest(http.MethodGet, "/unknown", nil))
	if unknown.Code != http.StatusNotFound {
		t.Fatalf("unknown top-level route=%d", unknown.Code)
	}
}

func TestConfigRequiresAuthenticationWithoutRenderingControls(t *testing.T) {
	h := testHandler(t)
	w := httptest.NewRecorder()
	h.Root(w, httptest.NewRequest(http.MethodGet, "/?config", nil))
	if w.Code != http.StatusUnauthorized || !strings.Contains(w.Body.String(), "Authentication required") || strings.Contains(w.Body.String(), "Current instances") {
		t.Fatalf("config denial: %d %q", w.Code, w.Body.String())
	}
}

func TestLauncherDocumentCompatibility(t *testing.T) {
	port := 7333
	items, err := normalize(Document{Version: 1, Product: "trestle", Instances: []Instance{{Name: "Local", Domain: "127.0.0.1", Port: &port}, {Name: "Cloud", Domain: "https://db.example"}}})
	if err != nil {
		t.Fatal(err)
	}
	view, err := makeView(items)
	if err != nil {
		t.Fatal(err)
	}
	if len(view.Instances) != 2 || view.Instances[0].AppURL != "http://127.0.0.1:7333/app/" || view.Instances[1].AppURL != "https://db.example/app/" {
		t.Fatalf("unexpected view: %#v", view)
	}
	if _, err := normalize(Document{Version: 1, Product: "warden", Instances: []Instance{}}); err == nil {
		t.Fatal("accepted another product")
	}
}
