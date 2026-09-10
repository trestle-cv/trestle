package server

import (
	"bytes"
	"context"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/trestle-cv/trestle/internal/requestmeta"
)

func TestHealthReadinessAndRequestID(t *testing.T) {
	var logs bytes.Buffer
	s := New(slog.New(slog.NewJSONHandler(&logs, nil)))
	for _, test := range []struct {
		path   string
		status int
	}{{"/system/health", 200}, {"/system/ready", 503}} {
		r := httptest.NewRequest(http.MethodGet, test.path, nil)
		w := httptest.NewRecorder()
		s.Handler().ServeHTTP(w, r)
		if w.Code != test.status {
			t.Fatalf("%s: got %d", test.path, w.Code)
		}
		if w.Header().Get("X-Request-ID") == "" {
			t.Fatal("missing request ID")
		}
		for _, header := range []string{"Content-Security-Policy", "Permissions-Policy", "X-Content-Type-Options", "X-Frame-Options", "Referrer-Policy"} {
			if w.Header().Get(header) == "" {
				t.Fatalf("%s: missing %s", test.path, header)
			}
		}
	}
	s.SetReady(true)
	w := httptest.NewRecorder()
	s.Handler().ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/system/ready", nil))
	if w.Code != 200 || !strings.Contains(w.Body.String(), "ready") {
		t.Fatalf("unexpected response: %d %s", w.Code, w.Body.String())
	}
	if strings.Contains(logs.String(), "Authorization") {
		t.Fatal("sensitive header logged")
	}
}

func TestGantryRouteConventionMounts(t *testing.T) {
	dashboard := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.Write([]byte("app:" + r.URL.Path)) })
	root := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.Write([]byte("launcher")) })
	manage := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.Write([]byte("manage")) })
	s := NewWithOptions(slog.Default(), dashboard, nil, nil, Options{Root: root, Manage: manage})
	for _, tc := range []struct {
		path     string
		status   int
		body     string
		location string
	}{{"/", 200, "launcher", ""}, {"/app", 308, "", "/app/"}, {"/app/overview", 200, "app:/app/overview", ""}, {"/assets/test.css", 200, "app:/assets/test.css", ""}, {"/manage", 308, "", "/manage/"}, {"/manage/", 200, "manage", ""}, {"/healthz", 200, "status", ""}} {
		w := httptest.NewRecorder()
		s.Handler().ServeHTTP(w, httptest.NewRequest(http.MethodGet, tc.path, nil))
		if w.Code != tc.status || !strings.Contains(w.Body.String(), tc.body) || w.Header().Get("Location") != tc.location {
			t.Errorf("%s: status=%d body=%q location=%q", tc.path, w.Code, w.Body.String(), w.Header().Get("Location"))
		}
	}
}

func TestForwardedHeadersRequireTrustedImmediatePeer(t *testing.T) {
	echo := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(requestmeta.Scheme(r) + " " + requestmeta.ClientIP(r)))
	})
	s := NewWithOptions(slog.Default(), echo, nil, nil, Options{TrustedProxies: []netip.Prefix{netip.MustParsePrefix("10.0.0.0/8")}})

	untrusted := httptest.NewRequest(http.MethodGet, "/", nil)
	untrusted.RemoteAddr = "198.51.100.10:1234"
	untrusted.Header.Set("X-Forwarded-Proto", "https")
	untrusted.Header.Set("X-Forwarded-For", "203.0.113.7")
	w := httptest.NewRecorder()
	s.Handler().ServeHTTP(w, untrusted)
	if got := strings.TrimSpace(w.Body.String()); got != "http 198.51.100.10" {
		t.Fatalf("untrusted forwarding accepted: %q", got)
	}

	trusted := httptest.NewRequest(http.MethodGet, "/", nil)
	trusted.RemoteAddr = "10.1.2.3:1234"
	trusted.Header.Set("X-Forwarded-Proto", "https")
	trusted.Header.Set("X-Forwarded-For", "203.0.113.7")
	w = httptest.NewRecorder()
	s.Handler().ServeHTTP(w, trusted)
	if got := strings.TrimSpace(w.Body.String()); got != "https 203.0.113.7" {
		t.Fatalf("trusted forwarding ignored: %q", got)
	}
}

func TestForwardedChainStopsAtFirstUntrustedHop(t *testing.T) {
	echo := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.Write([]byte(requestmeta.ClientIP(r))) })
	s := NewWithOptions(slog.Default(), echo, nil, nil, Options{TrustedProxies: []netip.Prefix{netip.MustParsePrefix("10.0.0.0/8")}})
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	r.RemoteAddr = "10.1.2.3:1234"
	r.Header.Set("X-Forwarded-For", "192.0.2.50, 198.51.100.9, 10.2.3.4")
	w := httptest.NewRecorder()
	s.Handler().ServeHTTP(w, r)
	if got := strings.TrimSpace(w.Body.String()); got != "198.51.100.9" {
		t.Fatalf("unexpected client: %q", got)
	}
}

// TestReadinessDistinguishesDatabaseUnavailable proves /system/health stays
// 200 (process liveness) while /system/ready returns 503 database_unavailable
// when the database probe fails and 200 when it recovers.
func TestReadinessDistinguishesDatabaseUnavailable(t *testing.T) {
	app := New(slog.New(slog.NewTextHandler(io.Discard, nil)))
	app.SetReady(true)
	var dbUp atomic.Bool
	dbUp.Store(true)
	app.SetDatabaseCheck(func(context.Context) error {
		if !dbUp.Load() {
			return errors.New("database down")
		}
		return nil
	})
	get := func(path string) *httptest.ResponseRecorder {
		w := httptest.NewRecorder()
		app.Handler().ServeHTTP(w, httptest.NewRequest("GET", path, nil))
		return w
	}
	if w := get("/system/ready"); w.Code != 200 || !strings.Contains(w.Body.String(), `"ready"`) {
		t.Fatalf("ready up=%d %s", w.Code, w.Body.String())
	}
	dbUp.Store(false)
	if w := get("/system/health"); w.Code != 200 {
		t.Fatalf("health liveness must stay 200 while db down, got %d", w.Code)
	}
	if w := get("/system/ready"); w.Code != 503 || !strings.Contains(w.Body.String(), "database_unavailable") {
		t.Fatalf("ready down=%d %s", w.Code, w.Body.String())
	}
	dbUp.Store(true)
	if w := get("/system/ready"); w.Code != 200 || !strings.Contains(w.Body.String(), `"ready"`) {
		t.Fatalf("ready recovered=%d %s", w.Code, w.Body.String())
	}
}
