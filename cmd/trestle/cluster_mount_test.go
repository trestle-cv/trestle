package main

import (
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/trestle-cv/trestle/internal/server"
)

// TestClusterAPIMountedAtPublicPath is a regression for the production-composition
// defect where the cluster peer surface was registered on the application API mux
// (/api/cluster/v1/...) but that mux is itself mounted at /api/v1/, leaving the
// peer-facing join/collect/RPC endpoints unreachable at their public paths.
func TestClusterAPIMountedAtPublicPath(t *testing.T) {
	appAPI := http.NewServeMux()
	appAPI.Handle("/api/v1/collections/", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	cluster := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.URL.Path == "/api/cluster/v1/join":
			w.WriteHeader(http.StatusOK)
		case strings.HasPrefix(r.URL.Path, "/api/cluster/v1/rpc/"):
			w.WriteHeader(http.StatusOK)
		default:
			http.NotFound(w, r)
		}
	})
	rootMux := http.NewServeMux()
	rootMux.Handle("/api/cluster/v1/", cluster)
	rootMux.Handle("/", http.HandlerFunc(http.NotFound))
	app := server.NewWithOptions(slog.New(slog.NewTextHandler(io.Discard, nil)), nil, appAPI, nil, server.Options{Root: rootMux})

	for _, p := range []string{"/api/cluster/v1/join", "/api/cluster/v1/rpc/status"} {
		req := httptest.NewRequest(http.MethodPost, p, nil)
		rec := httptest.NewRecorder()
		app.Handler().ServeHTTP(rec, req)
		if rec.Code != http.StatusOK {
			t.Fatalf("cluster peer path %s unreachable: got %d", p, rec.Code)
		}
	}
	req := httptest.NewRequest(http.MethodGet, "/api/v1/collections/x", nil)
	rec := httptest.NewRecorder()
	app.Handler().ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("application API under /api/v1/ shadowed by root mount: got %d", rec.Code)
	}
}

// TestClusterAPIMountNotBuriedUnderAppAPI reproduces the pre-fix wiring: the
// cluster handler registered on the application API mux (which the server mounts
// at /api/v1/) cannot be reached at its public path. It documents the failure
// mode the fix exists to prevent.
func TestClusterAPIMountNotBuriedUnderAppAPI(t *testing.T) {
	appAPI := http.NewServeMux()
	appAPI.Handle("/api/v1/collections/", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	appAPI.Handle("/api/cluster/v1/", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	app := server.NewWithOptions(slog.New(slog.NewTextHandler(io.Discard, nil)), nil, appAPI, nil, server.Options{})

	req := httptest.NewRequest(http.MethodPost, "/api/cluster/v1/join", nil)
	rec := httptest.NewRecorder()
	app.Handler().ServeHTTP(rec, req)
	if rec.Code != http.StatusNotFound {
		t.Fatalf("expected cluster path buried under /api/v1/ mount to be unreachable; got %d", rec.Code)
	}
}
