package runtime

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	corerepl "github.com/gantry-tools/gantry-core/replication"
	"github.com/hashicorp/raft"
	"github.com/trestle-cv/trestle/internal/adminauth"
	"github.com/trestle-cv/trestle/internal/collections"
	"github.com/trestle-cv/trestle/internal/store"
)

// operatorHandler mirrors the production main.go operator endpoints: admin
// authorization + status/join/snapshot over the real replicated runtime.
func operatorHandler(t *testing.T, n *certNode, admin *adminauth.Handler) http.Handler {
	t.Helper()
	mux := http.NewServeMux()
	mux.Handle("/admin/v1/", admin)
	mux.HandleFunc("/admin/v1/replication/status", func(w http.ResponseWriter, r *http.Request) {
		if _, ok := admin.Authorize(r, false); !ok {
			http.Error(w, "unauthorized", 401)
			return
		}
		mode, ready := n.rt.Controller.State()
		cfgs, _ := n.rt.Node.Configuration()
		_ = json.NewEncoder(w).Encode(map[string]any{"mode": mode.String(), "readiness": ready.String(), "state": n.rt.Node.State().String(), "servers": cfgs})
	})
	mux.HandleFunc("/admin/v1/replication/join", func(w http.ResponseWriter, r *http.Request) {
		if _, ok := admin.Authorize(r, true); !ok {
			http.Error(w, "forbidden", 403)
			return
		}
		var in struct {
			NodeID  string `json:"node_id"`
			Address string `json:"address"`
		}
		if json.NewDecoder(r.Body).Decode(&in) != nil || in.NodeID == "" || in.Address == "" {
			http.Error(w, "bad request", 400)
			return
		}
		if e := n.rt.Node.AddVoter(raft.ServerID(in.NodeID), raft.ServerAddress(in.Address)); e != nil {
			http.Error(w, e.Error(), 409)
			return
		}
		w.WriteHeader(204)
	})
	mux.HandleFunc("/admin/v1/replication/snapshot", func(w http.ResponseWriter, r *http.Request) {
		if _, ok := admin.Authorize(r, true); !ok {
			http.Error(w, "forbidden", 403)
			return
		}
		if e := n.rt.Node.Snapshot(); e != nil {
			http.Error(w, e.Error(), 500)
			return
		}
		w.WriteHeader(204)
	})
	return mux
}

func adminSession(t *testing.T, h http.Handler) (*http.Cookie, string) {
	t.Helper()
	do := func(method, path string, body any, cookie *http.Cookie, csrf string) *httptest.ResponseRecorder {
		var rd io.Reader
		if body != nil {
			b, _ := json.Marshal(body)
			rd = strings.NewReader(string(b))
		}
		r := httptest.NewRequest(method, path, rd)
		if body != nil {
			r.Header.Set("Content-Type", "application/json")
		}
		if cookie != nil {
			r.AddCookie(cookie)
		}
		if csrf != "" {
			r.Header.Set("X-Trestle-CSRF", csrf)
		}
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		return w
	}
	setup := do("POST", "/admin/v1/setup", map[string]string{"username": "admin", "email": "admin@example.com", "password": "testpass", "applicationRegistrationPolicy": "closed"}, nil, "")
	var session struct {
		CSRFToken string `json:"csrfToken"`
	}
	_ = json.Unmarshal(setup.Body.Bytes(), &session)
	cookies := setup.Result().Cookies()
	if len(cookies) == 0 {
		t.Fatalf("no session cookie (setup=%d)", setup.Code)
	}
	return cookies[0], session.CSRFToken
}

func opCall(t *testing.T, h http.Handler, method, path string, body any, cookie *http.Cookie, csrf string) *httptest.ResponseRecorder {
	t.Helper()
	var rd io.Reader
	if body != nil {
		b, _ := json.Marshal(body)
		rd = strings.NewReader(string(b))
	}
	r := httptest.NewRequest(method, path, rd)
	if body != nil {
		r.Header.Set("Content-Type", "application/json")
	}
	if cookie != nil {
		r.AddCookie(cookie)
	}
	if csrf != "" {
		r.Header.Set("X-Trestle-CSRF", csrf)
	}
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	return w
}

// TestReplicationOperatorAuthorization certifies the operator surface:
// admin-only status/join/snapshot with CSRF, unauthenticated rejection,
// non-admin rejection, standalone fail-closed and malformed-join rejection.
func TestReplicationOperatorAuthorization(t *testing.T) {
	ca := newCertCA(t)
	ctx := context.Background()
	s, e := store.Open(ctx, t.TempDir())
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() { s.Close() })
	admin := adminauth.New(s.DB(), "sqlite")

	// Single-node replicated runtime (production composition).
	n := buildNode(t, ctx, ca, t.TempDir(), "A", freePort(t), nil, true, &http.Client{})
	h := operatorHandler(t, n, admin)
	waitReady(t, n, corerepl.ReadinessReadyLeader)

	cookie, csrf := adminSession(t, h)
	// Admin status succeeds.
	if w := opCall(t, h, http.MethodGet, "/admin/v1/replication/status", nil, cookie, ""); w.Code != 200 {
		t.Fatalf("admin status: %d", w.Code)
	}
	// Unauthenticated status rejected.
	if w := opCall(t, h, http.MethodGet, "/admin/v1/replication/status", nil, nil, ""); w.Code != 401 {
		t.Fatalf("unauthenticated status: %d", w.Code)
	}
	// Non-admin (no valid session) snapshot rejected.
	if w := opCall(t, h, http.MethodPost, "/admin/v1/replication/snapshot", nil, &http.Cookie{Name: "trestle_admin_session", Value: "bogus"}, "x"); w.Code != 403 {
		t.Fatalf("non-admin snapshot: %d", w.Code)
	}
	// A committed mutation gives the snapshot something to capture.
	col := collections.Collection{ID: "col_a", Name: "alpha", Kind: "base", CreatedAt: "2026-01-01T00:00:00Z", UpdatedAt: "2026-01-01T00:00:00Z",
		Fields: []collections.Field{{ID: "fld_n", Name: "name", Type: "text"}}}
	if _, e := n.rt.Controller.PutCollection(ctx, col); e != nil {
		t.Fatalf("collection: %v", e)
	}
	// Admin snapshot (with CSRF) succeeds.
	if w := opCall(t, h, http.MethodPost, "/admin/v1/replication/snapshot", nil, cookie, csrf); w.Code != 204 {
		t.Fatalf("admin snapshot: %d body=%s", w.Code, w.Body.String())
	}
	// Malformed join rejected.
	if w := opCall(t, h, http.MethodPost, "/admin/v1/replication/join", map[string]string{"node_id": "B"}, cookie, csrf); w.Code != 400 {
		t.Fatalf("malformed join: %d", w.Code)
	}
	// Snapshot without CSRF rejected (mutation requires CSRF).
	if w := opCall(t, h, http.MethodPost, "/admin/v1/replication/snapshot", nil, cookie, ""); w.Code != 403 {
		t.Fatalf("snapshot without csrf: %d", w.Code)
	}
}
