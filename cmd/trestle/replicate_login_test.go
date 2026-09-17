package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

// TestReplicateLoginUsesTrestleSession is a regression for the production
// composition defect where the replication operator CLI authenticated against
// the Watchpost-style /admin/v1/login path, which the Trestle adminauth does
// not expose (404), making the operator surface unusable against a real node.
func TestReplicateLoginUsesTrestleSession(t *testing.T) {
	var loginPath, loginBody string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/admin/v1/session":
			loginPath = r.URL.Path
			var creds map[string]string
			if err := json.NewDecoder(r.Body).Decode(&creds); err != nil {
				http.Error(w, "bad", 400)
				return
			}
			loginBody = creds["username"] + "/" + creds["password"]
			http.SetCookie(w, &http.Cookie{Name: "trestle_admin_session", Value: "sess"})
			_ = json.NewEncoder(w).Encode(map[string]any{"authenticated": true, "csrfToken": "tok"})
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()

	session, err := replicateLogin(&http.Client{}, srv.URL, "admin", "pw")
	if err != nil {
		t.Fatalf("replicateLogin: %v", err)
	}
	if loginPath != "/admin/v1/session" {
		t.Fatalf("login path = %q want /admin/v1/session", loginPath)
	}
	if loginBody != "admin/pw" {
		t.Fatalf("login payload = %q want admin/pw", loginBody)
	}
	if session.csrf != "tok" {
		t.Fatalf("csrf = %q want tok", session.csrf)
	}
	if session.cookie == nil || session.cookie.Name != "trestle_admin_session" {
		t.Fatalf("expected session cookie, got %+v", session.cookie)
	}
}
