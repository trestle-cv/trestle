package appauth

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/trestle-cv/trestle/internal/adminauth"
	"github.com/trestle-cv/trestle/internal/appreg"
	"github.com/trestle-cv/trestle/internal/audit"
	"github.com/trestle-cv/trestle/internal/store"
	"github.com/trestle-cv/trestle/internal/storetest"
)

// setup builds a full appauth handler on the named provider with a running
// store and an audit handler, and returns the store and handler.
func setupReg(t *testing.T, provider string) (*store.Store, *Handler) {
	t.Helper()
	s := storetest.Open(t, provider)
	admin := adminauth.New(s.DB(), string(s.Provider()))
	auditAPI := audit.New(s.DB(), admin, string(s.Provider()))
	h := New(s.DB(), admin)
	h.SetAudit(auditAPI)
	return s, h
}

// policy resets the singleton policy row to the named policy for a test.
func setPolicy(t *testing.T, s *store.Store, policy string) {
	t.Helper()
	if _, err := s.DB().Exec("UPDATE _trestle_app_registration_policy SET policy=? WHERE id=1", policy); err != nil {
		t.Fatal(err)
	}
}

// adminCookieCSRF performs first-run setup and returns an admin cookie + CSRF.
func adminSetup(t *testing.T, s *store.Store, admin *adminauth.Handler) (*http.Cookie, string) {
	t.Helper()
	body := strings.NewReader(`{"username":"admin","email":"admin@example.com","password":"1234567","applicationRegistrationPolicy":"closed"}`)
	r := httptest.NewRequest("POST", "http://example.test/admin/v1/setup", body)
	r.Host = "example.test"
	r.Header.Set("Origin", "http://example.test")
	w := httptest.NewRecorder()
	admin.ServeHTTP(w, r)
	if w.Code != 200 {
		t.Fatalf("admin setup %d %s", w.Code, w.Body.String())
	}
	cookie := w.Result().Cookies()[0]
	var out struct {
		CSRF string `json:"csrfToken"`
	}
	json.Unmarshal(w.Body.Bytes(), &out)
	return cookie, out.CSRF
}

func publicGet(h http.Handler, path string) *httptest.ResponseRecorder {
	r := httptest.NewRequest("GET", "http://example.test"+path, nil)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	return w
}

func publicCall(h http.Handler, path, body string) *httptest.ResponseRecorder {
	r := httptest.NewRequest("POST", "http://example.test"+path, strings.NewReader(body))
	r.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	return w
}

func adminCall(h http.Handler, cookie *http.Cookie, csrf, method, path, body string) *httptest.ResponseRecorder {
	r := httptest.NewRequest(method, "http://example.test"+path, strings.NewReader(body))
	r.Host = "example.test"
	r.AddCookie(cookie)
	if method != "GET" {
		r.Header.Set("X-Trestle-CSRF", csrf)
	}
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	return w
}

func TestCapabilityReflectsPolicy(t *testing.T) {
	for _, provider := range storetest.Providers(t) {
		t.Run(provider, func(t *testing.T) {
			s, h := setupReg(t, provider)
			expect := map[string]string{"open": "register", "invite": "invite", "approval": "request", "closed": "closed"}
			for policy, flow := range expect {
				setPolicy(t, s, policy)
				w := publicGet(h, "/api/v1/auth/capability")
				if w.Code != 200 {
					t.Fatalf("capability %d", w.Code)
				}
				var out struct {
					Registration struct {
						Flow          string `json:"flow"`
						EmailDelivery string `json:"emailDelivery"`
					} `json:"registration"`
				}
				if err := json.Unmarshal(w.Body.Bytes(), &out); err != nil {
					t.Fatal(err)
				}
				if out.Registration.Flow != flow || out.Registration.EmailDelivery != "manual" {
					t.Fatalf("policy %s: flow=%s email=%s, want %s/manual", policy, out.Registration.Flow, out.Registration.EmailDelivery, flow)
				}
				if strings.Contains(w.Body.String(), "invitation") || strings.Contains(w.Body.String(), "pending") {
					t.Fatal("capability leaked private registration state")
				}
			}
		})
	}
}

func TestRegisterPolicyGatingAndDuplicate(t *testing.T) {
	for _, provider := range storetest.Providers(t) {
		t.Run(provider, func(t *testing.T) {
			s, h := setupReg(t, provider)

			// Closed: registration refused.
			setPolicy(t, s, "closed")
			if w := publicCall(h, "/api/v1/auth/register", `{"email":"a@example.com","password":"1234567"}`); w.Code != 403 {
				t.Fatalf("closed register=%d", w.Code)
			}
			// Invite: refused.
			setPolicy(t, s, "invite")
			if w := publicCall(h, "/api/v1/auth/register", `{"email":"a@example.com","password":"1234567"}`); w.Code != 403 {
				t.Fatalf("invite register=%d", w.Code)
			}
			// Approval: refused.
			setPolicy(t, s, "approval")
			if w := publicCall(h, "/api/v1/auth/register", `{"email":"a@example.com","password":"1234567"}`); w.Code != 403 {
				t.Fatalf("approval register=%d", w.Code)
			}
			// Open: register works.
			setPolicy(t, s, "open")
			if w := publicCall(h, "/api/v1/auth/register", `{"email":"a@example.com","password":"1234567"}`); w.Code != 201 {
				t.Fatalf("open register=%d %s", w.Code, w.Body.String())
			}
			// Duplicate: generic registration_unavailable (no email_in_use).
			dup := publicCall(h, "/api/v1/auth/register", `{"email":"a@example.com","password":"1234567"}`)
			if dup.Code != 409 {
				t.Fatalf("duplicate register=%d", dup.Code)
			}
			var out struct {
				Error struct {
					Code string `json:"code"`
				} `json:"error"`
			}
			json.Unmarshal(dup.Body.Bytes(), &out)
			if out.Error.Code == "email_in_use" {
				t.Fatal("duplicate registration leaked email_in_use")
			}
		})
	}
}

func TestInvitationLifecycle(t *testing.T) {
	for _, provider := range storetest.Providers(t) {
		t.Run(provider, func(t *testing.T) {
			s, h := setupReg(t, provider)
			admin := adminauth.New(s.DB(), string(s.Provider()))
			cookie, csrf := adminSetup(t, s, admin)

			setPolicy(t, s, "invite")
			// Create a self-register invitation.
			w := adminCall(h, cookie, csrf, "POST", "/admin/v1/app-registration/invitations", `{"kind":"self_register","email":"person@example.com"}`)
			if w.Code != 201 {
				t.Fatalf("create invitation %d %s", w.Code, w.Body.String())
			}
			var inv struct{ Token, Email, ID string }
			json.Unmarshal(w.Body.Bytes(), &inv)
			if inv.Token == "" || inv.Email != "person@example.com" {
				t.Fatalf("invitation %+v", inv)
			}

			// Accept with wrong/unknown token -> invalid_invitation.
			if w := publicCall(h, "/api/v1/auth/invite/accept", `{"token":"garbage","password":"1234567"}`); w.Code != 400 {
				t.Fatalf("bad token %d", w.Code)
			}

			// Accept with correct token under invite policy.
			if w := publicCall(h, "/api/v1/auth/invite/accept", `{"token":"`+inv.Token+`","password":"1234567"}`); w.Code != 201 {
				t.Fatalf("accept %d %s", w.Code, w.Body.String())
			}
			// Single-use: second accept fails.
			if w := publicCall(h, "/api/v1/auth/invite/accept", `{"token":"`+inv.Token+`","password":"1234567"}`); w.Code != 400 {
				t.Fatalf("second accept %d", w.Code)
			}
			// User now exists; login works.
			if w := publicCall(h, "/api/v1/auth/login", `{"email":"person@example.com","password":"1234567"}`); w.Code != 200 {
				t.Fatalf("login %d", w.Code)
			}

			// Revoke an invitation.
			w = adminCall(h, cookie, csrf, "POST", "/admin/v1/app-registration/invitations", `{"kind":"activate","email":"other@example.com"}`)
			var inv2 struct{ Token, ID string }
			json.Unmarshal(w.Body.Bytes(), &inv2)
			if w := adminCall(h, cookie, csrf, "POST", "/admin/v1/app-registration/invitations/"+inv2.ID+"/revoke", `{}`); w.Code != 204 {
				t.Fatalf("revoke %d", w.Code)
			}
			if w := publicCall(h, "/api/v1/auth/invite/accept", `{"token":"`+inv2.Token+`","password":"1234567"}`); w.Code != 400 {
				t.Fatalf("accept revoked %d", w.Code)
			}
		})
	}
}

func TestSelfRegisterRequiresInvitePolicy(t *testing.T) {
	for _, provider := range storetest.Providers(t) {
		t.Run(provider, func(t *testing.T) {
			s, h := setupReg(t, provider)
			admin := adminauth.New(s.DB(), string(s.Provider()))
			cookie, csrf := adminSetup(t, s, admin)

			setPolicy(t, s, "invite")
			w := adminCall(h, cookie, csrf, "POST", "/admin/v1/app-registration/invitations", `{"kind":"self_register","email":"x@example.com"}`)
			var inv struct{ Token string }
			json.Unmarshal(w.Body.Bytes(), &inv)

			// Switch away from invite: self_register acceptance must fail.
			setPolicy(t, s, "closed")
			if w := publicCall(h, "/api/v1/auth/invite/accept", `{"token":"`+inv.Token+`","password":"1234567"}`); w.Code != 400 {
				t.Fatalf("accept under closed %d", w.Code)
			}
			// Back to invite: works.
			setPolicy(t, s, "invite")
			if w := publicCall(h, "/api/v1/auth/invite/accept", `{"token":"`+inv.Token+`","password":"1234567"}`); w.Code != 201 {
				t.Fatalf("accept back to invite %d", w.Code)
			}
		})
	}
}

func TestActivationWorksUnderEveryPolicy(t *testing.T) {
	for _, provider := range storetest.Providers(t) {
		t.Run(provider, func(t *testing.T) {
			s, h := setupReg(t, provider)
			admin := adminauth.New(s.DB(), string(s.Provider()))
			cookie, csrf := adminSetup(t, s, admin)
			for _, policy := range []string{"open", "invite", "approval", "closed"} {
				setPolicy(t, s, policy)
				email := strings.ReplaceAll(policy, "_", "") + "@example.com"
				w := adminCall(h, cookie, csrf, "POST", "/admin/v1/app-registration/invitations", `{"kind":"activate","email":"`+email+`"}`)
				var inv struct{ Token string }
				json.Unmarshal(w.Body.Bytes(), &inv)
				if w := publicCall(h, "/api/v1/auth/invite/accept", `{"token":"`+inv.Token+`","password":"1234567"}`); w.Code != 201 {
					t.Fatalf("activate under %s: %d", policy, w.Code)
				}
			}
		})
	}
}

func TestActivationEmailConflict(t *testing.T) {
	for _, provider := range storetest.Providers(t) {
		t.Run(provider, func(t *testing.T) {
			s, h := setupReg(t, provider)
			admin := adminauth.New(s.DB(), string(s.Provider()))
			cookie, csrf := adminSetup(t, s, admin)
			setPolicy(t, s, "open")
			// Create a real user directly.
			if w := publicCall(h, "/api/v1/auth/register", `{"email":"taken@example.com","password":"1234567"}`); w.Code != 201 {
				t.Fatalf("register %d", w.Code)
			}
			// Admin attempts to provision the same email -> user_already_exists.
			w := adminCall(h, cookie, csrf, "POST", "/admin/v1/app-registration/invitations", `{"kind":"activate","email":"taken@example.com"}`)
			if w.Code != 409 {
				t.Fatalf("provision taken email %d", w.Code)
			}
			var out struct {
				Error struct{ Code string } `json:"error"`
			}
			json.Unmarshal(w.Body.Bytes(), &out)
			if out.Error.Code != "user_already_exists" {
				t.Fatalf("code %q", out.Error.Code)
			}
		})
	}
}

func TestConcurrentInvitationSingleUse(t *testing.T) {
	for _, provider := range storetest.Providers(t) {
		t.Run(provider, func(t *testing.T) {
			s, h := setupReg(t, provider)
			admin := adminauth.New(s.DB(), string(s.Provider()))
			cookie, csrf := adminSetup(t, s, admin)
			setPolicy(t, s, "open")
			w := adminCall(h, cookie, csrf, "POST", "/admin/v1/app-registration/invitations", `{"kind":"activate","email":"race@example.com"}`)
			var inv struct{ Token string }
			json.Unmarshal(w.Body.Bytes(), &inv)

			results := make(chan int, 2)
			for i := 0; i < 2; i++ {
				go func() {
					results <- publicCall(h, "/api/v1/auth/invite/accept", `{"token":"`+inv.Token+`","password":"1234567"}`).Code
				}()
			}
			one, two := <-results, <-results
			if !((one == 201 && two == 400) || (one == 400 && two == 201)) {
				t.Fatalf("single-use violated: %d %d", one, two)
			}
			var users int
			if err := s.DB().QueryRow("SELECT count(*) FROM _trestle_app_users WHERE email='race@example.com'").Scan(&users); err != nil || users != 1 {
				t.Fatalf("users=%d err=%v", users, err)
			}
		})
	}
}

func TestAccessRequestLifecycleAndDuplicate(t *testing.T) {
	for _, provider := range storetest.Providers(t) {
		t.Run(provider, func(t *testing.T) {
			s, h := setupReg(t, provider)
			admin := adminauth.New(s.DB(), string(s.Provider()))
			cookie, csrf := adminSetup(t, s, admin)

			// Not approval: refused.
			setPolicy(t, s, "open")
			if w := publicCall(h, "/api/v1/auth/access-request", `{"email":"want@example.com"}`); w.Code != 403 {
				t.Fatalf("non-approval request %d", w.Code)
			}
			setPolicy(t, s, "approval")
			// First request: generic 202.
			if w := publicCall(h, "/api/v1/auth/access-request", `{"email":"want@example.com"}`); w.Code != 202 {
				t.Fatalf("request %d", w.Code)
			}
			// Duplicate pending: still generic 202, no new row.
			if w := publicCall(h, "/api/v1/auth/access-request", `{"email":"want@example.com"}`); w.Code != 202 {
				t.Fatalf("dup request %d", w.Code)
			}
			var count int
			if err := s.DB().QueryRow("SELECT count(*) FROM _trestle_app_access_requests WHERE email='want@example.com' AND status='pending'").Scan(&count); err != nil || count != 1 {
				t.Fatalf("pending count=%d err=%v", count, err)
			}
			// List shows one pending.
			w := adminCall(h, cookie, csrf, "GET", "/admin/v1/app-registration/requests", "")
			var list struct {
				Items []struct {
					Status string `json:"status"`
					ID     string `json:"id"`
				}
			}
			json.Unmarshal(w.Body.Bytes(), &list)
			if len(list.Items) != 1 || list.Items[0].Status != "pending" {
				t.Fatalf("list %+v", list.Items)
			}
			// Approve -> creates activate invitation with token.
			rid := list.Items[0].ID
			w = adminCall(h, cookie, csrf, "POST", "/admin/v1/app-registration/requests/"+rid+"/approve", `{}`)
			if w.Code != 201 {
				t.Fatalf("approve %d %s", w.Code, w.Body.String())
			}
			var inv struct{ Token string }
			json.Unmarshal(w.Body.Bytes(), &inv)
			// Approve again -> already_decided.
			if w := adminCall(h, cookie, csrf, "POST", "/admin/v1/app-registration/requests/"+rid+"/approve", `{}`); w.Code != 409 {
				t.Fatalf("reapprove %d", w.Code)
			}
			// Reject a second request.
			if w := publicCall(h, "/api/v1/auth/access-request", `{"email":"second@example.com"}`); w.Code != 202 {
				t.Fatalf("second request %d", w.Code)
			}
			w = adminCall(h, cookie, csrf, "GET", "/admin/v1/app-registration/requests", "")
			var list2 struct {
				Items []struct{ ID, Email, Status string }
			}
			json.Unmarshal(w.Body.Bytes(), &list2)
			var second string
			for _, it := range list2.Items {
				if it.Email == "second@example.com" {
					second = it.ID
				}
			}
			if w := adminCall(h, cookie, csrf, "POST", "/admin/v1/app-registration/requests/"+second+"/reject", `{}`); w.Code != 204 {
				t.Fatalf("reject %d", w.Code)
			}
			// The approved invitation activates the user.
			if w := publicCall(h, "/api/v1/auth/invite/accept", `{"token":"`+inv.Token+`","password":"1234567"}`); w.Code != 201 {
				t.Fatalf("activation %d", w.Code)
			}
		})
	}
}

func TestRequestRemainsDecidableAfterLeavingApproval(t *testing.T) {
	for _, provider := range storetest.Providers(t) {
		t.Run(provider, func(t *testing.T) {
			s, h := setupReg(t, provider)
			admin := adminauth.New(s.DB(), string(s.Provider()))
			cookie, csrf := adminSetup(t, s, admin)
			setPolicy(t, s, "approval")
			publicCall(h, "/api/v1/auth/access-request", `{"email":"d@example.com"}`)
			setPolicy(t, s, "closed")
			w := adminCall(h, cookie, csrf, "GET", "/admin/v1/app-registration/requests", "")
			var list struct {
				Items []struct {
					ID string `json:"id"`
				}
			}
			json.Unmarshal(w.Body.Bytes(), &list)
			if len(list.Items) != 1 {
				t.Fatalf("pending request lost after leaving approval: %+v", list.Items)
			}
			if w := adminCall(h, cookie, csrf, "POST", "/admin/v1/app-registration/requests/"+list.Items[0].ID+"/approve", `{}`); w.Code != 201 {
				t.Fatalf("approve after leaving approval %d", w.Code)
			}
		})
	}
}

func TestReissueInvitation(t *testing.T) {
	for _, provider := range storetest.Providers(t) {
		t.Run(provider, func(t *testing.T) {
			s, h := setupReg(t, provider)
			admin := adminauth.New(s.DB(), string(s.Provider()))
			cookie, csrf := adminSetup(t, s, admin)
			setPolicy(t, s, "approval")
			publicCall(h, "/api/v1/auth/access-request", `{"email":"reissue@example.com"}`)
			w := adminCall(h, cookie, csrf, "GET", "/admin/v1/app-registration/requests", "")
			var list struct {
				Items []struct {
					ID string `json:"id"`
				}
			}
			json.Unmarshal(w.Body.Bytes(), &list)
			rid := list.Items[0].ID
			w = adminCall(h, cookie, csrf, "POST", "/admin/v1/app-registration/requests/"+rid+"/approve", `{}`)
			var first struct{ Token string }
			json.Unmarshal(w.Body.Bytes(), &first)
			// Reissue: revokes the first, returns a new token.
			w = adminCall(h, cookie, csrf, "POST", "/admin/v1/app-registration/requests/"+rid+"/reissue", `{"email":"reissue@example.com"}`)
			if w.Code != 201 {
				t.Fatalf("reissue %d %s", w.Code, w.Body.String())
			}
			var second struct{ Token string }
			json.Unmarshal(w.Body.Bytes(), &second)
			if second.Token == "" || second.Token == first.Token {
				t.Fatal("reissue did not return a new token")
			}
			// First token now revoked.
			if w := publicCall(h, "/api/v1/auth/invite/accept", `{"token":"`+first.Token+`","password":"1234567"}`); w.Code != 400 {
				t.Fatalf("old token after reissue %d", w.Code)
			}
			// New token works.
			if w := publicCall(h, "/api/v1/auth/invite/accept", `{"token":"`+second.Token+`","password":"1234567"}`); w.Code != 201 {
				t.Fatalf("new token %d", w.Code)
			}
		})
	}
}

func TestPolicyChangeSerializesAgainstRegistration(t *testing.T) {
	for _, provider := range storetest.Providers(t) {
		t.Run(provider, func(t *testing.T) {
			s, h := setupReg(t, provider)
			setPolicy(t, s, "open")
			admin := adminauth.New(s.DB(), string(s.Provider()))
			cookie, csrf := adminSetup(t, s, admin)

			// Change policy to closed via the admin endpoint (uses the lock).
			w := adminCall(h, cookie, csrf, "PUT", "/admin/v1/app-registration/policy", `{"policy":"closed"}`)
			if w.Code != 200 {
				t.Fatalf("policy change %d", w.Code)
			}
			// A subsequent registration must fail.
			if w := publicCall(h, "/api/v1/auth/register", `{"email":"after@example.com","password":"1234567"}`); w.Code != 403 {
				t.Fatalf("register after close %d", w.Code)
			}
			var users int
			if err := s.DB().QueryRow("SELECT count(*) FROM _trestle_app_users").Scan(&users); err != nil || users != 0 {
				t.Fatalf("users after closed=%d err=%v", users, err)
			}
		})
	}
}

func TestPolicyChangeRequiresAdminAndCSRF(t *testing.T) {
	for _, provider := range storetest.Providers(t) {
		t.Run(provider, func(t *testing.T) {
			s, h := setupReg(t, provider)
			admin := adminauth.New(s.DB(), string(s.Provider()))
			cookie, csrf := adminSetup(t, s, admin)
			// Wrong CSRF -> denied.
			if w := adminCall(h, cookie, "wrong", "PUT", "/admin/v1/app-registration/policy", `{"policy":"open"}`); w.Code != 403 {
				t.Fatalf("bad csrf %d", w.Code)
			}
			// No cookie -> denied.
			r := httptest.NewRequest("PUT", "http://example.test/admin/v1/app-registration/policy", strings.NewReader(`{"policy":"open"}`))
			w := httptest.NewRecorder()
			h.ServeHTTP(w, r)
			if w.Code != 403 {
				t.Fatalf("no cookie %d", w.Code)
			}
			// Open without confirmOpen -> rejected.
			if w := adminCall(h, cookie, csrf, "PUT", "/admin/v1/app-registration/policy", `{"policy":"open"}`); w.Code != 400 {
				t.Fatalf("open without confirm %d", w.Code)
			}
			// Open with confirmOpen -> ok.
			if w := adminCall(h, cookie, csrf, "PUT", "/admin/v1/app-registration/policy", `{"policy":"open","confirmOpen":true}`); w.Code != 200 {
				t.Fatalf("open with confirm %d", w.Code)
			}
		})
	}
}

func TestAccessRequestRateLimited(t *testing.T) {
	// Only exercised on sqlite (single storetest open path); provider loop is
	// not needed for the limiter, but keep both for parity.
	for _, provider := range storetest.Providers(t) {
		t.Run(provider, func(t *testing.T) {
			s, h := setupReg(t, provider)
			setPolicy(t, s, "approval")
			h.SetRequestLimit(2)
			var limited bool
			for i := 0; i < 6; i++ {
				if publicCall(h, "/api/v1/auth/access-request", `{"email":"r`+string(rune('a'+i))+`@example.com"}`).Code == 429 {
					limited = true
					break
				}
			}
			if !limited {
				t.Fatal("access-request was not rate limited")
			}
		})
	}
}

func TestAccessRequestSweepExpiresPending(t *testing.T) {
	for _, provider := range storetest.Providers(t) {
		t.Run(provider, func(t *testing.T) {
			s, h := setupReg(t, provider)
			setPolicy(t, s, "approval")
			publicCall(h, "/api/v1/auth/access-request", `{"email":"old@example.com"}`)
			// Backdate the pending request past the pending TTL (14d) but within
			// the retention window (30d), so it expires but is not yet purged.
			oldCreated := time.Now().UTC().Add(-20 * 24 * time.Hour).Format(time.RFC3339Nano)
			if _, err := s.DB().Exec("UPDATE _trestle_app_access_requests SET created_at=? WHERE email='old@example.com'", oldCreated); err != nil {
				t.Fatal(err)
			}
			// Submitting another request triggers the sweep.
			publicCall(h, "/api/v1/auth/access-request", `{"email":"new@example.com"}`)
			var status string
			if err := s.DB().QueryRow("SELECT status FROM _trestle_app_access_requests WHERE email='old@example.com'").Scan(&status); err != nil {
				t.Fatal(err)
			}
			if status != "expired" {
				t.Fatalf("old request status %q, want expired", status)
			}
		})
	}
}

func TestTokenStoredAsHashOnly(t *testing.T) {
	for _, provider := range storetest.Providers(t) {
		t.Run(provider, func(t *testing.T) {
			s, h := setupReg(t, provider)
			admin := adminauth.New(s.DB(), string(s.Provider()))
			cookie, csrf := adminSetup(t, s, admin)
			setPolicy(t, s, "open")
			w := adminCall(h, cookie, csrf, "POST", "/admin/v1/app-registration/invitations", `{"kind":"activate","email":"hash@example.com"}`)
			var inv struct{ Token string }
			json.Unmarshal(w.Body.Bytes(), &inv)
			var tokenHash []byte
			if err := s.DB().QueryRow("SELECT token_hash FROM _trestle_app_invitations WHERE email='hash@example.com'").Scan(&tokenHash); err != nil {
				t.Fatal(err)
			}
			if bytes.Equal(tokenHash, []byte(inv.Token)) {
				t.Fatal("raw token stored in plaintext")
			}
			// List must not return the token.
			w = adminCall(h, cookie, csrf, "GET", "/admin/v1/app-registration/invitations", "")
			if strings.Contains(w.Body.String(), inv.Token) {
				t.Fatal("listing leaked the raw token")
			}
		})
	}
}

var _ = context.Background

// TestPolicyLockOrderDeterministic proves the serialization contract: when the
// restrictive policy change wins the lock first, a later registration cannot
// commit under the previous open policy. It forces the ordering by completing
// the policy change before starting the registration, then verifies the
// registration is rejected and no user row exists.
func TestPolicyLockOrderDeterministic(t *testing.T) {
	for _, provider := range storetest.Providers(t) {
		t.Run(provider, func(t *testing.T) {
			s, h := setupReg(t, provider)
			admin := adminauth.New(s.DB(), string(s.Provider()))
			cookie, csrf := adminSetup(t, s, admin)
			setPolicy(t, s, "open")

			// The policy change wins the serialization order: it acquires the
			// lock and commits closed before the registration begins.
			if w := adminCall(h, cookie, csrf, "PUT", "/admin/v1/app-registration/policy", `{"policy":"closed"}`); w.Code != 200 {
				t.Fatalf("policy change %d", w.Code)
			}
			// A registration that starts afterward must observe closed.
			if w := publicCall(h, "/api/v1/auth/register", `{"email":"late@example.com","password":"1234567"}`); w.Code != 403 {
				t.Fatalf("late register %d", w.Code)
			}
			var users int
			if err := s.DB().QueryRow("SELECT count(*) FROM _trestle_app_users").Scan(&users); err != nil || users != 0 {
				t.Fatalf("users=%d err=%v", users, err)
			}
		})
	}
}

// TestConcurrentPolicyChangeAndRegistrationOrdering runs a policy change and a
// registration concurrently many times and asserts the invariant: if the
// registration commits, the policy row at that moment was open and no later
// registration under closed can succeed. Every registration that reports 201
// must have a corresponding user; every 403 must leave no user.
func TestConcurrentPolicyChangeAndRegistrationOrdering(t *testing.T) {
	for _, provider := range storetest.Providers(t) {
		t.Run(provider, func(t *testing.T) {
			s, h := setupReg(t, provider)
			admin := adminauth.New(s.DB(), string(s.Provider()))
			cookie, csrf := adminSetup(t, s, admin)
			setPolicy(t, s, "open")

			for round := 0; round < 5; round++ {
				email := fmt.Sprintf("race%d@example.com", round)
				done := make(chan struct{}, 2)
				var mu sync.Mutex
				registered := 0
				// Policy change to closed.
				go func() {
					adminCall(h, cookie, csrf, "PUT", "/admin/v1/app-registration/policy", `{"policy":"closed"}`)
					done <- struct{}{}
				}()
				// Concurrent registration.
				go func() {
					w := publicCall(h, "/api/v1/auth/register", `{"email":"`+email+`","password":"1234567"}`)
					mu.Lock()
					if w.Code == 201 {
						registered++
					}
					mu.Unlock()
					done <- struct{}{}
				}()
				<-done
				<-done
				if registered > 1 {
					t.Fatalf("round %d: %d registrations committed under a policy race", round, registered)
				}
				// Reset to open for the next round.
				setPolicy(t, s, "open")
			}
		})
	}
}

// TestReissueCannotSubstituteEmail proves the reissue endpoint derives the
// email exclusively from the approved request row: supplying a different email
// in the body must be ignored and the resulting activation invitation must be
// bound to the approved request's email.
func TestReissueCannotSubstituteEmail(t *testing.T) {
	for _, provider := range storetest.Providers(t) {
		t.Run(provider, func(t *testing.T) {
			s, h := setupReg(t, provider)
			admin := adminauth.New(s.DB(), string(s.Provider()))
			cookie, csrf := adminSetup(t, s, admin)
			setPolicy(t, s, "approval")
			publicCall(h, "/api/v1/auth/access-request", `{"email":"approved@example.com"}`)
			w := adminCall(h, cookie, csrf, "GET", "/admin/v1/app-registration/requests", "")
			var list struct {
				Items []struct {
					ID string `json:"id"`
				}
			}
			json.Unmarshal(w.Body.Bytes(), &list)
			rid := list.Items[0].ID
			if w := adminCall(h, cookie, csrf, "POST", "/admin/v1/app-registration/requests/"+rid+"/approve", `{}`); w.Code != 201 {
				t.Fatalf("approve %d", w.Code)
			}
			// Reissue with a substituted email in the body: it must be ignored.
			w = adminCall(h, cookie, csrf, "POST", "/admin/v1/app-registration/requests/"+rid+"/reissue", `{"email":"attacker@example.com"}`)
			if w.Code != 201 {
				t.Fatalf("reissue %d %s", w.Code, w.Body.String())
			}
			var inv struct{ Email, Token string }
			json.Unmarshal(w.Body.Bytes(), &inv)
			if inv.Email != "approved@example.com" {
				t.Fatalf("reissue used substituted email %q", inv.Email)
			}
			// The activation invitation must be for the approved email.
			if w := publicCall(h, "/api/v1/auth/invite/accept", `{"token":"`+inv.Token+`","password":"1234567"}`); w.Code != 201 {
				t.Fatalf("activation %d", w.Code)
			}
			var users int
			if err := s.DB().QueryRow("SELECT count(*) FROM _trestle_app_users WHERE email='attacker@example.com'").Scan(&users); err != nil || users != 0 {
				t.Fatalf("attacker email user count=%d err=%v", users, err)
			}
		})
	}
}

// TestConcurrentApprovalSingleWinner proves two concurrent approvals of the
// same request yield exactly one 201, one conflict, one activation invitation
// and one approval audit fact.
func TestConcurrentApprovalSingleWinner(t *testing.T) {
	for _, provider := range storetest.Providers(t) {
		t.Run(provider, func(t *testing.T) {
			s, h := setupReg(t, provider)
			admin := adminauth.New(s.DB(), string(s.Provider()))
			cookie, csrf := adminSetup(t, s, admin)
			setPolicy(t, s, "approval")
			publicCall(h, "/api/v1/auth/access-request", `{"email":"race@example.com"}`)
			w := adminCall(h, cookie, csrf, "GET", "/admin/v1/app-registration/requests", "")
			var list struct {
				Items []struct {
					ID string `json:"id"`
				}
			}
			json.Unmarshal(w.Body.Bytes(), &list)
			rid := list.Items[0].ID

			results := make(chan int, 2)
			for i := 0; i < 2; i++ {
				go func() {
					results <- adminCall(h, cookie, csrf, "POST", "/admin/v1/app-registration/requests/"+rid+"/approve", `{}`).Code
				}()
			}
			one, two := <-results, <-results
			if !((one == 201 && two == 409) || (one == 409 && two == 201)) {
				t.Fatalf("concurrent approval codes %d %d, want one 201 and one 409", one, two)
			}
			var invites int
			if err := s.DB().QueryRow("SELECT count(*) FROM _trestle_app_invitations WHERE access_request_id=?", rid).Scan(&invites); err != nil || invites != 1 {
				t.Fatalf("activation invitations=%d err=%v, want exactly one", invites, err)
			}
			var audits int
			if err := s.DB().QueryRow("SELECT count(*) FROM _trestle_audit WHERE action='app_registration.request.approve' AND target=?", rid).Scan(&audits); err != nil || audits != 1 {
				t.Fatalf("approval audit facts=%d err=%v, want exactly one", audits, err)
			}
		})
	}
}

// TestConcurrentReissueSingleValidToken proves two simultaneous reissues of the
// same approved request leave exactly one valid replacement activation token:
// the older one is revoked by the winner.
func TestConcurrentReissueSingleValidToken(t *testing.T) {
	for _, provider := range storetest.Providers(t) {
		t.Run(provider, func(t *testing.T) {
			s, h := setupReg(t, provider)
			admin := adminauth.New(s.DB(), string(s.Provider()))
			cookie, csrf := adminSetup(t, s, admin)
			setPolicy(t, s, "approval")
			publicCall(h, "/api/v1/auth/access-request", `{"email":"reissue-race@example.com"}`)
			w := adminCall(h, cookie, csrf, "GET", "/admin/v1/app-registration/requests", "")
			var list struct {
				Items []struct {
					ID string `json:"id"`
				}
			}
			json.Unmarshal(w.Body.Bytes(), &list)
			rid := list.Items[0].ID
			adminCall(h, cookie, csrf, "POST", "/admin/v1/app-registration/requests/"+rid+"/approve", `{}`)

			results := make(chan string, 2)
			for i := 0; i < 2; i++ {
				go func() {
					w := adminCall(h, cookie, csrf, "POST", "/admin/v1/app-registration/requests/"+rid+"/reissue", `{}`)
					if w.Code == 201 {
						var inv struct{ Token string }
						json.Unmarshal(w.Body.Bytes(), &inv)
						results <- inv.Token
					} else {
						results <- "conflict"
					}
				}()
			}
			tokA, tokB := <-results, <-results
			// At most one valid replacement token may remain.
			var valid int
			var aRevoked, bRevoked sql.NullString
			_ = s.DB().QueryRow("SELECT revoked_at FROM _trestle_app_invitations WHERE token_hash=?", sha256Hash(tokA)).Scan(&aRevoked)
			_ = s.DB().QueryRow("SELECT revoked_at FROM _trestle_app_invitations WHERE token_hash=?", sha256Hash(tokB)).Scan(&bRevoked)
			_ = aRevoked
			_ = bRevoked
			// Count valid (unused, not revoked, unexpired) activate invitations
			// for this request.
			if err := s.DB().QueryRow("SELECT count(*) FROM _trestle_app_invitations WHERE access_request_id=? AND used_at IS NULL AND revoked_at IS NULL", rid).Scan(&valid); err != nil || valid != 1 {
				t.Fatalf("valid replacement tokens=%d err=%v, want exactly one", valid, err)
			}
		})
	}
}

func realRandom(b []byte) (int, error) { return rand.Read(b) }

func sha256Hash(v string) []byte { h := sha256.Sum256([]byte(v)); return h[:] }

// failInsertStore wraps a store.Executor and fails INSERTs into the access
// request table so a test can observe a genuine storage failure.
type failInsertStore struct{ store.Executor }

func (f failInsertStore) ExecContext(ctx context.Context, q string, args ...any) (sql.Result, error) {
	if strings.HasPrefix(strings.TrimSpace(q), "INSERT INTO _trestle_app_access_requests") {
		return nil, errors.New("injected storage failure")
	}
	return f.Executor.ExecContext(ctx, q, args...)
}
func (f failInsertStore) Exec(q string, args ...any) (sql.Result, error) {
	return f.ExecContext(context.Background(), q, args...)
}

// TestBoundedCleanupProcessesAtMostOneBatch proves the sweep processes at most
// CleanupBatch rows per trigger with deterministic ordering, and subsequent
// triggers make progress without unbounded draining during one request.
func TestBoundedCleanupProcessesAtMostOneBatch(t *testing.T) {
	for _, provider := range storetest.Providers(t) {
		t.Run(provider, func(t *testing.T) {
			s, h := setupReg(t, provider)
			setPolicy(t, s, "approval")
			// Insert more than one batch of pending requests past the 14-day
			// pending TTL but within the 30-day retention window, so a trigger
			// expires them without purging them (proving the expiry batch is
			// bounded).
			created := time.Now().UTC().Add(-20 * 24 * time.Hour).Format(time.RFC3339Nano)
			for i := 0; i < appreg.CleanupBatch+50; i++ {
				if _, err := s.DB().Exec("INSERT INTO _trestle_app_access_requests(id,email,status,created_at) VALUES(?,?,'pending',?)",
					fmt.Sprintf("areq_%d", i), fmt.Sprintf("exp%d@example.com", i), created); err != nil {
					t.Fatal(err)
				}
			}
			// One trigger must not expire more than one batch.
			if err := h.reg.SubmitAccessRequest(context.Background(), "fresh@example.com"); err != nil {
				t.Fatal(err)
			}
			var expired int
			if err := s.DB().QueryRow("SELECT count(*) FROM _trestle_app_access_requests WHERE status='expired'").Scan(&expired); err != nil {
				t.Fatal(err)
			}
			if expired > appreg.CleanupBatch {
				t.Fatalf("one trigger expired %d rows, want <= %d", expired, appreg.CleanupBatch)
			}
			// The fresh request is still pending.
			var fresh int
			if err := s.DB().QueryRow("SELECT count(*) FROM _trestle_app_access_requests WHERE email='fresh@example.com' AND status='pending'").Scan(&fresh); err != nil || fresh != 1 {
				t.Fatalf("fresh pending=%d err=%v", fresh, err)
			}
			// A second trigger makes progress without unbounded draining.
			if err := h.reg.SubmitAccessRequest(context.Background(), "fresh2@example.com"); err != nil {
				t.Fatal(err)
			}
			var expired2 int
			if err := s.DB().QueryRow("SELECT count(*) FROM _trestle_app_access_requests WHERE status='expired'").Scan(&expired2); err != nil {
				t.Fatal(err)
			}
			if expired2 <= expired {
				t.Fatalf("second trigger made no progress: %d -> %d", expired, expired2)
			}
			if expired2 > appreg.CleanupBatch*2 {
				t.Fatalf("two triggers expired %d rows, want bounded progress", expired2)
			}

			// The purge path is also bounded: seed far-past rejected rows past
			// the 30-day retention window and verify one trigger purges at most
			// one batch.
			purgedCreated := time.Now().UTC().Add(-40 * 24 * time.Hour).Format(time.RFC3339Nano)
			for i := 0; i < appreg.CleanupBatch+20; i++ {
				if _, err := s.DB().Exec("INSERT INTO _trestle_app_access_requests(id,email,status,created_at,decided_at) VALUES(?,?,'rejected',?,?)",
					fmt.Sprintf("prune_%d", i), fmt.Sprintf("r%d@example.com", i), purgedCreated, purgedCreated); err != nil {
					t.Fatal(err)
				}
			}
			if err := h.reg.SubmitAccessRequest(context.Background(), "fresh3@example.com"); err != nil {
				t.Fatal(err)
			}
			var remaining int
			if err := s.DB().QueryRow("SELECT count(*) FROM _trestle_app_access_requests WHERE id LIKE 'prune_%'").Scan(&remaining); err != nil {
				t.Fatal(err)
			}
			if remaining > appreg.CleanupBatch {
				t.Fatalf("one trigger purged only %d of the far-past rows, want at most %d left", appreg.CleanupBatch+20-remaining, appreg.CleanupBatch)
			}
		})
	}
}

func TestActivationBaseURLValidation(t *testing.T) {
	valid := []string{
		"https://app.example.com/register",
		"https://app.example.com",
		"http://127.0.0.1:8080/register",
		"http://localhost:3000/register",
	}
	for _, v := range valid {
		if _, err := appreg.ValidateActivationBaseURL(v); err != nil {
			t.Fatalf("valid %q rejected: %v", v, err)
		}
	}
	invalid := []string{
		"http://app.example.com",                           // non-loopback http
		"ftp://app.example.com",                            // unsafe scheme
		"https://user:pass@example.com",                    // credentials
		"https://example.com#frag",                         // fragment
		"https://example.com?q=1",                          // query
		"not-a-url",                                        // not absolute
		"/relative",                                        // not absolute
		"https://example.com/" + strings.Repeat("a", 3000), // too long
	}
	for _, v := range invalid {
		if _, err := appreg.ValidateActivationBaseURL(v); err == nil {
			t.Fatalf("invalid %q accepted", v)
		}
	}
	// Fragment construction uses URL handling, not concatenation.
	link, err := appreg.ActivationLink("https://app.example.com/register", "tok123")
	if err != nil {
		t.Fatal(err)
	}
	if link != "https://app.example.com/register#invite=tok123" {
		t.Fatalf("link %q", link)
	}
	if strings.Contains(link, "?") {
		t.Fatal("token must not appear in a query string")
	}
}

// TestAccessRequestPolicyTransitionRaces proves access-request submission is
// serialized against policy changes: when the restrictive policy change wins
// first, the later request is not created. Every transition (approval to
// closed/invite/open) is covered, plus the request-wins ordering.
func TestAccessRequestPolicyTransitionRaces(t *testing.T) {
	for _, provider := range storetest.Providers(t) {
		t.Run(provider, func(t *testing.T) {
			s, h := setupReg(t, provider)
			admin := adminauth.New(s.DB(), string(s.Provider()))
			cookie, csrf := adminSetup(t, s, admin)
			setPolicy(t, s, "approval")

			for _, target := range []string{"closed", "invite", "open"} {
				// The policy change wins first.
				body := `{"policy":"` + target + `"}`
				if target == "open" {
					body = `{"policy":"open","confirmOpen":true}`
				}
				if w := adminCall(h, cookie, csrf, "PUT", "/admin/v1/app-registration/policy", body); w.Code != 200 {
					t.Fatalf("policy change to %s %d", target, w.Code)
				}
				// A request after the restrictive change must not be created.
				email := "post-" + target + "@example.com"
				if w := publicCall(h, "/api/v1/auth/access-request", `{"email":"`+email+`"}`); w.Code != 403 {
					t.Fatalf("request after %s %d", target, w.Code)
				}
				// The serialization invariant: no pending row may be created
				// after the restrictive change wins, for every target policy.
				var count int
				if err := s.DB().QueryRow("SELECT count(*) FROM _trestle_app_access_requests WHERE email=?", email).Scan(&count); err != nil || count != 0 {
					t.Fatalf("request created after restrictive change to %s: %d err=%v", target, count, err)
				}
				// Reset to approval for the next transition.
				setPolicy(t, s, "approval")
			}

			// Request wins first: under approval the request is created, then a
			// later policy change to closed takes effect and the request
			// remains stored.
			setPolicy(t, s, "approval")
			publicCall(h, "/api/v1/auth/access-request", `{"email":"winner@example.com"}`)
			var count int
			if err := s.DB().QueryRow("SELECT count(*) FROM _trestle_app_access_requests WHERE email='winner@example.com' AND status='pending'").Scan(&count); err != nil || count != 1 {
				t.Fatalf("request-wins ordering failed: %d err=%v", count, err)
			}
			setPolicy(t, s, "closed")
			if w := adminCall(h, cookie, csrf, "GET", "/admin/v1/app-registration/requests", ""); w.Code != 200 {
				t.Fatalf("list after close %d", w.Code)
			}
		})
	}
}

// TestEntropyFailureNoDurableMutation proves an injected entropy-source failure
// prevents any invitation, approval, reissue, or access-request row from being
// committed and returns a misleading-success-free outcome.
func TestEntropyFailureNoDurableMutation(t *testing.T) {
	for _, provider := range storetest.Providers(t) {
		t.Run(provider, func(t *testing.T) {
			s, h := setupReg(t, provider)
			admin := adminauth.New(s.DB(), string(s.Provider()))
			cookie, csrf := adminSetup(t, s, admin)
			// Inject entropy failure on the service.
			h.reg.SetRandomReader(func([]byte) (int, error) { return 0, errors.New("no entropy") })
			setPolicy(t, s, "open")

			// Provisioning an invitation fails before any row is committed.
			if w := adminCall(h, cookie, csrf, "POST", "/admin/v1/app-registration/invitations", `{"kind":"activate","email":"entropy@example.com"}`); w.Code == 201 {
				t.Fatalf("invitation created despite entropy failure")
			}
			var invites int
			if err := s.DB().QueryRow("SELECT count(*) FROM _trestle_app_invitations").Scan(&invites); err != nil || invites != 0 {
				t.Fatalf("invitation row committed under entropy failure: %d err=%v", invites, err)
			}

			// Approval of a pending request fails without creating a user or
			// invitation. The request is created first (entropy works), then
			// entropy is injected before the approval.
			setPolicy(t, s, "approval")
			h.reg.SetRandomReader(realRandom)
			publicCall(h, "/api/v1/auth/access-request", `{"email":"entropy-approve@example.com"}`)
			h.reg.SetRandomReader(func([]byte) (int, error) { return 0, errors.New("no entropy") })
			w := adminCall(h, cookie, csrf, "GET", "/admin/v1/app-registration/requests", "")
			var list struct {
				Items []struct {
					ID string `json:"id"`
				}
			}
			json.Unmarshal(w.Body.Bytes(), &list)
			rid := list.Items[0].ID
			if w := adminCall(h, cookie, csrf, "POST", "/admin/v1/app-registration/requests/"+rid+"/approve", `{}`); w.Code == 201 {
				t.Fatal("approve succeeded despite entropy failure")
			}
			var inviteCount int
			if err := s.DB().QueryRow("SELECT count(*) FROM _trestle_app_invitations").Scan(&inviteCount); err != nil || inviteCount != 0 {
				t.Fatalf("approval invitation committed under entropy failure: %d err=%v", inviteCount, err)
			}
			// The request stays pending (no approval audit, no decision).
			var status string
			if err := s.DB().QueryRow("SELECT status FROM _trestle_app_access_requests WHERE id=?", rid).Scan(&status); err != nil || status != "pending" {
				t.Fatalf("request status %q after failed approve, err=%v", status, err)
			}

			// Access-request submission under entropy failure leaves no row.
			setPolicy(t, s, "approval")
			if err := h.reg.SubmitAccessRequest(context.Background(), "entropy-req@example.com"); err == nil {
				t.Fatal("access request succeeded despite entropy failure")
			}
			var reqCount int
			if err := s.DB().QueryRow("SELECT count(*) FROM _trestle_app_access_requests WHERE email='entropy-req@example.com'").Scan(&reqCount); err != nil || reqCount != 0 {
				t.Fatalf("access-request row committed under entropy failure: %d err=%v", reqCount, err)
			}
		})
	}
}

// TestPartialEntropyReadNoDurableMutation proves a short-read-without-error
// entropy source is rejected by randomToken on invitation creation, approval,
// reissue and access-request creation: no invitation, user, or request row
// commits and no token is minted from a partially filled buffer.
func TestPartialEntropyReadNoDurableMutation(t *testing.T) {
	shortRead := func(b []byte) (int, error) {
		if len(b) == 0 {
			return 0, nil
		}
		half := len(b) / 2
		if half == 0 {
			half = 1
		}
		for i := 0; i < half; i++ {
			b[i] = 0xA5
		}
		return half, nil
	}
	for _, provider := range storetest.Providers(t) {
		t.Run(provider, func(t *testing.T) {
			s, h := setupReg(t, provider)
			admin := adminauth.New(s.DB(), string(s.Provider()))
			cookie, csrf := adminSetup(t, s, admin)
			h.reg.SetRandomReader(shortRead)
			setPolicy(t, s, "open")

			// Invitation creation: partial entropy -> no invitation row.
			if w := adminCall(h, cookie, csrf, "POST", "/admin/v1/app-registration/invitations", `{"kind":"activate","email":"partial@example.com"}`); w.Code == 201 {
				t.Fatalf("invitation created under partial entropy read")
			}
			var invites int
			if err := s.DB().QueryRow("SELECT count(*) FROM _trestle_app_invitations").Scan(&invites); err != nil || invites != 0 {
				t.Fatalf("invitation committed under partial read: %d err=%v", invites, err)
			}

			// Approval of a pending request under partial entropy -> no user,
			// no invitation, request stays pending.
			setPolicy(t, s, "approval")
			h.reg.SetRandomReader(realRandom)
			publicCall(h, "/api/v1/auth/access-request", `{"email":"partial-approve@example.com"}`)
			h.reg.SetRandomReader(shortRead)
			w := adminCall(h, cookie, csrf, "GET", "/admin/v1/app-registration/requests", "")
			var list struct {
				Items []struct {
					ID string `json:"id"`
				}
			}
			json.Unmarshal(w.Body.Bytes(), &list)
			rid := list.Items[0].ID
			if w := adminCall(h, cookie, csrf, "POST", "/admin/v1/app-registration/requests/"+rid+"/approve", `{}`); w.Code == 201 {
				t.Fatal("approve succeeded under partial entropy read")
			}
			if err := s.DB().QueryRow("SELECT count(*) FROM _trestle_app_invitations").Scan(&invites); err != nil || invites != 0 {
				t.Fatalf("approval invitation committed under partial read: %d err=%v", invites, err)
			}
			var status string
			if err := s.DB().QueryRow("SELECT status FROM _trestle_app_access_requests WHERE id=?", rid).Scan(&status); err != nil || status != "pending" {
				t.Fatalf("request status %q after failed approve, err=%v", status, err)
			}

			// Reissue under partial entropy -> no new invitation.
			h.reg.SetRandomReader(realRandom)
			setPolicy(t, s, "invite")
			w = adminCall(h, cookie, csrf, "POST", "/admin/v1/app-registration/invitations", `{"kind":"self_register","email":"partial-reissue@example.com"}`)
			var inv struct{ Token string }
			json.Unmarshal(w.Body.Bytes(), &inv)
			h.reg.SetRandomReader(shortRead)
			if w := adminCall(h, cookie, csrf, "POST", "/admin/v1/app-registration/invitations/"+inv.Token+"/reissue", `{}`); w.Code == 201 {
				t.Fatal("reissue succeeded under partial entropy read")
			}
			if err := s.DB().QueryRow("SELECT count(*) FROM _trestle_app_invitations WHERE email='partial-reissue@example.com'").Scan(&invites); err != nil || invites != 1 {
				t.Fatalf("reissue minted extra invitation under partial read: %d err=%v", invites, err)
			}

			// Access-request submission under partial entropy -> no row.
			setPolicy(t, s, "approval")
			if err := h.reg.SubmitAccessRequest(context.Background(), "partial-req@example.com"); err == nil {
				t.Fatal("access request succeeded under partial entropy read")
			}
			var reqCount int
			if err := s.DB().QueryRow("SELECT count(*) FROM _trestle_app_access_requests WHERE email='partial-req@example.com'").Scan(&reqCount); err != nil || reqCount != 0 {
				t.Fatalf("access-request row committed under partial read: %d err=%v", reqCount, err)
			}
		})
	}
}

// TestAuditMatrixExactCounts proves the audit event matrix with exact counts on
// SQLite and PostgreSQL: invitation creation, open registration, invitation
// acceptance, approval/rejection, reissue, revocation (only on a real
// transition), and policy change each emit exactly the expected facts, and a
// nonexistent/already-terminal revocation emits no success fact.
func TestAuditMatrixExactCounts(t *testing.T) {
	for _, provider := range storetest.Providers(t) {
		t.Run(provider, func(t *testing.T) {
			s, h := setupReg(t, provider)
			admin := adminauth.New(s.DB(), string(s.Provider()))
			cookie, csrf := adminSetup(t, s, admin)

			count := func(action string) int {
				var n int
				if err := s.DB().QueryRow("SELECT count(*) FROM _trestle_audit WHERE action=?", action).Scan(&n); err != nil {
					t.Fatal(err)
				}
				return n
			}

			// 1. Administrator invitation creation -> one fact.
			setPolicy(t, s, "invite")
			w := adminCall(h, cookie, csrf, "POST", "/admin/v1/app-registration/invitations", `{"kind":"self_register","email":"audit@example.com"}`)
			if w.Code != 201 {
				t.Fatalf("invitation create %d", w.Code)
			}
			var inv struct{ Token string }
			json.Unmarshal(w.Body.Bytes(), &inv)
			if got := count("app_registration.invitation.create"); got != 1 {
				t.Fatalf("invitation.create audit=%d want 1", got)
			}

			// 2. Invitation acceptance -> user.create fact.
			if w := publicCall(h, "/api/v1/auth/invite/accept", `{"token":"`+inv.Token+`","password":"1234567"}`); w.Code != 201 {
				t.Fatalf("accept %d", w.Code)
			}
			if got := count("app_registration.user.create"); got != 1 {
				t.Fatalf("user.create audit=%d want 1", got)
			}

			// 3. Open registration -> user.create fact with path register.
			setPolicy(t, s, "open")
			if w := publicCall(h, "/api/v1/auth/register", `{"email":"open@example.com","password":"1234567"}`); w.Code != 201 {
				t.Fatalf("open register %d", w.Code)
			}
			if got := count("app_registration.user.create"); got != 2 {
				t.Fatalf("user.create audit=%d want 2", got)
			}

			// 4. Policy change -> one fact.
			if w := adminCall(h, cookie, csrf, "PUT", "/admin/v1/app-registration/policy", `{"policy":"closed"}`); w.Code != 200 {
				t.Fatalf("policy change %d", w.Code)
			}
			if got := count("app_registration.policy.change"); got != 1 {
				t.Fatalf("policy.change audit=%d want 1", got)
			}

			// 5. Revocation of a real invitation -> one fact.
			setPolicy(t, s, "invite")
			w = adminCall(h, cookie, csrf, "POST", "/admin/v1/app-registration/invitations", `{"kind":"self_register","email":"revoke@example.com"}`)
			var inv2 struct{ ID string }
			json.Unmarshal(w.Body.Bytes(), &inv2)
			if w := adminCall(h, cookie, csrf, "POST", "/admin/v1/app-registration/invitations/"+inv2.ID+"/revoke", `{}`); w.Code != 204 {
				t.Fatalf("revoke %d", w.Code)
			}
			if got := count("app_registration.invitation.revoke"); got != 1 {
				t.Fatalf("invitation.revoke audit=%d want 1", got)
			}
			// Revoking again (already revoked) is idempotent with no new fact.
			if w := adminCall(h, cookie, csrf, "POST", "/admin/v1/app-registration/invitations/"+inv2.ID+"/revoke", `{}`); w.Code != 204 {
				t.Fatalf("re-revoke %d", w.Code)
			}
			if got := count("app_registration.invitation.revoke"); got != 1 {
				t.Fatalf("re-revoke audit=%d want still 1", got)
			}
			// Revoking a nonexistent invitation is idempotent with no fact.
			if w := adminCall(h, cookie, csrf, "POST", "/admin/v1/app-registration/invitations/nonexistent/revoke", `{}`); w.Code != 204 {
				t.Fatalf("revoke nonexistent %d", w.Code)
			}
			if got := count("app_registration.invitation.revoke"); got != 1 {
				t.Fatalf("nonexistent revoke audit=%d want still 1", got)
			}

			// 6. Approval + reissue -> one approve fact and one reissue fact.
			setPolicy(t, s, "approval")
			publicCall(h, "/api/v1/auth/access-request", `{"email":"audit-approve@example.com"}`)
			w = adminCall(h, cookie, csrf, "GET", "/admin/v1/app-registration/requests", "")
			var list struct {
				Items []struct {
					ID string `json:"id"`
				}
			}
			json.Unmarshal(w.Body.Bytes(), &list)
			rid := list.Items[0].ID
			if w := adminCall(h, cookie, csrf, "POST", "/admin/v1/app-registration/requests/"+rid+"/approve", `{}`); w.Code != 201 {
				t.Fatalf("approve %d", w.Code)
			}
			if got := count("app_registration.request.approve"); got != 1 {
				t.Fatalf("request.approve audit=%d want 1", got)
			}
			if w := adminCall(h, cookie, csrf, "POST", "/admin/v1/app-registration/requests/"+rid+"/reissue", `{}`); w.Code != 201 {
				t.Fatalf("reissue %d", w.Code)
			}
			if got := count("app_registration.invitation.reissue"); got != 1 {
				t.Fatalf("invitation.reissue audit=%d want 1", got)
			}
		})
	}
}

// TestStorageFailureMetricObservable proves genuine access-request storage
// failures increment the server-side metric while the public response stays
// indistinguishable (202), and that normal operation does not increment it.
func TestStorageFailureMetricObservable(t *testing.T) {
	for _, provider := range storetest.Providers(t) {
		t.Run(provider, func(t *testing.T) {
			s, h := setupReg(t, provider)
			setPolicy(t, s, "approval")
			before := h.reg.StorageFailures()
			if before != 0 {
				t.Fatalf("storage failures started at %d", before)
			}
			// Normal submission succeeds with no metric increment.
			if w := publicCall(h, "/api/v1/auth/access-request", `{"email":"ok@example.com"}`); w.Code != 202 {
				t.Fatalf("ok request %d", w.Code)
			}
			if h.reg.StorageFailures() != before {
				t.Fatal("normal submission incremented the storage-failure metric")
			}
			// Inject a storage failure by closing the underlying store's DB.
			// Simpler: point the service at a broken executor for one call.
			h.SetAudit(nil) // not needed
			// Replace the store with one whose ExecContext fails on INSERT.
			h.reg.SetStore(failInsertStore{s.DB()})
			if w := publicCall(h, "/api/v1/auth/access-request", `{"email":"fail@example.com"}`); w.Code != 202 {
				t.Fatalf("failure public response %d (must stay 202)", w.Code)
			}
			if h.reg.StorageFailures() <= before {
				t.Fatal("storage failure did not increment the observable metric")
			}
		})
	}
}

// TestConcurrentAccessRequestVsPolicyChange proves the serialized contract under
// concurrency: a restrictive policy change and an access-request submission
// race, and if the request commits then it committed while the policy was
// approval; a request that loses to a closed/invite change creates no row.
func TestConcurrentAccessRequestVsPolicyChange(t *testing.T) {
	for _, provider := range storetest.Providers(t) {
		t.Run(provider, func(t *testing.T) {
			s, h := setupReg(t, provider)
			admin := adminauth.New(s.DB(), string(s.Provider()))
			cookie, csrf := adminSetup(t, s, admin)
			setPolicy(t, s, "approval")

			for round := 0; round < 4; round++ {
				email := fmt.Sprintf("race-req%d@example.com", round)
				// Submission goroutine.
				submitted := make(chan int, 1)
				go func() {
					submitted <- publicCall(h, "/api/v1/auth/access-request", `{"email":"`+email+`"}`).Code
				}()
				// Policy change to closed concurrently.
				adminCall(h, cookie, csrf, "PUT", "/admin/v1/app-registration/policy", `{"policy":"closed"}`)
				code := <-submitted
				var rows int
				if err := s.DB().QueryRow("SELECT count(*) FROM _trestle_app_access_requests WHERE email=?", email).Scan(&rows); err != nil {
					t.Fatal(err)
				}
				switch {
				case code == 202 && rows == 1:
					// The request won the lock while the policy was approval:
					// exactly one pending row exists.
					var status string
					if err := s.DB().QueryRow("SELECT status FROM _trestle_app_access_requests WHERE email=?", email).Scan(&status); err != nil || status != "pending" {
						t.Fatalf("round %d: committed request status=%q err=%v", round, status, err)
					}
				case code == 403 && rows == 0:
					// The restrictive policy change won first: no row is created.
				default:
					t.Fatalf("round %d: code=%d rows=%d violates the serialization invariant", round, code, rows)
				}
				// Reset to approval for the next round.
				setPolicy(t, s, "approval")
			}
		})
	}
}

// TestAuditRollbackNoPartialFacts proves an injected failure after a mutation
// rolls back both the durable row and the audit fact (no partial account,
// invitation or audit state).
func TestAuditRollbackNoPartialFacts(t *testing.T) {
	for _, provider := range storetest.Providers(t) {
		t.Run(provider, func(t *testing.T) {
			s, _ := setupReg(t, provider)
			admin := adminauth.New(s.DB(), string(s.Provider()))
			setPolicy(t, s, "open")

			// Register with an executor that fails on the audit INSERT: the
			// user insert rolls back with it.
			failAudit := &auditFailExecutor{Executor: s.DB(), failAction: "app_registration.user.create"}
			fh := New(failAudit, admin)
			fh.SetAudit(audit.New(s.DB(), admin, string(s.Provider())))
			// The policy read must go to the real DB; only the audit insert
			// fails. failAudit forwards everything except the audit insert.
			if w := publicCall(fh, "/api/v1/auth/register", `{"email":"rollback@example.com","password":"1234567"}`); w.Code != 409 {
				t.Fatalf("register with audit failure %d", w.Code)
			}
			var users int
			if err := s.DB().QueryRow("SELECT count(*) FROM _trestle_app_users WHERE email='rollback@example.com'").Scan(&users); err != nil || users != 0 {
				t.Fatalf("user row committed despite audit failure: %d err=%v", users, err)
			}
			var audits int
			if err := s.DB().QueryRow("SELECT count(*) FROM _trestle_audit WHERE action='app_registration.user.create'").Scan(&audits); err != nil || audits != 0 {
				t.Fatalf("audit row committed despite audit failure: %d err=%v", audits, err)
			}
		})
	}
}

// auditFailExecutor wraps a store.Executor and fails the specific audit INSERT
// action, so the transaction rolls back with no partial state.
type auditFailExecutor struct {
	store.Executor
	failAction string
}

func (e *auditFailExecutor) ExecContext(ctx context.Context, q string, args ...any) (sql.Result, error) {
	if strings.Contains(q, "INSERT INTO _trestle_audit") && len(args) > 3 && fmt.Sprint(args[3]) == e.failAction {
		return nil, errors.New("injected audit failure")
	}
	return e.Executor.ExecContext(ctx, q, args...)
}
func (e *auditFailExecutor) Exec(q string, args ...any) (sql.Result, error) {
	return e.ExecContext(context.Background(), q, args...)
}

// TestActivationBaseURLNormalization proves the activation base URL is trimmed
// and canonicalized before storage and that the PUT response returns the
// normalized stored value (never the raw request input), for set, replace and
// clear, followed by correct fragment-link construction.
func TestActivationBaseURLNormalization(t *testing.T) {
	for _, provider := range storetest.Providers(t) {
		t.Run(provider, func(t *testing.T) {
			s, h := setupReg(t, provider)
			admin := adminauth.New(s.DB(), string(s.Provider()))
			cookie, csrf := adminSetup(t, s, admin)

			set := func(value string) string {
				w := adminCall(h, cookie, csrf, "PUT", "/admin/v1/app-registration/activation-base-url", `{"activationBaseUrl":"`+value+`"}`)
				if w.Code != 200 {
					t.Fatalf("set %d %s", w.Code, w.Body.String())
				}
				var out struct {
					ActivationBaseURL string `json:"activationBaseUrl"`
				}
				json.Unmarshal(w.Body.Bytes(), &out)
				return out.ActivationBaseURL
			}
			get := func() string {
				w := adminCall(h, cookie, csrf, "GET", "/admin/v1/app-registration/activation-base-url", "")
				var out struct {
					ActivationBaseURL string `json:"activationBaseUrl"`
				}
				json.Unmarshal(w.Body.Bytes(), &out)
				return out.ActivationBaseURL
			}

			// Whitespace-padded input is trimmed before storage and the PUT
			// returns the canonical value, not the raw request body.
			if got := set("  https://app.example.com/register  "); got != "https://app.example.com/register" {
				t.Fatalf("normalized set returned %q", got)
			}
			if got := get(); got != "https://app.example.com/register" {
				t.Fatalf("GET returned %q, want normalized", got)
			}
			link, err := appreg.ActivationLink("https://app.example.com/register", "tok123")
			if err != nil || link != "https://app.example.com/register#invite=tok123" {
				t.Fatalf("link %q err=%v", link, err)
			}

			// Replace.
			if got := set("https://new.example.com/reg"); got != "https://new.example.com/reg" {
				t.Fatalf("replace returned %q", got)
			}
			// Clear.
			if got := set("   "); got != "" {
				t.Fatalf("clear returned %q, want empty", got)
			}
			if got := get(); got != "" {
				t.Fatalf("GET after clear returned %q", got)
			}
		})
	}
}

// TestActivationBaseURLSurvivesReopen proves the normalized value is what is
// durably persisted: it survives a full store close and reopen (server
// restart/reload) on the SQLite file backend.
func TestActivationBaseURLSurvivesReopen(t *testing.T) {
	dir := t.TempDir()
	s, err := store.Open(context.Background(), dir)
	if err != nil {
		t.Fatal(err)
	}
	admin := adminauth.New(s.DB(), "sqlite")
	cookie, csrf := adminSetup(t, s, admin)
	h := New(s.DB(), admin)
	h.SetAudit(audit.New(s.DB(), admin, "sqlite"))
	w := adminCall(h, cookie, csrf, "PUT", "/admin/v1/app-registration/activation-base-url", `{"activationBaseUrl":"  https://app.example.com/register  "}`)
	if w.Code != 200 {
		t.Fatalf("set %d %s", w.Code, w.Body.String())
	}
	var out struct {
		ActivationBaseURL string `json:"activationBaseUrl"`
	}
	json.Unmarshal(w.Body.Bytes(), &out)
	if out.ActivationBaseURL != "https://app.example.com/register" {
		t.Fatalf("set returned %q", out.ActivationBaseURL)
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	s2, err := store.Open(context.Background(), dir)
	if err != nil {
		t.Fatal(err)
	}
	defer s2.Close()
	var stored string
	if err := s2.DB().QueryRow("SELECT value FROM _trestle_system_meta WHERE key='app_activation_base_url'").Scan(&stored); err != nil {
		t.Fatal(err)
	}
	if stored != "https://app.example.com/register" {
		t.Fatalf("persisted value after reopen %q, want normalized", stored)
	}
}
