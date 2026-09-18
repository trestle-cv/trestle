package cluster

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestEndpointSchemeValidation(t *testing.T) {
	if err := validateEndpointScheme("https://node.example", false); err != nil {
		t.Fatalf("https rejected by default: %v", err)
	}
	if err := validateEndpointScheme("http://node.example", false); err == nil {
		t.Fatal("http endpoint accepted by default")
	}
	if err := validateEndpointScheme("ftp://node.example", false); err == nil {
		t.Fatal("non-http scheme accepted")
	}
	if err := validateEndpointScheme("http://node.example", true); err != nil {
		t.Fatalf("http rejected in explicit plaintext mode: %v", err)
	}
	if err := validateEndpointScheme("https://node.example", true); err != nil {
		t.Fatalf("https rejected in explicit plaintext mode: %v", err)
	}
	if err := validateEndpointScheme("", true); err != nil {
		t.Fatalf("empty endpoint rejected: %v", err)
	}
}

func TestBeginOutboundRequiresHttpsUnlessPlaintext(t *testing.T) {
	_, svc := openTest(t)
	ctx := context.Background()

	// Default: a remote HTTP join URL is rejected by the transport guard.
	if _, err := svc.BeginOutbound(ctx, "http://127.0.0.1:9/join", "token", nil); err == nil || !strings.Contains(err.Error(), "must use https") {
		t.Fatalf("http join accepted by default (err=%v)", err)
	}

	// Explicit plaintext mode: the guard is bypassed and the request reaches
	// the remote HTTP endpoint.
	svc.SetInsecurePlaintext(true)
	if _, err := svc.UpdateIdentity(ctx, "", "http://identity.example", "test"); err != nil {
		t.Fatalf("http public endpoint rejected in plaintext mode: %v", err)
	}
	received := false
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		received = true
		w.WriteHeader(http.StatusAccepted)
		_, _ = w.Write([]byte(`{}`))
	}))
	defer ts.Close()
	if _, err := svc.BeginOutbound(ctx, ts.URL, "token", nil); err != nil {
		if strings.Contains(err.Error(), "must use https") {
			t.Fatalf("http join still rejected in plaintext mode: %v", err)
		}
		// Any non-guard error (e.g. receipt decoding) is acceptable: the point is
		// the transport guard no longer blocks HTTP.
	}
	if !received {
		t.Fatal("plaintext join did not reach the remote HTTP endpoint")
	}
}
