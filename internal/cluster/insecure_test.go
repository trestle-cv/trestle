package cluster

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	core "github.com/gantry-tools/gantry-core/cluster"
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

func TestJoinApproveAcceptPermitsHttpOnlyInPlaintext(t *testing.T) {
	ctx := context.Background()

	// Default: the host rejects a joiner whose advertised public endpoint is
	// HTTP, and the joiner rejects a host advertising HTTP.
	{
		_, host := openTest(t)
		_, joiner := openTest(t)
		_, token, err := host.Invite(ctx)
		if err != nil {
			t.Fatal(err)
		}
		joinID, err := joiner.UpdateIdentity(ctx, "joiner", "https://joiner.example", "test")
		if err != nil {
			t.Fatal(err)
		}
		joinID.PublicEndpoint = "http://joiner.example"
		localInbound, _ := core.NewSecret(32)
		if _, err := host.SubmitJoin(ctx, JoinSubmission{InvitationToken: token, Identity: joinID, CredentialForHost: localInbound}); err == nil || !strings.Contains(err.Error(), "https") {
			t.Fatalf("http-advertised join accepted by default (err=%v)", err)
		}

		_, host2 := openTest(t)
		_, joiner2 := openTest(t)
		// The host stores an HTTP endpoint by opting into plaintext; the joiner
		// remains in the default HTTPS-only mode and must reject it.
		host2.SetInsecurePlaintext(true)
		_, token2, err := host2.Invite(ctx)
		if err != nil {
			t.Fatal(err)
		}
		joinID2, err := joiner2.UpdateIdentity(ctx, "joiner", "https://joiner2.example", "test")
		if err != nil {
			t.Fatal(err)
		}
		if _, err := host2.UpdateIdentity(ctx, "host", "http://host2.example", "test"); err != nil {
			t.Fatal(err)
		}
		localInbound2, _ := core.NewSecret(32)
		receipt, err := host2.SubmitJoin(ctx, JoinSubmission{InvitationToken: token2, Identity: joinID2, CredentialForHost: localInbound2})
		if err != nil {
			t.Fatal(err)
		}
		if err := host2.DecideJoin(ctx, receipt.RequestID, true); err != nil {
			t.Fatal(err)
		}
		result, err := host2.PollJoin(ctx, receipt.RequestID, receipt.RequestSecret)
		if err != nil {
			t.Fatal(err)
		}
		if err := joiner2.AcceptRemote(ctx, *result.Remote, result.Credential, localInbound2); err == nil || !strings.Contains(err.Error(), "https") {
			t.Fatalf("http-advertised host accepted by default (err=%v)", err)
		}
	}

	// Explicit plaintext mode: HTTP advertised endpoints are accepted through
	// the full join/approve/collect path.
	{
		_, host := openTest(t)
		_, joiner := openTest(t)
		host.SetInsecurePlaintext(true)
		joiner.SetInsecurePlaintext(true)
		hostID, err := host.UpdateIdentity(ctx, "host", "http://host.example", "test")
		if err != nil {
			t.Fatal(err)
		}
		joinID, err := joiner.UpdateIdentity(ctx, "joiner", "http://joiner.example", "test")
		if err != nil {
			t.Fatal(err)
		}
		_, token, err := host.Invite(ctx)
		if err != nil {
			t.Fatal(err)
		}
		localInbound, _ := core.NewSecret(32)
		receipt, err := host.SubmitJoin(ctx, JoinSubmission{InvitationToken: token, Identity: joinID, CredentialForHost: localInbound})
		if err != nil {
			t.Fatalf("plaintext join rejected: %v", err)
		}
		if err := host.DecideJoin(ctx, receipt.RequestID, true); err != nil {
			t.Fatal(err)
		}
		result, err := host.PollJoin(ctx, receipt.RequestID, receipt.RequestSecret)
		if err != nil {
			t.Fatal(err)
		}
		if result.State != core.PairingApproved || result.Remote == nil || result.Remote.NodeID != hostID.NodeID || result.Credential == "" {
			t.Fatalf("result=%+v", result)
		}
		if err := joiner.AcceptRemote(ctx, *result.Remote, result.Credential, localInbound); err != nil {
			t.Fatalf("plaintext accept rejected: %v", err)
		}
		hm, _ := host.Members(ctx)
		jm, _ := joiner.Members(ctx)
		if len(hm) != 1 || len(jm) != 1 {
			t.Fatalf("membership incomplete: host=%+v joiner=%+v", hm, jm)
		}
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
