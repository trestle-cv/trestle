package cluster

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"
	"time"

	core "github.com/gantry-tools/gantry-core/cluster"
	"github.com/trestle-cv/trestle/internal/store"
)

func openTest(t *testing.T) (*store.Store, *Service) {
	t.Helper()
	s, err := store.Open(context.Background(), filepath.Join(t.TempDir(), "data"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.Close() })
	return s, New(s.DB())
}
func TestIdentityPersists(t *testing.T) {
	_, svc := openTest(t)
	ctx := context.Background()
	a, err := svc.EnsureIdentity(ctx, "test")
	if err != nil {
		t.Fatal(err)
	}
	b, err := svc.EnsureIdentity(ctx, "test")
	if err != nil {
		t.Fatal(err)
	}
	if a.NodeID != b.NodeID || a.InstallationID != b.InstallationID {
		t.Fatal("identity changed")
	}
}
func TestInviteIsSingleUseAndMembershipLifecycle(t *testing.T) {
	_, host := openTest(t)
	_, remote := openTest(t)
	ctx := context.Background()
	ri, err := remote.UpdateIdentity(ctx, "remote", "https://remote.example", "test")
	if err != nil {
		t.Fatal(err)
	}
	inv, token, err := host.Invite(ctx)
	if err != nil || inv.State != core.PairingPending {
		t.Fatal(err)
	}
	bundle, err := host.Pair(ctx, token, ri)
	if err != nil {
		t.Fatal(err)
	}
	if bundle.Credential == "" {
		t.Fatal("missing credential")
	}
	if _, err = host.Pair(ctx, token, ri); err == nil {
		t.Fatal("invitation replay accepted")
	}
	ms, err := host.Members(ctx)
	if err != nil || len(ms) != 1 {
		t.Fatalf("members=%v err=%v", len(ms), err)
	}
	if err = host.SetEnabled(ctx, ri.NodeID, false); err != nil {
		t.Fatal(err)
	}
	if err = host.SetEnabled(ctx, ri.NodeID, true); err != nil {
		t.Fatal(err)
	}
	if _, err = host.Rotate(ctx, ri.NodeID); err != nil {
		t.Fatal(err)
	}
	if err = host.Revoke(ctx, ri.NodeID); err != nil {
		t.Fatal(err)
	}
	if err = host.Remove(ctx, ri.NodeID); err != nil {
		t.Fatal(err)
	}
}
func TestThreeNodeAggregatePreservesOwnershipAndPartialFailure(t *testing.T) {
	_, a := openTest(t)
	_, b := openTest(t)
	_, c := openTest(t)
	ctx := context.Background()
	ai, _ := a.UpdateIdentity(ctx, "a", "https://a.example", "1")
	bi, _ := b.UpdateIdentity(ctx, "b", "https://b.example", "1")
	ci, _ := c.UpdateIdentity(ctx, "c", "https://c.example", "1")
	sec := func() (string, string) { x, _ := core.NewSecret(32); y, _ := core.NewSecret(32); return x, y }
	x, y := sec()
	_ = a.AddMember(ctx, bi, x, y)
	x, y = sec()
	_ = a.AddMember(ctx, ci, x, y)
	members, _ := a.Members(ctx)
	local := Summary{NodeID: ai.NodeID, Collections: 1}
	report, err := Aggregate(ctx, ai.NodeID, local, members, "all", func(_ context.Context, id string) (Summary, error) {
		if id == ci.NodeID {
			return Summary{}, context.DeadlineExceeded
		}
		return Summary{NodeID: id, Collections: 2}, nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if !report.Partial || len(report.Results) != 3 {
		t.Fatalf("partial=%v results=%d", report.Partial, len(report.Results))
	}
	for _, r := range report.Results {
		if r.OwnerNode != r.NodeID {
			t.Fatalf("owner %s node %s", r.OwnerNode, r.NodeID)
		}
	}
}
func TestHealthTransitions(t *testing.T) {
	m := Member{State: core.MemberActive, Compatible: true}
	if got := health(m, time.Now()); got != core.HealthOffline {
		t.Fatalf("health=%s", got)
	}
	now := time.Now()
	m.LastSeenAt = &now
	if got := health(m, now); got != core.HealthOnline {
		t.Fatalf("health=%s", got)
	}
}

func TestSignedTransportBetweenNodes(t *testing.T) {
	ctx := context.Background()
	_, a := openTest(t)
	_, b := openTest(t)
	ai, _ := a.EnsureIdentity(ctx, "1")
	bi, _ := b.EnsureIdentity(ctx, "1")
	secretAB, _ := core.NewSecret(32)
	secretBA, _ := core.NewSecret(32)
	// Endpoint is filled after the TLS test server starts; membership is added below.
	bt := NewTransport(b.db, b, nil)
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if _, _, err := bt.Authenticate(r, "cluster.trestle.summary"); err != nil {
			http.Error(w, err.Error(), http.StatusUnauthorized)
			return
		}
		value, err := b.LocalSummary(r.Context())
		if err != nil {
			t.Errorf("summary: %v", err)
			http.Error(w, "summary", 500)
			return
		}
		_ = json.NewEncoder(w).Encode(value)
	}))
	defer server.Close()
	bi.PublicEndpoint = server.URL
	ai.PublicEndpoint = "https://a.example"
	if err := a.AddMember(ctx, bi, secretAB, secretBA); err != nil {
		t.Fatal(err)
	}
	if err := b.AddMember(ctx, ai, secretBA, secretAB); err != nil {
		t.Fatal(err)
	}
	at := NewTransport(a.db, a, server.Client())
	remote := RemoteReader{Transport: at}
	got, err := remote.Summary(ctx, bi.NodeID)
	if err != nil {
		t.Fatal(err)
	}
	if got.NodeID != bi.NodeID {
		t.Fatalf("node=%s want=%s", got.NodeID, bi.NodeID)
	}
}

func TestJoinApproveCollectLifecycle(t *testing.T) {
	_, host := openTest(t)
	_, joiner := openTest(t)
	ctx := context.Background()
	hostID, err := host.UpdateIdentity(ctx, "host", "https://host.example", "test")
	if err != nil {
		t.Fatal(err)
	}
	joinID, err := joiner.UpdateIdentity(ctx, "joiner", "https://joiner.example", "test")
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
		t.Fatal(err)
	}
	if _, err := host.SubmitJoin(ctx, JoinSubmission{InvitationToken: token, Identity: joinID, CredentialForHost: localInbound}); err == nil {
		t.Fatal("invitation replay accepted")
	}
	pending, err := host.PendingJoins(ctx)
	if err != nil || len(pending) != 1 || pending[0].Fingerprint == "" {
		t.Fatalf("pending=%v err=%v", pending, err)
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
		t.Fatal(err)
	}
	again, err := host.PollJoin(ctx, receipt.RequestID, receipt.RequestSecret)
	if err != nil {
		t.Fatal(err)
	}
	if again.State != core.PairingUsed || again.Credential != "" {
		t.Fatal("pairing result replay exposed credential")
	}
	hm, _ := host.Members(ctx)
	jm, _ := joiner.Members(ctx)
	if len(hm) != 1 || hm[0].NodeID != joinID.NodeID || len(jm) != 1 || jm[0].NodeID != hostID.NodeID {
		t.Fatalf("host=%+v joiner=%+v", hm, jm)
	}
}

func TestCompatibleProductVersionsAndStandaloneRemoval(t *testing.T) {
	_, a := openTest(t)
	_, b := openTest(t)
	ctx := context.Background()
	ai, err := a.UpdateIdentity(ctx, "a", "https://a.example", "1.0.0")
	if err != nil {
		t.Fatal(err)
	}
	bi, err := b.UpdateIdentity(ctx, "b", "https://b.example", "1.1.0")
	if err != nil {
		t.Fatal(err)
	}
	x, _ := core.NewSecret(32)
	y, _ := core.NewSecret(32)
	if err := a.AddMember(ctx, bi, x, y); err != nil {
		t.Fatalf("compatible rolling version rejected: %v", err)
	}
	bad := bi
	bad.NodeID = "bad_protocol"
	bad.InstallationID = "bad_install"
	bad.ProtocolVersion = ProtocolVersion + 1
	if err := a.AddMember(ctx, bad, x, y); err == nil {
		t.Fatal("incompatible protocol accepted")
	}
	if err := a.Revoke(ctx, bi.NodeID); err != nil {
		t.Fatal(err)
	}
	if err := a.Remove(ctx, bi.NodeID); err != nil {
		t.Fatal(err)
	}
	members, err := a.Members(ctx)
	if err != nil || len(members) != 0 {
		t.Fatalf("standalone members=%v err=%v", members, err)
	}
	local, err := a.LocalSummary(ctx)
	if err != nil || local.NodeID != ai.NodeID {
		t.Fatalf("standalone summary=%+v err=%v", local, err)
	}
}
