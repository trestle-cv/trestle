package replicated

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/gantry-tools/gantry-core/replication"
	"github.com/trestle-cv/trestle/internal/storetest"
)

// TestAuthenticatorRejectsMismatchedWebhookKey proves a prospective node with a
// different webhook key cannot authenticate a replication connection: voter
// admission fails at the transport handshake before it can participate in
// execution. Only the non-secret fingerprint is compared; the raw key never
// leaves a node.
func TestAuthenticatorRejectsMismatchedWebhookKey(t *testing.T) {
	s := storetest.Open(t, "sqlite")
	a := NewAuthenticator(s.DB(), replication.Version, "FP_A")

	peerCaps := func(fp string) replication.Capabilities {
		return replication.Capabilities{ID: "tr_peer", OperationSchemaVersions: []int{replication.Version}, SnapshotFormatVersions: []int{replication.SnapshotFormatVersion}, Features: []string{WebhookKeyFingerprintFeature(fp)}}
	}
	handshake := func(caps replication.Capabilities, nonce string) *replication.AuthRequest {
		req, err := replication.SignHandshake("peer-secret", "tr_peer", "tr_peer", "node-peer", replication.Version, caps, nonce, time.Now())
		if err != nil {
			t.Fatal(err)
		}
		return req
	}

	// Accepting side: a peer with a different fingerprint is refused.
	reqMismatch := handshake(peerCaps("FP_B"), "nonce-1")
	if _, err := a.Authenticate(context.Background(), *reqMismatch); err == nil || !strings.Contains(err.Error(), "webhook key fingerprint mismatch") {
		t.Fatalf("accepting side: expected fingerprint mismatch rejection, got %v", err)
	}
	// A peer advertising no fingerprint is also refused when we hold a key.
	reqNone := handshake(replication.Capabilities{ID: "tr_peer", OperationSchemaVersions: []int{replication.Version}}, "nonce-2")
	if _, err := a.Authenticate(context.Background(), *reqNone); err == nil || !strings.Contains(err.Error(), "does not advertise a webhook key fingerprint") {
		t.Fatalf("accepting side: expected missing-fingerprint rejection, got %v", err)
	}
	// Matching fingerprint passes the webhook gate (fails later at the member
	// lookup, proving the gate itself allowed the peer).
	reqMatch := handshake(peerCaps("FP_A"), "nonce-3")
	if _, err := a.Authenticate(context.Background(), *reqMatch); err == nil || strings.Contains(err.Error(), "webhook key fingerprint") {
		t.Fatalf("accepting side: matching fingerprint should pass the webhook gate, got %v", err)
	}

	// Dialing side (VerifyPeer) enforces the same compatibility.
	if err := a.VerifyPeer(context.Background(), "tr_peer", *reqMismatch); err == nil || !strings.Contains(err.Error(), "webhook key fingerprint mismatch") {
		t.Fatalf("dialing side: expected fingerprint mismatch rejection, got %v", err)
	}
	if err := a.VerifyPeer(context.Background(), "tr_peer", *reqMatch); err == nil || strings.Contains(err.Error(), "webhook key fingerprint") {
		t.Fatalf("dialing side: matching fingerprint should pass the webhook gate, got %v", err)
	}
}

// TestAuthenticatorNoKeyNoConstraint proves a node without any webhook key
// material advertises no fingerprint and enforces no compatibility gate (so a
// webhook-less cluster forms normally).
func TestAuthenticatorNoKeyNoConstraint(t *testing.T) {
	s := storetest.Open(t, "sqlite")
	a := NewAuthenticator(s.DB(), replication.Version, "")
	req, err := replication.SignHandshake("peer-secret", "tr_peer", "tr_peer", "node-peer", replication.Version,
		replication.Capabilities{ID: "tr_peer", OperationSchemaVersions: []int{replication.Version}}, "nonce-1", time.Now())
	if err != nil {
		t.Fatal(err)
	}
	// No local fingerprint: the peer (whatever it advertises) passes the webhook
	// gate and fails later only on the member lookup.
	if _, err := a.Authenticate(context.Background(), *req); err == nil || strings.Contains(err.Error(), "webhook key fingerprint") {
		t.Fatalf("no-key node should enforce no webhook gate, got %v", err)
	}
}

// TestWebhookKeyAdmissionOK proves voter admission is refused before AddVoter
// when a prospective node's webhook-key fingerprint is missing or mismatched.
func TestWebhookKeyAdmissionOK(t *testing.T) {
	if ok, _ := WebhookKeyAdmissionOK("FP_A", "FP_A"); !ok {
		t.Fatal("matching fingerprint should admit")
	}
	if ok, reason := WebhookKeyAdmissionOK("FP_A", "FP_B"); ok || !strings.Contains(reason, "mismatch") {
		t.Fatalf("mismatched fingerprint should be refused, got ok=%v reason=%q", ok, reason)
	}
	if ok, _ := WebhookKeyAdmissionOK("FP_A", ""); ok {
		t.Fatal("missing member fingerprint should be refused")
	}
	// A cluster without webhook key material enforces no constraint.
	if ok, _ := WebhookKeyAdmissionOK("", "FP_B"); !ok {
		t.Fatal("no-key cluster should enforce no admission constraint")
	}
}
