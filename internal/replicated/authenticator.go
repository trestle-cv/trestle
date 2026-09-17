package replicated

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/gantry-tools/gantry-core/replication"
	"github.com/hashicorp/raft"
	"github.com/trestle-cv/trestle/internal/store"
)

const replicationCapability = "replication"

type Authenticator struct {
	db        *sql.DB
	protocol  int
	localID   raft.ServerID
	localCaps string
	now       func() time.Time
}

func NewAuthenticator(db store.Executor, protocol int) *Authenticator {
	a := &Authenticator{db: db, protocol: protocol, now: time.Now}
	_ = db.QueryRow(`SELECT node_id,capabilities_json FROM _trestle_cluster_identity WHERE singleton=1`).Scan(&a.localID, &a.localCaps)
	return a
}
func (a *Authenticator) member(ctx context.Context, id string) (state, caps, secret string, inbound []byte, err error) {
	err = a.db.QueryRowContext(ctx, `SELECT state,capabilities_json,outbound_secret,inbound_secret_hash FROM _trestle_cluster_members WHERE node_id=?`, id).Scan(&state, &caps, &secret, &inbound)
	return
}
func hasCap(raw string) bool {
	var xs []string
	_ = json.Unmarshal([]byte(raw), &xs)
	for _, x := range xs {
		if x == replicationCapability {
			return true
		}
	}
	return false
}
func (a *Authenticator) OutboundCredential(ctx context.Context, peer raft.ServerID) (string, error) {
	_, _, s, _, e := a.member(ctx, string(peer))
	return s, e
}
func (a *Authenticator) Authenticate(ctx context.Context, in replication.AuthRequest) (replication.AuthResult, error) {
	if in.NodeID != in.RaftServerID {
		return replication.AuthResult{}, errors.New("raft identity mismatch")
	}
	if in.Protocol != a.protocol {
		return replication.AuthResult{}, errors.New("incompatible replication protocol")
	}
	state, caps, _, hash, err := a.member(ctx, string(in.NodeID))
	if err != nil || state != "active" || !hasCap(caps) {
		return replication.AuthResult{}, errors.New("replication member unavailable")
	}
	d := sha256.Sum256([]byte(in.PresentedSecret))
	if !equal(d[:], hash) || !replication.VerifyHandshakeSignature(in.PresentedSecret, in) {
		return replication.AuthResult{}, errors.New("replication credential rejected")
	}
	if err = a.consume(ctx, string(in.NodeID), in.Nonce); err != nil {
		return replication.AuthResult{}, err
	}
	return replication.AuthResult{Allowed: true, ServerAddress: in.RaftServerAddr}, nil
}
func (a *Authenticator) VerifyPeer(ctx context.Context, expected raft.ServerID, in replication.AuthRequest) error {
	if in.NodeID != expected || in.RaftServerID != expected {
		return fmt.Errorf("peer identity mismatch")
	}
	if in.Protocol != a.protocol {
		return errors.New("incompatible replication protocol")
	}
	state, caps, _, hash, err := a.member(ctx, string(expected))
	if err != nil || state != "active" || !hasCap(caps) {
		return errors.New("replication member unavailable")
	}
	d := sha256.Sum256([]byte(in.PresentedSecret))
	if !equal(d[:], hash) || !replication.VerifyHandshakeSignature(in.PresentedSecret, in) {
		return errors.New("replication credential rejected")
	}
	return a.consume(ctx, string(expected), in.Nonce)
}
func equal(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	var v byte
	for i := range a {
		v |= a[i] ^ b[i]
	}
	return v == 0
}
func (a *Authenticator) consume(ctx context.Context, id, nonce string) error {
	if nonce == "" {
		return errors.New("replication nonce required")
	}
	_, err := a.db.ExecContext(ctx, `INSERT INTO _trestle_cluster_nonces(node_id,nonce,seen_at) VALUES(?,?,?)`, id, "repl-handshake:"+nonce, a.now().UTC().Format(time.RFC3339Nano))
	if err != nil {
		return errors.New("replication replay rejected")
	}
	return nil
}
func (a *Authenticator) Membership(ctx context.Context, id raft.ServerID) (replication.MembershipStatus, error) {
	if id == a.localID {
		return replication.MembershipStatus{State: replication.MembershipActive, Protocol: a.protocol, ReplicationEnabled: hasCap(a.localCaps), Capabilities: a.caps(id, a.localCaps)}, nil
	}
	state, caps, _, _, err := a.member(ctx, string(id))
	if err != nil {
		return replication.MembershipStatus{}, err
	}
	st := replication.MembershipActive
	if state == "disabled" {
		st = replication.MembershipDisabled
	}
	if state == "revoked" {
		st = replication.MembershipRevoked
	}
	return replication.MembershipStatus{State: st, Protocol: a.protocol, ReplicationEnabled: hasCap(caps), Capabilities: a.caps(id, caps)}, nil
}
func (a *Authenticator) caps(id raft.ServerID, raw string) replication.Capabilities {
	return replication.Capabilities{ID: id, OperationSchemaVersions: []int{1, replication.Version}, SnapshotFormatVersions: []int{replication.SnapshotFormatVersion}}
}
func (a *Authenticator) CapabilitiesOf(id raft.ServerID) (replication.Capabilities, bool) {
	if id == a.localID {
		return a.caps(id, a.localCaps), true
	}
	_, caps, _, _, e := a.member(context.Background(), string(id))
	return a.caps(id, caps), e == nil
}

var _ replication.PeerAuthenticator = (*Authenticator)(nil)
var _ replication.MembershipChecker = (*Authenticator)(nil)
var _ replication.PeerCredentialSource = (*Authenticator)(nil)
var _ replication.CapabilitySource = (*Authenticator)(nil)
