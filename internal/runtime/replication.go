package runtime

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/gantry-tools/gantry-core/replication"
	"github.com/hashicorp/raft"
	clusterapi "github.com/trestle-cv/trestle/internal/cluster"
	"github.com/trestle-cv/trestle/internal/replicated"
	"github.com/trestle-cv/trestle/internal/store"
	"github.com/trestle-cv/trestle/internal/webhooks"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"sync"
	"time"
)

// advertisedFeatures returns the replication capability features a node
// advertises in every authenticated handshake. Only the non-secret webhook-key
// fingerprint is advertised; the raw key never leaves the node.
func advertisedFeatures(webhookKeyFingerprint string) []string {
	if webhookKeyFingerprint == "" {
		return nil
	}
	return []string{replicated.WebhookKeyFingerprintFeature(webhookKeyFingerprint)}
}

type Replicated struct {
	Controller *replicated.Controller
	Node       *replication.Node
	FSM        *replicated.FSM
	Net        *replication.NetTransport
	rs         *replication.BoltStore
	stop       context.CancelFunc
	done       chan struct{}
	once       sync.Once
}
type ReplicationOptions struct {
	DB                       store.Executor
	DataDir, NodeID, Address string
	Bootstrap                bool
	TLS                      *tls.Config
	Insecure                 bool
	Transport                *clusterapi.Transport
	Timing                   replication.Timing
}

func NewReplication(ctx context.Context, o ReplicationOptions) (*Replicated, error) {
	if o.DB == nil {
		return nil, errors.New("replication database required")
	}
	if o.DB.Dialect().Provider() != store.SQLite {
		return nil, errors.New("Trestle clustering currently requires SQLite")
	}
	if o.DataDir == "" || o.Address == "" {
		return nil, errors.New("replication data dir and address required")
	}
	if o.TLS == nil && !o.Insecure {
		return nil, errors.New("replication TLS required")
	}
	if o.NodeID == "" {
		if e := o.DB.QueryRow(`SELECT node_id FROM _trestle_cluster_identity WHERE singleton=1`).Scan(&o.NodeID); e != nil {
			return nil, e
		}
	}
	if o.Timing.HeartbeatTimeout == 0 {
		o.Timing = replication.ProductionTiming()
	}
	dir := filepath.Join(o.DataDir, "replication")
	if e := os.MkdirAll(dir, 0750); e != nil {
		return nil, e
	}
	fsm, e := replicated.NewFSM(o.DB)
	if e != nil {
		return nil, e
	}
	webhookKeyFingerprint := ""
	if fp, e := webhooks.KeyFingerprint(o.DataDir); e == nil {
		webhookKeyFingerprint = fp
	} else if !errors.Is(e, os.ErrNotExist) {
		return nil, fmt.Errorf("read webhook key fingerprint: %w", e)
	}
	auth := replicated.NewAuthenticator(o.DB, replication.Version, webhookKeyFingerprint)
	nt, e := replication.NewNetTransport(replication.NetTransportOptions{ID: raft.ServerID(o.NodeID), Address: raft.ServerAddress(o.Address), Authenticator: auth, Membership: auth, PeerCredentials: auth, TLSConfig: o.TLS, Protocol: replication.Version, Capabilities: replication.Capabilities{ID: raft.ServerID(o.NodeID), OperationSchemaVersions: []int{replication.Version}, SnapshotFormatVersions: []int{replication.SnapshotFormatVersion}, Features: advertisedFeatures(webhookKeyFingerprint)}, RevalidateEvery: o.Timing.RevalidateEvery, InsecureAllowPlaintext: o.Insecure})
	if e != nil {
		return nil, e
	}
	bs, e := replication.NewBoltStore(filepath.Join(dir, "raft.db"))
	if e != nil {
		nt.Close()
		return nil, e
	}
	sn, e := raft.NewFileSnapshotStore(filepath.Join(dir, "snapshots"), 3, nil)
	if e != nil {
		bs.Close()
		nt.Close()
		return nil, e
	}
	// Join/bootstrap invariant: a node that has no raft history and is not
	// bootstrapping this cluster must start from empty consensus-owned
	// application state. Raft may catch a new voter up by replaying retained
	// log entries without installing a snapshot; replaying on top of arbitrary
	// pre-existing local rows would not produce canonical cluster state. A
	// first-time member must therefore be clean (or explicitly reseeded from
	// canonical state). An existing member restart retains its own canonical
	// DB + raft state and is always allowed.
	hasRaftState, e := raft.HasExistingState(bs, bs, sn)
	if e != nil {
		bs.Close()
		nt.Close()
		return nil, e
	}
	if !o.Bootstrap && !hasRaftState {
		empty, e := replicated.ConsensusTablesEmpty(o.DB)
		if e != nil {
			bs.Close()
			nt.Close()
			return nil, e
		}
		if !empty {
			bs.Close()
			nt.Close()
			return nil, errors.New("replication join refused: node has pre-existing consensus-owned application state (collections, records, events, audit, jobs, webhook or function definitions) but no replicated history; a node joining a Trestle cluster for the first time must start with empty consensus-owned tables or be reseeded from canonical cluster state")
		}
	}
	node, e := replication.NewNode(replication.NodeOptions{ID: raft.ServerID(o.NodeID), Address: raft.ServerAddress(o.Address), Transport: nt, LogStore: bs, StableStore: bs, SnapshotStore: sn, FSM: fsm, Bootstrap: o.Bootstrap, CapabilitySource: auth, HeartbeatTimeout: o.Timing.HeartbeatTimeout, ElectionTimeout: o.Timing.ElectionTimeout, CommitTimeout: o.Timing.CommitTimeout, LeaderLeaseTimeout: o.Timing.LeaderLeaseTimeout, ProposeTimeout: o.Timing.ProposeTimeout})
	if e != nil {
		return nil, e
	}
	c := replicated.NewController(node)
	c.SetMode(replication.ModeReplicated)
	c.SetReadiness(replication.ReadinessStarting)
	c.SetForwardClient(forward(o.Transport, node))
	ctx, cancel := context.WithCancel(ctx)
	r := &Replicated{Controller: c, Node: node, FSM: fsm, Net: nt, rs: bs, stop: cancel, done: make(chan struct{})}
	go func() {
		replication.NewReadinessDriver(node, c.SetReadiness, fsm.ApplyFailure, 150*time.Millisecond).Run(ctx)
		close(r.done)
	}()
	return r, nil
}
func forward(t *clusterapi.Transport, n *replication.Node) replication.ForwardClient {
	return func(ctx context.Context, fr replication.ForwardRequest) (*replication.ApplyResult, error) {
		if t == nil {
			return nil, errors.New("forward transport unavailable")
		}
		_, id := n.Leader()
		if id == "" {
			return nil, errors.New("no leader")
		}
		b, _ := json.Marshal(fr)
		resp, e := t.Do(ctx, string(id), http.MethodPost, "/api/cluster/v1/replication/propose", "replication", b)
		if e != nil {
			return nil, e
		}
		defer resp.Body.Close()
		if resp.StatusCode != 200 {
			x, _ := io.ReadAll(resp.Body)
			return nil, fmt.Errorf("forward rejected: %s", x)
		}
		var ar replication.ApplyResult
		e = json.NewDecoder(resp.Body).Decode(&ar)
		return &ar, e
	}
}
func (r *Replicated) Close() {
	r.once.Do(func() {
		r.Controller.SetReadiness(replication.ReadinessShuttingDown)
		r.stop()
		<-r.done
		_ = r.Node.Shutdown()
		_ = r.rs.Close()
		_ = r.Net.Close()
	})
}
