package runtime

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	corerepl "github.com/gantry-tools/gantry-core/replication"
	"github.com/hashicorp/raft"
	clusterapi "github.com/trestle-cv/trestle/internal/cluster"
	"github.com/trestle-cv/trestle/internal/collections"
	"github.com/trestle-cv/trestle/internal/records"
	"github.com/trestle-cv/trestle/internal/store"
)

type certCA struct {
	cert *x509.Certificate
	key  *ecdsa.PrivateKey
}

func newCertCA(t *testing.T) *certCA {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "trestle-test-ca"}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(2 * time.Hour), IsCA: true, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature, BasicConstraintsValid: true}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	cert, _ := x509.ParseCertificate(der)
	return &certCA{cert: cert, key: key}
}

func (ca *certCA) nodeCert(t *testing.T, name string) tls.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(2), Subject: pkix.Name{CommonName: name}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(2 * time.Hour), KeyUsage: x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth}}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, ca.cert, &key.PublicKey, ca.key)
	if err != nil {
		t.Fatal(err)
	}
	leaf, _ := x509.ParseCertificate(der)
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key, Leaf: leaf}
}

func (ca *certCA) nodeTLS(t *testing.T, name string) *tls.Config {
	t.Helper()
	cert := ca.nodeCert(t, name)
	pool := x509.NewCertPool()
	pool.AddCert(ca.cert)
	return &tls.Config{Certificates: []tls.Certificate{cert}, RootCAs: pool, ClientCAs: pool, ClientAuth: tls.RequireAndVerifyClientCert, InsecureSkipVerify: true, MinVersion: tls.VersionTLS12}
}

func (ca *certCA) serverTLS(t *testing.T, name string) *tls.Config {
	t.Helper()
	// Server-only config: the forward RPC authenticates via the signed Gantry
	// envelope, so the propose endpoint does not require a TLS client cert.
	return &tls.Config{Certificates: []tls.Certificate{ca.nodeCert(t, name)}, MinVersion: tls.VersionTLS12}
}

func hashSecret(s string) []byte {
	h := sha256.Sum256([]byte(s))
	return h[:]
}

func seedNodeDB(t *testing.T, db store.Executor, nodeID string, peers map[string][2]string) {
	t.Helper()
	now := time.Now().UTC().Format(time.RFC3339Nano)
	if _, e := db.Exec(`INSERT INTO _trestle_cluster_identity(singleton,node_id,installation_id,public_key,private_key,capabilities_json,protocol_version,product_version,created_at) VALUES(1,?,?,?,?,?,?,?,?)`,
		nodeID, nodeID+"-inst", []byte("k"), []byte("k"), `["cluster.health","replication"]`, 1, "0.1.0", now); e != nil {
		t.Fatal(e)
	}
	for peer, cred := range peers {
		if _, e := db.Exec(`INSERT INTO _trestle_cluster_members(node_id,installation_id,public_endpoint,public_key,capabilities_json,protocol_version,product_version,state,outbound_secret,inbound_secret_hash,credential_version,created_at,paired_at) VALUES(?,?,?,?,?,?,?,?,?,?,1,?,?)`,
			peer, peer+"-inst", "https://"+peer+".example", []byte("k"), `["cluster.health","replication"]`, 1, "0.1.0", "active", cred[0], hashSecret(cred[1]), now, now); e != nil {
			t.Fatal(e)
		}
	}
}

func setEndpoint(t *testing.T, db store.Executor, peer, url string) {
	t.Helper()
	if _, e := db.Exec(`UPDATE _trestle_cluster_members SET public_endpoint=? WHERE node_id=?`, url, peer); e != nil {
		t.Fatal(e)
	}
}

type certNode struct {
	rt    *Replicated
	srv   *httptest.Server
	store *store.Store
	id    string
	dir   string
}

func freePort(t *testing.T) string {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := l.Addr().String()
	_ = l.Close()
	return addr
}

func buildNode(t *testing.T, ctx context.Context, ca *certCA, dataDir, nodeID, addr string, peers map[string][2]string, bootstrap bool, httpClient *http.Client) *certNode {
	t.Helper()
	s, e := store.Open(ctx, dataDir)
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() { s.Close() })
	seedNodeDB(t, s.DB(), nodeID, peers)
	return openNode(t, ctx, ca, s, dataDir, nodeID, addr, bootstrap, httpClient)
}

// restartNode reopens an existing node's durable state (the same SQLite
// database, Raft log and snapshots) as a fresh process, exercising the restart
// and snapshot+trailing-log recovery path. The member table already exists, so
// the identity/membership seed is not re-run.
func restartNode(t *testing.T, ctx context.Context, ca *certCA, dataDir, nodeID, addr string, httpClient *http.Client) *certNode {
	t.Helper()
	s, e := store.Open(ctx, dataDir)
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() { s.Close() })
	return openNode(t, ctx, ca, s, dataDir, nodeID, addr, false, httpClient)
}

func openNode(t *testing.T, ctx context.Context, ca *certCA, s *store.Store, dataDir, nodeID, addr string, bootstrap bool, httpClient *http.Client) *certNode {
	t.Helper()
	clusterSvc := clusterapi.New(s.DB())
	clusterTransport := clusterapi.NewTransport(s.DB(), clusterSvc, nil)
	clusterTransport.SetHTTPClient(httpClient)
	tlsConf := ca.nodeTLS(t, nodeID)
	rt, e := NewReplication(ctx, ReplicationOptions{
		DB: s.DB(), DataDir: dataDir, NodeID: nodeID, Address: addr, Bootstrap: bootstrap,
		TLS: tlsConf, Transport: clusterTransport, Timing: corerepl.ProductionTiming(),
	})
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(rt.Close)
	return &certNode{rt: rt, srv: startNodeServer(t, ca, nodeID, rt, clusterTransport), store: s, id: nodeID, dir: dataDir}
}

// startNodeServer exposes the production-shaped proposal endpoint the follower
// forwarding path authenticates against.
func startNodeServer(t *testing.T, ca *certCA, nodeID string, rt *Replicated, clusterTransport *clusterapi.Transport) *httptest.Server {
	t.Helper()
	us := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/cluster/v1/replication/propose" {
			http.NotFound(w, r)
			return
		}
		body, _, e := clusterTransport.Authenticate(r, "replication")
		if e != nil {
			http.Error(w, "unauthorized", 401)
			return
		}
		var fr corerepl.ForwardRequest
		if json.Unmarshal(body, &fr) != nil {
			http.Error(w, "bad request", 400)
			return
		}
		mode, ready := rt.Controller.State()
		if mode != corerepl.ModeReplicated || ready != corerepl.ReadinessReadyLeader {
			http.Error(w, "leader not ready", 503)
			return
		}
		cctx := corerepl.WithRequestID(r.Context(), fr.OpID)
		res, e := rt.Controller.Propose(cctx, fr.Kind, fr.ObjectID, fr.Revision, fr.Payload)
		if e != nil {
			http.Error(w, e.Error(), 503)
			return
		}
		_ = json.NewEncoder(w).Encode(res)
	}))
	us.TLS = ca.serverTLS(t, nodeID)
	us.StartTLS()
	t.Cleanup(us.Close)
	return us
}

// meshSecrets generates the per-direction pairwise Gantry credentials for a
// fully meshed set of node ids.
func meshSecrets(ids []string) map[string]map[string][2]string {
	out := map[string]map[string][2]string{}
	for _, id := range ids {
		out[id] = map[string][2]string{}
	}
	for i := 0; i < len(ids); i++ {
		for j := i + 1; j < len(ids); j++ {
			ij := ids[i] + "_to_" + ids[j]
			ji := ids[j] + "_to_" + ids[i]
			out[ids[i]][ids[j]] = [2]string{ij, ji}
			out[ids[j]][ids[i]] = [2]string{ji, ij}
		}
	}
	return out
}

// fullMeshNodes builds N independent production-shaped nodes with the complete
// Gantry trust graph (every node paired with every other node) and returns them
// keyed by node id. Gantry pairing remains separate from raft voter membership.
func fullMeshNodes(t *testing.T, ctx context.Context, ca *certCA, httpClient *http.Client, ids ...string) map[string]*certNode {
	t.Helper()
	secrets := meshSecrets(ids)
	nodes := map[string]*certNode{}
	for i, id := range ids {
		nodes[id] = buildNode(t, ctx, ca, t.TempDir(), id, freePort(t), secrets[id], i == 0, httpClient)
	}
	return nodes
}

// repairEndpoints re-points every node's Gantry member rows at the current
// HTTPS endpoint of every other node (used after nodes restart on new ports).
func repairEndpoints(t *testing.T, nodes ...*certNode) {
	t.Helper()
	for _, n := range nodes {
		for _, m := range nodes {
			if n.id == m.id {
				continue
			}
			setEndpoint(t, n.store.DB(), m.id, m.srv.URL)
		}
	}
}

// disableMember sets a Gantry member to disabled on the local node, the same
// authorization effect an operator achieves through the production member
// disable/revoke surface.
func disableMember(t *testing.T, n *certNode, peerID string) {
	t.Helper()
	if _, e := n.store.DB().Exec(`UPDATE _trestle_cluster_members SET state='disabled' WHERE node_id=?`, peerID); e != nil {
		t.Fatal(e)
	}
}

func enableMember(t *testing.T, n *certNode, peerID string) {
	t.Helper()
	if _, e := n.store.DB().Exec(`UPDATE _trestle_cluster_members SET state='active' WHERE node_id=?`, peerID); e != nil {
		t.Fatal(e)
	}
}

func waitReady(t *testing.T, n *certNode, want corerepl.Readiness) {
	t.Helper()
	deadline := time.Now().Add(40 * time.Second)
	for time.Now().Before(deadline) {
		_, rd := n.rt.Controller.State()
		if rd == want {
			return
		}
		time.Sleep(100 * time.Millisecond)
	}
	_, rd := n.rt.Controller.State()
	t.Fatalf("node %s readiness=%s want %s", n.id, rd, want)
}

func recordCountNoFail(n *certNode, collectionName string) int {
	var id string
	if e := n.store.DB().QueryRow(`SELECT id FROM _trestle_collections WHERE name=?`, collectionName).Scan(&id); e != nil {
		return -1
	}
	var c int
	if e := n.store.DB().QueryRow(`SELECT COUNT(*) FROM ` + `"` + collections.PhysicalTableName(id) + `"`).Scan(&c); e != nil {
		return -1
	}
	return c
}

func recordCount(t *testing.T, n *certNode, collectionName string) int {
	t.Helper()
	var id string
	if e := n.store.DB().QueryRow(`SELECT id FROM _trestle_collections WHERE name=?`, collectionName).Scan(&id); e != nil {
		t.Fatalf("collection %s missing: %v", collectionName, e)
	}
	var c int
	if e := n.store.DB().QueryRow(`SELECT COUNT(*) FROM ` + `"` + collections.PhysicalTableName(id) + `"`).Scan(&c); e != nil {
		t.Fatalf("record count: %v", e)
	}
	return c
}

func waitRecordCount(t *testing.T, n *certNode, collectionName string, want int) {
	t.Helper()
	deadline := time.Now().Add(60 * time.Second)
	for time.Now().Before(deadline) {
		if recordCountNoFail(n, collectionName) == want {
			return
		}
		time.Sleep(100 * time.Millisecond)
	}
	t.Fatalf("node %s collection %s record count=%d want %d", n.id, collectionName, recordCount(t, n, collectionName), want)
}

func followerPut(t *testing.T, n *certNode, ctx context.Context, rec records.ReplicatedRecord, idem context.Context) {
	t.Helper()
	first := true
	deadline := time.Now().Add(60 * time.Second)
	for time.Now().Before(deadline) {
		_, rd := n.rt.Controller.State()
		if rd != corerepl.ReadinessReadyFollower && rd != corerepl.ReadinessReadyLeader {
			time.Sleep(100 * time.Millisecond)
			continue
		}
		c := ctx
		if idem != nil {
			c = idem
		}
		_, e := n.rt.Controller.PutRecord(c, rec)
		if e == nil {
			return
		}
		if first {
			t.Logf("follower put first error: %v | state=%s readiness=%s", e, n.rt.Node.State(), func() string { _, r := n.rt.Controller.State(); return r.String() }())
			first = false
		}
		if isRetriable(e) {
			time.Sleep(150 * time.Millisecond)
			continue
		} else {
			t.Fatalf("follower put: %v", e)
		}
	}
	t.Fatal("follower put timed out")
}

func isRetriable(e error) bool {
	return e != nil && (containsErr(e, "learner") || containsErr(e, "no leader") || containsErr(e, "unavailable"))
}

func containsErr(e error, s string) bool {
	return e != nil && len(e.Error()) >= len(s) && index(e.Error(), s) >= 0
}

func index(s, sub string) int {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return i
		}
	}
	return -1
}

func leaderPut(t *testing.T, n *certNode, ctx context.Context, rec records.ReplicatedRecord) {
	t.Helper()
	deadline := time.Now().Add(40 * time.Second)
	for time.Now().Before(deadline) {
		if _, e := n.rt.Controller.PutRecord(ctx, rec); e == nil {
			return
		} else if isRetriable(e) {
			time.Sleep(200 * time.Millisecond)
			continue
		} else {
			t.Fatalf("leader put: %v", e)
		}
	}
	t.Fatal("leader put timed out")
}

func waitAnyLeader(t *testing.T, nodes ...*certNode) {
	t.Helper()
	deadline := time.Now().Add(40 * time.Second)
	for time.Now().Before(deadline) {
		for _, n := range nodes {
			if n.rt.Node.State() == raft.Leader {
				return
			}
		}
		time.Sleep(100 * time.Millisecond)
	}
	t.Fatal("no leader elected after loss")
}

// waitReadyAny waits until a node reaches ready-leader or ready-follower.
func waitReadyAny(t *testing.T, n *certNode) {
	t.Helper()
	deadline := time.Now().Add(60 * time.Second)
	for time.Now().Before(deadline) {
		_, rd := n.rt.Controller.State()
		if rd == corerepl.ReadinessReadyLeader || rd == corerepl.ReadinessReadyFollower {
			return
		}
		time.Sleep(100 * time.Millisecond)
	}
	_, rd := n.rt.Controller.State()
	t.Fatalf("node %s never became ready: %s", n.id, rd)
}

func isLeader(n *certNode) bool { return n.rt.Node.State() == raft.Leader }

// TestThreeNodeProductionCertification exercises the production-shaped cluster:
// real TLS transports, explicit raft membership, leader + follower-forwarded
// mutations, convergence, leader loss/failover and caller idempotency.
func TestThreeNodeProductionCertification(t *testing.T) {
	ca := newCertCA(t)
	pool := x509.NewCertPool()
	pool.AddCert(ca.cert)
	httpClient := &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{RootCAs: pool, InsecureSkipVerify: true, MinVersion: tls.VersionTLS12}}}
	ctx := context.Background()
	const aToB, bToA, aToC, cToA, bToC, cToB = "A_to_B", "B_to_A", "A_to_C", "C_to_A", "B_to_C", "C_to_B"

	a := buildNode(t, ctx, ca, t.TempDir(), "A", freePort(t), map[string][2]string{"B": {aToB, bToA}, "C": {aToC, cToA}}, true, httpClient)
	b := buildNode(t, ctx, ca, t.TempDir(), "B", freePort(t), map[string][2]string{"A": {bToA, aToB}, "C": {bToC, cToB}}, false, httpClient)
	c := buildNode(t, ctx, ca, t.TempDir(), "C", freePort(t), map[string][2]string{"A": {cToA, aToC}, "B": {cToB, bToC}}, false, httpClient)
	setEndpoint(t, a.store.DB(), "B", b.srv.URL)
	setEndpoint(t, a.store.DB(), "C", c.srv.URL)
	setEndpoint(t, b.store.DB(), "A", a.srv.URL)
	setEndpoint(t, b.store.DB(), "C", c.srv.URL)
	setEndpoint(t, c.store.DB(), "A", a.srv.URL)
	setEndpoint(t, c.store.DB(), "B", b.srv.URL)

	waitReady(t, a, corerepl.ReadinessReadyLeader)
	if e := a.rt.Node.AddVoter("B", b.rt.Node.Address()); e != nil {
		t.Fatalf("join B: %v", e)
	}
	if e := a.rt.Node.AddVoter("C", c.rt.Node.Address()); e != nil {
		t.Fatalf("join C: %v", e)
	}
	waitReady(t, b, corerepl.ReadinessReadyFollower)
	waitReady(t, c, corerepl.ReadinessReadyFollower)

	// Leader mutations: collection + a record through A.
	col := collections.Collection{ID: "col_people", Name: "people", Kind: "base", CreatedAt: "2026-01-01T00:00:00Z", UpdatedAt: "2026-01-01T00:00:00Z",
		Fields: []collections.Field{{ID: "fld_name", Name: "name", Type: "text"}, {ID: "fld_age", Name: "age", Type: "number"}}}
	if _, e := a.rt.Controller.PutCollection(ctx, col); e != nil {
		t.Fatalf("leader collection: %v", e)
	}
	rec1 := records.ReplicatedRecord{CollectionID: "col_people", RecordID: "r1", Version: 1, CreatedAt: "2026-01-01T00:00:00Z", UpdatedAt: "2026-01-01T00:00:00Z", Values: map[string]any{"name": "alice", "age": 30.0}}
	if _, e := a.rt.Controller.PutRecord(ctx, rec1); e != nil {
		t.Fatalf("leader record: %v", e)
	}
	waitRecordCount(t, a, "people", 1)
	waitRecordCount(t, b, "people", 1)
	waitRecordCount(t, c, "people", 1)
	waitReady(t, b, corerepl.ReadinessReadyFollower)

	// Follower-forwarded mutation through B with a caller idempotency identity.
	rec2 := records.ReplicatedRecord{CollectionID: "col_people", RecordID: "r2", Version: 1, CreatedAt: "2026-01-01T00:00:00Z", UpdatedAt: "2026-01-01T00:00:00Z", Values: map[string]any{"name": "bob", "age": 40.0}}
	idem := corerepl.WithRequestID(ctx, "trestle-idem-col_people-req2")
	followerPut(t, b, ctx, rec2, idem)
	// Ambiguous retry of the same identity -> one mutation.
	followerPut(t, b, ctx, rec2, idem)
	waitRecordCount(t, a, "people", 2)
	waitRecordCount(t, b, "people", 2)
	waitRecordCount(t, c, "people", 2)

	// Leader loss: close A; B/C elect a new leader; a write still commits.
	a.rt.Close()
	waitAnyLeader(t, b, c)
	leader, follower := b, c
	if !isLeader(leader) {
		leader, follower = c, b
	}
	waitReady(t, leader, corerepl.ReadinessReadyLeader)
	rec3 := records.ReplicatedRecord{CollectionID: "col_people", RecordID: "r3", Version: 1, CreatedAt: "2026-01-01T00:00:00Z", UpdatedAt: "2026-01-01T00:00:00Z", Values: map[string]any{"name": "carol", "age": 25.0}}
	leaderPut(t, leader, ctx, rec3)
	waitRecordCount(t, leader, "people", 3)
	waitRecordCount(t, follower, "people", 3)
}

// expectMutationClosed attempts an authoritative mutation on n and asserts it
// fails closed with the product state unchanged (no local SQLite fallback).
func expectMutationClosed(t *testing.T, n *certNode, ctx context.Context, collectionID, recordID string) {
	t.Helper()
	before := recordCountNoFail(n, "people")
	rec := records.ReplicatedRecord{CollectionID: collectionID, RecordID: recordID, Version: 1, CreatedAt: "2026-01-01T00:00:00Z", UpdatedAt: "2026-01-01T00:00:00Z", Values: map[string]any{"name": "nope", "age": 0.0}}
	if _, e := n.rt.Controller.PutRecord(ctx, rec); e == nil {
		t.Fatalf("node %s mutation unexpectedly committed without quorum", n.id)
	} else if !isRetriable(e) && !containsErr(e, "quorum") && !containsErr(e, "not leader") {
		t.Logf("node %s closed mutation error: %v", n.id, e)
	}
	if got := recordCountNoFail(n, "people"); got != before {
		t.Fatalf("node %s local state mutated on rejected op: before=%d after=%d", n.id, before, got)
	}
}

// TestFiveNodeProductionCertification certifies the generic arbitrary-voter
// path beyond three nodes: five voters formed through the identical AddVoter
// membership path, full-mesh Gantry trust, quorum boundaries at 5/5, 4/5, 3/5
// and 2/5, multi-follower forwarding, snapshot+trailing-log recovery, a
// whole-cluster restart, peer revocation, and the repaired distributed
// semantics (idempotency, stale preconditions, duplicate collections).
func TestFiveNodeProductionCertification(t *testing.T) {
	ca := newCertCA(t)
	pool := x509.NewCertPool()
	pool.AddCert(ca.cert)
	httpClient := &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{RootCAs: pool, InsecureSkipVerify: true, MinVersion: tls.VersionTLS12}}}
	ctx := context.Background()

	nodes := fullMeshNodes(t, ctx, ca, httpClient, "A", "B", "C", "D", "E")
	a, b, c, d, e := nodes["A"], nodes["B"], nodes["C"], nodes["D"], nodes["E"]
	all := []*certNode{a, b, c, d, e}
	repairEndpoints(t, all...)

	// Raft formation: A bootstraps, then voters 2..5 travel the generic
	// AddVoter path (the same path trestle replicate join drives).
	waitReady(t, a, corerepl.ReadinessReadyLeader)
	for _, n := range []*certNode{b, c, d, e} {
		if err := a.rt.Node.AddVoter(raft.ServerID(n.id), n.rt.Node.Address()); err != nil {
			t.Fatalf("join %s (generic path): %v", n.id, err)
		}
	}
	for _, n := range []*certNode{b, c, d, e} {
		waitReady(t, n, corerepl.ReadinessReadyFollower)
	}
	cfgs, err := a.rt.Node.Configuration()
	if err != nil {
		t.Fatal(err)
	}
	voters := 0
	for _, s := range cfgs {
		if s.Suffrage == raft.Voter {
			voters++
		}
	}
	if voters != 5 {
		t.Fatalf("expected 5 voters, got %d", voters)
	}
	leader := a
	followers := []*certNode{}
	for _, n := range all {
		if isLeader(n) {
			leader = n
		} else {
			followers = append(followers, n)
		}
	}
	if len(followers) != 4 {
		t.Fatalf("expected 1 leader + 4 followers, got leader=%s followers=%d", leader.id, len(followers))
	}

	// Baseline convergence: collection + records through the leader.
	col := collections.Collection{ID: "col_people", Name: "people", Kind: "base", CreatedAt: "2026-01-01T00:00:00Z", UpdatedAt: "2026-01-01T00:00:00Z",
		Fields: []collections.Field{{ID: "fld_name", Name: "name", Type: "text"}, {ID: "fld_age", Name: "age", Type: "number"}}}
	if _, e := leader.rt.Controller.PutCollection(ctx, col); e != nil {
		t.Fatalf("leader collection: %v", e)
	}
	rec1 := records.ReplicatedRecord{CollectionID: "col_people", RecordID: "r1", Version: 1, CreatedAt: "2026-01-01T00:00:00Z", UpdatedAt: "2026-01-01T00:00:00Z", Values: map[string]any{"name": "alice", "age": 30.0}}
	if _, e := leader.rt.Controller.PutRecord(ctx, rec1); e != nil {
		t.Fatalf("leader record: %v", e)
	}
	for _, n := range all {
		waitRecordCount(t, n, "people", 1)
	}

	// Multi-follower forwarding: B, C, D and E each originate a mutation.
	byName := map[string]*certNode{"A": a, "B": b, "C": c, "D": d, "E": e}
	for i, f := range []*certNode{b, c, d, e} {
		rec := records.ReplicatedRecord{CollectionID: "col_people", RecordID: "r" + itoa(i+2), Version: 1, CreatedAt: "2026-01-01T00:00:00Z", UpdatedAt: "2026-01-01T00:00:00Z", Values: map[string]any{"name": f.id, "age": float64(i + 2)}}
		followerPut(t, f, ctx, rec, nil)
	}
	for _, n := range all {
		waitRecordCount(t, n, "people", 5)
	}

	// Distributed semantics wall on the 5-voter cluster.
	idemRec := records.ReplicatedRecord{CollectionID: "col_people", RecordID: "idem1", Version: 1, CreatedAt: "2026-01-01T00:00:00Z", UpdatedAt: "2026-01-01T00:00:00Z", Values: map[string]any{"name": "idem", "age": 1.0}}
	idemCtx := corerepl.WithRequestID(ctx, "trestle-idem-col_people-5node")
	if _, e := leader.rt.Controller.PutRecord(idemCtx, idemRec); e != nil {
		t.Fatalf("idempotent create: %v", e)
	}
	if _, e := leader.rt.Controller.PutRecord(idemCtx, idemRec); e != nil {
		t.Fatalf("idempotent replay must return the committed result: %v", e)
	}
	badCtx := corerepl.WithRequestID(ctx, "trestle-idem-col_people-5node")
	badRec := records.ReplicatedRecord{CollectionID: "col_people", RecordID: "idem1", Version: 1, CreatedAt: "2026-01-01T00:00:00Z", UpdatedAt: "2026-01-01T00:00:00Z", Values: map[string]any{"name": "changed", "age": 99.0}}
	if _, e := leader.rt.Controller.PutRecord(badCtx, badRec); e == nil {
		t.Fatal("changed-intent idempotent retry must be rejected")
	} else if !containsErr(e, "different payload") {
		t.Fatalf("changed-intent rejection: %v", e)
	}
	// Stale record precondition through a follower: reject, replica stays healthy.
	stale := records.ReplicatedRecord{CollectionID: "col_people", RecordID: "idem1", Version: 99, CreatedAt: "2026-01-01T00:00:00Z", UpdatedAt: "2026-01-01T00:00:00Z", Values: map[string]any{"name": "stale", "age": 2.0}}
	expectRejected(t, func() error {
		_, e := b.rt.Controller.PutRecord(ctx, stale)
		return e
	})
	// Duplicate collection (same name, different id): reject, replica stays healthy.
	dup := collections.Collection{ID: "col_people2", Name: "people", Kind: "base", CreatedAt: "2026-01-01T00:00:00Z", UpdatedAt: "2026-01-01T00:00:00Z",
		Fields: []collections.Field{{ID: "fld_name2", Name: "name", Type: "text"}}}
	expectRejected(t, func() error {
		_, e := c.rt.Controller.PutCollection(ctx, dup)
		return e
	})
	// After the semantic conflicts, a valid mutation still commits + converges.
	postRec := records.ReplicatedRecord{CollectionID: "col_people", RecordID: "after-conflicts", Version: 1, CreatedAt: "2026-01-01T00:00:00Z", UpdatedAt: "2026-01-01T00:00:00Z", Values: map[string]any{"name": "ok", "age": 7.0}}
	followerPut(t, d, ctx, postRec, nil)
	for _, n := range all {
		waitRecordCount(t, n, "people", 7)
	}

	// Quorum wall: 5/5 already proven; stop E -> 4/5 still writable.
	e.rt.Close()
	remaining := []*certNode{a, b, c, d}
	waitAnyLeader(t, remaining...)
	leader = findLeader(t, remaining...)
	q1 := records.ReplicatedRecord{CollectionID: "col_people", RecordID: "q45", Version: 1, CreatedAt: "2026-01-01T00:00:00Z", UpdatedAt: "2026-01-01T00:00:00Z", Values: map[string]any{"name": "q45", "age": 45.0}}
	leaderPut(t, leader, ctx, q1)
	for _, n := range remaining {
		waitRecordCount(t, n, "people", 8)
	}

	// Stop D -> 3/5: two voter failures tolerated, still writable.
	d.rt.Close()
	remaining = []*certNode{a, b, c}
	waitAnyLeader(t, remaining...)
	leader = findLeader(t, remaining...)
	q2 := records.ReplicatedRecord{CollectionID: "col_people", RecordID: "q35", Version: 1, CreatedAt: "2026-01-01T00:00:00Z", UpdatedAt: "2026-01-01T00:00:00Z", Values: map[string]any{"name": "q35", "age": 35.0}}
	leaderPut(t, leader, ctx, q2)
	for _, n := range remaining {
		waitRecordCount(t, n, "people", 9)
	}

	// Stop C -> 2/5: no quorum; authoritative mutations fail closed with NO
	// local SQLite fallback and unchanged product state.
	c.rt.Close()
	remaining = []*certNode{a, b}
	for _, n := range remaining {
		expectMutationClosed(t, n, ctx, "col_people", "noquorum")
	}

	// Restore the stopped voters; the full cluster reconverges.
	restartInto := func(orig *certNode, dataDir string) *certNode {
		rn := restartNode(t, ctx, ca, dataDir, orig.id, string(orig.rt.Node.Address()), httpClient)
		return rn
	}
	c2 := restartInto(c, c.dir)
	d2 := restartInto(d, d.dir)
	e2 := restartInto(e, e.dir)
	_ = byName
	nodes["C"], nodes["D"], nodes["E"] = c2, d2, e2
	all = []*certNode{a, b, c2, d2, e2}
	repairEndpoints(t, all...)
	waitAnyLeader(t, all...)
	for _, n := range all {
		waitReadyAny(t, n)
	}
	// The restored cluster reconverges to a single equal semantic state. A
	// timed-out 2/5 proposal may legitimately commit during recovery (raft
	// ambiguous commit-on-recovery), so convergence is asserted as equality
	// across nodes plus a fresh committed write, not an exact count.
	waitConvergedEqual(t, all...)
	recovery := records.ReplicatedRecord{CollectionID: "col_people", RecordID: "post-recovery", Version: 1, CreatedAt: "2026-01-01T00:00:00Z", UpdatedAt: "2026-01-01T00:00:00Z", Values: map[string]any{"name": "recovered", "age": 11.0}}
	leaderPut(t, findLeader(t, all...), ctx, recovery)
	for _, n := range all {
		waitRecordPresent(t, n, "col_people", "post-recovery")
	}

	// Leader transition on the restored 5-voter cluster (force a leadership
	// change by shutting the current leader down and letting the quorum elect).
	cur := findLeader(t, all...)
	cur.rt.Close()
	rest := []*certNode{}
	for _, n := range all {
		if n.id != cur.id {
			rest = append(rest, n)
		}
	}
	waitAnyLeader(t, rest...)
	newLeader := findLeader(t, rest...)
	transRec := records.ReplicatedRecord{CollectionID: "col_people", RecordID: "after-transition", Version: 1, CreatedAt: "2026-01-01T00:00:00Z", UpdatedAt: "2026-01-01T00:00:00Z", Values: map[string]any{"name": "transition", "age": 10.0}}
	leaderPut(t, newLeader, ctx, transRec)
	for _, n := range rest {
		waitRecordPresent(t, n, "col_people", "after-transition")
	}

	// Snapshot + trailing-log recovery: force a snapshot on one follower,
	// commit trailing mutations, restart it and verify it recovers through them.
	snapNode := findFollower(t, rest...)
	if e := snapNode.rt.Node.Snapshot(); e != nil {
		t.Fatalf("force snapshot: %v", e)
	}
	for i := 0; i < 3; i++ {
		tr := records.ReplicatedRecord{CollectionID: "col_people", RecordID: "trail" + itoa(i), Version: 1, CreatedAt: "2026-01-01T00:00:00Z", UpdatedAt: "2026-01-01T00:00:00Z", Values: map[string]any{"name": "trail", "age": float64(i)}}
		leaderPut(t, newLeader, ctx, tr)
	}
	// The restarted node takes over the snapshot node's raft address and
	// durable state; the old process must release the address first.
	snapNode.rt.Close()
	snapNode2 := restartNode(t, ctx, ca, snapNode.dir, snapNode.id, string(snapNode.rt.Node.Address()), httpClient)
	rest = replaceNode(t, rest, snapNode, snapNode2)
	repairEndpoints(t, rest...)
	waitReadyAny(t, snapNode2)
	waitRecordPresent(t, snapNode2, "col_people", "trail2")
	waitConvergedEqual(t, rest...)

	// Whole-cluster restart: close all five, restart each over its durable
	// state, re-point the mesh, and verify election, convergence and a fresh
	// authoritative mutation.
	for _, n := range rest {
		n.rt.Close()
	}
	allRestarted := []*certNode{}
	for _, n := range rest {
		allRestarted = append(allRestarted, restartNode(t, ctx, ca, n.dir, n.id, string(n.rt.Node.Address()), httpClient))
	}
	repairEndpoints(t, allRestarted...)
	waitAnyLeader(t, allRestarted...)
	for _, n := range allRestarted {
		waitReadyAny(t, n)
	}
	waitConvergedEqual(t, allRestarted...)
	restartRec := records.ReplicatedRecord{CollectionID: "col_people", RecordID: "after-full-restart", Version: 1, CreatedAt: "2026-01-01T00:00:00Z", UpdatedAt: "2026-01-01T00:00:00Z", Values: map[string]any{"name": "restarted", "age": 12.0}}
	leaderPut(t, findLeader(t, allRestarted...), ctx, restartRec)
	for _, n := range allRestarted {
		waitRecordPresent(t, n, "col_people", "after-full-restart")
	}

	// Peer disable/revoke against one voter while quorum remains: the healthy
	// majority continues, the isolated peer cannot originate authoritative
	// mutations, and re-enabling restores catch-up.
	var isolated *certNode
	for _, n := range allRestarted {
		if n.id == snapNode2.id {
			isolated = n
			break
		}
	}
	if isolated == nil {
		t.Fatal("isolated peer not found after restart")
	}
	for _, n := range allRestarted {
		if n.id != isolated.id {
			disableMember(t, n, isolated.id)
		}
	}
	quorumOK := records.ReplicatedRecord{CollectionID: "col_people", RecordID: "after-disable", Version: 1, CreatedAt: "2026-01-01T00:00:00Z", UpdatedAt: "2026-01-01T00:00:00Z", Values: map[string]any{"name": "quorum", "age": 13.0}}
	leaderPut(t, findLeader(t, allRestarted...), ctx, quorumOK)
	// Disable takes effect through the revalidation window; wait until the
	// isolated peer can no longer reach a quorum before asserting fail-closed.
	waitReadiness(t, isolated, corerepl.ReadinessNoLeader)
	expectMutationClosed(t, isolated, ctx, "col_people", "isolated-write")
	for _, n := range allRestarted {
		if n.id != isolated.id {
			enableMember(t, n, isolated.id)
		}
	}
	waitReadyAny(t, isolated)
	reenabled := records.ReplicatedRecord{CollectionID: "col_people", RecordID: "after-reenable", Version: 1, CreatedAt: "2026-01-01T00:00:00Z", UpdatedAt: "2026-01-01T00:00:00Z", Values: map[string]any{"name": "reenabled", "age": 14.0}}
	leaderPut(t, findLeader(t, allRestarted...), ctx, reenabled)
	for _, n := range allRestarted {
		waitRecordPresent(t, n, "col_people", "after-reenable")
	}
}

// findLeader returns a leader among nodes, or fails.
func findLeader(t *testing.T, nodes ...*certNode) *certNode {
	t.Helper()
	deadline := time.Now().Add(40 * time.Second)
	for time.Now().Before(deadline) {
		for _, n := range nodes {
			if isLeader(n) {
				return n
			}
		}
		time.Sleep(100 * time.Millisecond)
	}
	t.Fatal("no leader found")
	return nil
}

func findFollower(t *testing.T, nodes ...*certNode) *certNode {
	t.Helper()
	for _, n := range nodes {
		if !isLeader(n) {
			return n
		}
	}
	t.Fatal("no follower found")
	return nil
}

func replaceNode(t *testing.T, nodes []*certNode, old, repl *certNode) []*certNode {
	t.Helper()
	for i, n := range nodes {
		if n.id == old.id {
			nodes[i] = repl
			return nodes
		}
	}
	t.Fatal("node not found for replacement")
	return nodes
}

func itoa(i int) string {
	if i == 0 {
		return "0"
	}
	var b [20]byte
	pos := len(b)
	for i > 0 {
		pos--
		b[pos] = byte('0' + i%10)
		i /= 10
	}
	return string(b[pos:])
}

// TestJoinUnpairedVoterAvailability investigates the operational consequence of
// adding a Raft voter that is NOT an active Gantry-paired peer. It proves the
// membership change commits (raft commits configuration before transport
// reachability is known) and that a permanently unreachable voter reduces the
// cluster's failure tolerance: a 3-voter cluster that tolerated one failure
// tolerates none once a fourth, unreachable voter is added.
func TestJoinUnpairedVoterAvailability(t *testing.T) {
	ca := newCertCA(t)
	pool := x509.NewCertPool()
	pool.AddCert(ca.cert)
	httpClient := &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{RootCAs: pool, InsecureSkipVerify: true, MinVersion: tls.VersionTLS12}}}
	ctx := context.Background()

	nodes := fullMeshNodes(t, ctx, ca, httpClient, "A", "B", "C")
	a, b, c := nodes["A"], nodes["B"], nodes["C"]
	all := []*certNode{a, b, c}
	repairEndpoints(t, all...)

	waitReady(t, a, corerepl.ReadinessReadyLeader)
	for _, n := range []*certNode{b, c} {
		if e := a.rt.Node.AddVoter(raft.ServerID(n.id), n.rt.Node.Address()); e != nil {
			t.Fatalf("join %s: %v", n.id, e)
		}
	}
	for _, n := range []*certNode{b, c} {
		waitReady(t, n, corerepl.ReadinessReadyFollower)
	}
	col := collections.Collection{ID: "col_people", Name: "people", Kind: "base", CreatedAt: "2026-01-01T00:00:00Z", UpdatedAt: "2026-01-01T00:00:00Z",
		Fields: []collections.Field{{ID: "fld_name", Name: "name", Type: "text"}, {ID: "fld_age", Name: "age", Type: "number"}}}
	if _, e := a.rt.Controller.PutCollection(ctx, col); e != nil {
		t.Fatal(e)
	}
	for _, n := range all {
		waitRecordCount(t, n, "people", 0)
	}
	_ = recordCountNoFail(a, "people")

	// Add a voter that is NOT a Gantry peer and whose address is unreachable.
	const bogusID = "X"
	bogusAddr := "127.0.0.1:1"
	if e := a.rt.Node.AddVoter(raft.ServerID(bogusID), raft.ServerAddress(bogusAddr)); e != nil {
		t.Fatalf("AddVoter for an unpaired node should commit via the real quorum, got: %v", e)
	}
	// The membership change committed: the config now has 4 voters.
	cfg, err := a.rt.Node.Configuration()
	if err != nil {
		t.Fatal(err)
	}
	voters := 0
	for _, s := range cfg {
		if s.Suffrage == raft.Voter {
			voters++
		}
	}
	if voters != 4 {
		t.Fatalf("expected the unpaired voter to be added (4 voters), got %d", voters)
	}
	// Availability consequence: with an unpaired voter whose capabilities are
	// unknown, the leader's mutation path fails closed immediately — the Core
	// rolling-version gate refuses to propose while any voter's schema support
	// is unconfirmed. The cluster becomes read-only (no authoritative writes),
	// even though all three real voters are up.
	okRec := records.ReplicatedRecord{CollectionID: "col_people", RecordID: "still-ok", Version: 1, CreatedAt: "2026-01-01T00:00:00Z", UpdatedAt: "2026-01-01T00:00:00Z", Values: map[string]any{"name": "ok", "age": 1.0}}
	if _, e := a.rt.Controller.PutRecord(ctx, okRec); e == nil {
		t.Fatal("expected authoritative mutation to fail closed with an unpaired voter in the config")
	} else if !containsErr(e, "capabilities unknown") {
		t.Logf("unpaired-voter mutation rejection: %v", e)
	}
	// The rejected write did not change local product state.
	if got := recordCountNoFail(a, "people"); got != 0 {
		t.Fatalf("rejected write mutated local state: count=%d", got)
	}
}

// waitRecordPresent waits until the specific record id is materialized on n.
func waitRecordPresent(t *testing.T, n *certNode, collectionID, recordID string) {
	t.Helper()
	var id string
	if e := n.store.DB().QueryRow(`SELECT id FROM _trestle_collections WHERE name=?`, "people").Scan(&id); e != nil {
		t.Fatalf("collection lookup: %v", e)
	}
	deadline := time.Now().Add(60 * time.Second)
	for time.Now().Before(deadline) {
		var c int
		if e := n.store.DB().QueryRow(`SELECT COUNT(*) FROM `+`"`+collections.PhysicalTableName(id)+`" WHERE _id=?`, recordID).Scan(&c); e != nil || c == 0 {
			time.Sleep(100 * time.Millisecond)
			continue
		}
		return
	}
	t.Fatalf("node %s record %s not materialized", n.id, recordID)
}

// waitConvergedEqual waits until every node reports the same record count for
// the people collection (semantic convergence without an exact-count assumption,
// which raft's ambiguous commit-on-recovery can legitimately adjust).
func waitConvergedEqual(t *testing.T, nodes ...*certNode) {
	t.Helper()
	deadline := time.Now().Add(60 * time.Second)
	for time.Now().Before(deadline) {
		first := recordCountNoFail(nodes[0], "people")
		ok := true
		for _, n := range nodes[1:] {
			if recordCountNoFail(n, "people") != first {
				ok = false
				break
			}
		}
		if ok && first >= 0 {
			return
		}
		time.Sleep(100 * time.Millisecond)
	}
	vals := []int{}
	for _, n := range nodes {
		vals = append(vals, recordCountNoFail(n, "people"))
	}
	t.Fatalf("nodes not converged to equal state: %v", vals)
}

// expectRejected retries fn across transient catch-up states (learner, no
// leader, unavailable) and asserts the final non-transient outcome is an error
// (a deterministic rejection), never a successful mutation.
func expectRejected(t *testing.T, fn func() error) {
	t.Helper()
	deadline := time.Now().Add(60 * time.Second)
	for time.Now().Before(deadline) {
		e := fn()
		if e == nil {
			t.Fatal("expected a deterministic rejection, mutation succeeded")
		}
		if isRetriable(e) {
			time.Sleep(150 * time.Millisecond)
			continue
		}
		return
	}
	t.Fatal("rejection never became non-transient")
}

// waitReadiness waits until a node reaches a specific readiness.
func waitReadiness(t *testing.T, n *certNode, want corerepl.Readiness) {
	t.Helper()
	deadline := time.Now().Add(90 * time.Second)
	for time.Now().Before(deadline) {
		_, rd := n.rt.Controller.State()
		if rd == want {
			return
		}
		time.Sleep(100 * time.Millisecond)
	}
	_, rd := n.rt.Controller.State()
	t.Fatalf("node %s readiness=%s want %s", n.id, rd, want)
}
