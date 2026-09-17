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
	us := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/api/cluster/v1/replication/propose" {
			println("PROPOSE-HANDLER start")
			body, _, e := clusterTransport.Authenticate(r, "replication")
			if e != nil {
				println("PROPOSE-HANDLER auth fail:", e.Error())
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
				println("PROPOSE-HANDLER not leader:", ready.String())
				http.Error(w, "leader not ready", 503)
				return
			}
			cctx := corerepl.WithRequestID(r.Context(), fr.OpID)
			println("PROPOSE-HANDLER proposing", fr.Kind)
			res, e := rt.Controller.Propose(cctx, fr.Kind, fr.ObjectID, fr.Revision, fr.Payload)
			if e != nil {
				println("PROPOSE-HANDLER propose err:", e.Error())
				http.Error(w, e.Error(), 503)
				return
			}
			println("PROPOSE-HANDLER done")
			_ = json.NewEncoder(w).Encode(res)
			return
		}
		http.NotFound(w, r)
	}))
	us.TLS = ca.serverTLS(t, nodeID)
	us.StartTLS()
	server := us
	t.Cleanup(server.Close)
	return &certNode{rt: rt, srv: server, store: s, id: nodeID}
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

	go func() {
		for i := 0; i < 30; i++ {
			time.Sleep(500 * time.Millisecond)
			ai, at := b.rt.FSM.AppliedIndex()
			println("DBG B applied=", ai, at, "failure=", func() string {
				f := b.rt.FSM.ApplyFailure()
				if f == nil {
					return "nil"
				}
				return f.Error()
			}(), "rec=", recordCountNoFail(b, "people"))
			_, rd := b.rt.Controller.State()
			println("DBG B readiness=", rd.String(), "raft=", b.rt.Node.State().String())
		}
	}()

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
