package runtime

import (
	"context"
	"net"
	"strings"
	"testing"

	"github.com/trestle-cv/trestle/internal/store"
)

func freeAddr(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	return ln.Addr().String()
}

// TestNewReplicationRefusesDirtyJoinState enforces the join/bootstrap
// invariant: a node with pre-existing consensus-owned application state but no
// raft history must refuse to start replicated operation rather than risk
// log-replay contamination.
func TestNewReplicationRefusesDirtyJoinState(t *testing.T) {
	dir := t.TempDir()
	s, err := store.Open(context.Background(), dir)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	if _, err := s.DB().Exec("INSERT INTO _trestle_collections(id,name,kind,created_at,updated_at) VALUES('col_x','x','base','2026-01-01T00:00:00Z','2026-01-01T00:00:00Z')"); err != nil {
		t.Fatal(err)
	}
	_, err = NewReplication(context.Background(), ReplicationOptions{
		DB: s.DB(), DataDir: t.TempDir(), NodeID: "tr_dirty", Address: freeAddr(t), Bootstrap: false, Insecure: true,
	})
	if err == nil {
		t.Fatal("expected join refusal for dirty consensus-owned state")
	}
	if !strings.Contains(err.Error(), "join refused") {
		t.Fatalf("unexpected error: %v", err)
	}
}

// TestNewReplicationAllowsCleanJoinAndBootstrap proves a clean first-time node
// joins, a bootstrapping node may retain its own history (which becomes the
// canonical consensus state), and an existing member restart is allowed even
// with populated consensus tables because it retains its own raft history.
func TestNewReplicationAllowsCleanJoinAndBootstrap(t *testing.T) {
	s, err := store.Open(context.Background(), t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	rt, err := NewReplication(context.Background(), ReplicationOptions{
		DB: s.DB(), DataDir: t.TempDir(), NodeID: "tr_clean", Address: freeAddr(t), Bootstrap: false, Insecure: true,
	})
	if err != nil {
		t.Fatalf("clean join refused: %v", err)
	}
	rt.Close()

	s2, err := store.Open(context.Background(), t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer s2.Close()
	if _, err := s2.DB().Exec("INSERT INTO _trestle_collections(id,name,kind,created_at,updated_at) VALUES('col_x','x','base','2026-01-01T00:00:00Z','2026-01-01T00:00:00Z')"); err != nil {
		t.Fatal(err)
	}
	dir2 := t.TempDir()
	rt2, err := NewReplication(context.Background(), ReplicationOptions{
		DB: s2.DB(), DataDir: dir2, NodeID: "tr_boot", Address: freeAddr(t), Bootstrap: true, Insecure: true,
	})
	if err != nil {
		t.Fatalf("bootstrap with history refused: %v", err)
	}
	rt2.Close()

	// Existing member restart: the same store + raft data dir carries durable
	// raft history, so populated consensus tables are allowed (they are this
	// member's own canonical state).
	rt3, err := NewReplication(context.Background(), ReplicationOptions{
		DB: s2.DB(), DataDir: dir2, NodeID: "tr_boot", Address: freeAddr(t), Bootstrap: false, Insecure: true,
	})
	if err != nil {
		t.Fatalf("existing member restart with populated tables refused: %v", err)
	}
	rt3.Close()
}
