package replicated

import (
	"bytes"
	"encoding/json"
	"testing"

	"github.com/gantry-tools/gantry-core/replication"
	"github.com/hashicorp/raft"
	"github.com/trestle-cv/trestle/internal/collections"
	"github.com/trestle-cv/trestle/internal/storetest"
)

func testFSM(t *testing.T) *FSM {
	t.Helper()
	s := storetest.Open(t, "sqlite")
	f, e := NewFSM(s.DB())
	if e != nil {
		t.Fatal(e)
	}
	return f
}

func testCollection(name string) collections.Collection {
	return collections.Collection{
		ID: "col_test1", Name: name, Kind: "base",
		CreatedAt: "2026-01-01T00:00:00Z", UpdatedAt: "2026-01-01T00:00:00Z",
		Fields: []collections.Field{
			{ID: "fld_name", Name: "name", Type: "text"},
			{ID: "fld_score", Name: "score", Type: "number"},
		},
	}
}

func testRecord(id string, version int64, name string, score float64) RecordPayload {
	return RecordPayload{
		CollectionID: "col_test1", RecordID: id, Version: version,
		CreatedAt: "2026-01-01T00:00:00Z", UpdatedAt: "2026-01-01T00:00:00Z",
		Values: map[string]any{"name": name, "score": score},
	}
}

func putOp(id, obj string, rev int64, payload any) replication.Operation {
	b, _ := json.Marshal(payload)
	return replication.Operation{Version: replication.Version, Product: "trestle", Kind: KindRecordPut, ID: id, ObjectID: obj, Revision: rev, Payload: b}
}

func collectionOp(id string, c collections.Collection) (replication.Operation, error) {
	b, _ := json.Marshal(c)
	return replication.Operation{Version: replication.Version, Product: "trestle", Kind: KindCollectionPut, ID: id, ObjectID: c.Name, Payload: b}, nil
}

func applyCollectionAt(t *testing.T, f *FSM, name string) {
	t.Helper()
	co, _ := collectionOp("col-"+name, testCollection(name))
	idx, _ := f.AppliedIndex()
	if e := errOf(f.Apply(&raft.Log{Index: idx + 1, Term: 1, Type: raft.LogCommand, Data: mustEncode(t, co)})); e != nil {
		t.Fatalf("collection apply failed: %v", e)
	}
}

func mustEncode(t *testing.T, op replication.Operation) []byte {
	t.Helper()
	raw, e := op.Encode()
	if e != nil {
		t.Fatal(e)
	}
	return raw
}

func applyLog(t *testing.T, f *FSM, index, term uint64, op replication.Operation) interface{} {
	t.Helper()
	raw, e := op.Encode()
	if e != nil {
		t.Fatal(e)
	}
	return f.Apply(&raft.Log{Index: index, Term: term, Type: raft.LogCommand, Data: raw})
}

// TestFSMRecordVersionPreconditions proves stale record updates/creates fail
// closed instead of silently overwriting a newer version.
func TestFSMRecordVersionPreconditions(t *testing.T) {
	f := testFSM(t)
	applyCollectionAt(t, f, "people")
	if e := errOf(applyLog(t, f, 2, 1, putOp("op-c1", "r1", 1, testRecord("r1", 1, "A", 1)))); e != nil {
		t.Fatalf("create failed: %v", e)
	}
	if e := errOf(applyLog(t, f, 3, 1, putOp("op-u1", "r1", 2, testRecord("r1", 2, "B", 2)))); e != nil {
		t.Fatalf("update failed: %v", e)
	}
	// Stale update: op claims version 2 (expects current 1) but current is 2.
	if errOf(applyLog(t, f, 4, 1, putOp("op-stale", "r1", 2, testRecord("r1", 2, "C", 3)))) == nil {
		t.Fatal("stale record update must fail closed")
	}
	// A stale update is a caller conflict, not replica corruption: the op is
	// rejected but the replica must stay healthy and keep applying commits.
	if f.ApplyFailure() != nil {
		t.Fatal("stale update must not poison the replica")
	}
	if e := errOf(applyLog(t, f, 5, 1, putOp("op-next", "r1", 3, testRecord("r1", 3, "D", 4)))); e != nil {
		t.Fatalf("replica must continue applying commits after a rejected stale update: %v", e)
	}
	// Create collision.
	f2 := testFSM(t)
	applyCollectionAt(t, f2, "people")
	if e := errOf(applyLog(t, f2, 2, 1, putOp("op-c1", "r1", 1, testRecord("r1", 1, "A", 1)))); e != nil {
		t.Fatal(e)
	}
	if errOf(applyLog(t, f2, 3, 1, putOp("op-dup", "r1", 1, testRecord("r1", 1, "A", 1)))) == nil {
		t.Fatal("duplicate create must fail closed")
	}
	if f2.ApplyFailure() != nil {
		t.Fatal("duplicate create must not poison the replica")
	}
}

// TestFSMCollectionConflictDoesNotFence proves a duplicate collection name
// committed under a different id is rejected for the operation without
// poisoning the replica (a racing duplicate create is a caller conflict, not
// replica corruption).
func TestFSMCollectionConflictDoesNotFence(t *testing.T) {
	f := testFSM(t)
	applyCollectionAt(t, f, "people")
	coll := testCollection("people")
	coll.ID = "col_different"
	coll.CreatedAt = "2026-01-01T00:00:00Z"
	coll.UpdatedAt = "2026-01-01T00:00:00Z"
	conflict, _ := collectionOp("op-c2", coll)
	if e := errOf(applyLog(t, f, 2, 1, conflict)); e == nil {
		t.Fatal("duplicate collection name with a different id must fail closed")
	}
	if f.ApplyFailure() != nil {
		t.Fatal("collection conflict must not poison the replica")
	}
	// The replica must keep applying subsequent commits.
	orders := testCollection("orders")
	orders.ID = "col_orders"
	orders.Fields = []collections.Field{
		{ID: "fld_o_name", Name: "name", Type: "text"},
		{ID: "fld_o_total", Name: "total", Type: "number"},
	}
	ordersOp, _ := collectionOp("col-op-orders", orders)
	if e := errOf(applyLog(t, f, 3, 1, ordersOp)); e != nil {
		t.Fatalf("replica must keep applying commits after a rejected collection conflict: %v", e)
	}
	if f.ApplyFailure() != nil {
		t.Fatal("replica must stay healthy after a rejected collection conflict")
	}
}

// TestFSMDurableRestartNoDoubleApply proves restart reconstruction from the
// durable meta does not re-mutate already-materialized committed state.
func TestFSMDurableRestartNoDoubleApply(t *testing.T) {
	s := storetest.Open(t, "sqlite")
	f, e := NewFSM(s.DB())
	if e != nil {
		t.Fatal(e)
	}
	applyCollectionAt(t, f, "people")
	applyLog(t, f, 2, 1, putOp("op-1", "r1", 1, testRecord("r1", 1, "A", 1)))
	applyLog(t, f, 3, 1, putOp("op-2", "r1", 2, testRecord("r1", 2, "B", 2)))

	f2, e := NewFSM(s.DB())
	if e != nil {
		t.Fatal(e)
	}
	idx, _ := f2.AppliedIndex()
	if idx != 3 {
		t.Fatalf("applied index not reconstructed: %d", idx)
	}
	if _, ok := f2.OpKnown("op-1"); !ok {
		t.Fatal("durable op-ID knowledge not reconstructed")
	}
	// Replay at/below the persisted index records op-ID idempotency only.
	co, _ := collectionOp("col-people", testCollection("people"))
	applyLog(t, f2, 1, 1, co)
	applyLog(t, f2, 2, 1, putOp("op-1", "r1", 1, testRecord("r1", 1, "A", 1)))
	applyLog(t, f2, 3, 1, putOp("op-2", "r1", 2, testRecord("r1", 2, "B", 2)))
	var n int
	if e := s.DB().QueryRow(`SELECT COUNT(*) FROM _trestle_collections`).Scan(&n); e != nil || n != 1 {
		t.Fatalf("replay double-mutated or lost state: n=%d e=%v", n, e)
	}
}

// TestFSMSnapshotRestore proves the raft snapshot captures and restores the
// full consensus-owned state.
func TestFSMSnapshotRestore(t *testing.T) {
	f := testFSM(t)
	co, _ := collectionOp("op-col", testCollection("people"))
	applyLog(t, f, 1, 1, co)
	applyLog(t, f, 2, 1, putOp("op-r1", "r1", 1, testRecord("r1", 1, "A", 1)))

	snap, e := f.Snapshot()
	if e != nil {
		t.Fatal(e)
	}
	var buf bytes.Buffer
	if e := snap.(*snapshot).Persist(&memSink{buf: &buf}); e != nil {
		t.Fatal(e)
	}
	f2 := testFSM(t)
	if e := f2.Restore(&readerCloser{bytes.NewReader(buf.Bytes())}); e != nil {
		t.Fatalf("restore: %v", e)
	}
	idx, _ := f2.AppliedIndex()
	if idx != 2 {
		t.Fatalf("restored index=%d want 2", idx)
	}
	var n int
	if e := f2.db.QueryRow(`SELECT COUNT(*) FROM _trestle_collections WHERE name='people'`).Scan(&n); e != nil || n != 1 {
		t.Fatalf("restored collection missing: n=%d e=%v", n, e)
	}
	var rn int
	if e := f2.db.QueryRow(`SELECT COUNT(*) FROM ` + q(collections.PhysicalTableName("col_test1"))).Scan(&rn); e != nil || rn != 1 {
		t.Fatalf("restored record missing: rn=%d e=%v", rn, e)
	}
}

// TestFSMApplyFailureFences proves a committed apply failure poisons the FSM
// and fences every later committed entry.
func TestFSMApplyFailureFences(t *testing.T) {
	f := testFSM(t)
	bad := replication.Operation{Version: replication.Version, Product: "trestle", Kind: "trestle.bogus", ID: "op-bad", ObjectID: "x", Payload: json.RawMessage(`{}`)}
	raw, _ := bad.Encode()
	if v := f.Apply(&raft.Log{Index: 1, Term: 1, Type: raft.LogCommand, Data: raw}); v == nil {
		t.Fatal("unsupported committed operation must fail")
	}
	if f.ApplyFailure() == nil {
		t.Fatal("must be poisoned")
	}
	applyLog(t, f, 2, 1, putOp("op-later", "r1", 1, testRecord("r1", 1, "A", 1)))
	var n int
	if e := f.db.QueryRow(`SELECT COUNT(*) FROM _trestle_collections`).Scan(&n); e != nil || n != 0 {
		t.Fatalf("fenced later entry materialized state: n=%d", n)
	}
}

// TestFSMOpIDDedup proves same-ID/same-payload returns the prior result and
// same-ID/different-payload is an idempotency conflict (not a health failure).
func TestFSMOpIDDedup(t *testing.T) {
	f := testFSM(t)
	applyCollectionAt(t, f, "people")
	applyLog(t, f, 2, 1, putOp("op-same", "r1", 1, testRecord("r1", 1, "A", 1)))
	if v := applyLog(t, f, 3, 1, putOp("op-same", "r1", 1, testRecord("r1", 1, "A", 1))); v == nil {
		t.Fatal("same-ID same-payload retry must return the committed result")
	}
	if v := applyLog(t, f, 4, 1, putOp("op-same", "r1", 1, testRecord("r1", 1, "Z", 9))); v == nil {
		t.Fatal("same-ID different-payload must be rejected")
	}
	if f.ApplyFailure() != nil {
		t.Fatal("idempotency conflict must not poison the replica")
	}
}

func errOf(v interface{}) error {
	if e, ok := v.(error); ok {
		return e
	}
	return nil
}

func must2(t *testing.T, op replication.Operation, e error) replication.Operation {
	t.Helper()
	if e != nil {
		t.Fatal(e)
	}
	return op
}

type memSink struct{ buf *bytes.Buffer }

func (m *memSink) Write(p []byte) (int, error) { return m.buf.Write(p) }
func (m *memSink) Close() error                { return nil }
func (m *memSink) Cancel() error               { return nil }
func (m *memSink) ID() string                  { return "mem" }

type readerCloser struct{ *bytes.Reader }

func (r *readerCloser) Close() error { return nil }

// TestFSMIdempotencyMappingIsConsensusOwned proves a create's caller idempotency
// key is materialized into the replicated idempotency table so a retry on any
// node can replay the original result instead of re-proposing a fresh record id.
func TestFSMIdempotencyMappingIsConsensusOwned(t *testing.T) {
	f := testFSM(t)
	applyCollectionAt(t, f, "people")
	rec := testRecord("r1", 1, "A", 1)
	rec.IdempotencyKey = "create-cust-1"
	if e := errOf(applyLog(t, f, 2, 1, putOp("op-idem", "r1", 1, rec))); e != nil {
		t.Fatalf("create with idempotency key failed: %v", e)
	}
	var key string
	if e := f.db.QueryRow(`SELECT idempotency_key FROM _trestle_record_idempotency WHERE collection_id='col_test1' AND record_id='r1'`).Scan(&key); e != nil || key != "create-cust-1" {
		t.Fatalf("idempotency mapping not materialized: %q err=%v", key, e)
	}
	// Deleting the record removes the mapping so the key can be reused later.
	del := testRecord("r1", 1, "A", 1)
	if e := errOf(applyLog(t, f, 3, 1, deleteOp("op-del", del))); e != nil {
		t.Fatalf("delete failed: %v", e)
	}
	var n int
	if e := f.db.QueryRow(`SELECT COUNT(*) FROM _trestle_record_idempotency WHERE record_id='r1'`).Scan(&n); e != nil || n != 0 {
		t.Fatalf("idempotency mapping not removed on delete: n=%d", n)
	}
}

func deleteOp(id string, p RecordPayload) replication.Operation {
	b, _ := json.Marshal(p)
	return replication.Operation{Version: replication.Version, Product: "trestle", Kind: KindRecordDelete, ID: id, ObjectID: p.RecordID, Revision: p.Version, Payload: b}
}
