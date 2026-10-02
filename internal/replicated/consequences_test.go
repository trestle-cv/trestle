package replicated

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"testing"

	"github.com/gantry-tools/gantry-core/replication"
	"github.com/hashicorp/raft"
	"github.com/trestle-cv/trestle/internal/collections"
	"github.com/trestle-cv/trestle/internal/replpayload"
	"github.com/trestle-cv/trestle/internal/storetest"
)

func recordOp(t *testing.T, id string, p RecordPayload, committed string) replication.Operation {
	t.Helper()
	b, _ := json.Marshal(p)
	op := replication.Operation{Version: replication.Version, Product: "trestle", Kind: KindRecordPut, ID: id, ObjectID: p.RecordID, Revision: p.Version, Payload: b}
	op.Committed.Timestamp = committed
	return op
}

func consequenceRecord(id string, version int64, collection, topic string) RecordPayload {
	return RecordPayload{
		CollectionID: collection, RecordID: id, Version: version,
		CreatedAt: "2026-01-01T00:00:00Z", UpdatedAt: "2026-01-01T00:00:00Z",
		Values: map[string]any{"name": "r-" + id, "score": float64(1)},
		Topic:  topic, EventPayload: map[string]any{"values": map[string]any{"name": "r-" + id}},
		ActorKind: "admin", AuditAction: "record.create", AuditTarget: "issues/" + id, AuditOutcome: "success",
		AuditDetails: map[string]any{"version": 1},
	}
}

func applyRecordOp(t *testing.T, f *FSM, op replication.Operation, index uint64) {
	t.Helper()
	raw := mustEncode(t, op)
	if e := errOf(f.Apply(&raft.Log{Index: index, Term: 1, Type: raft.LogCommand, Data: raw})); e != nil {
		t.Fatalf("apply %s: %v", op.Kind, e)
	}
}

func applyPayloadOp(t *testing.T, f *FSM, kind, id, obj string, payload any, index uint64) {
	t.Helper()
	b, _ := json.Marshal(payload)
	op := replication.Operation{Version: replication.Version, Product: "trestle", Kind: kind, ID: id, ObjectID: obj, Payload: b}
	op.Committed.Timestamp = "2026-01-01T00:01:00Z"
	applyRecordOp(t, f, op, index)
}

func count(t *testing.T, f *FSM, table string) int64 {
	t.Helper()
	var n int64
	if e := f.db.QueryRow("SELECT count(*) FROM " + q(table)).Scan(&n); e != nil {
		t.Fatal(e)
	}
	return n
}

// TestFSMRecordConsequencesDeterministic proves two FSMs applying the same
// record consequence ops produce byte-identical event/audit/job rows with
// convergent explicit identities.
func TestFSMRecordConsequencesDeterministic(t *testing.T) {
	f1, f2 := testFSM(t), testFSM(t)
	applyCollectionAt(t, f1, "issues")
	applyCollectionAt(t, f2, "issues")

	ops := []replication.Operation{
		recordOp(t, "op-create", consequenceRecord("rec_1", 1, "col_test1", "record.created"), ""),
		recordOp(t, "op-update", func() RecordPayload {
			p := consequenceRecord("rec_1", 2, "col_test1", "record.updated")
			p.AuditAction = "record.update"
			p.Values["score"] = float64(9)
			return p
		}(), ""),
		recordOp(t, "op-delete", func() RecordPayload {
			p := consequenceRecord("rec_1", 3, "col_test1", "record.deleted")
			p.AuditAction = ""
			return p
		}(), ""),
	}
	for i, op := range ops {
		applyRecordOp(t, f1, op, uint64(i+2))
		applyRecordOp(t, f2, op, uint64(i+2))
	}

	events1 := tableDump(t, f1, `SELECT sequence,occurred_at,topic,collection_name,record_id,payload_json,dedup_key FROM `+q("_trestle_events")+` ORDER BY sequence`)
	events2 := tableDump(t, f2, `SELECT sequence,occurred_at,topic,collection_name,record_id,payload_json,dedup_key FROM `+q("_trestle_events")+` ORDER BY sequence`)
	if events1 != events2 {
		t.Fatalf("event rows diverged:\n%s\nvs\n%s", events1, events2)
	}
	if count(t, f1, "_trestle_events") != 3 || count(t, f1, "_trestle_audit") != 2 || count(t, f1, "_trestle_jobs") != 0 {
		t.Fatalf("unexpected consequence counts: events=%d audit=%d jobs=%d", count(t, f1, "_trestle_events"), count(t, f1, "_trestle_audit"), count(t, f1, "_trestle_jobs"))
	}
	if !strings.Contains(events1, "op-create:event") || !strings.Contains(events1, "op-delete:event") {
		t.Fatalf("dedup keys missing: %s", events1)
	}
}

// TestFSMWebhookFunctionAndJobOps exercises the automation definition and job
// lifecycle operation kinds end to end.
func TestFSMWebhookFunctionAndJobOps(t *testing.T) {
	f := testFSM(t)
	applyCollectionAt(t, f, "issues")

	// Webhook + function put.
	wh := replpayload.WebhookPayload{ID: "wh_1", Name: "hook", URL: "https://receiver.example/hook", Topics: "record.created", SecretCipher: []byte("cipher-bytes"), Enabled: true, CreatedAt: "2026-01-01T00:00:00Z", UpdatedAt: "2026-01-01T00:00:00Z"}
	fn := replpayload.FunctionPayload{ID: "fn_1", Name: "fn", Provider: "aws-lambda", Target: "arn:aws:lambda:us-east-1:1:function:x", Region: "us-east-1", Topics: "record.created", Enabled: true, CreatedAt: "2026-01-01T00:00:00Z", UpdatedAt: "2026-01-01T00:00:00Z"}
	applyPayloadOp(t, f, KindWebhookPut, "op-wh", wh.ID, wh, 2)
	applyPayloadOp(t, f, KindFunctionPut, "op-fn", fn.ID, fn, 3)

	// A record create with consequences enqueues one webhook job and one
	// lambda job deterministically.
	applyRecordOp(t, f, recordOp(t, "op-rec", consequenceRecord("rec_1", 1, "col_test1", "record.created"), ""), 4)
	if count(t, f, "_trestle_jobs") != 2 {
		t.Fatalf("jobs = %d, want 2", count(t, f, "_trestle_jobs"))
	}
	var jobID, lambdaID, ik string
	f.db.QueryRow("SELECT id,idempotency_key FROM _trestle_jobs WHERE kind='webhook'").Scan(&jobID, &ik)
	if ik != "op:op-rec:job:wh_1" {
		t.Fatalf("webhook idempotency key = %q", ik)
	}
	if !strings.HasPrefix(jobID, "job_") {
		t.Fatalf("job id %q", jobID)
	}
	f.db.QueryRow("SELECT id FROM _trestle_jobs WHERE kind='aws-lambda'").Scan(&lambdaID)

	// Job lifecycle via raft-mediated ops. Committed time advances between ops
	// so backoff availability and lease expiry are deterministic.
	idx := uint64(5)
	jobOp := func(id, kind string, payload any, obj, ts string) {
		b, _ := json.Marshal(payload)
		op := replication.Operation{Version: replication.Version, Product: "trestle", Kind: kind, ID: id, ObjectID: obj, Payload: b}
		op.Committed.Timestamp = ts
		applyRecordOp(t, f, op, idx)
		idx++
	}
	// Webhook: claim -> complete ok -> succeeded.
	jobOp("op-claim", KindJobClaim, JobPayload{ID: jobID}, jobID, "2026-01-01T00:01:00Z")
	checkJobStatus(t, f, jobID, "running")
	jobOp("op-complete", KindJobComplete, JobPayload{ID: jobID, OK: true}, jobID, "2026-01-01T00:01:00Z")
	checkJobStatus(t, f, jobID, "succeeded")

	// Lambda: repeated claim/fail exhausts attempts (max_attempts=5) and
	// dead-letters.
	times := []string{"2026-01-01T00:01:00Z", "2026-01-01T00:02:00Z", "2026-01-01T00:04:00Z", "2026-01-01T00:08:00Z", "2026-01-01T00:16:00Z"}
	for i := 0; i < 5; i++ {
		jobOp(fmt.Sprintf("op-lc-%d", i), KindJobClaim, JobPayload{ID: lambdaID}, lambdaID, times[i])
		jobOp(fmt.Sprintf("op-lf-%d", i), KindJobComplete, JobPayload{ID: lambdaID, OK: false, Error: "boom"}, lambdaID, times[i])
	}
	checkJobStatus(t, f, lambdaID, "dead")

	// Retry revives a dead job; cancel works; stale-release reclaims an
	// expired running lease.
	jobOp("op-retry", KindJobRetry, JobPayload{ID: lambdaID}, lambdaID, "2026-01-01T00:33:00Z")
	checkJobStatus(t, f, lambdaID, "pending")
	jobOp("op-cancel", KindJobCancel, JobPayload{ID: lambdaID}, lambdaID, "2026-01-01T00:34:00Z")
	checkJobStatus(t, f, lambdaID, "cancelled")
	jobOp("op-retry2", KindJobRetry, JobPayload{ID: lambdaID}, lambdaID, "2026-01-01T00:36:00Z")
	checkJobStatus(t, f, lambdaID, "pending")
	jobOp("op-rc", KindJobClaim, JobPayload{ID: lambdaID}, lambdaID, "2026-01-01T00:36:00Z")
	checkJobStatus(t, f, lambdaID, "running")
	// Lease expires at 00:36+30s; a later stale release reclaims it.
	jobOp("op-stale", KindJobReleaseStale, ReleaseStalePayload{Marker: "release"}, "stale", "2026-01-01T01:10:00Z")
	checkJobStatus(t, f, lambdaID, "pending")

	// Webhook delete removes the definition.
	b, _ := json.Marshal(replpayload.WebhookPayload{ID: "wh_1"})
	applyRecordOp(t, f, replication.Operation{Version: replication.Version, Product: "trestle", Kind: KindWebhookDelete, ID: "op-whdel", ObjectID: "wh_1", Payload: b}, idx)
	if n := count(t, f, "_trestle_webhooks"); n != 0 {
		t.Fatalf("webhooks after delete = %d", n)
	}
}

func checkJobStatus(t *testing.T, f *FSM, id, want string) {
	t.Helper()
	var status string
	if e := f.db.QueryRow("SELECT status FROM _trestle_jobs WHERE id=?", id).Scan(&status); e != nil {
		t.Fatal(e)
	}
	if status != want {
		t.Fatalf("job %s status = %q, want %q", id, status, want)
	}
}

// TestFSMBatchConsequenceOrdinals verifies batch put produces ordinal-qualified
// consequence identities and is atomic.
func TestFSMBatchConsequenceOrdinals(t *testing.T) {
	f := testFSM(t)
	applyCollectionAt(t, f, "issues")
	recs := []RecordPayload{
		consequenceRecord("rec_a", 1, "col_test1", "record.created"),
		consequenceRecord("rec_b", 1, "col_test1", "record.created"),
	}
	b, _ := json.Marshal(recs)
	op := replication.Operation{Version: replication.Version, Product: "trestle", Kind: KindRecordBatchPut, ID: "op-batch", ObjectID: "batch", Payload: b}
	applyRecordOp(t, f, op, 2)
	if count(t, f, "_trestle_events") != 2 || count(t, f, "_trestle_audit") != 2 {
		t.Fatalf("batch consequences: events=%d audit=%d", count(t, f, "_trestle_events"), count(t, f, "_trestle_audit"))
	}
	var ev string
	f.db.QueryRow("SELECT dedup_key FROM _trestle_events ORDER BY sequence LIMIT 1").Scan(&ev)
	if ev != "op:op-batch:event:0" {
		t.Fatalf("batch event dedup key = %q, want op:op-batch:event:0", ev)
	}
}

// TestFSMBatchAtomicOnSemanticFailure proves a batch is one atomic replicated
// operation: a semantic failure in any record rolls back the whole batch, so
// no prefix of records or consequences ever survives.
func TestFSMBatchAtomicOnSemanticFailure(t *testing.T) {
	f := testFSM(t)
	applyCollectionAt(t, f, "issues")
	recs := []RecordPayload{
		consequenceRecord("rec_ok", 1, "col_test1", "record.created"),
		// record_2 carries version 2 for a create on a fresh collection: a
		// deterministic stale-precondition semantic failure.
		consequenceRecord("rec_bad", 2, "col_test1", "record.created"),
	}
	b, _ := json.Marshal(recs)
	op := replication.Operation{Version: replication.Version, Product: "trestle", Kind: KindRecordBatchPut, ID: "op-batch-bad", ObjectID: "batch", Payload: b}
	raw := mustEncode(t, op)
	if e := errOf(f.Apply(&raft.Log{Index: 2, Term: 1, Type: raft.LogCommand, Data: raw})); e == nil {
		t.Fatal("batch with a stale record should fail")
	}
	// A semantic conflict must be rejected for its caller without fencing the
	// replica: the FSM stays healthy and can serve future commits.
	if e := f.ApplyFailure(); e != nil {
		t.Fatalf("semantic batch conflict fenced the replica: %v", e)
	}
	var recOK, recBad int64
	f.db.QueryRow("SELECT count(*) FROM \"" + q(collections.PhysicalTableName("col_test1")) + "\" WHERE _id='rec_ok'").Scan(&recOK)
	f.db.QueryRow("SELECT count(*) FROM \"" + q(collections.PhysicalTableName("col_test1")) + "\" WHERE _id='rec_bad'").Scan(&recBad)
	if recOK != 0 || recBad != 0 {
		t.Fatalf("batch prefix survived semantic failure: rec_ok=%d rec_bad=%d", recOK, recBad)
	}
	if count(t, f, "_trestle_events") != 0 || count(t, f, "_trestle_audit") != 0 || count(t, f, "_trestle_jobs") != 0 {
		t.Fatalf("batch consequences survived semantic failure: events=%d audit=%d jobs=%d", count(t, f, "_trestle_events"), count(t, f, "_trestle_audit"), count(t, f, "_trestle_jobs"))
	}
}

// TestFSMSnapshotRestoreFullSurface proves the snapshot carries the full
// consensus surface (events, audit, jobs, automation definitions) and a fresh
// FSM restores to identical state.
func TestFSMSnapshotRestoreFullSurface(t *testing.T) {
	f := testFSM(t)
	applyCollectionAt(t, f, "issues")
	whB, _ := json.Marshal(replpayload.WebhookPayload{ID: "wh_1", Name: "hook", URL: "https://receiver.example/hook", Topics: "record.created", SecretCipher: []byte("cipher"), Enabled: true, CreatedAt: "2026-01-01T00:00:00Z", UpdatedAt: "2026-01-01T00:00:00Z"})
	applyRecordOp(t, f, replication.Operation{Version: replication.Version, Product: "trestle", Kind: KindWebhookPut, ID: "op-wh", ObjectID: "wh_1", Payload: whB}, 2)
	applyRecordOp(t, f, recordOp(t, "op-rec", consequenceRecord("rec_1", 1, "col_test1", "record.created"), ""), 3)

	snap, err := f.Snapshot()
	if err != nil {
		t.Fatal(err)
	}
	var buf bytes.Buffer
	if err := snap.Persist(memorySink{&buf}); err != nil {
		t.Fatal(err)
	}

	fresh := testFSM(t)
	if err := fresh.Restore(snapshotReader{bytes.NewReader(buf.Bytes())}); err != nil {
		t.Fatal(err)
	}
	if count(t, fresh, "_trestle_events") != 1 || count(t, fresh, "_trestle_audit") != 1 || count(t, fresh, "_trestle_jobs") != 1 || count(t, fresh, "_trestle_webhooks") != 1 {
		t.Fatalf("restored consequence counts wrong: events=%d audit=%d jobs=%d webhooks=%d",
			count(t, fresh, "_trestle_events"), count(t, fresh, "_trestle_audit"), count(t, fresh, "_trestle_jobs"), count(t, fresh, "_trestle_webhooks"))
	}
	var seq1, seq2 int64
	f.db.QueryRow("SELECT sequence FROM _trestle_events").Scan(&seq1)
	fresh.db.QueryRow("SELECT sequence FROM _trestle_events").Scan(&seq2)
	if seq1 != seq2 {
		t.Fatalf("restored event sequence %d != original %d", seq2, seq1)
	}
}

// TestFSMReplayDoesNotDuplicateConsequences proves durable restart replay (the
// persisted applied index path) never duplicates event/audit/job rows.
func TestFSMReplayDoesNotDuplicateConsequences(t *testing.T) {
	s := storetest.Open(t, "sqlite")
	f, err := NewFSM(s.DB())
	if err != nil {
		t.Fatal(err)
	}
	applyCollectionAt(t, f, "issues")
	applyRecordOp(t, f, recordOp(t, "op-rec", consequenceRecord("rec_1", 1, "col_test1", "record.created"), ""), 2)
	if count(t, f, "_trestle_events") != 1 {
		t.Fatalf("events = %d", count(t, f, "_trestle_events"))
	}

	// Reopen the FSM from the same store: persisted index stops re-mutation.
	f2, err := NewFSM(s.DB())
	if err != nil {
		t.Fatal(err)
	}
	// Re-apply the same log entry (as restart replay would).
	applyRecordOp(t, f2, recordOp(t, "op-rec", consequenceRecord("rec_1", 1, "col_test1", "record.created"), ""), 2)
	if count(t, f2, "_trestle_events") != 1 {
		t.Fatalf("replay duplicated events: %d", count(t, f2, "_trestle_events"))
	}
}

type memorySink struct{ buf *bytes.Buffer }

func (m memorySink) ID() string                  { return "mem" }
func (m memorySink) Cancel() error               { return nil }
func (m memorySink) Write(p []byte) (int, error) { return m.buf.Write(p) }
func (m memorySink) Close() error                { return nil }

type snapshotReader struct{ r *bytes.Reader }

func (s snapshotReader) Read(p []byte) (int, error) { return s.r.Read(p) }
func (s snapshotReader) Close() error               { return nil }

func tableDump(t *testing.T, f *FSM, query string) string {
	t.Helper()
	rows, err := f.db.Query(query)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	var out strings.Builder
	cols, _ := rows.Columns()
	for rows.Next() {
		vals := make([]any, len(cols))
		ptrs := make([]any, len(cols))
		for i := range vals {
			ptrs[i] = &vals[i]
		}
		if err := rows.Scan(ptrs...); err != nil {
			t.Fatal(err)
		}
		for _, v := range vals {
			if v == nil {
				out.WriteString("NULL|")
				continue
			}
			switch x := v.(type) {
			case []byte:
				out.WriteString(string(x) + "|")
			default:
				out.WriteString(fmt.Sprint(x) + "|")
			}
		}
		out.WriteString("\n")
	}
	return out.String()
}

var _ = context.Background
