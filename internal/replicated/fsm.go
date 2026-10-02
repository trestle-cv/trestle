package replicated

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/gantry-tools/gantry-core/replication"
	"github.com/hashicorp/raft"
	"github.com/trestle-cv/trestle/internal/collections"
	"github.com/trestle-cv/trestle/internal/replerr"
	"github.com/trestle-cv/trestle/internal/replpayload"
	"github.com/trestle-cv/trestle/internal/store"
)

const (
	KindCollectionPut    = "trestle.collection.put"
	KindCollectionDelete = "trestle.collection.delete"
	KindRecordPut        = "trestle.record.put"
	KindRecordDelete     = "trestle.record.delete"
	KindRecordBatchPut   = "trestle.record.batch_put"
	KindWebhookPut       = "trestle.webhook.put"
	KindWebhookDelete    = "trestle.webhook.delete"
	KindFunctionPut      = "trestle.function.put"
	KindFunctionDelete   = "trestle.function.delete"
	KindJobClaim         = "trestle.job.claim"
	KindJobComplete      = "trestle.job.complete"
	KindJobReleaseStale  = "trestle.job.release_stale"
	KindJobCancel        = "trestle.job.cancel"
	KindJobRetry         = "trestle.job.retry"

	metaTable  = "_trestle_replicated_meta"
	metaIndex  = "applied_index"
	metaTerm   = "applied_term"
	metaOpKey  = "op:"
	snapFormat = 2
)

var (
	// ErrCollectionConflict reports a deterministic per-operation caller
	// conflict: a collection name committed under two different IDs (a racing
	// duplicate create). The operation is rejected for its caller; it is not
	// replica corruption.
	ErrCollectionConflict = replerr.ErrCollectionConflict
	// ErrStalePrecondition reports a deterministic per-operation caller
	// conflict: a record create/update/delete carrying a stale version. The
	// operation is rejected for its caller; it is not replica corruption.
	ErrStalePrecondition = replerr.ErrStalePrecondition
)

// semanticConflict reports whether e is a deterministic per-operation caller
// conflict. Such an operation is rejected and returned to its caller, but it
// must NOT fence the replica: committed-apply health is a corruption signal,
// not a client-error signal. A stale update or a duplicate collection name is
// the caller's mistake and must leave the replica able to serve future commits.
func semanticConflict(e error) bool {
	return replerr.IsSemanticConflict(e)
}

// RecordPayload is the consensus-owned record mutation. It carries every piece
// of durable consequence state (event topic/payload, audit fields) resolved at
// proposal time so each replica materializes byte-identical consequences.
type RecordPayload struct {
	CollectionID string         `json:"collection_id"`
	RecordID     string         `json:"record_id"`
	Version      int64          `json:"version"`
	CreatedAt    string         `json:"created_at"`
	UpdatedAt    string         `json:"updated_at"`
	Values       map[string]any `json:"values"`
	// IdempotencyKey is the caller-provided key recorded at create time. It is
	// consensus-owned so any node can replay the original result for a retry
	// instead of re-proposing (which would build a new record id and trip the
	// operation-id digest conflict).
	IdempotencyKey string `json:"idempotency_key,omitempty"`
	// Event/audit consequence inputs. Topic is empty for mutations that carry
	// no durable consequence (snapshot record restore). Audit fields are empty
	// for delete (delete emits an event and automation jobs but no audit,
	// matching the standalone handler).
	Topic          string         `json:"topic,omitempty"`
	EventPayload   map[string]any `json:"event_payload,omitempty"`
	ActorKind      string         `json:"actor_kind,omitempty"`
	ActorID        string         `json:"actor_id,omitempty"`
	AuditAction    string         `json:"audit_action,omitempty"`
	AuditTarget    string         `json:"audit_target,omitempty"`
	AuditOutcome   string         `json:"audit_outcome,omitempty"`
	AuditRequestID string         `json:"audit_request_id,omitempty"`
	AuditDetails   map[string]any `json:"audit_details,omitempty"`
}

// JobPayload carries a raft-mediated job lifecycle transition. External
// execution never enters the FSM; only durable state transitions do.
type JobPayload struct {
	ID    string `json:"id"`
	OK    bool   `json:"ok,omitempty"`
	Error string `json:"error,omitempty"`
}

// ReleaseStalePayload is a non-empty marker so a `release_stale` operation has
// a valid payload (the operation contract requires one).
type ReleaseStalePayload struct {
	Marker string `json:"marker"`
}

// FSM deterministically materializes consensus-owned Trestle collection
// definitions, records, durable events/audit, job obligations and automation
// definitions. Each committed apply is transactional: the product mutation,
// the durable consequences, the applied index/term and the durable operation-ID
// digest advance together (or not at all).
type FSM struct {
	mu             sync.Mutex
	db             store.Executor
	applied        map[string]string
	index          uint64
	term           uint64
	persistedIndex uint64
	failure        error
}

func NewFSM(db store.Executor) (*FSM, error) {
	f := &FSM{db: db, applied: map[string]string{}}
	if _, e := db.Exec(`CREATE TABLE IF NOT EXISTS ` + metaTable + `(k TEXT PRIMARY KEY,v TEXT)`); e != nil {
		return nil, e
	}
	// Reconstruct the durable applied position and operation-ID knowledge so a
	// restart does not re-mutate already-materialized committed state.
	if v, ok, e := metaGet(db, metaIndex); e != nil {
		return nil, e
	} else if ok {
		f.persistedIndex = v
		f.index = v
	}
	if v, ok, e := metaGet(db, metaTerm); e != nil {
		return nil, e
	} else if ok {
		f.term = v
	}
	rows, e := db.Query(`SELECT k,v FROM ` + metaTable + ` WHERE k LIKE '` + metaOpKey + `%'`)
	if e != nil {
		return nil, e
	}
	defer rows.Close()
	for rows.Next() {
		var k, v string
		if e := rows.Scan(&k, &v); e != nil {
			return nil, e
		}
		f.applied[trimPrefix(k, metaOpKey)] = v
	}
	return f, rows.Err()
}

func (f *FSM) OpKnown(id string) (string, bool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	v, ok := f.applied[id]
	return v, ok
}
func (f *FSM) AppliedIndex() (uint64, uint64) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.index, f.term
}
func (f *FSM) ApplyFailure() error { f.mu.Lock(); defer f.mu.Unlock(); return f.failure }

func (f *FSM) Apply(l *raft.Log) interface{} {
	op, e := replication.DecodeOperation(l.Data)
	if e != nil {
		f.setFailure(fmt.Errorf("corrupt committed entry at index %d: %w", l.Index, e))
		return e
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.failure != nil {
		return f.failure
	}
	digest, e := op.Digest()
	if e != nil {
		f.setFailure(e)
		return e
	}
	if d, ok := f.applied[op.ID]; ok {
		if d != digest {
			// Durable idempotency conflict: the identity was already applied
			// with different semantic bytes. This is a caller conflict, not a
			// replica-health failure.
			return errors.New("operation id reused with different payload")
		}
		// The committed entry WAS applied (as a durable dedup): advance the
		// applied position (and the durable applied index) so follower
		// wait-for-local-apply and restart recovery track the raft position.
		f.index, f.term = l.Index, l.Term
		if l.Index > f.persistedIndex {
			_, _ = f.db.Exec(`INSERT INTO `+metaTable+`(k,v) VALUES(?,?) ON CONFLICT(k) DO UPDATE SET v=excluded.v`, metaIndex, fmt.Sprint(l.Index))
			_, _ = f.db.Exec(`INSERT INTO `+metaTable+`(k,v) VALUES(?,?) ON CONFLICT(k) DO UPDATE SET v=excluded.v`, metaTerm, fmt.Sprint(l.Term))
		}
		return &replication.ApplyResult{Index: l.Index, Term: l.Term, ObjectID: op.ObjectID, OpID: op.ID, Kind: op.Kind, Revision: op.Revision}
	}
	// Durable restart replays the whole log. Entries at or below the persisted
	// applied index are already materialized: record durable op-ID idempotency
	// without re-mutating product state.
	if l.Index <= f.persistedIndex {
		f.applied[op.ID] = digest
		f.index, f.term = l.Index, l.Term
		return &replication.ApplyResult{Index: l.Index, Term: l.Term, ObjectID: op.ObjectID, OpID: op.ID, Kind: op.Kind, Revision: op.Revision}
	}

	ctx := context.Background()
	if e := f.materialize(ctx, op, digest, l.Index, l.Term); e != nil {
		if semanticConflict(e) {
			return e
		}
		log.Printf("trestle replication FSM apply failure at index %d op %s kind %s obj %s: %v", l.Index, op.ID, op.Kind, op.ObjectID, e)
		f.setFailure(e)
		return e
	}
	return &replication.ApplyResult{Index: l.Index, Term: l.Term, ObjectID: op.ObjectID, OpID: op.ID, Kind: op.Kind, Revision: op.Revision}
}

// materialize applies one committed operation atomically (product mutation +
// durable consequences + durable op-ID + applied index/term in one transaction).
func (f *FSM) materialize(ctx context.Context, op replication.Operation, digest string, index, term uint64) error {
	tx, e := f.db.BeginTx(ctx, nil)
	if e != nil {
		return e
	}
	defer tx.Rollback()
	dialect := f.db.Dialect()
	now := op.Committed.Timestamp
	switch op.Kind {
	case KindCollectionPut:
		var d collections.Collection
		if e := json.Unmarshal(op.Payload, &d); e != nil {
			return fmt.Errorf("invalid collection payload: %w", e)
		}
		if e := applyCollection(ctx, tx, dialect, d); e != nil {
			return e
		}
	case KindCollectionDelete:
		if e := deleteCollection(ctx, tx, op.ObjectID); e != nil {
			return e
		}
	case KindRecordPut:
		var p RecordPayload
		if e := json.Unmarshal(op.Payload, &p); e != nil {
			return fmt.Errorf("invalid record payload: %w", e)
		}
		if e := applyRecordPut(ctx, tx, dialect, p, op.ID, -1); e != nil {
			return e
		}
	case KindRecordDelete:
		var p RecordPayload
		if e := json.Unmarshal(op.Payload, &p); e != nil {
			return fmt.Errorf("invalid record payload: %w", e)
		}
		if e := applyRecordDelete(ctx, tx, dialect, p, op.ID, -1); e != nil {
			return e
		}
	case KindRecordBatchPut:
		var ps []RecordPayload
		if e := json.Unmarshal(op.Payload, &ps); e != nil {
			return fmt.Errorf("invalid batch payload: %w", e)
		}
		for i := range ps {
			if e := applyRecordPut(ctx, tx, dialect, ps[i], op.ID, i); e != nil {
				return e
			}
		}
	case KindWebhookPut:
		var w replpayload.WebhookPayload
		if e := json.Unmarshal(op.Payload, &w); e != nil {
			return fmt.Errorf("invalid webhook payload: %w", e)
		}
		if e := applyWebhookPut(ctx, tx, dialect, w); e != nil {
			return e
		}
	case KindWebhookDelete:
		if e := deleteWebhook(ctx, tx, op.ObjectID); e != nil {
			return e
		}
	case KindFunctionPut:
		var fn replpayload.FunctionPayload
		if e := json.Unmarshal(op.Payload, &fn); e != nil {
			return fmt.Errorf("invalid function payload: %w", e)
		}
		if e := applyFunctionPut(ctx, tx, dialect, fn); e != nil {
			return e
		}
	case KindFunctionDelete:
		if e := deleteFunction(ctx, tx, op.ObjectID); e != nil {
			return e
		}
	case KindJobClaim:
		var j JobPayload
		if e := json.Unmarshal(op.Payload, &j); e != nil {
			return fmt.Errorf("invalid job payload: %w", e)
		}
		if e := applyJobClaim(ctx, tx, j.ID, now); e != nil {
			return e
		}
	case KindJobComplete:
		var j JobPayload
		if e := json.Unmarshal(op.Payload, &j); e != nil {
			return fmt.Errorf("invalid job payload: %w", e)
		}
		if e := applyJobComplete(ctx, tx, j.ID, j.OK, j.Error, now); e != nil {
			return e
		}
	case KindJobReleaseStale:
		if e := applyJobReleaseStale(ctx, tx, now); e != nil {
			return e
		}
	case KindJobCancel:
		var j JobPayload
		if e := json.Unmarshal(op.Payload, &j); e != nil {
			return fmt.Errorf("invalid job payload: %w", e)
		}
		if e := applyJobCancel(ctx, tx, j.ID, now); e != nil {
			return e
		}
	case KindJobRetry:
		var j JobPayload
		if e := json.Unmarshal(op.Payload, &j); e != nil {
			return fmt.Errorf("invalid job payload: %w", e)
		}
		if e := applyJobRetry(ctx, tx, j.ID, now); e != nil {
			return e
		}
	default:
		return fmt.Errorf("unsupported trestle replicated operation %q", op.Kind)
	}
	if e := metaPut(tx, metaIndex, index); e != nil {
		return e
	}
	if e := metaPut(tx, metaTerm, term); e != nil {
		return e
	}
	if _, e := tx.ExecContext(ctx, `INSERT INTO `+metaTable+`(k,v) VALUES(?,?) ON CONFLICT(k) DO UPDATE SET v=excluded.v`, metaOpKey+op.ID, digest); e != nil {
		return e
	}
	if e := tx.Commit(); e != nil {
		return e
	}
	f.applied[op.ID] = digest
	f.index, f.term = index, term
	return nil
}

// applyRecordPut deterministically materializes a record create/update plus its
// durable consequences (event, audit, matched job obligations) in the same
// transaction. ordinal < 0 selects the single-record consequence identity
// scheme; ordinal >= 0 selects the batch ordinal scheme.
func applyRecordPut(ctx context.Context, tx store.Transaction, dialect store.Dialect, p RecordPayload, opID string, ordinal int) error {
	if e := putRecord(ctx, tx, dialect, p); e != nil {
		return e
	}
	return emitRecordConsequences(ctx, tx, dialect, p, opID, ordinal)
}

// applyRecordDelete deterministically materializes a record delete plus its
// durable consequences (record.deleted event and matched jobs; delete emits no
// audit, matching the standalone handler).
func applyRecordDelete(ctx context.Context, tx store.Transaction, dialect store.Dialect, p RecordPayload, opID string, ordinal int) error {
	if e := deleteRecord(ctx, tx, p); e != nil {
		return e
	}
	return emitRecordConsequences(ctx, tx, dialect, p, opID, ordinal)
}

func emitRecordConsequences(ctx context.Context, tx store.Transaction, dialect store.Dialect, p RecordPayload, opID string, ordinal int) error {
	if p.Topic == "" {
		return nil
	}
	name, e := collectionName(ctx, tx, p.CollectionID)
	if e != nil {
		return e
	}
	occurred := p.UpdatedAt
	if p.Version == 1 {
		occurred = p.CreatedAt
	}
	if e := emitEvent(ctx, tx, p.Topic, name, p.RecordID, p.EventPayload, occurred, seqKey(opID, "event", ordinal)); e != nil {
		return e
	}
	if p.AuditAction != "" {
		if e := emitAudit(ctx, tx, p.ActorKind, p.ActorID, p.AuditAction, p.AuditTarget, p.AuditOutcome, p.AuditRequestID, p.AuditDetails, occurred, seqKey(opID, "audit", ordinal)); e != nil {
			return e
		}
	}
	base := "op:" + opID + ":job"
	if ordinal >= 0 {
		base += ":" + strconv.Itoa(ordinal)
	}
	return enqueueJobs(ctx, tx, dialect, p.Topic, name, p.RecordID, p.EventPayload, occurred, base)
}

func emitEvent(ctx context.Context, tx store.Transaction, topic, collectionName, recordID string, payload any, occurredAt, dedupKey string) error {
	b, e := json.Marshal(payload)
	if e != nil {
		return e
	}
	var seq int64
	if e := tx.QueryRowContext(ctx, `SELECT COALESCE(MAX(sequence),0)+1 FROM `+q("_trestle_events")).Scan(&seq); e != nil {
		return e
	}
	_, e = tx.ExecContext(ctx, `INSERT INTO `+q("_trestle_events")+`(sequence,occurred_at,topic,collection_name,record_id,payload_json,dedup_key) VALUES(?,?,?,?,?,?,?) ON CONFLICT(dedup_key) DO NOTHING`,
		seq, occurredAt, topic, nullable(collectionName), nullable(recordID), string(b), dedupKey)
	return e
}

func emitAudit(ctx context.Context, tx store.Transaction, actorKind, actorID, action, target, outcome, requestID string, details any, occurredAt, dedupKey string) error {
	b, e := json.Marshal(details)
	if e != nil {
		return e
	}
	var id int64
	if e := tx.QueryRowContext(ctx, `SELECT COALESCE(MAX(id),0)+1 FROM `+q("_trestle_audit")).Scan(&id); e != nil {
		return e
	}
	_, e = tx.ExecContext(ctx, `INSERT INTO `+q("_trestle_audit")+`(id,occurred_at,actor_kind,actor_id,action,target,outcome,request_id,details_json,dedup_key) VALUES(?,?,?,?,?,?,?,?,?,?) ON CONFLICT(dedup_key) DO NOTHING`,
		id, occurredAt, actorKind, nullable(actorID), action, nullable(target), outcome, nullable(requestID), string(b), dedupKey)
	return e
}

// enqueueJobs deterministically maps a committed event to the enabled webhook
// and function definitions whose topic lists match, enqueuing one durable job
// per target with a deterministic identity.
func enqueueJobs(ctx context.Context, tx store.Transaction, dialect store.Dialect, topic, collectionName, recordID string, payload any, occurredAt, jobBase string) error {
	rows, e := tx.QueryContext(ctx, `SELECT id,topics FROM `+q("_trestle_webhooks")+` WHERE enabled=?`, dialect.Boolean(true))
	if e != nil {
		return e
	}
	for rows.Next() {
		var id, topics string
		if e := rows.Scan(&id, &topics); e != nil {
			rows.Close()
			return e
		}
		if !containsTopic(topics, topic) {
			continue
		}
		delivery := map[string]any{
			"targetId":   id,
			"topic":      topic,
			"collection": collectionName,
			"recordId":   recordID,
			"payload":    payload,
			"deliveryId": "del_" + deterministicHex(jobBase+":"+id+":delivery", 9),
		}
		if e := enqueueJob(ctx, tx, "webhook", delivery, jobBase+":"+id, occurredAt); e != nil {
			rows.Close()
			return e
		}
	}
	rows.Close()
	if e := rows.Err(); e != nil {
		return e
	}
	rows, e = tx.QueryContext(ctx, `SELECT id,topics FROM `+q("_trestle_functions")+` WHERE enabled=?`, dialect.Boolean(true))
	if e != nil {
		return e
	}
	for rows.Next() {
		var id, topics string
		if e := rows.Scan(&id, &topics); e != nil {
			rows.Close()
			return e
		}
		if !containsTopic(topics, topic) {
			continue
		}
		invocation := map[string]any{
			"TargetID":     id,
			"Topic":        topic,
			"Collection":   collectionName,
			"RecordID":     recordID,
			"Payload":      payload,
			"InvocationID": "inv_" + deterministicHex(jobBase+":"+id+":invocation", 9),
		}
		if e := enqueueJob(ctx, tx, "aws-lambda", invocation, jobBase+":"+id, occurredAt); e != nil {
			rows.Close()
			return e
		}
	}
	rows.Close()
	return rows.Err()
}

func enqueueJob(ctx context.Context, tx store.Transaction, kind string, payload any, idempotencyKey, occurredAt string) error {
	b, e := json.Marshal(payload)
	if e != nil {
		return e
	}
	id := "job_" + deterministicHex(idempotencyKey, 12)
	_, e = tx.ExecContext(ctx, `INSERT INTO `+q("_trestle_jobs")+`(id,kind,payload_json,status,available_at,idempotency_key,created_at,updated_at) VALUES(?,?,?,'pending',?,?,?,?) ON CONFLICT(idempotency_key) DO NOTHING`,
		id, kind, string(b), occurredAt, idempotencyKey, occurredAt, occurredAt)
	return e
}

func collectionName(ctx context.Context, tx store.Transaction, collectionID string) (string, error) {
	var name string
	err := tx.QueryRowContext(ctx, `SELECT name FROM `+q("_trestle_collections")+` WHERE id=?`, collectionID).Scan(&name)
	return name, err
}

// applyCollection deterministically materializes a collection definition
// supplied by consensus (IDs and timestamps are part of the committed payload).
func applyCollection(ctx context.Context, tx store.Transaction, dialect store.Dialect, def collections.Collection) error {
	if def.ID == "" || def.Name == "" || def.CreatedAt == "" || def.UpdatedAt == "" {
		return fmt.Errorf("replicated collection definition is incomplete")
	}
	for _, f := range def.Fields {
		if f.ID == "" {
			return fmt.Errorf("replicated field id is required")
		}
	}
	var beforeID string
	var beforeFields []collections.Field
	err := tx.QueryRowContext(ctx, `SELECT id FROM `+q("_trestle_collections")+` WHERE name=?`, def.Name).Scan(&beforeID)
	if errors.Is(err, sql.ErrNoRows) {
		if _, e := tx.ExecContext(ctx, `INSERT INTO `+q("_trestle_collections")+`(id,name,kind,created_at,updated_at) VALUES(?,?,?,?,?)`, def.ID, def.Name, def.Kind, def.CreatedAt, def.UpdatedAt); e != nil {
			return e
		}
		if e := insertFields(ctx, tx, dialect, def.ID, def.CreatedAt, def.Fields); e != nil {
			return e
		}
		if e := collections.CreatePhysicalTx(ctx, tx, dialect, def.ID, def.Fields); e != nil {
			return e
		}
		return nil
	}
	if err != nil {
		return err
	}
	if beforeID != def.ID {
		return fmt.Errorf("%w: collection %q already exists under id %s", ErrCollectionConflict, def.Name, beforeID)
	}
	beforeFields, err = loadFields(ctx, tx, def.ID)
	if err != nil {
		return err
	}
	if _, e := tx.ExecContext(ctx, `UPDATE `+q("_trestle_collections")+` SET name=?,kind=?,updated_at=? WHERE id=?`, def.Name, def.Kind, def.UpdatedAt, def.ID); e != nil {
		return e
	}
	if _, e := tx.ExecContext(ctx, `DELETE FROM `+q("_trestle_fields")+` WHERE collection_id=?`, def.ID); e != nil {
		return e
	}
	if e := insertFields(ctx, tx, dialect, def.ID, def.UpdatedAt, def.Fields); e != nil {
		return e
	}
	if e := collections.RebuildPhysicalTx(ctx, tx, dialect, def.ID, beforeFields, def.Fields); e != nil {
		return e
	}
	return nil
}

func insertFields(ctx context.Context, tx store.Transaction, dialect store.Dialect, collectionID, now string, fields []collections.Field) error {
	for i, f := range fields {
		var def any
		if len(f.Default) > 0 {
			def = string(f.Default)
		}
		if _, e := tx.ExecContext(ctx, `INSERT INTO `+q("_trestle_fields")+`(id,collection_id,position,name,type,required,is_unique,default_json,created_at) VALUES(?,?,?,?,?,?,?,?,?)`,
			f.ID, collectionID, i, f.Name, f.Type, dialect.Boolean(f.Required), dialect.Boolean(f.Unique), def, now); e != nil {
			return e
		}
	}
	return nil
}

func loadFields(ctx context.Context, tx store.Transaction, collectionID string) ([]collections.Field, error) {
	rows, e := tx.QueryContext(ctx, `SELECT id,name,type,required,is_unique,default_json FROM `+q("_trestle_fields")+` WHERE collection_id=? ORDER BY position`, collectionID)
	if e != nil {
		return nil, e
	}
	defer rows.Close()
	var out []collections.Field
	for rows.Next() {
		var f collections.Field
		var req, uniq any
		var def sql.NullString
		if e := rows.Scan(&f.ID, &f.Name, &f.Type, &req, &uniq, &def); e != nil {
			return nil, e
		}
		f.Required = req == int64(1)
		f.Unique = uniq == int64(1)
		if def.Valid {
			f.Default = json.RawMessage(def.String)
		}
		out = append(out, f)
	}
	return out, rows.Err()
}

// deleteCollection deterministically drops a collection and its records. A
// re-applied delete (already absent) is an idempotent no-op.
func deleteCollection(ctx context.Context, tx store.Transaction, name string) error {
	var id string
	err := tx.QueryRowContext(ctx, `SELECT id FROM `+q("_trestle_collections")+` WHERE name=?`, name).Scan(&id)
	if errors.Is(err, sql.ErrNoRows) {
		return nil
	}
	if err != nil {
		return err
	}
	if _, e := tx.ExecContext(ctx, `DROP TABLE IF EXISTS `+q(collections.PhysicalTableName(id))); e != nil {
		return e
	}
	if _, e := tx.ExecContext(ctx, `DELETE FROM `+q("_trestle_collections")+` WHERE id=?`, id); e != nil {
		return e
	}
	return nil
}

// putRecord enforces the record version precondition: create (version 1) must
// not collide with an existing row; update (version N) must observe current
// N-1. A re-applied create/update (already at the target state) is idempotent.
func putRecord(ctx context.Context, tx store.Transaction, dialect store.Dialect, p RecordPayload) error {
	rows, e := tx.QueryContext(ctx, `SELECT id,name,type FROM `+q("_trestle_fields")+` WHERE collection_id=? ORDER BY position`, p.CollectionID)
	if e != nil {
		return e
	}
	var fieldMeta []struct {
		id, name, kind string
	}
	for rows.Next() {
		var f struct{ id, name, kind string }
		if e := rows.Scan(&f.id, &f.name, &f.kind); e != nil {
			rows.Close()
			return e
		}
		fieldMeta = append(fieldMeta, f)
	}
	rows.Close()
	if e := rows.Err(); e != nil {
		return e
	}
	if len(fieldMeta) == 0 {
		return fmt.Errorf("record collection %q not found", p.CollectionID)
	}
	table := q(collections.PhysicalTableName(p.CollectionID))
	var current int64
	err := tx.QueryRowContext(ctx, `SELECT _version FROM `+table+` WHERE _id=?`, p.RecordID).Scan(&current)
	if errors.Is(err, sql.ErrNoRows) {
		if p.Version != 1 {
			return fmt.Errorf("%w: record %q create requires version 1 (got %d)", ErrStalePrecondition, p.RecordID, p.Version)
		}
		cols, args, marks := []string{"_id", "_version", "_created", "_updated"}, []any{p.RecordID, p.Version, p.CreatedAt, p.UpdatedAt}, []string{"?", "?", "?", "?"}
		for _, f := range fieldMeta {
			col := q(collections.PhysicalColumnName(f.id))
			cols = append(cols, col)
			marks = append(marks, "?")
			args = append(args, encodeField(dialect, f.kind, p.Values[f.name]))
		}
		if _, e := tx.ExecContext(ctx, `INSERT INTO `+table+`(`+join(cols)+`) VALUES(`+join(marks)+`)`, args...); e != nil {
			return e
		}
		if p.IdempotencyKey != "" {
			if _, e := tx.ExecContext(ctx, `INSERT INTO `+q("_trestle_record_idempotency")+`(collection_id,idempotency_key,record_id,created_at) VALUES(?,?,?,?)`, p.CollectionID, p.IdempotencyKey, p.RecordID, p.CreatedAt); e != nil {
				return fmt.Errorf("%w: idempotency key %q reused", ErrStalePrecondition, p.IdempotencyKey)
			}
		}
		return nil
	}
	if err != nil {
		return err
	}
	if p.Version != current+1 {
		return fmt.Errorf("%w: record %q stale update: expected version %d, current %d", ErrStalePrecondition, p.RecordID, p.Version-1, current)
	}
	sets, args := []string{"_version=?", "_updated=?"}, []any{p.Version, p.UpdatedAt}
	for _, f := range fieldMeta {
		col := q(collections.PhysicalColumnName(f.id))
		sets = append(sets, col+"=?")
		args = append(args, encodeField(dialect, f.kind, p.Values[f.name]))
	}
	args = append(args, p.RecordID, current)
	r, e := tx.ExecContext(ctx, `UPDATE `+table+` SET `+join(sets)+` WHERE _id=? AND _version=?`, args...)
	if e != nil {
		return e
	}
	if n, _ := r.RowsAffected(); n != 1 {
		return fmt.Errorf("%w: record %q stale update: concurrent modification", ErrStalePrecondition, p.RecordID)
	}
	return nil
}

// deleteRecord enforces the version precondition; a re-applied delete (already
// absent) is an idempotent no-op.
func deleteRecord(ctx context.Context, tx store.Transaction, p RecordPayload) error {
	table := q(collections.PhysicalTableName(p.CollectionID))
	var current int64
	err := tx.QueryRowContext(ctx, `SELECT _version FROM `+table+` WHERE _id=?`, p.RecordID).Scan(&current)
	if errors.Is(err, sql.ErrNoRows) {
		return nil
	}
	if err != nil {
		return err
	}
	if current != p.Version {
		return fmt.Errorf("%w: record %q stale delete: expected version %d, current %d", ErrStalePrecondition, p.RecordID, p.Version, current)
	}
	if _, e := tx.ExecContext(ctx, `DELETE FROM `+table+` WHERE _id=? AND _version=?`, p.RecordID, p.Version); e != nil {
		return e
	}
	if _, e := tx.ExecContext(ctx, `DELETE FROM `+q("_trestle_record_idempotency")+` WHERE collection_id=? AND record_id=?`, p.CollectionID, p.RecordID); e != nil {
		return e
	}
	return nil
}

// applyWebhookPut deterministically materializes a webhook definition,
// applying the canonical ciphertext carried in the command verbatim.
func applyWebhookPut(ctx context.Context, tx store.Transaction, dialect store.Dialect, w replpayload.WebhookPayload) error {
	if w.ID == "" || w.Name == "" || w.URL == "" {
		return fmt.Errorf("replicated webhook definition is incomplete")
	}
	if len(w.SecretCipher) == 0 {
		return fmt.Errorf("replicated webhook secret ciphertext is required")
	}
	_, e := tx.ExecContext(ctx, `INSERT INTO `+q("_trestle_webhooks")+`(id,name,url,topics,secret_cipher,enabled,created_at,updated_at) VALUES(?,?,?,?,?,?,?,?)
		ON CONFLICT(id) DO UPDATE SET name=excluded.name,url=excluded.url,topics=excluded.topics,secret_cipher=excluded.secret_cipher,enabled=excluded.enabled,updated_at=excluded.updated_at`,
		w.ID, w.Name, w.URL, w.Topics, w.SecretCipher, dialect.Boolean(w.Enabled), w.CreatedAt, w.UpdatedAt)
	return e
}

func deleteWebhook(ctx context.Context, tx store.Transaction, id string) error {
	_, e := tx.ExecContext(ctx, `DELETE FROM `+q("_trestle_webhooks")+` WHERE id=?`, id)
	return e
}

// applyFunctionPut deterministically materializes a function definition.
func applyFunctionPut(ctx context.Context, tx store.Transaction, dialect store.Dialect, fn replpayload.FunctionPayload) error {
	if fn.ID == "" || fn.Name == "" || fn.Provider != "aws-lambda" || fn.Target == "" || fn.Region == "" {
		return fmt.Errorf("replicated function definition is incomplete")
	}
	_, e := tx.ExecContext(ctx, `INSERT INTO `+q("_trestle_functions")+`(id,name,provider,target,region,topics,callback_scopes,enabled,created_at,updated_at) VALUES(?,?,?,?,?,?,?,?,?,?)
		ON CONFLICT(id) DO UPDATE SET name=excluded.name,target=excluded.target,region=excluded.region,topics=excluded.topics,callback_scopes=excluded.callback_scopes,enabled=excluded.enabled,updated_at=excluded.updated_at`,
		fn.ID, fn.Name, fn.Provider, fn.Target, fn.Region, fn.Topics, fn.CallbackScopes, dialect.Boolean(fn.Enabled), fn.CreatedAt, fn.UpdatedAt)
	return e
}

func deleteFunction(ctx context.Context, tx store.Transaction, id string) error {
	_, e := tx.ExecContext(ctx, `DELETE FROM `+q("_trestle_functions")+` WHERE id=?`, id)
	return e
}

// applyJobClaim claims a pending, available job on behalf of the leader worker.
// The lease is derived from the committed operation timestamp so every replica
// agrees on when it expires.
func applyJobClaim(ctx context.Context, tx store.Transaction, id, now string) error {
	var status, availableAt string
	err := tx.QueryRowContext(ctx, `SELECT status,available_at FROM `+q("_trestle_jobs")+` WHERE id=?`, id).Scan(&status, &availableAt)
	if errors.Is(err, sql.ErrNoRows) {
		return nil
	}
	if err != nil {
		return err
	}
	if status != "pending" || availableAt > now {
		return fmt.Errorf("%w: job %q not claimable (status %s, available %s)", ErrStalePrecondition, id, status, availableAt)
	}
	_, err = tx.ExecContext(ctx, `UPDATE `+q("_trestle_jobs")+` SET status='running',attempts=attempts+1,lease_until=?,updated_at=? WHERE id=? AND status='pending'`, addSeconds(now, 30), now, id)
	return err
}

// applyJobComplete records a successful or failed execution. Timing (retry
// backoff, dead-letter) is derived from the committed timestamp.
func applyJobComplete(ctx context.Context, tx store.Transaction, id string, ok bool, errMsg, now string) error {
	if ok {
		_, e := tx.ExecContext(ctx, `UPDATE `+q("_trestle_jobs")+` SET status='succeeded',lease_until=NULL,last_error=NULL,updated_at=? WHERE id=?`, now, id)
		return e
	}
	var attempts, max int
	err := tx.QueryRowContext(ctx, `SELECT attempts,max_attempts FROM `+q("_trestle_jobs")+` WHERE id=?`, id).Scan(&attempts, &max)
	if errors.Is(err, sql.ErrNoRows) {
		return nil
	}
	if err != nil {
		return err
	}
	status := "pending"
	if attempts >= max {
		status = "dead"
	}
	delay := 1 << min(attempts, 8)
	message := errMsg
	if len(message) > 500 {
		message = message[:500]
	}
	_, err = tx.ExecContext(ctx, `UPDATE `+q("_trestle_jobs")+` SET status=?,available_at=?,lease_until=NULL,last_error=?,updated_at=? WHERE id=?`, status, addSeconds(now, delay), message, now, id)
	return err
}

// applyJobReleaseStale reclaims running jobs whose lease has expired in
// committed time, so a new leader can resume work after failover.
func applyJobReleaseStale(ctx context.Context, tx store.Transaction, now string) error {
	_, e := tx.ExecContext(ctx, `UPDATE `+q("_trestle_jobs")+` SET status='pending',lease_until=NULL,updated_at=? WHERE status='running' AND lease_until<?`, now, now)
	return e
}

func applyJobCancel(ctx context.Context, tx store.Transaction, id, now string) error {
	_, e := tx.ExecContext(ctx, `UPDATE `+q("_trestle_jobs")+` SET status='cancelled',lease_until=NULL,updated_at=? WHERE id=? AND status IN ('pending','running')`, now, id)
	return e
}

func applyJobRetry(ctx context.Context, tx store.Transaction, id, now string) error {
	_, e := tx.ExecContext(ctx, `UPDATE `+q("_trestle_jobs")+` SET status='pending',attempts=0,available_at=?,lease_until=NULL,last_error=NULL,updated_at=? WHERE id=? AND status IN ('dead','cancelled')`, now, now, id)
	return e
}

func encodeField(dialect store.Dialect, kind string, v any) any {
	if kind == "json" && v != nil {
		b, _ := json.Marshal(v)
		return string(b)
	}
	if kind == "boolean" {
		if b, ok := v.(bool); ok {
			return dialect.Boolean(b)
		}
		if n, ok := v.(float64); ok {
			return dialect.Boolean(n != 0)
		}
	}
	return v
}

// --- snapshot ----------------------------------------------------------------

type snapshotEnvelope struct {
	Format      int                  `json:"format"`
	Index       uint64               `json:"index"`
	Term        uint64               `json:"term"`
	Integrity   string               `json:"integrity"`
	Applied     map[string]string    `json:"applied"`
	Collections []snapshotCollection `json:"collections"`
	Events      []snapshotEvent      `json:"events"`
	Audit       []snapshotAudit      `json:"audit"`
	Jobs        []snapshotJob        `json:"jobs"`
	Webhooks    []snapshotWebhook    `json:"webhooks"`
	Functions   []snapshotFunction   `json:"functions"`
}
type snapshotCollection struct {
	Definition collections.Collection `json:"definition"`
	Records    []RecordPayload        `json:"records"`
}
type snapshotEvent struct {
	Sequence       int64  `json:"sequence"`
	OccurredAt     string `json:"occurred_at"`
	Topic          string `json:"topic"`
	CollectionName string `json:"collection_name,omitempty"`
	RecordID       string `json:"record_id,omitempty"`
	PayloadJSON    string `json:"payload_json"`
	DedupKey       string `json:"dedup_key,omitempty"`
}
type snapshotAudit struct {
	ID          int64  `json:"id"`
	OccurredAt  string `json:"occurred_at"`
	ActorKind   string `json:"actor_kind"`
	ActorID     string `json:"actor_id,omitempty"`
	Action      string `json:"action"`
	Target      string `json:"target,omitempty"`
	Outcome     string `json:"outcome"`
	RequestID   string `json:"request_id,omitempty"`
	DetailsJSON string `json:"details_json"`
	DedupKey    string `json:"dedup_key,omitempty"`
}
type snapshotJob struct {
	ID             string `json:"id"`
	Kind           string `json:"kind"`
	PayloadJSON    string `json:"payload_json"`
	Status         string `json:"status"`
	Attempts       int    `json:"attempts"`
	MaxAttempts    int    `json:"max_attempts"`
	AvailableAt    string `json:"available_at"`
	LeaseUntil     string `json:"lease_until,omitempty"`
	IdempotencyKey string `json:"idempotency_key,omitempty"`
	LastError      string `json:"last_error,omitempty"`
	CreatedAt      string `json:"created_at"`
	UpdatedAt      string `json:"updated_at"`
}
type snapshotWebhook struct {
	ID           string `json:"id"`
	Name         string `json:"name"`
	URL          string `json:"url"`
	Topics       string `json:"topics"`
	SecretCipher []byte `json:"secret_cipher"`
	Enabled      bool   `json:"enabled"`
	CreatedAt    string `json:"created_at"`
	UpdatedAt    string `json:"updated_at"`
}
type snapshotFunction struct {
	ID             string `json:"id"`
	Name           string `json:"name"`
	Provider       string `json:"provider"`
	Target         string `json:"target"`
	Region         string `json:"region"`
	Topics         string `json:"topics"`
	CallbackScopes string `json:"callback_scopes"`
	Enabled        bool   `json:"enabled"`
	CreatedAt      string `json:"created_at"`
	UpdatedAt      string `json:"updated_at"`
}

func (f *FSM) Snapshot() (raft.FSMSnapshot, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	snap := &snapshot{db: f.db, index: f.index, term: f.term, applied: map[string]string{}}
	for k, v := range f.applied {
		snap.applied[k] = v
	}
	return snap, nil
}

func (f *FSM) Restore(rc io.ReadCloser) error {
	defer rc.Close()
	b, e := io.ReadAll(rc)
	if e != nil {
		return e
	}
	var env snapshotEnvelope
	if e := json.Unmarshal(b, &env); e != nil {
		return e
	}
	if env.Format != snapFormat {
		return fmt.Errorf("unsupported trestle snapshot format %d (want %d)", env.Format, snapFormat)
	}
	if env.Index <= f.persistedIndex {
		// Snapshot behind the current materialization: preserve product state
		// and only seed durable op-ID knowledge for entries the retained log no
		// longer replays.
		f.mu.Lock()
		for k, v := range env.Applied {
			if _, ok := f.applied[k]; !ok {
				f.applied[k] = v
			}
		}
		f.mu.Unlock()
		return nil
	}
	ctx := context.Background()
	f.mu.Lock()
	defer f.mu.Unlock()
	tx, e := f.db.BeginTx(ctx, nil)
	if e != nil {
		return e
	}
	defer tx.Rollback()
	dialect := f.db.Dialect()
	// Replace the full consensus-owned surface.
	names, e := listCollections(ctx, tx)
	if e != nil {
		return e
	}
	for _, n := range names {
		if e := deleteCollection(ctx, tx, n); e != nil {
			return e
		}
	}
	for _, c := range env.Collections {
		if e := applyCollection(ctx, tx, dialect, c.Definition); e != nil {
			return e
		}
		for _, rec := range c.Records {
			if e := putRecord(ctx, tx, dialect, rec); e != nil {
				return e
			}
		}
	}
	if e := replaceConsensusTables(ctx, tx, dialect, env); e != nil {
		return e
	}
	if e := metaPut(tx, metaIndex, env.Index); e != nil {
		return e
	}
	if e := metaPut(tx, metaTerm, env.Term); e != nil {
		return e
	}
	for id, dg := range env.Applied {
		if _, e := tx.ExecContext(ctx, `INSERT INTO `+metaTable+`(k,v) VALUES(?,?) ON CONFLICT(k) DO UPDATE SET v=excluded.v`, metaOpKey+id, dg); e != nil {
			return e
		}
	}
	if e := tx.Commit(); e != nil {
		return e
	}
	f.applied = map[string]string{}
	for k, v := range env.Applied {
		f.applied[k] = v
	}
	f.index, f.term = env.Index, env.Term
	f.persistedIndex = env.Index
	return nil
}

// replaceConsensusTables clears and repopulates the consensus-owned event,
// audit, job, webhook and function tables from the snapshot, preserving the
// explicit numeric identities so every restored node stays cursor-aligned.
func replaceConsensusTables(ctx context.Context, tx store.Transaction, dialect store.Dialect, env snapshotEnvelope) error {
	for _, table := range []string{"_trestle_events", "_trestle_audit", "_trestle_jobs", "_trestle_webhooks", "_trestle_functions"} {
		if _, e := tx.ExecContext(ctx, `DELETE FROM `+q(table)); e != nil {
			return e
		}
	}
	for _, ev := range env.Events {
		if _, e := tx.ExecContext(ctx, `INSERT INTO `+q("_trestle_events")+`(sequence,occurred_at,topic,collection_name,record_id,payload_json,dedup_key) VALUES(?,?,?,?,?,?,?)`,
			ev.Sequence, ev.OccurredAt, ev.Topic, nullable(ev.CollectionName), nullable(ev.RecordID), ev.PayloadJSON, nullable(ev.DedupKey)); e != nil {
			return e
		}
	}
	for _, au := range env.Audit {
		if _, e := tx.ExecContext(ctx, `INSERT INTO `+q("_trestle_audit")+`(id,occurred_at,actor_kind,actor_id,action,target,outcome,request_id,details_json,dedup_key) VALUES(?,?,?,?,?,?,?,?,?,?)`,
			au.ID, au.OccurredAt, au.ActorKind, nullable(au.ActorID), au.Action, nullable(au.Target), au.Outcome, nullable(au.RequestID), au.DetailsJSON, nullable(au.DedupKey)); e != nil {
			return e
		}
	}
	for _, j := range env.Jobs {
		if _, e := tx.ExecContext(ctx, `INSERT INTO `+q("_trestle_jobs")+`(id,kind,payload_json,status,attempts,max_attempts,available_at,lease_until,idempotency_key,last_error,created_at,updated_at) VALUES(?,?,?,?,?,?,?,?,?,?,?,?)`,
			j.ID, j.Kind, j.PayloadJSON, j.Status, j.Attempts, j.MaxAttempts, j.AvailableAt, nullable(j.LeaseUntil), nullable(j.IdempotencyKey), nullable(j.LastError), j.CreatedAt, j.UpdatedAt); e != nil {
			return e
		}
	}
	for _, w := range env.Webhooks {
		if _, e := tx.ExecContext(ctx, `INSERT INTO `+q("_trestle_webhooks")+`(id,name,url,topics,secret_cipher,enabled,created_at,updated_at) VALUES(?,?,?,?,?,?,?,?)`,
			w.ID, w.Name, w.URL, w.Topics, w.SecretCipher, dialect.Boolean(w.Enabled), w.CreatedAt, w.UpdatedAt); e != nil {
			return e
		}
	}
	for _, fn := range env.Functions {
		if _, e := tx.ExecContext(ctx, `INSERT INTO `+q("_trestle_functions")+`(id,name,provider,target,region,topics,callback_scopes,enabled,created_at,updated_at) VALUES(?,?,?,?,?,?,?,?,?,?)`,
			fn.ID, fn.Name, fn.Provider, fn.Target, fn.Region, fn.Topics, fn.CallbackScopes, dialect.Boolean(fn.Enabled), fn.CreatedAt, fn.UpdatedAt); e != nil {
			return e
		}
	}
	return nil
}

func listCollections(ctx context.Context, tx store.Transaction) ([]string, error) {
	rows, e := tx.QueryContext(ctx, `SELECT name FROM `+q("_trestle_collections")+` ORDER BY name`)
	if e != nil {
		return nil, e
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var n string
		if e := rows.Scan(&n); e != nil {
			return nil, e
		}
		out = append(out, n)
	}
	return out, rows.Err()
}

func (f *FSM) setFailure(e error) {
	if f.failure == nil {
		f.failure = e
		log.Printf("trestle replication FSM apply failure (replica poisoned): %v", e)
	}
}

type snapshot struct {
	db      store.Executor
	index   uint64
	term    uint64
	applied map[string]string
}

func (s *snapshot) Persist(sink raft.SnapshotSink) error {
	ctx := context.Background()
	env := snapshotEnvelope{Format: snapFormat, Index: s.index, Term: s.term, Applied: s.applied}
	rows, e := s.db.Query(`SELECT name FROM ` + q("_trestle_collections") + ` ORDER BY name`)
	if e != nil {
		_ = sink.Cancel()
		return e
	}
	var colNames []string
	for rows.Next() {
		var n string
		if e := rows.Scan(&n); e != nil {
			rows.Close()
			_ = sink.Cancel()
			return e
		}
		colNames = append(colNames, n)
	}
	rows.Close()
	for _, n := range colNames {
		sc := snapshotCollection{}
		var id string
		if e := s.db.QueryRowContext(ctx, `SELECT id,name,kind,created_at,updated_at FROM `+q("_trestle_collections")+` WHERE name=?`, n).Scan(&id, &sc.Definition.Name, &sc.Definition.Kind, &sc.Definition.CreatedAt, &sc.Definition.UpdatedAt); e != nil {
			_ = sink.Cancel()
			return e
		}
		sc.Definition.ID = id
		frows, e := s.db.QueryContext(ctx, `SELECT id,name,type,required,is_unique,default_json FROM `+q("_trestle_fields")+` WHERE collection_id=? ORDER BY position`, id)
		if e != nil {
			_ = sink.Cancel()
			return e
		}
		for frows.Next() {
			var f collections.Field
			var req, uniq any
			var def sql.NullString
			if e := frows.Scan(&f.ID, &f.Name, &f.Type, &req, &uniq, &def); e != nil {
				frows.Close()
				_ = sink.Cancel()
				return e
			}
			f.Required = req == int64(1)
			f.Unique = uniq == int64(1)
			if def.Valid {
				f.Default = json.RawMessage(def.String)
			}
			sc.Definition.Fields = append(sc.Definition.Fields, f)
		}
		frows.Close()
		// Read all records of the collection.
		cols := []string{"_id", "_version", "_created", "_updated"}
		for _, f := range sc.Definition.Fields {
			cols = append(cols, q(collections.PhysicalColumnName(f.ID)))
		}
		rrows, e := s.db.QueryContext(ctx, `SELECT `+join(cols)+` FROM `+q(collections.PhysicalTableName(id))+` ORDER BY _id`)
		if e != nil {
			_ = sink.Cancel()
			return e
		}
		for rrows.Next() {
			rec := RecordPayload{CollectionID: id}
			dests := []any{&rec.RecordID, &rec.Version, &rec.CreatedAt, &rec.UpdatedAt}
			vals := make([]any, len(sc.Definition.Fields))
			for i := range vals {
				dests = append(dests, &vals[i])
			}
			if e := rrows.Scan(dests...); e != nil {
				rrows.Close()
				_ = sink.Cancel()
				return e
			}
			rec.Values = map[string]any{}
			for i, f := range sc.Definition.Fields {
				rec.Values[f.Name] = decodeField(f.Type, vals[i])
			}
			sc.Records = append(sc.Records, rec)
		}
		rrows.Close()
		env.Collections = append(env.Collections, sc)
	}
	if e := loadSnapshotConsequences(ctx, s.db, &env); e != nil {
		_ = sink.Cancel()
		return e
	}
	// Integrity over the canonical content.
	cp := env
	cp.Integrity = ""
	raw, e := json.Marshal(cp)
	if e != nil {
		_ = sink.Cancel()
		return e
	}
	sum := sha256.Sum256(raw)
	env.Integrity = hex.EncodeToString(sum[:])
	b, e := json.Marshal(env)
	if e != nil {
		_ = sink.Cancel()
		return e
	}
	if _, e := sink.Write(b); e != nil {
		_ = sink.Cancel()
		return e
	}
	return sink.Close()
}

// loadSnapshotConsequences reads the full consensus-owned consequence tables
// into the snapshot envelope so a restored node reconstructs identical state.
func loadSnapshotConsequences(ctx context.Context, db store.Executor, env *snapshotEnvelope) error {
	erows, e := db.QueryContext(ctx, `SELECT sequence,occurred_at,topic,COALESCE(collection_name,''),COALESCE(record_id,''),payload_json,COALESCE(dedup_key,'') FROM `+q("_trestle_events")+` ORDER BY sequence`)
	if e != nil {
		return e
	}
	for erows.Next() {
		var ev snapshotEvent
		if e := erows.Scan(&ev.Sequence, &ev.OccurredAt, &ev.Topic, &ev.CollectionName, &ev.RecordID, &ev.PayloadJSON, &ev.DedupKey); e != nil {
			erows.Close()
			return e
		}
		env.Events = append(env.Events, ev)
	}
	erows.Close()
	if e := erows.Err(); e != nil {
		return e
	}
	arows, e := db.QueryContext(ctx, `SELECT id,occurred_at,actor_kind,COALESCE(actor_id,''),action,COALESCE(target,''),outcome,COALESCE(request_id,''),details_json,COALESCE(dedup_key,'') FROM `+q("_trestle_audit")+` ORDER BY id`)
	if e != nil {
		return e
	}
	for arows.Next() {
		var au snapshotAudit
		if e := arows.Scan(&au.ID, &au.OccurredAt, &au.ActorKind, &au.ActorID, &au.Action, &au.Target, &au.Outcome, &au.RequestID, &au.DetailsJSON, &au.DedupKey); e != nil {
			arows.Close()
			return e
		}
		env.Audit = append(env.Audit, au)
	}
	arows.Close()
	if e := arows.Err(); e != nil {
		return e
	}
	jrows, e := db.QueryContext(ctx, `SELECT id,kind,payload_json,status,attempts,max_attempts,available_at,COALESCE(lease_until,''),COALESCE(idempotency_key,''),COALESCE(last_error,''),created_at,updated_at FROM `+q("_trestle_jobs")+` ORDER BY id`)
	if e != nil {
		return e
	}
	for jrows.Next() {
		var j snapshotJob
		if e := jrows.Scan(&j.ID, &j.Kind, &j.PayloadJSON, &j.Status, &j.Attempts, &j.MaxAttempts, &j.AvailableAt, &j.LeaseUntil, &j.IdempotencyKey, &j.LastError, &j.CreatedAt, &j.UpdatedAt); e != nil {
			jrows.Close()
			return e
		}
		env.Jobs = append(env.Jobs, j)
	}
	jrows.Close()
	if e := jrows.Err(); e != nil {
		return e
	}
	wrows, e := db.QueryContext(ctx, `SELECT id,name,url,topics,secret_cipher,enabled,created_at,updated_at FROM `+q("_trestle_webhooks")+` ORDER BY id`)
	if e != nil {
		return e
	}
	for wrows.Next() {
		var w snapshotWebhook
		var enabledRaw any
		if e := wrows.Scan(&w.ID, &w.Name, &w.URL, &w.Topics, &w.SecretCipher, &enabledRaw, &w.CreatedAt, &w.UpdatedAt); e != nil {
			wrows.Close()
			return e
		}
		w.Enabled, e = db.Dialect().DecodeBoolean(enabledRaw)
		if e != nil {
			wrows.Close()
			return e
		}
		env.Webhooks = append(env.Webhooks, w)
	}
	wrows.Close()
	if e := wrows.Err(); e != nil {
		return e
	}
	frows, e := db.QueryContext(ctx, `SELECT id,name,provider,target,region,topics,callback_scopes,enabled,created_at,updated_at FROM `+q("_trestle_functions")+` ORDER BY id`)
	if e != nil {
		return e
	}
	for frows.Next() {
		var fn snapshotFunction
		var enabledRaw any
		if e := frows.Scan(&fn.ID, &fn.Name, &fn.Provider, &fn.Target, &fn.Region, &fn.Topics, &fn.CallbackScopes, &enabledRaw, &fn.CreatedAt, &fn.UpdatedAt); e != nil {
			frows.Close()
			return e
		}
		fn.Enabled, e = db.Dialect().DecodeBoolean(enabledRaw)
		if e != nil {
			frows.Close()
			return e
		}
		env.Functions = append(env.Functions, fn)
	}
	frows.Close()
	return frows.Err()
}

func (s *snapshot) Release() {}

func decodeField(kind string, v any) any {
	if v == nil {
		return nil
	}
	switch kind {
	case "boolean":
		if n, ok := v.(int64); ok {
			return n == 1
		}
	case "json":
		var out any
		_ = json.Unmarshal([]byte(fmt.Sprint(v)), &out)
		return out
	case "number":
		return v
	}
	return v
}

// ConsensusTablesEmpty reports whether every consensus-owned application table
// is empty. It is the clean-state precondition a prospective node must satisfy
// before joining a replicated cluster for the first time (the cluster can only
// bootstrap canonical state onto empty consensus-owned tables or a snapshot).
func ConsensusTablesEmpty(db store.Executor) (bool, error) {
	tables := []string{"_trestle_collections", "_trestle_events", "_trestle_audit", "_trestle_jobs", "_trestle_webhooks", "_trestle_functions"}
	for _, table := range tables {
		var count int64
		if e := db.QueryRow(`SELECT count(*) FROM ` + q(table)).Scan(&count); e != nil {
			return false, e
		}
		if count > 0 {
			return false, nil
		}
	}
	return true, nil
}

func q(s string) string { return `"` + s + `"` }
func join(x []string) string {
	r := ""
	for i, s := range x {
		if i > 0 {
			r += ","
		}
		r += s
	}
	return r
}
func trimPrefix(s, p string) string { return s[len(p):] }
func metaGet(db store.Executor, k string) (uint64, bool, error) {
	var s string
	err := db.QueryRow(`SELECT v FROM `+metaTable+` WHERE k=?`, k).Scan(&s)
	if errors.Is(err, sql.ErrNoRows) {
		return 0, false, nil
	}
	if err != nil {
		return 0, false, err
	}
	var v uint64
	if _, e := fmt.Sscanf(s, "%d", &v); e != nil {
		return 0, false, e
	}
	return v, true, nil
}
func metaPut(tx store.Transaction, k string, v uint64) error {
	_, e := tx.Exec(`INSERT INTO `+metaTable+`(k,v) VALUES(?,?) ON CONFLICT(k) DO UPDATE SET v=excluded.v`, k, fmt.Sprint(v))
	return e
}

func nullable(s string) any {
	if s == "" {
		return nil
	}
	return s
}

func seqKey(opID, kind string, ordinal int) string {
	if ordinal < 0 {
		return "op:" + opID + ":" + kind
	}
	return "op:" + opID + ":" + kind + ":" + strconv.Itoa(ordinal)
}

func containsTopic(list, want string) bool {
	for _, item := range strings.Split(list, ",") {
		if strings.TrimSpace(item) == want {
			return true
		}
	}
	return false
}

func deterministicHex(seed string, n int) string {
	sum := sha256.Sum256([]byte(seed))
	return hex.EncodeToString(sum[:n])
}

func addSeconds(value string, seconds int) string {
	t, err := time.Parse(time.RFC3339Nano, value)
	if err != nil {
		return value
	}
	return t.Add(time.Duration(seconds) * time.Second).UTC().Format(time.RFC3339Nano)
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
