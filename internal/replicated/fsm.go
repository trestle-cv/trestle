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
	"sync"

	"github.com/gantry-tools/gantry-core/replication"
	"github.com/hashicorp/raft"
	"github.com/trestle-cv/trestle/internal/collections"
	"github.com/trestle-cv/trestle/internal/store"
)

const (
	KindCollectionPut    = "trestle.collection.put"
	KindCollectionDelete = "trestle.collection.delete"
	KindRecordPut        = "trestle.record.put"
	KindRecordDelete     = "trestle.record.delete"

	metaTable  = "_trestle_replicated_meta"
	metaIndex  = "applied_index"
	metaTerm   = "applied_term"
	metaOpKey  = "op:"
	snapFormat = 1
)

type RecordPayload struct {
	CollectionID string         `json:"collection_id"`
	RecordID     string         `json:"record_id"`
	Version      int64          `json:"version"`
	CreatedAt    string         `json:"created_at"`
	UpdatedAt    string         `json:"updated_at"`
	Values       map[string]any `json:"values"`
}

// FSM deterministically materializes consensus-owned Trestle collection
// definitions and records. Each committed apply is transactional: the product
// mutation, the object/record version, the durable applied index/term and the
// durable operation-ID digest advance together (or not at all). Restart
// reconstructs the durable applied position and operation-ID knowledge from
// _trestle_replicated_meta, and the raft snapshot carries the consensus-owned
// state so snapshot+trailing-log recovery is complete.
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
		f.setFailure(e)
		return e
	}
	return &replication.ApplyResult{Index: l.Index, Term: l.Term, ObjectID: op.ObjectID, OpID: op.ID, Kind: op.Kind, Revision: op.Revision}
}

// materialize applies one committed operation atomically (product mutation +
// durable op-ID + applied index/term in a single transaction).
func (f *FSM) materialize(ctx context.Context, op replication.Operation, digest string, index, term uint64) error {
	tx, e := f.db.BeginTx(ctx, nil)
	if e != nil {
		return e
	}
	defer tx.Rollback()
	switch op.Kind {
	case KindCollectionPut:
		var d collections.Collection
		if e := json.Unmarshal(op.Payload, &d); e != nil {
			return fmt.Errorf("invalid collection payload: %w", e)
		}
		if e := applyCollection(ctx, tx, f.db.Dialect(), d); e != nil {
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
		if e := putRecord(ctx, tx, f.db.Dialect(), p); e != nil {
			return e
		}
	case KindRecordDelete:
		var p RecordPayload
		if e := json.Unmarshal(op.Payload, &p); e != nil {
			return fmt.Errorf("invalid record payload: %w", e)
		}
		if e := deleteRecord(ctx, tx, p); e != nil {
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
		return fmt.Errorf("replicated collection id mismatch")
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
	var defs []collections.Field
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
	_ = defs
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
			return fmt.Errorf("record %q create requires version 1 (got %d)", p.RecordID, p.Version)
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
		return nil
	}
	if err != nil {
		return err
	}
	if p.Version != current+1 {
		return fmt.Errorf("record %q stale update: expected version %d, current %d", p.RecordID, p.Version-1, current)
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
		return fmt.Errorf("record %q stale update: concurrent modification", p.RecordID)
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
		return fmt.Errorf("record %q stale delete: expected version %d, current %d", p.RecordID, p.Version, current)
	}
	if _, e := tx.ExecContext(ctx, `DELETE FROM `+table+` WHERE _id=? AND _version=?`, p.RecordID, p.Version); e != nil {
		return e
	}
	return nil
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
		return fmt.Errorf("unsupported trestle snapshot format %d", env.Format)
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
	// Replace consensus-owned state.
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
		if e := applyCollection(ctx, tx, f.db.Dialect(), c.Definition); e != nil {
			return e
		}
		for _, rec := range c.Records {
			if e := putRecord(ctx, tx, f.db.Dialect(), rec); e != nil {
				return e
			}
		}
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

type snapshotEnvelope struct {
	Format      int                  `json:"format"`
	Index       uint64               `json:"index"`
	Term        uint64               `json:"term"`
	Integrity   string               `json:"integrity"`
	Applied     map[string]string    `json:"applied"`
	Collections []snapshotCollection `json:"collections"`
}
type snapshotCollection struct {
	Definition collections.Collection `json:"definition"`
	Records    []RecordPayload        `json:"records"`
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
