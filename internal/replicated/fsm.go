package replicated

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
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
)

type RecordPayload struct {
	CollectionID string         `json:"collection_id"`
	RecordID     string         `json:"record_id"`
	Version      int64          `json:"version"`
	CreatedAt    string         `json:"created_at"`
	UpdatedAt    string         `json:"updated_at"`
	Values       map[string]any `json:"values"`
}
type FSM struct {
	mu          sync.Mutex
	db          *sql.DB
	applied     map[string]string
	index, term uint64
	failure     error
}

func NewFSM(db store.Executor) (*FSM, error) {
	f := &FSM{db: db, applied: map[string]string{}}
	_, e := db.Exec(`CREATE TABLE IF NOT EXISTS _trestle_replicated_meta(k TEXT PRIMARY KEY,v TEXT)`)
	return f, e
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
		f.poison(e)
		return e
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.failure != nil {
		return f.failure
	}
	if d, ok := f.applied[op.ID]; ok {
		nd, _ := op.Digest()
		if d != nd {
			return errors.New("operation id reused with different payload")
		}
		return &replication.ApplyResult{Index: l.Index, Term: l.Term, ObjectID: op.ObjectID}
	}
	var err error
	switch op.Kind {
	case KindCollectionPut:
		var d collections.Collection
		err = json.Unmarshal(op.Payload, &d)
		if err == nil {
			err = collections.ApplyReplicatedDefinition(context.Background(), f.db, d)
		}
	case KindCollectionDelete:
		err = collections.DeleteDefinition(context.Background(), f.db, op.ObjectID)
	case KindRecordPut:
		var p RecordPayload
		err = json.Unmarshal(op.Payload, &p)
		if err == nil {
			err = f.putRecord(p)
		}
	case KindRecordDelete:
		var p RecordPayload
		err = json.Unmarshal(op.Payload, &p)
		if err == nil {
			err = f.deleteRecord(p)
		}
	default:
		err = fmt.Errorf("unsupported trestle replicated operation %q", op.Kind)
	}
	if err != nil {
		f.failure = err
		return err
	}
	d, _ := op.Digest()
	f.applied[op.ID] = d
	f.index, f.term = l.Index, l.Term
	_, err = f.db.Exec(`INSERT INTO _trestle_replicated_meta(k,v) VALUES('applied_index',?) ON CONFLICT(k) DO UPDATE SET v=excluded.v`, fmt.Sprint(l.Index))
	if err != nil {
		f.failure = err
		return err
	}
	return &replication.ApplyResult{Index: l.Index, Term: l.Term, ObjectID: op.ObjectID}
}
func (f *FSM) poison(e error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.failure == nil {
		f.failure = e
	}
}
func (f *FSM) putRecord(p RecordPayload) error {
	var name string
	if e := f.db.QueryRow(`SELECT name FROM _trestle_collections WHERE id=?`, p.CollectionID).Scan(&name); e != nil {
		return e
	}
	defs, e := collections.LoadDefinition(context.Background(), f.db, name)
	if e != nil {
		return e
	}
	cols := []string{"_id", "_version", "_created", "_updated"}
	args := []any{p.RecordID, p.Version, p.CreatedAt, p.UpdatedAt}
	marks := []string{"?", "?", "?", "?"}
	for _, fld := range defs.Fields {
		cols = append(cols, q(collections.PhysicalColumnName(fld.ID)))
		v := p.Values[fld.Name]
		if fld.Type == "json" && v != nil {
			b, _ := json.Marshal(v)
			v = string(b)
		}
		if fld.Type == "boolean" {
			if b, ok := v.(bool); ok {
				if b {
					v = 1
				} else {
					v = 0
				}
			}
		}
		args = append(args, v)
		marks = append(marks, "?")
	}
	table := q(collections.PhysicalTableName(p.CollectionID))
	_, e = f.db.Exec("INSERT INTO "+table+"("+join(cols)+") VALUES("+join(marks)+") ON CONFLICT(_id) DO UPDATE SET _version=excluded._version,_updated=excluded._updated", args...)
	return e
}
func (f *FSM) deleteRecord(p RecordPayload) error {
	_, e := f.db.Exec("DELETE FROM "+q(collections.PhysicalTableName(p.CollectionID))+" WHERE _id=? AND _version=?", p.RecordID, p.Version)
	return e
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
func (f *FSM) Snapshot() (raft.FSMSnapshot, error) { return &snapshot{db: f.db}, nil }
func (f *FSM) Restore(rc io.ReadCloser) error      { defer rc.Close(); return nil }

type snapshot struct{ db store.Executor }

func (s *snapshot) Persist(sink raft.SnapshotSink) error {
	_, e := sink.Write([]byte(`{"trestle":1}`))
	if e != nil {
		_ = sink.Cancel()
		return e
	}
	return sink.Close()
}
func (s *snapshot) Release() {}
