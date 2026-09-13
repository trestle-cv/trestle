package propagation

import (
	"context"
	"database/sql"
	"encoding/json"
	"time"

	core "github.com/gantry-tools/gantry-core/propagation"
	"github.com/trestle-cv/trestle/internal/store"
)

type StateStore struct {
	db  store.Executor
	now func() time.Time
}

func NewStateStore(db any) *StateStore { return &StateStore{db: store.Adapt(db), now: time.Now} }

func (s *StateStore) SaveProfile(ctx context.Context, p core.Profile) error {
	selector, err := json.Marshal(p.Selector)
	if err != nil {
		return err
	}
	kinds, err := json.Marshal(p.Kinds)
	if err != nil {
		return err
	}
	now := s.now().UTC().Format(time.RFC3339Nano)
	_, err = s.db.ExecContext(ctx, `INSERT INTO _trestle_propagation_profiles(id,name,selector_json,kinds_json,mode,schedule,maintenance_window,enabled,last_run_at,created_at,updated_at)
VALUES(?,?,?,?,?,?,?,?,?,?,?) ON CONFLICT(id) DO UPDATE SET name=excluded.name,selector_json=excluded.selector_json,kinds_json=excluded.kinds_json,mode=excluded.mode,schedule=excluded.schedule,maintenance_window=excluded.maintenance_window,enabled=excluded.enabled,last_run_at=excluded.last_run_at,updated_at=excluded.updated_at`,
		p.ID, p.Name, string(selector), string(kinds), string(p.Mode), p.Schedule, p.MaintenanceWindow, s.db.Dialect().Boolean(p.Enabled), nullableTime(p.LastRunAt), now, now)
	return err
}
func (s *StateStore) DeleteProfile(ctx context.Context, id string) error {
	_, err := s.db.ExecContext(ctx, "DELETE FROM _trestle_propagation_profiles WHERE id=?", id)
	return err
}
func (s *StateStore) ListProfiles(ctx context.Context) ([]core.Profile, error) {
	rows, err := s.db.QueryContext(ctx, "SELECT id,name,selector_json,kinds_json,mode,schedule,maintenance_window,enabled,last_run_at FROM _trestle_propagation_profiles ORDER BY name,id")
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []core.Profile
	for rows.Next() {
		var p core.Profile
		var sel, kinds string
		var enabled any
		var last sql.NullString
		if err := rows.Scan(&p.ID, &p.Name, &sel, &kinds, &p.Mode, &p.Schedule, &p.MaintenanceWindow, &enabled, &last); err != nil {
			return nil, err
		}
		if err = json.Unmarshal([]byte(sel), &p.Selector); err != nil {
			return nil, err
		}
		if err = json.Unmarshal([]byte(kinds), &p.Kinds); err != nil {
			return nil, err
		}
		p.Enabled, err = s.db.Dialect().DecodeBoolean(enabled)
		if err != nil {
			return nil, err
		}
		if last.Valid {
			if parsed, e := time.Parse(time.RFC3339Nano, last.String); e == nil {
				p.LastRunAt = &parsed
			}
		}
		out = append(out, p)
	}
	return out, rows.Err()
}
func (s *StateStore) RecordHistory(ctx context.Context, h core.HistoryRecord) error {
	_, err := s.db.ExecContext(ctx, `INSERT INTO _trestle_propagation_history(id,plan_id,actor,target,status,applied,failed,rolled_back,detail,created_at) VALUES(?,?,?,?,?,?,?,?,?,?) ON CONFLICT(id) DO UPDATE SET status=excluded.status,applied=excluded.applied,failed=excluded.failed,rolled_back=excluded.rolled_back,detail=excluded.detail`, h.ID, h.PlanID, h.Actor, h.Target, h.Status, h.Applied, h.Failed, h.RolledBack, h.Detail, h.CreatedAt.UTC().Format(time.RFC3339Nano))
	return err
}
func (s *StateStore) ListHistory(ctx context.Context, limit int) ([]core.HistoryRecord, error) {
	if limit <= 0 || limit > 200 {
		limit = 50
	}
	rows, err := s.db.QueryContext(ctx, "SELECT id,plan_id,actor,target,status,applied,failed,rolled_back,detail,created_at FROM _trestle_propagation_history ORDER BY created_at DESC LIMIT ?", limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []core.HistoryRecord
	for rows.Next() {
		var h core.HistoryRecord
		var at string
		if err := rows.Scan(&h.ID, &h.PlanID, &h.Actor, &h.Target, &h.Status, &h.Applied, &h.Failed, &h.RolledBack, &h.Detail, &at); err != nil {
			return nil, err
		}
		h.CreatedAt, _ = time.Parse(time.RFC3339Nano, at)
		out = append(out, h)
	}
	return out, rows.Err()
}

var _ core.StateStore = (*StateStore)(nil)

func nullableTime(t *time.Time) any {
	if t == nil {
		return nil
	}
	return t.UTC().Format(time.RFC3339Nano)
}
