package cluster

import (
	"context"
	"time"

	core "github.com/gantry-tools/gantry-core/cluster"
)

func (s *Service) Audit(ctx context.Context, actorID, action, target, requestID string) error {
	if action == "" {
		return nil
	}
	_, err := s.db.ExecContext(ctx, `INSERT INTO _trestle_audit(occurred_at,actor_kind,actor_id,action,target,outcome,request_id,details_json) VALUES(?,?,?,?,?,?,?,?)`, time.Now().UTC().Format(time.RFC3339Nano), "admin", actorID, action, target, "success", requestID, "{}")
	return err
}

func (s *Service) RecentAudit(ctx context.Context, limit int) ([]core.AuditView, error) {
	if limit < 1 || limit > 100 {
		limit = 25
	}
	rows, err := s.db.QueryContext(ctx, `SELECT occurred_at,action,coalesce(target,''),coalesce(details_json,'') FROM _trestle_audit WHERE action LIKE 'cluster.%' ORDER BY id DESC LIMIT ?`, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []core.AuditView{}
	for rows.Next() {
		var at, action, nodeID, detail string
		if err := rows.Scan(&at, &action, &nodeID, &detail); err != nil {
			return nil, err
		}
		t, _ := time.Parse(time.RFC3339Nano, at)
		out = append(out, core.AuditView{At: t, Action: action, NodeID: nodeID, Detail: detail})
	}
	return out, rows.Err()
}
