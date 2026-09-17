package replicated

import (
	"context"
	"encoding/json"
	"fmt"
	"github.com/gantry-tools/gantry-core/replication"
	"github.com/trestle-cv/trestle/internal/collections"
	"github.com/trestle-cv/trestle/internal/records"
	"sync/atomic"
)

type Controller struct {
	auth *replication.Authority
	node *replication.Node
	seq  atomic.Uint64
}

func NewController(n *replication.Node) *Controller {
	return &Controller{auth: replication.NewAuthority(), node: n}
}
func (c *Controller) SetMode(m replication.Mode)                       { c.auth.SetMode(m) }
func (c *Controller) SetReadiness(r replication.Readiness)             { c.auth.SetReadiness(r) }
func (c *Controller) State() (replication.Mode, replication.Readiness) { return c.auth.State() }
func (c *Controller) SetForwardClient(f replication.ForwardClient)     { c.auth.SetForwardClient(f) }
func (c *Controller) Node() *replication.Node                          { return c.node }
func (c *Controller) Propose(ctx context.Context, kind, obj string, rev int64, payload any) (*replication.ApplyResult, error) {
	b, e := json.Marshal(payload)
	if e != nil {
		return nil, e
	}
	id := replication.RequestID(ctx)
	if id == "" {
		// Node-scoped operation identity: the per-node counter is prefixed with
		// this node's raft ID so concurrent proposers on different nodes never
		// generate colliding operation IDs (a collision would trip the durable
		// same-ID/different-payload idempotency conflict and poison the replica).
		id = fmt.Sprintf("trestle-%s-%d", c.node.ID(), c.seq.Add(1))
	}
	fr := replication.ForwardRequest{Kind: kind, ObjectID: obj, OpID: id, Revision: rev, Payload: b}
	local := func(context.Context) (*replication.ApplyResult, error) {
		op := replication.Operation{Version: replication.Version, Product: "trestle", Kind: kind, ID: id, ObjectID: obj, Revision: rev, Payload: b}
		return c.node.Propose(ctx, op)
	}
	forward := func(ctx context.Context) (*replication.ApplyResult, error) {
		f := c.auth.ForwardClient()
		if f == nil {
			return nil, fmt.Errorf("replication forward unavailable")
		}
		r, e := f(ctx, fr)
		if e == nil && r != nil {
			e = c.node.WaitApplied(ctx, r.Index)
		}
		return r, e
	}
	return c.auth.Route(ctx, local, forward)
}
func (c *Controller) PutCollection(ctx context.Context, d collections.Collection) (*replication.ApplyResult, error) {
	return c.Propose(ctx, KindCollectionPut, d.ID, 0, d)
}
func (c *Controller) DeleteCollection(ctx context.Context, name string) (*replication.ApplyResult, error) {
	return c.Propose(ctx, KindCollectionDelete, name, 0, nil)
}
func (c *Controller) PutRecord(ctx context.Context, r records.ReplicatedRecord) (*replication.ApplyResult, error) {
	return c.Propose(ctx, KindRecordPut, r.RecordID, r.Version, r)
}
func (c *Controller) DeleteRecord(ctx context.Context, r records.ReplicatedRecord) (*replication.ApplyResult, error) {
	return c.Propose(ctx, KindRecordDelete, r.RecordID, r.Version, r)
}
