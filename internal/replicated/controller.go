package replicated

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/gantry-tools/gantry-core/replication"
	"github.com/trestle-cv/trestle/internal/collections"
	"github.com/trestle-cv/trestle/internal/records"
	"sync/atomic"
)

type Controller struct {
	auth  *replication.Authority
	node  *replication.Node
	seq   atomic.Uint64
	epoch int64
}

func NewController(n *replication.Node) *Controller {
	return &Controller{auth: replication.NewAuthority(), node: n, epoch: time.Now().UnixNano()}
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
		// Node- and process-scoped operation identity: the per-process counter
		// is prefixed with this node's raft ID and a process epoch so neither
		// concurrent proposers on different nodes nor a restart of the same
		// node (which would otherwise reuse the same IDs against the durable
		// applied map) can generate a colliding operation ID. A collision would
		// trip the durable same-ID/different-payload idempotency conflict and
		// poison the caller.
		id = fmt.Sprintf("trestle-%s-%d-%d", c.node.ID(), c.epoch, c.seq.Add(1))
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
