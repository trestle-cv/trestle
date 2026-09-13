package cluster

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	core "github.com/gantry-tools/gantry-core/propagation"
)

type propagationWire struct {
	Kinds     []string        `json:"kinds,omitempty"`
	Target    string          `json:"target,omitempty"`
	Envelopes []core.Envelope `json:"envelopes,omitempty"`
	PlanID    string          `json:"plan_id,omitempty"`
	Selector  core.Selector   `json:"selector,omitempty"`
	DryRun    bool            `json:"dry_run,omitempty"`
	Profile   *core.Profile   `json:"profile,omitempty"`
}

func propActor(adminID string) core.Actor { return core.Actor{Kind: "admin", ID: adminID} }
func (h *HTTPHandler) propagationAdmin(w http.ResponseWriter, r *http.Request, adminID string) {
	if h.Propagation == nil {
		http.Error(w, "propagation unavailable", 503)
		return
	}
	path := strings.TrimPrefix(r.URL.Path, "/admin/v1/cluster/propagation")
	switch {
	case r.Method == http.MethodGet && path == "/kinds":
		write(w, h.Propagation.Adapter.Kinds(), nil)
	case r.Method == http.MethodPost && path == "/export":
		var q propagationWire
		if !decodeProp(w, r, &q) {
			return
		}
		v, e := h.Propagation.Export(r.Context(), q.Kinds, propActor(adminID), q.Target)
		write(w, v, e)
	case r.Method == http.MethodPost && path == "/preview":
		var q propagationWire
		if !decodeProp(w, r, &q) {
			return
		}
		v, e := h.Propagation.Preview(r.Context(), q.Envelopes, propActor(adminID))
		write(w, v, e)
	case r.Method == http.MethodPost && path == "/apply":
		var q propagationWire
		if !decodeProp(w, r, &q) {
			return
		}
		if q.PlanID == "" {
			q.PlanID = fmt.Sprintf("plan-%d", time.Now().UnixNano())
		}
		v, e := h.Propagation.Apply(r.Context(), q.PlanID, q.Envelopes, propActor(adminID), q.Target)
		write(w, v, e)
	case r.Method == http.MethodPost && path == "/propagate":
		var q propagationWire
		if !decodeProp(w, r, &q) {
			return
		}
		h.propagate(w, r, q, propActor(adminID))
	case r.Method == http.MethodGet && path == "/history":
		v, e := h.Propagation.History(r.Context(), 50)
		write(w, v, e)
	case r.Method == http.MethodGet && path == "/profiles":
		v, e := h.Propagation.Profiles(r.Context())
		write(w, v, e)
	case r.Method == http.MethodPut && strings.HasPrefix(path, "/profiles/"):
		var p core.Profile
		if !decodeProp(w, r, &p) {
			return
		}
		p.ID = strings.TrimPrefix(path, "/profiles/")
		e := h.Propagation.SaveProfile(r.Context(), p)
		write(w, map[string]bool{"ok": e == nil}, e)
	default:
		http.NotFound(w, r)
	}
}
func decodeProp(w http.ResponseWriter, r *http.Request, v any) bool {
	if e := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20)).Decode(v); e != nil {
		http.Error(w, "invalid propagation request", 400)
		return false
	}
	return true
}
func (h *HTTPHandler) propagationRPC(w http.ResponseWriter, r *http.Request) {
	body, _, e := h.Transport.Authenticate(r, "cluster.propagation")
	if e != nil {
		http.Error(w, e.Error(), 401)
		return
	}
	var q propagationWire
	if e = json.Unmarshal(body, &q); e != nil {
		http.Error(w, "invalid propagation payload", 400)
		return
	}
	actor := core.Actor{Kind: "node", ID: r.Header.Get("X-Gantry-Node")}
	if strings.HasSuffix(r.URL.Path, "/preview") {
		v, e := h.Propagation.Preview(r.Context(), q.Envelopes, actor)
		write(w, v, e)
		return
	}
	if strings.HasSuffix(r.URL.Path, "/apply") {
		v, e := h.Propagation.Apply(r.Context(), q.PlanID, q.Envelopes, actor, actor.ID)
		write(w, v, e)
		return
	}
	http.NotFound(w, r)
}
func (h *HTTPHandler) remotePreview(ctx context.Context, node string, env []core.Envelope, actor core.Actor) (core.Preview, error) {
	b, _ := json.Marshal(propagationWire{Envelopes: env})
	resp, e := h.Transport.Do(ctx, node, http.MethodPost, "/api/cluster/v1/rpc/propagation/preview", "cluster.propagation", b)
	if e != nil {
		return core.Preview{}, e
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return core.Preview{}, fmt.Errorf("remote status %d", resp.StatusCode)
	}
	var v core.Preview
	e = json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&v)
	return v, e
}
func (h *HTTPHandler) remoteApply(ctx context.Context, node, plan string, env []core.Envelope, actor core.Actor) (core.ApplyBundleResult, error) {
	b, _ := json.Marshal(propagationWire{PlanID: plan, Envelopes: env})
	resp, e := h.Transport.Do(ctx, node, http.MethodPost, "/api/cluster/v1/rpc/propagation/apply", "cluster.propagation", b)
	if e != nil {
		return core.ApplyBundleResult{}, e
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return core.ApplyBundleResult{}, fmt.Errorf("remote status %d", resp.StatusCode)
	}
	var v core.ApplyBundleResult
	e = json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&v)
	return v, e
}
func (h *HTTPHandler) propagate(w http.ResponseWriter, r *http.Request, q propagationWire, actor core.Actor) {
	env, e := h.Propagation.Export(r.Context(), q.Kinds, actor, "members")
	if e != nil {
		write(w, nil, e)
		return
	}
	members, e := h.Service.Members(r.Context())
	if e != nil {
		write(w, nil, e)
		return
	}
	ms := make([]core.Member, 0, len(members))
	for _, m := range members {
		ms = append(ms, core.Member{ID: m.NodeID, Capabilities: m.Capabilities, Enabled: m.State == "active"})
	}
	nodes, e := core.Select(q.Selector, ms)
	if e != nil {
		write(w, nil, e)
		return
	}
	pre := core.PreviewNodes(r.Context(), nodes, env, actor, 4, h.remotePreview)
	blocked := false
	for _, x := range pre {
		if x.Error != "" || !x.Preview.Applicable {
			blocked = true
		}
	}
	if q.DryRun || blocked {
		write(w, map[string]any{"plan_id": q.PlanID, "preview": pre, "applicable": !blocked}, nil)
		return
	}
	if q.PlanID == "" {
		q.PlanID = fmt.Sprintf("plan-%d", time.Now().UnixNano())
	}
	ap := core.ApplyNodes(r.Context(), nodes, q.PlanID, env, actor, 4, h.remoteApply)
	write(w, map[string]any{"plan_id": q.PlanID, "preview": pre, "results": ap}, nil)
}

var _ = bytes.NewReader
