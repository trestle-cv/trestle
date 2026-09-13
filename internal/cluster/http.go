package cluster

import (
	"encoding/json"
	"net/http"
	"strings"

	core "github.com/gantry-tools/gantry-core/cluster"
	coreprop "github.com/gantry-tools/gantry-core/propagation"
	"github.com/trestle-cv/trestle/internal/adminauth"
)

type HTTPHandler struct {
	Service     *Service
	Transport   *Transport
	Auth        *adminauth.Handler
	Version     string
	Propagation *coreprop.Manager
}

func (h *HTTPHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	if strings.HasPrefix(r.URL.Path, "/api/cluster/v1/rpc/") {
		h.rpc(w, r)
		return
	}
	if r.Method == http.MethodPost && r.URL.Path == "/api/cluster/v1/join" {
		var in JoinSubmission
		if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20)).Decode(&in); err != nil {
			http.Error(w, "invalid join request", http.StatusBadRequest)
			return
		}
		v, e := h.Service.SubmitJoin(r.Context(), in)
		if e != nil {
			write(w, nil, e)
			return
		}
		w.WriteHeader(http.StatusAccepted)
		_ = json.NewEncoder(w).Encode(v)
		return
	}
	if r.Method == http.MethodGet && strings.HasPrefix(r.URL.Path, "/api/cluster/v1/join/") {
		id := strings.TrimPrefix(r.URL.Path, "/api/cluster/v1/join/")
		secret := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
		v, e := h.Service.PollJoin(r.Context(), id, secret)
		write(w, v, e)
		return
	}
	mutation := r.Method != http.MethodGet
	principal, ok := h.Auth.AuthorizeCapability(r, mutation, "*")
	if !ok {
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}
	switch {
	case r.Method == http.MethodGet && r.URL.Path == "/admin/v1/cluster/identity":
		v, e := h.Service.EnsureIdentity(r.Context(), h.Version)
		write(w, map[string]any{"identity": v, "fingerprint": v.Fingerprint()}, e)
	case r.Method == http.MethodGet && r.URL.Path == "/admin/v1/cluster/members":
		v, e := h.Service.Members(r.Context())
		write(w, v, e)
	case r.Method == http.MethodPost && r.URL.Path == "/admin/v1/cluster/invitations":
		inv, token, e := h.Service.Invite(r.Context())
		inv.Token = token
		if e == nil {
			e = h.Service.Audit(r.Context(), principal.AdminID, core.AuditInviteCreate, inv.ID, r.Header.Get("X-Trestle-Request-ID"))
		}
		write(w, inv, e)
	case r.Method == http.MethodGet && r.URL.Path == "/admin/v1/cluster/joins":
		v, e := h.Service.PendingJoins(r.Context())
		write(w, v, e)
	case r.Method == http.MethodPost && strings.HasPrefix(r.URL.Path, "/admin/v1/cluster/joins/"):
		rest := strings.TrimPrefix(r.URL.Path, "/admin/v1/cluster/joins/")
		parts := strings.Split(rest, "/")
		if len(parts) != 2 || (parts[1] != "approve" && parts[1] != "reject") {
			http.NotFound(w, r)
			return
		}
		e := h.Service.DecideJoin(r.Context(), parts[0], parts[1] == "approve")
		if e == nil {
			action := core.AuditJoinReject
			if parts[1] == "approve" {
				action = core.AuditJoinApprove
			}
			e = h.Service.Audit(r.Context(), principal.AdminID, action, parts[0], r.Header.Get("X-Trestle-Request-ID"))
		}
		write(w, map[string]any{"ok": e == nil}, e)
	case r.Method == http.MethodGet && r.URL.Path == "/admin/v1/cluster/outbound":
		v, e := h.Service.ListOutbound(r.Context())
		write(w, v, e)
	case r.Method == http.MethodPost && r.URL.Path == "/admin/v1/cluster/outbound":
		var in struct {
			URL   string `json:"url"`
			Token string `json:"token"`
		}
		if e := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20)).Decode(&in); e != nil {
			http.Error(w, "invalid outbound join", http.StatusBadRequest)
			return
		}
		v, e := h.Service.BeginOutbound(r.Context(), in.URL, in.Token, nil)
		if e == nil {
			e = h.Service.Audit(r.Context(), principal.AdminID, "cluster.join.begin", v.ID, r.Header.Get("X-Trestle-Request-ID"))
		}
		write(w, v, e)
	case r.Method == http.MethodPost && strings.HasPrefix(r.URL.Path, "/admin/v1/cluster/outbound/"):
		id := strings.TrimSuffix(strings.TrimPrefix(r.URL.Path, "/admin/v1/cluster/outbound/"), "/collect")
		v, e := h.Service.CollectOutbound(r.Context(), id, nil)
		write(w, v, e)
	case r.Method == http.MethodPost && strings.HasPrefix(r.URL.Path, "/admin/v1/cluster/members/"):
		rest := strings.TrimPrefix(r.URL.Path, "/admin/v1/cluster/members/")
		parts := strings.Split(rest, "/")
		if len(parts) != 2 {
			http.NotFound(w, r)
			return
		}
		var e error
		var v any = map[string]bool{"ok": true}
		switch parts[1] {
		case "enable":
			e = h.Service.SetEnabled(r.Context(), parts[0], true)
		case "disable":
			e = h.Service.SetEnabled(r.Context(), parts[0], false)
		case "revoke":
			e = h.Service.Revoke(r.Context(), parts[0])
		case "remove":
			e = h.Service.Remove(r.Context(), parts[0])
		case "rotate":
			var secret string
			secret, e = h.Service.Rotate(r.Context(), parts[0])
			v = map[string]any{"ok": e == nil, "credential": secret}
		default:
			http.NotFound(w, r)
			return
		}
		if e == nil {
			action := map[string]string{"enable": core.AuditMemberEnable, "disable": core.AuditMemberDisable, "rotate": core.AuditMemberRotate, "revoke": core.AuditMemberRevoke, "remove": core.AuditMemberRemove}[parts[1]]
			e = h.Service.Audit(r.Context(), principal.AdminID, action, parts[0], r.Header.Get("X-Trestle-Request-ID"))
		}
		write(w, v, e)
	case r.Method == http.MethodGet && r.URL.Path == "/admin/v1/cluster/audit":
		v, e := h.Service.RecentAudit(r.Context(), 25)
		write(w, v, e)
	case r.Method == http.MethodGet && r.URL.Path == "/admin/v1/cluster/summary":
		h.aggregateSummary(w, r)
	case r.Method == http.MethodGet && r.URL.Path == "/admin/v1/cluster/compare":
		h.aggregateCompare(w, r)
	case strings.HasPrefix(r.URL.Path, "/admin/v1/cluster/propagation"):
		h.propagationAdmin(w, r, principal.AdminID)
	default:
		http.NotFound(w, r)
	}
}
func (h *HTTPHandler) rpc(w http.ResponseWriter, r *http.Request) {
	if strings.Contains(r.URL.Path, "/propagation/") {
		h.propagationRPC(w, r)
		return
	}
	cap := "cluster.trestle.summary"
	if strings.HasSuffix(r.URL.Path, "/compare") {
		cap = "cluster.trestle.compare"
	}
	if _, _, e := h.Transport.Authenticate(r, cap); e != nil {
		http.Error(w, e.Error(), http.StatusUnauthorized)
		return
	}
	if strings.HasSuffix(r.URL.Path, "/summary") {
		v, e := h.Service.LocalSummary(r.Context())
		write(w, v, e)
		return
	}
	if strings.HasSuffix(r.URL.Path, "/compare") {
		v, e := h.Service.LocalComparison(r.Context())
		write(w, v, e)
		return
	}
	http.NotFound(w, r)
}
func (h *HTTPHandler) aggregateSummary(w http.ResponseWriter, r *http.Request) {
	local, e := h.Service.LocalSummary(r.Context())
	if e != nil {
		write(w, nil, e)
		return
	}
	members, e := h.Service.Members(r.Context())
	if e != nil {
		write(w, nil, e)
		return
	}
	remote := RemoteReader{h.Transport}
	v, e := Aggregate(r.Context(), local.NodeID, local, members, r.URL.Query().Get("target"), remote.Summary)
	write(w, v, e)
}
func (h *HTTPHandler) aggregateCompare(w http.ResponseWriter, r *http.Request) {
	local, e := h.Service.LocalComparison(r.Context())
	if e != nil {
		write(w, nil, e)
		return
	}
	members, e := h.Service.Members(r.Context())
	if e != nil {
		write(w, nil, e)
		return
	}
	remote := RemoteReader{h.Transport}
	v, e := Aggregate(r.Context(), local.NodeID, local, members, r.URL.Query().Get("target"), remote.Comparison)
	write(w, v, e)
}
func write(w http.ResponseWriter, v any, e error) {
	if e != nil {
		http.Error(w, e.Error(), http.StatusBadRequest)
		return
	}
	_ = json.NewEncoder(w).Encode(v)
}
