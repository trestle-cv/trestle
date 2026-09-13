package cluster

import (
	"encoding/json"
	"net/http"
	"strings"

	"github.com/trestle-cv/trestle/internal/adminauth"
)

type HTTPHandler struct {
	Service   *Service
	Transport *Transport
	Auth      *adminauth.Handler
	Version   string
}

func (h *HTTPHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	if strings.HasPrefix(r.URL.Path, "/admin/v1/cluster/rpc/") {
		h.rpc(w, r)
		return
	}
	mutation := r.Method != http.MethodGet
	if _, ok := h.Auth.AuthorizeCapability(r, mutation, "*"); !ok {
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}
	switch {
	case r.Method == http.MethodGet && r.URL.Path == "/admin/v1/cluster/identity":
		v, e := h.Service.EnsureIdentity(r.Context(), h.Version)
		write(w, v, e)
	case r.Method == http.MethodGet && r.URL.Path == "/admin/v1/cluster/members":
		v, e := h.Service.Members(r.Context())
		write(w, v, e)
	case r.Method == http.MethodPost && r.URL.Path == "/admin/v1/cluster/invitations":
		inv, token, e := h.Service.Invite(r.Context())
		write(w, map[string]any{"invitation": inv, "token": token}, e)
	case r.Method == http.MethodGet && r.URL.Path == "/admin/v1/cluster/summary":
		h.aggregateSummary(w, r)
	case r.Method == http.MethodGet && r.URL.Path == "/admin/v1/cluster/compare":
		h.aggregateCompare(w, r)
	default:
		http.NotFound(w, r)
	}
}
func (h *HTTPHandler) rpc(w http.ResponseWriter, r *http.Request) {
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
