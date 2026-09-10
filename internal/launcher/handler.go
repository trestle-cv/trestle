package launcher

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"

	corelauncher "github.com/gantry-tools/gantry-core/launcher"
	"github.com/trestle-cv/trestle/internal/adminauth"
	"github.com/trestle-cv/trestle/internal/store"
)

const Version = 1

var idPattern = regexp.MustCompile(`^[A-Za-z0-9._-]{1,128}$`)

type Instance struct {
	ID     string `json:"id,omitempty"`
	Name   string `json:"name"`
	Domain string `json:"domain"`
	Port   *int   `json:"port,omitempty"`
}
type instanceView struct {
	ID     string `json:"id"`
	Name   string `json:"name"`
	Domain string `json:"domain"`
	Port   *int   `json:"port,omitempty"`
	AppURL string `json:"appUrl"`
}
type Document struct {
	Version   int        `json:"version"`
	Product   string     `json:"product,omitempty"`
	Instances []Instance `json:"instances"`
}
type View struct {
	Version   int            `json:"version"`
	Product   string         `json:"product"`
	Instances []instanceView `json:"instances"`
}

type Handler struct {
	db     store.Executor
	auth   *adminauth.Handler
	static http.Handler
}

func New(db any, auth *adminauth.Handler, static http.Handler) *Handler {
	return &Handler{db: store.Adapt(db), auth: auth, static: static}
}

func (h *Handler) Root(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" {
		http.NotFound(w, r)
		return
	}
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		http.Error(w, "method", 405)
		return
	}
	items, err := h.load(r.Context())
	if err != nil {
		http.Error(w, "launcher unavailable", 500)
		return
	}
	if r.URL.Query().Has("config") {
		if h.auth == nil {
			corelauncher.WriteAccessError(w, http.StatusUnauthorized, "Trestle", "T", "#f2a66f")
			return
		}
		if _, ok := h.auth.Authorize(r, false); !ok {
			corelauncher.WriteAccessError(w, http.StatusUnauthorized, "Trestle", "T", "#f2a66f")
			return
		}
		if _, ok := h.auth.AuthorizeCapability(r, false, "launcher.configure.all"); !ok {
			corelauncher.WriteAccessError(w, http.StatusForbidden, "Trestle", "T", "#f2a66f")
			return
		}
		h.page(w, r)
		return
	}
	switch len(items) {
	case 0:
		http.Redirect(w, r, "/app/", 302)
	case 1:
		target, err := appURL(items[0])
		if err != nil {
			http.Error(w, "invalid launcher configuration", 500)
			return
		}
		http.Redirect(w, r, target, 302)
	default:
		h.page(w, r)
	}
}
func (h *Handler) page(w http.ResponseWriter, r *http.Request) {
	clone := r.Clone(r.Context())
	clone.URL.Path = "/launcher.html"
	clone.URL.RawPath = ""
	w.Header().Set("Cache-Control", "no-store")
	h.static.ServeHTTP(w, clone)
}
func (h *Handler) Instances(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method", 405)
		return
	}
	items, err := h.load(r.Context())
	if err != nil {
		http.Error(w, "launcher unavailable", 500)
		return
	}
	view, err := makeView(items)
	if err != nil {
		http.Error(w, "invalid launcher configuration", 500)
		return
	}
	output(w, view)
}
func (h *Handler) Config(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPut {
		http.Error(w, "method", 405)
		return
	}
	principal, ok := h.auth.AuthorizeCapability(r, true, "launcher.configure.all")
	if !ok {
		http.Error(w, "forbidden", 403)
		return
	}
	var doc Document
	dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20))
	dec.DisallowUnknownFields()
	if dec.Decode(&doc) != nil || ensureEOF(dec) != nil {
		http.Error(w, "invalid json", 400)
		return
	}
	items, err := normalize(doc)
	if err != nil {
		http.Error(w, err.Error(), 400)
		return
	}
	if err = h.replaceBy(r.Context(), items, principal.AdminID, r.Header.Get("X-Trestle-Request-ID")); err != nil {
		http.Error(w, "unable to save launcher configuration", 500)
		return
	}
	view, _ := makeView(items)
	output(w, view)
}
func (h *Handler) load(ctx context.Context) ([]Instance, error) {
	rows, err := h.db.QueryContext(ctx, "SELECT id,name,domain,port FROM _trestle_launcher_instances ORDER BY position")
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Instance
	for rows.Next() {
		var v Instance
		var p *int
		if err := rows.Scan(&v.ID, &v.Name, &v.Domain, &p); err != nil {
			return nil, err
		}
		v.Port = p
		out = append(out, v)
	}
	return out, rows.Err()
}
func (h *Handler) replace(ctx context.Context, items []Instance) error {
	return h.replaceBy(ctx, items, "", "")
}
func (h *Handler) replaceBy(ctx context.Context, items []Instance, actorID, requestID string) error {
	tx, err := h.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if _, err = tx.ExecContext(ctx, "DELETE FROM _trestle_launcher_instances"); err != nil {
		return err
	}
	for i, v := range items {
		if _, err = tx.ExecContext(ctx, "INSERT INTO _trestle_launcher_instances(id,position,name,domain,port) VALUES(?,?,?,?,?)", v.ID, i, v.Name, v.Domain, v.Port); err != nil {
			return err
		}
	}
	if actorID != "" {
		details, _ := json.Marshal(map[string]int{"instances": len(items)})
		if _, err = tx.ExecContext(ctx, "INSERT INTO _trestle_audit(occurred_at,actor_kind,actor_id,action,target,outcome,request_id,details_json) VALUES(?,?,?,?,?,?,?,?)", time.Now().UTC().Format(time.RFC3339Nano), "admin", actorID, "launcher.configuration.replace", "launcher", "success", requestID, string(details)); err != nil {
			return err
		}
	}
	return tx.Commit()
}
func normalize(doc Document) ([]Instance, error) {
	if doc.Version != Version {
		return nil, errors.New("unsupported launcher configuration version")
	}
	if doc.Product != "" && doc.Product != "trestle" {
		return nil, errors.New("launcher configuration is for another product")
	}
	if doc.Instances == nil {
		return nil, errors.New("instances must be an array")
	}
	if len(doc.Instances) > 1000 {
		return nil, errors.New("too many launcher instances")
	}
	seen := map[string]bool{}
	out := make([]Instance, 0, len(doc.Instances))
	for _, v := range doc.Instances {
		v.Name = strings.TrimSpace(v.Name)
		if v.Name == "" || len(v.Name) > 100 {
			return nil, errors.New("every instance requires a name of at most 100 characters")
		}
		d, err := normalizeDomain(v.Domain)
		if err != nil {
			return nil, err
		}
		v.Domain = d
		if v.Port != nil && (*v.Port < 1 || *v.Port > 65535) {
			return nil, errors.New("instance ports must be from 1 to 65535")
		}
		v.ID = strings.TrimSpace(v.ID)
		if !idPattern.MatchString(v.ID) || seen[v.ID] {
			v.ID = adminauth.NewID("instance")
		}
		seen[v.ID] = true
		out = append(out, v)
	}
	return out, nil
}
func normalizeDomain(raw string) (string, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" || len(raw) > 512 || strings.IndexFunc(raw, func(r rune) bool { return r <= ' ' }) >= 0 {
		return "", errors.New("every instance requires a valid domain or IP")
	}
	probe := raw
	if !strings.Contains(raw, "://") {
		probe = "https://" + raw
	}
	u, err := url.Parse(probe)
	if err != nil || u.Hostname() == "" || (u.Scheme != "http" && u.Scheme != "https") || u.User != nil || u.RawQuery != "" || u.Fragment != "" || (u.Path != "" && u.Path != "/") {
		return "", errors.New("every instance requires a valid HTTP(S) domain or IP without a path")
	}
	return strings.TrimSuffix(raw, "/"), nil
}
func appURL(v Instance) (string, error) {
	raw := v.Domain
	if !strings.Contains(raw, "://") {
		u, err := url.Parse("https://" + raw)
		if err != nil {
			return "", err
		}
		scheme := "https"
		host := u.Hostname()
		if host == "localhost" || strings.HasSuffix(host, ".localhost") || net.ParseIP(host) != nil {
			scheme = "http"
		}
		raw = scheme + "://" + raw
	}
	u, err := url.Parse(raw)
	if err != nil {
		return "", err
	}
	if v.Port != nil {
		u.Host = net.JoinHostPort(u.Hostname(), fmt.Sprint(*v.Port))
	}
	u.Path = "/app/"
	u.RawQuery = ""
	u.Fragment = ""
	return u.String(), nil
}
func makeView(items []Instance) (View, error) {
	out := View{Version: Version, Product: "trestle", Instances: make([]instanceView, 0, len(items))}
	for _, v := range items {
		u, err := appURL(v)
		if err != nil {
			return View{}, err
		}
		out.Instances = append(out.Instances, instanceView{v.ID, v.Name, v.Domain, v.Port, u})
	}
	return out, nil
}
func ensureEOF(d *json.Decoder) error {
	var x any
	err := d.Decode(&x)
	if errors.Is(err, io.EOF) {
		return nil
	}
	return errors.New("trailing json")
}
func output(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	_ = json.NewEncoder(w).Encode(v)
}
