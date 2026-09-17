package cluster

import (
	"context"
	"crypto/ed25519"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"errors"
	"sort"
	"strings"
	"time"

	core "github.com/gantry-tools/gantry-core/cluster"
	"github.com/trestle-cv/trestle/internal/store"
)

const ProtocolVersion = core.ProtocolVersion

var DefaultCapabilities = []string{"cluster.health", "cluster.trestle.summary", "cluster.trestle.compare", "cluster.propagation", "replication"}

type Service struct {
	db  store.Executor
	now func() time.Time
}

func New(db store.Executor) *Service { return &Service{db: db, now: time.Now} }

type Member struct {
	core.Identity
	State             string `json:"state"`
	Health            string `json:"health"`
	Compatible        bool   `json:"compatible"`
	CredentialVersion int    `json:"credential_version"`
	LastLatencyMS     *int64 `json:"last_latency_ms,omitempty"`
}

type PairingBundle struct {
	Identity   core.Identity `json:"identity"`
	Credential string        `json:"credential"`
}

type Summary struct {
	NodeID      string `json:"node_id"`
	Collections int    `json:"collections"`
	JobsPending int    `json:"jobs_pending"`
	Webhooks    int    `json:"webhooks"`
	Functions   int    `json:"functions"`
}

type Comparison struct {
	NodeID        string `json:"node_id"`
	SchemaVersion int    `json:"schema_version"`
	Collections   int    `json:"collections"`
	Roles         int    `json:"roles"`
	JobsPending   int    `json:"jobs_pending"`
	Webhooks      int    `json:"webhooks"`
	Functions     int    `json:"functions"`
}

func (s *Service) EnsureIdentity(ctx context.Context, productVersion string) (core.Identity, error) {
	var i core.Identity
	var pub, priv []byte
	var caps, created string
	err := s.db.QueryRowContext(ctx, `SELECT node_id,installation_id,display_name,public_endpoint,public_key,private_key,capabilities_json,protocol_version,product_version,created_at FROM _trestle_cluster_identity WHERE singleton=1`).Scan(&i.NodeID, &i.InstallationID, &i.DisplayName, &i.PublicEndpoint, &pub, &priv, &caps, &i.ProtocolVersion, &i.ProductVersion, &created)
	if err == nil {
		i.PublicKey = base64.RawURLEncoding.EncodeToString(pub)
		_ = json.Unmarshal([]byte(caps), &i.Capabilities)
		i.CreatedAt, _ = time.Parse(time.RFC3339Nano, created)
		return i, nil
	}
	if !errors.Is(err, sql.ErrNoRows) {
		return core.Identity{}, err
	}
	g, err := core.GenerateIdentity("tr_", "ti_", DefaultCapabilities, ProtocolVersion, productVersion, s.now().UTC())
	if err != nil {
		return core.Identity{}, err
	}
	pub, _ = base64.RawURLEncoding.DecodeString(g.Identity.PublicKey)
	capsB, _ := json.Marshal(g.Identity.Capabilities)
	_, err = s.db.ExecContext(ctx, `INSERT INTO _trestle_cluster_identity(singleton,node_id,installation_id,public_key,private_key,capabilities_json,protocol_version,product_version,created_at) VALUES(1,?,?,?,?,?,?,?,?)`, g.Identity.NodeID, g.Identity.InstallationID, pub, []byte(ed25519.PrivateKey(g.PrivateKey)), string(capsB), ProtocolVersion, productVersion, g.Identity.CreatedAt.Format(time.RFC3339Nano))
	if err != nil {
		return core.Identity{}, err
	}
	return g.Identity, nil
}

func (s *Service) UpdateIdentity(ctx context.Context, name, endpoint, version string) (core.Identity, error) {
	if endpoint != "" && !strings.HasPrefix(endpoint, "https://") {
		return core.Identity{}, errors.New("cluster public endpoint must use https")
	}
	if _, err := s.EnsureIdentity(ctx, version); err != nil {
		return core.Identity{}, err
	}
	_, err := s.db.ExecContext(ctx, `UPDATE _trestle_cluster_identity SET display_name=?,public_endpoint=?,product_version=? WHERE singleton=1`, strings.TrimSpace(name), strings.TrimRight(endpoint, "/"), version)
	if err != nil {
		return core.Identity{}, err
	}
	return s.EnsureIdentity(ctx, version)
}

func (s *Service) Invite(ctx context.Context) (core.Invitation, string, error) {
	inv, token, err := core.NewInvitation(s.now().UTC())
	if err != nil {
		return inv, "", err
	}
	_, err = s.db.ExecContext(ctx, `INSERT INTO _trestle_cluster_invitations(id,token_hash,state,created_at,expires_at) VALUES(?,?,?,?,?)`, inv.ID, core.SecretDigest(token), inv.State, inv.CreatedAt.Format(time.RFC3339Nano), inv.ExpiresAt.Format(time.RFC3339Nano))
	return inv, token, err
}

func (s *Service) Pair(ctx context.Context, token string, remote core.Identity) (PairingBundle, error) {
	if err := remote.Validate(); err != nil {
		return PairingBundle{}, err
	}
	now := s.now().UTC()
	var id, state, expires string
	var hash []byte
	err := s.db.QueryRowContext(ctx, `SELECT id,token_hash,state,expires_at FROM _trestle_cluster_invitations WHERE token_hash=?`, core.SecretDigest(token)).Scan(&id, &hash, &state, &expires)
	if err != nil {
		return PairingBundle{}, err
	}
	exp, _ := time.Parse(time.RFC3339Nano, expires)
	if err = core.ValidateInvitation(core.Invitation{ID: id, State: state, ExpiresAt: exp}, now); err != nil {
		return PairingBundle{}, err
	}
	if err = core.Compatible(ProtocolVersion, remote.ProtocolVersion, DefaultCapabilities, remote.Capabilities, ""); err != nil {
		return PairingBundle{}, err
	}
	outbound, err := core.NewSecret(core.MinimumCredentialBytes)
	if err != nil {
		return PairingBundle{}, err
	}
	inbound, err := core.NewSecret(core.MinimumCredentialBytes)
	if err != nil {
		return PairingBundle{}, err
	}
	pub, _ := base64.RawURLEncoding.DecodeString(remote.PublicKey)
	caps, _ := json.Marshal(core.NormalizeCapabilities(remote.Capabilities))
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return PairingBundle{}, err
	}
	defer tx.Rollback()
	if _, err = tx.ExecContext(ctx, `INSERT INTO _trestle_cluster_members(node_id,installation_id,display_name,public_endpoint,public_key,capabilities_json,protocol_version,product_version,state,outbound_secret,inbound_secret_hash,created_at,paired_at) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)`, remote.NodeID, remote.InstallationID, remote.DisplayName, remote.PublicEndpoint, pub, string(caps), remote.ProtocolVersion, remote.ProductVersion, core.MemberActive, outbound, core.SecretDigest(inbound), now.Format(time.RFC3339Nano), now.Format(time.RFC3339Nano)); err != nil {
		return PairingBundle{}, err
	}
	if _, err = tx.ExecContext(ctx, `UPDATE _trestle_cluster_invitations SET state=?,used_at=? WHERE id=? AND state=?`, core.PairingUsed, now.Format(time.RFC3339Nano), id, core.PairingPending); err != nil {
		return PairingBundle{}, err
	}
	if err = tx.Commit(); err != nil {
		return PairingBundle{}, err
	}
	local, err := s.EnsureIdentity(ctx, "")
	if err != nil {
		return PairingBundle{}, err
	}
	return PairingBundle{Identity: local, Credential: inbound}, nil
}

func (s *Service) AddMember(ctx context.Context, remote core.Identity, outbound, inbound string) error {
	if err := core.Compatible(ProtocolVersion, remote.ProtocolVersion, DefaultCapabilities, remote.Capabilities, ""); err != nil {
		return err
	}
	now := s.now().UTC()
	pub, _ := base64.RawURLEncoding.DecodeString(remote.PublicKey)
	caps, _ := json.Marshal(core.NormalizeCapabilities(remote.Capabilities))
	_, err := s.db.ExecContext(ctx, `INSERT INTO _trestle_cluster_members(node_id,installation_id,display_name,public_endpoint,public_key,capabilities_json,protocol_version,product_version,state,outbound_secret,inbound_secret_hash,created_at,paired_at) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)`, remote.NodeID, remote.InstallationID, remote.DisplayName, remote.PublicEndpoint, pub, string(caps), remote.ProtocolVersion, remote.ProductVersion, core.MemberActive, outbound, core.SecretDigest(inbound), now.Format(time.RFC3339Nano), now.Format(time.RFC3339Nano))
	return err
}

func (s *Service) Members(ctx context.Context) ([]Member, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT node_id,installation_id,display_name,public_endpoint,public_key,capabilities_json,protocol_version,product_version,state,created_at,paired_at,last_seen_at,last_latency_ms,credential_version FROM _trestle_cluster_members ORDER BY node_id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []Member{}
	now := s.now().UTC()
	for rows.Next() {
		var m Member
		var pub []byte
		var caps, created, paired string
		var seen sql.NullString
		var latency sql.NullInt64
		if err = rows.Scan(&m.NodeID, &m.InstallationID, &m.DisplayName, &m.PublicEndpoint, &pub, &caps, &m.ProtocolVersion, &m.ProductVersion, &m.State, &created, &paired, &seen, &latency, &m.CredentialVersion); err != nil {
			return nil, err
		}
		m.PublicKey = base64.RawURLEncoding.EncodeToString(pub)
		_ = json.Unmarshal([]byte(caps), &m.Capabilities)
		m.CreatedAt, _ = time.Parse(time.RFC3339Nano, created)
		if seen.Valid {
			t, _ := time.Parse(time.RFC3339Nano, seen.String)
			m.LastSeenAt = &t
		}
		if latency.Valid {
			v := latency.Int64
			m.LastLatencyMS = &v
		}
		m.Compatible = core.Compatible(ProtocolVersion, m.ProtocolVersion, DefaultCapabilities, m.Capabilities, "") == nil
		m.Health = health(m, now)
		out = append(out, m)
	}
	return out, rows.Err()
}
func health(m Member, now time.Time) string {
	if m.State == core.MemberDisabled {
		return core.HealthDisabled
	}
	if m.State == core.MemberRevoked {
		return core.HealthRevoked
	}
	if !m.Compatible {
		return core.HealthDegraded
	}
	if m.LastSeenAt == nil || now.Sub(*m.LastSeenAt) > 10*time.Minute {
		return core.HealthOffline
	}
	if now.Sub(*m.LastSeenAt) > 2*time.Minute {
		return core.HealthDegraded
	}
	return core.HealthOnline
}
func (s *Service) SetEnabled(ctx context.Context, id string, enabled bool) error {
	state := core.MemberDisabled
	if enabled {
		state = core.MemberActive
	}
	r, err := s.db.ExecContext(ctx, `UPDATE _trestle_cluster_members SET state=? WHERE node_id=? AND state!=?`, state, id, core.MemberRevoked)
	if err != nil {
		return err
	}
	n, _ := r.RowsAffected()
	if n != 1 {
		return errors.New("cluster member unavailable")
	}
	return nil
}
func (s *Service) Revoke(ctx context.Context, id string) error {
	r, err := s.db.ExecContext(ctx, `UPDATE _trestle_cluster_members SET state=?,revoked_at=? WHERE node_id=? AND state!=?`, core.MemberRevoked, s.now().UTC().Format(time.RFC3339Nano), id, core.MemberRevoked)
	if err != nil {
		return err
	}
	n, _ := r.RowsAffected()
	if n != 1 {
		return errors.New("cluster member unavailable")
	}
	return nil
}
func (s *Service) Remove(ctx context.Context, id string) error {
	r, err := s.db.ExecContext(ctx, `DELETE FROM _trestle_cluster_members WHERE node_id=? AND state=?`, id, core.MemberRevoked)
	if err != nil {
		return err
	}
	n, _ := r.RowsAffected()
	if n != 1 {
		return errors.New("revoke member before removal")
	}
	return nil
}
func (s *Service) Rotate(ctx context.Context, id string) (string, error) {
	sec, err := core.NewSecret(core.MinimumCredentialBytes)
	if err != nil {
		return "", err
	}
	r, err := s.db.ExecContext(ctx, `UPDATE _trestle_cluster_members SET outbound_secret=?,credential_version=credential_version+1 WHERE node_id=? AND state=?`, sec, id, core.MemberActive)
	if err != nil {
		return "", err
	}
	n, _ := r.RowsAffected()
	if n != 1 {
		return "", errors.New("cluster member unavailable")
	}
	return sec, nil
}

func (s *Service) LocalSummary(ctx context.Context) (Summary, error) {
	i, err := s.EnsureIdentity(ctx, "")
	if err != nil {
		return Summary{}, err
	}
	q := []struct {
		p *int
		s string
		a []any
	}{}
	v := Summary{NodeID: i.NodeID}
	q = []struct {
		p *int
		s string
		a []any
	}{{&v.Collections, `SELECT COUNT(*) FROM _trestle_collections`, nil}, {&v.JobsPending, `SELECT COUNT(*) FROM _trestle_jobs WHERE status IN ('pending','running')`, nil}, {&v.Webhooks, `SELECT COUNT(*) FROM _trestle_webhooks WHERE enabled=?`, []any{s.db.Dialect().Boolean(true)}}, {&v.Functions, `SELECT COUNT(*) FROM _trestle_functions WHERE enabled=?`, []any{s.db.Dialect().Boolean(true)}}}
	for _, x := range q {
		if err = s.db.QueryRowContext(ctx, x.s, x.a...).Scan(x.p); err != nil {
			return Summary{}, err
		}
	}
	return v, nil
}
func (s *Service) LocalComparison(ctx context.Context) (Comparison, error) {
	i, err := s.EnsureIdentity(ctx, "")
	if err != nil {
		return Comparison{}, err
	}
	v := Comparison{NodeID: i.NodeID, SchemaVersion: store.CurrentVersion}
	qs := []struct {
		p *int
		s string
	}{{&v.Collections, `SELECT COUNT(*) FROM _trestle_collections`}, {&v.Roles, `SELECT COUNT(*) FROM _trestle_roles`}, {&v.JobsPending, `SELECT COUNT(*) FROM _trestle_jobs WHERE status IN ('pending','running')`}, {&v.Webhooks, `SELECT COUNT(*) FROM _trestle_webhooks`}, {&v.Functions, `SELECT COUNT(*) FROM _trestle_functions`}}
	for _, x := range qs {
		if err = s.db.QueryRowContext(ctx, x.s).Scan(x.p); err != nil {
			return Comparison{}, err
		}
	}
	return v, nil
}

type PeerReader interface {
	Summary(context.Context, string) (Summary, error)
	Comparison(context.Context, string) (Comparison, error)
}

func Aggregate[T any](ctx context.Context, localID string, local T, members []Member, target string, read func(context.Context, string) (T, error)) (core.Report[T], error) {
	parsed, err := core.ParseTarget(target)
	if err != nil {
		return core.Report[T]{}, err
	}
	req, _ := core.NewID("fan_", 10)
	results := []core.NodeResult[T]{}
	if parsed.Kind != core.TargetMembers && (parsed.Kind != core.TargetNode || parsed.NodeID == localID) {
		v := local
		results = append(results, core.NodeResult[T]{NodeID: localID, OwnerNode: localID, OK: true, Value: &v})
	}
	ids := []string{}
	for _, m := range members {
		if m.State != core.MemberActive {
			continue
		}
		if parsed.Kind == core.TargetLocal {
			continue
		}
		if parsed.Kind == core.TargetNode && m.NodeID != parsed.NodeID {
			continue
		}
		ids = append(ids, m.NodeID)
	}
	results = append(results, core.FanOut(ctx, ids, 4, read)...)
	sort.Slice(results, func(i, j int) bool { return results[i].NodeID < results[j].NodeID })
	return core.Report[T]{RequestID: req, Partial: core.IsPartial(results), Results: results}, nil
}
