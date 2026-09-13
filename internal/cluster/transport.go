package cluster

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	core "github.com/gantry-tools/gantry-core/cluster"
	"github.com/trestle-cv/trestle/internal/store"
)

type Transport struct {
	db       store.Executor
	identity *Service
	client   *http.Client
	now      func() time.Time
}

func NewTransport(db store.Executor, identity *Service, client *http.Client) *Transport {
	if client == nil {
		client = &http.Client{Timeout: 10 * time.Second}
	}
	return &Transport{db: db, identity: identity, client: client, now: time.Now}
}

func (t *Transport) Authenticate(r *http.Request, requiredCapability string) ([]byte, string, error) {
	body, err := io.ReadAll(io.LimitReader(r.Body, core.MaxRequestBytes+1))
	if err != nil || int64(len(body)) > core.MaxRequestBytes {
		return nil, "", errors.New("cluster request too large")
	}
	env, err := core.ReadEnvelope(r.Header, t.now().UTC())
	if err != nil {
		return nil, "", err
	}
	secret := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
	if secret == "" {
		return nil, "", errors.New("cluster credential required")
	}
	var state string
	var protocol int
	var capsJSON string
	var inboundHash []byte
	if err = t.db.QueryRowContext(r.Context(), `SELECT state,protocol_version,capabilities_json,inbound_secret_hash FROM _trestle_cluster_members WHERE node_id=?`, env.NodeID).Scan(&state, &protocol, &capsJSON, &inboundHash); err != nil {
		return nil, "", errors.New("cluster member unavailable")
	}
	var caps []string
	_ = json.Unmarshal([]byte(capsJSON), &caps)
	_, err = core.VerifyIncoming(core.VerifyRequestInput{
		Material:           core.AuthMaterial{State: state, Protocol: protocol, Capabilities: caps, CurrentHash: inboundHash},
		RequiredCapability: requiredCapability, PresentedSecret: secret, Method: r.Method, RequestURI: r.URL.RequestURI(), Envelope: env, Body: body, Now: t.now().UTC(),
	})
	if err != nil {
		return nil, "", err
	}
	cutoff := t.now().UTC().Add(-2 * core.ClockSkew).Format(time.RFC3339Nano)
	_, _ = t.db.ExecContext(r.Context(), `DELETE FROM _trestle_cluster_nonces WHERE seen_at<?`, cutoff)
	if _, err = t.db.ExecContext(r.Context(), `INSERT INTO _trestle_cluster_nonces(node_id,nonce,seen_at) VALUES(?,?,?)`, env.NodeID, env.Nonce, t.now().UTC().Format(time.RFC3339Nano)); err != nil {
		return nil, "", errors.New("cluster replay rejected")
	}
	_, _ = t.db.ExecContext(r.Context(), `UPDATE _trestle_cluster_members SET last_seen_at=? WHERE node_id=?`, t.now().UTC().Format(time.RFC3339Nano), env.NodeID)
	return body, env.RequestID, nil
}

func (t *Transport) Do(ctx context.Context, nodeID, method, path, capability string, body []byte) (*http.Response, error) {
	if int64(len(body)) > core.MaxRequestBytes {
		return nil, errors.New("cluster request too large")
	}
	var endpoint, secret, state string
	var protocol int
	if err := t.db.QueryRowContext(ctx, `SELECT public_endpoint,outbound_secret,state,protocol_version FROM _trestle_cluster_members WHERE node_id=?`, nodeID).Scan(&endpoint, &secret, &state, &protocol); err != nil {
		return nil, err
	}
	if state != core.MemberActive || protocol != core.ProtocolVersion {
		return nil, errors.New("cluster member unavailable or incompatible")
	}
	u, err := url.Parse(endpoint)
	if err != nil || u.Scheme != "https" || u.Host == "" {
		return nil, errors.New("cluster endpoint must use https")
	}
	if !strings.HasPrefix(path, "/") {
		path = "/" + path
	}
	req, err := http.NewRequestWithContext(ctx, method, strings.TrimRight(endpoint, "/")+path, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	local, err := t.identity.EnsureIdentity(ctx, "")
	if err != nil {
		return nil, err
	}
	nonce, _ := core.NewSecret(18)
	requestID, _ := core.NewID("req_", 12)
	core.WriteEnvelope(req.Header, local.NodeID, secret, method, req.URL.RequestURI(), capability, core.ProtocolVersion, body, t.now().UTC(), nonce, requestID)
	req.Header.Set("Authorization", "Bearer "+secret)
	req.Header.Set("Content-Type", "application/json")
	started := t.now()
	resp, err := t.client.Do(req)
	if err == nil {
		_, _ = t.db.ExecContext(ctx, `UPDATE _trestle_cluster_members SET last_seen_at=?,last_latency_ms=? WHERE node_id=?`, t.now().UTC().Format(time.RFC3339Nano), t.now().Sub(started).Milliseconds(), nodeID)
	}
	return resp, err
}

type RemoteReader struct{ Transport *Transport }

func (r RemoteReader) Summary(ctx context.Context, nodeID string) (Summary, error) {
	var v Summary
	err := r.get(ctx, nodeID, "/admin/v1/cluster/rpc/summary", "cluster.trestle.summary", &v)
	return v, err
}
func (r RemoteReader) Comparison(ctx context.Context, nodeID string) (Comparison, error) {
	var v Comparison
	err := r.get(ctx, nodeID, "/admin/v1/cluster/rpc/compare", "cluster.trestle.compare", &v)
	return v, err
}
func (r RemoteReader) get(ctx context.Context, nodeID, path, capability string, out any) error {
	resp, err := r.Transport.Do(ctx, nodeID, http.MethodGet, path, capability, nil)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("remote status %d", resp.StatusCode)
	}
	return json.NewDecoder(io.LimitReader(resp.Body, core.MaxRequestBytes)).Decode(out)
}
