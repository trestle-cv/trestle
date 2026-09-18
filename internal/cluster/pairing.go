package cluster

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	core "github.com/gantry-tools/gantry-core/cluster"
)

type JoinRequest = core.JoinRequest
type JoinSubmission = core.JoinSubmission
type JoinReceipt = core.JoinReceipt
type PairingResult = core.PairingResult

type OutboundJoin struct {
	ID        string    `json:"id"`
	RemoteURL string    `json:"remote_url"`
	RequestID string    `json:"request_id"`
	State     string    `json:"state"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
	LastError string    `json:"last_error,omitempty"`
}

func (s *Service) SubmitJoin(ctx context.Context, in JoinSubmission) (JoinReceipt, error) {
	now := s.now().UTC()
	if err := core.ValidateJoinSubmissionWithPolicy(in, now, s.insecurePlaintext); err != nil {
		return JoinReceipt{}, err
	}
	local, err := s.EnsureIdentity(ctx, "")
	if err != nil {
		return JoinReceipt{}, err
	}
	if local.NodeID == in.Identity.NodeID || local.InstallationID == in.Identity.InstallationID {
		return JoinReceipt{}, errors.New("cannot pair node with itself")
	}
	if err = core.Compatible(ProtocolVersion, in.Identity.ProtocolVersion, DefaultCapabilities, in.Identity.Capabilities, ""); err != nil {
		return JoinReceipt{}, err
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return JoinReceipt{}, err
	}
	defer tx.Rollback()
	var inviteID, expiresText, state string
	if err = tx.QueryRowContext(ctx, `SELECT id,expires_at,state FROM _trestle_cluster_invitations WHERE token_hash=?`, core.SecretDigest(in.InvitationToken)).Scan(&inviteID, &expiresText, &state); err != nil {
		return JoinReceipt{}, errors.New("invitation unavailable")
	}
	expires, _ := time.Parse(time.RFC3339Nano, expiresText)
	if err = core.ValidateInvitation(core.Invitation{ID: inviteID, State: state, ExpiresAt: expires}, now); err != nil {
		return JoinReceipt{}, err
	}
	requestID, err := core.NewID("join_", 12)
	if err != nil {
		return JoinReceipt{}, err
	}
	requestSecret, err := core.NewSecret(32)
	if err != nil {
		return JoinReceipt{}, err
	}
	caps, _ := json.Marshal(core.NormalizeCapabilities(in.Identity.Capabilities))
	pub, err := base64.RawURLEncoding.DecodeString(in.Identity.PublicKey)
	if err != nil {
		return JoinReceipt{}, errors.New("invalid node public key")
	}
	requestExpires := now.Add(core.PairingLifetime)
	_, err = tx.ExecContext(ctx, `INSERT INTO _trestle_cluster_join_requests(id,request_secret_hash,invitation_id,node_id,installation_id,display_name,public_endpoint,public_key,capabilities_json,protocol_version,product_version,credential_for_local,state,expires_at,created_at) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`, requestID, core.SecretDigest(requestSecret), inviteID, in.Identity.NodeID, in.Identity.InstallationID, in.Identity.DisplayName, strings.TrimRight(in.Identity.PublicEndpoint, "/"), pub, string(caps), in.Identity.ProtocolVersion, in.Identity.ProductVersion, in.CredentialForHost, core.PairingPending, requestExpires.Format(time.RFC3339Nano), now.Format(time.RFC3339Nano))
	if err != nil {
		return JoinReceipt{}, err
	}
	if _, err = tx.ExecContext(ctx, `UPDATE _trestle_cluster_invitations SET state=?,used_at=? WHERE id=? AND state=?`, core.PairingUsed, now.Format(time.RFC3339Nano), inviteID, core.PairingPending); err != nil {
		return JoinReceipt{}, err
	}
	if err = tx.Commit(); err != nil {
		return JoinReceipt{}, err
	}
	return JoinReceipt{RequestID: requestID, RequestSecret: requestSecret, State: core.PairingPending}, nil
}

func (s *Service) PendingJoins(ctx context.Context) ([]JoinRequest, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT id,node_id,installation_id,display_name,public_endpoint,public_key,capabilities_json,protocol_version,product_version,state,expires_at,created_at FROM _trestle_cluster_join_requests WHERE state=? ORDER BY created_at`, core.PairingPending)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []JoinRequest
	for rows.Next() {
		v, err := scanTrestleJoin(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, v)
	}
	return out, rows.Err()
}

func scanTrestleJoin(scanner interface{ Scan(...any) error }) (JoinRequest, error) {
	var v JoinRequest
	var pub []byte
	var caps, expires, created string
	if err := scanner.Scan(&v.ID, &v.NodeID, &v.InstallationID, &v.DisplayName, &v.PublicEndpoint, &pub, &caps, &v.ProtocolVersion, &v.ProductVersion, &v.State, &expires, &created); err != nil {
		return v, err
	}
	v.PublicKey = base64.RawURLEncoding.EncodeToString(pub)
	_ = json.Unmarshal([]byte(caps), &v.Capabilities)
	v.Capabilities = core.NormalizeCapabilities(v.Capabilities)
	v.ExpiresAt, _ = time.Parse(time.RFC3339Nano, expires)
	v.CreatedAt, _ = time.Parse(time.RFC3339Nano, created)
	v.Fingerprint = (core.Identity{PublicKey: v.PublicKey}).Fingerprint()
	return v, nil
}

func (s *Service) DecideJoin(ctx context.Context, id string, approve bool) error {
	now := s.now().UTC()
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	var nodeID, installationID, name, endpoint, caps, product, credentialForLocal, expiresText string
	var public []byte
	var protocol int
	err = tx.QueryRowContext(ctx, `SELECT node_id,installation_id,display_name,public_endpoint,public_key,capabilities_json,protocol_version,product_version,credential_for_local,expires_at FROM _trestle_cluster_join_requests WHERE id=? AND state=?`, id, core.PairingPending).Scan(&nodeID, &installationID, &name, &endpoint, &public, &caps, &protocol, &product, &credentialForLocal, &expiresText)
	if err != nil {
		return errors.New("pending join request unavailable")
	}
	expires, _ := time.Parse(time.RFC3339Nano, expiresText)
	if !expires.After(now) {
		return errors.New("join request expired")
	}
	state := core.PairingRejected
	if approve {
		if err = core.Compatible(ProtocolVersion, protocol, DefaultCapabilities, decodeCaps(caps), ""); err != nil {
			return err
		}
		state = core.PairingApproved
		placeholder, _ := core.NewSecret(32)
		_, err = tx.ExecContext(ctx, `INSERT INTO _trestle_cluster_members(node_id,installation_id,display_name,public_endpoint,public_key,capabilities_json,protocol_version,product_version,state,outbound_secret,inbound_secret_hash,credential_version,created_at,paired_at) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?) ON CONFLICT(node_id) DO UPDATE SET installation_id=excluded.installation_id,display_name=excluded.display_name,public_endpoint=excluded.public_endpoint,public_key=excluded.public_key,capabilities_json=excluded.capabilities_json,protocol_version=excluded.protocol_version,product_version=excluded.product_version,state='active',outbound_secret=excluded.outbound_secret,inbound_secret_hash=excluded.inbound_secret_hash,credential_version=_trestle_cluster_members.credential_version+1,paired_at=excluded.paired_at,revoked_at=NULL`, nodeID, installationID, name, endpoint, public, caps, protocol, product, core.MemberActive, credentialForLocal, core.SecretDigest(placeholder), 1, now.Format(time.RFC3339Nano), now.Format(time.RFC3339Nano))
		if err != nil {
			return err
		}
	}
	_, err = tx.ExecContext(ctx, `UPDATE _trestle_cluster_join_requests SET state=?,decided_at=? WHERE id=? AND state=?`, state, now.Format(time.RFC3339Nano), id, core.PairingPending)
	if err != nil {
		return err
	}
	return tx.Commit()
}

func decodeCaps(raw string) []string { var v []string; _ = json.Unmarshal([]byte(raw), &v); return v }

func (s *Service) PollJoin(ctx context.Context, id, secret string) (PairingResult, error) {
	host, err := s.EnsureIdentity(ctx, "")
	if err != nil {
		return PairingResult{}, err
	}
	now := s.now().UTC()
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return PairingResult{}, err
	}
	defer tx.Rollback()
	var state, nodeID, expiresText string
	var consumed sql.NullString
	err = tx.QueryRowContext(ctx, `SELECT state,node_id,expires_at,response_consumed_at FROM _trestle_cluster_join_requests WHERE id=? AND request_secret_hash=?`, id, core.SecretDigest(secret)).Scan(&state, &nodeID, &expiresText, &consumed)
	if err != nil {
		return PairingResult{}, errors.New("join request unavailable")
	}
	expires, _ := time.Parse(time.RFC3339Nano, expiresText)
	if state == core.PairingPending && !expires.After(now) {
		return PairingResult{State: core.PairingExpired}, nil
	}
	if state == core.PairingRejected {
		return PairingResult{State: core.PairingRejected}, nil
	}
	if state != core.PairingApproved {
		return PairingResult{State: state}, nil
	}
	if consumed.Valid {
		return PairingResult{}, errors.New("pairing result already collected")
	}
	credential, err := core.NewSecret(32)
	if err != nil {
		return PairingResult{}, err
	}
	if _, err = tx.ExecContext(ctx, `UPDATE _trestle_cluster_members SET inbound_secret_hash=?,credential_version=credential_version+1 WHERE node_id=?`, core.SecretDigest(credential), nodeID); err != nil {
		return PairingResult{}, err
	}
	if _, err = tx.ExecContext(ctx, `UPDATE _trestle_cluster_join_requests SET state=?,response_consumed_at=? WHERE id=?`, core.PairingUsed, now.Format(time.RFC3339Nano), id); err != nil {
		return PairingResult{}, err
	}
	if err = tx.Commit(); err != nil {
		return PairingResult{}, err
	}
	return PairingResult{State: core.PairingApproved, Remote: &host, Credential: credential}, nil
}

func (s *Service) AcceptRemote(ctx context.Context, remote core.Identity, outboundCredential, inboundCredential string) error {
	if err := remote.ValidateEndpoint(s.insecurePlaintext); err != nil {
		return err
	}
	if outboundCredential == "" || inboundCredential == "" {
		return errors.New("incomplete pairing result")
	}
	pub, err := base64.RawURLEncoding.DecodeString(remote.PublicKey)
	if err != nil {
		return err
	}
	caps, _ := json.Marshal(core.NormalizeCapabilities(remote.Capabilities))
	now := s.now().UTC().Format(time.RFC3339Nano)
	_, err = s.db.ExecContext(ctx, `INSERT INTO _trestle_cluster_members(node_id,installation_id,display_name,public_endpoint,public_key,capabilities_json,protocol_version,product_version,state,outbound_secret,inbound_secret_hash,credential_version,created_at,paired_at) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?) ON CONFLICT(node_id) DO UPDATE SET installation_id=excluded.installation_id,display_name=excluded.display_name,public_endpoint=excluded.public_endpoint,public_key=excluded.public_key,capabilities_json=excluded.capabilities_json,protocol_version=excluded.protocol_version,product_version=excluded.product_version,state='active',outbound_secret=excluded.outbound_secret,inbound_secret_hash=excluded.inbound_secret_hash,credential_version=_trestle_cluster_members.credential_version+1,paired_at=excluded.paired_at,revoked_at=NULL`, remote.NodeID, remote.InstallationID, remote.DisplayName, remote.PublicEndpoint, pub, string(caps), remote.ProtocolVersion, remote.ProductVersion, core.MemberActive, outboundCredential, core.SecretDigest(inboundCredential), 1, now, now)
	return err
}

func (s *Service) BeginOutbound(ctx context.Context, remoteURL, invitationToken string, client *http.Client) (OutboundJoin, error) {
	remoteURL = strings.TrimRight(strings.TrimSpace(remoteURL), "/")
	if err := validateEndpointScheme(remoteURL, s.insecurePlaintext); err != nil {
		return OutboundJoin{}, err
	}
	local, err := s.EnsureIdentity(ctx, "")
	if err != nil {
		return OutboundJoin{}, err
	}
	if local.PublicEndpoint == "" {
		return OutboundJoin{}, errors.New("configure this Trestle public HTTPS endpoint before joining a cluster")
	}
	localInbound, err := core.NewSecret(32)
	if err != nil {
		return OutboundJoin{}, err
	}
	payload, _ := json.Marshal(JoinSubmission{InvitationToken: invitationToken, Identity: local, CredentialForHost: localInbound})
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, remoteURL+"/api/cluster/v1/join", bytes.NewReader(payload))
	if err != nil {
		return OutboundJoin{}, err
	}
	req.Header.Set("Content-Type", "application/json")
	if client == nil {
		client = &http.Client{Timeout: 15 * time.Second}
	}
	resp, err := client.Do(req)
	if err != nil {
		return OutboundJoin{}, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusAccepted {
		return OutboundJoin{}, fmt.Errorf("remote join returned %s", resp.Status)
	}
	var receipt JoinReceipt
	if err = json.NewDecoder(io.LimitReader(resp.Body, core.MaxRequestBytes)).Decode(&receipt); err != nil {
		return OutboundJoin{}, err
	}
	oid, err := core.NewID("out_", 12)
	if err != nil {
		return OutboundJoin{}, err
	}
	now := s.now().UTC()
	_, err = s.db.ExecContext(ctx, `INSERT INTO _trestle_cluster_outbound_joins(id,remote_url,request_id,request_secret,local_inbound_credential,state,created_at,updated_at,last_error) VALUES(?,?,?,?,?,?,?,?,?)`, oid, remoteURL, receipt.RequestID, receipt.RequestSecret, localInbound, core.PairingPending, now.Format(time.RFC3339Nano), now.Format(time.RFC3339Nano), "")
	if err != nil {
		return OutboundJoin{}, err
	}
	return OutboundJoin{ID: oid, RemoteURL: remoteURL, RequestID: receipt.RequestID, State: core.PairingPending, CreatedAt: now, UpdatedAt: now}, nil
}

func (s *Service) ListOutbound(ctx context.Context) ([]OutboundJoin, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT id,remote_url,request_id,state,created_at,updated_at,last_error FROM _trestle_cluster_outbound_joins ORDER BY created_at`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []OutboundJoin
	for rows.Next() {
		var v OutboundJoin
		var c, u string
		if err = rows.Scan(&v.ID, &v.RemoteURL, &v.RequestID, &v.State, &c, &u, &v.LastError); err != nil {
			return nil, err
		}
		v.CreatedAt, _ = time.Parse(time.RFC3339Nano, c)
		v.UpdatedAt, _ = time.Parse(time.RFC3339Nano, u)
		out = append(out, v)
	}
	return out, rows.Err()
}

func (s *Service) CollectOutbound(ctx context.Context, id string, client *http.Client) (OutboundJoin, error) {
	var v OutboundJoin
	var requestSecret, localInbound, created, updated string
	err := s.db.QueryRowContext(ctx, `SELECT id,remote_url,request_id,request_secret,local_inbound_credential,state,created_at,updated_at,last_error FROM _trestle_cluster_outbound_joins WHERE id=?`, id).Scan(&v.ID, &v.RemoteURL, &v.RequestID, &requestSecret, &localInbound, &v.State, &created, &updated, &v.LastError)
	if err != nil {
		return v, errors.New("outbound join unavailable")
	}
	v.CreatedAt, _ = time.Parse(time.RFC3339Nano, created)
	v.UpdatedAt, _ = time.Parse(time.RFC3339Nano, updated)
	if v.State != core.PairingPending {
		return v, nil
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, v.RemoteURL+"/api/cluster/v1/join/"+url.PathEscape(v.RequestID), nil)
	if err != nil {
		return v, err
	}
	req.Header.Set("Authorization", "Bearer "+requestSecret)
	if client == nil {
		client = &http.Client{Timeout: 15 * time.Second}
	}
	resp, err := client.Do(req)
	if err != nil {
		return v, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return v, fmt.Errorf("remote pairing status returned %s", resp.Status)
	}
	var result PairingResult
	if err = json.NewDecoder(io.LimitReader(resp.Body, core.MaxRequestBytes)).Decode(&result); err != nil {
		return v, err
	}
	now := s.now().UTC()
	switch result.State {
	case core.PairingApproved:
		if result.Remote == nil || result.Credential == "" {
			return v, errors.New("remote approval incomplete")
		}
		if err = s.AcceptRemote(ctx, *result.Remote, result.Credential, localInbound); err != nil {
			return v, err
		}
		v.State = core.PairingApproved
	case core.PairingRejected, core.PairingExpired:
		v.State = result.State
	default:
		v.State = core.PairingPending
	}
	v.UpdatedAt = now
	_, err = s.db.ExecContext(ctx, `UPDATE _trestle_cluster_outbound_joins SET state=?,updated_at=?,last_error='' WHERE id=?`, v.State, now.Format(time.RFC3339Nano), id)
	return v, err
}
