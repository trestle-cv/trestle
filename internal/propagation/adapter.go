package propagation

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"time"

	core "github.com/gantry-tools/gantry-core/propagation"
	"github.com/trestle-cv/trestle/internal/collections"
	"github.com/trestle-cv/trestle/internal/store"
)

type Adapter struct {
	db  store.Executor
	now func() time.Time
}

func New(db any) *Adapter { return &Adapter{db: store.Adapt(db), now: time.Now} }
func (a *Adapter) Kinds() []core.KindDescriptor {
	return []core.KindDescriptor{{Kind: "access-policy", Label: "Access policies", SchemaVersion: 1, Reversible: true}, {Kind: "function-definition", Label: "Functions", SchemaVersion: 1, Reversible: true}, {Kind: "project-setting", Label: "Project settings", SchemaVersion: 1, Reversible: true}, {Kind: "schema", Label: "Collection schemas", SchemaVersion: 1, Reversible: true}, {Kind: "webhook-definition", Label: "Webhooks", SchemaVersion: 1, Reversible: true}}
}
func want(kinds []string, kind string) bool {
	if len(kinds) == 0 {
		return true
	}
	for _, k := range kinds {
		if k == kind {
			return true
		}
	}
	return false
}
func revTime(v string) int64 {
	t, err := time.Parse(time.RFC3339Nano, v)
	if err != nil || t.UnixNano() < 1 {
		return 1
	}
	return t.UnixNano()
}
func mk(kind, id string, rev int64, source, target string, actor core.Actor, payload any, secrets []core.SecretRef, deps []string) (core.Envelope, error) {
	b, err := json.Marshal(payload)
	if err != nil {
		return core.Envelope{}, err
	}
	e := core.Envelope{Kind: kind, ID: id, SchemaVersion: 1, Revision: max1(rev), SourceNode: source, CreatedAt: time.Now().UTC(), Target: target, Conflict: core.ConflictSourceWins, Actor: actor, Payload: b, Secrets: secrets, Dependencies: deps}
	if err = e.Validate(); err != nil {
		return core.Envelope{}, err
	}
	return e, nil
}
func max1(v int64) int64 {
	if v < 1 {
		return 1
	}
	return v
}

type accessPayload struct {
	CollectionID string `json:"collection_id"`
	Operation    string `json:"operation"`
	Expression   string `json:"expression"`
}
type webhookPayload struct {
	Name    string `json:"name"`
	URL     string `json:"url"`
	Topics  string `json:"topics"`
	Enabled bool   `json:"enabled"`
}
type functionPayload struct {
	Name           string `json:"name"`
	Provider       string `json:"provider"`
	Target         string `json:"target"`
	Region         string `json:"region"`
	Topics         string `json:"topics"`
	CallbackScopes string `json:"callback_scopes"`
	Enabled        bool   `json:"enabled"`
}
type settingPayload struct {
	RegistrationPolicy string `json:"registration_policy"`
}

func (a *Adapter) Export(ctx context.Context, kinds []string, actor core.Actor, target string) ([]core.Envelope, error) {
	source := "trestle-local"
	out := []core.Envelope{}
	if want(kinds, "schema") {
		defs, err := collections.ListDefinitions(ctx, a.db)
		if err != nil {
			return nil, err
		}
		for _, d := range defs {
			e, err := mk("schema", d.Name, revTime(d.UpdatedAt), source, target, core.Actor{Kind: actor.Kind, ID: actor.ID, Permission: "collections.update"}, d, nil, nil)
			if err != nil {
				return nil, err
			}
			out = append(out, e)
		}
	}
	if want(kinds, "access-policy") {
		rows, err := a.db.QueryContext(ctx, "SELECT collection_id,operation,expression,updated_at FROM _trestle_collection_rules ORDER BY collection_id,operation")
		if err != nil {
			return nil, err
		}
		for rows.Next() {
			var p accessPayload
			var updated string
			if err := rows.Scan(&p.CollectionID, &p.Operation, &p.Expression, &updated); err != nil {
				rows.Close()
				return nil, err
			}
			e, err := mk("access-policy", p.CollectionID+":"+p.Operation, revTime(updated), source, target, core.Actor{Kind: actor.Kind, ID: actor.ID, Permission: "roles.update"}, p, nil, []string{"schema:" + p.CollectionID})
			if err != nil {
				rows.Close()
				return nil, err
			}
			out = append(out, e)
		}
		if err := rows.Close(); err != nil {
			return nil, err
		}
	}
	if want(kinds, "project-setting") {
		var p settingPayload
		var setAt string
		err := a.db.QueryRowContext(ctx, "SELECT policy,set_at FROM _trestle_app_registration_policy WHERE id=1").Scan(&p.RegistrationPolicy, &setAt)
		if err == nil {
			e, err := mk("project-setting", "registration-policy", revTime(setAt), source, target, core.Actor{Kind: actor.Kind, ID: actor.ID, Permission: "settings.update"}, p, nil, nil)
			if err != nil {
				return nil, err
			}
			out = append(out, e)
		} else if !errors.Is(err, sql.ErrNoRows) {
			return nil, err
		}
	}
	if want(kinds, "webhook-definition") {
		rows, err := a.db.QueryContext(ctx, "SELECT id,name,url,topics,secret_cipher,enabled,updated_at FROM _trestle_webhooks ORDER BY id")
		if err != nil {
			return nil, err
		}
		for rows.Next() {
			var id string
			var p webhookPayload
			var secret []byte
			var enabledRaw any
			var updated string
			if err := rows.Scan(&id, &p.Name, &p.URL, &p.Topics, &secret, &enabledRaw, &updated); err != nil {
				rows.Close()
				return nil, err
			}
			v, err := a.db.Dialect().DecodeBoolean(enabledRaw)
			if err != nil {
				rows.Close()
				return nil, err
			}
			p.Enabled = v
			refs := []core.SecretRef{}
			if len(secret) > 0 {
				refs = append(refs, core.SecretRef{Name: "trestle.webhook." + id, Required: true})
			}
			e, err := mk("webhook-definition", id, revTime(updated), source, target, core.Actor{Kind: actor.Kind, ID: actor.ID, Permission: "webhooks.update"}, p, refs, nil)
			if err != nil {
				rows.Close()
				return nil, err
			}
			out = append(out, e)
		}
		if err := rows.Close(); err != nil {
			return nil, err
		}
	}
	if want(kinds, "function-definition") {
		rows, err := a.db.QueryContext(ctx, "SELECT id,name,provider,target,region,topics,callback_scopes,enabled,updated_at FROM _trestle_functions ORDER BY id")
		if err != nil {
			return nil, err
		}
		for rows.Next() {
			var id string
			var p functionPayload
			var enabledRaw any
			var updated string
			if err := rows.Scan(&id, &p.Name, &p.Provider, &p.Target, &p.Region, &p.Topics, &p.CallbackScopes, &enabledRaw, &updated); err != nil {
				rows.Close()
				return nil, err
			}
			v, err := a.db.Dialect().DecodeBoolean(enabledRaw)
			if err != nil {
				rows.Close()
				return nil, err
			}
			p.Enabled = v
			e, err := mk("function-definition", id, revTime(updated), source, target, core.Actor{Kind: actor.Kind, ID: actor.ID, Permission: "functions.update"}, p, nil, nil)
			if err != nil {
				rows.Close()
				return nil, err
			}
			out = append(out, e)
		}
		if err := rows.Close(); err != nil {
			return nil, err
		}
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Kind == out[j].Kind {
			return out[i].ID < out[j].ID
		}
		return out[i].Kind < out[j].Kind
	})
	return out, nil
}
func (a *Adapter) Snapshot(ctx context.Context, kinds []string) (map[string]core.ObjectState, error) {
	envs, err := a.Export(ctx, kinds, core.Actor{}, "local")
	if err != nil {
		return nil, err
	}
	out := map[string]core.ObjectState{}
	for _, e := range envs {
		out[e.Kind+"/"+e.ID] = core.ObjectState{Existing: core.Existing{Kind: e.Kind, ID: e.ID, Digest: e.Digest, Revision: e.Revision}, Payload: e.Payload, Reversible: true}
	}
	return out, nil
}
func (a *Adapter) TargetState(ctx context.Context, src []core.Envelope, actor core.Actor) (core.TargetState, error) {
	snap, err := a.Snapshot(ctx, nil)
	if err != nil {
		return core.TargetState{}, err
	}
	existing := map[string]core.Existing{}
	deps := map[string]bool{}
	for k, v := range snap {
		existing[k] = v.Existing
		if v.Existing.Kind == "schema" {
			var d collections.Collection
			if json.Unmarshal(v.Payload, &d) == nil {
				deps["schema:"+d.ID] = true
			}
		}
	}
	secrets := core.MapSecrets{}
	for _, e := range src {
		if e.Kind != "webhook-definition" {
			continue
		}
		var secret []byte
		err := a.db.QueryRowContext(ctx, "SELECT secret_cipher FROM _trestle_webhooks WHERE id=?", e.ID).Scan(&secret)
		if err == nil && len(secret) > 0 {
			secrets["trestle.webhook."+e.ID] = true
		} else if err != nil && !errors.Is(err, sql.ErrNoRows) {
			return core.TargetState{}, err
		}
	}
	perms := map[string]bool{}
	for _, e := range src {
		if e.Actor.Permission != "" {
			perms[e.Actor.Permission] = true
		}
	}
	return core.TargetState{Existing: existing, SupportedSchemas: map[string]int{"schema": 1, "access-policy": 1, "project-setting": 1, "webhook-definition": 1, "function-definition": 1}, Dependencies: deps, Secrets: secrets, Permissions: perms}, nil
}
func (a *Adapter) Apply(ctx context.Context, e core.Envelope) (core.AppliedRevision, error) {
	if err := ValidateEnvelope(e); err != nil {
		return core.AppliedRevision{}, err
	}
	switch e.Kind {
	case "schema":
		var d collections.Collection
		if err := json.Unmarshal(e.Payload, &d); err != nil {
			return core.AppliedRevision{}, err
		}
		var before string
		_ = a.db.QueryRowContext(ctx, "SELECT updated_at FROM _trestle_collections WHERE name=?", d.Name).Scan(&before)
		if err := collections.ApplyDefinition(ctx, a.db, d); err != nil {
			return core.AppliedRevision{}, err
		}
		return core.AppliedRevision{Kind: e.Kind, ID: e.ID, Before: revTime(before), After: e.Revision, Reversible: true}, nil
	case "access-policy":
		var p accessPayload
		if err := json.Unmarshal(e.Payload, &p); err != nil {
			return core.AppliedRevision{}, err
		}
		now := a.now().UTC().Format(time.RFC3339Nano)
		_, err := a.db.ExecContext(ctx, "INSERT INTO _trestle_collection_rules(collection_id,operation,expression,updated_at) VALUES(?,?,?,?) ON CONFLICT(collection_id,operation) DO UPDATE SET expression=excluded.expression,updated_at=excluded.updated_at", p.CollectionID, p.Operation, p.Expression, now)
		if err != nil {
			return core.AppliedRevision{}, err
		}
		return core.AppliedRevision{Kind: e.Kind, ID: e.ID, After: e.Revision, Reversible: true}, nil
	case "project-setting":
		var p settingPayload
		if err := json.Unmarshal(e.Payload, &p); err != nil {
			return core.AppliedRevision{}, err
		}
		_, err := a.db.ExecContext(ctx, "INSERT INTO _trestle_app_registration_policy(id,policy,set_at) VALUES(1,?,?) ON CONFLICT(id) DO UPDATE SET policy=excluded.policy,set_at=excluded.set_at", p.RegistrationPolicy, a.now().UTC().Format(time.RFC3339Nano))
		if err != nil {
			return core.AppliedRevision{}, err
		}
		return core.AppliedRevision{Kind: e.Kind, ID: e.ID, After: e.Revision, Reversible: true}, nil
	case "webhook-definition":
		var p webhookPayload
		if err := json.Unmarshal(e.Payload, &p); err != nil {
			return core.AppliedRevision{}, err
		}
		var secret []byte
		err := a.db.QueryRowContext(ctx, "SELECT secret_cipher FROM _trestle_webhooks WHERE id=?", e.ID).Scan(&secret)
		if errors.Is(err, sql.ErrNoRows) {
			if len(e.Secrets) > 0 {
				return core.AppliedRevision{}, fmt.Errorf("webhook %s requires destination secret", e.ID)
			}
			secret = []byte{}
		} else if err != nil {
			return core.AppliedRevision{}, err
		}
		now := a.now().UTC().Format(time.RFC3339Nano)
		_, err = a.db.ExecContext(ctx, "INSERT INTO _trestle_webhooks(id,name,url,topics,secret_cipher,enabled,created_at,updated_at) VALUES(?,?,?,?,?,?,?,?) ON CONFLICT(id) DO UPDATE SET name=excluded.name,url=excluded.url,topics=excluded.topics,enabled=excluded.enabled,updated_at=excluded.updated_at", e.ID, p.Name, p.URL, p.Topics, secret, a.db.Dialect().Boolean(p.Enabled), now, now)
		if err != nil {
			return core.AppliedRevision{}, err
		}
		return core.AppliedRevision{Kind: e.Kind, ID: e.ID, After: e.Revision, Reversible: true}, nil
	case "function-definition":
		var p functionPayload
		if err := json.Unmarshal(e.Payload, &p); err != nil {
			return core.AppliedRevision{}, err
		}
		now := a.now().UTC().Format(time.RFC3339Nano)
		_, err := a.db.ExecContext(ctx, "INSERT INTO _trestle_functions(id,name,provider,target,region,topics,callback_scopes,enabled,created_at,updated_at) VALUES(?,?,?,?,?,?,?,?,?,?) ON CONFLICT(id) DO UPDATE SET name=excluded.name,provider=excluded.provider,target=excluded.target,region=excluded.region,topics=excluded.topics,callback_scopes=excluded.callback_scopes,enabled=excluded.enabled,updated_at=excluded.updated_at", e.ID, p.Name, p.Provider, p.Target, p.Region, p.Topics, p.CallbackScopes, a.db.Dialect().Boolean(p.Enabled), now, now)
		if err != nil {
			return core.AppliedRevision{}, err
		}
		return core.AppliedRevision{Kind: e.Kind, ID: e.ID, After: e.Revision, Reversible: true}, nil
	}
	return core.AppliedRevision{}, fmt.Errorf("unsupported kind %q", e.Kind)
}
func (a *Adapter) Restore(ctx context.Context, s core.ObjectState) error {
	if s.Existing.Revision == 0 && len(s.Payload) == 0 {
		switch s.Existing.Kind {
		case "schema":
			return collections.DeleteDefinition(ctx, a.db, s.Existing.ID)
		case "access-policy":
			parts := splitAccessID(s.Existing.ID)
			_, err := a.db.ExecContext(ctx, "DELETE FROM _trestle_collection_rules WHERE collection_id=? AND operation=?", parts[0], parts[1])
			return err
		case "project-setting":
			_, err := a.db.ExecContext(ctx, "DELETE FROM _trestle_app_registration_policy WHERE id=1")
			return err
		case "webhook-definition":
			_, err := a.db.ExecContext(ctx, "DELETE FROM _trestle_webhooks WHERE id=?", s.Existing.ID)
			return err
		case "function-definition":
			_, err := a.db.ExecContext(ctx, "DELETE FROM _trestle_functions WHERE id=?", s.Existing.ID)
			return err
		}
	}
	e := core.Envelope{Kind: s.Existing.Kind, ID: s.Existing.ID, SchemaVersion: 1, Revision: max1(s.Existing.Revision), SourceNode: "rollback", Target: "local", Conflict: core.ConflictSourceWins, Payload: s.Payload}
	switch e.Kind {
	case "schema":
		e.Actor.Permission = "collections.update"
	case "access-policy":
		e.Actor.Permission = "roles.update"
	case "project-setting":
		e.Actor.Permission = "settings.update"
	case "webhook-definition":
		e.Actor.Permission = "webhooks.update"
	case "function-definition":
		e.Actor.Permission = "functions.update"
	}
	_, err := a.Apply(ctx, e)
	return err
}
func splitAccessID(id string) [2]string {
	for i := 0; i < len(id); i++ {
		if id[i] == ':' {
			return [2]string{id[:i], id[i+1:]}
		}
	}
	return [2]string{id, ""}
}
