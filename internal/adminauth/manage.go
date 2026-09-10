package adminauth

import (
	"context"
	"database/sql"
	"encoding/json"
	"net/http"
	"strings"

	coreauth "github.com/gantry-tools/gantry-core/auth"
	"github.com/trestle-cv/trestle/internal/store"
)

func (h *Handler) ManagePage(static http.Handler) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/manage/" {
			http.NotFound(w, r)
			return
		}
		if r.Method != http.MethodGet && r.Method != http.MethodHead {
			http.Error(w, "method", 405)
			return
		}
		allowed := false
		for _, capability := range []string{"accounts.manage", "roles.manage", "sessions.manage", "authentication.manage", "launcher.configure.all"} {
			if _, ok := h.AuthorizeCapability(r, false, capability); ok {
				allowed = true
				break
			}
		}
		if !allowed {
			http.Redirect(w, r, "/app/?return=%2Fmanage%2F", 302)
			return
		}
		clone := r.Clone(r.Context())
		clone.URL.Path = "/manage.html"
		clone.URL.RawPath = ""
		w.Header().Set("Cache-Control", "no-store")
		static.ServeHTTP(w, clone)
	}
}

var capabilityCatalog = []coreauth.CapabilityInfo{
	{Key: "accounts.manage", Group: "Administration", Label: "Manage users"},
	{Key: "roles.manage", Group: "Administration", Label: "Manage roles"},
	{Key: "sessions.manage", Group: "Administration", Label: "Manage sessions"},
	{Key: "authentication.manage", Group: "Administration", Label: "Manage authentication"},
	{Key: "launcher.view", Group: "Launcher", Label: "View launcher"},
	{Key: "launcher.configure.self", Group: "Launcher", Label: "Configure own launcher"},
	{Key: "launcher.configure.all", Group: "Launcher", Label: "Configure launcher"},
	{Key: "launcher.propagate", Group: "Launcher", Label: "Propagate launcher config"},
	{Key: "audit.read", Group: "Administration", Label: "Read audit log"},
	{Key: "settings.manage", Group: "Trestle", Label: "Manage product settings"},
}

func knownCapability(value string) bool {
	for _, v := range capabilityCatalog {
		if v.Key == value {
			return true
		}
	}
	return false
}

type managedUser struct {
	ID        string   `json:"id"`
	Email     string   `json:"email"`
	Enabled   bool     `json:"enabled"`
	Roles     []string `json:"roles"`
	CreatedAt string   `json:"createdAt"`
}
type managedRole struct {
	ID           string   `json:"id"`
	Name         string   `json:"name"`
	Capabilities []string `json:"capabilities"`
	BuiltIn      bool     `json:"builtIn"`
}
type userMutation struct {
	Action   string   `json:"action"`
	ID       string   `json:"id"`
	Email    string   `json:"email"`
	Password string   `json:"password"`
	Enabled  *bool    `json:"enabled"`
	Roles    []string `json:"roles"`
}

func (h *Handler) manageUsers(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodPost {
		h.mutateUser(w, r)
		return
	}
	if r.Method != http.MethodGet {
		http.Error(w, "method", 405)
		return
	}
	allowed := false
	for _, capability := range []string{"accounts.manage", "sessions.manage", "authentication.manage"} {
		if _, ok := h.AuthorizeCapability(r, false, capability); ok {
			allowed = true
			break
		}
	}
	if !allowed {
		writeError(w, 403, "authorization_denied", "A user-management capability is required.")
		return
	}
	rows, err := h.db.QueryContext(r.Context(), "SELECT id,email,disabled_at,created_at FROM _trestle_admins ORDER BY email")
	if err != nil {
		writeError(w, 500, "internal_error", "The request could not be completed.")
		return
	}
	out := []managedUser{}
	for rows.Next() {
		var v managedUser
		var disabled sql.NullString
		if rows.Scan(&v.ID, &v.Email, &disabled, &v.CreatedAt) != nil {
			writeError(w, 500, "internal_error", "The request could not be completed.")
			return
		}
		v.Enabled = !disabled.Valid
		out = append(out, v)
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		writeError(w, 500, "internal_error", "The request could not be completed.")
		return
	}
	rows.Close()
	for i := range out {
		roles, err := h.userRoles(r, out[i].ID)
		if err != nil {
			writeError(w, 500, "internal_error", "The request could not be completed.")
			return
		}
		out[i].Roles = roles
	}
	writeJSON(w, 200, map[string]any{"accounts": out})
}

func (h *Handler) mutateUser(w http.ResponseWriter, r *http.Request) {
	var input userMutation
	if !decodeJSON(w, r, &input) {
		return
	}
	required := "accounts.manage"
	if input.Action == "revoke-sessions" {
		required = "sessions.manage"
	}
	if input.Action == "reset-password" {
		required = "authentication.manage"
	}
	principal, ok := h.AuthorizeCapability(r, true, required)
	if !ok {
		writeError(w, 403, "authorization_denied", "The required capability and CSRF token are required.")
		return
	}
	input.Email, _ = normalizeEmail(input.Email)
	input.Roles = coreauth.DedupeStrings(input.Roles)
	tx, err := h.db.BeginTx(r.Context(), nil)
	if err != nil {
		writeError(w, 500, "internal_error", "The request could not be completed.")
		return
	}
	defer tx.Rollback()
	now := h.now().UTC().Format("2006-01-02T15:04:05.999999999Z07:00")
	switch input.Action {
	case "create":
		if input.Email == "" || len(input.Roles) == 0 {
			writeError(w, 422, "validation_failed", "Email and at least one role are required.")
			return
		}
		hash, err := hashPassword(input.Password)
		if err != nil {
			writeError(w, 422, "validation_failed", err.Error())
			return
		}
		if !rolesExist(r.Context(), tx, input.Roles) {
			writeError(w, 422, "validation_failed", "An assigned role does not exist.")
			return
		}
		id := NewID("adm")
		if _, err = tx.ExecContext(r.Context(), "INSERT INTO _trestle_admins(id,email,password_hash,created_at) VALUES(?,?,?,?)", id, input.Email, hash, now); err == nil {
			err = replaceRoles(r.Context(), tx, id, input.Roles)
		}
	case "update":
		if input.ID == "" || len(input.Roles) == 0 || !rolesExist(r.Context(), tx, input.Roles) {
			writeError(w, 422, "validation_failed", "A user and valid roles are required.")
			return
		}
		enabled := true
		if input.Enabled != nil {
			enabled = *input.Enabled
		}
		if !enabled || !contains(input.Roles, "administrator") {
			safe, checkErr := canDemote(r.Context(), tx, input.ID)
			if checkErr != nil || !safe {
				writeError(w, 409, "administrator_required", "Trestle must retain an enabled password-backed administrator.")
				return
			}
		}
		var disabled any
		if !enabled {
			disabled = now
		}
		if input.Email != "" {
			_, err = tx.ExecContext(r.Context(), "UPDATE _trestle_admins SET email=?,disabled_at=? WHERE id=?", input.Email, disabled, input.ID)
		} else {
			_, err = tx.ExecContext(r.Context(), "UPDATE _trestle_admins SET disabled_at=? WHERE id=?", disabled, input.ID)
		}
		if err == nil {
			err = replaceRoles(r.Context(), tx, input.ID, input.Roles)
		}
	case "reset-password":
		hash, hashErr := hashPassword(input.Password)
		if hashErr != nil {
			writeError(w, 422, "validation_failed", hashErr.Error())
			return
		}
		_, err = tx.ExecContext(r.Context(), "UPDATE _trestle_admins SET password_hash=? WHERE id=?", hash, input.ID)
		if err == nil {
			_, err = tx.ExecContext(r.Context(), "UPDATE _trestle_admin_sessions SET revoked_at=? WHERE admin_id=? AND id<>? AND revoked_at IS NULL", now, input.ID, principal.SessionID)
		}
	case "revoke-sessions":
		_, err = tx.ExecContext(r.Context(), "UPDATE _trestle_admin_sessions SET revoked_at=? WHERE admin_id=? AND id<>? AND revoked_at IS NULL", now, input.ID, principal.SessionID)
	default:
		writeError(w, 400, "unsupported_action", "The user action is not supported.")
		return
	}
	if err == nil {
		details, _ := json.Marshal(map[string]string{"action": input.Action})
		_, err = tx.ExecContext(r.Context(), "INSERT INTO _trestle_audit(occurred_at,actor_kind,actor_id,action,target,outcome,request_id,details_json) VALUES(?,?,?,?,?,?,?,?)", now, "admin", principal.AdminID, "accounts.manage", input.ID, "success", r.Header.Get("X-Trestle-Request-ID"), string(details))
	}
	if err != nil || tx.Commit() != nil {
		writeError(w, 409, "update_failed", "The user could not be updated.")
		return
	}
	w.WriteHeader(http.StatusNoContent)
}
func rolesExist(ctx context.Context, tx store.Transaction, roles []string) bool {
	for _, role := range roles {
		var count int
		if tx.QueryRowContext(ctx, "SELECT count(*) FROM _trestle_roles WHERE id=?", role).Scan(&count) != nil || count != 1 {
			return false
		}
	}
	return true
}
func replaceRoles(ctx context.Context, tx store.Transaction, id string, roles []string) error {
	if _, err := tx.ExecContext(ctx, "DELETE FROM _trestle_admin_roles WHERE admin_id=?", id); err != nil {
		return err
	}
	for _, role := range roles {
		if _, err := tx.ExecContext(ctx, "INSERT INTO _trestle_admin_roles(admin_id,role_id) VALUES(?,?)", id, role); err != nil {
			return err
		}
	}
	return nil
}
func canDemote(ctx context.Context, tx store.Transaction, id string) (bool, error) {
	var isAdmin, count int
	if err := tx.QueryRowContext(ctx, "SELECT count(*) FROM _trestle_admin_roles WHERE admin_id=? AND role_id='administrator'", id).Scan(&isAdmin); err != nil {
		return false, err
	}
	if isAdmin == 0 {
		return true, nil
	}
	if err := tx.QueryRowContext(ctx, "SELECT count(*) FROM _trestle_admins a JOIN _trestle_admin_roles ar ON ar.admin_id=a.id WHERE ar.role_id='administrator' AND a.disabled_at IS NULL AND a.id<>?", id).Scan(&count); err != nil {
		return false, err
	}
	return count > 0, nil
}
func contains(values []string, want string) bool {
	for _, v := range values {
		if v == want {
			return true
		}
	}
	return false
}
func (h *Handler) userRoles(r *http.Request, id string) ([]string, error) {
	rows, err := h.db.QueryContext(r.Context(), "SELECT role_id FROM _trestle_admin_roles WHERE admin_id=? ORDER BY role_id", id)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []string{}
	for rows.Next() {
		var s string
		if err := rows.Scan(&s); err != nil {
			return nil, err
		}
		out = append(out, s)
	}
	return out, rows.Err()
}
func (h *Handler) manageRoles(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodGet {
		if _, ok := h.AuthorizeCapability(r, false, "roles.manage"); !ok {
			writeError(w, 403, "authorization_denied", "The roles.manage capability is required.")
			return
		}
		rows, err := h.db.QueryContext(r.Context(), "SELECT id,name,capabilities_json,built_in FROM _trestle_roles ORDER BY built_in DESC,name")
		if err != nil {
			writeError(w, 500, "internal_error", "The request could not be completed.")
			return
		}
		defer rows.Close()
		out := []managedRole{}
		for rows.Next() {
			var v managedRole
			var raw string
			if rows.Scan(&v.ID, &v.Name, &raw, &v.BuiltIn) != nil || json.Unmarshal([]byte(raw), &v.Capabilities) != nil {
				writeError(w, 500, "internal_error", "The request could not be completed.")
				return
			}
			out = append(out, v)
		}
		writeJSON(w, 200, map[string]any{"roles": out, "capabilities": capabilityCatalog})
		return
	}
	if r.Method != http.MethodPut {
		http.Error(w, "method", 405)
		return
	}
	if _, ok := h.AuthorizeCapability(r, true, "roles.manage"); !ok {
		writeError(w, 403, "authorization_denied", "The roles.manage capability and CSRF token are required.")
		return
	}
	var v managedRole
	if !decodeJSON(w, r, &v) {
		return
	}
	v.ID = strings.TrimSpace(v.ID)
	v.Name = strings.TrimSpace(v.Name)
	v.Capabilities = coreauth.DedupeStrings(v.Capabilities)
	if v.ID == "" || v.Name == "" || v.ID == "administrator" {
		writeError(w, 422, "validation_failed", "A non-administrator role ID and name are required.")
		return
	}
	for _, c := range v.Capabilities {
		if c == "*" || !knownCapability(c) {
			writeError(w, 422, "validation_failed", "The role contains an unknown capability.")
			return
		}
	}
	raw, _ := json.Marshal(v.Capabilities)
	_, err := h.db.ExecContext(r.Context(), "INSERT INTO _trestle_roles(id,name,capabilities_json,built_in) VALUES(?,?,?,?) ON CONFLICT(id) DO UPDATE SET name=excluded.name,capabilities_json=excluded.capabilities_json WHERE _trestle_roles.built_in=0", v.ID, v.Name, string(raw), false)
	if err != nil {
		writeError(w, 500, "internal_error", "The request could not be completed.")
		return
	}
	writeJSON(w, 200, v)
}
