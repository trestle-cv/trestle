package adminauth

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"time"

	coreauth "github.com/gantry-tools/gantry-core/auth"
	"github.com/trestle-cv/trestle/internal/store"
)

const accountSchemaVersion = 1

type accountPersistence struct{ db store.Executor }

func trestleAccountPolicy() coreauth.AccountPolicy {
	return coreauth.AccountPolicy{SchemaVersion: accountSchemaVersion, ProductName: "Trestle", KnownCapability: knownCapability}
}

func (p accountPersistence) LoadAccounts() (coreauth.AccountsFile, error) {
	result := coreauth.AccountsFile{Version: accountSchemaVersion, Accounts: []coreauth.Account{}}
	rows, err := p.db.Query("SELECT id,username,email,password_hash,created_at,disabled_at FROM _trestle_admins ORDER BY email")
	if err != nil {
		return result, err
	}
	type stored struct {
		id, username, email, hash, created string
		disabled                           sql.NullString
	}
	loaded := []stored{}
	for rows.Next() {
		var item stored
		if err := rows.Scan(&item.id, &item.username, &item.email, &item.hash, &item.created, &item.disabled); err != nil {
			rows.Close()
			return result, err
		}
		loaded = append(loaded, item)
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		return result, err
	}
	rows.Close()
	for _, item := range loaded {
		createdAt, err := time.Parse(time.RFC3339Nano, item.created)
		if err != nil {
			return result, err
		}
		roles, err := p.accountRoles(item.id)
		if err != nil {
			return result, err
		}
		result.Accounts = append(result.Accounts, coreauth.Account{
			ID: item.id, DisplayName: item.username, Enabled: !item.disabled.Valid, Roles: roles, CreatedAt: createdAt,
			Identities: []coreauth.Identity{{ID: "pwd_" + item.id, Type: "password", Username: item.username, Email: item.email, PasswordHash: item.hash, Enabled: true}},
		})
	}
	return result, nil
}

func (p accountPersistence) accountRoles(accountID string) ([]string, error) {
	rows, err := p.db.Query("SELECT role_id FROM _trestle_admin_roles WHERE admin_id=? ORDER BY role_id", accountID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	roles := []string{}
	for rows.Next() {
		var role string
		if err := rows.Scan(&role); err != nil {
			return nil, err
		}
		roles = append(roles, role)
	}
	return roles, rows.Err()
}

func (p accountPersistence) LoadRoles() (coreauth.RolesFile, error) {
	result := coreauth.RolesFile{Version: accountSchemaVersion, Roles: []coreauth.Role{}}
	rows, err := p.db.Query("SELECT id,name,capabilities_json,built_in FROM _trestle_roles ORDER BY id")
	if err != nil {
		return result, err
	}
	defer rows.Close()
	for rows.Next() {
		var role coreauth.Role
		var capabilities string
		var builtIn any
		if err := rows.Scan(&role.ID, &role.Name, &capabilities, &builtIn); err != nil {
			return result, err
		}
		if err := json.Unmarshal([]byte(capabilities), &role.Capabilities); err != nil {
			return result, err
		}
		role.BuiltIn, err = p.db.Dialect().DecodeBoolean(builtIn)
		if err != nil {
			return result, err
		}
		result.Roles = append(result.Roles, role)
	}
	return result, rows.Err()
}

func passwordIdentity(account coreauth.Account) (coreauth.Identity, error) {
	for _, identity := range account.Identities {
		if identity.Type == "password" {
			return identity, nil
		}
	}
	return coreauth.Identity{}, errors.New("Trestle account requires a password identity")
}

func (p accountPersistence) SaveAccounts(value coreauth.AccountsFile) error {
	return store.WithTx(context.Background(), p.db, func(tx store.Transaction) error {
		existingRows, err := tx.Query("SELECT id FROM _trestle_admins")
		if err != nil {
			return err
		}
		existing := map[string]bool{}
		for existingRows.Next() {
			var id string
			if err := existingRows.Scan(&id); err != nil {
				existingRows.Close()
				return err
			}
			existing[id] = true
		}
		existingRows.Close()
		for _, account := range value.Accounts {
			identity, err := passwordIdentity(account)
			if err != nil {
				return err
			}
			disabled := any(nil)
			if !account.Enabled {
				disabled = time.Now().UTC().Format(time.RFC3339Nano)
			}
			if existing[account.ID] {
				_, err = tx.Exec("UPDATE _trestle_admins SET username=?,email=?,password_hash=?,disabled_at=? WHERE id=?", identity.Username, identity.Email, identity.PasswordHash, disabled, account.ID)
			} else {
				_, err = tx.Exec("INSERT INTO _trestle_admins(id,username,email,password_hash,created_at,disabled_at) VALUES(?,?,?,?,?,?)", account.ID, identity.Username, identity.Email, identity.PasswordHash, account.CreatedAt.Format(time.RFC3339Nano), disabled)
			}
			if err != nil {
				return err
			}
			if _, err = tx.Exec("DELETE FROM _trestle_admin_roles WHERE admin_id=?", account.ID); err != nil {
				return err
			}
			for _, role := range account.Roles {
				if _, err = tx.Exec("INSERT INTO _trestle_admin_roles(admin_id,role_id) VALUES(?,?)", account.ID, role); err != nil {
					return err
				}
			}
			delete(existing, account.ID)
		}
		for id := range existing {
			if _, err := tx.Exec("DELETE FROM _trestle_admins WHERE id=?", id); err != nil {
				return err
			}
		}
		return nil
	})
}

func (p accountPersistence) SaveRoles(value coreauth.RolesFile) error {
	return store.WithTx(context.Background(), p.db, func(tx store.Transaction) error {
		for _, role := range value.Roles {
			encoded, err := json.Marshal(role.Capabilities)
			if err != nil {
				return err
			}
			result, err := tx.Exec("UPDATE _trestle_roles SET name=?,capabilities_json=?,built_in=? WHERE id=?", role.Name, string(encoded), p.db.Dialect().Boolean(role.BuiltIn), role.ID)
			if err != nil {
				return err
			}
			changed, err := result.RowsAffected()
			if err != nil {
				return err
			}
			if changed == 0 {
				if _, err = tx.Exec("INSERT INTO _trestle_roles(id,name,capabilities_json,built_in) VALUES(?,?,?,?)", role.ID, role.Name, string(encoded), p.db.Dialect().Boolean(role.BuiltIn)); err != nil {
					return err
				}
			}
		}
		return nil
	})
}
