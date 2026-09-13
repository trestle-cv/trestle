package collections

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/trestle-cv/trestle/internal/store"
)

// LoadDefinition returns the durable schema definition without any records.
func LoadDefinition(ctx context.Context, db store.Executor, name string) (Collection, error) {
	var item Collection
	if err := db.QueryRowContext(ctx, "SELECT id,name,kind,created_at,updated_at FROM _trestle_collections WHERE name=?", name).Scan(&item.ID, &item.Name, &item.Kind, &item.CreatedAt, &item.UpdatedAt); err != nil {
		return item, err
	}
	rows, err := db.QueryContext(ctx, "SELECT id,name,type,required,is_unique,default_json FROM _trestle_fields WHERE collection_id=? ORDER BY position", item.ID)
	if err != nil {
		return item, err
	}
	defer rows.Close()
	item.Fields = []Field{}
	for rows.Next() {
		var f Field
		var requiredRaw, uniqueRaw any
		var def sql.NullString
		if err := rows.Scan(&f.ID, &f.Name, &f.Type, &requiredRaw, &uniqueRaw, &def); err != nil {
			return item, err
		}
		required, err := db.Dialect().DecodeBoolean(requiredRaw)
		if err != nil {
			return item, err
		}
		unique, err := db.Dialect().DecodeBoolean(uniqueRaw)
		if err != nil {
			return item, err
		}
		f.Required = required
		f.Unique = unique
		if def.Valid {
			f.Default = json.RawMessage(def.String)
		}
		item.Fields = append(item.Fields, f)
	}
	return item, rows.Err()
}

func ListDefinitions(ctx context.Context, db store.Executor) ([]Collection, error) {
	rows, err := db.QueryContext(ctx, "SELECT name FROM _trestle_collections ORDER BY name")
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	names := []string{}
	for rows.Next() {
		var n string
		if err := rows.Scan(&n); err != nil {
			return nil, err
		}
		names = append(names, n)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	out := make([]Collection, 0, len(names))
	for _, n := range names {
		v, err := LoadDefinition(ctx, db, n)
		if err != nil {
			return nil, err
		}
		out = append(out, v)
	}
	return out, nil
}

// ApplyDefinition applies only schema changes proven non-destructive by the
// existing collection rebuild classifier. Record-destructive migrations remain
// an explicit local administration operation rather than propagation policy.
func ApplyDefinition(ctx context.Context, db store.Executor, def Collection) error {
	in := input{Name: def.Name, Fields: append([]Field(nil), def.Fields...)}
	if details := validate(in); len(details) > 0 {
		return fmt.Errorf("invalid collection definition")
	}
	before, err := LoadDefinition(ctx, db, def.Name)
	if errors.Is(err, sql.ErrNoRows) {
		return createDefinition(ctx, db, in)
	}
	if err != nil {
		return err
	}
	if changes := destructiveChanges(before.Fields, in.Fields); len(changes) > 0 {
		return fmt.Errorf("destructive schema change requires local approval: %v", changes)
	}
	now := time.Now().UTC().Format(time.RFC3339Nano)
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	id := before.ID
	existing := map[string]string{}
	existingIDs := map[string]bool{}
	rows, err := tx.QueryContext(ctx, "SELECT name,id FROM _trestle_fields WHERE collection_id=?", id)
	if err != nil {
		return err
	}
	for rows.Next() {
		var name, fid string
		if err := rows.Scan(&name, &fid); err != nil {
			rows.Close()
			return err
		}
		existing[name] = fid
		existingIDs[fid] = true
	}
	if err := rows.Close(); err != nil {
		return err
	}
	resolveFieldIDs(in.Fields, existing)
	for i := range in.Fields {
		if in.Fields[i].ID != "" && !existingIDs[in.Fields[i].ID] && existing[in.Fields[i].Name] == "" {
			in.Fields[i].ID = newID("fld_")
		}
	}
	if _, err = tx.ExecContext(ctx, "UPDATE _trestle_collections SET name=?,updated_at=? WHERE id=?", in.Name, now, id); err != nil {
		return err
	}
	if _, err = tx.ExecContext(ctx, "DELETE FROM _trestle_fields WHERE collection_id=?", id); err != nil {
		return err
	}
	if err = insertFieldsContext(ctx, tx, db.Dialect(), id, now, in.Fields); err != nil {
		return err
	}
	if err = rebuildPhysical(ctx, tx, db.Dialect(), id, before.Fields, in.Fields); err != nil {
		return err
	}
	return tx.Commit()
}

func createDefinition(ctx context.Context, db store.Executor, in input) error {
	now := time.Now().UTC().Format(time.RFC3339Nano)
	id := newID("col_")
	resolveFieldIDs(in.Fields, nil)
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if _, err = tx.ExecContext(ctx, "INSERT INTO _trestle_collections(id,name,kind,created_at,updated_at) VALUES(?,?,'base',?,?)", id, in.Name, now, now); err != nil {
		return err
	}
	if err = insertFieldsContext(ctx, tx, db.Dialect(), id, now, in.Fields); err != nil {
		return err
	}
	if err = createPhysical(ctx, tx, db.Dialect(), id, in.Fields); err != nil {
		return err
	}
	return tx.Commit()
}
func insertFieldsContext(ctx context.Context, tx store.Transaction, dialect store.Dialect, collectionID, now string, fields []Field) error {
	for i, f := range fields {
		var def any
		if len(f.Default) > 0 {
			def = string(f.Default)
		}
		if _, err := tx.ExecContext(ctx, "INSERT INTO _trestle_fields(id,collection_id,position,name,type,required,is_unique,default_json,created_at) VALUES(?,?,?,?,?,?,?,?,?)", f.ID, collectionID, i, f.Name, f.Type, dialect.Boolean(f.Required), dialect.Boolean(f.Unique), def, now); err != nil {
			return err
		}
	}
	return nil
}
func DeleteDefinition(ctx context.Context, db store.Executor, name string) error {
	var id string
	if err := db.QueryRowContext(ctx, "SELECT id FROM _trestle_collections WHERE name=?", name).Scan(&id); err != nil {
		return err
	}
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if _, err = tx.ExecContext(ctx, "DROP TABLE "+quote(PhysicalTableName(id))); err != nil {
		return err
	}
	if _, err = tx.ExecContext(ctx, "DELETE FROM _trestle_collections WHERE id=?", id); err != nil {
		return err
	}
	return tx.Commit()
}
