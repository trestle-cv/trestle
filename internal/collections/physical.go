package collections

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"strings"

	"github.com/trestle-cv/trestle/internal/store"
)

func PhysicalTableName(collectionID string) string {
	sum := sha256.Sum256([]byte(collectionID))
	return "_trestle_data_" + hex.EncodeToString(sum[:8])
}
func physicalColumn(fieldID string) string {
	sum := sha256.Sum256([]byte(fieldID))
	return "f_" + hex.EncodeToString(sum[:8])
}
func PhysicalColumnName(fieldID string) string { return physicalColumn(fieldID) }
func quote(identifier string) string           { return `"` + strings.ReplaceAll(identifier, `"`, `""`) + `"` }

func createPhysical(ctx context.Context, tx store.Transaction, dialect store.Dialect, collectionID string, fields []Field) error {
	parts := []string{`_id TEXT PRIMARY KEY`, `_version INTEGER NOT NULL DEFAULT 1 CHECK(_version > 0)`, `_created TEXT NOT NULL`, `_updated TEXT NOT NULL`}
	for _, f := range fields {
		part, err := columnDDL(dialect, f)
		if err != nil {
			return err
		}
		parts = append(parts, part)
	}
	_, err := tx.ExecContext(ctx, "CREATE TABLE "+quote(PhysicalTableName(collectionID))+" ("+strings.Join(parts, ",")+")"+dialect.TableSuffix())
	return err
}

func columnDDL(dialect store.Dialect, f Field) (string, error) {
	column := quote(physicalColumn(f.ID))
	base, err := dialect.ColumnType(f.Type)
	if err != nil {
		return "", err
	}
	part := column + " " + base
	switch f.Type {
	case "boolean":
		part += dialect.BooleanCheck(column)
	case "json":
		part += dialect.JSONCheck(column)
	case "number":
		part += dialect.NumberCheck(column)
	}
	if f.Required {
		part += " NOT NULL"
	}
	if f.Unique {
		part += " UNIQUE"
	}
	return part, nil
}

func rebuildPhysical(ctx context.Context, tx store.Transaction, dialect store.Dialect, collectionID string, oldFields, newFields []Field) error {
	table := PhysicalTableName(collectionID)
	temporary := table + "_next"
	if _, err := tx.ExecContext(ctx, "DROP TABLE IF EXISTS "+quote(temporary)); err != nil {
		return err
	}
	parts := []string{`_id TEXT PRIMARY KEY`, `_version INTEGER NOT NULL DEFAULT 1 CHECK(_version > 0)`, `_created TEXT NOT NULL`, `_updated TEXT NOT NULL`}
	for _, f := range newFields {
		part, err := columnDDL(dialect, f)
		if err != nil {
			return err
		}
		parts = append(parts, part)
	}
	if _, err := tx.ExecContext(ctx, "CREATE TABLE "+quote(temporary)+" ("+strings.Join(parts, ",")+")"+dialect.TableSuffix()); err != nil {
		return err
	}
	old := map[string]bool{}
	for _, f := range oldFields {
		old[f.ID] = true
	}
	to := []string{"_id", "_version", "_created", "_updated"}
	from := append([]string{}, to...)
	for _, f := range newFields {
		if old[f.ID] {
			column := physicalColumn(f.ID)
			to = append(to, quote(column))
			from = append(from, quote(column))
		}
	}
	if _, err := tx.ExecContext(ctx, "INSERT INTO "+quote(temporary)+" ("+strings.Join(to, ",")+") SELECT "+strings.Join(from, ",")+" FROM "+quote(table)); err != nil {
		return fmt.Errorf("copy compatible record data: %w", err)
	}
	if _, err := tx.ExecContext(ctx, "DROP TABLE "+quote(table)); err != nil {
		return err
	}
	_, err := tx.ExecContext(ctx, "ALTER TABLE "+quote(temporary)+" RENAME TO "+quote(table))
	return err
}

func destructiveChanges(oldFields, newFields []Field) []string {
	old := map[string]Field{}
	for _, f := range oldFields {
		old[f.ID] = f
	}
	seen := map[string]bool{}
	changes := []string{}
	for _, f := range newFields {
		if before, ok := old[f.ID]; ok {
			seen[f.ID] = true
			if before.Type != f.Type {
				changes = append(changes, "change type of "+before.Name)
			}
			if !before.Required && f.Required {
				changes = append(changes, "make "+f.Name+" required")
			}
		}
	}
	for _, f := range oldFields {
		if !seen[f.ID] {
			changes = append(changes, "remove "+f.Name)
		}
	}
	return changes
}

// CreatePhysicalTx is the exported tx-aware physical-table creator used by the
// replicated FSM (deterministic consensus materialization).
func CreatePhysicalTx(ctx context.Context, tx store.Transaction, dialect store.Dialect, collectionID string, fields []Field) error {
	return createPhysical(ctx, tx, dialect, collectionID, fields)
}

// RebuildPhysicalTx is the exported tx-aware physical-table rebuild used by the
// replicated FSM (deterministic consensus materialization).
func RebuildPhysicalTx(ctx context.Context, tx store.Transaction, dialect store.Dialect, collectionID string, oldFields, newFields []Field) error {
	return rebuildPhysical(ctx, tx, dialect, collectionID, oldFields, newFields)
}
