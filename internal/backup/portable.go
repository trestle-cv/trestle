package backup

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/trestle-cv/trestle/internal/collections"
	"github.com/trestle-cv/trestle/internal/store"
)

// PortableFormat is the versioned logical archive used for PostgreSQL backup
// and for cross-provider migration. It is a transactionally consistent logical
// snapshot, not a copy of an operator's whole database service.
const PortableFormat = "trestle-portable-v1"

// blobColumns are the system-table columns stored as byte arrays on both
// providers; on export they are base64-encoded and on import they are decoded.
var blobColumns = map[string]bool{"token_hash": true, "csrf_hash": true, "refresh_hash": true, "secret_hash": true, "secret_cipher": true}

type PortableBundle struct {
	Format        string               `json:"format"`
	SchemaVersion int                  `json:"schemaVersion"`
	Provider      string               `json:"provider"`
	ExportedAt    string               `json:"exportedAt"`
	Collections   []PortableCollection `json:"collections"`
	System        PortableSystem       `json:"system"`
	// RestoreNotices records the portable format's restore-policy decisions so
	// a restore is fail-visible instead of silently dropping state. They are
	// carried into the archive and replayed as durable audit rows on import.
	RestoreNotices []string `json:"restoreNotices,omitempty"`
}

type PortableCollection struct {
	ID        string           `json:"id"`
	Name      string           `json:"name"`
	Kind      string           `json:"kind"`
	CreatedAt string           `json:"createdAt"`
	UpdatedAt string           `json:"updatedAt"`
	Fields    []PortableField  `json:"fields"`
	Records   []PortableRecord `json:"records"`
}

type PortableField struct {
	ID        string          `json:"id"`
	Name      string          `json:"name"`
	Type      string          `json:"type"`
	Required  bool            `json:"required"`
	Unique    bool            `json:"unique"`
	CreatedAt string          `json:"createdAt,omitempty"`
	Default   json.RawMessage `json:"default,omitempty"`
}

type PortableRecord struct {
	ID        string         `json:"id"`
	Version   int            `json:"version"`
	CreatedAt string         `json:"createdAt"`
	UpdatedAt string         `json:"updatedAt"`
	Values    map[string]any `json:"values"`
}

type PortableSystem struct {
	Admins              []map[string]any `json:"admins"`
	AdminSessions       []map[string]any `json:"adminSessions"`
	AppUsers            []map[string]any `json:"appUsers"`
	AppSessions         []map[string]any `json:"appSessions"`
	Credentials         []map[string]any `json:"credentials"`
	AppAccess           []map[string]any `json:"appAccess"`
	CollectionRules     []map[string]any `json:"collectionRules"`
	Events              []map[string]any `json:"events"`
	Audit               []map[string]any `json:"audit"`
	Jobs                []map[string]any `json:"jobs"`
	Webhooks            []map[string]any `json:"webhooks"`
	Functions           []map[string]any `json:"functions"`
	Files               []map[string]any `json:"files"`
	SystemMeta          []map[string]any `json:"systemMeta"`
	RegistrationPolicy  []map[string]any `json:"registrationPolicy"`
	Invitations         []map[string]any `json:"invitations"`
	AccessRequests      []map[string]any `json:"accessRequests"`
	Roles               []map[string]any `json:"roles,omitempty"`
	AdminRoles          []map[string]any `json:"adminRoles,omitempty"`
	PropagationProfiles []map[string]any `json:"propagationProfiles,omitempty"`
	PropagationHistory  []map[string]any `json:"propagationHistory,omitempty"`
}

func quote(identifier string) string { return `"` + strings.ReplaceAll(identifier, `"`, `""`) + `"` }

// beginSnapshot opens a read-only repeatable snapshot for the exporter.
// PostgreSQL uses REPEATABLE READ READ ONLY so every query observes the same
// committed state even if another writer commits mid-export; SQLite holds a
// shared lock for the transaction, which also yields one coherent snapshot.
func beginSnapshot(ctx context.Context, db store.Executor) (store.Transaction, error) {
	if db.Dialect().Provider() == store.Postgres {
		return db.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelRepeatableRead, ReadOnly: true})
	}
	tx, err := db.BeginTx(ctx, &sql.TxOptions{ReadOnly: true})
	if err != nil {
		return db.BeginTx(ctx, nil)
	}
	return tx, nil
}

// Export writes a portable logical snapshot of every table to w in bounded
// deterministic order. Reads happen inside one read-only repeatable snapshot
// transaction so the archive represents a single coherent state. Blobs are
// base64-encoded JSON byte arrays; booleans are decoded through the dialect.
func Export(ctx context.Context, db store.Executor, dialect store.Dialect, w io.Writer) error {
	tx, err := beginSnapshot(ctx, db)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	bundle := PortableBundle{Format: PortableFormat, SchemaVersion: store.CurrentVersion, Provider: string(dialect.Provider()), ExportedAt: time.Now().UTC().Format(time.RFC3339Nano)}

	rows, err := tx.QueryContext(ctx, "SELECT id,name,kind,created_at,updated_at FROM _trestle_collections ORDER BY name")
	if err != nil {
		return err
	}
	type collectionMeta struct{ id, name, kind, createdAt, updatedAt string }
	var metas []collectionMeta
	for rows.Next() {
		var m collectionMeta
		if err := rows.Scan(&m.id, &m.name, &m.kind, &m.createdAt, &m.updatedAt); err != nil {
			rows.Close()
			return err
		}
		metas = append(metas, m)
	}
	if err := rows.Close(); err != nil {
		return err
	}
	for _, meta := range metas {
		pc, err := exportCollection(ctx, tx, dialect, meta.id, meta.name, meta.kind, meta.createdAt, meta.updatedAt)
		if err != nil {
			return err
		}
		bundle.Collections = append(bundle.Collections, pc)
	}

	metaRows, err := tx.QueryContext(ctx, "SELECT key,value,updated_at FROM _trestle_system_meta WHERE key <> 'database_provider' ORDER BY key")
	if err != nil {
		return err
	}
	for metaRows.Next() {
		var key, value, updated string
		if err := metaRows.Scan(&key, &value, &updated); err != nil {
			metaRows.Close()
			return err
		}
		bundle.System.SystemMeta = append(bundle.System.SystemMeta, map[string]any{"key": key, "value": value, "updated_at": updated})
	}
	if err := metaRows.Close(); err != nil {
		return err
	}

	for _, item := range []struct {
		name string
		dst  *[]map[string]any
		base string
	}{
		{"admins", &bundle.System.Admins, "_trestle_admins"},
		{"adminSessions", &bundle.System.AdminSessions, "_trestle_admin_sessions"},
		{"appUsers", &bundle.System.AppUsers, "_trestle_app_users"},
		{"appSessions", &bundle.System.AppSessions, "_trestle_app_sessions"},
		{"credentials", &bundle.System.Credentials, "_trestle_credentials"},
		{"appAccess", &bundle.System.AppAccess, "_trestle_app_access"},
		{"collectionRules", &bundle.System.CollectionRules, "_trestle_collection_rules"},
		{"events", &bundle.System.Events, "_trestle_events"},
		{"audit", &bundle.System.Audit, "_trestle_audit"},
		{"jobs", &bundle.System.Jobs, "_trestle_jobs"},
		{"webhooks", &bundle.System.Webhooks, "_trestle_webhooks"},
		{"functions", &bundle.System.Functions, "_trestle_functions"},
		{"files", &bundle.System.Files, "_trestle_files"},
		{"registrationPolicy", &bundle.System.RegistrationPolicy, "_trestle_app_registration_policy"},
		{"invitations", &bundle.System.Invitations, "_trestle_app_invitations"},
		{"accessRequests", &bundle.System.AccessRequests, "_trestle_app_access_requests"},
		{"roles", &bundle.System.Roles, "_trestle_roles"},
		{"adminRoles", &bundle.System.AdminRoles, "_trestle_admin_roles"},
	} {
		values, err := dumpTable(ctx, tx, dialect, item.base)
		if err != nil {
			return fmt.Errorf("export %s: %w", item.name, err)
		}
		*item.dst = values
	}

	// Propagation schedules and their history are durable configuration and are
	// carried into the archive (last_run_at is transient scheduling state and is
	// cleared on import so schedules re-evaluate from a known baseline).
	profiles, err := dumpTable(ctx, tx, dialect, "_trestle_propagation_profiles")
	if err != nil {
		return fmt.Errorf("export propagation profiles: %w", err)
	}
	bundle.System.PropagationProfiles = profiles
	history, err := dumpTable(ctx, tx, dialect, "_trestle_propagation_history")
	if err != nil {
		return fmt.Errorf("export propagation history: %w", err)
	}
	bundle.System.PropagationHistory = history

	// Cluster identity and membership are deliberately excluded from the
	// portable archive: cluster_identity carries the node's private signing key
	// and cluster_members carries plaintext shared credentials, and the archive
	// container is not encrypted. Excluding them is an explicit, fail-visible
	// restore policy, never a silent assumption.
	var identityCount, memberCount int
	if err = tx.QueryRowContext(ctx, `SELECT COUNT(*) FROM _trestle_cluster_identity`).Scan(&identityCount); err != nil {
		return fmt.Errorf("inspect cluster identity: %w", err)
	}
	if err = tx.QueryRowContext(ctx, `SELECT COUNT(*) FROM _trestle_cluster_members`).Scan(&memberCount); err != nil {
		return fmt.Errorf("inspect cluster membership: %w", err)
	}
	if identityCount > 0 {
		bundle.RestoreNotices = append(bundle.RestoreNotices, "cluster identity was not included in the portable archive because it contains the node's private signing key; the restored node generates a new identity and must be re-paired")
	}
	if memberCount > 0 {
		bundle.RestoreNotices = append(bundle.RestoreNotices, "cluster membership was not included in the portable archive because member rows contain plaintext shared credentials; cluster topology is not restored and peers must be re-paired after restore")
	}

	encoder := json.NewEncoder(w)
	encoder.SetIndent("", "  ")
	if err := encoder.Encode(bundle); err != nil {
		return err
	}
	return tx.Rollback()
}

func exportCollection(ctx context.Context, tx store.Transaction, dialect store.Dialect, id, name, kind, createdAt, updatedAt string) (PortableCollection, error) {
	pc := PortableCollection{ID: id, Name: name, Kind: kind, CreatedAt: createdAt, UpdatedAt: updatedAt}
	fieldRows, err := tx.QueryContext(ctx, "SELECT id,name,type,required,is_unique,created_at,default_json FROM _trestle_fields WHERE collection_id=? ORDER BY position", id)
	if err != nil {
		return pc, err
	}
	type fieldMeta struct {
		fieldID          string
		column           string
		name, typ        string
		required, unique bool
		createdAt        string
		def              sql.NullString
	}
	var fields []fieldMeta
	for fieldRows.Next() {
		var f fieldMeta
		var reqRaw, uniqRaw any
		if err := fieldRows.Scan(&f.fieldID, &f.name, &f.typ, &reqRaw, &uniqRaw, &f.createdAt, &f.def); err != nil {
			fieldRows.Close()
			return pc, err
		}
		f.column = collections.PhysicalColumnName(f.fieldID)
		f.required, _ = dialect.DecodeBoolean(reqRaw)
		f.unique, _ = dialect.DecodeBoolean(uniqRaw)
		fields = append(fields, f)
	}
	if err := fieldRows.Close(); err != nil {
		return pc, err
	}
	for _, f := range fields {
		pf := PortableField{ID: f.fieldID, Name: f.name, Type: f.typ, Required: f.required, Unique: f.unique, CreatedAt: f.createdAt}
		if f.def.Valid {
			pf.Default = json.RawMessage(f.def.String)
		}
		pc.Fields = append(pc.Fields, pf)
	}
	selectParts := []string{`_id`, `_version`, `_created`, `_updated`}
	for _, f := range fields {
		selectParts = append(selectParts, quote(f.column))
	}
	table := collections.PhysicalTableName(id)
	recRows, err := tx.QueryContext(ctx, "SELECT "+strings.Join(selectParts, ",")+" FROM "+quote(table)+" ORDER BY _id")
	if err != nil {
		return pc, err
	}
	defer recRows.Close()
	for recRows.Next() {
		var rec PortableRecord
		dest := []any{&rec.ID, &rec.Version, &rec.CreatedAt, &rec.UpdatedAt}
		raw := make([]any, len(fields))
		for i := range raw {
			dest = append(dest, &raw[i])
		}
		if err := recRows.Scan(dest...); err != nil {
			return pc, err
		}
		rec.Values = map[string]any{}
		for i, f := range fields {
			rec.Values[f.name] = decodeValue(dialect, f.typ, raw[i])
		}
		pc.Records = append(pc.Records, rec)
	}
	return pc, recRows.Err()
}

func dumpTable(ctx context.Context, tx store.Transaction, dialect store.Dialect, table string) ([]map[string]any, error) {
	rows, err := tx.QueryContext(ctx, "SELECT * FROM "+quote(table)+" ORDER BY 1")
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	columns, err := rows.Columns()
	if err != nil {
		return nil, err
	}
	var out []map[string]any
	for rows.Next() {
		raw := make([]any, len(columns))
		dest := make([]any, len(columns))
		for i := range raw {
			dest[i] = &raw[i]
		}
		if err := rows.Scan(dest...); err != nil {
			return nil, err
		}
		row := map[string]any{}
		for i, col := range columns {
			row[col] = encodeValue(dialect, raw[i])
		}
		out = append(out, row)
	}
	return out, rows.Err()
}

func encodeValue(dialect store.Dialect, v any) any {
	switch t := v.(type) {
	case []byte:
		return base64.StdEncoding.EncodeToString(t)
	case bool:
		return t
	case int64:
		return t
	case float64:
		return t
	case string:
		return t
	default:
		return t
	}
}

func decodeValue(dialect store.Dialect, kind string, v any) any {
	if v == nil {
		return nil
	}
	switch kind {
	case "boolean":
		if b, err := dialect.DecodeBoolean(v); err == nil {
			return b
		}
	case "number":
		switch t := v.(type) {
		case int64:
			return t
		case float64:
			return t
		}
	case "json":
		if s, ok := v.(string); ok {
			var decoded any
			if json.Unmarshal([]byte(s), &decoded) == nil {
				return decoded
			}
			return s
		}
	}
	return v
}

// Import restores a portable bundle into an empty destination. It validates
// the format and schema first, then creates collections and inserts system
// rows inside one transaction so a failure leaves the destination untouched.
func Import(ctx context.Context, db store.Executor, dialect store.Dialect, r io.Reader) error {
	var bundle PortableBundle
	decoder := json.NewDecoder(io.LimitReader(r, 1<<30))
	if err := decoder.Decode(&bundle); err != nil {
		return errors.New("invalid portable archive")
	}
	if bundle.Format != PortableFormat {
		return errors.New("unsupported portable archive format")
	}
	if bundle.SchemaVersion > store.CurrentVersion {
		return errors.New("archive requires a newer schema")
	}
	if err := ValidateEmptyDestination(ctx, db); err != nil {
		return err
	}

	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	for _, pc := range bundle.Collections {
		if err := importCollection(ctx, tx, dialect, pc); err != nil {
			return err
		}
	}
	for _, item := range []struct {
		src   []map[string]any
		table string
	}{
		{bundle.System.Admins, "_trestle_admins"},
		{bundle.System.AdminSessions, "_trestle_admin_sessions"},
		{bundle.System.AppUsers, "_trestle_app_users"},
		{bundle.System.AppSessions, "_trestle_app_sessions"},
		{bundle.System.Credentials, "_trestle_credentials"},
		{bundle.System.AppAccess, "_trestle_app_access"},
		{bundle.System.CollectionRules, "_trestle_collection_rules"},
		{bundle.System.Events, "_trestle_events"},
		{bundle.System.Audit, "_trestle_audit"},
		{bundle.System.Jobs, "_trestle_jobs"},
		{bundle.System.Webhooks, "_trestle_webhooks"},
		{bundle.System.Functions, "_trestle_functions"},
		{bundle.System.Files, "_trestle_files"},
		{bundle.System.Invitations, "_trestle_app_invitations"},
		{bundle.System.AccessRequests, "_trestle_app_access_requests"},
	} {
		if err := insertRows(ctx, tx, dialect, item.table, item.src); err != nil {
			return err
		}
	}
	for _, row := range bundle.System.SystemMeta {
		key, _ := row["key"].(string)
		value, _ := row["value"].(string)
		updated, _ := row["updated_at"].(string)
		if key == "" || value == "" {
			continue
		}
		if _, err := tx.ExecContext(ctx, "INSERT INTO _trestle_system_meta(key,value,updated_at) VALUES(?,?,?) ON CONFLICT(key) DO NOTHING", key, value, updated); err != nil {
			return err
		}
	}
	if err := importRoles(ctx, tx, dialect, bundle.System.Roles, bundle.System.AdminRoles); err != nil {
		return err
	}
	if err := importPropagation(ctx, tx, dialect, bundle.System.PropagationProfiles, bundle.System.PropagationHistory); err != nil {
		return err
	}
	if err := importRestoreNotices(ctx, tx, bundle.RestoreNotices); err != nil {
		return err
	}
	if err := restoreRegistrationPolicy(ctx, tx, dialect, bundle); err != nil {
		return err
	}
	if err := applyRestorePolicy(ctx, tx, dialect); err != nil {
		return err
	}
	return tx.Commit()
}

// restoreRegistrationPolicy replaces the target's fresh-install policy seed
// with the backup's policy. A v15+ backup restores its saved policy row; a
// pre-v15 backup predates policy entirely, so the historical behavior (open
// registration) is restored. The decision is driven by the durable backup
// SchemaVersion, never by row counts.
func restoreRegistrationPolicy(ctx context.Context, tx store.Transaction, dialect store.Dialect, bundle PortableBundle) error {
	now := time.Now().UTC().Format(time.RFC3339Nano)
	if _, err := tx.ExecContext(ctx, "DELETE FROM _trestle_app_registration_policy"); err != nil {
		return err
	}
	if bundle.SchemaVersion >= 15 {
		if len(bundle.System.RegistrationPolicy) == 0 {
			// Defensive: a v15+ archive should carry its policy row.
			if _, err := tx.ExecContext(ctx, "INSERT INTO _trestle_app_registration_policy(id,policy,set_at) VALUES(1,'open',?)", now); err != nil {
				return err
			}
			return nil
		}
		return insertRows(ctx, tx, dialect, "_trestle_app_registration_policy", bundle.System.RegistrationPolicy)
	}
	// Pre-v15 archive: the pre-policy era had open registration.
	if _, err := tx.ExecContext(ctx, "INSERT INTO _trestle_app_registration_policy(id,policy,set_at) VALUES(1,'open',?)", now); err != nil {
		return err
	}
	return nil
}

func importCollection(ctx context.Context, tx store.Transaction, dialect store.Dialect, pc PortableCollection) error {
	now := time.Now().UTC().Format(time.RFC3339Nano)
	id := pc.ID
	if id == "" {
		id = "col_import_" + token(12)
	}
	createdAt := pc.CreatedAt
	updatedAt := pc.UpdatedAt
	if createdAt == "" {
		createdAt = now
	}
	if updatedAt == "" {
		updatedAt = now
	}
	if _, err := tx.ExecContext(ctx, "INSERT INTO _trestle_collections(id,name,kind,created_at,updated_at) VALUES(?,?,?,?,?)", id, pc.Name, pc.Kind, createdAt, updatedAt); err != nil {
		return err
	}
	fieldIDs := make([]string, len(pc.Fields))
	for i, pf := range pc.Fields {
		fid := pf.ID
		if fid == "" {
			fid = "fld_import_" + token(12)
		}
		fieldIDs[i] = fid
		var def any
		if len(pf.Default) > 0 {
			def = string(pf.Default)
		}
		fieldCreatedAt := pf.CreatedAt
		if fieldCreatedAt == "" {
			fieldCreatedAt = now
		}
		if _, err := tx.ExecContext(ctx, "INSERT INTO _trestle_fields(id,collection_id,position,name,type,required,is_unique,default_json,created_at) VALUES(?,?,?,?,?,?,?,?,?)", fid, id, i, pf.Name, pf.Type, dialect.Boolean(pf.Required), dialect.Boolean(pf.Unique), def, fieldCreatedAt); err != nil {
			return err
		}
	}
	if err := createPhysical(ctx, tx, dialect, id, fieldIDs, pc.Fields); err != nil {
		return err
	}
	for _, rec := range pc.Records {
		if err := insertRecord(ctx, tx, dialect, id, fieldIDs, pc.Fields, rec); err != nil {
			return err
		}
	}
	return nil
}

func createPhysical(ctx context.Context, tx store.Transaction, dialect store.Dialect, collectionID string, fieldIDs []string, fields []PortableField) error {
	parts := []string{`_id TEXT PRIMARY KEY`, `_version INTEGER NOT NULL DEFAULT 1 CHECK(_version > 0)`, `_created TEXT NOT NULL`, `_updated TEXT NOT NULL`}
	for i, f := range fields {
		column := quote(collections.PhysicalColumnName(fieldIDs[i]))
		base, err := dialect.ColumnType(f.Type)
		if err != nil {
			return err
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
		parts = append(parts, part)
	}
	_, err := tx.ExecContext(ctx, "CREATE TABLE "+quote(collections.PhysicalTableName(collectionID))+" ("+strings.Join(parts, ",")+")"+dialect.TableSuffix())
	return err
}

func insertRecord(ctx context.Context, tx store.Transaction, dialect store.Dialect, collectionID string, fieldIDs []string, fields []PortableField, rec PortableRecord) error {
	columns := []string{`_id`, `_version`, `_created`, `_updated`}
	marks := []string{"?", "?", "?", "?"}
	args := []any{rec.ID, rec.Version, rec.CreatedAt, rec.UpdatedAt}
	for i, pf := range fields {
		columns = append(columns, quote(collections.PhysicalColumnName(fieldIDs[i])))
		marks = append(marks, "?")
		args = append(args, encodeField(dialect, pf.Type, rec.Values[pf.Name]))
	}
	_, err := tx.ExecContext(ctx, "INSERT INTO "+quote(collections.PhysicalTableName(collectionID))+" ("+strings.Join(columns, ",")+") VALUES ("+strings.Join(marks, ",")+")", args...)
	return err
}

func encodeField(dialect store.Dialect, kind string, v any) any {
	if v == nil {
		return nil
	}
	switch kind {
	case "boolean":
		if b, ok := v.(bool); ok {
			return dialect.Boolean(b)
		}
	case "json":
		b, _ := json.Marshal(v)
		return string(b)
	}
	return v
}

// importPropagation restores propagation profiles and their history. Profiles
// are durable configuration (selectors, kinds, mode, schedule, maintenance
// window) and are carried across providers. last_run_at is transient scheduling
// state and is deliberately cleared so a restored node re-evaluates its
// schedules from a known baseline instead of silently skipping the next run.
func importPropagation(ctx context.Context, tx store.Transaction, dialect store.Dialect, profiles, history []map[string]any) error {
	for _, row := range profiles {
		id, _ := row["id"].(string)
		name, _ := row["name"].(string)
		selector, _ := row["selector_json"].(string)
		kinds, _ := row["kinds_json"].(string)
		mode, _ := row["mode"].(string)
		schedule, _ := row["schedule"].(string)
		window, _ := row["maintenance_window"].(string)
		created, _ := row["created_at"].(string)
		updated, _ := row["updated_at"].(string)
		if id == "" || name == "" || selector == "" || kinds == "" || mode == "" {
			continue
		}
		enabled := decodeArchiveBool(row["enabled"])
		if _, err := tx.ExecContext(ctx, "INSERT INTO _trestle_propagation_profiles(id,name,selector_json,kinds_json,mode,schedule,maintenance_window,enabled,created_at,updated_at,last_run_at) VALUES(?,?,?,?,?,?,?,?,?,?,NULL)", id, name, selector, kinds, mode, schedule, window, dialect.Boolean(enabled), created, updated); err != nil {
			return fmt.Errorf("insert _trestle_propagation_profiles: %w", err)
		}
	}
	for _, row := range history {
		if len(row) == 0 {
			continue
		}
		columns := make([]string, 0, len(row))
		args := make([]any, 0, len(row))
		marks := make([]string, 0, len(row))
		for col, value := range row {
			columns = append(columns, quote(col))
			marks = append(marks, "?")
			args = append(args, decodeRowValue(col, value))
		}
		stmt := "INSERT INTO _trestle_propagation_history (" + strings.Join(columns, ",") + ") VALUES (" + strings.Join(marks, ",") + ")"
		if _, err := tx.ExecContext(ctx, stmt, args...); err != nil {
			return fmt.Errorf("insert _trestle_propagation_history: %w", err)
		}
	}
	return nil
}

// importRestoreNotices replays the portable format's restore-policy decisions
// as durable system metadata so a restore is fail-visible: the operator can
// inspect exactly what was deliberately not restored instead of reasoning about
// an empty table.
func importRestoreNotices(ctx context.Context, tx store.Transaction, notices []string) error {
	if len(notices) == 0 {
		return nil
	}
	now := time.Now().UTC().Format(time.RFC3339Nano)
	for index, notice := range notices {
		if notice == "" {
			continue
		}
		key := fmt.Sprintf("restore_notice_%d", index+1)
		if _, err := tx.ExecContext(ctx, "INSERT INTO _trestle_system_meta(key,value,updated_at) VALUES(?,?,?) ON CONFLICT(key) DO UPDATE SET value=excluded.value,updated_at=excluded.updated_at", key, notice, now); err != nil {
			return fmt.Errorf("record restore notice: %w", err)
		}
	}
	return nil
}

// importRoles restores the role catalog and per-admin role assignments. The
// destination's fresh-install migration seeds the built-in administrator role,
// so the tables are cleared and rebuilt from the archive rather than merged,
// which would otherwise leave restored admins with no capabilities and locked
// out. A pre-roles archive (SchemaVersion < 16) is left with the fresh-install
// seed so restored admins keep the administrator role.
func importRoles(ctx context.Context, tx store.Transaction, dialect store.Dialect, roles, adminRoles []map[string]any) error {
	if len(roles) == 0 && len(adminRoles) == 0 {
		return nil
	}
	if _, err := tx.ExecContext(ctx, "DELETE FROM _trestle_admin_roles"); err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, "DELETE FROM _trestle_roles"); err != nil {
		return err
	}
	for _, row := range roles {
		id, _ := row["id"].(string)
		name, _ := row["name"].(string)
		capabilities, _ := row["capabilities_json"].(string)
		if id == "" || name == "" {
			continue
		}
		builtIn := decodeArchiveBool(row["built_in"])
		if _, err := tx.ExecContext(ctx, "INSERT INTO _trestle_roles(id,name,capabilities_json,built_in) VALUES(?,?,?,?)", id, name, capabilities, dialect.Boolean(builtIn)); err != nil {
			return fmt.Errorf("insert _trestle_roles: %w", err)
		}
	}
	for _, row := range adminRoles {
		adminID, _ := row["admin_id"].(string)
		roleID, _ := row["role_id"].(string)
		if adminID == "" || roleID == "" {
			continue
		}
		if _, err := tx.ExecContext(ctx, "INSERT INTO _trestle_admin_roles(admin_id,role_id) VALUES(?,?)", adminID, roleID); err != nil {
			return fmt.Errorf("insert _trestle_admin_roles: %w", err)
		}
	}
	return nil
}

// decodeArchiveBool converts a portable built_in value (bool on PostgreSQL,
// int64 on SQLite) into a Go bool.
func decodeArchiveBool(v any) bool {
	switch t := v.(type) {
	case bool:
		return t
	case int64:
		return t != 0
	case float64:
		return t != 0
	}
	return false
}

func insertRows(ctx context.Context, tx store.Transaction, dialect store.Dialect, table string, rows []map[string]any) error {
	for _, row := range rows {
		if len(row) == 0 {
			continue
		}
		columns := make([]string, 0, len(row))
		args := make([]any, 0, len(row))
		marks := make([]string, 0, len(row))
		for col, value := range row {
			columns = append(columns, quote(col))
			marks = append(marks, "?")
			args = append(args, decodeRowValue(col, value))
		}
		stmt := "INSERT INTO " + quote(table) + " (" + strings.Join(columns, ",") + ") VALUES (" + strings.Join(marks, ",") + ")"
		if _, err := tx.ExecContext(ctx, stmt, args...); err != nil {
			return fmt.Errorf("insert %s: %w", table, err)
		}
	}
	return nil
}

func decodeRowValue(column string, v any) any {
	if blobColumns[column] {
		if s, ok := v.(string); ok {
			if decoded, err := base64.StdEncoding.DecodeString(s); err == nil {
				return decoded
			}
		}
	}
	return v
}

func token(n int) string {
	b := make([]byte, n)
	rand.Read(b)
	return base64.RawURLEncoding.EncodeToString(b)
}

// applyRestorePolicy enforces the secret/session treatment for restored or
// migrated data: encrypted integration secrets are invalidated (webhooks are
// disabled with empty ciphertext so they must be reconfigured) and live
// sessions plus bearer access tokens are revoked. Credential secret hashes
// survive because lookup is hash-based.
func applyRestorePolicy(ctx context.Context, tx store.Transaction, dialect store.Dialect) error {
	if _, err := tx.ExecContext(ctx, "UPDATE _trestle_webhooks SET secret_cipher=?, enabled=?", []byte{}, dialect.Boolean(false)); err != nil {
		return err
	}
	now := time.Now().UTC().Format(time.RFC3339Nano)
	if _, err := tx.ExecContext(ctx, "UPDATE _trestle_admin_sessions SET revoked_at=? WHERE revoked_at IS NULL", now); err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, "UPDATE _trestle_app_sessions SET revoked_at=? WHERE revoked_at IS NULL", now); err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, "DELETE FROM _trestle_app_access"); err != nil {
		return err
	}
	// Outstanding invitations are invalidated on restore: only invitations that
	// are currently unused, not revoked and not expired receive the revocation
	// timestamp. Used invitations stay used, previously revoked invitations
	// retain their original revocation time, and expired invitations remain
	// expired rather than being reclassified as revoked.
	if _, err := tx.ExecContext(ctx, "UPDATE _trestle_app_invitations SET revoked_at=? WHERE used_at IS NULL AND revoked_at IS NULL AND expires_at > ?", now, now); err != nil {
		return err
	}
	return nil
}

// portableTables are the tables the portable format owns. A restore or
// migration destination must have every one empty before import begins, and
// system metadata must contain only the provider/initialization marker, so an
// archive can never silently merge with existing durable state or collide.
var portableTables = []string{
	"_trestle_collections", "_trestle_fields", "_trestle_record_idempotency",
	"_trestle_admins", "_trestle_admin_sessions", "_trestle_app_users",
	"_trestle_app_sessions", "_trestle_app_access", "_trestle_credentials",
	"_trestle_collection_rules", "_trestle_events", "_trestle_audit",
	"_trestle_jobs", "_trestle_webhooks", "_trestle_functions", "_trestle_files",
	"_trestle_file_deletions", "_trestle_app_invitations", "_trestle_app_access_requests",
	// Cluster identity/membership and propagation state are owned by the
	// portable format: a restore is only permitted into a fresh destination
	// with none of these present, so topology loss can never silently merge
	// with pre-existing cluster state.
	"_trestle_cluster_identity", "_trestle_cluster_members",
	"_trestle_propagation_profiles", "_trestle_propagation_history",
}

// ValidateEmptyDestination requires every portable-owned table to be empty and
// system metadata to contain only the provider/initialization marker, without
// running any migration or repair. The migration history is exempt and is
// validated separately as current and authoritative.
func ValidateEmptyDestination(ctx context.Context, db store.Executor) error {
	for _, table := range portableTables {
		var count int
		if err := db.QueryRowContext(ctx, "SELECT count(*) FROM "+quote(table)).Scan(&count); err != nil {
			return fmt.Errorf("import destination is not an initialized empty database: %s: %w", table, err)
		}
		if count != 0 {
			return fmt.Errorf("import destination is not empty: %s has %d rows", table, count)
		}
	}
	rows, err := db.QueryContext(ctx, "SELECT key FROM _trestle_system_meta ORDER BY key")
	if err != nil {
		return fmt.Errorf("inspect destination system metadata: %w", err)
	}
	defer rows.Close()
	for rows.Next() {
		var key string
		if err := rows.Scan(&key); err != nil {
			return err
		}
		if key != "database_provider" {
			return fmt.Errorf("import destination has unexpected system metadata %q", key)
		}
	}
	return rows.Err()
}
