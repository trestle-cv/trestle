package records

import (
	"bytes"
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/gantry-tools/gantry-core/replication"
	"github.com/trestle-cv/trestle/internal/adminauth"
	"github.com/trestle-cv/trestle/internal/appauth"
	"github.com/trestle-cv/trestle/internal/audit"
	"github.com/trestle-cv/trestle/internal/collections"
	"github.com/trestle-cv/trestle/internal/events"
	"github.com/trestle-cv/trestle/internal/httperr"
	"github.com/trestle-cv/trestle/internal/identities"
	querylang "github.com/trestle-cv/trestle/internal/query"
	"github.com/trestle-cv/trestle/internal/rules"
	"github.com/trestle-cv/trestle/internal/store"
)

type Handler struct {
	db          store.Executor
	auth        *adminauth.Handler
	credentials *identities.Handler
	users       *appauth.Handler
	ruleHandler *rules.Handler
	events      *events.Handler
	auditor     *audit.Handler
	now         func() time.Time
	authority   MutationAuthority
}

type ReplicatedRecord struct {
	CollectionID string         `json:"collection_id"`
	RecordID     string         `json:"record_id"`
	Version      int64          `json:"version"`
	CreatedAt    string         `json:"created_at"`
	UpdatedAt    string         `json:"updated_at"`
	Values       map[string]any `json:"values"`
}
type MutationAuthority interface {
	PutRecord(context.Context, ReplicatedRecord) (*replication.ApplyResult, error)
	DeleteRecord(context.Context, ReplicatedRecord) (*replication.ApplyResult, error)
}

func (h *Handler) SetMutationAuthority(a MutationAuthority) { h.authority = a }

type field struct {
	id, name, kind string
	required       bool
	defaultJSON    sql.NullString
}
type schema struct {
	id, name, table string
	fields          []field
}
type Record struct {
	ID        string         `json:"id"`
	Version   int            `json:"version"`
	CreatedAt string         `json:"createdAt"`
	UpdatedAt string         `json:"updatedAt"`
	Values    map[string]any `json:"values"`
}
type createInput struct {
	ID     string         `json:"id,omitempty"`
	Values map[string]any `json:"values"`
}

func New(db any, auth *adminauth.Handler, credentials ...*identities.Handler) *Handler {
	h := &Handler{db: store.Adapt(db), auth: auth, now: time.Now}
	if len(credentials) > 0 {
		h.credentials = credentials[0]
	}
	return h
}
func (h *Handler) ConfigureAccess(users *appauth.Handler, ruleHandler *rules.Handler) {
	h.users, h.ruleHandler = users, ruleHandler
}
func (h *Handler) ConfigureEvents(eventHandler *events.Handler) { h.events = eventHandler }
func (h *Handler) ConfigureAudit(auditor *audit.Handler)        { h.auditor = auditor }
func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	mutation := r.Method != http.MethodGet
	_, adminOK := h.auth.Authorize(r, mutation)
	actor := rules.Actor{}
	if !adminOK && h.credentials != nil {
		scope := "records:read"
		if mutation {
			scope = "records:write"
		}
		if principal, ok := h.credentials.Authenticate(r, scope); ok {
			actor = rules.Actor{ID: principal.ID, Kind: "service"}
		}
	}
	if !adminOK && actor.ID == "" && h.users != nil {
		if id, ok := h.users.Authenticate(r); ok {
			actor = rules.Actor{ID: id, Kind: "user"}
		}
	}
	if !adminOK && actor.ID == "" {
		status := 401
		if mutation {
			status = 403
		}
		writeError(w, status, "authorization_denied", "The request is not authorized.")
		return
	}
	collection, id, batch, ok := parsePath(r.URL.Path)
	if !ok {
		http.NotFound(w, r)
		return
	}
	s, err := h.loadSchema(r, collection)
	if errors.Is(err, sql.ErrNoRows) {
		writeError(w, 404, "collection_not_found", "The collection was not found.")
		return
	} else if err != nil {
		writeError(w, 500, "internal_error", "The request could not be completed.")
		return
	}
	rowRule := ""
	if !adminOK {
		op := operation(r.Method, id, batch)
		allowed, expression, ruleErr := h.ruleHandler.Allowed(r, collection, op, actor, nil)
		if ruleErr != nil {
			writeError(w, 500, "internal_error", "The request could not be completed.")
			return
		}
		if !allowed && strings.HasPrefix(expression, "actor.id == record.") {
			rowRule = expression
			if id != "" {
				if record, fetchErr := h.fetch(r, s, id); fetchErr == nil {
					allowed = rules.Evaluate(expression, actor, record.Values)
				}
			}
		} else if !allowed && strings.HasPrefix(expression, "actor.id == input.") && op == "create" {
			body, readErr := io.ReadAll(http.MaxBytesReader(w, r.Body, 1<<20))
			if readErr == nil {
				r.Body = io.NopCloser(bytes.NewReader(body))
				var input createInput
				if json.Unmarshal(body, &input) == nil {
					allowed = rules.Evaluate(expression, actor, input.Values)
				}
			}
		}
		if !allowed && (id != "" || rowRule == "") {
			if id != "" {
				writeError(w, 404, "record_not_found", "The record was not found.")
			} else {
				writeError(w, 403, "authorization_denied", "The request is not authorized.")
			}
			return
		}
	}
	switch {
	case batch && r.Method == http.MethodPost:
		h.batchCreate(w, r, s)
	case id == "" && r.Method == http.MethodPost:
		h.create(w, r, s)
	case id == "" && r.Method == http.MethodGet:
		h.list(w, r, s, rowRule, actor)
	case id != "" && r.Method == http.MethodGet:
		h.get(w, r, s, id)
	case id != "" && r.Method == http.MethodPatch:
		h.update(w, r, s, id)
	case id != "" && r.Method == http.MethodDelete:
		h.remove(w, r, s, id)
	default:
		http.NotFound(w, r)
	}
}
func operation(method, id string, batch bool) string {
	if method == http.MethodPost {
		return "create"
	}
	if id == "" || batch {
		return "list"
	}
	switch method {
	case http.MethodGet:
		return "view"
	case http.MethodPatch:
		return "update"
	case http.MethodDelete:
		return "delete"
	}
	return "view"
}
func parsePath(p string) (string, string, bool, bool) {
	prefix := "/api/v1/collections/"
	if strings.HasPrefix(p, "/admin/v1/data/") {
		prefix = "/admin/v1/data/"
	}
	rest := strings.TrimPrefix(p, prefix)
	if rest == p {
		return "", "", false, false
	}
	parts := strings.Split(strings.Trim(rest, "/"), "/")
	if len(parts) < 2 || parts[1] != "records" {
		return "", "", false, false
	}
	if len(parts) == 3 && parts[2] == "batch" {
		return parts[0], "", true, true
	}
	if len(parts) > 3 {
		return "", "", false, false
	}
	id := ""
	if len(parts) == 3 {
		id = parts[2]
	}
	return parts[0], id, false, true
}
func (h *Handler) loadSchema(r *http.Request, name string) (schema, error) {
	var s schema
	if err := h.db.QueryRowContext(r.Context(), "SELECT id,name FROM _trestle_collections WHERE name=? AND kind='base'", name).Scan(&s.id, &s.name); err != nil {
		return s, err
	}
	s.table = collections.PhysicalTableName(s.id)
	rows, err := h.db.QueryContext(r.Context(), "SELECT id,name,type,required,default_json FROM _trestle_fields WHERE collection_id=? ORDER BY position", s.id)
	if err != nil {
		return s, err
	}
	defer rows.Close()
	dialect := h.db.Dialect()
	for rows.Next() {
		var f field
		var requiredRaw any
		if err := rows.Scan(&f.id, &f.name, &f.kind, &requiredRaw, &f.defaultJSON); err != nil {
			return s, err
		}
		required, err := dialect.DecodeBoolean(requiredRaw)
		if err != nil {
			return s, err
		}
		f.required = required
		s.fields = append(s.fields, f)
	}
	return s, rows.Err()
}

func (h *Handler) create(w http.ResponseWriter, r *http.Request, s schema) {
	key := strings.TrimSpace(r.Header.Get("Idempotency-Key"))
	if len(key) > 200 {
		writeError(w, 400, "invalid_idempotency_key", "The idempotency key is too long.")
		return
	}
	if key != "" {
		var existing string
		err := h.db.QueryRowContext(r.Context(), "SELECT record_id FROM _trestle_record_idempotency WHERE collection_id=? AND idempotency_key=?", s.id, key).Scan(&existing)
		if err == nil {
			record, fetchErr := h.fetch(r, s, existing)
			if fetchErr == nil {
				w.Header().Set("Idempotency-Replayed", "true")
				w.Header().Set("ETag", fmt.Sprintf(`"%d"`, record.Version))
				writeJSON(w, 200, projectRecord(record, projection(r)))
				return
			}
		} else if !errors.Is(err, sql.ErrNoRows) {
			writeError(w, 500, "internal_error", "The request could not be completed.")
			return
		}
	}
	var in createInput
	if !decode(w, r, &in) {
		return
	}
	if h.authority != nil {
		values, details := validateValues(s, in.Values)
		if len(details) > 0 {
			writeValidation(w, details)
			return
		}
		id := in.ID
		if id == "" {
			id = newID("rec_")
		}
		if !validID(id) {
			writeValidation(w, []httperr.Field{{Path: "id", Code: "invalid"}})
			return
		}
		now := h.now().UTC().Format(time.RFC3339Nano)
		rr := ReplicatedRecord{CollectionID: s.id, RecordID: id, Version: 1, CreatedAt: now, UpdatedAt: now, Values: values}
		if _, e := h.authority.PutRecord(r.Context(), rr); e == nil {
			rec, e := h.fetch(r, s, id)
			if e != nil {
				writeError(w, 500, "internal_error", e.Error())
				return
			}
			w.Header().Set("ETag", fmt.Sprintf(`"%d"`, rec.Version))
			writeJSON(w, 201, projectRecord(rec, projection(r)))
			return
		} else if !errors.Is(e, replication.ErrStandalone) {
			writeError(w, 503, "replication_unavailable", e.Error())
			return
		}
	}
	tx, err := h.db.BeginTx(r.Context(), nil)
	if err != nil {
		writeError(w, 500, "internal_error", "The request could not be completed.")
		return
	}
	defer tx.Rollback()
	record, details, err := h.insert(r, tx, s, in)
	if len(details) > 0 {
		writeValidation(w, details)
		return
	}
	if err != nil {
		writeError(w, 409, "record_conflict", "The record conflicts with the collection schema.")
		return
	}
	if h.auditor != nil {
		if err = h.auditor.Emit(r.Context(), tx, "admin", "", "record.create", s.name+"/"+record.ID, "success", r.Header.Get("X-Trestle-Request-ID"), map[string]any{"version": record.Version}); err != nil {
			writeError(w, 500, "internal_error", "The request could not be completed.")
			return
		}
	}
	if key != "" {
		if _, err = tx.ExecContext(r.Context(), "INSERT INTO _trestle_record_idempotency(collection_id,idempotency_key,record_id,created_at) VALUES(?,?,?,?)", s.id, key, record.ID, record.CreatedAt); err != nil {
			writeError(w, 409, "idempotency_conflict", "The idempotency key is already in use.")
			return
		}
	}
	if err = tx.Commit(); err != nil {
		writeError(w, 500, "internal_error", "The request could not be completed.")
		return
	}
	w.Header().Set("ETag", fmt.Sprintf(`"%d"`, record.Version))
	writeJSON(w, 201, projectRecord(record, projection(r)))
}
func (h *Handler) batchCreate(w http.ResponseWriter, r *http.Request, s schema) {
	var body struct {
		Records []createInput `json:"records"`
	}
	if !decode(w, r, &body) {
		return
	}
	if len(body.Records) == 0 || len(body.Records) > 1000 {
		writeValidation(w, []httperr.Field{{Path: "records", Code: "size"}})
		return
	}
	tx, err := h.db.BeginTx(r.Context(), nil)
	if err != nil {
		writeError(w, 500, "internal_error", "The request could not be completed.")
		return
	}
	defer tx.Rollback()
	items := []Record{}
	for i, in := range body.Records {
		record, details, err := h.insert(r, tx, s, in)
		if len(details) > 0 {
			for j := range details {
				details[j].Path = "records[" + strconv.Itoa(i) + "]." + details[j].Path
			}
			writeValidation(w, details)
			return
		}
		if err != nil {
			writeError(w, 409, "record_conflict", "The batch conflicts with the collection schema.")
			return
		}
		items = append(items, record)
		if h.auditor != nil {
			if err = h.auditor.Emit(r.Context(), tx, "admin", "", "record.create", s.name+"/"+record.ID, "success", r.Header.Get("X-Trestle-Request-ID"), map[string]any{"batch": true}); err != nil {
				writeError(w, 500, "internal_error", "The request could not be completed.")
				return
			}
		}
	}
	if err = tx.Commit(); err != nil {
		writeError(w, 500, "internal_error", "The request could not be completed.")
		return
	}
	writeJSON(w, 201, map[string]any{"items": items})
}
func (h *Handler) insert(r *http.Request, tx store.Transaction, s schema, in createInput) (Record, []httperr.Field, error) {
	values, details := validateValues(s, in.Values)
	if len(details) > 0 {
		return Record{}, details, nil
	}
	id := in.ID
	if id == "" {
		id = newID("rec_")
	}
	if !validID(id) {
		return Record{}, []httperr.Field{{Path: "id", Code: "invalid"}}, nil
	}
	now := h.now().UTC().Format(time.RFC3339Nano)
	columns := []string{"_id", "_created", "_updated"}
	args := []any{id, now, now}
	marks := []string{"?", "?", "?"}
	for _, f := range s.fields {
		columns = append(columns, quote(collections.PhysicalColumnName(f.id)))
		args = append(args, encodeValue(h.db.Dialect(), f, values[f.name]))
		marks = append(marks, "?")
	}
	_, err := tx.ExecContext(r.Context(), "INSERT INTO "+quote(s.table)+"("+strings.Join(columns, ",")+") VALUES("+strings.Join(marks, ",")+")", args...)
	if err != nil {
		return Record{}, nil, err
	}
	if h.events != nil {
		if err = h.events.Emit(r.Context(), tx, "record.created", s.name, id, map[string]any{"values": values}); err != nil {
			return Record{}, nil, err
		}
	}
	return Record{ID: id, Version: 1, CreatedAt: now, UpdatedAt: now, Values: values}, nil, nil
}
func (h *Handler) list(w http.ResponseWriter, r *http.Request, s schema, rowRule string, actor rules.Actor) {
	limit := 100
	if raw := r.URL.Query().Get("limit"); raw != "" {
		parsed, err := strconv.Atoi(raw)
		if err != nil || parsed < 1 || parsed > 100 {
			writeError(w, 400, "invalid_limit", "Limit must be between 1 and 100.")
			return
		}
		limit = parsed
	}
	statement, args, err := listSQL(h.db.Dialect(), s, r, limit)
	if err != nil {
		writeError(w, 400, "invalid_query", err.Error())
		return
	}
	rows, err := h.db.QueryContext(r.Context(), statement, args...)
	if err != nil {
		writeError(w, 500, "internal_error", "The request could not be completed.")
		return
	}
	defer rows.Close()
	items := []Record{}
	for rows.Next() {
		record, err := scanRecord(rows, s)
		if err != nil {
			writeError(w, 500, "internal_error", "The request could not be completed.")
			return
		}
		if rowRule != "" && !rules.Evaluate(rowRule, actor, record.Values) {
			continue
		}
		items = append(items, projectRecord(record, projection(r)))
	}
	next := ""
	if len(items) == limit {
		next = base64.RawURLEncoding.EncodeToString([]byte(items[len(items)-1].ID))
	}
	writeJSON(w, 200, map[string]any{"items": items, "nextCursor": next})
}

func listSQL(dialect store.Dialect, s schema, r *http.Request, limit int) (string, []any, error) {
	columns := []string{"_id", "_version", "_created", "_updated"}
	fields := map[string]querylang.Field{
		"id": {Column: "_id", Type: "text"}, "createdAt": {Column: "_created", Type: "datetime"}, "updatedAt": {Column: "_updated", Type: "datetime"},
	}
	for _, f := range s.fields {
		column := collections.PhysicalColumnName(f.id)
		columns = append(columns, quote(column))
		fields[f.name] = querylang.Field{Column: column, Type: f.kind}
	}
	expr, err := querylang.Parse(r.URL.Query().Get("filter"))
	if err != nil {
		return "", nil, err
	}
	where, args, err := querylang.Compile(expr, fields, dialect)
	if err != nil {
		return "", nil, err
	}
	sortName := strings.TrimSpace(r.URL.Query().Get("sort"))
	direction := "ASC"
	if strings.HasPrefix(sortName, "-") {
		direction = "DESC"
		sortName = strings.TrimPrefix(sortName, "-")
	}
	if sortName == "" {
		sortName = "id"
	}
	sortField, ok := fields[sortName]
	if !ok {
		return "", nil, errors.New("unknown sort field")
	}
	if cursor := r.URL.Query().Get("cursor"); cursor != "" {
		if sortName != "id" || direction != "ASC" {
			return "", nil, errors.New("cursor currently requires ascending id sort")
		}
		decoded, decodeErr := base64.RawURLEncoding.DecodeString(cursor)
		if decodeErr != nil || !validID(string(decoded)) {
			return "", nil, errors.New("invalid cursor")
		}
		if where != "" {
			where += " AND "
		}
		where += `"_id" > ?`
		args = append(args, string(decoded))
	}
	statement := "SELECT " + strings.Join(columns, ",") + " FROM " + quote(s.table)
	if where != "" {
		statement += " WHERE " + where
	}
	statement += " ORDER BY " + quote(sortField.Column) + " " + direction
	if sortField.Column != "_id" {
		statement += `,"_id" ASC`
	}
	statement += " LIMIT ?"
	args = append(args, limit)
	return statement, args, nil
}
func (h *Handler) get(w http.ResponseWriter, r *http.Request, s schema, id string) {
	record, err := h.fetch(r, s, id)
	if errors.Is(err, sql.ErrNoRows) {
		writeError(w, 404, "record_not_found", "The record was not found.")
		return
	} else if err != nil {
		writeError(w, 500, "internal_error", "The request could not be completed.")
		return
	}
	w.Header().Set("ETag", fmt.Sprintf(`"%d"`, record.Version))
	writeJSON(w, 200, projectRecord(record, projection(r)))
}

func projection(r *http.Request) map[string]bool {
	raw := strings.TrimSpace(r.URL.Query().Get("fields"))
	if raw == "" {
		return nil
	}
	result := map[string]bool{}
	for _, name := range strings.Split(raw, ",") {
		if name = strings.TrimSpace(name); name != "" {
			result[name] = true
		}
	}
	return result
}

func projectRecord(record Record, fields map[string]bool) Record {
	if fields == nil {
		return record
	}
	values := map[string]any{}
	for name, value := range record.Values {
		if fields[name] {
			values[name] = value
		}
	}
	record.Values = values
	return record
}
func (h *Handler) fetch(r *http.Request, s schema, id string) (Record, error) {
	query, args := selectSQL(s, id, 1)
	return scanRecord(h.db.QueryRowContext(r.Context(), query, args...), s)
}

type scanner interface{ Scan(...any) error }

func scanRecord(row scanner, s schema) (Record, error) {
	var record Record
	dest := []any{&record.ID, &record.Version, &record.CreatedAt, &record.UpdatedAt}
	raw := make([]any, len(s.fields))
	for i := range raw {
		dest = append(dest, &raw[i])
	}
	if err := row.Scan(dest...); err != nil {
		return record, err
	}
	record.Values = map[string]any{}
	for i, f := range s.fields {
		record.Values[f.name] = decodeValue(f, raw[i])
	}
	return record, nil
}
func selectSQL(s schema, id string, limit int) (string, []any) {
	columns := []string{"_id", "_version", "_created", "_updated"}
	for _, f := range s.fields {
		columns = append(columns, quote(collections.PhysicalColumnName(f.id)))
	}
	query := "SELECT " + strings.Join(columns, ",") + " FROM " + quote(s.table)
	args := []any{}
	if id != "" {
		query += " WHERE _id=?"
		args = append(args, id)
	}
	query += " ORDER BY _id LIMIT ?"
	args = append(args, limit)
	return query, args
}
func (h *Handler) update(w http.ResponseWriter, r *http.Request, s schema, id string) {
	version, ok := ifMatch(w, r)
	if !ok {
		return
	}
	current, err := h.fetch(r, s, id)
	if errors.Is(err, sql.ErrNoRows) {
		writeError(w, 404, "record_not_found", "The record was not found.")
		return
	} else if err != nil {
		writeError(w, 500, "internal_error", "The request could not be completed.")
		return
	}
	var in struct {
		Values map[string]any `json:"values"`
	}
	if !decode(w, r, &in) {
		return
	}
	for key, value := range in.Values {
		current.Values[key] = value
	}
	values, details := validateValues(s, current.Values)
	if len(details) > 0 {
		writeValidation(w, details)
		return
	}
	now := h.now().UTC().Format(time.RFC3339Nano)
	if h.authority != nil {
		rr := ReplicatedRecord{CollectionID: s.id, RecordID: id, Version: version + 1, CreatedAt: current.CreatedAt, UpdatedAt: now, Values: values}
		if _, e := h.authority.PutRecord(r.Context(), rr); e == nil {
			rec, e := h.fetch(r, s, id)
			if e != nil {
				writeError(w, 500, "internal_error", e.Error())
				return
			}
			w.Header().Set("ETag", fmt.Sprintf(`"%d"`, rec.Version))
			writeJSON(w, 200, rec)
			return
		} else if !errors.Is(e, replication.ErrStandalone) {
			writeError(w, 503, "replication_unavailable", e.Error())
			return
		}
	}
	sets := []string{"_version=_version+1", "_updated=?"}
	args := []any{now}
	for _, f := range s.fields {
		sets = append(sets, quote(collections.PhysicalColumnName(f.id))+"=?")
		args = append(args, encodeValue(h.db.Dialect(), f, values[f.name]))
	}
	args = append(args, id, version)
	tx, err := h.db.BeginTx(r.Context(), nil)
	if err != nil {
		writeError(w, 500, "internal_error", "The request could not be completed.")
		return
	}
	defer tx.Rollback()
	result, err := tx.ExecContext(r.Context(), "UPDATE "+quote(s.table)+" SET "+strings.Join(sets, ",")+" WHERE _id=? AND _version=?", args...)
	if err != nil {
		writeError(w, 409, "record_conflict", "The record conflicts with the collection schema.")
		return
	}
	n, _ := result.RowsAffected()
	if n == 0 {
		writeError(w, 412, "version_conflict", "The record changed since it was read.")
		return
	}
	if h.events != nil {
		if err = h.events.Emit(r.Context(), tx, "record.updated", s.name, id, map[string]any{"values": values, "version": version + 1}); err != nil {
			writeError(w, 500, "internal_error", "The request could not be completed.")
			return
		}
	}
	if h.auditor != nil {
		if err = h.auditor.Emit(r.Context(), tx, "admin", "", "record.update", s.name+"/"+id, "success", r.Header.Get("X-Trestle-Request-ID"), map[string]any{"version": version + 1}); err != nil {
			writeError(w, 500, "internal_error", "The request could not be completed.")
			return
		}
	}
	if err = tx.Commit(); err != nil {
		writeError(w, 500, "internal_error", "The request could not be completed.")
		return
	}
	current.Version = version + 1
	current.UpdatedAt = now
	current.Values = values
	w.Header().Set("ETag", fmt.Sprintf(`"%d"`, current.Version))
	writeJSON(w, 200, current)
}
func (h *Handler) remove(w http.ResponseWriter, r *http.Request, s schema, id string) {
	version, ok := ifMatch(w, r)
	if !ok {
		return
	}
	if h.authority != nil {
		rr := ReplicatedRecord{CollectionID: s.id, RecordID: id, Version: version}
		if _, e := h.authority.DeleteRecord(r.Context(), rr); e == nil {
			w.WriteHeader(204)
			return
		} else if !errors.Is(e, replication.ErrStandalone) {
			writeError(w, 503, "replication_unavailable", e.Error())
			return
		}
	}
	tx, err := h.db.BeginTx(r.Context(), nil)
	if err != nil {
		writeError(w, 500, "internal_error", "The request could not be completed.")
		return
	}
	defer tx.Rollback()
	result, err := tx.ExecContext(r.Context(), "DELETE FROM "+quote(s.table)+" WHERE _id=? AND _version=?", id, version)
	if err != nil {
		writeError(w, 500, "internal_error", "The request could not be completed.")
		return
	}
	n, _ := result.RowsAffected()
	if n == 0 {
		writeError(w, 412, "version_conflict", "The record was missing or changed since it was read.")
		return
	}
	if h.events != nil {
		if err = h.events.Emit(r.Context(), tx, "record.deleted", s.name, id, map[string]any{"version": version}); err != nil {
			writeError(w, 500, "internal_error", "The request could not be completed.")
			return
		}
	}
	if err = tx.Commit(); err != nil {
		writeError(w, 500, "internal_error", "The request could not be completed.")
		return
	}
	w.WriteHeader(204)
}

func validateValues(s schema, input map[string]any) (map[string]any, []httperr.Field) {
	if input == nil {
		input = map[string]any{}
	}
	known := map[string]field{}
	for _, f := range s.fields {
		known[f.name] = f
	}
	details := []httperr.Field{}
	for key := range input {
		if _, ok := known[key]; !ok {
			details = append(details, httperr.Field{Path: "values." + key, Code: "unknown"})
		}
	}
	result := map[string]any{}
	for _, f := range s.fields {
		value, ok := input[f.name]
		if !ok && f.defaultJSON.Valid {
			_ = json.Unmarshal([]byte(f.defaultJSON.String), &value)
			ok = true
		}
		if !ok || value == nil {
			if f.required {
				details = append(details, httperr.Field{Path: "values." + f.name, Code: "required"})
			}
			result[f.name] = nil
			continue
		}
		if !validType(f.kind, value) {
			details = append(details, httperr.Field{Path: "values." + f.name, Code: "wrong_type"})
		}
		result[f.name] = value
	}
	return result, details
}
func validType(kind string, value any) bool {
	switch kind {
	case "text", "email", "url", "select", "relation", "datetime":
		text, ok := value.(string)
		if !ok {
			return false
		}
		if kind == "datetime" {
			_, err := time.Parse(time.RFC3339, text)
			return err == nil
		}
		return true
	case "number":
		_, ok := value.(float64)
		return ok
	case "boolean":
		_, ok := value.(bool)
		return ok
	case "json":
		return true
	}
	return false
}
func encodeValue(d store.Dialect, f field, value any) any {
	if value == nil {
		return nil
	}
	switch f.kind {
	case "boolean":
		return d.Boolean(value.(bool))
	case "json":
		b, _ := json.Marshal(value)
		return string(b)
	}
	return value
}
func decodeValue(f field, value any) any {
	if value == nil {
		return nil
	}
	switch f.kind {
	case "boolean":
		switch v := value.(type) {
		case int64:
			return v == 1
		case bool:
			return v
		}
	case "json":
		var decoded any
		if text, ok := value.(string); ok && json.Unmarshal([]byte(text), &decoded) == nil {
			return decoded
		}
	}
	return value
}
func ifMatch(w http.ResponseWriter, r *http.Request) (int, bool) {
	value := strings.Trim(r.Header.Get("If-Match"), `"`)
	version, err := strconv.Atoi(value)
	if err != nil || version < 1 {
		writeError(w, 428, "precondition_required", "A valid If-Match record version is required.")
		return 0, false
	}
	return version, true
}
func validID(id string) bool {
	return len(id) >= 5 && len(id) <= 80 && !strings.ContainsAny(id, "/\\ \t\r\n")
}
func newID(prefix string) string {
	b := make([]byte, 15)
	_, _ = rand.Read(b)
	return prefix + base64.RawURLEncoding.EncodeToString(b)
}
func quote(identifier string) string { return `"` + strings.ReplaceAll(identifier, `"`, `""`) + `"` }
func decode(w http.ResponseWriter, r *http.Request, out any) bool {
	r.Body = http.MaxBytesReader(w, r.Body, 8<<20)
	d := json.NewDecoder(r.Body)
	d.DisallowUnknownFields()
	if d.Decode(out) != nil {
		writeError(w, 400, "invalid_json", "The request body is invalid.")
		return false
	}
	return true
}
func writeValidation(w http.ResponseWriter, details []httperr.Field) {
	writeJSON(w, 422, httperr.New("validation_failed", "The request could not be applied.", w.Header().Get("X-Request-ID"), details...))
}
func writeError(w http.ResponseWriter, status int, code, message string) {
	writeJSON(w, status, httperr.New(code, message, w.Header().Get("X-Request-ID")))
}
func writeJSON(w http.ResponseWriter, status int, value any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(value)
}
