package collections

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"regexp"
	"strings"
	"time"

	"github.com/gantry-tools/gantry-core/replication"
	"github.com/trestle-cv/trestle/internal/adminauth"
	"github.com/trestle-cv/trestle/internal/httperr"
	"github.com/trestle-cv/trestle/internal/store"
)

var namePattern = regexp.MustCompile(`^[a-z][a-z0-9_]{0,62}$`)
var fieldTypes = map[string]bool{"text": true, "number": true, "boolean": true, "datetime": true, "json": true, "select": true, "relation": true, "email": true, "url": true}
var reserved = map[string]bool{"admin": true, "api": true, "system": true, "trestle": true}

type Handler struct {
	db        store.Executor
	auth      *adminauth.Handler
	now       func() time.Time
	authority MutationAuthority
}

type MutationAuthority interface {
	PutCollection(context.Context, Collection) (*replication.ApplyResult, error)
	DeleteCollection(context.Context, string) (*replication.ApplyResult, error)
}

func (h *Handler) SetMutationAuthority(a MutationAuthority) { h.authority = a }

type Collection struct {
	ID        string  `json:"id"`
	Name      string  `json:"name"`
	Kind      string  `json:"kind"`
	Fields    []Field `json:"fields"`
	CreatedAt string  `json:"createdAt"`
	UpdatedAt string  `json:"updatedAt"`
}
type Field struct {
	ID       string          `json:"id,omitempty"`
	Name     string          `json:"name"`
	Type     string          `json:"type"`
	Required bool            `json:"required"`
	Unique   bool            `json:"unique"`
	Default  json.RawMessage `json:"default,omitempty"`
}
type input struct {
	Name   string  `json:"name"`
	Fields []Field `json:"fields"`
}

func New(db any, auth *adminauth.Handler) *Handler {
	return &Handler{db: store.Adapt(db), auth: auth, now: time.Now}
}

func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	mutation := r.Method != http.MethodGet
	if _, ok := h.auth.Authorize(r, mutation); !ok {
		code := http.StatusUnauthorized
		if mutation {
			code = http.StatusForbidden
		}
		writeError(w, code, "authorization_denied", "The request is not authorized.")
		return
	}
	name := strings.TrimPrefix(r.URL.Path, "/admin/v1/collections")
	name = strings.TrimPrefix(name, "/")
	switch {
	case name == "" && r.Method == http.MethodGet:
		h.list(w, r)
	case name == "" && r.Method == http.MethodPost:
		h.create(w, r)
	case name != "" && r.Method == http.MethodGet:
		h.get(w, r, name)
	case name != "" && r.Method == http.MethodPatch:
		h.update(w, r, name)
	case name != "" && r.Method == http.MethodDelete:
		h.remove(w, r, name)
	default:
		http.NotFound(w, r)
	}
}

func (h *Handler) list(w http.ResponseWriter, r *http.Request) {
	rows, err := h.db.QueryContext(r.Context(), "SELECT id,name,kind,created_at,updated_at FROM _trestle_collections ORDER BY name")
	if err != nil {
		writeError(w, 500, "internal_error", "The request could not be completed.")
		return
	}
	defer rows.Close()
	items := []Collection{}
	for rows.Next() {
		var item Collection
		if rows.Scan(&item.ID, &item.Name, &item.Kind, &item.CreatedAt, &item.UpdatedAt) != nil {
			writeError(w, 500, "internal_error", "The request could not be completed.")
			return
		}
		items = append(items, item)
	}
	writeJSON(w, 200, map[string]any{"items": items})
}
func (h *Handler) get(w http.ResponseWriter, r *http.Request, name string) {
	item, err := h.load(r, name)
	if errors.Is(err, sql.ErrNoRows) {
		writeError(w, 404, "not_found", "The collection was not found.")
		return
	}
	if err != nil {
		writeError(w, 500, "internal_error", "The request could not be completed.")
		return
	}
	writeJSON(w, 200, item)
}
func (h *Handler) create(w http.ResponseWriter, r *http.Request) {
	var in input
	if !decode(w, r, &in) {
		return
	}
	if details := validate(in); len(details) > 0 {
		writeValidation(w, details)
		return
	}
	now := h.now().UTC().Format(time.RFC3339Nano)
	id := newID("col_")
	resolveFieldIDs(in.Fields, nil)
	if h.authority != nil {
		def := Collection{ID: id, Name: in.Name, Kind: "base", Fields: in.Fields, CreatedAt: now, UpdatedAt: now}
		if _, err := h.authority.PutCollection(r.Context(), def); err == nil {
			item, _ := h.load(r, in.Name)
			writeJSON(w, 201, item)
			return
		} else if !errors.Is(err, replication.ErrStandalone) {
			writeError(w, 503, "replication_unavailable", err.Error())
			return
		}
	}
	tx, err := h.db.BeginTx(r.Context(), nil)
	if err != nil {
		writeError(w, 500, "internal_error", "The request could not be completed.")
		return
	}
	defer tx.Rollback()
	if _, err = tx.ExecContext(r.Context(), "INSERT INTO _trestle_collections(id,name,kind,created_at,updated_at) VALUES(?,?,'base',?,?)", id, in.Name, now, now); err != nil {
		writeError(w, 409, "collection_exists", "A collection with that name already exists.")
		return
	}
	if err = insertFields(r, tx, h.db.Dialect(), id, now, in.Fields); err != nil {
		writeError(w, 500, "internal_error", "The request could not be completed.")
		return
	}
	if err = createPhysical(r.Context(), tx, h.db.Dialect(), id, in.Fields); err != nil {
		writeError(w, 422, "schema_change_failed", "The physical schema could not be created.")
		return
	}
	if err = tx.Commit(); err != nil {
		writeError(w, 500, "internal_error", "The request could not be completed.")
		return
	}
	item, _ := h.load(r, in.Name)
	writeJSON(w, 201, item)
}
func (h *Handler) update(w http.ResponseWriter, r *http.Request, name string) {
	before, loadErr := h.load(r, name)
	if errors.Is(loadErr, sql.ErrNoRows) {
		writeError(w, 404, "not_found", "The collection was not found.")
		return
	} else if loadErr != nil {
		writeError(w, 500, "internal_error", "The request could not be completed.")
		return
	}
	var in input
	if !decode(w, r, &in) {
		return
	}
	if details := validate(in); len(details) > 0 {
		writeValidation(w, details)
		return
	}
	now := h.now().UTC().Format(time.RFC3339Nano)
	tx, err := h.db.BeginTx(r.Context(), nil)
	if err != nil {
		writeError(w, 500, "internal_error", "The request could not be completed.")
		return
	}
	defer tx.Rollback()
	var id string
	if err = tx.QueryRowContext(r.Context(), "SELECT id FROM _trestle_collections WHERE name=?", name).Scan(&id); errors.Is(err, sql.ErrNoRows) {
		writeError(w, 404, "not_found", "The collection was not found.")
		return
	} else if err != nil {
		writeError(w, 500, "internal_error", "The request could not be completed.")
		return
	}
	if _, err = tx.ExecContext(r.Context(), "UPDATE _trestle_collections SET name=?,updated_at=? WHERE id=?", in.Name, now, id); err != nil {
		writeError(w, 409, "collection_exists", "A collection with that name already exists.")
		return
	}
	existing := map[string]string{}
	existingIDs := map[string]bool{}
	rows, err := tx.QueryContext(r.Context(), "SELECT name,id FROM _trestle_fields WHERE collection_id=?", id)
	if err != nil {
		writeError(w, 500, "internal_error", "The request could not be completed.")
		return
	}
	for rows.Next() {
		var fieldName, fieldID string
		if rows.Scan(&fieldName, &fieldID) != nil {
			rows.Close()
			writeError(w, 500, "internal_error", "The request could not be completed.")
			return
		}
		existing[fieldName] = fieldID
		existingIDs[fieldID] = true
	}
	if err = rows.Close(); err != nil {
		writeError(w, 500, "internal_error", "The request could not be completed.")
		return
	}
	resolveFieldIDs(in.Fields, existing)
	for i := range in.Fields {
		if in.Fields[i].ID != "" && !existingIDs[in.Fields[i].ID] && existing[in.Fields[i].Name] == "" {
			in.Fields[i].ID = newID("fld_")
		}
	}
	changes := destructiveChanges(before.Fields, in.Fields)
	if len(changes) > 0 && r.Header.Get("X-Trestle-Acknowledge-Schema") != "true" {
		writeJSON(w, 409, map[string]any{"error": map[string]any{"code": "schema_acknowledgement_required", "message": "The schema change requires explicit acknowledgement.", "changes": changes}})
		return
	}
	if h.authority != nil {
		def := Collection{ID: before.ID, Name: in.Name, Kind: before.Kind, Fields: in.Fields, CreatedAt: before.CreatedAt, UpdatedAt: now}
		if _, e := h.authority.PutCollection(r.Context(), def); e == nil {
			item, _ := h.load(r, in.Name)
			writeJSON(w, 200, item)
			return
		} else if !errors.Is(e, replication.ErrStandalone) {
			writeError(w, 503, "replication_unavailable", e.Error())
			return
		}
	}
	if _, err = tx.ExecContext(r.Context(), "DELETE FROM _trestle_fields WHERE collection_id=?", id); err != nil {
		writeError(w, 500, "internal_error", "The request could not be completed.")
		return
	}
	if err = insertFields(r, tx, h.db.Dialect(), id, now, in.Fields); err != nil {
		writeError(w, 500, "internal_error", "The request could not be completed.")
		return
	}
	if err = rebuildPhysical(r.Context(), tx, h.db.Dialect(), id, before.Fields, in.Fields); err != nil {
		writeError(w, 422, "schema_change_failed", "Existing records are incompatible with the requested schema.")
		return
	}
	if err = tx.Commit(); err != nil {
		writeError(w, 500, "internal_error", "The request could not be completed.")
		return
	}
	item, _ := h.load(r, in.Name)
	writeJSON(w, 200, item)
}
func (h *Handler) remove(w http.ResponseWriter, r *http.Request, name string) {
	if h.authority != nil {
		if _, e := h.authority.DeleteCollection(r.Context(), name); e == nil {
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
	var id string
	if err = tx.QueryRowContext(r.Context(), "SELECT id FROM _trestle_collections WHERE name=?", name).Scan(&id); errors.Is(err, sql.ErrNoRows) {
		writeError(w, 404, "not_found", "The collection was not found.")
		return
	} else if err != nil {
		writeError(w, 500, "internal_error", "The request could not be completed.")
		return
	}
	if _, err = tx.ExecContext(r.Context(), "DROP TABLE "+quote(PhysicalTableName(id))); err != nil {
		writeError(w, 500, "internal_error", "The request could not be completed.")
		return
	}
	result, err := tx.ExecContext(r.Context(), "DELETE FROM _trestle_collections WHERE name=?", name)
	if err != nil {
		writeError(w, 500, "internal_error", "The request could not be completed.")
		return
	}
	n, _ := result.RowsAffected()
	if n == 0 {
		writeError(w, 404, "not_found", "The collection was not found.")
		return
	}
	if err = tx.Commit(); err != nil {
		writeError(w, 500, "internal_error", "The request could not be completed.")
		return
	}
	w.WriteHeader(204)
}
func (h *Handler) load(r *http.Request, name string) (Collection, error) {
	var item Collection
	err := h.db.QueryRowContext(r.Context(), "SELECT id,name,kind,created_at,updated_at FROM _trestle_collections WHERE name=?", name).Scan(&item.ID, &item.Name, &item.Kind, &item.CreatedAt, &item.UpdatedAt)
	if err != nil {
		return item, err
	}
	rows, err := h.db.QueryContext(r.Context(), "SELECT id,name,type,required,is_unique,default_json FROM _trestle_fields WHERE collection_id=? ORDER BY position", item.ID)
	if err != nil {
		return item, err
	}
	defer rows.Close()
	item.Fields = []Field{}
	dialect := h.db.Dialect()
	for rows.Next() {
		var f Field
		var requiredRaw, uniqueRaw any
		var def sql.NullString
		if err := rows.Scan(&f.ID, &f.Name, &f.Type, &requiredRaw, &uniqueRaw, &def); err != nil {
			return item, err
		}
		required, err := dialect.DecodeBoolean(requiredRaw)
		if err != nil {
			return item, err
		}
		unique, err := dialect.DecodeBoolean(uniqueRaw)
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

func resolveFieldIDs(fields []Field, existing map[string]string) {
	valid := map[string]bool{}
	for _, id := range existing {
		valid[id] = true
	}
	for i := range fields {
		if valid[fields[i].ID] {
			continue
		}
		if id := existing[fields[i].Name]; id != "" {
			fields[i].ID = id
		} else {
			fields[i].ID = newID("fld_")
		}
	}
}
func insertFields(r *http.Request, tx store.Transaction, dialect store.Dialect, collectionID, now string, fields []Field) error {
	for i, f := range fields {
		var def any
		if len(f.Default) > 0 {
			def = string(f.Default)
		}
		_, err := tx.ExecContext(r.Context(), "INSERT INTO _trestle_fields(id,collection_id,position,name,type,required,is_unique,default_json,created_at) VALUES(?,?,?,?,?,?,?,?,?)", f.ID, collectionID, i, f.Name, f.Type, dialect.Boolean(f.Required), dialect.Boolean(f.Unique), def, now)
		if err != nil {
			return err
		}
	}
	return nil
}
func validate(in input) []httperr.Field {
	details := []httperr.Field{}
	if !namePattern.MatchString(in.Name) || strings.HasPrefix(in.Name, "_") || reserved[in.Name] {
		details = append(details, httperr.Field{Path: "name", Code: "invalid"})
	}
	seen := map[string]bool{}
	for i, f := range in.Fields {
		path := "fields[" + itoa(i) + "]"
		if !namePattern.MatchString(f.Name) || strings.HasPrefix(f.Name, "_") {
			details = append(details, httperr.Field{Path: path + ".name", Code: "invalid"})
		}
		if seen[f.Name] {
			details = append(details, httperr.Field{Path: path + ".name", Code: "duplicate"})
		}
		seen[f.Name] = true
		if !fieldTypes[f.Type] {
			details = append(details, httperr.Field{Path: path + ".type", Code: "unsupported"})
		}
		if len(f.Default) > 0 && !json.Valid(f.Default) {
			details = append(details, httperr.Field{Path: path + ".default", Code: "invalid_json"})
		} else if len(f.Default) > 0 && fieldTypes[f.Type] && !validDefault(f.Type, f.Default) {
			details = append(details, httperr.Field{Path: path + ".default", Code: "wrong_type"})
		}
	}
	return details
}

func validDefault(kind string, raw json.RawMessage) bool {
	var value any
	if json.Unmarshal(raw, &value) != nil {
		return false
	}
	switch kind {
	case "text", "email", "url", "select", "relation":
		_, ok := value.(string)
		return ok
	case "number":
		_, ok := value.(float64)
		return ok
	case "boolean":
		_, ok := value.(bool)
		return ok
	case "datetime":
		text, ok := value.(string)
		if !ok {
			return false
		}
		_, err := time.Parse(time.RFC3339, text)
		return err == nil
	case "json":
		return true
	default:
		return false
	}
}
func decode(w http.ResponseWriter, r *http.Request, out any) bool {
	r.Body = http.MaxBytesReader(w, r.Body, 256<<10)
	d := json.NewDecoder(r.Body)
	d.DisallowUnknownFields()
	if d.Decode(out) != nil {
		writeError(w, 400, "invalid_json", "The request body is invalid.")
		return false
	}
	return true
}
func newID(prefix string) string {
	b := make([]byte, 15)
	_, _ = rand.Read(b)
	return prefix + base64.RawURLEncoding.EncodeToString(b)
}
func itoa(v int) string {
	if v == 0 {
		return "0"
	}
	digits := ""
	for v > 0 {
		digits = string(rune('0'+v%10)) + digits
		v /= 10
	}
	return digits
}
func writeValidation(w http.ResponseWriter, details []httperr.Field) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(422)
	_ = json.NewEncoder(w).Encode(httperr.New("validation_failed", "The request could not be applied.", w.Header().Get("X-Request-ID"), details...))
}
func writeError(w http.ResponseWriter, status int, code, message string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(httperr.New(code, message, w.Header().Get("X-Request-ID")))
}
func writeJSON(w http.ResponseWriter, status int, value any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(value)
}
