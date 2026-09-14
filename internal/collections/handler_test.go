package collections

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"

	"github.com/trestle-cv/trestle/internal/adminauth"
	"github.com/trestle-cv/trestle/internal/storetest"
)

type authSession struct {
	cookie *http.Cookie
	csrf   string
}

func setupTest(t *testing.T, provider string) (*Handler, authSession) {
	t.Helper()
	s := storetest.Open(t, provider)
	auth := adminauth.New(s.DB(), string(s.Provider()))
	body := bytes.NewBufferString(`{"username":"admin","email":"admin@example.com","password":"correct horse battery staple","applicationRegistrationPolicy":"closed"}`)
	r := httptest.NewRequest("POST", "http://example.test/admin/v1/setup", body)
	r.Host = "example.test"
	r.Header.Set("Origin", "http://example.test")
	w := httptest.NewRecorder()
	auth.ServeHTTP(w, r)
	if w.Code != 200 {
		t.Fatalf("setup: %d %s", w.Code, w.Body.String())
	}
	var response struct {
		CSRF string `json:"csrfToken"`
	}
	if err := json.NewDecoder(w.Body).Decode(&response); err != nil {
		t.Fatal(err)
	}
	return New(s.DB(), auth), authSession{w.Result().Cookies()[0], response.CSRF}
}
func call(t *testing.T, h http.Handler, s authSession, method, path string, body any) *httptest.ResponseRecorder {
	t.Helper()
	var b bytes.Buffer
	if body != nil {
		json.NewEncoder(&b).Encode(body)
	}
	r := httptest.NewRequest(method, "http://example.test"+path, &b)
	r.Host = "example.test"
	r.Header.Set("Origin", "http://example.test")
	r.Header.Set("X-Trestle-CSRF", s.csrf)
	if s.cookie != nil {
		r.AddCookie(s.cookie)
	}
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	return w
}

func TestCollectionMetadataLifecycle(t *testing.T) {
	for _, provider := range storetest.Providers(t) {
		t.Run(provider, func(t *testing.T) {
			h, s := setupTest(t, provider)
			payload := input{Name: "issues", Fields: []Field{{Name: "title", Type: "text", Required: true}, {Name: "priority", Type: "number", Default: json.RawMessage(`1`)}}}
			w := call(t, h, s, "POST", "/admin/v1/collections", payload)
			if w.Code != 201 {
				t.Fatalf("create: %d %s", w.Code, w.Body.String())
			}
			if !strings.Contains(w.Body.String(), `"issues"`) || !strings.Contains(w.Body.String(), `"title"`) {
				t.Fatal(w.Body.String())
			}
			var created Collection
			if err := json.Unmarshal(w.Body.Bytes(), &created); err != nil {
				t.Fatal(err)
			}
			titleID := created.Fields[0].ID
			w = call(t, h, s, "GET", "/admin/v1/collections", nil)
			if w.Code != 200 || !strings.Contains(w.Body.String(), "issues") {
				t.Fatalf("list: %d %s", w.Code, w.Body.String())
			}
			payload.Name = "incidents"
			payload.Fields = append(payload.Fields, Field{Name: "open", Type: "boolean", Default: json.RawMessage(`true`)})
			w = call(t, h, s, "PATCH", "/admin/v1/collections/issues", payload)
			if w.Code != 200 || !strings.Contains(w.Body.String(), "incidents") {
				t.Fatalf("update: %d %s", w.Code, w.Body.String())
			}
			var updated Collection
			if err := json.Unmarshal(w.Body.Bytes(), &updated); err != nil {
				t.Fatal(err)
			}
			if updated.Fields[0].ID != titleID {
				t.Fatalf("unchanged field ID changed: %s -> %s", titleID, updated.Fields[0].ID)
			}
			w = call(t, h, s, "GET", "/admin/v1/collections/incidents", nil)
			if w.Code != 200 || !strings.Contains(w.Body.String(), `"open"`) {
				t.Fatalf("get: %d %s", w.Code, w.Body.String())
			}
			w = call(t, h, s, "DELETE", "/admin/v1/collections/incidents", nil)
			if w.Code != 204 {
				t.Fatalf("delete: %d %s", w.Code, w.Body.String())
			}
			w = call(t, h, s, "GET", "/admin/v1/collections/incidents", nil)
			if w.Code != 404 {
				t.Fatalf("deleted get: %d", w.Code)
			}
		})
	}
}
func TestCollectionValidationAndAuthorization(t *testing.T) {
	for _, provider := range storetest.Providers(t) {
		t.Run(provider, func(t *testing.T) {
			h, s := setupTest(t, provider)
			bad := input{Name: "_system", Fields: []Field{{Name: "same", Type: "text"}, {Name: "same", Type: "shell"}}}
			w := call(t, h, s, "POST", "/admin/v1/collections", bad)
			if w.Code != 422 || !strings.Contains(w.Body.String(), "duplicate") || !strings.Contains(w.Body.String(), "unsupported") {
				t.Fatalf("validation: %d %s", w.Code, w.Body.String())
			}
			w = call(t, h, authSession{}, "GET", "/admin/v1/collections", nil)
			if w.Code != 401 {
				t.Fatalf("unauthorized read: %d", w.Code)
			}
			s.csrf = "wrong"
			w = call(t, h, s, "POST", "/admin/v1/collections", input{Name: "notes"})
			if w.Code != 403 {
				t.Fatalf("csrf mutation: %d", w.Code)
			}
		})
	}
}

func TestDefaultMustMatchFieldType(t *testing.T) {
	for _, provider := range storetest.Providers(t) {
		t.Run(provider, func(t *testing.T) {
			h, s := setupTest(t, provider)
			w := call(t, h, s, "POST", "/admin/v1/collections", input{Name: "events", Fields: []Field{{Name: "starts_at", Type: "datetime", Default: json.RawMessage(`"not-a-date"`)}, {Name: "count", Type: "number", Default: json.RawMessage(`"many"`)}}})
			if w.Code != 422 || strings.Count(w.Body.String(), "wrong_type") != 2 {
				t.Fatalf("default validation: %d %s", w.Code, w.Body.String())
			}
		})
	}
}
func TestDuplicateCollectionRollsBack(t *testing.T) {
	for _, provider := range storetest.Providers(t) {
		t.Run(provider, func(t *testing.T) {
			h, s := setupTest(t, provider)
			payload := input{Name: "notes", Fields: []Field{{Name: "body", Type: "text"}}}
			if w := call(t, h, s, "POST", "/admin/v1/collections", payload); w.Code != 201 {
				t.Fatal(w.Body.String())
			}
			if w := call(t, h, s, "POST", "/admin/v1/collections", payload); w.Code != 409 {
				t.Fatalf("duplicate: %d", w.Code)
			}
			w := call(t, h, s, "GET", "/admin/v1/collections", nil)
			if strings.Count(w.Body.String(), `"name":"notes"`) != 1 {
				t.Fatal(w.Body.String())
			}
		})
	}
}

func TestPhysicalSchemaPreservesStableFieldData(t *testing.T) {
	for _, provider := range storetest.Providers(t) {
		t.Run(provider, func(t *testing.T) {
			h, s := setupTest(t, provider)
			payload := input{Name: "notes", Fields: []Field{{Name: "body", Type: "text"}}}
			w := call(t, h, s, "POST", "/admin/v1/collections", payload)
			if w.Code != 201 {
				t.Fatal(w.Body.String())
			}
			var created Collection
			if json.Unmarshal(w.Body.Bytes(), &created) != nil {
				t.Fatal("decode create")
			}
			table := PhysicalTableName(created.ID)
			column := physicalColumn(created.Fields[0].ID)
			if _, err := h.db.Exec("INSERT INTO " + quote(table) + "(_id,_created,_updated," + quote(column) + ") VALUES('rec_1','2026-01-01T00:00:00Z','2026-01-01T00:00:00Z','hello')"); err != nil {
				t.Fatal(err)
			}
			payload.Fields[0].ID = created.Fields[0].ID
			payload.Fields[0].Name = "content"
			w = call(t, h, s, "PATCH", "/admin/v1/collections/notes", payload)
			if w.Code != 200 {
				t.Fatalf("rename: %d %s", w.Code, w.Body.String())
			}
			var value string
			if err := h.db.QueryRow("SELECT " + quote(column) + " FROM " + quote(table) + " WHERE _id='rec_1'").Scan(&value); err != nil || value != "hello" {
				t.Fatalf("preserved value=%q err=%v", value, err)
			}
		})
	}
}

func TestDestructiveSchemaRequiresAcknowledgement(t *testing.T) {
	for _, provider := range storetest.Providers(t) {
		t.Run(provider, func(t *testing.T) {
			h, s := setupTest(t, provider)
			payload := input{Name: "tasks", Fields: []Field{{Name: "title", Type: "text"}, {Name: "done", Type: "boolean"}}}
			w := call(t, h, s, "POST", "/admin/v1/collections", payload)
			if w.Code != 201 {
				t.Fatal(w.Body.String())
			}
			var created Collection
			json.Unmarshal(w.Body.Bytes(), &created)
			payload.Fields = created.Fields[:1]
			w = call(t, h, s, "PATCH", "/admin/v1/collections/tasks", payload)
			if w.Code != 409 || !strings.Contains(w.Body.String(), "schema_acknowledgement_required") {
				t.Fatalf("unacknowledged: %d %s", w.Code, w.Body.String())
			}
			var count int
			if err := h.db.QueryRow("SELECT count(*) FROM _trestle_fields WHERE collection_id=?", created.ID).Scan(&count); err != nil || count != 2 {
				t.Fatalf("metadata changed before acknowledgement: %d %v", count, err)
			}
			var b bytes.Buffer
			json.NewEncoder(&b).Encode(payload)
			r := httptest.NewRequest("PATCH", "http://example.test/admin/v1/collections/tasks", &b)
			r.Host = "example.test"
			r.Header.Set("Origin", "http://example.test")
			r.Header.Set("X-Trestle-CSRF", s.csrf)
			r.Header.Set("X-Trestle-Acknowledge-Schema", "true")
			r.AddCookie(s.cookie)
			w = httptest.NewRecorder()
			h.ServeHTTP(w, r)
			if w.Code != 200 {
				t.Fatalf("acknowledged: %d %s", w.Code, w.Body.String())
			}
		})
	}
}

func TestAllFieldTypesRoundTrip(t *testing.T) {
	for _, provider := range storetest.Providers(t) {
		t.Run(provider, func(t *testing.T) {
			h, s := setupTest(t, provider)
			payload := input{Name: "typed", Fields: []Field{
				{Name: "title", Type: "text"},
				{Name: "email", Type: "email"},
				{Name: "url", Type: "url"},
				{Name: "state", Type: "select"},
				{Name: "owner", Type: "relation"},
				{Name: "score", Type: "number"},
				{Name: "done", Type: "boolean"},
				{Name: "starts", Type: "datetime"},
				{Name: "meta", Type: "json"},
			}}
			w := call(t, h, s, "POST", "/admin/v1/collections", payload)
			if w.Code != 201 {
				t.Fatal(w.Body.String())
			}
			var created Collection
			json.Unmarshal(w.Body.Bytes(), &created)
			if len(created.Fields) != 9 {
				t.Fatalf("fields=%d", len(created.Fields))
			}
			w = call(t, h, s, "GET", "/admin/v1/collections/typed", nil)
			if w.Code != 200 {
				t.Fatal(w.Body.String())
			}
			var fetched Collection
			json.Unmarshal(w.Body.Bytes(), &fetched)
			types := map[string]string{}
			for _, f := range fetched.Fields {
				types[f.Name] = f.Type
			}
			for name, want := range map[string]string{"title": "text", "email": "email", "url": "url", "state": "select", "owner": "relation", "score": "number", "done": "boolean", "starts": "datetime", "meta": "json"} {
				if types[name] != want {
					t.Fatalf("field %q type=%q want %q", name, types[name], want)
				}
			}
		})
	}
}

func TestConcurrentCollectionNameRace(t *testing.T) {
	for _, provider := range storetest.Providers(t) {
		t.Run(provider, func(t *testing.T) {
			h, s := setupTest(t, provider)
			start := make(chan struct{})
			codes := make(chan int, 4)
			payload := input{Name: "raced", Fields: []Field{{Name: "body", Type: "text"}}}
			for i := 0; i < 4; i++ {
				go func() {
					<-start
					codes <- call(t, h, s, "POST", "/admin/v1/collections", payload).Code
				}()
			}
			close(start)
			ok, conflict := 0, 0
			for i := 0; i < 4; i++ {
				switch <-codes {
				case 201:
					ok++
				case 409:
					conflict++
				}
			}
			if ok != 1 || conflict != 3 {
				t.Fatalf("201=%d 409=%d, want one winner", ok, conflict)
			}
			w := call(t, h, s, "GET", "/admin/v1/collections", nil)
			if strings.Count(w.Body.String(), `"name":"raced"`) != 1 {
				t.Fatal(w.Body.String())
			}
		})
	}
}

func TestIncompatibleSchemaChangePreservesMetadataAndRows(t *testing.T) {
	for _, provider := range storetest.Providers(t) {
		t.Run(provider, func(t *testing.T) {
			h, s := setupTest(t, provider)
			payload := input{Name: "notes", Fields: []Field{{Name: "count", Type: "text"}}}
			w := call(t, h, s, "POST", "/admin/v1/collections", payload)
			if w.Code != 201 {
				t.Fatal(w.Body.String())
			}
			var created Collection
			json.Unmarshal(w.Body.Bytes(), &created)
			table := PhysicalTableName(created.ID)
			column := physicalColumn(created.Fields[0].ID)
			if _, err := h.db.Exec("INSERT INTO " + quote(table) + "(_id,_created,_updated," + quote(column) + ") VALUES('rec_1','2026-01-01T00:00:00Z','2026-01-01T00:00:00Z','not-a-number')"); err != nil {
				t.Fatal(err)
			}
			payload.Fields[0].ID = created.Fields[0].ID
			payload.Fields[0].Type = "number"
			var b bytes.Buffer
			json.NewEncoder(&b).Encode(payload)
			r := httptest.NewRequest("PATCH", "http://example.test/admin/v1/collections/notes", &b)
			r.Host = "example.test"
			r.Header.Set("Origin", "http://example.test")
			r.Header.Set("X-Trestle-CSRF", s.csrf)
			r.Header.Set("X-Trestle-Acknowledge-Schema", "true")
			r.AddCookie(s.cookie)
			w = httptest.NewRecorder()
			h.ServeHTTP(w, r)
			if w.Code != 422 || !strings.Contains(w.Body.String(), "schema_change_failed") {
				t.Fatalf("incompatible change: %d %s", w.Code, w.Body.String())
			}
			var count int
			if err := h.db.QueryRow("SELECT count(*) FROM _trestle_fields WHERE collection_id=?", created.ID).Scan(&count); err != nil || count != 1 {
				t.Fatalf("metadata after failure: %d %v", count, err)
			}
			var value string
			if err := h.db.QueryRow("SELECT " + quote(column) + " FROM " + quote(table) + " WHERE _id='rec_1'").Scan(&value); err != nil || value != "not-a-number" {
				t.Fatalf("row after failure value=%q err=%v", value, err)
			}
		})
	}
}

func TestJSONPhysicalConstraint(t *testing.T) {
	for _, provider := range storetest.Providers(t) {
		t.Run(provider, func(t *testing.T) {
			h, s := setupTest(t, provider)
			payload := input{Name: "notes", Fields: []Field{{Name: "meta", Type: "json"}}}
			w := call(t, h, s, "POST", "/admin/v1/collections", payload)
			if w.Code != 201 {
				t.Fatal(w.Body.String())
			}
			var created Collection
			json.Unmarshal(w.Body.Bytes(), &created)
			table := `"` + PhysicalTableName(created.ID) + `"`
			column := `"` + physicalColumn(created.Fields[0].ID) + `"`
			seq := 0
			insert := func(value any) error {
				seq++
				_, err := h.db.Exec("INSERT INTO "+table+"(_id,_created,_updated,"+column+") VALUES(?,?,?,?)", "rec_"+strconv.Itoa(seq), "2026-01-01T00:00:00Z", "2026-01-01T00:00:00Z", value)
				return err
			}
			if err := insert(`{"a":1}`); err != nil {
				t.Fatalf("valid JSON rejected: %v", err)
			}
			if err := insert(`null`); err != nil {
				t.Fatalf("JSON null rejected: %v", err)
			}
			if err := insert(nil); err != nil {
				t.Fatalf("SQL NULL rejected: %v", err)
			}
			if err := insert(`{invalid`); err == nil {
				t.Fatal("invalid JSON accepted by physical table")
			}
			if err := insert(`{"keep":true}`); err != nil {
				t.Fatal(err)
			}
			payload.Fields[0].ID = created.Fields[0].ID
			payload.Fields[0].Name = "metadata"
			var b bytes.Buffer
			json.NewEncoder(&b).Encode(payload)
			r := httptest.NewRequest("PATCH", "http://example.test/admin/v1/collections/notes", &b)
			r.Host = "example.test"
			r.Header.Set("Origin", "http://example.test")
			r.Header.Set("X-Trestle-CSRF", s.csrf)
			r.Header.Set("X-Trestle-Acknowledge-Schema", "true")
			r.AddCookie(s.cookie)
			w = httptest.NewRecorder()
			h.ServeHTTP(w, r)
			if w.Code != 200 {
				t.Fatalf("rebuild: %d %s", w.Code, w.Body.String())
			}
			var value string
			if err := h.db.QueryRow("SELECT " + column + " FROM " + table + " WHERE _id='rec_5'").Scan(&value); err != nil || value != `{"keep":true}` {
				t.Fatalf("preserved json=%q err=%v", value, err)
			}
		})
	}
}
