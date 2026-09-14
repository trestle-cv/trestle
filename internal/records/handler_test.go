package records

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"

	"github.com/trestle-cv/trestle/internal/adminauth"
	"github.com/trestle-cv/trestle/internal/collections"
	"github.com/trestle-cv/trestle/internal/storetest"
)

type session struct {
	cookie *http.Cookie
	csrf   string
}

func setup(t *testing.T, provider string) (*Handler, session) {
	t.Helper()
	s := storetest.Open(t, provider)
	auth := adminauth.New(s.DB(), string(s.Provider()))
	w := invoke(t, auth, session{}, "POST", "/admin/v1/setup", map[string]any{"username": "admin", "email": "admin@example.com", "password": "correct horse battery staple", "applicationRegistrationPolicy": "closed"}, nil)
	if w.Code != 200 {
		t.Fatal(w.Body.String())
	}
	var login struct {
		CSRF string `json:"csrfToken"`
	}
	json.Unmarshal(w.Body.Bytes(), &login)
	sess := session{w.Result().Cookies()[0], login.CSRF}
	schemas := collections.New(s.DB(), auth)
	w = invoke(t, schemas, sess, "POST", "/admin/v1/collections", map[string]any{"name": "issues", "fields": []map[string]any{{"name": "title", "type": "text", "required": true}, {"name": "done", "type": "boolean", "default": false}, {"name": "score", "type": "number"}, {"name": "owner", "type": "text"}}}, nil)
	if w.Code != 201 {
		t.Fatalf("schema: %d %s", w.Code, w.Body.String())
	}
	return New(s.DB(), auth), sess
}
func invoke(t *testing.T, h http.Handler, s session, method, path string, body any, headers map[string]string) *httptest.ResponseRecorder {
	t.Helper()
	return runInvoke(h, s, method, path, body, headers)
}
func runInvoke(h http.Handler, s session, method, path string, body any, headers map[string]string) *httptest.ResponseRecorder {
	var b bytes.Buffer
	if body != nil {
		json.NewEncoder(&b).Encode(body)
	}
	r := httptest.NewRequest(method, "http://example.test"+path, &b)
	r.Host = "example.test"
	r.Header.Set("Origin", "http://example.test")
	r.Header.Set("X-Trestle-CSRF", s.csrf)
	for key, value := range headers {
		r.Header.Set(key, value)
	}
	if s.cookie != nil {
		r.AddCookie(s.cookie)
	}
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	return w
}

func TestRecordCRUDAndVersions(t *testing.T) {
	for _, provider := range storetest.Providers(t) {
		t.Run(provider, func(t *testing.T) {
			h, s := setup(t, provider)
			w := invoke(t, h, s, "POST", "/api/v1/collections/issues/records", map[string]any{"values": map[string]any{"title": "first", "score": 2}}, nil)
			if w.Code != 201 || w.Header().Get("ETag") != "\"1\"" {
				t.Fatalf("create %d %s", w.Code, w.Body.String())
			}
			var created Record
			json.Unmarshal(w.Body.Bytes(), &created)
			if created.Values["done"] != false {
				t.Fatalf("default missing: %#v", created)
			}
			w = invoke(t, h, s, "GET", "/api/v1/collections/issues/records/"+created.ID, nil, nil)
			if w.Code != 200 {
				t.Fatal(w.Body.String())
			}
			w = invoke(t, h, s, "PATCH", "/api/v1/collections/issues/records/"+created.ID, map[string]any{"values": map[string]any{"done": true}}, map[string]string{"If-Match": "\"1\""})
			if w.Code != 200 || w.Header().Get("ETag") != "\"2\"" {
				t.Fatalf("update %d %s", w.Code, w.Body.String())
			}
			w = invoke(t, h, s, "PATCH", "/api/v1/collections/issues/records/"+created.ID, map[string]any{"values": map[string]any{"title": "stale"}}, map[string]string{"If-Match": "\"1\""})
			if w.Code != 412 {
				t.Fatalf("stale %d", w.Code)
			}
			w = invoke(t, h, s, "DELETE", "/api/v1/collections/issues/records/"+created.ID, nil, map[string]string{"If-Match": "\"2\""})
			if w.Code != 204 {
				t.Fatalf("delete %d %s", w.Code, w.Body.String())
			}
		})
	}
}
func TestValidationAndAtomicBatch(t *testing.T) {
	for _, provider := range storetest.Providers(t) {
		t.Run(provider, func(t *testing.T) {
			h, s := setup(t, provider)
			w := invoke(t, h, s, "POST", "/api/v1/collections/issues/records", map[string]any{"values": map[string]any{"done": "yes", "unknown": 1}}, nil)
			if w.Code != 422 || !strings.Contains(w.Body.String(), "wrong_type") || !strings.Contains(w.Body.String(), "unknown") {
				t.Fatalf("validation %d %s", w.Code, w.Body.String())
			}
			w = invoke(t, h, s, "POST", "/api/v1/collections/issues/records/batch", map[string]any{"records": []map[string]any{{"id": "rec_same", "values": map[string]any{"title": "one"}}, {"id": "rec_same", "values": map[string]any{"title": "two"}}}}, nil)
			if w.Code != 409 {
				t.Fatalf("batch conflict %d %s", w.Code, w.Body.String())
			}
			w = invoke(t, h, s, "GET", "/api/v1/collections/issues/records", nil, nil)
			if !strings.Contains(w.Body.String(), `"items":[]`) {
				t.Fatalf("batch was not atomic: %s", w.Body.String())
			}
		})
	}
}

func TestBatchAcceptsMoreThanOneHundredRecords(t *testing.T) {
	for _, provider := range storetest.Providers(t) {
		t.Run(provider, func(t *testing.T) {
			h, s := setup(t, provider)
			records := make([]map[string]any, 101)
			for i := range records {
				records[i] = map[string]any{"values": map[string]any{"title": "batch-" + strconv.Itoa(i)}}
			}
			w := invoke(t, h, s, "POST", "/api/v1/collections/issues/records/batch", map[string]any{"records": records}, nil)
			if w.Code != http.StatusCreated {
				t.Fatalf("batch of 101 records: %d %s", w.Code, w.Body.String())
			}
		})
	}
}
func TestMutationNeedsVersionAndCSRF(t *testing.T) {
	for _, provider := range storetest.Providers(t) {
		t.Run(provider, func(t *testing.T) {
			h, s := setup(t, provider)
			w := invoke(t, h, s, "POST", "/api/v1/collections/issues/records", map[string]any{"values": map[string]any{"title": "first"}}, nil)
			var created Record
			json.Unmarshal(w.Body.Bytes(), &created)
			w = invoke(t, h, s, "PATCH", "/api/v1/collections/issues/records/"+created.ID, map[string]any{"values": map[string]any{"title": "next"}}, nil)
			if w.Code != 428 {
				t.Fatalf("missing version %d", w.Code)
			}
			s.csrf = "bad"
			w = invoke(t, h, s, "DELETE", "/api/v1/collections/issues/records/"+created.ID, nil, map[string]string{"If-Match": "1"})
			if w.Code != 403 {
				t.Fatalf("csrf %d", w.Code)
			}
		})
	}
}

func TestIdempotentCreateProjectionAndBounds(t *testing.T) {
	for _, provider := range storetest.Providers(t) {
		t.Run(provider, func(t *testing.T) {
			h, s := setup(t, provider)
			headers := map[string]string{"Idempotency-Key": "request-17"}
			w := invoke(t, h, s, "POST", "/api/v1/collections/issues/records?fields=title", map[string]any{"values": map[string]any{"title": "same", "score": 4}}, headers)
			if w.Code != 201 || strings.Contains(w.Body.String(), `"score"`) {
				t.Fatalf("first create %d %s", w.Code, w.Body.String())
			}
			var first Record
			json.Unmarshal(w.Body.Bytes(), &first)
			w = invoke(t, h, s, "POST", "/api/v1/collections/issues/records?fields=title", map[string]any{"values": map[string]any{"title": "ignored"}}, headers)
			var replay Record
			json.Unmarshal(w.Body.Bytes(), &replay)
			if w.Code != 200 || w.Header().Get("Idempotency-Replayed") != "true" || replay.ID != first.ID {
				t.Fatalf("replay %d %s", w.Code, w.Body.String())
			}
			w = invoke(t, h, s, "GET", "/api/v1/collections/issues/records?limit=101", nil, nil)
			if w.Code != 400 {
				t.Fatalf("limit %d %s", w.Code, w.Body.String())
			}
		})
	}
}

func TestTypedFilterSortAndCursor(t *testing.T) {
	for _, provider := range storetest.Providers(t) {
		t.Run(provider, func(t *testing.T) {
			h, s := setup(t, provider)
			for _, title := range []string{"alpha", "beta", "gamma"} {
				w := invoke(t, h, s, "POST", "/api/v1/collections/issues/records", map[string]any{"values": map[string]any{"title": title}}, nil)
				if w.Code != 201 {
					t.Fatal(w.Body.String())
				}
			}
			w := invoke(t, h, s, "GET", `/api/v1/collections/issues/records?filter=title%20~%20%22et%22`, nil, nil)
			if w.Code != 200 || !strings.Contains(w.Body.String(), "beta") || strings.Contains(w.Body.String(), "alpha") {
				t.Fatalf("filter %d %s", w.Code, w.Body.String())
			}
			w = invoke(t, h, s, "GET", `/api/v1/collections/issues/records?filter=title%20=%20%22x%27%20OR%201%3D1%20--%22`, nil, nil)
			if w.Code != 200 || !strings.Contains(w.Body.String(), `"items":[]`) {
				t.Fatalf("injection %d %s", w.Code, w.Body.String())
			}
			w = invoke(t, h, s, "GET", `/api/v1/collections/issues/records?limit=1`, nil, nil)
			var page struct {
				Items      []Record `json:"items"`
				NextCursor string   `json:"nextCursor"`
			}
			json.Unmarshal(w.Body.Bytes(), &page)
			if len(page.Items) != 1 || page.NextCursor == "" {
				t.Fatalf("page: %s", w.Body.String())
			}
			w = invoke(t, h, s, "GET", `/api/v1/collections/issues/records?limit=1&cursor=`+page.NextCursor, nil, nil)
			if w.Code != 200 || strings.Contains(w.Body.String(), page.Items[0].ID) {
				t.Fatalf("cursor %d %s", w.Code, w.Body.String())
			}
		})
	}
}

func TestBooleanFilterBothProviders(t *testing.T) {
	for _, provider := range storetest.Providers(t) {
		t.Run(provider, func(t *testing.T) {
			h, s := setup(t, provider)
			for _, done := range []bool{true, false, true} {
				w := invoke(t, h, s, "POST", "/api/v1/collections/issues/records", map[string]any{"values": map[string]any{"title": "t", "done": done}}, nil)
				if w.Code != 201 {
					t.Fatal(w.Body.String())
				}
			}
			w := invoke(t, h, s, "GET", `/api/v1/collections/issues/records?filter=done%20=%20true`, nil, nil)
			if w.Code != 200 {
				t.Fatal(w.Body.String())
			}
			var out struct {
				Items []Record `json:"items"`
			}
			json.Unmarshal(w.Body.Bytes(), &out)
			if len(out.Items) != 2 {
				t.Fatalf("boolean filter items=%d %s", len(out.Items), w.Body.String())
			}
		})
	}
}

func TestBatchOneThousandRecords(t *testing.T) {
	for _, provider := range storetest.Providers(t) {
		t.Run(provider, func(t *testing.T) {
			h, s := setup(t, provider)
			records := make([]map[string]any, 1000)
			for i := range records {
				records[i] = map[string]any{"values": map[string]any{"title": "bulk-" + strconv.Itoa(i)}}
			}
			w := invoke(t, h, s, "POST", "/api/v1/collections/issues/records/batch", map[string]any{"records": records}, nil)
			if w.Code != http.StatusCreated {
				t.Fatalf("batch of 1000: %d %s", w.Code, w.Body.String())
			}
			var id string
			if err := h.db.QueryRow("SELECT id FROM _trestle_collections WHERE name='issues'").Scan(&id); err != nil {
				t.Fatal(err)
			}
			var committed int
			table := `"` + collections.PhysicalTableName(id) + `"`
			if err := h.db.QueryRow("SELECT count(*) FROM " + table).Scan(&committed); err != nil || committed != 1000 {
				t.Fatalf("committed=%d err=%v, want 1000", committed, err)
			}
		})
	}
}

func TestIdempotencyRaceOneWinner(t *testing.T) {
	for _, provider := range storetest.Providers(t) {
		t.Run(provider, func(t *testing.T) {
			h, s := setup(t, provider)
			start := make(chan struct{})
			codes := make(chan int, 2)
			body := map[string]any{"values": map[string]any{"title": "duplicate"}}
			for i := 0; i < 2; i++ {
				go func() {
					<-start
					codes <- runInvoke(h, s, "POST", "/api/v1/collections/issues/records", body, map[string]string{"Idempotency-Key": "race-key"}).Code
				}()
			}
			close(start)
			created, loser := 0, 0
			for i := 0; i < 2; i++ {
				switch <-codes {
				case 201:
					created++
				case 200, 409:
					loser++
				default:
					t.Fatalf("unexpected code")
				}
			}
			if created != 1 || loser != 1 {
				t.Fatalf("201=%d loser=%d, want one winner", created, loser)
			}
			var records int
			if err := h.db.QueryRow("SELECT count(*) FROM _trestle_record_idempotency").Scan(&records); err != nil || records != 1 {
				t.Fatalf("idempotency rows=%d err=%v", records, err)
			}
		})
	}
}

func TestConcurrentUpdateOneWinner(t *testing.T) {
	for _, provider := range storetest.Providers(t) {
		t.Run(provider, func(t *testing.T) {
			h, s := setup(t, provider)
			w := invoke(t, h, s, "POST", "/api/v1/collections/issues/records", map[string]any{"values": map[string]any{"title": "base"}}, nil)
			var created Record
			json.Unmarshal(w.Body.Bytes(), &created)
			start := make(chan struct{})
			codes := make(chan int, 2)
			for i := 0; i < 2; i++ {
				go func() {
					<-start
					codes <- runInvoke(h, s, "PATCH", "/api/v1/collections/issues/records/"+created.ID, map[string]any{"values": map[string]any{"title": "next"}}, map[string]string{"If-Match": `"1"`}).Code
				}()
			}
			close(start)
			ok, stale := 0, 0
			for i := 0; i < 2; i++ {
				switch <-codes {
				case 200:
					ok++
				case 412:
					stale++
				}
			}
			if ok != 1 || stale != 1 {
				t.Fatalf("200=%d 412=%d, want one winner and one stale", ok, stale)
			}
		})
	}
}

func TestQueryNullSemantics(t *testing.T) {
	for _, provider := range storetest.Providers(t) {
		t.Run(provider, func(t *testing.T) {
			h, s := setup(t, provider)
			invoke(t, h, s, "POST", "/api/v1/collections/issues/records", map[string]any{"values": map[string]any{"title": "owned"}}, nil)
			invoke(t, h, s, "POST", "/api/v1/collections/issues/records", map[string]any{"values": map[string]any{"title": "anonymous", "owner": "alice"}}, nil)
			w := invoke(t, h, s, "GET", `/api/v1/collections/issues/records?filter=owner%20=%20null`, nil, nil)
			if w.Code != 200 || !strings.Contains(w.Body.String(), "owned") || strings.Contains(w.Body.String(), "anonymous") {
				t.Fatalf("IS NULL %d %s", w.Code, w.Body.String())
			}
			w = invoke(t, h, s, "GET", `/api/v1/collections/issues/records?filter=owner%20!=%20null`, nil, nil)
			if w.Code != 200 || !strings.Contains(w.Body.String(), "anonymous") || strings.Contains(w.Body.String(), "owned") {
				t.Fatalf("IS NOT NULL %d %s", w.Code, w.Body.String())
			}
		})
	}
}

func TestQueryNumberDatetimeAndCase(t *testing.T) {
	for _, provider := range storetest.Providers(t) {
		t.Run(provider, func(t *testing.T) {
			h, s := setup(t, provider)
			invoke(t, h, s, "POST", "/api/v1/collections/issues/records", map[string]any{"values": map[string]any{"title": "Alpha", "score": 2}}, nil)
			invoke(t, h, s, "POST", "/api/v1/collections/issues/records", map[string]any{"values": map[string]any{"title": "beta", "score": 5}}, nil)
			w := invoke(t, h, s, "GET", `/api/v1/collections/issues/records?filter=score%20%3E=%203`, nil, nil)
			if w.Code != 200 || !strings.Contains(w.Body.String(), "beta") || strings.Contains(w.Body.String(), "Alpha") {
				t.Fatalf("number filter %d %s", w.Code, w.Body.String())
			}
			w = invoke(t, h, s, "GET", `/api/v1/collections/issues/records?filter=title%20=%20%22alpha%22`, nil, nil)
			if w.Code != 200 || !strings.Contains(w.Body.String(), `"items":[]`) {
				t.Fatalf("case-sensitive match %d %s", w.Code, w.Body.String())
			}
			first := invoke(t, h, s, "GET", `/api/v1/collections/issues/records?limit=1&sort=-title`, nil, nil)
			if first.Code != 200 || !strings.Contains(first.Body.String(), "beta") {
				t.Fatalf("desc sort %d %s", first.Code, first.Body.String())
			}
			w = invoke(t, h, s, "GET", `/api/v1/collections/issues/records?filter=createdAt%20%3E%20%222000-01-01T00%3A00%3A00Z%22`, nil, nil)
			if w.Code != 200 || !strings.Contains(w.Body.String(), "Alpha") {
				t.Fatalf("datetime filter %d %s", w.Code, w.Body.String())
			}
		})
	}
}

func TestQueryFilterCursorCombined(t *testing.T) {
	for _, provider := range storetest.Providers(t) {
		t.Run(provider, func(t *testing.T) {
			h, s := setup(t, provider)
			for i := 0; i < 5; i++ {
				invoke(t, h, s, "POST", "/api/v1/collections/issues/records", map[string]any{"values": map[string]any{"title": "item", "score": i}}, nil)
			}
			var page struct {
				Items      []Record `json:"items"`
				NextCursor string   `json:"nextCursor"`
			}
			seen := 0
			cursor := ""
			for {
				path := `/api/v1/collections/issues/records?filter=title%20=%20%22item%22&limit=2`
				if cursor != "" {
					path += "&cursor=" + cursor
				}
				w := invoke(t, h, s, "GET", path, nil, nil)
				if w.Code != 200 {
					t.Fatalf("page %d %s", w.Code, w.Body.String())
				}
				json.Unmarshal(w.Body.Bytes(), &page)
				seen += len(page.Items)
				cursor = page.NextCursor
				if cursor == "" {
					break
				}
			}
			if seen != 5 {
				t.Fatalf("filtered cursor total=%d", seen)
			}
		})
	}
}

func TestQueryErrorMapping(t *testing.T) {
	for _, provider := range storetest.Providers(t) {
		t.Run(provider, func(t *testing.T) {
			h, s := setup(t, provider)
			w := invoke(t, h, s, "GET", `/api/v1/collections/issues/records?filter=missing%20=%20%22x%22`, nil, nil)
			if w.Code != 400 {
				t.Fatalf("unknown field %d %s", w.Code, w.Body.String())
			}
			w = invoke(t, h, s, "GET", `/api/v1/collections/issues/records?filter=score%20~%20%221%22`, nil, nil)
			if w.Code != 400 {
				t.Fatalf("invalid op %d %s", w.Code, w.Body.String())
			}
			w = invoke(t, h, s, "GET", `/api/v1/collections/issues/records?sort=missing`, nil, nil)
			if w.Code != 400 {
				t.Fatalf("unknown sort %d %s", w.Code, w.Body.String())
			}
		})
	}
}

func TestContainsCaseSemanticsAndWildcards(t *testing.T) {
	for _, provider := range storetest.Providers(t) {
		t.Run(provider, func(t *testing.T) {
			h, s := setup(t, provider)
			for _, title := range []string{"Alpha", "beta", "gamma"} {
				invoke(t, h, s, "POST", "/api/v1/collections/issues/records", map[string]any{"values": map[string]any{"title": title}}, nil)
			}
			contains := func(filter string) bool {
				w := invoke(t, h, s, "GET", "/api/v1/collections/issues/records?filter="+filter, nil, nil)
				if w.Code != 200 {
					t.Fatalf("filter %s: %d %s", filter, w.Code, w.Body.String())
				}
				return strings.Contains(w.Body.String(), `"Alpha"`) || strings.Contains(w.Body.String(), `"beta"`) || strings.Contains(w.Body.String(), `"gamma"`)
			}
			matches := func(filter string) []Record {
				w := invoke(t, h, s, "GET", "/api/v1/collections/issues/records?filter="+filter, nil, nil)
				var out struct {
					Items []Record `json:"items"`
				}
				json.Unmarshal(w.Body.Bytes(), &out)
				return out.Items
			}
			// Case-insensitive contains on both providers.
			if !contains(`title%20~%20%22alpha%22`) || !contains(`title%20~%20%22ALPHA%22`) || !contains(`title%20~%20%22ET%22`) {
				t.Fatal("case-insensitive contains failed")
			}
			// Wildcards are intentional: % matches any run, _ any single char.
			if items := matches(`title%20~%20%22b%25a%22`); len(items) != 1 || items[0].Values["title"] != "beta" {
				t.Fatalf("percent wildcard: %#v", items)
			}
			if items := matches(`title%20~%20%22a_pha%22`); len(items) != 1 || items[0].Values["title"] != "Alpha" {
				t.Fatalf("underscore wildcard: %#v", items)
			}
			// A value that is not present still matches nothing.
			if items := matches(`title%20~%20%22zzz%22`); len(items) != 0 {
				t.Fatalf("absent contains matched: %#v", items)
			}
		})
	}
}

func TestJSONRecordRoundTrip(t *testing.T) {
	for _, provider := range storetest.Providers(t) {
		t.Run(provider, func(t *testing.T) {
			s := storetest.Open(t, provider)
			auth := adminauth.New(s.DB(), string(s.Provider()))
			w := invoke(t, auth, session{}, "POST", "/admin/v1/setup", map[string]any{"username": "admin", "email": "admin@example.com", "password": "correct horse battery staple", "applicationRegistrationPolicy": "closed"}, nil)
			var login struct {
				CSRF string `json:"csrfToken"`
			}
			json.Unmarshal(w.Body.Bytes(), &login)
			sess := session{w.Result().Cookies()[0], login.CSRF}
			schemas := collections.New(s.DB(), auth)
			w = invoke(t, schemas, sess, "POST", "/admin/v1/collections", map[string]any{"name": "payloads", "fields": []map[string]any{{"name": "meta", "type": "json"}}}, nil)
			if w.Code != 201 {
				t.Fatal(w.Body.String())
			}
			h := New(s.DB(), auth)
			value := map[string]any{"nested": map[string]any{"tags": []any{"a", "b"}, "n": 3.5, "ok": true}}
			w = invoke(t, h, sess, "POST", "/api/v1/collections/payloads/records", map[string]any{"values": map[string]any{"meta": value}}, nil)
			if w.Code != 201 {
				t.Fatal(w.Body.String())
			}
			var created Record
			json.Unmarshal(w.Body.Bytes(), &created)
			w = invoke(t, h, sess, "GET", "/api/v1/collections/payloads/records/"+created.ID, nil, nil)
			var got Record
			json.Unmarshal(w.Body.Bytes(), &got)
			encoded, _ := json.Marshal(got.Values["meta"])
			want, _ := json.Marshal(value)
			if string(encoded) != string(want) {
				t.Fatalf("json round trip got %s want %s", encoded, want)
			}
		})
	}
}
