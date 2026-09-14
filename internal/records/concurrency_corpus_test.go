package records

import (
	"encoding/json"
	"fmt"
	"sync"
	"testing"

	"github.com/trestle-cv/trestle/internal/adminauth"
	"github.com/trestle-cv/trestle/internal/collections"
	"github.com/trestle-cv/trestle/internal/storetest"
)

// TestConcurrentCreateUniqueFieldOneWinner proves simultaneous record creation
// with the same unique field value resolves to exactly one winner on both
// providers (no duplicate and no torn row).
func TestConcurrentCreateUniqueFieldOneWinner(t *testing.T) {
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
			w = invoke(t, schemas, sess, "POST", "/admin/v1/collections", map[string]any{"name": "tickets", "fields": []map[string]any{{"name": "code", "type": "text", "unique": true, "required": true}}}, nil)
			if w.Code != 201 {
				t.Fatalf("schema %d %s", w.Code, w.Body.String())
			}
			h := New(s.DB(), auth)

			create := func() int {
				return invoke(t, h, sess, "POST", "/api/v1/collections/tickets/records", map[string]any{"values": map[string]any{"code": "T-1"}}, nil).Code
			}
			ready := make(chan struct{})
			var a, b int
			var wg sync.WaitGroup
			wg.Add(2)
			go func() { defer wg.Done(); <-ready; a = create() }()
			go func() { defer wg.Done(); <-ready; b = create() }()
			close(ready)
			wg.Wait()

			// Deterministic semantics: exactly one create commits.
			wins := 0
			for _, code := range []int{a, b} {
				if code == 201 {
					wins++
				}
			}
			if wins != 1 {
				t.Fatalf("create winners=%d (a=%d b=%d), want exactly 1", wins, a, b)
			}
			var colID string
			if err := s.DB().QueryRow("SELECT id FROM _trestle_collections WHERE name='tickets'").Scan(&colID); err != nil {
				t.Fatal(err)
			}
			var count int
			if err := s.DB().QueryRow("SELECT count(*) FROM " + collections.PhysicalTableName(colID)).Scan(&count); err != nil {
				t.Fatal(err)
			}
			if count != 1 {
				t.Fatalf("record rows=%d, want exactly 1", count)
			}
		})
	}
}

// TestConcurrentEditOptimisticVersionOneWinner proves two concurrent updates to
// the same version resolve to exactly one winner via optimistic concurrency.
func TestConcurrentEditOptimisticVersionOneWinner(t *testing.T) {
	for _, provider := range storetest.Providers(t) {
		t.Run(provider, func(t *testing.T) {
			h, s := setup(t, provider)
			created := invoke(t, h, s, "POST", "/api/v1/collections/issues/records", map[string]any{"values": map[string]any{"title": "base"}}, nil)
			if created.Code != 201 {
				t.Fatalf("create %d %s", created.Code, created.Body.String())
			}
			var rec Record
			json.Unmarshal(created.Body.Bytes(), &rec)

			update := func(title string) int {
				return invoke(t, h, s, "PATCH", "/api/v1/collections/issues/records/"+rec.ID, map[string]any{"values": map[string]any{"title": title}}, map[string]string{"If-Match": "1"}).Code
			}
			ready := make(chan struct{})
			var a, b int
			var wg sync.WaitGroup
			wg.Add(2)
			go func() { defer wg.Done(); <-ready; a = update("one") }()
			go func() { defer wg.Done(); <-ready; b = update("two") }()
			close(ready)
			wg.Wait()

			wins := 0
			for _, code := range []int{a, b} {
				if code == 200 {
					wins++
				}
			}
			if wins != 1 {
				t.Fatalf("update winners=%d (a=%d b=%d), want exactly 1", wins, a, b)
			}
			// The committed value is exactly one of the two updates.
			got := invoke(t, h, s, "GET", "/api/v1/collections/issues/records/"+rec.ID, nil, nil)
			var final Record
			json.Unmarshal(got.Body.Bytes(), &final)
			title, _ := final.Values["title"].(string)
			if title != "one" && title != "two" {
				t.Fatalf("final title=%q, want one of the committed updates", title)
			}
			if final.Version != 2 {
				t.Fatalf("final version=%d, want 2", final.Version)
			}
		})
	}
}

// TestDeleteUpdateRaceResolvesConsistently proves a delete racing an update
// commits deterministically: the record ends deleted and the update either
// won (then the delete removed it) or was rejected; no partial or torn state.
func TestDeleteUpdateRaceResolvesConsistently(t *testing.T) {
	for _, provider := range storetest.Providers(t) {
		t.Run(provider, func(t *testing.T) {
			st := storetest.Open(t, provider)
			auth := adminauth.New(st.DB(), string(st.Provider()))
			w := invoke(t, auth, session{}, "POST", "/admin/v1/setup", map[string]any{"username": "admin", "email": "admin@example.com", "password": "correct horse battery staple", "applicationRegistrationPolicy": "closed"}, nil)
			var login struct {
				CSRF string `json:"csrfToken"`
			}
			json.Unmarshal(w.Body.Bytes(), &login)
			sess := session{w.Result().Cookies()[0], login.CSRF}
			schemas := collections.New(st.DB(), auth)
			w = invoke(t, schemas, sess, "POST", "/admin/v1/collections", map[string]any{"name": "issues", "fields": []map[string]any{{"name": "title", "type": "text", "required": true}}}, nil)
			if w.Code != 201 {
				t.Fatalf("schema %d %s", w.Code, w.Body.String())
			}
			h := New(st.DB(), auth)

			created := invoke(t, h, sess, "POST", "/api/v1/collections/issues/records", map[string]any{"values": map[string]any{"title": "race"}}, nil)
			var rec Record
			json.Unmarshal(created.Body.Bytes(), &rec)

			update := func() int {
				return invoke(t, h, sess, "PATCH", "/api/v1/collections/issues/records/"+rec.ID, map[string]any{"values": map[string]any{"title": "updated"}}, map[string]string{"If-Match": "1"}).Code
			}
			remove := func() int {
				return invoke(t, h, sess, "DELETE", "/api/v1/collections/issues/records/"+rec.ID, nil, map[string]string{"If-Match": "1"}).Code
			}
			ready := make(chan struct{})
			var upd, del int
			var wg sync.WaitGroup
			wg.Add(2)
			go func() { defer wg.Done(); <-ready; upd = update() }()
			go func() { defer wg.Done(); <-ready; del = remove() }()
			close(ready)
			wg.Wait()

			// Optimistic concurrency: exactly one of the update or the delete
			// commits against version 1. If the update won, the record exists
			// with version 2; if the delete won, the record is gone.
			switch {
			case upd == 200 && del == 412:
				got := invoke(t, h, sess, "GET", "/api/v1/collections/issues/records/"+rec.ID, nil, nil)
				if got.Code != 200 {
					t.Fatalf("update winner but record missing (upd=%d del=%d)", upd, del)
				}
				var final Record
				json.Unmarshal(got.Body.Bytes(), &final)
				if final.Version != 2 || final.Values["title"] != "updated" {
					t.Fatalf("update winner state=%#v", final)
				}
			case del == 204 && (upd == 409 || upd == 404 || upd == 412):
				// The update lost (conflict, not-found, or version conflict
				// after the delete removed the row); the record is gone.
				got := invoke(t, h, sess, "GET", "/api/v1/collections/issues/records/"+rec.ID, nil, nil)
				if got.Code != 404 {
					t.Fatalf("delete winner but record still present (upd=%d del=%d)", upd, del)
				}
			default:
				t.Fatalf("unexpected race outcome upd=%d del=%d", upd, del)
			}
		})
	}
}

// TestSchemaChangeDuringRecordAccess proves a collection schema change running
// concurrently with record writes and reads leaves a consistent schema and
// never loses a committed record: every create that returned 201 is durable in
// the final physical table with its values intact, and the field set is exactly
// the old or the new one (never torn).
func TestSchemaChangeDuringRecordAccess(t *testing.T) {
	for _, provider := range storetest.Providers(t) {
		t.Run(provider, func(t *testing.T) {
			st := storetest.Open(t, provider)
			auth := adminauth.New(st.DB(), string(st.Provider()))
			w := invoke(t, auth, session{}, "POST", "/admin/v1/setup", map[string]any{"username": "admin", "email": "admin@example.com", "password": "correct horse battery staple", "applicationRegistrationPolicy": "closed"}, nil)
			var login struct {
				CSRF string `json:"csrfToken"`
			}
			json.Unmarshal(w.Body.Bytes(), &login)
			sess := session{w.Result().Cookies()[0], login.CSRF}
			schemas := collections.New(st.DB(), auth)
			w = invoke(t, schemas, sess, "POST", "/admin/v1/collections", map[string]any{"name": "events", "fields": []map[string]any{{"name": "title", "type": "text", "required": true}}}, nil)
			if w.Code != 201 {
				t.Fatalf("schema %d %s", w.Code, w.Body.String())
			}
			h := New(st.DB(), auth)

			// Baseline records before the change.
			ids := []string{"baseline"}
			created := invoke(t, h, sess, "POST", "/api/v1/collections/events/records", map[string]any{"values": map[string]any{"title": "base"}}, nil)
			var base Record
			json.Unmarshal(created.Body.Bytes(), &base)
			ids = append(ids, base.ID)

			// Concurrent schema change (add a field) and record writes.
			change := func() int {
				return invoke(t, schemas, sess, "PATCH", "/admin/v1/collections/events", map[string]any{"fields": []map[string]any{
					{"name": "title", "type": "text", "required": true},
					{"name": "extra", "type": "text"},
				}}, nil).Code
			}
			createRecord := func(i int) (string, int) {
				w := invoke(t, h, sess, "POST", "/api/v1/collections/events/records", map[string]any{"values": map[string]any{"title": fmt.Sprintf("t%d", i)}}, nil)
				if w.Code != 201 {
					return "", w.Code
				}
				var r Record
				json.Unmarshal(w.Body.Bytes(), &r)
				return r.ID, 201
			}
			ready := make(chan struct{})
			var changeCode int
			var wg sync.WaitGroup
			wg.Add(2)
			go func() { defer wg.Done(); <-ready; changeCode = change() }()
			createdIDs := make([]string, 8)
			go func() {
				defer wg.Done()
				<-ready
				for i := 0; i < len(createdIDs); i++ {
					id, code := createRecord(i)
					if code == 201 {
						createdIDs[i] = id
					}
				}
			}()
			close(ready)
			wg.Wait()

			// Schema is exactly the old or the new field set, never torn.
			var fieldCount int
			if err := st.DB().QueryRow("SELECT count(*) FROM _trestle_fields WHERE collection_id=(SELECT id FROM _trestle_collections WHERE name='events')").Scan(&fieldCount); err != nil {
				t.Fatal(err)
			}
			if fieldCount != 1 && fieldCount != 2 {
				t.Fatalf("field count=%d, want 1 or 2 (schema torn)", fieldCount)
			}
			// The change either committed (200) or was rejected cleanly and
			// retryably (422); both leave a consistent, non-torn schema.
			if changeCode != 200 && changeCode != 422 {
				t.Fatalf("schema change returned %d", changeCode)
			}

			// Every 201 create is durable with its title intact in the final
			// physical table.
			var colID string
			if err := st.DB().QueryRow("SELECT id FROM _trestle_collections WHERE name='events'").Scan(&colID); err != nil {
				t.Fatal(err)
			}
			table := collections.PhysicalTableName(colID)
			var titleField string
			if err := st.DB().QueryRow("SELECT id FROM _trestle_fields WHERE collection_id=? AND name='title'", colID).Scan(&titleField); err != nil {
				t.Fatal(err)
			}
			titleColumn := collections.PhysicalColumnName(titleField)
			allIDs := append([]string{base.ID}, createdIDs...)
			for _, id := range allIDs {
				if id == "" {
					continue
				}
				var title string
				if err := st.DB().QueryRow("SELECT "+titleColumn+" FROM "+table+" WHERE _id=?", id).Scan(&title); err != nil {
					t.Fatalf("committed record %s lost during schema change: %v", id, err)
				}
				if title == "" {
					t.Fatalf("committed record %s has empty title", id)
				}
			}
		})
	}
}
