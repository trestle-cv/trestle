package records

import (
	"encoding/json"
	"testing"

	"github.com/trestle-cv/trestle/internal/adminauth"
	"github.com/trestle-cv/trestle/internal/appauth"
	"github.com/trestle-cv/trestle/internal/audit"
	"github.com/trestle-cv/trestle/internal/collections"
	"github.com/trestle-cv/trestle/internal/events"
	functionapi "github.com/trestle-cv/trestle/internal/functions"
	"github.com/trestle-cv/trestle/internal/identities"
	"github.com/trestle-cv/trestle/internal/jobs"
	"github.com/trestle-cv/trestle/internal/rules"
	"github.com/trestle-cv/trestle/internal/storetest"
	"github.com/trestle-cv/trestle/internal/webhooks"
)

// TestComposedRecordRollbackLeavesNoExternalState wires both dispatchers
// (webhooks and Lambda functions) plus audit and events into the record
// handler, forces the record transaction to fail after the associated writes
// are attempted, and asserts that no committed record, SSE event, audit fact,
// webhook job or Lambda job becomes visible on either provider.
func TestComposedRecordRollbackLeavesNoExternalState(t *testing.T) {
	for _, provider := range storetest.Providers(t) {
		t.Run(provider, func(t *testing.T) {
			s := storetest.Open(t, provider)
			admin := adminauth.New(s.DB(), string(s.Provider()))
			setup := invoke(t, admin, session{}, "POST", "/admin/v1/setup", map[string]any{"username": "admin", "email": "admin@example.com", "password": "correct horse battery staple", "applicationRegistrationPolicy": "closed"}, nil)
			var body struct {
				CSRF string `json:"csrfToken"`
			}
			json.Unmarshal(setup.Body.Bytes(), &body)
			sess := session{cookie: setup.Result().Cookies()[0], csrf: body.CSRF}

			schemas := collections.New(s.DB(), admin)
			created := invoke(t, schemas, sess, "POST", "/admin/v1/collections", map[string]any{"name": "issues", "fields": []map[string]any{{"name": "title", "type": "text", "required": true}}}, nil)
			if created.Code != 201 {
				t.Fatalf("collection %d %s", created.Code, created.Body.String())
			}

			users := appauth.New(s.DB(), admin)
			credentials := identities.New(s.DB(), admin)
			ruleHandler := rules.New(s.DB(), admin)
			queue := jobs.New(s.DB(), admin)
			webhookAPI, err := webhooks.New(s.DB(), admin, queue, t.TempDir())
			if err != nil {
				t.Fatal(err)
			}
			functionAPI := functionapi.New(s.DB(), admin, queue, functionapi.Options{})
			eventAPI := events.New(s.DB(), admin, credentials)
			eventAPI.ConfigureDispatcher(webhookAPI)
			eventAPI.ConfigureDispatcher(functionAPI)
			auditAPI := audit.New(s.DB(), admin, string(s.Provider()))
			recordAPI := New(s.DB(), admin, credentials)
			recordAPI.ConfigureAccess(users, ruleHandler)
			recordAPI.ConfigureEvents(eventAPI)
			recordAPI.ConfigureAudit(auditAPI)

			// A webhook target and a function target both subscribed to
			// record.created, so a committed mutation would enqueue both.
			wh := invoke(t, webhookAPI, sess, "POST", "/admin/v1/webhooks", map[string]any{"name": "hook", "url": "https://receiver.invalid/hook", "topics": []string{"record.created"}}, nil)
			if wh.Code != 201 {
				t.Fatalf("webhook %d %s", wh.Code, wh.Body.String())
			}
			fn := invoke(t, functionAPI, sess, "POST", "/admin/v1/functions", map[string]any{"name": "fn", "target": "arn:aws:lambda:us-east-1:1:function:x", "region": "us-east-1", "topics": []string{"record.created"}}, nil)
			if fn.Code != 201 {
				t.Fatalf("function %d %s", fn.Code, fn.Body.String())
			}

			// A batch where the second record reuses the first record's ID makes
			// the whole transaction fail after events, audit facts and outbox
			// jobs for the first record were already written in the transaction.
			w := invoke(t, recordAPI, sess, "POST", "/api/v1/collections/issues/records/batch", map[string]any{"records": []map[string]any{
				{"id": "rec_dup", "values": map[string]any{"title": "one"}},
				{"id": "rec_dup", "values": map[string]any{"title": "two"}},
			}}, nil)
			if w.Code != 409 {
				t.Fatalf("expected 409 batch conflict, got %d %s", w.Code, w.Body.String())
			}

			var recordCount, eventCount, auditCount, webhookJobs, functionJobs int
			checks := []struct {
				query string
				dst   *int
			}{
				{"SELECT count(*) FROM _trestle_events", &eventCount},
				{"SELECT count(*) FROM _trestle_audit", &auditCount},
				{"SELECT count(*) FROM _trestle_jobs WHERE kind='webhook'", &webhookJobs},
				{"SELECT count(*) FROM _trestle_jobs WHERE kind='function'", &functionJobs},
			}
			var colID string
			if err := s.DB().QueryRow("SELECT id FROM _trestle_collections WHERE name='issues'").Scan(&colID); err != nil {
				t.Fatal(err)
			}
			table := `"` + collections.PhysicalTableName(colID) + `"`
			if err := s.DB().QueryRow("SELECT count(*) FROM " + table).Scan(&recordCount); err != nil {
				t.Fatal(err)
			}
			for _, check := range checks {
				if err := s.DB().QueryRow(check.query).Scan(check.dst); err != nil {
					t.Fatal(err)
				}
			}
			if recordCount != 0 || eventCount != 0 || auditCount != 0 || webhookJobs != 0 || functionJobs != 0 {
				t.Fatalf("rollback leaked state: records=%d events=%d audit=%d webhookJobs=%d functionJobs=%d",
					recordCount, eventCount, auditCount, webhookJobs, functionJobs)
			}
		})
	}
}
