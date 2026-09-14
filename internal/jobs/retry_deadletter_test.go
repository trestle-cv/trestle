package jobs

import (
	"context"
	"encoding/json"
	"errors"
	"testing"
	"time"

	"github.com/trestle-cv/trestle/internal/storetest"
)

// TestJobRetryBackoffThenDeadLetter proves a failing job retries with an
// exponential backoff and is dead-lettered after max_attempts, with its error
// message retained, on both providers.
func TestJobRetryBackoffThenDeadLetter(t *testing.T) {
	for _, provider := range storetest.Providers(t) {
		t.Run(provider, func(t *testing.T) {
			s := storetest.Open(t, provider)
			h := New(s.DB(), nil)
			h.Register("boom", func(context.Context, json.RawMessage) error {
				return errors.New("boom")
			})
			fake := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
			h.now = func() time.Time { return fake }

			tx, err := s.DB().BeginTx(context.Background(), nil)
			if err != nil {
				t.Fatal(err)
			}
			if _, _, err := h.Enqueue(context.Background(), tx, "boom", map[string]any{}, ""); err != nil {
				t.Fatal(err)
			}
			if err := tx.Commit(); err != nil {
				t.Fatal(err)
			}
			var id string
			if err := s.DB().QueryRow("SELECT id FROM _trestle_jobs LIMIT 1").Scan(&id); err != nil {
				t.Fatal(err)
			}

			// First failure: retried with a future available_at (backoff), not dead.
			h.runOne(context.Background())
			var status string
			var attempts int
			var availableAt string
			if err := s.DB().QueryRow("SELECT status,attempts,available_at FROM _trestle_jobs WHERE id=?", id).Scan(&status, &attempts, &availableAt); err != nil {
				t.Fatal(err)
			}
			if status != "pending" || attempts != 1 {
				t.Fatalf("after first failure status=%q attempts=%d, want pending/1", status, attempts)
			}
			if parsed, _ := time.Parse(time.RFC3339Nano, availableAt); !parsed.After(fake) {
				t.Fatalf("retry available_at %q is not in the future (no backoff)", availableAt)
			}

			// Advance far enough past every backoff and drive to dead-letter.
			for i := 0; i < 8; i++ {
				fake = fake.Add(300 * time.Second)
				h.runOne(context.Background())
			}
			var lastError string
			if err := s.DB().QueryRow("SELECT status,attempts,last_error FROM _trestle_jobs WHERE id=?", id).Scan(&status, &attempts, &lastError); err != nil {
				t.Fatal(err)
			}
			if status != "dead" {
				t.Fatalf("final status=%q, want dead (attempts=%d)", status, attempts)
			}
			if lastError != "boom" {
				t.Fatalf("last_error=%q, want the failure message", lastError)
			}
		})
	}
}
