package jobs

import (
	"context"
	"encoding/json"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/trestle-cv/trestle/internal/storetest"
)

func TestConcurrentClaimsExecuteEachJobOnce(t *testing.T) {
	for _, provider := range storetest.Providers(t) {
		t.Run(provider, func(t *testing.T) {
			db := storetest.Open(t, provider)
			h := New(db.DB(), nil)
			var executed atomic.Int64
			h.Register("probe", func(context.Context, json.RawMessage) error {
				executed.Add(1)
				return nil
			})
			for i := 0; i < 64; i++ {
				tx, err := db.DB().BeginTx(context.Background(), nil)
				if err != nil {
					t.Fatal(err)
				}
				if _, _, err = h.Enqueue(context.Background(), tx, "probe", map[string]int{"index": i}, ""); err != nil {
					t.Fatal(err)
				}
				if err = tx.Commit(); err != nil {
					t.Fatal(err)
				}
			}
			var workers sync.WaitGroup
			for worker := 0; worker < 8; worker++ {
				workers.Add(1)
				go func() {
					defer workers.Done()
					for i := 0; i < 12; i++ {
						h.runOne(context.Background())
					}
				}()
			}
			workers.Wait()
			if got := executed.Load(); got != 64 {
				t.Fatalf("executed %d jobs, want 64", got)
			}
			var incomplete int
			if err := db.DB().QueryRow("SELECT count(*) FROM _trestle_jobs WHERE status!='succeeded' OR attempts!=1").Scan(&incomplete); err != nil || incomplete != 0 {
				t.Fatalf("incomplete or duplicate jobs: %d (%v)", incomplete, err)
			}
		})
	}
}

func TestExpiredLeaseRecoversAfterRestart(t *testing.T) {
	for _, provider := range storetest.Providers(t) {
		t.Run(provider, func(t *testing.T) {
			db := storetest.Open(t, provider)
			past := time.Now().Add(-time.Minute).UTC().Format(time.RFC3339Nano)
			now := time.Now().UTC().Format(time.RFC3339Nano)
			_, err := db.DB().Exec("INSERT INTO _trestle_jobs(id,kind,payload_json,status,attempts,available_at,lease_until,created_at,updated_at) VALUES('interrupted','noop','{}','running',1,?,?,?,?)", past, past, now, now)
			if err != nil {
				t.Fatal(err)
			}
			h := New(db.DB(), nil)
			h.runOne(context.Background())
			var status string
			var attempts int
			if err := db.DB().QueryRow("SELECT status,attempts FROM _trestle_jobs WHERE id='interrupted'").Scan(&status, &attempts); err != nil {
				t.Fatal(err)
			}
			if status != "succeeded" || attempts != 2 {
				t.Fatalf("recovered job = %s/%d, want succeeded/2", status, attempts)
			}
		})
	}
}

func TestRolledBackTransactionDoesNotPublishJob(t *testing.T) {
	for _, provider := range storetest.Providers(t) {
		t.Run(provider, func(t *testing.T) {
			db := storetest.Open(t, provider)
			h := New(db.DB(), nil)
			tx, err := db.DB().BeginTx(context.Background(), nil)
			if err != nil {
				t.Fatal(err)
			}
			if _, _, err := h.Enqueue(context.Background(), tx, "probe", map[string]any{"x": 1}, ""); err != nil {
				t.Fatal(err)
			}
			if err := tx.Rollback(); err != nil {
				t.Fatal(err)
			}
			var count int
			if err := db.DB().QueryRow("SELECT count(*) FROM _trestle_jobs").Scan(&count); err != nil || count != 0 {
				t.Fatalf("rolled-back job published: count=%d err=%v", count, err)
			}
		})
	}
}
