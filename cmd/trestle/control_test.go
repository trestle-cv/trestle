package main

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/trestle-cv/trestle/internal/adminauth"
	"github.com/trestle-cv/trestle/internal/store"
)

func useInstalledResetDir(t *testing.T, dir string) {
	t.Helper()
	old := resetInstalledDataDir
	resetInstalledDataDir = func() (string, bool, error) { return dir, true, nil }
	t.Cleanup(func() { resetInstalledDataDir = old })
	t.Setenv("TRESTLE_DATA_DIR", "")
}

func TestRunResetAuthUsesInstalledServiceData(t *testing.T) {
	dir := t.TempDir()
	db, err := store.Open(context.Background(), dir)
	if err != nil {
		t.Fatal(err)
	}
	if err := adminauth.New(db.DB(), "sqlite").SetupAdministrator(context.Background(), "admin@example.com", "correct horse battery", "closed"); err != nil {
		db.Close()
		t.Fatal(err)
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}
	useInstalledResetDir(t, dir)

	if code := runReset([]string{"--auth", "--confirm", "TRESTLE AUTH"}); code != 0 {
		t.Fatalf("reset exit = %d, want 0", code)
	}
	db, err = store.Open(context.Background(), dir)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	var admins int
	if err := db.DB().QueryRow("SELECT COUNT(*) FROM _trestle_admins").Scan(&admins); err != nil {
		t.Fatal(err)
	}
	if admins != 0 {
		t.Fatalf("administrator count = %d, want 0", admins)
	}
	backups, err := filepath.Glob(filepath.Join(dir, "reset-auth-*.db"))
	if err != nil || len(backups) != 1 {
		t.Fatalf("auth backups = %v, err = %v; want one", backups, err)
	}
}

func TestRunResetAllUsesInstalledServiceData(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "marker"), []byte("state"), 0600); err != nil {
		t.Fatal(err)
	}
	useInstalledResetDir(t, dir)

	if code := runReset([]string{"--all", "--confirm", "TRESTLE ALL"}); code != 0 {
		t.Fatalf("reset exit = %d, want 0", code)
	}
	if _, err := os.Stat(filepath.Join(dir, "marker")); !os.IsNotExist(err) {
		t.Fatalf("new data directory retained old marker: %v", err)
	}
	backups, err := filepath.Glob(dir + ".reset-*")
	if err != nil || len(backups) != 1 {
		t.Fatalf("full backups = %v, err = %v; want one", backups, err)
	}
	if got, err := os.ReadFile(filepath.Join(backups[0], "marker")); err != nil || string(got) != "state" {
		t.Fatalf("backup marker = %q, err = %v", got, err)
	}
}
