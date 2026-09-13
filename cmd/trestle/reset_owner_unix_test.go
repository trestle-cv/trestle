//go:build unix

package main

import (
	"os"
	"path/filepath"
	"syscall"
	"testing"
)

func TestPreserveResetDirectoryOwner(t *testing.T) {
	parent := t.TempDir()
	original := filepath.Join(parent, "original")
	replacement := filepath.Join(parent, "replacement")
	if err := os.Mkdir(original, 0700); err != nil {
		t.Fatal(err)
	}
	if os.Geteuid() == 0 {
		if err := os.Chown(original, 65534, 65534); err != nil {
			t.Skipf("cannot assign non-root fixture ownership: %v", err)
		}
	}
	info, err := os.Stat(original)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(replacement, 0700); err != nil {
		t.Fatal(err)
	}
	if err := preserveResetDirectoryOwner(replacement, info); err != nil {
		t.Fatal(err)
	}
	want := info.Sys().(*syscall.Stat_t)
	gotInfo, err := os.Stat(replacement)
	if err != nil {
		t.Fatal(err)
	}
	got := gotInfo.Sys().(*syscall.Stat_t)
	if got.Uid != want.Uid || got.Gid != want.Gid {
		t.Fatalf("replacement owner = %d:%d, want %d:%d", got.Uid, got.Gid, want.Uid, want.Gid)
	}
}
