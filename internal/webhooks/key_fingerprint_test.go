package webhooks

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestKeyFingerprintNonSecret proves the exported fingerprint is a SHA-256 of
// the webhook.key file (never the key itself), is stable for the same key, and
// differs across keys. An absent key reports an error rather than inventing a
// key.
func TestKeyFingerprintNonSecret(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "webhook.key")
	if _, err := KeyFingerprint(dir); err == nil {
		t.Fatal("absent key should error, not silently create material")
	}
	key := make([]byte, 32)
	for i := range key {
		key[i] = byte(i)
	}
	if err := os.WriteFile(path, key, 0600); err != nil {
		t.Fatal(err)
	}
	fp, err := KeyFingerprint(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(fp) != 64 {
		t.Fatalf("fingerprint length %d, want 64 hex", len(fp))
	}
	if strings.Contains(fp, string(key)) {
		t.Fatal("fingerprint must never contain the raw key")
	}
	fp2, err := KeyFingerprint(dir)
	if err != nil || fp2 != fp {
		t.Fatalf("fingerprint not stable: %q vs %q (err %v)", fp, fp2, err)
	}
	other := make([]byte, 32)
	other[0] = 0xFF
	dir2 := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir2, "webhook.key"), other, 0600); err != nil {
		t.Fatal(err)
	}
	fp3, _ := KeyFingerprint(dir2)
	if fp3 == fp {
		t.Fatal("different keys must produce different fingerprints")
	}
}
