package buildinfo

import "testing"

func TestCurrentHasDevelopmentIdentity(t *testing.T) {
	info := Current()
	if info.Version == "" || info.Commit == "" || info.Date == "" {
		t.Fatalf("incomplete build information: %#v", info)
	}
	if info.Go == "" || info.OS == "" || info.Arch == "" {
		t.Fatalf("incomplete runtime information: %#v", info)
	}
}

// The source default is the current development identity on main; release
// builds override it with ldflags. An ordinary development build must never
// present itself as the last published stable release, so this pins the exact
// development version rather than accepting any non-empty value.
func TestCurrentDevelopmentVersionIsNextPatch(t *testing.T) {
	info := Current()
	if info.Version != "0.1.4" {
		t.Fatalf("development build reports %q; want the next patch version 0.1.4", info.Version)
	}
	if info.Commit != "unknown" {
		t.Fatalf("development build unexpectedly reports a release commit: %q", info.Commit)
	}
}
