package service

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

type fakeResult struct {
	out  string
	code int
	err  error
}

func TestInstalledDataDirUsesOnlyManagedUnit(t *testing.T) {
	oldUnitPath := UnitPath
	UnitPath = filepath.Join(t.TempDir(), "trestle.service")
	t.Cleanup(func() { UnitPath = oldUnitPath })

	if dir, installed, err := InstalledDataDir(); err != nil || installed || dir != "" {
		t.Fatalf("absent unit = (%q, %v, %v), want (empty, false, nil)", dir, installed, err)
	}
	want := "/srv/trestle-data"
	if err := os.WriteFile(UnitPath, []byte(Unit(want, "127.0.0.1:7333", "")), 0644); err != nil {
		t.Fatal(err)
	}
	if dir, installed, err := InstalledDataDir(); err != nil || !installed || dir != want {
		t.Fatalf("managed unit = (%q, %v, %v), want (%q, true, nil)", dir, installed, err, want)
	}
	if err := os.WriteFile(UnitPath, []byte("[Service]\nExecStart=/tmp/trestle\n"), 0644); err != nil {
		t.Fatal(err)
	}
	if _, _, err := InstalledDataDir(); err == nil {
		t.Fatal("foreign unit did not fail closed")
	}
}

type fakeRunner struct {
	script map[string]fakeResult
	log    []string
	calls  map[string]int
	seq    map[string][]fakeResult
	// strict makes any unconfigured systemctl/journalctl invocation fail with
	// a nonzero exit so an unexpected lifecycle call can never be hidden by a
	// permissive default success.
	strict bool
}

func (f *fakeRunner) Run(name string, args ...string) (string, int, error) {
	key := name + " " + strings.Join(args, " ")
	f.log = append(f.log, key)
	if f.calls == nil {
		f.calls = map[string]int{}
	}
	n := f.calls[key]
	f.calls[key] = n + 1
	if seq, ok := f.seq[key]; ok && n < len(seq) {
		r := seq[n]
		return r.out, r.code, r.err
	}
	if r, ok := f.script[key]; ok {
		return r.out, r.code, r.err
	}
	if f.strict {
		return "", 1, fmt.Errorf("unexpected command: %s", key)
	}
	return "", 0, nil
}

func (f *fakeRunner) Stream(name string, args ...string) (int, error) {
	key := name + " " + strings.Join(args, " ")
	f.log = append(f.log, key)
	if r, ok := f.script[key]; ok {
		return r.code, r.err
	}
	if f.strict {
		return 1, fmt.Errorf("unexpected command: %s", key)
	}
	return 0, nil
}

func setupService(t *testing.T) *fakeRunner {
	t.Helper()
	dir := t.TempDir()
	oldUnit, oldBin := UnitPath, BinaryPath
	oldRoot, oldAccount := isRoot, ensureAccount
	oldUID := serviceUID
	oldOpenParent, oldConsistent := openDataParentSeam, dataParentConsistentSeam
	oldParentSafe := parentSafeSeam
	oldStatLeaf, oldMkdirAt := statDataLeafSeam, mkdirAtLeafSeam
	oldOpenAt, oldChmod, oldChown := openAtLeafSeam, fchmodLeafSeam, fchownLeafSeam
	oldFstat, oldUnlink, oldClose := fstatLeafSeam, unlinkAtSeam, closeFdSeam
	oldRunner := defaultRunner
	oldHealth := healthWindow
	oldWaitReady := waitServiceReady
	oldPriorRead := priorStateFileRead
	UnitPath = filepath.Join(dir, "trestle.service")
	BinaryPath = filepath.Join(dir, "trestle")
	os.WriteFile(BinaryPath, []byte("#!/bin/sh\nexit 0\n"), 0o755)
	isRoot = func() bool { return true }
	ensureAccount = func() error { return nil }
	serviceUID = func() (int, error) { return 4242, nil }
	openDataParentSeam = func(string) (int, error) { return 1, nil }
	dataParentConsistentSeam = func(int, string) bool { return true }
	parentSafeSeam = func(int) error { return nil }
	statDataLeafSeam = func(int, string) (dataLeafInfo, error) { return dataLeafInfo{}, os.ErrNotExist }
	mkdirAtLeafSeam = func(int, string) error { return nil }
	openAtLeafSeam = func(int, string) (int, error) { return 2, nil }
	fchmodLeafSeam = func(int) error { return nil }
	fchownLeafSeam = func(int) error { return nil }
	fstatLeafSeam = func(int) (dataLeafInfo, error) {
		return dataLeafInfo{isDir: true, mode: 0o700, uid: 4242}, nil
	}
	unlinkAtSeam = func(int, string) error { return nil }
	closeFdSeam = func(int) error { return nil }
	r := &fakeRunner{script: map[string]fakeResult{"systemctl reset-failed trestle.service": {}}, seq: map[string][]fakeResult{}}
	defaultRunner = r
	waitServiceReady = func() error { return nil }
	t.Cleanup(func() {
		UnitPath, BinaryPath = oldUnit, oldBin
		isRoot, ensureAccount = oldRoot, oldAccount
		serviceUID = oldUID
		openDataParentSeam, dataParentConsistentSeam = oldOpenParent, oldConsistent
		parentSafeSeam = oldParentSafe
		statDataLeafSeam, mkdirAtLeafSeam = oldStatLeaf, oldMkdirAt
		openAtLeafSeam, fchmodLeafSeam, fchownLeafSeam = oldOpenAt, oldChmod, oldChown
		fstatLeafSeam, unlinkAtSeam, closeFdSeam = oldFstat, oldUnlink, oldClose
		healthWindow = oldHealth
		waitServiceReady = oldWaitReady
		priorStateFileRead = oldPriorRead
		healthCheckFunc = func(url string) error { return healthCheckReal(url) }
		defaultRunner = oldRunner
	})
	return r
}

// useRealDataDirSeams switches the descriptor-relative data-dir seams to their
// real syscall implementations so a test exercises the actual filesystem
// establishment.
func useRealDataDirSeams(t *testing.T) {
	t.Helper()
	openDataParentSeam = openDataParentReal
	dataParentConsistentSeam = dataParentConsistentReal
	parentSafeSeam = parentSafeReal
	statDataLeafSeam = statDataLeafReal
	mkdirAtLeafSeam = mkdirAtLeafReal
	openAtLeafSeam = openAtLeafReal
	fchmodLeafSeam = fchmodLeafReal
	fchownLeafSeam = func(fd int) error { return nil } // tests run unprivileged; ownership is simulated
	fstatLeafSeam = fstatLeafReal
	unlinkAtSeam = unlinkAtLeafReal
	closeFdSeam = closeFdReal
}

// simulateSafeParent accepts the parent for tests that create real leaves under
// a temporary (non-root, writable) parent, since the safe-parent contract would
// refuse it; it keeps every other descriptor-relative seam real.
func simulateSafeParent(t *testing.T) {
	t.Helper()
	parentSafeSeam = func(int) error { return nil }
}

// hasMutatingSystemctl reports whether the fake runner issued a mutating
// lifecycle verb (enable/disable/start/stop/restart/daemon-reload).
func hasMutatingSystemctl(log []string) bool {
	for _, call := range log {
		for _, prefix := range []string{
			"systemctl enable ", "systemctl disable ", "systemctl start ",
			"systemctl restart ", "systemctl stop ", "systemctl daemon-reload",
		} {
			if strings.HasPrefix(call, prefix) {
				return true
			}
		}
	}
	return false
}

func installManagedUnit(t *testing.T) {
	t.Helper()
	if e := writeFileAtomic(UnitPath, []byte(Unit(DefaultDataDir, "127.0.0.1:8090", "")), 0o644); e != nil {
		t.Fatal(e)
	}
}

func setState(r *fakeRunner, enabled, active string) {
	r.script["systemctl is-enabled trestle.service"] = fakeResult{out: enabled, code: 0}
	r.script["systemctl is-active trestle.service"] = fakeResult{out: active, code: 0}
}

func prepareUpdate(r *fakeRunner, active string, healthOK bool) {
	r.script["systemctl is-active trestle.service"] = fakeResult{out: active, code: 0}
	old := healthCheckFunc
	healthCheckFunc = func(url string) error {
		if !healthOK {
			return fmt.Errorf("health failed")
		}
		return nil
	}
	_ = old
}

func mustRead(t *testing.T, path string) []byte {
	t.Helper()
	b, e := os.ReadFile(path)
	if e != nil {
		t.Fatal(e)
	}
	return b
}

func fakeSHA(path string) string {
	h, _ := fileSHA256(path)
	return h
}

func contains(hay []string, needle string) bool {
	for _, h := range hay {
		if h == needle {
			return true
		}
	}
	return false
}

func TestUnitHardeningAndManagedMarker(t *testing.T) {
	setupService(t)
	u := Unit(DefaultDataDir, "127.0.0.1:8090", "")
	for _, x := range []string{"# Managed by trestle. Do not edit manually.", "StartLimitIntervalSec=60", "StartLimitBurst=5", "Restart=on-failure", "RestartSec=3", "NoNewPrivileges=true", "ProtectSystem=strict", "ReadWritePaths=\"/var/lib/trestle\"", "User=" + ServiceUser, "Group=" + ServiceGroup, "WantedBy=multi-user.target"} {
		if !strings.Contains(u, x) {
			t.Fatal("missing " + x)
		}
	}
	if !strings.Contains(Unit(DefaultDataDir, "127.0.0.1:8090", "/etc/trestle/trestle.env"), "EnvironmentFile=\"/etc/trestle/trestle.env\"") {
		t.Fatal("env file not referenced")
	}
	if !strings.Contains(u, "trestle-managed: v1 sha256=") {
		t.Fatal("managed integrity header missing")
	}
}

func TestValidateNoControlAndQuote(t *testing.T) {
	if e := validateNoControl("127.0.0.1:8090", "listen"); e != nil {
		t.Fatal(e)
	}
	if e := validateNoControl("127.0.0.1:8090\nfoo", "listen"); e == nil {
		t.Fatal("newline accepted")
	}
	if got := systemdQuote(`/a b/"x"$y`); got != `"/a b/\"x\"\$y"` {
		t.Fatalf("quote = %q", got)
	}
}

func TestLifecycleVerbsRequireManagedUnit(t *testing.T) {
	r := setupService(t)
	for _, v := range []string{"start", "stop", "restart", "enable", "disable"} {
		if err := lifecycle(v); err == nil {
			t.Fatalf("%s succeeded without an installed unit", v)
		}
		if len(r.log) != 0 {
			t.Fatalf("%s touched systemctl without a managed unit", v)
		}
	}
	installManagedUnit(t)
	r.script["systemctl is-active trestle.service"] = fakeResult{out: "active", code: 0}
	r.script["systemctl start trestle.service"] = fakeResult{}
	if err := lifecycle("start"); err != nil {
		t.Fatal(err)
	}
	if !contains(r.log, "systemctl start trestle.service") {
		t.Fatal("start did not call systemctl")
	}
	if !contains(r.log, "systemctl reset-failed trestle.service") {
		t.Fatal("start did not clear the accumulated start-limit state")
	}
}

func TestLifecycleStartAndRestartVerifyHealth(t *testing.T) {
	r := setupService(t)
	installManagedUnit(t)
	r.script["systemctl start trestle.service"] = fakeResult{}
	r.script["systemctl restart trestle.service"] = fakeResult{}
	calls := 0
	waitServiceReady = func() error { calls++; return nil }
	if err := Start(); err != nil {
		t.Fatal(err)
	}
	if err := Restart(); err != nil {
		t.Fatal(err)
	}
	if calls != 2 {
		t.Fatalf("readiness checks = %d want 2", calls)
	}
	if r.calls["systemctl reset-failed trestle.service"] != 2 {
		t.Fatalf("reset-failed calls = %d want 2", r.calls["systemctl reset-failed trestle.service"])
	}
}

func TestLifecycleResetFailurePreventsStart(t *testing.T) {
	r := setupService(t)
	installManagedUnit(t)
	r.script["systemctl reset-failed trestle.service"] = fakeResult{out: "reset failed", code: 1}
	if err := Start(); err == nil {
		t.Fatal("start succeeded after reset-failed failed")
	}
	if contains(r.log, "systemctl start trestle.service") {
		t.Fatal("start was attempted after reset-failed failed")
	}
}

func TestLifecycleRefusesForeignUnit(t *testing.T) {
	setupService(t)
	if e := writeFileAtomic(UnitPath, []byte("[Unit]\nDescription=admin unit\n"), 0o644); e != nil {
		t.Fatal(e)
	}
	for _, v := range []string{"start", "stop", "restart", "enable", "disable", "uninstall"} {
		if err := lifecycle(v); err == nil {
			t.Fatalf("%s modified a foreign unit", v)
		}
	}
}

func TestInstallRequiresRoot(t *testing.T) {
	oldRoot := isRoot
	isRoot = func() bool { return false }
	defer func() { isRoot = oldRoot }()
	if e := Install("", t.TempDir(), "127.0.0.1:0", ""); e == nil {
		t.Fatal("install succeeded without root")
	}
}

func TestFreshInstallHealthFailureRollsBack(t *testing.T) {
	r := setupService(t)
	exe := filepath.Join(t.TempDir(), "tr")
	if err := os.WriteFile(exe, []byte("#!/bin/sh\nexit 0\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	r.script["systemctl daemon-reload"] = fakeResult{}
	r.script["systemctl enable trestle.service"] = fakeResult{}
	r.script["systemctl restart trestle.service"] = fakeResult{}
	r.script["systemctl stop trestle.service"] = fakeResult{}
	r.script["systemctl disable trestle.service"] = fakeResult{}
	waitServiceReady = func() error { return fmt.Errorf("wrong listener") }
	if err := Install(exe, "/var/lib/trestle", "127.0.0.1:8090", ""); err == nil {
		t.Fatal("install reported success before Trestle became healthy")
	}
	if _, err := os.Stat(UnitPath); !os.IsNotExist(err) {
		t.Fatal("failed fresh install left its unit installed")
	}
	if !contains(r.log, "systemctl stop trestle.service") || !contains(r.log, "systemctl disable trestle.service") {
		t.Fatalf("failed install was not neutralized: %v", r.log)
	}
}

func TestIdenticalActiveInstallStillChecksHealth(t *testing.T) {
	r := setupService(t)
	installManagedUnit(t)
	setState(r, "enabled", "active")
	statDataLeafSeam = func(int, string) (dataLeafInfo, error) {
		return dataLeafInfo{isDir: true, mode: 0o700, uid: 4242}, nil
	}
	exe := filepath.Join(t.TempDir(), "tr")
	if err := os.WriteFile(exe, mustRead(t, BinaryPath), 0o755); err != nil {
		t.Fatal(err)
	}
	waitServiceReady = func() error { return fmt.Errorf("foreign process") }
	if err := Install(exe, "/var/lib/trestle", "127.0.0.1:8090", ""); err == nil {
		t.Fatal("unhealthy active no-op install reported success")
	}
	if hasMutatingSystemctl(r.log) {
		t.Fatalf("no-op health failure mutated systemd: %v", r.log)
	}
}

func TestReinstallRestoresPriorUnitOnFailure(t *testing.T) {
	r := setupService(t)
	exe := filepath.Join(t.TempDir(), "tr")
	os.WriteFile(exe, []byte("#!/bin/sh\nexit 0\n"), 0o755)
	r.script["systemctl daemon-reload"] = fakeResult{}
	r.script["systemctl enable trestle.service"] = fakeResult{}
	r.script["systemctl start trestle.service"] = fakeResult{}
	if e := Install(exe, "/var/lib/trestle", "127.0.0.1:8090", ""); e != nil {
		t.Fatal(e)
	}
	priorUnit, _ := os.ReadFile(UnitPath)
	if !strings.Contains(string(priorUnit), "Managed by trestle") {
		t.Fatal("installed unit lacks the managed marker")
	}
	r.script["systemctl is-enabled trestle.service"] = fakeResult{out: "enabled", code: 0}
	r.script["systemctl is-active trestle.service"] = fakeResult{out: "active", code: 0}
	r.script["systemctl daemon-reload"] = fakeResult{}
	r.script["systemctl enable trestle.service"] = fakeResult{out: "failed to enable", code: 3}
	r.script["systemctl restart trestle.service"] = fakeResult{}
	r.script["systemctl start trestle.service"] = fakeResult{}
	if e := Install(exe, "/var/lib/trestle", "127.0.0.1:9090", ""); e == nil {
		t.Fatal("failed reinstall returned nil")
	}
	got, _ := os.ReadFile(UnitPath)
	if string(got) != string(priorUnit) {
		t.Fatalf("reinstall failure did not restore the prior unit")
	}
}

func TestStatusReportsStates(t *testing.T) {
	r := setupService(t)
	installManagedUnit(t)
	r.script["systemctl is-enabled trestle.service"] = fakeResult{out: "enabled", code: 0}
	r.script["systemctl is-active trestle.service"] = fakeResult{out: "active", code: 0}
	r.script["systemctl show -p MainPID --value trestle.service"] = fakeResult{out: "1234", code: 0}
	h := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(200)
		w.Write([]byte(`{"status":"ok"}`))
	}))
	defer h.Close()
	listen := strings.TrimPrefix(h.URL, "http://")
	writeFileAtomic(UnitPath, []byte(Unit(DefaultDataDir, listen, "")), 0o644)
	var buf bytes.Buffer
	if e := Status(&buf); e != nil {
		t.Fatal(e)
	}
	for _, want := range []string{"unit:    trestle.service", "enabled: enabled", "active:  active", "pid:     1234", "data:    /var/lib/trestle", "health:  ok"} {
		if !strings.Contains(buf.String(), want) {
			t.Fatalf("status output missing %q", want)
		}
	}
}

func TestHealthCheckRejectsForeignJSON(t *testing.T) {
	h := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"ok":true}`))
	}))
	defer h.Close()
	if err := healthCheckReal(h.URL); err == nil {
		t.Fatal("foreign JSON response was accepted as Trestle health")
	}
}

func TestLogsConstruction(t *testing.T) {
	r := setupService(t)
	installManagedUnit(t)
	if e := Logs(false, io.Discard); e != nil {
		t.Fatal(e)
	}
	if !contains(r.log, "journalctl --unit trestle.service") {
		t.Fatal("logs did not run journalctl --unit")
	}
}

func TestUninstallPreservesDataAndIsIdempotent(t *testing.T) {
	r := setupService(t)
	installManagedUnit(t)
	r.script["systemctl disable --now trestle.service"] = fakeResult{}
	r.script["systemctl daemon-reload"] = fakeResult{}
	if e := Uninstall(); e != nil {
		t.Fatal(e)
	}
	if _, e := os.Stat(UnitPath); !os.IsNotExist(e) {
		t.Fatal("unit file not removed")
	}
	r.log = nil
	if e := Uninstall(); e == nil {
		t.Fatal("uninstall of a missing unit should report not-installed")
	}
}

func TestReinstallChangedBinaryRestarts(t *testing.T) {
	r := setupService(t)
	installManagedUnit(t)
	setState(r, "enabled", "active")
	exe := filepath.Join(t.TempDir(), "tr2")
	os.WriteFile(exe, []byte("#!/bin/sh\n# different binary\nexit 0\n"), 0o755)
	r.script["systemctl daemon-reload"] = fakeResult{}
	r.script["systemctl enable trestle.service"] = fakeResult{}
	r.script["systemctl restart trestle.service"] = fakeResult{}
	if e := Install(exe, "/var/lib/trestle", "127.0.0.1:8090", ""); e != nil {
		t.Fatal(e)
	}
	if !contains(r.log, "systemctl restart trestle.service") {
		t.Fatal("changed binary did not trigger a restart")
	}
}

func TestReinstallSameBinaryIsNoOp(t *testing.T) {
	r := setupService(t)
	installManagedUnit(t)
	setState(r, "enabled", "active")
	exe := filepath.Join(t.TempDir(), "tr2")
	os.WriteFile(exe, mustRead(t, BinaryPath), 0o755)
	if e := Install(exe, "/var/lib/trestle", "127.0.0.1:8090", ""); e != nil {
		t.Fatal(e)
	}
	for _, call := range r.log {
		if strings.HasPrefix(call, "systemctl daemon-reload") {
			t.Fatal("identical reinstall performed a daemon-reload")
		}
	}
}

func TestReinstallRestoresExactNegativeState(t *testing.T) {
	r := setupService(t)
	installManagedUnit(t)
	setState(r, "disabled", "inactive")
	exe := filepath.Join(t.TempDir(), "tr2")
	os.WriteFile(exe, []byte("#!/bin/sh\n# new\nexit 0\n"), 0o755)
	// Forward path for a disabled+inactive prior: daemon-reload, disable, stop.
	// Force the forward stop to fail (1st call); rollback's stop succeeds (2nd).
	r.script["systemctl daemon-reload"] = fakeResult{}
	r.script["systemctl disable trestle.service"] = fakeResult{}
	r.seq["systemctl stop trestle.service"] = []fakeResult{{out: "activation failed", code: 1}, {}}
	if e := Install(exe, "/var/lib/trestle", "127.0.0.1:9090", ""); e == nil {
		t.Fatal("failed reinstall returned nil")
	}
	disableCalls, stopCalls := 0, 0
	for _, call := range r.log {
		if call == "systemctl disable trestle.service" {
			disableCalls++
		}
		if call == "systemctl stop trestle.service" {
			stopCalls++
		}
	}
	if disableCalls < 2 {
		t.Fatalf("negative enabled state not re-applied during rollback (disable calls=%d)", disableCalls)
	}
	if stopCalls < 1 {
		t.Fatalf("negative active state not re-applied during rollback (stop calls=%d)", stopCalls)
	}
	b, _ := os.ReadFile(UnitPath)
	if !strings.Contains(string(b), "127.0.0.1:8090") {
		t.Fatal("prior unit not restored after failed reinstall")
	}
}

func TestMalformedManagedUnitClassified(t *testing.T) {
	setupService(t)
	writeFileAtomic(UnitPath, []byte("# Managed by trestle. Do not edit manually.\n[Unit]\n[Service]\n[Install]\n"), 0o644)
	if e := lifecycle("start"); e == nil {
		t.Fatal("malformed managed unit accepted for start")
	}
	if e := Status(io.Discard); e == nil {
		t.Fatal("malformed managed unit accepted for status")
	}
}

func TestTamperedManagedUnitRejected(t *testing.T) {
	setupService(t)
	u := Unit(DefaultDataDir, "127.0.0.1:8090", "")
	tampered := strings.Replace(u, "127.0.0.1:8090", "127.0.0.1:9090", 1)
	writeFileAtomic(UnitPath, []byte(tampered), 0o644)
	if e := lifecycle("start"); e == nil {
		t.Fatal("tampered managed unit accepted for start")
	}
	if e := Status(io.Discard); e == nil {
		t.Fatal("tampered managed unit accepted for status")
	}
}

func TestUpdateAndRollbackRefuseForeignUnit(t *testing.T) {
	setupService(t)
	writeFileAtomic(UnitPath, []byte("[Unit]\nDescription=admin\n[Service]\nExecStart=/usr/bin/thing\n[Install]\nWantedBy=multi-user.target\n"), 0o644)
	before, _ := os.ReadFile(BinaryPath)
	exe := filepath.Join(t.TempDir(), "tr2")
	os.WriteFile(exe, []byte("#!/bin/sh\n# v2\nexit 0\n"), 0o755)
	if e := Update(exe, fakeSHA(exe)); e == nil {
		t.Fatal("update mutated a foreign unit")
	}
	if e := Rollback(); e == nil {
		t.Fatal("rollback mutated a foreign unit")
	}
	after, _ := os.ReadFile(BinaryPath)
	if !bytes.Equal(before, after) {
		t.Fatal("update/rollback mutated the binary of a foreign unit")
	}
}

func TestUpdatePreservesActiveState(t *testing.T) {
	r := setupService(t)
	installManagedUnit(t)
	exe := filepath.Join(t.TempDir(), "tr2")
	os.WriteFile(exe, []byte("#!/bin/sh\n# v2\nexit 0\n"), 0o755)
	setState(r, "enabled", "active")
	prepareUpdate(r, "active", true)
	r.script["systemctl restart trestle.service"] = fakeResult{}
	if e := Update(exe, fakeSHA(exe)); e != nil {
		t.Fatal(e)
	}
	if !contains(r.log, "systemctl restart trestle.service") {
		t.Fatal("active update did not restart")
	}
	r.log = nil
	setState(r, "enabled", "inactive")
	prepareUpdate(r, "inactive", true)
	if e := Update(exe, fakeSHA(exe)); e != nil {
		t.Fatal(e)
	}
	for _, call := range r.log {
		if strings.Contains(call, "restart trestle.service") || strings.Contains(call, "start trestle.service") {
			t.Fatalf("stopped update started the service: %s", call)
		}
	}
}

func TestUpdateFailedActivationRestoresOldBinary(t *testing.T) {
	r := setupService(t)
	installManagedUnit(t)
	oldBin := mustRead(t, BinaryPath)
	setState(r, "enabled", "active")
	prepareUpdate(r, "active", true)
	exe := filepath.Join(t.TempDir(), "tr2")
	os.WriteFile(exe, []byte("#!/bin/sh\n# v2\nexit 0\n"), 0o755)
	r.script["systemctl restart trestle.service"] = fakeResult{out: "activation failed", code: 1}
	r.script["systemctl stop trestle.service"] = fakeResult{}
	if e := Update(exe, fakeSHA(exe)); e == nil {
		t.Fatal("failed activation update returned nil")
	}
	now, _ := os.ReadFile(BinaryPath)
	if !bytes.Equal(now, oldBin) {
		t.Fatal("failed activation did not restore the old binary")
	}
}

func TestRollbackRestoresStoppedStateWithoutStarting(t *testing.T) {
	r := setupService(t)
	installManagedUnit(t)
	oldBin := mustRead(t, BinaryPath)
	setState(r, "enabled", "inactive")
	prepareUpdate(r, "inactive", true)
	exe := filepath.Join(t.TempDir(), "tr2")
	os.WriteFile(exe, []byte("#!/bin/sh\n# v2\nexit 0\n"), 0o755)
	if e := Update(exe, fakeSHA(exe)); e != nil {
		t.Fatal(e)
	}
	r.log = nil
	if e := Rollback(); e != nil {
		t.Fatal(e)
	}
	now, _ := os.ReadFile(BinaryPath)
	if !bytes.Equal(now, oldBin) {
		t.Fatal("rollback did not restore the old binary")
	}
	for _, call := range r.log {
		if strings.Contains(call, "restart trestle.service") || strings.Contains(call, "start trestle.service") {
			t.Fatalf("rollback of a stopped service started it: %s", call)
		}
	}
}

func TestRollbackRestoresRunningState(t *testing.T) {
	r := setupService(t)
	installManagedUnit(t)
	setState(r, "enabled", "active")
	prepareUpdate(r, "active", true)
	exe := filepath.Join(t.TempDir(), "tr2")
	os.WriteFile(exe, []byte("#!/bin/sh\n# v2\nexit 0\n"), 0o755)
	r.script["systemctl restart trestle.service"] = fakeResult{}
	if e := Update(exe, fakeSHA(exe)); e != nil {
		t.Fatal(e)
	}
	r.log = nil
	if e := Rollback(); e != nil {
		t.Fatal(e)
	}
	if !contains(r.log, "systemctl restart trestle.service") {
		t.Fatal("rollback of an active service did not restart it")
	}
	if _, e := os.Stat(BinaryPath + ".rollback"); !os.IsNotExist(e) {
		t.Fatal("rollback metadata not consumed after successful rollback")
	}
	for _, call := range r.log {
		if strings.HasPrefix(call, "systemctl enable ") || strings.HasPrefix(call, "systemctl disable ") {
			t.Fatalf("update/rollback changed enablement: %s", call)
		}
	}
}

func TestUpdateVerifiesHealthNotJustRestartExit(t *testing.T) {
	r := setupService(t)
	installManagedUnit(t)
	oldBin := mustRead(t, BinaryPath)
	exe := filepath.Join(t.TempDir(), "tr2")
	os.WriteFile(exe, []byte("#!/bin/sh\n# v2\nexit 0\n"), 0o755)
	setState(r, "enabled", "active")
	prepareUpdate(r, "active", false)
	healthWindow = 1 * time.Second
	r.script["systemctl restart trestle.service"] = fakeResult{}
	r.script["systemctl stop trestle.service"] = fakeResult{}
	if e := Update(exe, fakeSHA(exe)); e == nil {
		t.Fatal("update succeeded although the new binary never became healthy")
	}
	now, _ := os.ReadFile(BinaryPath)
	if !bytes.Equal(now, oldBin) {
		t.Fatal("unhealthy update did not restore the old binary")
	}
}

func TestUpdateActiveStateQueryFailureAborts(t *testing.T) {
	r := setupService(t)
	installManagedUnit(t)
	oldBin := mustRead(t, BinaryPath)
	exe := filepath.Join(t.TempDir(), "tr2")
	os.WriteFile(exe, []byte("#!/bin/sh\n# v2\nexit 0\n"), 0o755)
	r.script["systemctl is-active trestle.service"] = fakeResult{out: "", code: 1, err: fmt.Errorf("systemctl is-active failed")}
	if e := Update(exe, fakeSHA(exe)); e == nil {
		t.Fatal("update proceeded when the active state could not be determined")
	}
	now, _ := os.ReadFile(BinaryPath)
	if !bytes.Equal(now, oldBin) {
		t.Fatal("state-query failure still mutated the binary")
	}
}

func TestUpdatePriorStateMarkerWriteFailureAborts(t *testing.T) {
	r := setupService(t)
	installManagedUnit(t)
	oldBin := mustRead(t, BinaryPath)
	exe := filepath.Join(t.TempDir(), "tr2")
	os.WriteFile(exe, []byte("#!/bin/sh\n# v2\nexit 0\n"), 0o755)
	setState(r, "enabled", "inactive")
	r.script["systemctl is-active trestle.service"] = fakeResult{out: "inactive", code: 0}
	os.MkdirAll(BinaryPath+".prior-active", 0o700)
	if e := Update(exe, fakeSHA(exe)); e == nil {
		t.Fatal("update proceeded when the rollback marker could not be written")
	}
	now, _ := os.ReadFile(BinaryPath)
	if !bytes.Equal(now, oldBin) {
		t.Fatal("marker-write failure still mutated the binary")
	}
}

func TestRollbackFailClosedWithoutMarker(t *testing.T) {
	setupService(t)
	installManagedUnit(t)
	os.WriteFile(BinaryPath+".rollback", []byte("#!/bin/sh\nexit 0\n"), 0o755)
	os.Remove(BinaryPath + ".prior-active")
	if e := Rollback(); e == nil {
		t.Fatal("rollback defaulted to active without a prior-state marker")
	}
}

func TestEndToEndActiveUpdateThenRollback(t *testing.T) {
	r := setupService(t)
	installManagedUnit(t)
	oldBin := mustRead(t, BinaryPath)
	setState(r, "enabled", "active")
	prepareUpdate(r, "active", true)
	exe := filepath.Join(t.TempDir(), "tr2")
	os.WriteFile(exe, []byte("#!/bin/sh\n# v2\nexit 0\n"), 0o755)
	r.script["systemctl restart trestle.service"] = fakeResult{}
	if e := Update(exe, fakeSHA(exe)); e != nil {
		t.Fatal(e)
	}
	if _, e := os.Stat(BinaryPath + ".rollback"); e != nil {
		t.Fatal("rollback binary missing after successful update")
	}
	if _, e := os.Stat(BinaryPath + ".prior-active"); e != nil {
		t.Fatal("prior-active marker missing after successful update")
	}
	now, _ := os.ReadFile(BinaryPath)
	if bytes.Equal(now, oldBin) {
		t.Fatal("update did not replace the binary")
	}
	r.log = nil
	r.script["systemctl restart trestle.service"] = fakeResult{}
	if e := Rollback(); e != nil {
		t.Fatal(e)
	}
	back, _ := os.ReadFile(BinaryPath)
	if !bytes.Equal(back, oldBin) {
		t.Fatal("rollback did not restore the old binary")
	}
	if !contains(r.log, "systemctl restart trestle.service") {
		t.Fatal("rollback of an active service did not restart it")
	}
}

func TestEndToEndStoppedUpdateThenRollback(t *testing.T) {
	r := setupService(t)
	installManagedUnit(t)
	oldBin := mustRead(t, BinaryPath)
	setState(r, "enabled", "inactive")
	prepareUpdate(r, "inactive", true)
	exe := filepath.Join(t.TempDir(), "tr2")
	os.WriteFile(exe, []byte("#!/bin/sh\n# v2\nexit 0\n"), 0o755)
	if e := Update(exe, fakeSHA(exe)); e != nil {
		t.Fatal(e)
	}
	if _, e := os.Stat(BinaryPath + ".prior-active"); e != nil {
		t.Fatal("prior-active marker missing after stopped update")
	}
	r.log = nil
	if e := Rollback(); e != nil {
		t.Fatal(e)
	}
	back, _ := os.ReadFile(BinaryPath)
	if !bytes.Equal(back, oldBin) {
		t.Fatal("rollback did not restore the old binary")
	}
	for _, call := range r.log {
		if strings.Contains(call, "restart trestle.service") || strings.Contains(call, "start trestle.service") {
			t.Fatalf("rollback of a stopped service started it: %s", call)
		}
	}
}

func TestFailedUpdateRecoverySurfacesFailures(t *testing.T) {
	{
		r := setupService(t)
		installManagedUnit(t)
		setState(r, "enabled", "active")
		prepareUpdate(r, "active", false)
		healthWindow = 1 * time.Second
		exe := filepath.Join(t.TempDir(), "tr2")
		os.WriteFile(exe, []byte("#!/bin/sh\n# v2\nexit 0\n"), 0o755)
		r.script["systemctl restart trestle.service"] = fakeResult{}
		r.script["systemctl stop trestle.service"] = fakeResult{}
		r.seq["systemctl restart trestle.service"] = []fakeResult{{}, {out: "restore failed", code: 1}}
		uerr := Update(exe, fakeSHA(exe))
		if uerr == nil {
			t.Fatal("update succeeded despite a failed recovery restart")
		}
		if !strings.Contains(uerr.Error(), "recovery") {
			t.Fatalf("recovery restart failure not surfaced: %v", uerr)
		}
	}
}

func TestInitialRestartFailureSurfacesRecoveryFailure(t *testing.T) {
	r := setupService(t)
	installManagedUnit(t)
	setState(r, "enabled", "active")
	prepareUpdate(r, "active", true)
	exe := filepath.Join(t.TempDir(), "tr2")
	os.WriteFile(exe, []byte("#!/bin/sh\n# v2\nexit 0\n"), 0o755)
	r.seq["systemctl restart trestle.service"] = []fakeResult{
		{out: "new binary failed to start", code: 1},
		{out: "recovery restart failed", code: 1},
	}
	r.script["systemctl stop trestle.service"] = fakeResult{}
	uerr := Update(exe, fakeSHA(exe))
	if uerr == nil {
		t.Fatal("update succeeded despite initial restart failure")
	}
	if !strings.Contains(uerr.Error(), "restart after update") {
		t.Fatalf("original restart failure missing: %v", uerr)
	}
	if !strings.Contains(uerr.Error(), "recovery") {
		t.Fatalf("recovery failure not surfaced: %v", uerr)
	}
}

func TestInitialRestartFailureRecoverySucceedsCleansMetadata(t *testing.T) {
	r := setupService(t)
	installManagedUnit(t)
	oldBin := mustRead(t, BinaryPath)
	setState(r, "enabled", "active")
	prepareUpdate(r, "active", true)
	healthWindow = 1 * time.Second
	exe := filepath.Join(t.TempDir(), "tr2")
	os.WriteFile(exe, []byte("#!/bin/sh\n# v2\nexit 0\n"), 0o755)
	r.seq["systemctl restart trestle.service"] = []fakeResult{
		{out: "new binary failed to start", code: 1},
		{},
	}
	r.script["systemctl stop trestle.service"] = fakeResult{}
	uerr := Update(exe, fakeSHA(exe))
	if uerr == nil {
		t.Fatal("update should report the initial restart failure")
	}
	back, _ := os.ReadFile(BinaryPath)
	if !bytes.Equal(back, oldBin) {
		t.Fatal("recovery did not restore the old binary")
	}
	if _, e := os.Stat(BinaryPath + ".rollback"); !os.IsNotExist(e) {
		t.Fatal("stale rollback binary left after verified recovery")
	}
	if _, e := os.Stat(BinaryPath + ".prior-active"); !os.IsNotExist(e) {
		t.Fatal("stale prior-active marker left after verified recovery")
	}
}

// TestRecoveryFailsClosedWhenMarkerCorruptedAtRecoveryTime is the corrected
// real-sequence regression: the marker is written by Update, the new binary is
// activated, the health check fails, and only THEN is the marker corrupted (via
// a narrow injectable read seam) so recovery must fail closed rather than guess
// to active.
func TestRecoveryFailsClosedWhenMarkerCorruptedAtRecoveryTime(t *testing.T) {
	r := setupService(t)
	installManagedUnit(t)
	setState(r, "enabled", "active")
	prepareUpdate(r, "active", false)
	healthWindow = 1 * time.Second
	exe := filepath.Join(t.TempDir(), "tr2")
	os.WriteFile(exe, []byte("#!/bin/sh\n# v2\nexit 0\n"), 0o755)
	r.script["systemctl restart trestle.service"] = fakeResult{}
	r.script["systemctl stop trestle.service"] = fakeResult{}
	orig := priorStateFileRead
	priorStateFileRead = func(path string) ([]byte, error) {
		if strings.HasSuffix(path, ".prior-active") {
			return []byte("garbage"), nil
		}
		return os.ReadFile(path)
	}
	defer func() { priorStateFileRead = orig }()
	uerr := Update(exe, fakeSHA(exe))
	if uerr == nil {
		t.Fatal("update succeeded despite corrupted recovery marker")
	}
	if !strings.Contains(uerr.Error(), "recovery") {
		t.Fatalf("recovery fail-closed degradation not surfaced: %v", uerr)
	}
}

func TestRecoveryFailsClosedWhenMarkerMissingAtRecoveryTime(t *testing.T) {
	r := setupService(t)
	installManagedUnit(t)
	setState(r, "enabled", "active")
	prepareUpdate(r, "active", false)
	healthWindow = 1 * time.Second
	exe := filepath.Join(t.TempDir(), "tr2")
	os.WriteFile(exe, []byte("#!/bin/sh\n# v2\nexit 0\n"), 0o755)
	r.script["systemctl restart trestle.service"] = fakeResult{}
	r.script["systemctl stop trestle.service"] = fakeResult{}
	orig := priorStateFileRead
	priorStateFileRead = func(path string) ([]byte, error) {
		if strings.HasSuffix(path, ".prior-active") {
			return nil, fmt.Errorf("marker vanished")
		}
		return os.ReadFile(path)
	}
	defer func() { priorStateFileRead = orig }()
	uerr := Update(exe, fakeSHA(exe))
	if uerr == nil {
		t.Fatal("update succeeded despite missing recovery marker")
	}
	if !strings.Contains(uerr.Error(), "recovery") {
		t.Fatalf("recovery fail-closed degradation not surfaced: %v", uerr)
	}
}

func TestRollbackEnforcesManagedUnitBeforeBinary(t *testing.T) {
	setupService(t)
	writeFileAtomic(UnitPath, []byte("[Unit]\nDescription=admin\n[Service]\nExecStart=/usr/bin/thing\n[Install]\nWantedBy=multi-user.target\n"), 0o644)
	before, _ := os.ReadFile(BinaryPath)
	if e := Rollback(); e == nil {
		t.Fatal("rollback of a foreign unit succeeded")
	}
	if e := Update(filepath.Join(t.TempDir(), "x"), "x"); e == nil {
		t.Fatal("update of a foreign unit succeeded")
	}
	after, _ := os.ReadFile(BinaryPath)
	if !bytes.Equal(before, after) {
		t.Fatal("update/rollback mutated binary before the managed-unit check")
	}
}

func TestUnitExplicitRendering(t *testing.T) {
	setupService(t)
	// A default install resolves to 127.0.0.1:7333 and must record it through
	// --host/--port so it survives login, restart and reboot.
	def := UnitExplicit(DefaultDataDir, "127.0.0.1", "7333", "")
	for _, want := range []string{`"--host" "127.0.0.1"`, `"--port" "7333"`, `# trestle-listen: 127.0.0.1:7333`, `# trestle-listen-mode: explicit`, "NoNewPrivileges=true", "ProtectSystem=strict", "ReadWritePaths=\"/var/lib/trestle\""} {
		if !strings.Contains(def, want) {
			t.Fatalf("default explicit unit missing %q\n%s", want, def)
		}
	}
	if strings.Contains(def, "--listen") {
		t.Fatal("default explicit unit must use --host/--port, not legacy --listen")
	}
	if _, err := readManagedUnitBytes(t, []byte(def)); err != nil {
		t.Fatalf("default explicit unit should validate: %v", err)
	}
	// An explicit 0.0.0.0:7403 install records that exact listener.
	wide := UnitExplicit(DefaultDataDir, "0.0.0.0", "7403", "")
	for _, want := range []string{`"--host" "0.0.0.0"`, `"--port" "7403"`, `# trestle-listen: 0.0.0.0:7403`} {
		if !strings.Contains(wide, want) {
			t.Fatalf("wide explicit unit missing %q\n%s", want, wide)
		}
	}
	if _, err := readManagedUnitBytes(t, []byte(wide)); err != nil {
		t.Fatalf("wide explicit unit should validate: %v", err)
	}
}

func readManagedUnitBytes(t *testing.T, data []byte) (unitMeta, error) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "trestle.service")
	if err := os.WriteFile(path, data, 0644); err != nil {
		return unitMeta{}, err
	}
	return readManagedUnitFile(path)
}

func TestUnitLegacyBootstrapRendering(t *testing.T) {
	setupService(t)
	u := Unit(DefaultDataDir, "127.0.0.1:8080", "")
	for _, want := range []string{`"--listen" "127.0.0.1:8080"`, `# trestle-listen: 127.0.0.1:8080`, `# trestle-listen-mode: bootstrap`} {
		if !strings.Contains(u, want) {
			t.Fatalf("legacy unit missing %q\n%s", want, u)
		}
	}
	if strings.Contains(u, "--host") || strings.Contains(u, "--port") {
		t.Fatal("legacy unit must keep the single-address --listen form")
	}
	if _, err := readManagedUnitBytes(t, []byte(u)); err != nil {
		t.Fatalf("legacy unit should validate: %v", err)
	}
}

func TestListenModeMarkerValidation(t *testing.T) {
	setupService(t)
	explicit := UnitExplicit(DefaultDataDir, "127.0.0.1", "7333", "")
	meta, err := readManagedUnitBytes(t, []byte(explicit))
	if err != nil {
		t.Fatal(err)
	}
	if meta.listenMode != ListenModeExplicit || meta.listen != "127.0.0.1:7333" {
		t.Fatalf("explicit meta = %+v", meta)
	}
	legacy := Unit(DefaultDataDir, "127.0.0.1:8080", "")
	meta, err = readManagedUnitBytes(t, []byte(legacy))
	if err != nil {
		t.Fatal(err)
	}
	if meta.listenMode != ListenModeBootstrap {
		t.Fatalf("legacy meta mode = %q want bootstrap", meta.listenMode)
	}
	// A hostile mode value is rejected.
	bad := strings.Replace(legacy, "# trestle-listen-mode: bootstrap", "# trestle-listen-mode: attacker", 1)
	if _, err := readManagedUnitBytes(t, []byte(bad)); err == nil {
		t.Fatal("invalid listen-mode accepted")
	}
	// Old units predating the marker default to bootstrap.
	body := unitBody(unitSpec{dataDir: DefaultDataDir, listen: "127.0.0.1:8080", listenMode: ListenModeBootstrap})
	oldContent := "# trestle-listen: 127.0.0.1:8080\n# trestle-data: " + DefaultDataDir + "\n# trestle-health: " + trestleHealthPath + "\n" + body
	sum := sha256.Sum256([]byte(oldContent))
	old := trestleUnitMarker + "\n" + trestleManagedPrefix + "v1 sha256=" + hex.EncodeToString(sum[:]) + "\n" + oldContent
	meta, err = readManagedUnitBytes(t, []byte(old))
	if err != nil {
		t.Fatalf("legacy unit without marker should default to bootstrap: %v", err)
	}
	if meta.listenMode != ListenModeBootstrap {
		t.Fatalf("no-marker unit mode = %q want bootstrap", meta.listenMode)
	}
}

func TestUnitExplicitCanonicalValues(t *testing.T) {
	// Whitespace-surrounded host/port must never leak into the unit metadata or
	// ExecStart; only the canonical trimmed values are recorded.
	u := buildUnit(unitSpec{dataDir: "/config", host: "  127.0.0.1  ", port: "  7403  ", listenMode: ListenModeExplicit})
	for _, want := range []string{`"--host" "127.0.0.1"`, `"--port" "7403"`, `# trestle-listen: 127.0.0.1:7403`} {
		if !strings.Contains(u, want) {
			t.Fatalf("canonical explicit unit missing %q\n%s", want, u)
		}
	}
	for _, bad := range []string{`"  127.0.0.1  "`, `"  7403  "`, `# trestle-listen:   127.0.0.1:7403`} {
		if strings.Contains(u, bad) {
			t.Fatalf("unit leaked untrimmed value %q\n%s", bad, u)
		}
	}
}

func TestInstallExplicitFreshAndChanged(t *testing.T) {
	t.Run("fresh explicit install publishes and starts", func(t *testing.T) {
		r := setupService(t)
		exe := filepath.Join(t.TempDir(), "tr")
		os.WriteFile(exe, []byte("#!/bin/sh\nexit 0\n"), 0o755)
		r.script["systemctl daemon-reload"] = fakeResult{}
		r.script["systemctl enable trestle.service"] = fakeResult{}
		r.script["systemctl restart trestle.service"] = fakeResult{}
		if e := InstallExplicit(exe, "/var/lib/trestle", "127.0.0.1", "7403", ""); e != nil {
			t.Fatal(e)
		}
		unit := mustRead(t, UnitPath)
		for _, want := range []string{`"--host" "127.0.0.1"`, `"--port" "7403"`, `# trestle-listen-mode: explicit`} {
			if !strings.Contains(string(unit), want) {
				t.Fatalf("installed explicit unit missing %q\n%s", want, unit)
			}
		}
		for _, want := range []string{"systemctl daemon-reload", "systemctl enable trestle.service", "systemctl restart trestle.service"} {
			if !contains(r.log, want) {
				t.Fatalf("fresh explicit install did not call %q\nlog: %v", want, r.log)
			}
		}
	})

	t.Run("changed explicit listener restarts the service", func(t *testing.T) {
		r := setupService(t)
		exe := filepath.Join(t.TempDir(), "tr")
		os.WriteFile(exe, []byte("#!/bin/sh\nexit 0\n"), 0o755)
		r.script["systemctl daemon-reload"] = fakeResult{}
		r.script["systemctl enable trestle.service"] = fakeResult{}
		r.script["systemctl restart trestle.service"] = fakeResult{}
		if e := InstallExplicit(exe, "/var/lib/trestle", "127.0.0.1", "7403", ""); e != nil {
			t.Fatal(e)
		}
		setState(r, "enabled", "active")
		r.script["systemctl daemon-reload"] = fakeResult{}
		r.script["systemctl disable trestle.service"] = fakeResult{}
		r.script["systemctl enable trestle.service"] = fakeResult{}
		r.script["systemctl restart trestle.service"] = fakeResult{}
		r.log = nil
		if e := InstallExplicit(exe, "/var/lib/trestle", "127.0.0.1", "7404", ""); e != nil {
			t.Fatal(e)
		}
		unit := mustRead(t, UnitPath)
		if !strings.Contains(string(unit), `"--port" "7404"`) {
			t.Fatalf("reinstall did not record 7404:\n%s", unit)
		}
		if !strings.Contains(string(unit), `# trestle-listen-mode: explicit`) {
			t.Fatalf("reinstall unit must remain explicit mode:\n%s", unit)
		}
		if !contains(r.log, "systemctl restart trestle.service") {
			t.Fatalf("changed listener must restart the service\nlog: %v", r.log)
		}
	})

	t.Run("identical explicit reinstall is a genuine no-op", func(t *testing.T) {
		r := setupService(t)
		exe := filepath.Join(t.TempDir(), "tr")
		os.WriteFile(exe, mustRead(t, BinaryPath), 0o755)
		if e := InstallExplicit(exe, "/var/lib/trestle", "127.0.0.1", "7333", ""); e != nil {
			t.Fatal(e)
		}
		setState(r, "enabled", "active")
		r.log = nil
		if e := InstallExplicit(exe, "/var/lib/trestle", "127.0.0.1", "7333", ""); e != nil {
			t.Fatal(e)
		}
		if hasMutatingSystemctl(r.log) {
			t.Fatalf("identical explicit reinstall mutated systemd\nlog: %v", r.log)
		}
	})
}

func TestInstallExplicitFailureRestoresPriorUnit(t *testing.T) {
	r := setupService(t)
	exe := filepath.Join(t.TempDir(), "tr")
	os.WriteFile(exe, []byte("#!/bin/sh\nexit 0\n"), 0o755)
	r.script["systemctl daemon-reload"] = fakeResult{}
	r.script["systemctl enable trestle.service"] = fakeResult{}
	r.script["systemctl restart trestle.service"] = fakeResult{}
	if e := InstallExplicit(exe, "/var/lib/trestle", "127.0.0.1", "7403", ""); e != nil {
		t.Fatal(e)
	}
	priorUnit := mustRead(t, UnitPath)
	setState(r, "enabled", "active")
	r.script["systemctl daemon-reload"] = fakeResult{}
	r.script["systemctl disable trestle.service"] = fakeResult{}
	r.script["systemctl enable trestle.service"] = fakeResult{out: "failed to enable", code: 3}
	r.script["systemctl restart trestle.service"] = fakeResult{}
	r.script["systemctl stop trestle.service"] = fakeResult{}
	if e := InstallExplicit(exe, "/var/lib/trestle", "127.0.0.1", "7404", ""); e == nil {
		t.Fatal("failed explicit reinstall returned nil")
	}
	got := mustRead(t, UnitPath)
	if string(got) != string(priorUnit) {
		t.Fatal("failed explicit reinstall did not restore the prior unit")
	}
}

func TestStatusExplicitUsesRecordedListener(t *testing.T) {
	// A new explicit host/port unit records an authoritative listener; status
	// must report and health-check it as the runtime listener.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(200)
		w.Write([]byte(`{"status":"ok"}`))
	}))
	defer srv.Close()
	listen := strings.TrimPrefix(srv.URL, "http://")
	host, port := splitListen(t, listen)
	r := setupService(t)
	writeFileAtomic(UnitPath, []byte(UnitExplicit(DefaultDataDir, host, port, "")), 0o644)
	setState(r, "enabled", "active")
	r.script["systemctl show -p MainPID --value trestle.service"] = fakeResult{out: "99", code: 0}
	var buf bytes.Buffer
	if e := Status(&buf); e != nil {
		t.Fatal(e)
	}
	if !strings.Contains(buf.String(), "listen:  "+listen) {
		t.Fatalf("explicit unit status must use the recorded listener:\n%s", buf.String())
	}
	if !strings.Contains(buf.String(), "health:  ok") {
		t.Fatalf("explicit unit health check failed:\n%s", buf.String())
	}
}

func TestStatusLegacyBootstrapUsesRecordedListener(t *testing.T) {
	// A legacy --listen unit's recorded listener IS the runtime listener
	// (ExecStart flag beats the durable environment), so status reports it.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(200)
		w.Write([]byte(`{"status":"ok"}`))
	}))
	defer srv.Close()
	listen := strings.TrimPrefix(srv.URL, "http://")
	r := setupService(t)
	writeFileAtomic(UnitPath, []byte(Unit(DefaultDataDir, listen, "")), 0o644)
	setState(r, "enabled", "active")
	r.script["systemctl show -p MainPID --value trestle.service"] = fakeResult{out: "99", code: 0}
	var buf bytes.Buffer
	if e := Status(&buf); e != nil {
		t.Fatal(e)
	}
	if !strings.Contains(buf.String(), "listen:  "+listen) {
		t.Fatalf("legacy unit status must use its recorded listener:\n%s", buf.String())
	}
	if !strings.Contains(buf.String(), "health:  ok") {
		t.Fatalf("legacy unit health check failed:\n%s", buf.String())
	}
}

func TestTrestleEffectiveListen(t *testing.T) {
	if got, err := trestleEffectiveListen("", "127.0.0.1:8080"); err != nil || got != "127.0.0.1:8080" {
		t.Fatalf("fallback = %q, %v", got, err)
	}
	if got, err := trestleEffectiveListen("/etc/trestle/trestle.env", "127.0.0.1:8080"); err != nil || got != "127.0.0.1:8080" {
		t.Fatalf("durable resolution = %q, %v", got, err)
	}
}

func splitListen(t *testing.T, addr string) (string, string) {
	t.Helper()
	h, p, err := net.SplitHostPort(addr)
	if err != nil {
		t.Fatal(err)
	}
	return h, p
}
