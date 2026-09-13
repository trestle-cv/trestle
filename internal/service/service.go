// Package service implements the machine-service lifecycle for Trestle:
// a systemd system unit backed by a dedicated unprivileged account, a canonical
// /var/lib/trestle data directory and root-protected /etc/trestle
// configuration. The CLI surface, exit-code model and transaction semantics
// mirror the canonical Web Fleet reference so the whole ecosystem behaves
// predictably.
package service

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"time"
)

// UnitPath is the installed systemd system unit.
var UnitPath = "/etc/systemd/system/trestle.service"

// BinaryPath is the canonical installed binary location.
var BinaryPath = "/usr/local/bin/trestle"

// DefaultDataDir is the canonical data directory the installed service owns.
const DefaultDataDir = "/var/lib/trestle"

// DefaultEnvFile is the root-protected environment file holding protected
// TRESTLE_* configuration (secrets). It is read by systemd via
// EnvironmentFile= before the process drops to User=trestle.
const DefaultEnvFile = "/etc/trestle/trestle.env"

// DefaultListen is the canonical loopback listen address embedded in the unit.
const DefaultListen = "127.0.0.1:7333"

// Listen modes recorded in the managed-unit metadata. New units installed with
// an explicit --host/--port (or the CLI/env defaults) are "explicit": their
// recorded listener is the runtime listener. Legacy units installed with the
// single-address --listen form are "bootstrap": the recorded listener is a
// bootstrap value resolved through the durable configuration at runtime.
const (
	ListenModeExplicit  = "explicit"
	ListenModeBootstrap = "bootstrap"
)

// ServiceAccount is the dedicated unprivileged account the unit runs as.
const ServiceUser = "trestle"
const ServiceGroup = "trestle"

// trestleUnitMarker marks unit files written by `trestle service`.
const trestleUnitMarker = "# Managed by trestle. Do not edit manually."

// trestleManagedPrefix introduces the versioned integrity header followed by a
// SHA-256 of everything below it, so any hand edit is detected.
const trestleManagedPrefix = "# trestle-managed: "

// trestleHealthPath is the public, read-only liveness endpoint.
const trestleHealthPath = "/system/health"

var (
	errNotManaged = errors.New("not a managed unit")
	errMalformed  = errors.New("malformed managed unit header")
	errModified   = errors.New("managed unit body no longer matches its recorded checksum")
)

// Runner abstracts systemctl/journalctl so the CLI is testable without a real
// systemd manager. Run returns captured combined output, the exit code (0 on
// success, -1 when the command could not launch) and a launch error only.
type Runner interface {
	Run(name string, args ...string) (string, int, error)
	Stream(name string, args ...string) (int, error)
}

type execRunner struct{}

func (execRunner) Run(name string, args ...string) (string, int, error) {
	out, err := exec.Command(name, args...).CombinedOutput()
	if err == nil {
		return string(out), 0, nil
	}
	var ee *exec.ExitError
	if errors.As(err, &ee) {
		return string(out), ee.ExitCode(), nil
	}
	return string(out), -1, err
}

func (execRunner) Stream(name string, args ...string) (int, error) {
	cmd := exec.Command(name, args...)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	err := cmd.Run()
	if err == nil {
		return 0, nil
	}
	var ee *exec.ExitError
	if errors.As(err, &ee) {
		return ee.ExitCode(), nil
	}
	return -1, err
}

var defaultRunner Runner = execRunner{}

// setRunner replaces the systemctl runner (test seam; nil restores default).
func setRunner(r Runner) { defaultRunner = r }

func systemctl(args ...string) (string, int, error) { return defaultRunner.Run("systemctl", args...) }

func bounded(s string) string {
	const max = 2000
	if len(s) > max {
		return s[:max] + "..."
	}
	return s
}

func systemctlSuccess(args ...string) error {
	out, code, err := systemctl(args...)
	if err != nil {
		return fmt.Errorf("cannot run systemctl %s: %w", strings.Join(args, " "), err)
	}
	if code != 0 {
		return fmt.Errorf("systemctl %s exited %d: %s", strings.Join(args, " "), code, bounded(strings.TrimSpace(out)))
	}
	return nil
}

func unitStateWord(verb string) (string, error) {
	out, _, err := systemctl(verb, "trestle.service")
	if err != nil {
		return "", fmt.Errorf("cannot run systemctl %s: %w", verb, err)
	}
	return strings.TrimSpace(out), nil
}

func systemdQuote(s string) string {
	var b strings.Builder
	b.WriteByte('"')
	for i := 0; i < len(s); i++ {
		switch c := s[i]; c {
		case '%':
			b.WriteString("%%")
		case '"', '\\', '$', '`':
			b.WriteByte('\\')
			b.WriteByte(c)
		default:
			b.WriteByte(c)
		}
	}
	b.WriteByte('"')
	return b.String()
}

func validateNoControl(v, what string) error {
	for i := 0; i < len(v); i++ {
		if v[i] < 0x20 || v[i] == 0x7f {
			return fmt.Errorf("%s %q contains a control character", what, v)
		}
	}
	return nil
}

func fileSHA256(path string) (string, error) {
	b, e := os.ReadFile(path)
	if e != nil {
		return "", e
	}
	h := sha256.Sum256(b)
	return hex.EncodeToString(h[:]), nil
}

// validateManagedUnit performs the structural ownership/integrity check: the
// unit must carry the trestle managed header AND the required directives, so a
// stale or malformed managed unit is classified rather than treated healthy.
func validateManagedUnit(body []byte) error {
	if _, err := readManagedUnit(string(body)); err != nil {
		return err
	}
	t := string(body)
	for _, want := range []string{"[Unit]", "[Service]", "[Install]", "Description=Trestle records service", "ExecStart=" + BinaryPath, "User=" + ServiceUser, "WantedBy=multi-user.target"} {
		if !strings.Contains(t, want) {
			return fmt.Errorf("malformed managed unit: missing %q", want)
		}
	}
	return nil
}

func requireManaged(verb string) error {
	b, e := os.ReadFile(UnitPath)
	if errors.Is(e, os.ErrNotExist) {
		return fmt.Errorf("refusing to %s trestle.service: unit is not installed (run `trestle service install`)", verb)
	}
	if e != nil {
		return fmt.Errorf("refusing to %s trestle.service: %w", verb, e)
	}
	if ve := validateManagedUnit(b); ve != nil {
		return fmt.Errorf("refusing to %s trestle.service: %v", verb, ve)
	}
	return nil
}

func requireLinux() error {
	if runtime.GOOS != "linux" {
		return errors.New("service management is supported on Linux only")
	}
	return nil
}

var isRoot = func() bool { return os.Geteuid() == 0 }
var ensureAccount = func() error { return ensureServiceAccount() }

func requireRoot(verb string) error {
	if !isRoot() {
		return fmt.Errorf("%s requires root (sudo trestle service %s)", verb, verb)
	}
	return nil
}

func copyFile(src, dst string, mode os.FileMode) error {
	in, e := os.Open(src)
	if e != nil {
		return e
	}
	defer in.Close()
	tmp := dst + ".new"
	out, e := os.OpenFile(tmp, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, mode)
	if e != nil {
		return e
	}
	if _, e = io.Copy(out, in); e != nil {
		out.Close()
		return e
	}
	if e = out.Sync(); e != nil {
		out.Close()
		return e
	}
	if e = out.Close(); e != nil {
		return e
	}
	return os.Rename(tmp, dst)
}

// unitMeta carries the recorded managed-unit configuration.
type unitMeta struct {
	listen     string
	listenMode string
	data       string
	envfile    string
	health     string
}

// unitSpec carries the values recorded in a generated unit. The legacy
// single-address --listen form is preserved for compatibility; otherwise the
// canonical --host/--port pair is written to ExecStart.
type unitSpec struct {
	dataDir    string
	envfile    string
	listen     string // legacy single-address form (bootstrap)
	host       string
	port       string
	listenMode string
}

// listener returns the listen address recorded in the unit metadata: the legacy
// listen address when set, otherwise the host/port pair joined safely (so IPv6
// hosts are bracketed). Values are canonicalized before being written so
// surrounding whitespace can never leak into the unit.
func (s unitSpec) listener() string {
	if s.listen != "" {
		return s.listen
	}
	return net.JoinHostPort(strings.TrimSpace(s.host), strings.TrimSpace(s.port))
}

// readManagedUnitFile reads a unit file path and parses its managed content.
func readManagedUnitFile(path string) (unitMeta, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return unitMeta{}, err
	}
	return readManagedUnit(string(data))
}

// InstalledDataDir returns the data directory recorded by the authenticated
// managed service unit. The boolean is false when Trestle is not installed.
// A present but foreign, malformed, or modified unit is an error so callers
// never silently operate on a fallback directory.
func InstalledDataDir() (string, bool, error) {
	meta, err := readManagedUnitFile(UnitPath)
	if errors.Is(err, os.ErrNotExist) {
		return "", false, nil
	}
	if err != nil {
		return "", false, fmt.Errorf("cannot use installed service configuration: %w", err)
	}
	if err := validateReadWritePath(meta.data); err != nil {
		return "", false, fmt.Errorf("installed service data directory: %w", err)
	}
	return meta.data, true, nil
}

func readManagedUnit(content string) (unitMeta, error) {
	lines := strings.Split(content, "\n")
	if len(lines) < 3 || lines[0] != trestleUnitMarker {
		return unitMeta{}, errNotManaged
	}
	count := 0
	for _, ln := range lines {
		if strings.HasPrefix(ln, trestleManagedPrefix) {
			count++
		}
	}
	if count != 1 || !strings.HasPrefix(lines[1], trestleManagedPrefix) {
		return unitMeta{}, errMalformed
	}
	sm := regexp.MustCompile(`^# trestle-managed: v1 sha256=([0-9a-f]{64})$`).FindStringSubmatch(lines[1])
	if sm == nil {
		return unitMeta{}, errMalformed
	}
	body := strings.Join(lines[2:], "\n")
	sum := sha256.Sum256([]byte(body))
	if hex.EncodeToString(sum[:]) != sm[1] {
		return unitMeta{}, errModified
	}
	// Old units predating the mode marker default to bootstrap: their recorded
	// listener is only a bootstrap value resolved through the durable
	// configuration, matching the legacy behaviour.
	meta := unitMeta{listenMode: ListenModeBootstrap}
	listenSeen, modeSeen, dataSeen, envfileSeen, healthSeen := 0, 0, 0, 0, 0
	for _, ln := range lines[2:] {
		switch {
		case strings.HasPrefix(ln, "# trestle-listen: "):
			listenSeen++
			if listenSeen > 1 {
				return unitMeta{}, errMalformed
			}
			meta.listen = strings.TrimSpace(strings.TrimPrefix(ln, "# trestle-listen: "))
		case strings.HasPrefix(ln, "# trestle-listen-mode: "):
			modeSeen++
			if modeSeen > 1 {
				return unitMeta{}, errMalformed
			}
			meta.listenMode = strings.TrimSpace(strings.TrimPrefix(ln, "# trestle-listen-mode: "))
		case strings.HasPrefix(ln, "# trestle-data: "):
			dataSeen++
			if dataSeen > 1 {
				return unitMeta{}, errMalformed
			}
			meta.data = strings.TrimSpace(strings.TrimPrefix(ln, "# trestle-data: "))
		case strings.HasPrefix(ln, "# trestle-envfile: "):
			envfileSeen++
			if envfileSeen > 1 {
				return unitMeta{}, errMalformed
			}
			meta.envfile = strings.TrimSpace(strings.TrimPrefix(ln, "# trestle-envfile: "))
		case strings.HasPrefix(ln, "# trestle-health: "):
			healthSeen++
			if healthSeen > 1 {
				return unitMeta{}, errMalformed
			}
			meta.health = strings.TrimSpace(strings.TrimPrefix(ln, "# trestle-health: "))
		}
	}
	if listenSeen != 1 || dataSeen != 1 || healthSeen != 1 || meta.listen == "" || meta.data == "" || meta.health == "" {
		return unitMeta{}, errMalformed
	}
	if meta.listenMode != ListenModeExplicit && meta.listenMode != ListenModeBootstrap {
		return unitMeta{}, errMalformed
	}
	if meta.health != trestleHealthPath {
		return unitMeta{}, errMalformed
	}
	for _, v := range []struct{ val, name string }{{meta.listen, "listen"}, {meta.data, "data-dir"}} {
		if err := validateNoControl(v.val, v.name); err != nil {
			return unitMeta{}, errMalformed
		}
	}
	if meta.envfile != "" {
		if err := validateNoControl(meta.envfile, "environment file"); err != nil {
			return unitMeta{}, errMalformed
		}
		if strings.ContainsAny(meta.envfile, "%") {
			return unitMeta{}, errMalformed
		}
	}
	return meta, nil
}

// unitBody renders the systemd directives (no managed header).
func unitBody(spec unitSpec) string {
	dataDir := spec.dataDir
	if dataDir == "" {
		dataDir = DefaultDataDir
	}
	var b strings.Builder
	b.WriteString("[Unit]\n")
	b.WriteString("Description=Trestle records service\n")
	b.WriteString("After=network-online.target\n")
	b.WriteString("Wants=network-online.target\n")
	b.WriteString("StartLimitIntervalSec=60\n")
	b.WriteString("StartLimitBurst=5\n\n")
	b.WriteString("[Service]\n")
	b.WriteString("Type=simple\n")
	b.WriteString("User=" + ServiceUser + "\n")
	b.WriteString("Group=" + ServiceGroup + "\n")
	b.WriteString("ExecStart=" + BinaryPath)
	if spec.listen != "" {
		b.WriteString(" " + systemdQuote("--listen") + " " + systemdQuote(spec.listen))
	} else {
		b.WriteString(" " + systemdQuote("--host") + " " + systemdQuote(strings.TrimSpace(spec.host)))
		b.WriteString(" " + systemdQuote("--port") + " " + systemdQuote(strings.TrimSpace(spec.port)))
	}
	b.WriteString(" " + systemdQuote("--data-dir") + " " + systemdQuote(dataDir))
	b.WriteString("\n")
	b.WriteString("Restart=on-failure\n")
	b.WriteString("RestartSec=3\n")
	b.WriteString("NoNewPrivileges=true\n")
	b.WriteString("PrivateTmp=true\n")
	b.WriteString("ProtectSystem=strict\n")
	b.WriteString("ProtectHome=true\n")
	b.WriteString("ReadWritePaths=" + systemdQuote(dataDir) + "\n")
	if spec.envfile != "" {
		b.WriteString("EnvironmentFile=" + systemdQuote(spec.envfile) + "\n")
	}
	b.WriteString("\n[Install]\n")
	b.WriteString("WantedBy=multi-user.target\n")
	return b.String()
}

// buildUnit returns the full managed unit content.
func buildUnit(spec unitSpec) string {
	dataDir := spec.dataDir
	if dataDir == "" {
		dataDir = DefaultDataDir
	}
	listen := spec.listener()
	meta := "# trestle-listen: " + listen + "\n"
	meta += "# trestle-listen-mode: " + spec.listenMode + "\n"
	meta += "# trestle-data: " + dataDir + "\n"
	if spec.envfile != "" {
		meta += "# trestle-envfile: " + spec.envfile + "\n"
	}
	meta += "# trestle-health: " + trestleHealthPath + "\n"
	content := meta + unitBody(spec)
	sum := sha256.Sum256([]byte(content))
	header := trestleUnitMarker + "\n" + trestleManagedPrefix + "v1 sha256=" + hex.EncodeToString(sum[:]) + "\n"
	return header + content
}

// Unit returns the full managed unit content for the legacy single-address
// bootstrap form (exported for tests).
func Unit(dataDir, listen string, envfile string) string {
	return buildUnit(unitSpec{dataDir: dataDir, listen: listen, envfile: envfile, listenMode: ListenModeBootstrap})
}

// UnitExplicit returns the full managed unit content for an explicit --host/--
// port install, whose recorded listener is the runtime listener (exported for
// tests).
func UnitExplicit(dataDir, host, port string, envfile string) string {
	return buildUnit(unitSpec{dataDir: dataDir, host: host, port: port, envfile: envfile, listenMode: ListenModeExplicit})
}

func writeFileAtomic(path string, data []byte, mode os.FileMode) error {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0700); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(dir, ".trestle-write-*")
	if err != nil {
		return err
	}
	name := tmp.Name()
	defer os.Remove(name)
	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Chmod(mode); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(name, path)
}

// validateEnvFile validates an EnvironmentFile path for the service unit:
// absolute, a regular non-symlink file with exactly owner-only 0600
// permissions, owned by root (uid 0), and free of systemd specifier and
// control characters. Machine configuration is root-owned so the service
// account cannot rewrite its own configuration.
func validateEnvFile(path string) error {
	if !filepath.IsAbs(path) {
		return fmt.Errorf("environment file %q must be an absolute path", path)
	}
	if err := validateNoControl(path, "environment file"); err != nil {
		return err
	}
	if strings.ContainsAny(path, "%") {
		return fmt.Errorf("environment file %q must not contain systemd specifiers (%% )", path)
	}
	info, err := os.Lstat(path)
	if err != nil {
		return fmt.Errorf("environment file: %w", err)
	}
	if info.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("environment file %q must not be a symlink", path)
	}
	if !info.Mode().IsRegular() {
		return fmt.Errorf("environment file %q must be a regular file", path)
	}
	if info.Mode().Perm() != 0o600 {
		return fmt.Errorf("environment file %q must have exactly 0600 permissions (owner read/write only)", path)
	}
	if fileUID(info) != 0 {
		return fmt.Errorf("environment file %q must be owned by root (uid 0); machine configuration is root-owned", path)
	}
	return nil
}

// dataDirStatus classifies the outcome of the non-mutating data-path
// inspection so the installer can defer every filesystem mutation until after
// all preflight succeeds.
type dataDirStatus int

const (
	// dataDirAcceptFresh means the final leaf is missing but its parent already
	// exists and was safely opened; the leaf may be created during the mutation
	// phase, relative to the retained parent descriptor.
	dataDirAcceptFresh dataDirStatus = iota
	// dataDirAcceptExisting means the leaf already exists and is a safe,
	// service-owned directory.
	dataDirAcceptExisting
)

// dataLeafInfo carries the leaf stat fields the installer needs, kept
// cross-platform so the descriptor-relative primitives can be declared and
// stubbed on every build target.
type dataLeafInfo struct {
	isDir     bool
	isSymlink bool
	mode      os.FileMode
	uid       int
}

// dataDirPlan is the result of the non-mutating inspection. It retains the
// validated parent directory descriptor AND, for an existing leaf, the retained
// leaf descriptor, so the mutation phase is bound to the exact objects
// inspected, never re-walked by pathname.
type dataDirPlan struct {
	status   dataDirStatus
	parentFd int
	leafFd   int // retained leaf descriptor for an existing leaf; -1 for a fresh leaf
	leafName string
	path     string
}

// close releases the retained descriptors exactly once (idempotent).
func (p *dataDirPlan) close() {
	if p.parentFd >= 0 {
		closeFdSeam(p.parentFd)
		p.parentFd = -1
	}
	if p.leafFd >= 0 {
		closeFdSeam(p.leafFd)
		p.leafFd = -1
	}
}

// inspectDataDir and establishDataDir are implemented on Linux using a
// descriptor-relative, no-symlink walk of the parent chain (see datadir_linux.go)
// so the validated parent is the exact directory mutated; non-Linux stubs fail
// (Install is Linux-gated).

// topLevelSystemRoots are filesystem roots that can never be a service data
// directory even as a direct target (e.g. `--data /var`).
var topLevelSystemRoots = map[string]bool{
	"/": true, "/bin": true, "/boot": true, "/dev": true, "/etc": true,
	"/home": true, "/lib": true, "/lib64": true, "/opt": true, "/proc": true,
	"/root": true, "/run": true, "/sbin": true, "/srv": true, "/sys": true,
	"/tmp": true, "/usr": true, "/var": true,
}

// protectedSystemTrees are system trees beneath which arbitrary application
// data does not belong. /var and /srv are intentionally NOT in this set so
// canonical /var/lib/<project> and /srv/<project> locations remain valid.
var protectedSystemTrees = map[string]bool{
	"/bin": true, "/boot": true, "/dev": true, "/etc": true, "/lib": true,
	"/lib64": true, "/proc": true, "/root": true, "/run": true, "/sbin": true,
	"/sys": true, "/usr": true,
}

// validateDataDirPath rejects data-directory paths that are dangerous system
// roots or live beneath protected system trees. It must run before any
// ownership or mode mutation.
func validateDataDirPath(path string) error {
	clean := filepath.Clean(path)
	if topLevelSystemRoots[clean] {
		return fmt.Errorf("data directory %q is a system directory and cannot be adopted as a service data directory", path)
	}
	for p := clean; p != "/"; p = filepath.Dir(p) {
		if protectedSystemTrees[p] {
			return fmt.Errorf("data directory %q lives beneath protected system tree %q and cannot be used as a service data directory", path, p)
		}
	}
	return nil
}

// validateReadWritePath validates a data directory for ReadWritePaths=.
func validateReadWritePath(path string) error {
	if !filepath.IsAbs(path) {
		return fmt.Errorf("data directory %q must be an absolute path", path)
	}
	if err := validateNoControl(path, "data directory"); err != nil {
		return err
	}
	if strings.ContainsAny(path, "%") {
		return fmt.Errorf("data directory %q must not contain systemd specifiers (%% )", path)
	}
	if strings.ContainsAny(path, `"\`) {
		return fmt.Errorf("data directory %q cannot be safely quoted in ReadWritePaths", path)
	}
	if len(path) > 0 && strings.ContainsRune("-+!~", rune(path[0])) {
		return fmt.Errorf("data directory %q starts with a ReadWritePaths special prefix; use a plain absolute path", path)
	}
	return nil
}

// Install installs (or idempotently reinstalls) the trestle systemd unit from
// the legacy single-address bootstrap listener. InstallExplicit installs from a
// canonical --host/--port pair whose recorded listener is the runtime listener.
// Both share the same transaction machinery in install.
func Install(exe, dataDir, listen string, envfile string) (retErr error) {
	return install(exe, unitSpec{dataDir: dataDir, listen: listen, envfile: envfile, listenMode: ListenModeBootstrap})
}

// InstallExplicit installs (or idempotently reinstalls) the trestle systemd
// unit from an explicit --host/--port pair, recording the canonical pair in
// ExecStart so the recorded listener is the runtime listener across restart and
// reboot.
func InstallExplicit(exe, dataDir, host, port string, envfile string) (retErr error) {
	return install(exe, unitSpec{dataDir: dataDir, host: host, port: port, envfile: envfile, listenMode: ListenModeExplicit})
}

func install(exe string, spec unitSpec) (retErr error) {
	dataDir := spec.dataDir
	listen := spec.listener()
	// Non-mutating preflight runs first so a foreign/tampered unit, unsupported
	// state, state-query failure, invalid executable, invalid environment file
	// or unacceptable data directory is rejected with zero account, mkdir,
	// chmod, chown, binary, unit or lifecycle mutation.
	if e := requireLinux(); e != nil {
		return e
	}
	if !isRoot() {
		return errors.New("service install requires root")
	}
	for _, v := range []struct{ val, name string }{{dataDir, "data dir"}, {listen, "listen"}} {
		if e := validateNoControl(v.val, v.name); e != nil {
			return e
		}
	}
	if dataDir == "" {
		dataDir = DefaultDataDir
	}
	if listen == "" {
		listen = DefaultListen
	}
	if e := validateReadWritePath(dataDir); e != nil {
		return e
	}
	if e := validateDataDirPath(dataDir); e != nil {
		return e
	}
	if spec.envfile != "" {
		if e := validateEnvFile(spec.envfile); e != nil {
			return e
		}
	}
	if _, e := exec.LookPath("systemctl"); e != nil {
		return errors.New("systemctl not found; is systemd installed?")
	}
	// Read and authenticate the existing managed unit (non-mutating).
	spec.dataDir = dataDir
	switch spec.listenMode {
	case ListenModeBootstrap:
		if spec.listen == "" {
			spec.listen = listen
		}
	case ListenModeExplicit:
		if strings.TrimSpace(spec.host) == "" || strings.TrimSpace(spec.port) == "" {
			return errors.New("service install requires an explicit --host and --port")
		}
	default:
		return fmt.Errorf("service install: unknown listen mode %q", spec.listenMode)
	}
	unit := buildUnit(spec)
	priorUnit, hadUnit := []byte(nil), false
	if b, e := os.ReadFile(UnitPath); e == nil {
		hadUnit = true
		priorUnit = b
		if ve := validateManagedUnit(b); ve != nil {
			return fmt.Errorf("refusing to reinstall trestle.service: %v", ve)
		}
	} else if !errors.Is(e, os.ErrNotExist) {
		return e
	}
	// Query and classify the exact prior systemd state (non-mutating). Query
	// failures are propagated and every state that cannot be recreated exactly
	// by rollback is refused up front.
	priorEnabled, priorActive := "", ""
	if hadUnit {
		var e error
		if priorEnabled, e = unitStateWord("is-enabled"); e != nil {
			return fmt.Errorf("refusing to reinstall trestle.service: %w", e)
		}
		if !restorableEnabledWord(priorEnabled) {
			return fmt.Errorf("refusing to reinstall trestle.service: prior enablement state %q cannot be restored exactly; disable or unmask it first", priorEnabled)
		}
		if priorActive, e = unitStateWord("is-active"); e != nil {
			return fmt.Errorf("refusing to reinstall trestle.service: %w", e)
		}
		if !restorableActiveWord(priorActive) {
			return fmt.Errorf("refusing to reinstall trestle.service: prior active state %q cannot be restored exactly; stop or restart it first", priorActive)
		}
		if !restorablePriorState(priorEnabled, priorActive) {
			return fmt.Errorf("refusing to reinstall trestle.service: prior state %s+%s cannot be restored exactly; unmask it first", priorEnabled, priorActive)
		}
	}
	// Inspect the incoming and installed executables (non-mutating).
	incomingDigest, err := fileSHA256(exe)
	if err != nil {
		return fmt.Errorf("read incoming executable: %w", err)
	}
	priorBinaryDigest, hadBinary := "", false
	if d, e := fileSHA256(BinaryPath); e == nil {
		hadBinary = true
		priorBinaryDigest = d
	}
	binaryChanged := !hadBinary || incomingDigest != priorBinaryDigest
	unitChanged := !hadUnit || string(priorUnit) != unit
	// Non-mutating data-path inspection: classify the requested directory
	// (acceptable fresh leaf with a safe existing parent, or acceptable existing
	// service-owned leaf) or refuse it. This runs before the genuine-no-op
	// return so a reinstall never claims "already correct" while a recorded
	// runtime prerequisite (the data directory) is missing or unsafe, and it
	// runs before any account/data mutation so an unacceptable existing
	// directory cannot trigger account creation first.
	dataPlan, dErr := inspectDataDir(dataDir)
	if dErr != nil {
		return fmt.Errorf("refusing to install trestle.service: %w", dErr)
	}
	defer dataPlan.close()
	// Genuine no-op: the installed unit and executable already match the request
	// AND the recorded data directory already exists as a safe service-owned
	// leaf, so the service is already running the requested version in its prior
	// state; nothing is rewritten, reloaded, enabled or started.
	if hadUnit && string(priorUnit) == unit && !binaryChanged && dataPlan.status == dataDirAcceptExisting {
		if priorActive == "active" {
			if e := waitServiceReady(); e != nil {
				return fmt.Errorf("installed trestle.service is not healthy: %w", e)
			}
		}
		return nil
	}
	// ---- Mutation phase begins here ----
	if e := ensureAccount(); e != nil {
		return e
	}
	if e := establishDataDir(&dataPlan); e != nil {
		return e
	}
	// Repair-only: the unit and binary already match the request, so the only
	// reason the no-op check did not return early was a missing data leaf, which
	// has just been recreated. No systemd state change is needed.
	if hadUnit && string(priorUnit) == unit && !binaryChanged {
		return nil
	}
	if hadBinary {
		if e := copyFile(BinaryPath, BinaryPath+".preinstall", 0o755); e != nil {
			return e
		}
	}
	installOK := false
	restore := func() string {
		var errs []string
		if e := systemctlSuccess("stop", "trestle.service"); e != nil {
			errs = append(errs, fmt.Sprintf("neutralize stop: %v", e))
		}
		if e := systemctlSuccess("disable", "trestle.service"); e != nil {
			errs = append(errs, fmt.Sprintf("neutralize disable: %v", e))
		}
		if hadBinary {
			if e := copyFile(BinaryPath+".preinstall", BinaryPath, 0o755); e != nil {
				errs = append(errs, fmt.Sprintf("restore binary: %v", e))
			}
		} else {
			_ = os.Remove(BinaryPath)
		}
		_ = os.Remove(BinaryPath + ".preinstall")
		if hadUnit {
			if e := writeFileAtomic(UnitPath, priorUnit, 0o644); e != nil {
				errs = append(errs, fmt.Sprintf("restore unit: %v", e))
			}
		} else {
			_ = os.Remove(UnitPath)
		}
		if e := systemctlSuccess("daemon-reload"); e != nil {
			errs = append(errs, fmt.Sprintf("reload systemd: %v", e))
		}
		if hadUnit {
			for _, args := range enableRestoreSteps(priorEnabled, "trestle.service") {
				if e := systemctlSuccess(args...); e != nil {
					errs = append(errs, fmt.Sprintf("restore enablement %q: %v", priorEnabled, e))
					break
				}
			}
			if priorActive == "active" {
				if e := systemctlSuccess("reset-failed", "trestle.service"); e != nil {
					errs = append(errs, fmt.Sprintf("clear failed state before restoring active state: %v", e))
				}
			}
			if e := systemctlSuccess(activeRestoreArgs(priorActive, "trestle.service")...); e != nil {
				errs = append(errs, fmt.Sprintf("restore active state %q: %v", priorActive, e))
			}
		}
		if len(errs) == 0 {
			return ""
		}
		return "; rollback incomplete: " + strings.Join(errs, "; ")
	}
	defer func() {
		if !installOK && retErr != nil {
			if rb := restore(); rb != "" {
				retErr = fmt.Errorf("%v%s", retErr, rb)
			}
		}
	}()
	if e := copyFile(exe, BinaryPath, 0o755); e != nil {
		return e
	}
	if e := writeFileAtomic(UnitPath, []byte(unit), 0o644); e != nil {
		return e
	}
	// Forward path: a fresh install establishes the machine-service default
	// (enabled + active). An EXISTING managed installation (changed OR
	// unchanged) must preserve its exact prior enablement and activity states
	// through the same canonical restoration helpers used by failed-install
	// rollback.
	steps := [][]string{}
	if unitChanged {
		steps = append(steps, []string{"daemon-reload"})
	}
	if !hadUnit {
		steps = append(steps, []string{"enable", "trestle.service"}, []string{"reset-failed", "trestle.service"}, []string{"restart", "trestle.service"})
	} else {
		steps = append(steps, enableRestoreSteps(priorEnabled, "trestle.service")...)
		if priorActive == "active" {
			steps = append(steps, []string{"reset-failed", "trestle.service"})
		}
		steps = append(steps, activeRestoreArgs(priorActive, "trestle.service"))
	}
	for _, a := range steps {
		if out, code, err := systemctl(a...); err != nil || code != 0 {
			retErr = fmt.Errorf("systemctl %s: %s: %w (installation rolled back)", strings.Join(a, " "), bounded(strings.TrimSpace(out)), errorIfNil(err, code, a))
			return retErr
		}
	}
	if !hadUnit || priorActive == "active" {
		if e := waitServiceReady(); e != nil {
			retErr = fmt.Errorf("trestle.service did not become healthy after install: %w (installation rolled back)", e)
			return retErr
		}
	}
	installOK = true
	_ = os.Remove(BinaryPath + ".preinstall")
	return nil
}

// restorableEnabledWord reports whether a prior is-enabled word can be
// recreated exactly by the rollback enablement sequence. Persistent enablement
// (enabled), runtime-only enablement (enabled-runtime) and their absence
// (disabled) are restorable. Masked/static/linked/generated/transient and other
// unit-file states are refused before mutation because enable/disable cannot
// reproduce them.
func restorableEnabledWord(word string) bool {
	switch word {
	case "enabled", "enabled-runtime", "disabled":
		return true
	}
	return false
}

// restorableActiveWord reports whether a prior is-active word can be recreated
// exactly by the rollback activation sequence. Running and stopped are
// restorable; transient, failed, reloading and unknown states are not.
func restorableActiveWord(word string) bool {
	switch word {
	case "active", "inactive":
		return true
	}
	return false
}

// restorablePriorState reports whether the enablement/active pair can be
// reproduced exactly.
func restorablePriorState(enabledWord, activeWord string) bool {
	return restorableEnabledWord(enabledWord) && restorableActiveWord(activeWord)
}

// enableRestoreSteps returns the systemctl calls that reproduce a prior
// is-enabled word exactly. Enablement is normalized first: the persistent
// enablement link created by the attempted install is removed with disable,
// then the intended persistent or runtime link is recreated, so a runtime-only
// prior never leaves a persistent enablement behind.
func enableRestoreSteps(word, unit string) [][]string {
	switch word {
	case "enabled":
		return [][]string{{"disable", unit}, {"enable", unit}}
	case "enabled-runtime":
		return [][]string{{"disable", unit}, {"enable", "--runtime", unit}}
	default: // disabled
		return [][]string{{"disable", unit}}
	}
}

// activeRestoreArgs returns the systemctl call that reproduces a prior
// is-active word exactly.
func activeRestoreArgs(word, unit string) []string {
	if word == "active" {
		return []string{"restart", unit}
	}
	return []string{"stop", unit}
}

func errorIfNil(err error, code int, args []string) error {
	if err != nil {
		return err
	}
	_ = args
	return fmt.Errorf("exited %d", code)
}

func ensureServiceAccount() error {
	if out, e := exec.Command("groupadd", "--system", ServiceGroup).CombinedOutput(); e != nil {
		if !strings.Contains(string(out), "exists") {
			return fmt.Errorf("groupadd: %s", strings.TrimSpace(string(out)))
		}
	}
	if out, e := exec.Command("useradd", "--system", "--no-create-home", "--shell", "/usr/sbin/nologin", "--gid", ServiceGroup, ServiceUser).CombinedOutput(); e != nil {
		if !strings.Contains(string(out), "exists") {
			return fmt.Errorf("useradd: %s", strings.TrimSpace(string(out)))
		}
	}
	return nil
}

func lookupServiceIDs() (int, int, error) {
	g, e := user.LookupGroup(ServiceGroup)
	if e != nil {
		return 0, 0, fmt.Errorf("service group not found: %w", e)
	}
	gid, _ := strconv.Atoi(g.Gid)
	u, e := user.Lookup(ServiceUser)
	if e != nil {
		return 0, 0, fmt.Errorf("service user not found: %w", e)
	}
	uid, _ := strconv.Atoi(u.Uid)
	return uid, gid, nil
}

// serviceUID returns the numeric UID of the service account. It is a variable
// so tests can simulate the account without a real system user.
var serviceUID = func() (int, error) {
	uid, _, e := lookupServiceIDs()
	return uid, e
}

func lifecycle(verb string) error {
	if e := requireLinux(); e != nil {
		return e
	}
	if e := requireRoot(verb); e != nil {
		return e
	}
	if e := requireManaged(verb); e != nil {
		return e
	}
	if verb == "start" || verb == "restart" {
		if err := systemctlSuccess("reset-failed", "trestle.service"); err != nil {
			return fmt.Errorf("clear previous failed state: %w", err)
		}
	}
	if err := systemctlSuccess(verb, "trestle.service"); err != nil {
		return err
	}
	if verb == "start" || verb == "restart" {
		if err := waitServiceReady(); err != nil {
			return fmt.Errorf("service %s did not become healthy: %w", verb, err)
		}
	}
	return nil
}

// Start starts the service.
func Start() error { return lifecycle("start") }

// Stop stops the service.
func Stop() error { return lifecycle("stop") }

// Restart restarts the service.
func Restart() error { return lifecycle("restart") }

// Enable enables the service at boot.
func Enable() error { return lifecycle("enable") }

// Disable disables the service at boot (without stopping it).
func Disable() error { return lifecycle("disable") }

// Uninstall stops and disables the service, removes the unit and reloads
// systemd. The data directory and installed binary are deliberately preserved.
func Uninstall() error {
	if e := requireLinux(); e != nil {
		return e
	}
	if e := requireRoot("uninstall"); e != nil {
		return e
	}
	if e := requireManaged("uninstall"); e != nil {
		return e
	}
	if e := systemctlSuccess("disable", "--now", "trestle.service"); e != nil {
		return fmt.Errorf("uninstall: %w", e)
	}
	if e := os.Remove(UnitPath); e != nil && !errors.Is(e, os.ErrNotExist) {
		return e
	}
	return systemctlSuccess("daemon-reload")
}

// trestleEffectiveListen resolves the actual runtime listener for a legacy
// bootstrap unit. Trestle's flag-over-environment configuration resolution
// makes the unit's recorded --listen authoritative for the runtime process (a
// flag in ExecStart always beats TRESTLE_LISTEN from the durable environment
// file), so the recorded bootstrap listener IS the runtime listener. The helper
// mirrors the shared Warden/Cortex pattern where legacy units consult their
// durable configuration before trusting the recorded bootstrap value; for
// Trestle that durable resolution deterministically equals the recorded
// listener, and an explicit host/port unit never reaches this path.
func trestleEffectiveListen(envfile, fallback string) (string, error) {
	_ = envfile
	return fallback, nil
}

// Status reports the resolved service state, pid, data/listen configuration and
// a live health check. It is read-only and does not require root.
func Status(out io.Writer) error {
	if e := requireLinux(); e != nil {
		return e
	}
	body, e := os.ReadFile(UnitPath)
	if errors.Is(e, os.ErrNotExist) {
		return fmt.Errorf("trestle.service is not installed (run `trestle service install`)")
	}
	if e != nil {
		return fmt.Errorf("cannot read %s: %w", UnitPath, e)
	}
	meta, ve := readManagedUnit(string(body))
	if ve != nil {
		return fmt.Errorf("trestle.service unit at %s is not valid: %v", UnitPath, ve)
	}
	enabled, _ := unitStateWord("is-enabled")
	active, _ := unitStateWord("is-active")
	pid, _, _ := systemctl("show", "-p", "MainPID", "--value", "trestle.service")
	// New explicit host/port units record an authoritative runtime listener;
	// legacy bootstrap units resolve the effective listener through the durable
	// configuration.
	listen := meta.listen
	if meta.listenMode != ListenModeExplicit {
		var effErr error
		listen, effErr = trestleEffectiveListen(meta.envfile, meta.listen)
		if effErr != nil {
			return fmt.Errorf("cannot resolve the effective listen address: %v", effErr)
		}
	}
	dataDir := meta.data
	if listen == "" {
		listen = DefaultListen
	}
	if dataDir == "" {
		dataDir = DefaultDataDir
	}
	fmt.Fprintf(out, "unit:    trestle.service\n")
	fmt.Fprintf(out, "file:    %s\n", UnitPath)
	fmt.Fprintf(out, "enabled: %s\n", strings.TrimSpace(enabled))
	fmt.Fprintf(out, "active:  %s\n", strings.TrimSpace(active))
	fmt.Fprintf(out, "pid:     %s\n", strings.TrimSpace(pid))
	fmt.Fprintf(out, "user:    %s\n", ServiceUser)
	fmt.Fprintf(out, "data:    %s\n", dataDir)
	fmt.Fprintf(out, "listen:  %s\n", listen)
	if meta.envfile != "" {
		fmt.Fprintf(out, "env:     %s\n", meta.envfile)
	}
	if strings.TrimSpace(active) != "active" {
		fmt.Fprintln(out, "health:  not running")
		return fmt.Errorf("trestle.service is %q; expected active", strings.TrimSpace(active))
	}
	if err := healthCheckFunc("http://" + listen + trestleHealthPath); err != nil {
		fmt.Fprintf(out, "health:  unreachable (%v)\n", err)
		return fmt.Errorf("service is active but its health check failed: %v", err)
	}
	fmt.Fprintln(out, "health:  ok")
	return nil
}

var healthCheckFunc = func(url string) error { return healthCheckReal(url) }

func healthCheckReal(url string) error {
	client := &http.Client{Timeout: 3 * time.Second}
	resp, err := client.Get(url)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return fmt.Errorf("health returned %d", resp.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return err
	}
	var v map[string]any
	if err := json.Unmarshal(body, &v); err != nil {
		return fmt.Errorf("expected a JSON object response: %v", err)
	}
	if status, _ := v["status"].(string); status != "ok" {
		return fmt.Errorf("health response does not identify Trestle")
	}
	return nil
}

// Logs streams the service journal.
func Logs(follow bool, out io.Writer) error {
	if e := requireLinux(); e != nil {
		return e
	}
	if e := requireManaged("view logs for"); e != nil {
		return e
	}
	args := []string{"--unit", "trestle.service"}
	if follow {
		args = append(args, "-f")
		code, err := defaultRunner.Stream("journalctl", args...)
		if err != nil {
			return err
		}
		if code != 0 {
			return fmt.Errorf("journalctl exited with status %d", code)
		}
		return nil
	}
	o, code, err := defaultRunner.Run("journalctl", args...)
	if err != nil {
		return fmt.Errorf("cannot run journalctl: %w", err)
	}
	if code != 0 {
		return fmt.Errorf("journalctl exited %d: %s", code, bounded(strings.TrimSpace(o)))
	}
	fmt.Fprint(out, o)
	return nil
}

// Verify returns nil when the artifact's SHA-256 matches want.
func Verify(path, want string) error {
	b, e := os.ReadFile(path)
	if e != nil {
		return e
	}
	h := sha256.Sum256(b)
	got := hex.EncodeToString(h[:])
	if !strings.EqualFold(got, strings.TrimSpace(want)) {
		return fmt.Errorf("checksum mismatch: got %s", got)
	}
	return nil
}

// priorStateFileRead is a narrow injectable seam so tests can corrupt the
// marker at the exact recovery-time stage (after Update has written it).
var priorStateFileRead = os.ReadFile

func Update(artifact, want string) error {
	if e := requireLinux(); e != nil {
		return e
	}
	if !isRoot() {
		return errors.New("update requires root")
	}
	if e := requireManaged("update"); e != nil {
		return e
	}
	if e := Verify(artifact, want); e != nil {
		return e
	}
	priorActive, err := unitStateWord("is-active")
	if err != nil {
		return fmt.Errorf("update: cannot determine current service state: %w", err)
	}
	priorActive = strings.TrimSpace(priorActive)
	if priorActive != "active" && priorActive != "inactive" && priorActive != "dead" && priorActive != "failed" {
		return fmt.Errorf("update: unexpected service state %q; refusing to update", priorActive)
	}
	wasActive := priorActive == "active"
	if _, e := os.Stat(BinaryPath); e == nil {
		if e := copyFile(BinaryPath, BinaryPath+".rollback", 0o755); e != nil {
			return e
		}
		if e := writeFileAtomic(BinaryPath+".prior-active", []byte(priorActive), 0o600); e != nil {
			_ = os.Remove(BinaryPath + ".rollback")
			return fmt.Errorf("update: cannot record rollback state: %w", e)
		}
	}
	if e := copyFile(artifact, BinaryPath, 0o755); e != nil {
		return e
	}
	if !wasActive {
		return nil
	}
	if out, code, err := systemctl("restart", "trestle.service"); err != nil || code != 0 {
		updateErr := fmt.Errorf("restart after update: %s: %w", bounded(strings.TrimSpace(out)), errorIfNil(err, code, nil))
		return updateFailureWithRecovery(updateErr, restoreAfterFailedUpdate())
	}
	if e := verifyActiveAndHealthy(); e != nil {
		updateErr := fmt.Errorf("update: new binary failed to become healthy: %w", e)
		return updateFailureWithRecovery(updateErr, restoreAfterFailedUpdate())
	}
	return nil
}

var healthWindow = 30 * time.Second

func updateFailureWithRecovery(updateErr, recoveryErr error) error {
	if recoveryErr != nil {
		return fmt.Errorf("%v; recovery also failed: %v", updateErr, recoveryErr)
	}
	return updateErr
}

func verifyActiveAndHealthy() error {
	listen := DefaultListen
	if b, e := os.ReadFile(UnitPath); e == nil {
		if meta, ve := readManagedUnit(string(b)); ve == nil && meta.listen != "" {
			listen = meta.listen
		}
	}
	deadline := time.Now().Add(healthWindow)
	for time.Now().Before(deadline) {
		active, _ := unitStateWord("is-active")
		if strings.TrimSpace(active) == "active" {
			if err := healthCheckFunc("http://" + listen + trestleHealthPath); err == nil {
				return nil
			}
		}
		time.Sleep(500 * time.Millisecond)
	}
	return fmt.Errorf("service did not become active and healthy within %s", healthWindow)
}

// waitServiceReady is a seam for lifecycle unit tests. Production always uses
// the same bounded active-and-health verification as update and recovery.
var waitServiceReady = verifyActiveAndHealthy

// restoreAfterFailedUpdate verifiably restores the previous version and its
// operational state after a failed update. It fails closed if the prior-state
// marker is missing or invalid at recovery time.
func restoreAfterFailedUpdate() error {
	b, err := priorStateFileRead(BinaryPath + ".prior-active")
	if err != nil {
		return fmt.Errorf("recovery: no prior-state marker: %w", err)
	}
	priorActive := strings.TrimSpace(string(b))
	if priorActive != "active" && priorActive != "inactive" && priorActive != "dead" && priorActive != "failed" {
		return fmt.Errorf("recovery: invalid prior-state marker %q", priorActive)
	}
	if e := systemctlSuccess("stop", "trestle.service"); e != nil {
		return fmt.Errorf("recovery: stop failed service: %w", e)
	}
	if e := copyFile(BinaryPath+".rollback", BinaryPath, 0o755); e != nil {
		return fmt.Errorf("recovery: restore old binary: %w", e)
	}
	if priorActive == "active" {
		if e := systemctlSuccess("restart", "trestle.service"); e != nil {
			return fmt.Errorf("recovery: restart old service: %w", e)
		}
		if e := verifyActiveAndHealthy(); e != nil {
			return fmt.Errorf("recovery: restored service not healthy: %w", e)
		}
	}
	_ = os.Remove(BinaryPath + ".prior-active")
	_ = os.Remove(BinaryPath + ".rollback")
	return nil
}

func Rollback() error {
	if e := requireLinux(); e != nil {
		return e
	}
	if !isRoot() {
		return errors.New("rollback requires root")
	}
	if e := requireManaged("rollback"); e != nil {
		return e
	}
	if _, e := os.Stat(BinaryPath + ".rollback"); e != nil {
		return errors.New("no rollback binary available")
	}
	b, err := priorStateFileRead(BinaryPath + ".prior-active")
	if err != nil {
		return fmt.Errorf("rollback: no prior-state marker; refusing to guess the service state")
	}
	priorActive := strings.TrimSpace(string(b))
	if priorActive != "active" && priorActive != "inactive" && priorActive != "dead" && priorActive != "failed" {
		return fmt.Errorf("rollback: invalid prior-state marker %q", priorActive)
	}
	wasActive := priorActive == "active"
	cur := BinaryPath + ".failed"
	_ = os.Remove(cur)
	if e := os.Rename(BinaryPath, cur); e != nil {
		return e
	}
	if e := os.Rename(BinaryPath+".rollback", BinaryPath); e != nil {
		_ = os.Rename(cur, BinaryPath)
		return e
	}
	if !wasActive {
		_ = os.Remove(BinaryPath + ".prior-active")
		_ = os.Remove(BinaryPath + ".rollback")
		return nil
	}
	if e := systemctlSuccess("restart", "trestle.service"); e != nil {
		return e
	}
	if e := verifyActiveAndHealthy(); e != nil {
		return e
	}
	_ = os.Remove(BinaryPath + ".prior-active")
	_ = os.Remove(BinaryPath + ".rollback")
	return nil
}

// Executable returns the absolute path of the running binary.
func Executable() string { p, _ := os.Executable(); p, _ = filepath.Abs(p); return p }
