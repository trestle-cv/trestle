# Trestle

Trestle is a self-hosted application backend with collections, authentication, files, realtime events and administration.

## Command line

```sh
trestle version
trestle --version
trestle service status
```

Unknown commands and unsupported options fail with a non-zero exit status.
Run the binary without a subcommand to start the integrated server, or use
`trestle serve` where that compatibility alias is supported.

Trestle is an open-source, self-hosted backend platform with
collections, authentication, access rules, files, realtime APIs, migrations,
administration, backups, and event-driven integrations in one compact binary.

Its stable HTTP/JSON/SSE contracts are intended to work from browsers, mobile
applications, and trusted backends written in any language.

For a complete external application, see
[Incident Desk](https://github.com/trestle-cv/trestle-example). It combines
application users, collection rules, typed records, realtime SSE and files
without importing Trestle packages or opening the SQLite database.

## Module path migration

Releases through v0.1.2 used the module identity `github.com/trestle-dev/trestle`.
Development from v0.1.3 uses `github.com/trestle-cv/trestle`.

- Downstream Go imports must use the new `github.com/trestle-cv/trestle` path
  when upgrading.
- Binary installation users are unaffected apart from the corrected download
  URLs; `install.sh`, `download.sh` and `update.sh` now default to the
  `trestle-cv` release channel.

Trestle v0.1.4 is the current stable public-preview release: checkpoints CP00-CP22 and all
ten CP23 hardening campaigns are implemented,
covering the process and SQLite foundation, embedded administration, typed
collections and records, authentication and access rules, local and
S3-compatible files, realtime events, audit, durable jobs, webhooks, AWS Lambda,
OpenAPI, reference clients, backup/recovery, and whole-product dogfooding.
Deployment and release automation are implemented. The stable public-preview
label means the release establishes a normal, installable download channel; it
is not a production-proven or battle-proven claim.

The `main` development line is 0.1.5: an ordinary development build reports
version 0.1.5 (commit `unknown`), while release builds and the published v0.1.4
stable tag are unaffected. Release builds override the default via ldflags with
the released version and commit. Installers and the public website always
target the actual published release, never the development line.

A separate PostgreSQL parity campaign (PG00-PG11) is complete. PostgreSQL is an
available external-database option for deployments needing its operational
model; SQLite remains the embedded zero-configuration option. The parity
corpus, migration safety and recovery semantics are exercised against
PostgreSQL 16, 17 and 18 in CI and PostgreSQL 18.6 locally. See
`POSTGRES-CHECKPOINTS.md`.

An active public-preview campaign (`PREVIEW-CHECKPOINTS.md`) hardens the whole
product for an honest preview. It adds a machine-readable PostgreSQL readiness
contract, a single reproducible PostgreSQL gate
(`scripts/test-postgres-gate.sh`), and proceeds through recovery, parity,
release, domain and publish/no-publish checkpoints. Trestle is an early public
preview for evaluation and prototypes; it is not presented as battle-proven or
production-immune. Each stable semver tag is a stable GitHub release with
stable public-preview maturity — it is not itself a release candidate, and it
makes no production-proven or battle-proven claim.

## Requirements

- Go 1.22 or newer
- A current Nift 4.x executable available as `nift`

Nift is a build-time dependency only. The generated dashboard is embedded in
the Go executable; deployments do not need Nift or a separate static directory.

## Build from source

Clone the repository, then build the Nift frontend before compiling Go:

```sh
nift build
nift status
go build -o trestle ./cmd/trestle
```

`nift status` should report all three tracked application outputs current. Nift
writes them beneath `internal/web/public/`, where Go's `embed` package includes
them in the executable. After changing `content/`, `templates/`, or frontend
assets, run `nift build` and rebuild the Go binary.

## Run Trestle

Start the compiled binary:

```sh
./trestle
```

Or build and run directly during development:

```sh
nift build
go run ./cmd/trestle
```

The default address is:

```text
http://127.0.0.1:7333
```

On first run, open that address and create the first administrator. The setup
route closes once the administrator is committed. Administrator passwords
currently require at least 7 characters.

First-run setup offers SQLite and PostgreSQL. **SQLite is the embedded
zero-configuration option**; PostgreSQL is the available external-database
option for deployments needing a server database. The setup selector persists
the chosen provider in an owner-only configuration file.

Trestle creates `./data/trestle.db` by default. The data directory is set to
owner-only permissions and must live on a local filesystem; shared/network
filesystem operation is not supported.

## Run as a systemd machine service

Run Trestle in the foreground with `./trestle` or `trestle serve`. To keep it
running unattended and boot-safely on a systemd host, install it as a system
service:

```sh
sudo trestle service install            # optional --host/--port, --listen, --data-dir, --env-file
trestle service status
trestle service logs                # or: trestle service logs --follow
sudo trestle service restart
sudo trestle service uninstall      # removes the service registration; keeps Trestle data
```

The system unit is written to `/etc/systemd/system/trestle.service` and runs as
a dedicated unprivileged `trestle` account (`nologin`, no home). It starts at
boot with `WantedBy=multi-user.target` and does **not** depend on any user login
or on systemd lingering. The binary is installed at `/usr/local/bin/trestle` and
the data directory is `/var/lib/trestle` (0700, owned `trestle:trestle`).
`service install` creates the account, data directory and unit idempotently, so
a clean machine needs no manual prerequisites.

`service install` resolves the executable to a stable absolute path, refuses
empty, relative or transient paths, and writes the unit atomically with a
versioned SHA-256 integrity header. An existing unit that is not managed by
Trestle is never overwritten or removed silently. Install is transactional: the
prior managed unit bytes are preserved, prior systemd enablement and activity
are inspected before mutation, only exactly-recreatable states are accepted
(`enabled`, `enabled-runtime`, `disabled` × `active`, `inactive`;
masked/static/linked/generated/transient/failed/reloading states are refused
before mutation — unmask or stop first), and rollback reproduces the exact prior
enablement and activity states, distinguishing persistent from runtime
enablement. A changed binary with an unchanged unit is still recognised as a
changed installation and the service is restarted. A byte-identical unit and
binary already enabled and active is a genuine no-op. A failed fresh install is
stopped and disabled while the unit is still loaded, then removed and systemd is
reloaded. `trestle service status` reports enabled/running state, PID, version,
listen address and a live health check of the public `GET /system/health`
endpoint, and exits nonzero when the service is failed or missing.

Install does not report success until an active service answers Trestle's
bounded health-and-identity check. The generated unit uses a finite crash-loop
policy (`StartLimitIntervalSec=60`, `StartLimitBurst=5`,
`Restart=on-failure`, `RestartSec=3`). Deliberate `service start`, `restart`
and active install/reinstall operations clear accumulated start-limit state
with `reset-failed` immediately before activation, while spontaneous repeated
crashes remain rate-limited.

The complete lifecycle family matches the Web Fleet convention:

```sh
sudo trestle service install|uninstall|start|stop|restart|enable|disable
trestle service status|logs [--follow]
sudo trestle service update ARTIFACT SHA256
sudo trestle service rollback
```

`update` replaces the binary with a checksum-verified artifact, preserving the
prior running/stopped state and enablement, and retaining rollback metadata so a
later `service rollback` restores the previous version and its operational
state. Failed updates recover to the previous binary before reactivation and
surface both the update and recovery failures when both occur.

### Configuration and secrets

`service install` records the canonical `--host`/`--port` listener (default
`127.0.0.1:7333`) and `--data-dir` (default `/var/lib/trestle`) in the unit, so
the recorded listener is the runtime listener across restart and reboot:

```sh
sudo trestle service install --host 127.0.0.1 --port 7403
```

The legacy single-address `--listen` form (and `TRESTLE_LISTEN`) is retained for
compatibility; it cannot be combined with `--host`/`--port`, and it records a
bootstrap listener that is resolved through the durable configuration. Because
the machine service does not inherit the shell environment, supply the remaining
`TRESTLE_*` configuration (including `TRESTLE_DATABASE_URL` for PostgreSQL and
`TRESTLE_S3_*`/`TRESTLE_AWS_*` credentials) through a root-protected environment
file:

```sh
sudo trestle service install --env-file /etc/trestle/trestle.env
```

The machine configuration file must be an absolute, regular, non-symlink file
with exactly `0600` permissions, owned by `root:root`; it is read by systemd via
`EnvironmentFile=` **before** the process drops to `User=trestle`, so the
service account cannot rewrite its own machine configuration. Secret values are
never copied into the unit or printed. The recorded environment file is
revalidated before `start`, `restart` and `status`; `stop`, `logs` and
`uninstall` remain available even if it is missing. Changing the file takes
effect on `trestle service restart`. Repeated `service install` calls preserve
the installed listen, data directory and environment file unless a flag is given
explicitly.

### External paths and the service account

In machine mode the `trestle` account reads and writes `/var/lib/trestle` (the
SQLite database, uploaded files, backups and the webhook signing key). The
PostgreSQL database and S3 storage are remote and carry no local filesystem
requirement. Development-only path overrides that refer outside `/var/lib/trestle`
(such as `TRESTLE_STATIC_DIR` for the embedded dashboard) are blocked by the
unit's `ProtectSystem=strict`/`ProtectHome=true` sandbox; if one is configured,
startup fails with a diagnostic rather than silently running with a degraded
dashboard. The unit applies the baseline hardening: `NoNewPrivileges`,
`PrivateTmp`, `ProtectSystem=strict`, `ProtectHome=true`,
`ReadWritePaths=/var/lib/trestle`, `Restart=on-failure`.

## Install a release

Two verified download paths are available. Both fetch the exact release archive
and its `SHA256SUMS`, verify the archive before writing anything, and never
execute the downloaded binary.

### Install on this user account

Writes to `~/.local/bin` (machine-wide `--system` installations are explicit):

```sh
curl -fsSL https://trestle.cv/install.sh | sh
```

### Download into this directory

Writes only `./trestle` in the current directory and changes nothing else -
suitable for portable folders, testing, manually operated servers, and users
who want to inspect exactly where the binary lives:

```sh
curl -fsSL https://trestle.cv/download.sh | sh
./trestle
```

`download.sh` supports a pinned version, an explicit output path, and `--force`
to overwrite an existing file:

```sh
curl -fsSL https://trestle.cv/download.sh | sh -s -- --version v0.1.4
curl -fsSL https://trestle.cv/download.sh | sh -s -- --output ./some-name
```

It refuses to overwrite an existing file, directory or symlink unless `--force`
is passed. Downloading never requires root.

### Update

Update the installed binary without changing instance data or configuration:

```sh
curl -fsSL https://trestle.cv/update.sh | sh
```

The updater supports `--dry-run`, `--version vX.Y.Z`, and `--rollback`, verifies
the selected archive with the same portable checksum check, and retains
`trestle.previous` for rollback. System installations pass `--system` through
`sudo` for install and update:

```sh
curl -fsSL https://trestle.cv/install.sh | sudo sh -s -- --system
```

All three public scripts verify archives with `sha256sum` where available and
fall back to `shasum -a 256` on macOS. Tagged releases contain Linux, macOS,
and Windows archives for amd64 and arm64, plus checksums and build provenance.

## Configuration

Flags override environment variables, which override defaults:

| Flag | Environment | Default |
| --- | --- | --- |
| `--host` | `TRESTLE_HOST` | `127.0.0.1` |
| `--port` | `TRESTLE_PORT` | `7333` |
| `--listen` | `TRESTLE_LISTEN` | none (legacy single-address form; alternative to `--host`/`--port`) |
| `--data-dir` | `TRESTLE_DATA_DIR` | `./data` |
| `--shutdown-timeout` | `TRESTLE_SHUTDOWN_TIMEOUT` | `10s` |
| `--log-level` | `TRESTLE_LOG_LEVEL` | `info` |
| `--static-dir` | `TRESTLE_STATIC_DIR` | embedded assets |
| `--trusted-proxies` | `TRESTLE_TRUSTED_PROXIES` | none |
| `--read-header-timeout` | `TRESTLE_READ_HEADER_TIMEOUT` | `5s` |
| `--read-timeout` | `TRESTLE_READ_TIMEOUT` | `5m` |
| `--idle-timeout` | `TRESTLE_IDLE_TIMEOUT` | `60s` |
| `--max-header-bytes` | `TRESTLE_MAX_HEADER_BYTES` | `1048576` |
| `--database-provider` | `TRESTLE_DATABASE_PROVIDER` | `sqlite` |
| `--database-url` | `TRESTLE_DATABASE_URL` | none (PostgreSQL only) |
| `--database-max-open` | `TRESTLE_DATABASE_MAX_OPEN` | `10` |
| `--database-max-idle` | `TRESTLE_DATABASE_MAX_IDLE` | `2` |
| `--database-connect-timeout` | `TRESTLE_DATABASE_CONNECT_TIMEOUT` | `10s` |
| `--database-conn-max-lifetime` | `TRESTLE_DATABASE_CONN_MAX_LIFETIME` | `30m` |

### Listener

The bind host and port follow the shared precedence **CLI flag > environment
variable > default**, with `127.0.0.1:7333` as the default:

```sh
./trestle                            # 127.0.0.1:7333
TRESTLE_PORT=7403 ./trestle          # 127.0.0.1:7403 (host defaulted)
./trestle --host 0.0.0.0 --port 7403 # CLI wins over environment and defaults
```

The port must be an integer from 1 through 65535; malformed, empty, zero,
negative or oversized values fail rather than falling back. Surrounding
whitespace is trimmed, and IPv6 hosts are bracketed (`--host ::1` binds
`[::1]:7333`). The legacy single-address `--listen` (and `TRESTLE_LISTEN`) is
retained for compatibility and is mutually exclusive with `--host`/`--port`; an
explicit host/port selection overrides `TRESTLE_LISTEN`, while a conflict
between `TRESTLE_LISTEN` and `TRESTLE_HOST`/`TRESTLE_PORT` environment variables
fails clearly. Explicit `--host`/`--port` (CLI or environment) overrides an
existing durable config listener in memory, so the advertised override controls
the runtime listener; a bare invocation or legacy `--listen` keeps the durable
config.

The default loopback binding is the recommended deployment: keep Trestle private
and terminate TLS with a reverse proxy on the same host (see
`deploy/caddy/Caddyfile` and `deploy/nginx/nginx.conf`). Binding `0.0.0.0`
exposes Trestle on all IPv4 interfaces with no authentication bypass; pair it
with explicit trusted-proxy configuration and TLS termination.

### Database providers

- `sqlite` (default) is the complete provider: one process owns one local
  database at `<data-dir>/trestle.db` with WAL, owner-only permissions, and
  refused unknown future schemas.
- `postgres` is available. Explicit startup configuration
  (`--database-provider postgres --database-url postgres://...`) or the stored
  first-run bootstrap selects it. Remote connections require TLS unless the
  host is loopback. The URL is stored atomically in a `0600`
  `<data-dir>/database.json` and is never returned by an API or written to
  logs, diagnostics, or support bundles.
- `--database-connect-timeout` must be a whole number of seconds. Trestle
  injects it as the driver's `connect_timeout` into every PostgreSQL connection
  configuration (startup, stored bootstrap, explicit flags, and the first-run
  connection test) so a hanging peer cannot stall startup indefinitely.
- The applied schema version is derived from validated
  `_trestle_schema_migrations` history on both providers. On SQLite,
  `PRAGMA user_version` is a compatibility mirror: a valid history restores an
  absent mirror, but history is never reconstructed from the marker, and
  disagreement or damaged history fails closed.
- Interrupted first-run setup is resumable: provider selection persists before
  restart, administrator creation stays available until one administrator
  commits, and setup never reopens afterward. A persisted but unreachable
  PostgreSQL configuration fails startup with a redacted error and requires
  manual `database.json` recovery.

The static-directory override is intended for frontend development. For
example, after running Nift in another terminal:

```sh
go run ./cmd/trestle --static-dir internal/web/public
```

Trestle logs a warning whenever the override is active.

Forwarded client and scheme headers are ignored unless the immediate peer is
inside an explicitly configured trusted-proxy CIDR. Bind Trestle to loopback
behind Caddy or nginx, preserve the public `Host`, and configure only the exact
proxy addresses you administer.

## Verify a change

```sh
nift build
nift status
node --check internal/web/public/assets/js/script.js
node scripts/check-web.mjs internal/web/public
go test ./...
go test -race ./...
go vet ./...
./scripts/test-release.sh
```

CI additionally compiles Linux, macOS, and Windows targets for both amd64 and
arm64.

## Current safety boundary

Trestle's stable public-preview line is the v0.1.x contract; the current
published release is v0.1.4, and the `main` development line is 0.1.5. The supported surfaces and explicit
exclusions of the released contract are recorded in `STABILITY.md`. A stable
public-preview release establishes the installable download channel and the
initial public compatibility contract; it is not a production-proven or
battle-proven claim, and independent field evidence remains distinct from
completing the engineering campaign.

## Project documents

Start with:

- [HANDOVER.md](HANDOVER.md) - product invariants and engineering workflow
- [CHECKPOINTS.md](CHECKPOINTS.md) - step-by-step implementation handover
- [PLAN.md](PLAN.md) - ordered implementation programme
- [ARCHITECTURE.md](ARCHITECTURE.md) - system and persistence boundaries
- [API.md](API.md) - language-neutral API contract direction
- [UI.md](UI.md) - fixed-viewport vanilla dashboard contract
- [FUNCTIONS.md](FUNCTIONS.md) - AWS Lambda event integration
- [SECURITY.md](SECURITY.md) - trust model and security invariants

## Headless administration

Use `trestle setup --email-file FILE --password-file FILE`, `trestle config show --json`, and the backup, restore, migrate and service commands for automation. Stop the service before `sudo trestle reset --auth` or `sudo trestle reset --all`; reset automatically uses the data directory recorded in a valid installed service unit. Use `--data-dir DIR` or `TRESTLE_DATA_DIR` for a development instance. Confirmation is the exact phrase `TRESTLE AUTH` or `TRESTLE ALL`. SQLite resets retain timestamped backups. PostgreSQL resets fail closed and require a database-native backup/reset workflow.
