# Trestle v{{VERSION}} - {{RELEASE_KIND}}

Trestle v{{VERSION}} {{RELEASE_KIND_BODY}}

## What this release is

- One self-hosted Go executable with an embedded administration dashboard, a
  versioned HTTP/OpenAPI boundary, and SQLite or PostgreSQL storage.
- Typed collections, application authentication, access rules, files, realtime
  SSE, audit, durable jobs, signed webhooks, AWS Lambda delivery, backups and
  offline restore.
- SQLite replicated clustering with deterministic record, event, audit and job
  consensus.
- Checksum-verified release archives for Linux, macOS and Windows on amd64 and
  arm64, plus `SHA256SUMS`.

## Supported database options

- **SQLite** is the embedded default. One Trestle process owns one local SQLite
  database; SQLite on a shared/network filesystem is not supported.
- **PostgreSQL 16, 17 or 18** is the externally operated option, on a
  single-process ownership model. PostgreSQL and SQLite share the same typed
  collections, transactions, rules, queries and API contracts; offline
  cross-provider migration is supported. Managed/serverless PostgreSQL
  topologies beyond the tested single-process model are outside the contract.

## Operator responsibilities

- Trestle binds loopback by default. TLS termination, trusted-proxy
  configuration (so forwarded scheme and client identity come only from
  configured CIDRs), firewalling, owner-only configuration/data permissions,
  provider-managed S3 recovery and host patching are operator responsibilities.
- **Back up before upgrading.** The updater replaces only the executable,
  verifies the archive against `SHA256SUMS` before writing, retains the previous
  binary for rollback (`update.sh --rollback`), and never modifies instance data
  or configuration. Schema upgrades are one-way: there is no automatic database
  downgrade during executable rollback.

## Clustering correctness

Trestle v{{VERSION}} establishes a replicated mutation-consequence contract for
SQLite clustering. A replicated record mutation now produces the same durable
consequences as the equivalent standalone mutation, atomically in the consensus
transaction:

- **Replicated events, audit and job obligations.** Record create/update/delete
  replicates its event, audit fact and matched automation job obligations with
  convergent, deterministic identities. Event/audit cursors are portable across
  nodes.
- **Replicated automation definitions.** Webhook and function definitions are
  consensus state; automation matching is deterministic and identical on every
  node regardless of which node received the request.
- **Raft-mediated job lifecycle.** Claim, completion, retry, cancel and stale
  release are consensus operations; external webhook and Lambda delivery stays
  asynchronous and at-least-once.
- **Atomic replicated batch creation.** A batch create commits as one atomic
  operation.
- **Full-surface snapshots.** Snapshots and restore cover records, events,
  audit, jobs and automation definitions.

Operator requirements for clustering:

- Every voter must use a **uniform `webhook.key`**, verified by a non-secret
  SHA-256 fingerprint at the replication handshake and at voter admission;
  provisioning is out of band and a mismatched node is refused.
- A **first-time voter must start from empty consensus-owned state**; an
  existing member restart retains its own state.
- **Lambda delivery is not automatically leadership-aware**: a leader without
  AWS credentials leaves Lambda obligations durable and pending until
  credentials are configured or leadership is transferred to a capable voter.
- Existing clustered deployments: mutations committed before this release
  replicated record state without durable consequences and are **not
  backfilled**; verify voter webhook keys match. Mixed-version clusters are not
  supported across this release.

## Known limitations

- No automatic database downgrade during executable rollback.
- Multiple Trestle processes sharing one database are not supported.
- No GraphQL, plugin marketplace, managed cloud, official container image,
  outbound verification email or self-service password recovery in this
  release.
- Clustering is SQLite-replicated only; PostgreSQL clustering is not supported.
- Webhook-key rotation, event/audit/job history retention, and automatic
  Lambda-capable leader election remain future work.
- Only the newest release line receives security fixes.

## Verified installation

Install on this user account (`~/.local/bin`), download into the current
directory (only `./trestle`), or update an existing install - all three verify
the archive checksum and never execute the downloaded binary:

```sh
curl -fsSL https://trestle.cv/install.sh | sh
curl -fsSL https://trestle.cv/download.sh | sh
./trestle
curl -fsSL https://trestle.cv/update.sh | sh
```

Pin any release with `--version vX.Y.Z`; download also supports `--output` and
`--force`.

## Changelog

Automatically generated notes follow.