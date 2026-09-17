# Trestle clustering contract

Trestle clustering uses the released Gantry Core replication runtime. The first clustered semantic surface is deliberately bounded to **collection definitions and records**. Authentication/session state, credentials, files, jobs, webhook/function execution, audit/events, propagation scheduling, launcher state, database setup state, and external side effects remain node-local or deferred until they have an explicit distributed contract.

## Authority

A node is either standalone or configured replicated. A replicated node never falls back to direct local writes when consensus is unavailable. Ready leaders propose semantic operations; ready followers forward the same caller operation identity to the leader and wait until the committed index is locally applied.

## Storage

The initial implementation is SQLite-only. PostgreSQL clustering is rejected at startup rather than pretending that a local PostgreSQL database is a Raft materialization. Raft log/stable state and snapshots live under `<data-dir>/replication/`.

## Identity and membership

Gantry pairing and Raft membership are distinct. Replication requires the `replication` capability, production mTLS, pairwise Gantry credentials, and explicit voter changes. Peer disable/revoke is enforced in both transport directions by Gantry Core v0.4.2.

## Checkpoints

1. Freeze the Trestle semantic/state boundary and Core reuse contract.
2. Upgrade to Gantry Core v0.4.2 and add production replication configuration.
3. Add the Trestle authenticator/runtime and explicit Raft operator surface.
4. Add deterministic collection-definition replication.
5. Add deterministic record create/update/delete replication and caller idempotency.
6. Add restart/snapshot/readiness/fail-closed integration certification.
7. Document Trestle clustering and update the Watchpost clustering docs to describe the shared Core runtime.

The implementation must preserve standalone behavior and existing durable formats outside the new replication metadata/state.
