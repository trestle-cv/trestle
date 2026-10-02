# Trestle clustering contract

Trestle clustering uses the released Gantry Core replication runtime. The consensus surface is: **collection definitions, records, durable events, audit facts, job obligations (including their lifecycle state), and webhook/function automation definitions**. Authentication/session state, credentials, files, propagation scheduling, launcher state, database setup state, and external side effects remain node-local or deferred until they have an explicit distributed contract.

## Authority

A node is either standalone or configured replicated. A replicated node never falls back to direct local writes when consensus is unavailable. Ready leaders propose semantic operations; ready followers forward the same caller operation identity to the leader and wait until the committed index is locally applied.

## Durable consequences are consensus-owned

One committed logical record mutation materializes, atomically inside the FSM transaction, the same durable consequences it would produce standalone:

- the record state transition;
- an event row (`record.created` / `record.updated` / `record.deleted`);
- an audit fact for create and update (delete emits an event but no audit, matching the standalone handler);
- matched webhook and Lambda job obligations, derived deterministically against the replicated automation definitions.

Consequence identities are deterministic and convergent on every replica:

- event: `op:<opID>:event` (single) / `op:<opID>:event:<ordinal>` (batch);
- audit: `op:<opID>:audit` / `op:<opID>:audit:<ordinal>`;
- job idempotency: `op:<opID>:job:<targetID>` / `op:<opID>:job:<ordinal>:<targetID>`.

The exposed event `sequence` and audit `id` are assigned explicitly by the FSM (`MAX+1` in apply order), so the numeric cursor is portable across nodes: an SSE `Last-Event-ID` or list `after` cursor obtained from one node continues correctly on another. Caller `Idempotency-Key` creates replay without duplicating any consequence.

A batch create is one raft operation that preserves standalone all-or-nothing semantics; a prefix of a failed batch is never committed.

## Job lifecycle is raft-mediated

`_trestle_jobs` is fully consensus-owned. After the FSM enqueues a pending obligation, every lifecycle transition (claim, complete/backoff/dead-letter, stale release, cancel, manual retry) is a raft operation proposed by the leader-owned worker and applied deterministically by the FSM. **External execution** (the webhook HTTP POST and the Lambda invoke) happens outside raft and remains asynchronous. Leases and retry backoff are derived from the operation's committed metadata timestamp, so replicas agree on when a lease expires and a retry becomes available. Only the raft leader runs the job worker; a stale leader's proposals fail closed. External delivery is at-least-once: after failover a new leader reclaims expired leases and may redeliver, but the durable obligation is never lost.

## Automation definitions are replicated; secrets stay out of raft

Webhook and function definitions are consensus-owned (`trestle.webhook.put/delete`, `trestle.function.put/delete`), so automation matching is deterministic and identical on every replica regardless of which node received the request.

- The webhook signing secret is stored only as AES-GCM ciphertext. The canonical ciphertext is produced once before proposal and applied verbatim; the FSM never encrypts, and **plaintext secrets never enter raft payloads, logs, or snapshots**.
- Decryption requires a **cluster-uniform `webhook.key`** (same 32-byte file on every node, provisioned out of band, mode 0600). **Compatibility is enforced at admission, not just surfaced:** every node advertises a non-secret SHA-256 fingerprint of its key in the authenticated replication handshake, and a peer advertising a different (or no) fingerprint is refused the connection, so a node with an incompatible key can never catch up, become ready, or execute replicated webhook work after failover. The join endpoint additionally requires the candidate's fingerprint and refuses `AddVoter` on mismatch. The bootstrap node's fingerprint is canonical; joining nodes must match it; an existing member restarting with a changed key cannot re-form replication with mismatched peers. Only fingerprints are exchanged; the raw key never leaves a node, enters raft, or appears in diagnostics. Rotation is a documented later enhancement.
- AWS credentials are never replicated; they remain process-local. **Lambda delivery availability is not automatically leadership-aware.** If the current leader lacks AWS credentials, Lambda obligations remain durable and `pending` (never consuming retry attempts) until credentials are configured on that leader or leadership is transferred to a credentials-capable voter. The status endpoint reports `lambdaConfigured`, and operators can transfer leadership (`POST /admin/v1/replication/transfer`, admin-authenticated, CSRF-protected, leader-aware) to a capable node.

## Join and bootstrap

A node joining a replicated cluster for the first time must begin with **empty consensus-owned application state** (collections, records, events, audit, jobs, webhook and function definitions), or be explicitly reseeded from canonical cluster state. Raft may catch a new voter up by replaying retained log entries without installing a snapshot; replaying on top of arbitrary pre-existing local rows would not produce canonical cluster state. `NewReplication` refuses to start a non-bootstrapping node that has consensus-owned rows but no raft history. An existing member restart retains its own canonical DB and raft state. A bootstrapping node (the first voter) retains its history, which becomes canonical. Node-local surfaces (auth/session, credentials, files, launcher) are never destroyed.

## Storage and snapshots

The initial implementation is SQLite-only. Raft log/stable state and snapshots live under `<data-dir>/replication/`. Snapshots carry the **full consensus surface** (collections, records, events, audit, jobs including lifecycle state, webhook/function definitions) with explicit identities, so a restored/joining node reconstructs identical state and stays cursor-aligned. No retention subset is applied; event/audit/job history retention is a future, separately reviewed feature.

## Failover and delivery guarantees

- Leader crash before commit: nothing committed, nothing owed.
- Leader crash after commit: event/audit/job obligations are inside the commit; a new leader has them.
- Leader crash mid-execution: the new leader reclaims the expired lease and may redeliver (at-least-once); durable state converges.
- Webhook/Lambda delivery is at-least-once with retries, backoff and dead-letter; durable job uniqueness is distinct from network delivery semantics.

## Identity and membership

Gantry pairing and Raft membership are distinct. Replication requires the `replication` capability, production mTLS, pairwise Gantry credentials, and explicit voter changes. The canonical raft ServerID is the Gantry/Trestle `tr_...` cluster node ID; mismatched explicit configuration should fail fast with a useful diagnostic, and `trestle replicate join <node-id> <raft-address>` treats the node-id as the peer's Gantry cluster identity.

## Checkpoints

1. Freeze the Trestle semantic/state boundary and Core reuse contract.
2. Upgrade to Gantry Core v0.4.2+ and add production replication configuration.
3. Add the Trestle authenticator/runtime and explicit Raft operator surface.
4. Add deterministic collection-definition replication.
5. Add deterministic record create/update/delete replication and caller idempotency.
6. Add atomic replicated durable consequences (event/audit/jobs) and raft-mediated job lifecycle.
7. Add restart/snapshot/readiness/fail-closed integration certification.
8. Document Trestle clustering and update the Watchpost clustering docs to describe the shared Core runtime.

The implementation must preserve standalone behavior and existing durable formats outside the new replication metadata/state.