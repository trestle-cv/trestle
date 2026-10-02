# Clustering implementation review notes

Implemented checkpoints in this workspace:

- replication contract and state classification;
- Gantry Core v0.4.2 dependency and production configuration;
- Trestle pairwise replication authenticator using existing cluster identity/member/nonce state;
- Gantry Core durable runtime composition (bbolt log/stable store, file snapshot store, production timing, readiness driver, mTLS/plaintext gate);
- explicit status/join and authenticated leader-proposal HTTP surfaces;
- deterministic collection-definition and record operation kinds;
- collection create/update/delete routing through replicated authority;
- record create/update/delete routing through replicated authority;
- follower forwarding with caller request identity and wait-for-local-apply;
- fail-closed SQLite-only clustering boundary.

## Deliberately excluded from the first semantic surface

Application/admin auth state, sessions, credentials, files, propagation scheduling, launcher state, database setup state and PostgreSQL materialization are not consensus state. Events/audit, job obligations (including lifecycle state) and webhook/function definitions ARE consensus state under the durable-consequences contract; see `docs/clustering/contract.md`. Webhook/function external execution is node-local (leader-owned), with secrets kept out of raft.

## Independent review priorities

DeepSeek should particularly inspect deterministic snapshot/restore completeness, record upsert version/precondition semantics, collection destructive-schema acknowledgement ordering, HTTP idempotency propagation, event/audit/job consequence convergence and raft-mediated job lifecycle for replicated record mutations, join/bootstrap clean-state enforcement, deterministic consequence identities, runtime shutdown ordering, operator endpoint authorization/CSRF behavior, and compatibility with Gantry Core v0.4.2.

The execution environment used for this implementation only has Go 1.23.2 while the workspace requires Go 1.25.0, and outbound toolchain download is blocked. `gofmt` and `git diff --check` were run, but the Go test/race/vet gates must be run by the independent reviewer on a Go 1.25-capable host before this candidate is accepted or dogfooded.
