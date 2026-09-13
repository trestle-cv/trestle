# Trestle cluster operation policy

Trestle clustering uses the shared Gantry identity, membership, pairing, targeting and bounded fan-out contracts. It does **not** make Trestle's application database distributed.

The initial cluster surface is intentionally read-oriented: cluster health/version reporting, schema/configuration comparison, job/webhook/function status aggregation, backup-state visibility and targeted administration. Each returned object keeps the node that owns it.

Records, files, sessions and raw database state remain node-local. A cluster member does not become an implicit replica and joining a cluster never copies collections or records.

Schema definitions and authorization policy are marked as candidates for controlled propagation only in the later propagation phase. They are not synchronized automatically in Phase 4.

## Phase 4 parity

Trestle uses the Gantry cluster lifecycle: `init`, `invite`, `join`, explicit `approve`/`reject`, one-time collection, `members`, `status`, credential `rotate`, `revoke`, and `remove`. Pairing and signed peer RPC use `/api/cluster/v1/`; authenticated management remains under `/admin/v1/cluster/`. The `/manage/` Cluster tab exposes the same pairing, membership, health, credential and audit concepts as the other clustered Gantry products.

Compatible product versions may coexist while the cluster protocol version remains compatible. Incompatible protocol versions fail closed. Removing all members returns the installation to valid standalone operation. None of these operations replicate Trestle records, files, sessions, or SQL state.
