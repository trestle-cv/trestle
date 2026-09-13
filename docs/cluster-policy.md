# Trestle cluster operation policy

Trestle clustering uses the shared Gantry identity, membership, pairing, targeting and bounded fan-out contracts. It does **not** make Trestle's application database distributed.

The initial cluster surface is intentionally read-oriented: cluster health/version reporting, schema/configuration comparison, job/webhook/function status aggregation, backup-state visibility and targeted administration. Each returned object keeps the node that owns it.

Records, files, sessions and raw database state remain node-local. A cluster member does not become an implicit replica and joining a cluster never copies collections or records.

Schema definitions and authorization policy are marked as candidates for controlled propagation only in the later propagation phase. They are not synchronized automatically in Phase 4.
