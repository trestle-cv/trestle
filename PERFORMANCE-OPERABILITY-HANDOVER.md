# Trestle performance + operability campaign handover

## Status and timing

This is a **future, separate campaign** to be executed **after the coordinated Gantry Go-project releases**. It is not part of the current release gate and must not delay or silently broaden that release campaign.

The clustering correctness work is already substantially certified. This campaign asks a different set of questions:

1. What performance/resource cost did clustering support add to ordinary standalone Trestle when replication is disabled?
2. What does consensus cost when clustering is enabled, and how does that cost scale with voter count and network latency?
3. How simple is Trestle to deploy, operate, upgrade, back up, restore, cluster, and recover compared with other self-hosted backends?
4. How does Trestle actually benchmark against PocketBase, Supabase, Appwrite and other relevant self-hosted alternatives on equivalent hardware and workloads?
5. Where does Trestle genuinely win, where does it lose, and what engineering changes are justified by the evidence?

Do not design the benchmark to make Trestle win. The goal is reproducible engineering evidence.

## Campaign principles

- Freeze exact source commits, dependency versions, VM types, OS images, database modes, durability settings, benchmark clients and workload definitions before comparing results.
- Prefer fresh, identical Linode VMs for comparative deployment and performance work.
- Separate **correctness**, **performance**, **resource cost**, and **operator effort**. A fast result that weakens durability or semantics is not comparable.
- Record raw results and enough metadata to reproduce them. Website graphs/tables are derived artifacts, not the source evidence.
- Run warmups, multiple measured repetitions, and report distributions rather than one lucky throughput number.
- Report p50/p95/p99 latency alongside throughput. Record errors and timeouts.
- Record CPU, RSS, disk usage/I/O where practical, network traffic, database size and relevant Raft/log/snapshot growth.
- Keep load generation off the system under test for serious measurements.
- Pin or record concurrency, connection reuse, payload sizes, indexes, dataset sizes and authentication mode.
- Preserve equivalent durability/safety settings across products where possible and document unavoidable differences.
- Distinguish SQLite Trestle from PostgreSQL Trestle; do not combine them into one result.
- Do not claim a competitor is slower/easier/harder from a non-equivalent setup.

## Campaign A — standalone clustering-overhead audit

First determine whether adding clustering machinery imposed measurable cost on users who never enable it.

### A1. Historical/current baselines

Identify a defensible pre-clustering Trestle commit/release and the post-clustering release. Build both reproducibly with comparable compiler settings.

Compare at minimum:

```text
pre-clustering Trestle
current Trestle, replication disabled
```

If practical, include an intermediate commit that isolates the introduction of Gantry Core replication composition.

### A2. Verify the disabled path

Review/profile where useful for accidental standalone hot-path work:

- replication readiness/authority work that should not occur;
- operation serialization/allocation;
- unnecessary locks/atomics;
- extra database queries or metadata writes;
- background Raft/transport goroutines/listeners;
- unnecessary TLS/peer initialization;
- increased idle memory/startup time.

Do not optimize speculatively before measuring.

### A3. Standalone workload matrix

Benchmark representative API operations:

- health/simple API baseline;
- create/get/update/delete record;
- list/pagination;
- indexed and representative multi-field filters;
- authenticated CRUD;
- mixed read/write workload;
- contention-heavy writes;
- small and larger JSON records;
- bulk operations where supported;
- realtime/event overhead separately if useful.

Use useful dataset tiers such as 10k, 100k and 1m records, adjusting only where actual constraints justify it.

### A4. Disabled-overhead conclusion

Measure deltas for throughput, p50/p95/p99, CPU, RSS, allocations where practical, idle resources, startup time, DB/I/O latency where practical, and binary size if material.

If overhead is material, profile it, fix justified regressions, add stable regression coverage where useful, and rerun the wall.

## Campaign B — clustering cost and scaling curve

### B1. Topology matrix

Benchmark at minimum:

```text
standalone / replication disabled
1 voter replicated
3 voters
5 voters
7 voters
```

Seven voters should remain only if it adds useful evidence rather than a larger graph.

### B2. Workload dimensions

Distinguish leader-originated writes, follower-forwarded writes, reads from leader/followers where semantics permit, mixed workloads, contention-heavy writes, payload sizes and bulk operations.

Quantify:

```text
standalone -> 1 voter
    cost of entering consensus machinery

1 -> 3
    cost of quorum replication

3 -> 5
    marginal replication cost

5 -> 7
    further scaling cost

leader -> follower
    forwarding/read-after-write penalty
```

### B3. Network topology

Keep separate results for same-host/local testing, same-region independent Linodes and geographically distributed Linodes. WAN write latency is expected to matter; measure it explicitly.

### B4. Cluster resource scaling

Record CPU, RSS, disk I/O, network traffic where practical, database size, `raft.db`, snapshots, goroutines/connections and write amplification where practical.

### B5. Failure-performance wall

Measure performance/availability impact under healthy quorum, follower loss, minimum writable majority, leader loss under load, election interruption, recovery and follower catch-up.

For five voters compare 5/5, 4/5 and 3/5. 2/5 remains a fail-closed correctness wall, not a throughput configuration.

## Campaign C — SQLite versus PostgreSQL Trestle

Compare equivalent standalone workloads for Trestle + SQLite and Trestle + PostgreSQL on equivalent hardware where practical. Measure setup complexity, idle resources and performance separately. Account for PostgreSQL's separate service rather than attributing all resource cost to Trestle.

Where the current clustering contract is SQLite-only, state that clearly instead of inventing a PostgreSQL clustering comparison.

## Campaign D — comparative self-hosted backend benchmark

Primary comparison set:

- Trestle;
- PocketBase;
- Supabase;
- Appwrite.

Before execution, review current versions and supported self-hosting procedures. Add another competitor only if it materially improves the comparison.

### D1. Fairness contract

Freeze version/commit, installation method, Linode plan/region/OS/storage, TLS arrangement, database backend, durability settings, indexes/schema, auth mode, payloads, dataset, benchmark client, concurrency, connection reuse, warmup, duration and repetitions.

PocketBase is likely the closest lightweight SQLite comparison. Supabase and Appwrite are broader stacks and should be presented with that architectural context.

### D2. Equivalent operations

Use a small common application schema and semantically equivalent create/get/update/delete, list, pagination, indexed filter, representative relationship/reference query where comparable, authenticated CRUD and concurrent mixed CRUD.

Mark non-equivalent operations non-comparable instead of forcing a misleading number.

### D3. Output

Report throughput, p50/p95/p99, error rate, CPU, RSS, disk footprint and network where useful across useful dataset sizes/concurrency levels.

## Campaign E — blank-Linode-to-working-backend operability benchmark

Raw speed is only half the product story.

### E1. Fresh-host setup stopwatch

From the same fresh supported Ubuntu image measure:

```text
blank Linode
-> install product/prerequisites
-> persistent storage
-> service configuration
-> HTTPS if in scope
-> admin/project initialization
-> schema/collection
-> usable auth/service identity
-> successful remote authenticated CRUD
```

Capture elapsed human time, commands, files edited, services/containers/processes, firewall/ports, secrets/certs, browser steps, ambiguous docs, failures/retries and idle CPU/RSS/disk.

### E2. Trestle modes

Dogfood repeatedly from scratch:

```text
standalone SQLite
standalone PostgreSQL
3-node clustered SQLite
5-node clustered SQLite
```

Treat avoidable ceremony as a product issue. The qualitative goal is that clustering feels like composing ordinary Trestle nodes plus explicit Gantry pairing/membership, not bespoke distributed-systems administration.

### E3. Cluster setup complexity

Measure provisioning, install, TLS/mTLS, Gantry pairing, Raft bootstrap/membership, verification, adding/removing/replacing voters and failed-node recovery. Record command count and operator decisions as well as elapsed time.

## Campaign F — lifecycle operability

Exercise restart, upgrade, backup, restore, configuration change, credential rotation, node/capacity changes where supported, failed-node replacement, standalone-to-HA path where supported, status/observability and uninstall/teardown.

For Trestle, verify the actual standalone-to-cluster contract. Do not invent merge/adoption semantics during this campaign; document limitations honestly.

## Campaign G — profiling and justified optimization

Only after reproducible baselines exist, profile material losses. Candidate areas include HTTP/router overhead, JSON, auth/rules, filter parsing/SQL generation, SQLite transactions, PostgreSQL round trips, allocations/copies, replication encoding, follower forwarding, `WaitApplied`, and Raft fsync/network behavior.

Do not optimize benchmark-only paths or weaken semantics. Every accepted optimization must rerun correctness gates and relevant benchmark walls.

## Reproducibility and evidence

Before execution, create a dedicated benchmark/evidence layout. The executing agent should propose it before production changes.

Retain campaign manifest, machine specs, versions, sanitized configs, schemas/workloads, benchmark scripts, raw outputs, summary CSV/JSON, analysis scripts, plots/tables and operator notes.

Every published number must be traceable to raw evidence. Use distributions/variance where useful and never cherry-pick the fastest run.

## Proposed public outputs

Only after independent review, consider publishing reproducible, dated/versioned results on `trestle.cv`:

- pre-clustering versus current clustering-OFF overhead;
- standalone/1/3/5/7-voter throughput and p50/p95/p99;
- leader versus follower-forwarded writes;
- failure/election/recovery performance;
- fresh Linode -> first authenticated CRUD for Trestle/PocketBase/Supabase/Appwrite;
- idle and loaded resource footprint with architectural context.

Avoid timeless claims such as “fastest” or “easiest.”

## Suggested execution phases

The future executing agent should turn this into checkpointed work before changing production code:

1. Freeze methodology and evidence format.
2. Establish pre-clustering/current standalone baselines.
3. Measure/profile clustering-disabled overhead.
4. Benchmark standalone SQLite across dataset/concurrency tiers.
5. Benchmark standalone PostgreSQL.
6. Benchmark 1/3/5/7-voter clustering cost.
7. Benchmark follower forwarding and same-region/WAN effects.
8. Benchmark failure/election/catch-up performance.
9. Dogfood Trestle fresh-host setup and lifecycle operations.
10. Freeze competitor methodology and versions.
11. Run PocketBase comparison.
12. Run Supabase comparison.
13. Run Appwrite comparison.
14. Analyze gaps and profile material Trestle losses.
15. Implement only justified improvements, checkpoint by checkpoint.
16. Rerun affected benchmark/correctness walls.
17. Independent methodology/result review.
18. Update docs/site with reproducible qualified results if worth publishing.

Re-evaluate ordering after each major phase. Do not start competitor benchmarking before Trestle's own methodology is stable.

## Correctness gates remain mandatory

Performance work must not regress established clustering correctness. After production changes run appropriate full gates, including:

```sh
gofmt -w <changed Go files>
go test ./...
go test -race ./...
go vet ./...
go build ./cmd/trestle
```

Preserve `GOWORK=off` / released-`gantry-core` certification and rerun relevant 3-node/5-node clustering walls when replication behavior changes.

Never weaken durability, authorization, quorum, idempotency, fail-closed behavior, snapshot/recovery, peer security or semantic-conflict handling for benchmark performance.

## Questions this campaign must answer

At completion we should be able to answer quantitatively:

1. What overhead, if any, does clustering support impose when clustering is disabled?
2. What are the latency/throughput/resource costs of 1, 3, 5 and 7 voters?
3. What is the follower-forwarding penalty?
4. How strongly does same-region versus WAN latency affect writes?
5. What happens to latency/availability during leader loss and reduced-but-valid quorum under load?
6. How do SQLite and PostgreSQL Trestle compare?
7. How do Trestle, PocketBase, Supabase and Appwrite compare on equivalent operations?
8. How do they compare in idle footprint and operational complexity?
9. How long does each take from a blank Linode to first authenticated CRUD?
10. How difficult are backup, restore, upgrade and failure recovery?
11. Which Trestle losses are architectural tradeoffs and which justify engineering work?
12. Which Trestle advantages are large and reproducible enough to document publicly?

## Stop boundary

This file is a handover for a **post-release** campaign only.

Until the coordinated Gantry releases are complete:

```text
DO NOT start performance optimization
DO NOT provision benchmark Linodes for this campaign
DO NOT modify Trestle to chase benchmark results
DO NOT publish comparative benchmark claims
```

When the campaign begins, first convert this handover into a concrete checkpoint plan, freeze methodology, and review that plan before executing expensive infrastructure work.
