# Phase 09 — Retention, Affinity, and V2 Release

## Status

**Planned**

## Depends on

- [Phase 08](phase-08-v4-capacity-accounting.md) Qualified for enforced capacity.
- [Phase 07](phase-07-prefix-aware-scheduling.md) reuse metadata and C1/C2
  behavior remain valid.
- V1 safety, fairness, graph, cancellation, and release invariants remain green.

If Phase 08 qualifies only observational accounting, V2 release is blocked. An
explicit project-scope decision would be required to redefine V2; Phase 09 must
not silently ship coarse hard admission under a definition that promises a
validated compute-plus-memory model.

## Objective

Use measured reuse value, recomputation cost, state lifetime, and memory pressure
to retain useful agent conversation state without indefinite pinning, starvation,
corruption, or unsafe memory pressure. Then qualify and package V2 across all
three repositories.

## Hypothesis

A small DS4-native retention policy with bounded classes, aging, and existing
disk-tier integration can reduce future recomputation and resumed-conversation
latency under pressure, while the V1 age bound and Phase 08 capacity model keep
memory use safe and cold work progressing.

## Repositories

| Repository | Phase role |
|---|---|
| Engine fork | Retention score/class, aging, pressure-aware eviction, affinity convergence, tests and V2 release ref |
| Lab repository | C3/C4 and targeted C5/soak, full V2 qualification, release report/tag, submodule pair |
| Integration fork | Pin and validate immutable V2 engine release and launch defaults |

## Entry criteria

- Phase 08 enforced capacity accurately reports relevant pool pressure and
  resident/projected bytes.
- Phase 07 measures logical/reusable/physical work and validates cache lineage.
- Existing live, warm, persisted, continuation-protected, and eviction
  lifecycles are mapped in exact source.
- Current LRU/depth-tier behavior has a retained C3/C4 baseline.
- Retention inputs can be represented without prompt content or unbounded user
  identifiers.
- Independent review is assigned for memory lifetime, eviction, persistence,
  and continuation correctness.

## Policy principles

1. Safety and active continuation protection are not retention preferences;
   they remain higher-order lifecycle constraints.
2. Retention value is the expected avoided future cost, not logical prompt
   length alone.
3. Priority decays with inactivity unless an existing bounded protection rule
   applies.
4. No ordinary conversation stays resident forever.
5. Under hard pressure, the Phase 08 capacity/watermark model remains
   authoritative.
6. A retained item is still revalidated by generation/frontier before reuse.
7. Cold requests keep the V1 starvation bound.
8. Disk is a lower tier, not proof that resident memory can remain overcommitted.

## Scope

### 1. Map current lifecycle and eviction behavior

Record exact source ownership for:

- active bank/request state;
- warm retired bank records;
- partial/full match and fork behavior;
- continuation grace and hard pin semantics;
- current LRU/depth or pin-tier choice;
- checkpoint/persist triggers and pacing;
- disk index, restore, expiry, and eviction;
- generation/frontier invalidation;
- cancellation and shutdown persistence;
- Phase 08 pool pressure and reclaim signals.

Do not layer a second cache index or lifecycle owner over an existing one.

### 2. Bounded retention classes

Start with a small ordered set whose exact names follow source conventions:

```text
protected-active       existing safety/continuation rule, not policy score
active-conversation    recently used and likely to resume
high-recompute-value   expensive reusable prefix with demonstrated reuse value
opportunistic          ordinary warm state
expired/evictable      no current retained value after aging
```

Classes are internal fixed enums. They are not user-settable priorities in V2.
Do not expose arbitrary pin APIs.

### 3. Retention score

Within non-protected candidates, use only measured/available factors:

- physical prefill work or wall time avoided by reuse;
- reusable committed token frontier;
- recent validated hit/resume frequency;
- time since last validated use;
- current/predicted pool pressure;
- copy/restore/persist cost;
- state size;
- affinity to a currently active bounded conversation if Phase 07 justified it.

Prefer an understandable lexicographic/class policy over a fragile floating
formula. If a score is used, define units, saturation, tie-breaking, and tests.
Never multiply unbounded user-controlled values into overflow-prone priority.

### 4. Aging and bounded lifetime

Every preference decays or expires according to explicit monotonic-time rules.
Aging must:

- be cheap and lazy where possible;
- avoid scanning all records on every scheduler epoch;
- remove stale affinity mappings;
- preserve existing bounded continuation grace/pin behavior;
- handle clock/process restart semantics honestly;
- not demote currently owned active state;
- expose fixed-cardinality reason counts.

Select defaults from C2/C3/C4 evidence. Do not ship an automatic policy tuner.

### 5. Pressure-aware eviction

When capacity needs reclaim:

1. exclude state protected by active ownership/continuation invariants;
2. consider candidates using class/value/age;
3. account for actual reclaimable bytes and pool limitation;
4. prefer the lowest future recompute cost per useful reclaimed resource;
5. persist/demote only when the existing disk tier and time budget make that
   worthwhile;
6. advance capacity generation exactly when reclaim changes feasibility;
7. invalidate scheduler/affinity metadata with the state lineage.

Avoid evicting many small valuable records when one low-value record solves the
limiting pool unless measurements justify otherwise. Equally, avoid an
unbounded optimization search; use a bounded, explainable candidate scan.

### 6. Existing disk tier

Treat DS4's persisted state as a lower tier:

- retain current file format and integrity validation unless a specific defect
  requires a separately reviewed change;
- use explicit persist reasons and pacing;
- distinguish resident hit, disk restore, and cold recompute;
- do not block the GPU-critical scheduler path on avoidable synchronous disk
  work without measuring it;
- bound disk entries/bytes/age under existing configuration;
- never include persisted cache content in benchmark artifacts;
- handle corrupt/incompatible records as safe misses with observable bounded
  reasons.

A disk copy does not justify keeping invalid resident metadata alive.

### 7. Affinity convergence

If Phase 07 introduced conversation affinity, integrate it with retention rather
than retaining a parallel policy:

- affinity points only to a valid generation/frontier;
- eviction/demotion/expiry invalidates or downgrades it;
- it influences preference but cannot override capacity or starvation;
- inactive mappings expire;
- continuation-authoritative state remains distinct from advisory affinity.

If affinity failed its Phase 07 gate, do not reintroduce it here without new
entry evidence.

### 8. C3 suspend/resume

Scenario:

1. build a deep conversation A;
2. introduce pressure from other conversations/one-shot work;
3. suspend A long enough to exercise aging/retention;
4. resume A;
5. classify the path as resident, warm, persisted restore, or cold;
6. measure TTFT, physical work, restore/copy cost, memory, and workflow time.

Compare V1/V2 pre-retention policy and candidate under the same pressure and
cache reset.

### 9. C4 retention pressure

Keep one or more valuable recurring conversations while generating many
low-value one-shot requests. Verify:

- valuable state is retained more often only while its measured value warrants
  it;
- one-shot/cold requests still progress under V1 fairness bounds;
- memory remains under Phase 08 watermarks;
- recomputation and workflow time improve;
- aged valuable state eventually becomes evictable.

### 10. Targeted C5 and soak

Run C5 if any retention, eviction, persistence, or affinity path touches
interrupted-prefill state. Always run a focused V2 soak covering:

- repeated conversation churn;
- cancellation during prefill/decode;
- evict/persist/restore cycles;
- stale/corrupt persisted record handling;
- capacity pressure near watermarks;
- server restart and clean shutdown;
- bounded disk growth;
- request/accounting/cache leak detection.

### 11. Observability

Use fixed classes/reasons:

```text
resident entries/bytes by fixed class
retain/demote/evict/persist/restore count by fixed reason
reclaimed bytes by fixed pool/reason
retention age/value buckets only if needed
recompute tokens/time avoided
affinity hit/stale/expired if present
disk hit/miss/corrupt/incompatible
```

Detailed per-conversation analysis stays in sanitized scenario artifacts using
synthetic IDs, not metric labels.

### 12. V2 configuration convergence

Retain only settings that represent supported policy:

- enabled policy version or V1 rollback mode;
- selected bounded aging/retention defaults;
- selected watermarks from Phase 08;
- existing disk limits/pacing with any validated adjustment.

Remove rejected score variants, aliases, and experiment-only switches. Document
which settings are operator policy versus model-derived constants.

### 13. V2 release packaging

After engine qualification:

1. create an immutable project-namespaced engine V2 tag, for example
   `spark-v2.0.0`;
2. update the integration fork to the exact V2 engine tag/commit and validated
   defaults;
3. run clean install/build/launch/smoke and selected cache workflow checks;
4. update umbrella submodule pins;
5. create the lab `release-v2` tag with the complete report and manifests.

Do not move V1 or upstream tags. Preserve a documented immutable V1 rollback.

## Explicit non-goals

- No paged/ref-counted shared-prefix allocator.
- No copy-on-write tail implementation.
- No host/scheduler overlap.
- No generic user priority or pin API.
- No new cache file format without an independently justified defect.
- No distributed cache or multi-node coherence.
- No automatic retention or watermark tuner.
- No upstream/toolchain/model update during release comparison.

## Deliverables

### Engine fork

- bounded retention classes and source-grounded value/aging policy;
- pressure-aware eviction integrated with Phase 08 accounting;
- safe existing disk-tier policy and invalidation;
- converged affinity behavior if previously justified;
- lifecycle/corruption/churn tests;
- cleaned V2 configuration surface;
- immutable V2 engine release tag and rollback ref.

### Lab repository

- C3 and C4 scenarios;
- targeted C5 and V2 soak;
- V1/V2 cache, memory, fairness, and workflow comparisons;
- complete V2 release report and raw qualification bundle;
- final engine/integration submodule pins;
- umbrella `release-v2` tag and roadmap status.

### Integration fork

- immutable V2 engine ref/defaults;
- public generic examples;
- clean install/build/launch/smoke evidence;
- release commit pinned by umbrella.

## Validation

### Retention correctness

Exercise:

- class assignment and deterministic tie-breaking;
- aging boundaries and monotonic time;
- active/protected state exclusion;
- eviction under each limiting pool;
- exact capacity generation/release accounting;
- affinity invalidation;
- disk persist/restore/corrupt/incompatible paths;
- cancellation and interrupted work;
- restart/shutdown and bounded disk growth;
- cold request under sustained valuable-cache traffic.

### Performance and workflow

Compare immutable V1, Phase 07/08 base, and retention candidate using:

- C3/C4 primary retention gates;
- C1/C2 prefix/fan-out/multi-turn regression;
- S1/S2/S3/S5/S6/S8 V1 safety/performance/fairness regression;
- target-local memory and representative-depth controls;
- full relevant correctness/API/tool/long-context/DSpark/graph gates.

Report incremental retention value separately from prior V2 prefix/capacity
wins.

### Release reproduction

From a fresh public clone and clean target work directory, reproduce exact
submodule refs, environment, target-native build, integration smoke, benchmark
smoke, and the documented compact V2 qualification subset.

### Review

DeepReview covers lifetime ownership, active/protected precedence, score/aging
arithmetic, eviction choice, capacity generation, persistence integrity,
affinity invalidation, and rollback. Focused security review covers persisted
state handling, path/config validation, LAN guidance, installer inputs, and
artifact redaction.

## V2 acceptance gate

V2 is released only when:

1. prefix scheduling uses validated reusable/uncached work and retains V1
   starvation bounds;
2. enforced compute-plus-memory admission passes Phase 08 safety/accuracy gates;
3. state-lifetime accounting and observed high-water behavior remain reconciled;
4. C1/C2 retain useful prefix/multi-turn gains;
5. C3/C4 show a material reduction in recomputation or resume/workflow time
   under the predeclared threshold;
6. retention/affinity does not starve cold requests or retain ordinary state
   indefinitely;
7. eviction/persist/restore/cancellation/restart soak shows no corruption,
   unbounded growth, OOM, crash, deadlock, or accounting leak;
8. all V1 correctness, API/tool, long-context, DSpark, graph, overload,
   cancellation, fairness, and single-request gates remain green;
9. configuration is converged and V1 rollback is documented/tested;
10. integration install/build/launch/smoke passes against the immutable V2 ref;
11. retained artifacts contain no prompt/cache content or private target data;
12. required reviews have no unresolved blocking findings;
13. the umbrella V2 tag pins the exact engine/integration pair and report.

## Artifacts

Retain:

- exact lifecycle/eviction ownership map;
- retention class/value/aging specification;
- C3/C4 raw results and cache-state manifests;
- C1/C2 and full V1 regression results;
- targeted C5 and soak logs/summaries;
- pool pressure, reclaim, persist/restore, and recompute evidence;
- configuration convergence and rollback record;
- review findings/resolutions;
- engine V2 tag, integration commit, lab tag, and exact SHAs;
- V2 release report.

Do not retain persisted cache payloads or private target paths in the lab
artifacts.

## Risks and rollback

| Risk | Mitigation / rollback |
|---|---|
| Valuable score pins memory indefinitely | Explicit aging/expiry and Phase 08 hard watermarks |
| Retention starves cold requests | V1 starvation precedence and C4 cold control |
| Eviction frees the wrong pool | Pool-aware reclaim bytes/reason from Phase 08 |
| Persistence blocks scheduler/GPU work | Pace and measure existing disk tier; avoid hot-path sync I/O |
| Affinity outlives state lineage | Generation/frontier validation and invalidation hooks |
| Disk state leaks into artifacts | Never collect payloads; sanitize paths and logs |
| V2 bundles unrelated wins | Incremental Phase 07/08/09 comparisons |

Rollback selects the immutable V1 engine/integration pair and prior lab tag.
Published tags never move. Failed retention alternatives are removed rather
than hidden behind unused flags.

## Exit handoff to research

Research receives:

- immutable V1 and V2 comparison refs;
- validated state-lifetime and capacity models;
- prefix, retention, copy/restore, and physical-memory measurements;
- soak-tested lifecycle/invalidation behavior;
- evidence identifying whether physical state duplication, graph shapes, or
  host bubbles now dominate.
