# Phase 08 — DeepSeek-V4 Capacity Accounting

## Status

**Planned**

## Depends on

- [Phase 07](phase-07-prefix-aware-scheduling.md) Qualified.
- Stable logical/reusable/uncached token accounting.
- Memory high-water and cache-lifetime evidence from V1 plus C1/C2.
- Exact V1 admission and V2 reuse ownership mapped in source.

## Objective

Replace coarse token-only capacity assumptions with a DS4-native two-currency
model: remaining compute work and resident/projected memory liability. Represent
DeepSeek-V4 state using its actual lifetimes and physical storage rates while
keeping one raw-token coordinate system for scheduling and prefix reasoning.

The model first observes, then predicts in shadow mode, and only then influences
hard admission after accuracy and safety are demonstrated.

## Hypothesis

A small source-derived state-lifetime model can predict per-request completion
and peak memory more accurately than logical context length alone, improving
admission utilization and explainability without unsafe overcommit or a generic
KV abstraction.

## Two currencies

Every request needs separate values:

```text
compute currency
  logical prompt tokens
  reusable prefix tokens
  uncached prefill tokens
  remaining prefill work
  promised remaining generation

memory currency
  currently resident bytes attributable to the request/lineage
  incremental bytes for remaining prefill
  incremental bytes for promised generation
  transient peak bytes
  shared/copied/restored bytes under existing semantics
  global reserve and safety watermark
```

The scheduler may compare compute work in raw-token coordinates. Allocation and
admission use physical bytes derived from actual per-state storage rules.

## Repositories

| Repository | Phase role |
|---|---|
| Engine fork | State inventory, projection API, shadow validation, watermarks, pool telemetry, optional enforced admission |
| Lab repository | Calibration scenarios, projected/observed comparison, S/C regression, submodule pin |
| Integration fork | No release change until Phase 09; candidate profile only if required |

## Entry criteria

- The exact engine release source and CUDA allocation/state structures are
  available for inspection.
- Peak-memory telemetry can be measured with acceptable perturbation and clear
  allocator semantics.
- The source audit can distinguish persistent, windowed, compressed,
  checkpoint/rollback, shared/copied, and transient state actually present in
  DS4. Do not proceed from framework terminology alone.
- Calibration scenarios cover representative context depths, concurrency,
  reuse, output budgets, and speculative settings.
- Accuracy/safety thresholds are declared before enforcement results are viewed.
- Independent review ownership includes C integer arithmetic, allocation
  lifetime, concurrency, and CUDA memory behavior.

## Scope

### 1. Inventory actual DS4 state

Build a table from frozen source and observed allocation behavior:

| State/pool | Owner | Lifetime | Raw-token relation | Physical element/byte rate | Alignment/granularity | Shared/copied semantics | Release event |
|---|---|---|---|---|---|---|---|

Inventory only state DS4 owns, which may include categories such as:

- persistent compressed attention/cache state;
- local/windowed state;
- raw or staging rows;
- per-bank sequence state;
- speculative rollback/checkpoint state;
- graph/static workspaces;
- prefill scratch and other transient peaks;
- persisted host/disk records where they affect resident planning;
- server/request buffers large enough to matter.

Names and formulas come from source. Do not force these into a generic K/V page
model or copy formulas from TensorRT-LLM without verifying DS4 layouts.

### 2. Common raw-token coordinate system

Represent request frontiers and prefix matches in logical raw-token coordinates.
Each pool translates raw-token ranges to physical entries according to its
actual compression/window/granularity rule.

Requirements:

- boundary and rounding behavior is explicit;
- layer- or state-specific ratios are supported where source requires them;
- windowed pools stop growing according to their true rule;
- shared/reused state is not charged as a new allocation unless copied;
- copy/fork costs reflect existing DS4 behavior, not future page sharing;
- integer operations are overflow-checked and use widths appropriate for the
  largest supported context and byte count.

### 3. Projection API

Expose a narrow internal query, conceptually returning:

```text
can_ever_fit
can_fit_now
resident_bytes
incremental_prefill_bytes
incremental_generation_bytes
projected_completion_bytes
projected_peak_bytes
headroom_after_peak
limiting_pool_or_reason
projection_confidence/version
```

The exact interface follows existing ownership. Avoid allocating or walking
large token arrays during a scheduler decision. Cache derived static model
coefficients and update request scalars at meaningful lifecycle boundaries.

`can_ever_fit` remains distinct from `can_fit_now`, preserving Phase 04's
impossible-versus-deferred contract.

### 4. Global and pool headroom

Do not plan to the theoretical final byte. Model:

- immutable weights and static graph/workspace demand;
- driver/runtime and allocator reserve;
- server/process overhead relevant to observed peaks;
- per-pool or global fragmentation/granularity margin;
- configured safety watermark;
- current protected/resident state;
- request projected peak.

Choose watermarks from calibration evidence and worst observed residuals, not a
convenient percentage. Record the selected value and sensitivity analysis.

If a pool-specific limit can fail before global free memory, expose that bounded
reason. Do not infer that global free memory guarantees a valid state layout.

### 5. Stage A — observational accounting

First expose current pool/state bytes and lifecycle high-water marks without
changing admission. Reconcile:

- formula-derived current resident bytes;
- engine allocator/accounting bytes;
- process/device-observed memory;
- known static/unattributed reserve.

Explain residual categories. An unexplained residual large enough to violate the
future watermark blocks enforcement.

### 6. Stage B — shadow projection

For every admission decision, compute the candidate projection but leave V1
behavior authoritative. Record fixed-cardinality projected decision/reason and
compare it with:

- actual admission result;
- observed peak during prefill/decode;
- final committed length;
- actual output versus promised output;
- OOM/allocation failure if any;
- capacity released at completion/cancellation.

Do not log per-request private content or unbounded request identifiers in
metrics. Detailed correlation remains in sanitized benchmark artifacts.

### 7. Stage C — bounded enforcement

Only after shadow accuracy passes its declared gate may the model influence
admission.

Enforcement rules:

- projection uncertainty fails safe; it does not permit overcommit;
- a hard stable over-limit result maps to `REJECT_IMPOSSIBLE`;
- current resident pressure with eventual feasibility maps to
  `DEFER_CAPACITY`;
- server queue/operator bounds remain `SHED_OVERLOAD`;
- output budget is included consistently;
- watermark changes advance the relevant capacity epoch;
- cancellation and release update accounting exactly once;
- a legacy/V1 capacity mode remains available for paired rollback during V2
  qualification.

Do not enforce one pool's formula while silently ignoring another material
lifetime.

### 8. Pool-pressure observability

Add only bounded observations justified by the inventory:

```text
current and high-water bytes by fixed pool class
projected completion/peak buckets or artifact fields
projection residual/error in controlled artifacts
admit/defer/impossible reason by limiting pool
watermark/headroom
allocation or reclaim failure by fixed reason
```

High-frequency pool telemetry is sampled at controlled phase boundaries. If
sampling changes performance, use target-local calibration runs rather than
leaving it enabled in headline benchmarks.

### 9. Calibration matrix

Use the smallest matrix that spans model behavior:

- short, medium, long, and project-maximum contexts;
- explicit small and larger output liabilities;
- omitted/default output budget;
- concurrency around current capacity transitions;
- cold, reused, forked/copied, and persisted/restore cases that exist;
- plain and DSpark/speculative modes where their state differs;
- cancellation during prefill and decode;
- near-watermark churn.

Reuse S1/S2/S5 and C1/C2 where possible. Add a dedicated calibration scenario
only when these do not isolate a pool/lifetime boundary.

### 10. Tests

Behavioral and arithmetic tests cover:

- zero, one, boundary, and maximum raw-token coordinates;
- compression/window rounding transitions;
- layer/state-specific rates;
- shared versus copied charge;
- promised output liability;
- overflow and invalid configuration;
- cancellation/release and capacity epoch;
- projection before/after reuse invalidation;
- stable impossible versus temporary pressure;
- watermark boundary and exact equality;
- observational/shadow mode has no semantic effect;
- legacy mode reproduces V1 behavior.

Use real model-derived coefficients/structures in integration tests where
possible; do not qualify enforcement using a mock model alone.

## Explicit non-goals

- No new page allocator or ref-counted shared state.
- No cache retention priority; Phase 09 owns it.
- No generic KV abstraction.
- No hard enforcement before shadow accuracy passes.
- No claim that process/device memory equals one exact request-owned sum.
- No removal of V1 overload/cancellation/fairness/graph policy.
- No host overlap or kernel work.
- No automatic watermark tuner in production.

## Deliverables

### Engine fork

- source-derived state/pool inventory;
- raw-token-to-physical accounting formulas;
- overflow-safe projection API;
- observational pool accounting;
- shadow decision mode and residual evidence;
- evidence-derived watermarks/headroom;
- enforced V2 admission only if the shadow gate passes;
- focused arithmetic/lifecycle/concurrency tests;
- V1 comparison/rollback mode.

### Lab repository

- calibration manifests and controlled telemetry collection;
- projection-versus-observed analysis;
- S1/S2/S5/C1/C2 paired candidate results;
- accuracy, safety, utilization, and performance report;
- engine submodule pin and staged decision record.

### Integration fork

- no release default yet; record candidate settings needed for Phase 09.

## Validation

### Reconciliation

At each calibration point, reconcile formula, engine-reported state, and
observed memory. Separate static/unattributed memory from request-dependent
residuals. Visual agreement is insufficient; retain raw values and calculate
signed/absolute error under the declared semantics.

### Shadow gate

Run enough repetitions across the matrix to bound underprediction. Any
underprediction beyond the predeclared safety margin or unexplained pool failure
blocks enforcement. Overprediction is safe but may reduce utilization; quantify
its opportunity cost.

### Enforcement gate

If shadow passes, compare V1 versus enforced candidate using:

- S5A/S5B for feasibility and output liability;
- S1/S2 for concurrency/utilization/goodput;
- C1/C2 for reuse/shared-copy accounting;
- S3/S6 for latency/fairness;
- S8 and churn for release correctness;
- target-local single and representative-depth controls;
- full relevant V1 correctness/API/tool/DSpark/graph gates.

### Review

DeepReview is required before shadow code is considered correct and again before
enforcement. Review formula provenance, integer/rounding safety, lifetime release,
shared/copied charging, concurrency, watermark reasoning, and mapping to Phase
04 outcomes. Resolve findings and rerun affected calibration and regression
runs.

## Acceptance gate

Phase 08 may qualify in two levels:

### Observational qualification

- state inventory and formulas are source-grounded;
- current accounting reconciles within declared residual categories;
- shadow mode has no semantic/performance regression beyond its gate;
- raw projection/error evidence is retained.

### Enforcement qualification

Additionally:

1. shadow underprediction remains inside the predeclared safety margin across
   the calibration matrix;
2. no unexplained allocation/OOM event contradicts a projected safe admission;
3. impossible, deferred, and overload mappings preserve Phase 04 semantics;
4. cancellation/release and epochs keep accounting exact under churn;
5. S1/S2/S5/C1/C2 demonstrate safe utilization or explainability improvement
   sufficient to justify enforcement;
6. S3/S6, graph, single-request, correctness, API/tool, and DSpark gates remain
   within V1/V2 thresholds;
7. watermark and rollback configuration are explicit and recorded;
8. no unresolved blocking review finding remains.

If observational accounting succeeds but enforcement accuracy does not, retain
the diagnostics and do not use the model for hard admission. That is a valid
research result, not permission to weaken the safety margin after seeing data.

## Artifacts

Retain:

- exact state/pool inventory with source references;
- formulas, coefficients, alignment/rounding rules, and overflow analysis;
- calibration raw telemetry;
- current/resident reconciliation;
- shadow projected-versus-observed datasets and error summaries;
- watermark selection and sensitivity analysis;
- enforced candidate S/C/V1 regression results if attempted;
- tests and review findings/resolutions;
- engine/lab commits and umbrella submodule pin;
- separate observational and enforcement decisions.

## Risks and rollback

| Risk | Mitigation / rollback |
|---|---|
| Formula copies another runtime instead of DS4 | Source-derived inventory and coefficients |
| Underprediction causes unsafe admission | Shadow-first gate, headroom, fail-safe uncertainty |
| Overprediction destroys concurrency | Quantify residual/opportunity; tune only from retained evidence |
| Raw-token conversion rounds incorrectly | Boundary tests and explicit per-pool granularity |
| Shared state is double/under charged | Existing ownership map and shared/copied semantics tests |
| Memory telemetry perturbs performance | Controlled calibration mode; disable expensive sampling in headline runs |
| Partial enforcement creates inconsistent outcomes | Enforce complete validated model or remain observational |

Rollback selects the immutable V1 capacity mode and restores the prior umbrella
pin. Observational metrics may remain only if they pass overhead and maintenance
value gates; failed enforcement code is removed rather than left half-active.

## Exit handoff to Phase 09

Phase 09 receives:

- validated state-lifetime inventory and raw-token coordinates;
- resident/projected memory and pool-pressure observations;
- safe enforced capacity model or an explicit observational-only decision;
- measured reuse value and recompute costs;
- concrete pressure signals that retention policy can consume without inventing
  a second capacity model.
