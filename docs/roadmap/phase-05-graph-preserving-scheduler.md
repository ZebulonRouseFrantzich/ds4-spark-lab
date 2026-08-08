# Phase 05 — Graph-Preserving Execution Scheduler

## Status

**Planned**

## Depends on

- [Phase 04](phase-04-deferred-capacity.md) Qualified.
- Explicit admission/waiting lifecycle and reliable S5/S8 behavior.
- Existing decode graph eligibility/replay/fallback evidence available.
- S3 demonstrates the baseline long-prefill/active-decode interference to solve.

## Objective

Change which pending prefill request receives service and how much bounded eager
prefill work runs before the next decode opportunity, while preserving DS4's
existing graph-aware decode/speculative dispatcher and specialized C/CUDA
substrate.

V1 borrows decode-protection and bounded-partial-prefill policy ideas from vLLM.
It does not copy vLLM's arbitrary mixed physical batch construction.

## Hypothesis

Servicing at most one partial prefill with a small allowed quantum between
normal decode opportunities will reduce active-decoder latency disruption and
maintain long-prefill progress without materially reducing graph replay,
aggregate goodput, correctness, or single-request performance.

## Architectural boundary

```text
dynamic scheduler policy
       |
       +-- select one waiting/prefilling request
       +-- choose one bounded eager prefill quantum
       |
       +-- preserve normal decode/spec pack
                       |
                       v
             existing graph-aware dispatcher
             with observable eager fallback
```

The first implementation must not require arbitrary prefill and decode work to
coexist inside a new CUDA graph. Do not alter kernels or graph capture merely to
implement policy.

## Service model

Initial scheduler epoch:

```text
1. process completions and cancellations
2. process capacity changes and eligible admissions
3. identify live decode/spec work
4. select at most one pending/prefilling request
5. if decode-latency policy allows, run one bounded eager prefill quantum
6. run the normal live decode/spec pack through the existing dispatcher
7. update accounting and repeat
```

The exact loop order is reconciled with frozen source ownership before editing.
The invariant is observable decode opportunity between bounded prefill service,
not a source-shape prescription.

## Repositories

| Repository | Phase role |
|---|---|
| Engine fork | Scheduler selection/service policy, bounded quantum, graph-path accounting, tests |
| Lab repository | Candidate profiles, quantum experiments, paired S1/S3/S5 results, submodule pin |
| Integration fork | No release default yet; capture candidate launch needs for Phase 06 |

## Entry criteria

- Phase 04 candidate is the known-good engine base.
- S3 has stable phase markers and active-decoder ITL/progress measurements.
- Existing prefill chunk/width controls and decode graph dispatcher symbols are
  mapped in the exact source.
- Phase 02/03 graph denominators and fallback reasons are usable.
- One candidate/legacy scheduler switch has an unambiguous name; avoid names
  that confuse implementation iteration with release V1/V2.
- Independent review is assigned because the change touches scheduling order
  and GPU execution-path eligibility.

## Scope

### 1. Map policy and execution ownership

Before editing, record exact source points for:

- pending and partially prefilling request ownership;
- existing prefill chunk execution and safe commit boundary;
- active decode/spec row collection;
- DSpark verification work and acceptance accounting;
- graph eligibility, capture/replay, and eager fallback;
- completion/cancellation transition;
- scheduler loop timing and lock/stream ownership.

Preserve these execution mechanisms unless evidence proves a narrower change is
impossible.

### 2. Dynamic selection, constrained service

Introduce the smallest scheduler locus that decides:

- whether prefill may run before the next decode opportunity;
- which one pending/prefilling request receives service;
- which allowed quantum applies;
- when decode must run next.

Start with existing arrival order and the Phase 04 bounded capacity/fit rules.
Long/short class policy belongs to Phase 06. Cache locality belongs to Phase 07.

The scheduler must not duplicate request ownership or capacity state. It reads
or transitions the existing lifecycle through documented interfaces.

### 3. Small prefill quantum ladder

Evaluate sequentially:

```text
256
512
1024
```

A quantum is the maximum service offered at that opportunity; the actual work
may be smaller at a request boundary or safe engine chunk boundary.

Test one candidate at a time. Do not run a Cartesian sweep of quantum, partial
prefill count, class limits, graph modes, and cache policy. Explore 2048/4096 or
more than one partial prefill only after the initial ladder leaves a measured,
explainable opportunity and the graph/decode gates remain healthy.

### 4. Decode cadence guard

When live decode/spec work exists, enforce an explicit invariant equivalent to:

```text
no more than one selected bounded prefill service quantum
before another normal decode opportunity
```

Measure the achieved wall time, because equal token counts do not imply equal
GPU cost at every context/width. The initial policy may use tokens as a simple
service unit but must not claim a universal compute currency.

If the existing engine can expose a cheap time guard without destabilizing hot
paths, compare it only after the token-quantum baseline. Do not add a complex
feedback controller in V1.

### 5. Preserve decode/spec execution

The normal decode pack continues through the existing graph-aware path. Keep:

- supported production row/shape classes;
- current device-side graph substrates;
- DSpark yield/quench and verification behavior;
- eager fallback for unsupported/ineligible cases;
- bank assignment and continuation correctness.

A scheduler step does not force eager execution solely because policy metadata
changed. Any new graph invalidation or fallback must have a bounded recorded
reason.

### 6. Work accounting

Report separate, honest units:

```text
prefill service quanta and tokens
normal decode opportunities and live rows
committed generated tokens
speculative proposed/accepted work where already available
wall time by service class when measurable
scheduler decision time
graph eligible/replay/fallback steps
```

Do not collapse a DSpark verification step, plain decode token, and prefill token
into one supposedly exact cost unit.

### 7. Candidate configuration

Keep the experimental surface small:

- one candidate/legacy policy switch;
- one prefill quantum selection;
- no long-prefill threshold until Phase 06;
- no max-partial-prefills setting while the implementation supports exactly one;
- no graph-specific policy knobs unless a measured fallback requires one.

Configuration is parsed once, validated, and recorded in the run manifest.
Invalid values fail clearly rather than silently selecting a default.

### 8. Tests

Behavioral tests cover:

- no live decode: prefill continues through bounded service until completion;
- live decode: decode opportunities occur between bounded prefill service;
- multiple pending prefills: one receives service per epoch under current order;
- request completion within a partial quantum;
- cancellation before and after partial service;
- capacity defer and admission handoff from Phase 04;
- speculative and plain decode packs;
- graph-eligible and forced-eager/fallback paths available in test configuration;
- scheduler disabled: exact Phase 04 behavior.

Test observable ordering/progress/path counters, not private function call counts.

## Explicit non-goals

- No arbitrary mixed prefill/decode CUDA graph.
- No CUDA kernel rewrite.
- No more than one partial prefill per epoch initially.
- No long/short fairness class or starvation policy beyond inherited bounds.
- No prefix-aware ordering or conversation affinity.
- No V4 memory projection.
- No adaptive controller or universal work-cost model.
- No broad configuration matrix.
- No integration release promotion before Phase 06.

## Deliverables

### Engine fork

- one scheduler policy locus integrated with existing lifecycle;
- at-most-one bounded prefill service per initial epoch;
- 256/512/1024 quantum support for controlled experiments;
- explicit decode cadence guard;
- preserved graph-aware decode/spec dispatcher;
- graph/service/decision observations with fixed semantics;
- focused scheduler/cancellation/capacity tests;
- candidate/legacy A/B switch.

### Lab repository

- resolved candidate profiles for each initial quantum;
- paired S1/S3/S5 and target-local comparison support;
- per-request progress and graph-path report;
- engine submodule pin for the selected candidate;
- keep/retune/revert decision and rejected-ladder evidence.

### Integration fork

- no default change; note any required launch option for Phase 06 packaging.

## Validation

### Correctness and lifecycle

Run all relevant Phase 04 and upstream correctness, API, tool-continuation,
long-context, DSpark, and cancellation gates. Re-run S5A/S5B/S8 to ensure the
scheduler did not weaken bounded deferred capacity.

### Primary scheduler benchmarks

#### S3

For each initial quantum, compare against the exact Phase 04 baseline:

- active-decoder p50/p95/p99/max ITL;
- worst per-request inter-token gap;
- long-prefill progress rate and TTFT;
- aggregate committed goodput;
- graph eligible/replay/fallback rate and reason;
- scheduler decision time;
- failures, sheds, and cancellations.

#### S1

Check aggregate/per-request throughput, latency, fairness, live rows, and graph
path over the existing concurrency sweep.

#### Target-local controls

Measure single request, representative prefill lengths, decode, and localhost
S3-like behavior where feasible. Use these controls for any small latency claim.

### Decision procedure

1. Run the exact Phase 04 baseline and one quantum candidate in paired order.
2. Reject candidates that fail correctness, reliability, graph, or
   single-request gates.
3. Among surviving candidates, prefer the smallest policy and configuration
   surface that materially improves S3 without harming S1 goodput.
4. Retain raw results for rejected values.
5. Freeze one selected default for Phase 06; do not average or auto-select at
   runtime.

### Review

Independent DeepReview focuses on epoch ordering, lock/stream ownership,
cancellation, partial-prefill commit boundaries, decode cadence, graph
eligibility, and disabled-path equivalence. Reviewer findings are resolved and
targeted validation rerun before qualification.

## Acceptance gate

Use the numerical thresholds frozen from Phase 02 variance before candidate
runs. Phase 05 is Qualified only when the selected candidate:

1. materially improves or deliberately bounds S3 active-decoder latency while
   the long prefill continues making progress;
2. keeps S1 aggregate goodput within its non-regression gate and preferably
   improves useful throughput;
3. keeps single-request target-local behavior within its declared regression
   gate;
4. keeps graph eligibility/replay within its declared gate and explains every
   new fallback class;
5. preserves S5A/S5B/S8 bounded capacity and cancellation behavior;
6. passes relevant correctness/API/tool/long-context/DSpark tests;
7. introduces no OOM, crash, deadlock, request starvation, or unbounded
   scheduler decision time;
8. uses one partial prefill and the smallest justified configuration surface;
9. has no unresolved blocking review finding.

If no candidate passes, Phase 05 is Rejected or Retuned. Reliability work from
Phase 04 may still proceed to release consideration, but an underperforming
scheduler is not promoted by relaxing the gate after results are known.

## Artifacts

Retain:

- exact source integration map and scheduler invariants;
- all 256/512/1024 raw comparisons, including rejected candidates;
- S1/S3/S5/S8 and target-local control results;
- graph eligible/replay/fallback breakdown;
- scheduler/service timing and progress evidence;
- correctness and lifecycle test outcomes;
- review findings/resolutions;
- selected configuration and rationale;
- engine/lab commits and umbrella submodule pin;
- keep/retune/revert decision.

## Risks and rollback

| Risk | Mitigation / rollback |
|---|---|
| Dynamic policy destroys graph replay | Preserve dispatcher; first-class graph gate and reasons |
| Token quantum misstates actual cost | Measure wall time and outcomes; do not claim universal units |
| Prefill still blocks decode too long | Small ladder and explicit decode opportunity guard |
| Decode starves prefill | Require measurable long-prefill progress and completion |
| Scheduler duplicates lifecycle ownership | One policy locus consuming existing Phase 04 state |
| Knob matrix obscures attribution | Sequential three-value ladder; one selected default |
| DSpark behavior regresses | Preserve path and rerun DSpark/correctness gates |

Rollback disables/reverts the scheduler candidate to exact Phase 04 behavior and
restores the prior umbrella pin. Do not keep a failed alternative as an
undocumented fallback path.

## Exit handoff to Phase 06

Phase 06 receives:

- one selected graph-preserving scheduler candidate;
- a frozen prefill quantum and explicit decode-cadence invariant;
- measured S1/S3/graph/single-request behavior;
- preserved bounded-capacity and cancellation semantics;
- remaining S2 evidence showing how long and short prefills compete under the
  selected scheduler.
