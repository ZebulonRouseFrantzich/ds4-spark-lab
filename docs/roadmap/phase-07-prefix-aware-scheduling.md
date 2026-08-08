# Phase 07 — Prefix-Aware Scheduling

## Status

**Planned**

## Depends on

- [Phase 06](phase-06-fairness-and-v1-release.md) Qualified and tagged.
- Stable V1 release behavior and rollback ref.
- Baseline evidence showing material repeated-prefix or resumed-conversation work
  remains avoidable.

## Objective

Make scheduler service cost and tie-breaking aware of reusable prefix state and
remaining uncached work, while preserving V1 capacity bounds, decode cadence,
fairness, graph behavior, continuation correctness, and cache ownership.

This phase changes policy around DS4's existing reuse substrate. It does not
introduce a new cache allocator or shared-page representation.

## Hypothesis

When requests have comparable age and safety priority, preferring the request
with less uncached work or better existing locality can reduce physical prefill,
TTFT, and workflow time. Bounded locality tie-breaking plus age credit can
capture that gain without starving cold requests or corrupting warm/continued
state.

## Repositories

| Repository | Phase role |
|---|---|
| Engine fork | Reuse metadata contract, uncached-work accounting, bounded locality policy, optional affinity, tests |
| Lab repository | C1/C2 scenarios, cache/work accounting, V1 comparison, submodule pin |
| Integration fork | No release change until Phase 09 unless a safe opt-in profile is required |

## Entry criteria

- V1 is reproducible from immutable refs.
- Existing warm-bank, fork-by-copy, partial-prefix, disk-persisted, and tool
  continuation behavior is mapped in the V1 source.
- Reusable-prefix measurements can be derived or exposed without scanning or
  copying full prompt content in the scheduler hot path.
- C1/C2 prompt material is deterministic, distributable, and tokenized under the
  released model.
- The V1 fairness and starvation metrics remain available as hard regression
  gates.
- Independent review is assigned because cache identity and continuation state
  are correctness-sensitive.

## Core distinction

Logical prompt length is not physical work:

```text
logical prompt tokens
- reusable committed prefix tokens
= uncached prefill tokens
```

A 180K logical prompt with 170K reusable tokens is a roughly 10K prefill
problem, not a 180K prefill problem. The scheduler still records both numbers;
it does not rewrite API token accounting or claim reused tokens were computed.

## Scope

### 1. Map the existing reuse substrate

Before editing, identify exact ownership and validity rules for:

- live warm-bank records;
- full-prefix match;
- partial-prefix match/fork;
- copy/fork destination selection;
- bank generation or lineage validation;
- persisted-state lookup/restore;
- interrupted prefill and committed work;
- tool continuation records and protected state;
- invalidation, eviction, cancellation, and retry;
- current hit/miss/reuse metrics.

Document which reuse decisions are advisory and which are revalidated by the
engine at admission. Scheduler metadata must never bypass engine-authoritative
lineage/frontier checks.

### 2. Scheduler-visible prefix metadata

Expose or compute the smallest safe metadata set:

```text
logical_prompt_tokens
reusable_prefix_tokens
uncached_prefill_tokens
reuse_source_class       # none/live/partial/persisted as supported
reuse_identity/generation suitable for internal revalidation
estimated restore/copy work when already measurable
```

Rules:

- no prompt text or token array is duplicated into generic scheduler metadata;
- cache identity remains internal and bounded;
- a stale match degrades to an engine-validated miss or safe retry;
- the scheduler does not assume an advisory hit is committed capacity;
- metrics distinguish logical tokens, physical prefill computed, restored work,
  and copied state.

### 3. Uncached-work scheduling

Use `uncached_prefill_tokens` for prefill class/service-cost decisions where the
value is reliable. Preserve the V1 bounded quantum and decode opportunity.

A request with a large logical prompt but a small uncached tail may be treated
as short work for selection. If the reuse match invalidates before service, the
request is reclassified using the safe current value; it must not retain an
unearned short-work priority indefinitely.

### 4. Locality as a bounded tie-breaker

Initial ordering precedence:

1. lifecycle safety and continuation requirements;
2. V1 hard starvation/age bound;
3. capacity feasibility;
4. base arrival/fairness policy;
5. reuse/locality tie-breaker within a bounded candidate window.

Cache locality must not override an old request without limit. Record each
locality-based bypass and apply age credit. If locality does not materially
improve work avoided or workflow time, remove it and retain uncached-work
accounting alone.

Do not implement a general radix-tree scheduler unless the source audit proves
one is already present and directly reusable. A small policy over existing DS4
match metadata is preferred.

### 5. Optional conversation affinity

Affinity is optional within this phase and lands only if C2 demonstrates
avoidable bank churn that a lightweight mapping can solve.

Potential key:

```text
conversation/continuation identity -> preferred valid bank lineage
```

Requirements:

- engine generation/frontier revalidation remains authoritative;
- affinity is a preference, never a permanent reservation;
- mappings expire with lineage invalidation or bounded inactivity;
- no tenant/auth semantics are implied where the server has none;
- arbitrary user-supplied identifiers do not become unbounded metric labels;
- affinity cannot bypass capacity, continuation protection, or starvation rules.

If the existing continuation contract already provides the needed behavior,
do not add a second mapping.

### 6. C1 shared-prefix fan-out

Create a deterministic scenario with a large common prefix and unique tails,
starting with 4/8/12 branches only as runtime permits.

Measure:

- logical prompt tokens;
- engine-reported reusable prefix and physical prefill tokens;
- copy/restore work and bytes where observable;
- TTFT and completion per branch;
- workflow wall time and goodput;
- bank/cache residency and invalidation;
- graph path and decode latency;
- fairness for an unrelated cold request.

C1 tests policy and current fork-by-copy behavior. It does not claim physical
shared pages.

### 7. C2 multi-turn agent simulation

Simulate several conversations over multiple overlapping turns with repeated
history and tool-like growth. Freeze every turn and arrival schedule.

Measure:

- cold versus warm/resumed TTFT;
- logical versus physical prompt work;
- affinity hit/miss/stale outcomes if implemented;
- per-conversation progress and starvation;
- total workflow wall time;
- continuation correctness and replay behavior;
- memory/residency high-water mark.

### 8. C5 interrupted prefill protection

Do not automatically add C5 as a release requirement. Add it in this phase only
if prefix metadata or scheduling changes touch interrupted-prefill reuse or
commit boundaries. If added:

1. begin a deep prefill;
2. cancel after safe committed chunks;
3. retry the identical prompt;
4. verify only committed work is reused;
5. verify no speculative/uncommitted state is exposed.

### 9. Observability

Add only meaningful fixed-cardinality observations:

```text
reuse candidates and validated hits by source class
logical prompt tokens
physical prefill tokens
reusable prefix tokens
locality-based bypass count
stale-match/revalidation fallback count
affinity hit/miss/stale count if affinity lands
copy/restore time or bytes only where source can measure honestly
```

Do not label metrics with prompt hashes, conversation IDs, paths, or raw cache
keys.

### 10. Candidate and rollback

Keep a V1 policy mode for paired comparison and emergency rollback. The V2
candidate uses one coherent metadata/selection path. Avoid independent switches
for every reuse field and tie-break rule; use narrowly scoped experiment flags
only while choosing the policy, then remove rejected alternatives.

## Explicit non-goals

- No ref-counted/paged shared state.
- No copy-on-write allocator.
- No new disk cache format unless a touched correctness defect requires it.
- No V4-accurate state-lifetime byte projection; Phase 08 owns it.
- No retention priority or eviction redesign; Phase 09 owns it.
- No locality-first policy without an age bound.
- No generic multi-tenant namespace.
- No arbitrary prompt-content logging or scheduler-side token copies.

## Deliverables

### Engine fork

- validated scheduler-visible reuse metadata;
- uncached-work-aware prefill classification/service cost;
- bounded locality tie-breaker only if it passes C1/C2;
- optional minimal affinity only if independently justified;
- stale-match, invalidation, cancellation, and continuation tests;
- fixed-cardinality reuse observations;
- V1 comparison/rollback mode.

### Lab repository

- C1 and C2 scenarios plus prompt/turn manifests;
- C5 only if touched behavior requires it;
- logical-versus-physical work reporting;
- paired V1/candidate results;
- engine submodule pin and decision report.

### Integration fork

- no default release update; document any candidate launch option for Phase 09.

## Validation

### Correctness

Run all V1 release gates plus focused cases for:

- full, partial, and no prefix match;
- stale lineage/generation;
- match invalidated between scheduling and admission;
- simultaneous fan-out from one trunk;
- branch divergence;
- cancellation and retry;
- persisted restore if used by policy;
- tool continuation and replay;
- unrelated cold request under sustained cache-friendly arrivals;
- affinity expiration/invalidation if implemented.

### Benchmarks

Compare immutable V1 and candidate using:

- C1 and C2 as primary value gates;
- S2 and S6 as fairness/starvation gates;
- S1 and S3 as throughput/decode/graph gates;
- S5A/S5B/S8 as admission/cancellation regression gates;
- target-local representative-depth controls.

Reset or preserve cache state exactly as the scenario declares. Never allow
later repetitions intended to be cold to become accidentally warm.

### Review

DeepReview focuses on cache identity, generation/frontier validation, scheduler
metadata lifetime, cancellation, continuation semantics, fairness precedence,
and stale-match fallback. Resolve findings and rerun affected cache and V1
regression scenarios.

## Acceptance gate

Phase 07 is Qualified only when:

1. engine-authoritative validation remains the final reuse decision;
2. logical, reusable, and physical work accounting reconcile within documented
   semantics;
3. C1/C2 show a material reduction in physical prefill or workflow time under
   predeclared thresholds;
4. an unrelated cold request retains the V1 starvation bound;
5. stale matches safely degrade without corruption, crash, or unbounded retry;
6. tool continuation, cancellation, and interrupted work remain correct;
7. S1/S2/S3/S5/S6/S8 and graph/single-request behavior remain within V1 gates;
8. optional affinity is included only if its independent incremental result is
   positive;
9. no prompt/content/private identity leaks through metrics or artifacts;
10. no unresolved blocking review finding remains.

If locality tie-breaking fails but uncached-work accounting passes, qualify the
smaller uncached-work policy and reject the tie-breaker. Do not bundle a failed
idea with a successful one.

## Artifacts

Retain:

- existing reuse-substrate ownership map;
- metadata and revalidation contract;
- C1/C2 raw runs and cache-state setup records;
- optional C5 and affinity incremental evidence;
- logical/reusable/physical work reconciliation;
- full V1 regression subset and graph-path results;
- fairness/cold-request evidence;
- review findings/resolutions;
- engine/lab commits and umbrella submodule pin;
- separate keep/reject decisions for uncached-work, locality, and affinity.

## Risks and rollback

| Risk | Mitigation / rollback |
|---|---|
| Advisory hit is treated as valid state | Engine generation/frontier revalidation remains authoritative |
| Cache-friendly traffic starves cold requests | V1 age bound precedes locality; explicit cold control |
| Metadata copies large prompts | Scalar/bounded metadata only |
| Logical tokens are reported as computed work | Separate logical, reused, copied/restored, and physical counters |
| Affinity duplicates continuation machinery | Add only after source audit and incremental C2 evidence |
| Cold scenarios become warm accidentally | Explicit reset/state manifest per repetition |

Rollback restores the immutable V1 policy/ref and umbrella pin. Rejected
locality or affinity code is removed rather than left as dormant complexity.

## Exit handoff to Phase 08

Phase 08 receives:

- validated logical/reusable/uncached token accounting;
- engine-authoritative reuse identity and lifetime map;
- C1/C2 workload and memory observations;
- stable V1 safety/fairness/graph invariants;
- concrete evidence of where current token-based capacity estimates diverge
  from observed V4 memory behavior.
