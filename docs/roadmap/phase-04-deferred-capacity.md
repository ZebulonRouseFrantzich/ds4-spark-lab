# Phase 04 — Bounded Deferred Capacity

## Status

**Planned**

## Depends on

- [Phase 03](phase-03-observability-audit.md) Qualified.
- Exact admission, fallback, queue, cancellation, and output-budget ownership
  mapped in the frozen engine source.
- S5A/S5B baseline behavior and current outcome counts retained.

## Objective

Replace ambiguous handling of temporary continuous-path capacity pressure with
an explicit, bounded admission contract. Valid requests that cannot fit now may
wait for a meaningful capacity change; impossible requests fail honestly;
operator overload limits continue to shed work; internal failures remain
failures.

The deep serial safety guard remains in place. The fix prevents valid transient
pressure from accidentally reaching it; it does not raise or disable it.

## Hypothesis

A small admission-result classification, explicit waiting state, capacity-change
epoch, and cancellation-safe retry path can make feasible deep requests complete
reliably without overcommit, busy-loop retries, unbounded queueing, or regression
to existing API/continuation semantics.

## Contract to establish

The exact identifiers are selected from the Phase 03 source audit, but the
observable categories are fixed:

```text
ADMIT_NOW          placement can proceed now
DEFER_CAPACITY     request is valid; current placement pressure may change
REJECT_IMPOSSIBLE  request cannot fit under configured hard constraints
UNSUPPORTED        no supported execution path exists
FATAL              engine/server invariant or internal operation failed

SHED_OVERLOAD      server policy refused bounded queue/client/byte/age pressure
```

`SHED_OVERLOAD` is not an engine placement result. `DEFER_CAPACITY` is a
single classification event; `WAITING_CAPACITY` is the request's server-owned
state while it remains eligible for retry.

## State invariants

1. A request occupies exactly one lifecycle state at a time.
2. A deferred request remains charged to existing queue/client/body-byte and
   continuation-protection accounting.
3. A request is retried only after a capacity fact relevant to placement may
   have changed, or during one explicitly bounded initial scan.
4. Cancellation/disconnect wins over future admission and releases all waiting
   ownership exactly once.
5. Impossible/unsupported/fatal results never enter the deferred queue.
6. Overload shedding never masquerades as engine impossibility.
7. A request does not enter deep serial fallback merely because continuous
   placement is temporarily full.
8. Existing decoders and protected continuation state keep their safety and
   progress guarantees.
9. Output liability uses the request's explicit budget or the resolved server
   default; omitted and explicit values are not equivalent.
10. No retry path can busy-loop without a capacity epoch change.

## Repositories

| Repository | Phase role |
|---|---|
| Engine fork | Admission result, waiting lifecycle, capacity epoch, bounded retry, cancellation and metrics/tests |
| Lab repository | S8 scenario, S5 assertions, candidate profile, paired results, submodule pin |
| Integration fork | No release change yet; optional test profile only if packaging blocks qualification |

## Entry criteria

- Phase 03 can distinguish current placement failure, serial fallback, overload
  shed, cancellation, and completion.
- Existing bounded queue and endpoint-native retry behavior have focused tests.
- The resolved default output budget is known for S5B.
- The candidate can be enabled/disabled through one clearly named legacy versus
  candidate switch for paired A/B. Do not use a name that conflicts with V1/V2
  release terminology.
- An independent reviewer is assigned because this phase changes a concurrent C
  request state machine and public HTTP outcomes.

## Scope

### 1. Source-level admission result

Refine the narrowest existing placement interface rather than layering string
parsing or server special cases over an ambiguous boolean.

Requirements:

- every return path maps to one documented category;
- capacity classification is based on current engine facts;
- hard impossibility is stable under a capacity epoch change;
- temporary pressure identifies no request as successful before ownership is
  established;
- unsupported and internal failure stay distinguishable;
- callers are migrated together; no old ambiguous path remains.

Do not generalize the API beyond the model/server paths needed by this phase.

### 2. Waiting-capacity lifecycle

Integrate deferred requests into the existing bounded queue/lifecycle owner.
Do not create a second unbounded side queue.

The waiting record needs only fields supported by the source audit, likely:

```text
arrival/order identity
current lifecycle state
capacity wait start
epoch last evaluated
resolved output liability
bypass/age credit if bounded fit lookahead is required
cancellation/continuation ownership already used by the server
```

Avoid copying prompts or request bodies solely for scheduler metadata. Reuse the
request object already charged by queue accounting.

### 3. Capacity epoch

Maintain a cheap monotonic generation that changes only when placement
feasibility may materially change, for example:

- a bank/request completes and releases state;
- cancellation releases owned capacity;
- an eviction/demotion/reclaim operation frees eligible state;
- protected state expires or becomes replaceable;
- the relevant memory plan changes.

A decode token that cannot affect admission must not trigger a full retry scan.
Document the source events that advance the epoch and test that no required
release event is omitted.

Handle generation wrap safely or use a width for which wrap is operationally
irrelevant and equality-only comparisons remain correct.

### 4. Bounded retry and fit behavior

Start mostly FCFS. If a head request cannot currently fit and the existing queue
would otherwise stall feasible work, allow a small bounded lookahead for a
request that can admit. Each bypass adds age/credit to the skipped request and
has a strict starvation bound.

Do not add sophisticated size classes or cache-locality policy here. Fit-aware
lookahead is included only to prevent immediate head-of-line blockage exposed
by S5 or existing queue semantics.

Retry work is bounded by queue size and epoch. It must not hold the GPU or a
coarse server lock while performing avoidable repeated projection.

### 5. Output-budget-aware semantics

Resolve the request's promised output once according to the existing API/server
rules. Admission uses that liability consistently on initial evaluation and
retry.

- **S5A:** explicit realistic output budget, initially 512.
- **S5B:** omitted budget, using the observed server default.

S5B may admit fewer requests or shed safely if the default legitimately implies
a larger liability. The phase must explain the outcome; it must not force S5B
to match S5A by ignoring promised output.

V2 will improve byte projection. Phase 04 uses the best existing engine
capacity facts and does not pretend to have a complete V4 state-lifetime model.

### 6. Preserve bounded overload and continuation policy

Deferred work remains subject to existing:

- maximum clients;
- queue depth;
- in-flight/queued body bytes;
- queue age;
- continuation grace/pin protection;
- client disconnect;
- endpoint-native error envelopes;
- `Retry-After` behavior.

When a bound expires or is exceeded, settle the request exactly once with the
correct existing API surface and reason. Do not convert an overload shed into a
permanent impossible result.

### 7. Cancellation path

Implement S8 with these observable steps:

1. create capacity pressure;
2. place a long request in `WAITING_CAPACITY`;
3. disconnect/cancel before admission;
4. prove no prefill begins for that request;
5. prove queue, body-byte, continuation pin, wait metadata, and any reserved
   capacity are released;
6. advance capacity later and prove the canceled request is not resurrected.

Also cover cancellation racing with an epoch change/admission handoff. The
source's ownership rules determine which terminal result wins, but cleanup is
exactly once.

### 8. Observability

Add only observations made meaningful by this phase:

```text
admit-now count
deferred count
retry count
retry-success count
impossible/unsupported/fatal count
capacity wait duration
waiting-capacity gauge
bounded bypass/starvation-bound events, if implemented
```

Use fixed reasons and keep existing shed counters authoritative. Do not add
request data to labels.

### 9. Candidate switch and clean cutover

One candidate/legacy switch supports paired A/B during qualification. Candidate
off must recover the exact baseline behavior. Candidate on must use the new
contract end to end; do not maintain two partial implementations.

After V1 promotion, remove or consolidate temporary experiment-only knobs under
the release policy. Do not leave ambiguous aliases.

## Explicit non-goals

- No scheduler prefill quantum or decode-cadence policy.
- No prefix-aware ordering.
- No V4-accurate byte projection.
- No cache retention or paging.
- No deep serial threshold increase.
- No unbounded wait queue.
- No retry on every decode step.
- No new public API fields.
- No general priority framework.

## Deliverables

### Engine fork

- explicit admission result contract and migrated callers;
- server-owned `WAITING_CAPACITY` lifecycle;
- capacity epoch and bounded retry logic;
- output-budget-consistent admission;
- bounded fit behavior only if required;
- cancellation/disconnect cleanup;
- preserved overload/continuation/error semantics;
- focused unit/integration/concurrency tests;
- meaningful fixed-cardinality observations;
- candidate/legacy A/B switch.

### Lab repository

- S8 scenario and cancellation assertions;
- strengthened S5A/S5B result classification;
- legacy and candidate launch profiles;
- paired raw results and reviewed report;
- engine submodule pin to the qualified candidate.

### Integration fork

- no release pin yet; record any launch configuration needed for later V1
  packaging without changing defaults prematurely.

## Validation

### Behavioral tests

Exercise:

- immediate admission;
- temporary defer followed by capacity release and successful completion;
- stable impossible request;
- unsupported and internal failure paths available in the source;
- overload by each existing bounded policy;
- queue-age expiry while waiting;
- explicit versus default output liability;
- client cancellation before and during admission handoff;
- continuation-protected capacity;
- repeated capacity epochs with no duplicate admission/settlement;
- head request that cannot fit while a bounded lookahead request can;
- starvation credit/bound if lookahead is implemented.

Tests assert external status/response semantics and lifecycle invariants, not
private struct layout.

### Correctness and API regression

Run all relevant frozen upstream server, API, tool-continuation, long-context,
and CUDA quality gates identified in Phase 02/03.

### Benchmark qualification

Run paired legacy/candidate:

- S5A as the primary success gate;
- S5B as the safe/explainable-default gate;
- S8 as the cancellation gate;
- S3 to prove existing decoders progress under waiting pressure;
- S1/S2 as bounded-overload and aggregate non-regression checks;
- single-request target-local controls.

No OOM, crash, deep serial degradation, unbounded wait, or unexplained status
change is acceptable.

### Concurrency and soak

Run a focused churn case of admissions, completions, capacity epochs,
cancellations, and queue expiry long enough to expose double-settlement,
stale-request resurrection, accounting underflow, or leaked waiting records.

### Review

Independent DeepReview is required. Focus on state ownership, lock ordering,
epoch advancement, cancellation races, output-budget resolution, and HTTP
projection. A focused security review verifies that overload behavior cannot be
bypassed into resource exhaustion and error/artifact paths do not leak content.

## Acceptance gate

Phase 04 is Qualified only when:

1. S5A feasible transient requests enter bounded wait and eventually complete
   without accidental deep serial 503;
2. S5B behavior matches the recorded default output liability and remains safe,
   bounded, and explainable;
3. S8 proves canceled waiting work never starts and releases every owned
   resource;
4. impossible, unsupported, fatal, and overload outcomes remain distinct;
5. all existing client/queue/byte/age/continuation bounds and `Retry-After`
   semantics remain intact;
6. retries occur only after relevant capacity epochs and remain bounded;
7. no OOM, crash, busy loop, double settlement, stale resurrection, or leaked
   capacity appears in tests or churn;
8. existing decodes keep progress and correctness/API/tool gates pass;
9. S1/S2/S3 and single-request results remain within predeclared non-regression
   gates except for the intended reliability improvement;
10. required independent and security reviews have no unresolved blocking
    findings.

## Artifacts

Retain:

- state-transition and ownership description tied to exact symbols/commit;
- admission result and epoch semantics;
- focused test and churn outcomes;
- paired raw S1/S2/S3/S5A/S5B/S8 results;
- wait/retry/shed/fallback metric snapshots;
- output-budget resolution evidence;
- review findings and resolutions;
- engine/lab commits and umbrella submodule pin;
- keep/retune/revert decision.

## Risks and rollback

| Risk | Mitigation / rollback |
|---|---|
| Deferred requests bypass operator bounds | Reuse existing queue owner/accounting; tests for every bound |
| Retry loop consumes CPU or blocks GPU | Capacity epoch plus bounded scan; decision-time measurement |
| Cancellation races admission | Explicit ownership transition and exactly-once settlement tests |
| Fit lookahead starves large request | Small window, age/bypass credit, hard bound |
| Output budget is under-reserved | Resolve once from existing API rules; separate S5A/S5B |
| Protected continuation state is evicted | Preserve existing protection checks and focused tests |
| New enum is only partially adopted | Migrate every caller in one clean cutover |
| Candidate changes HTTP envelopes | Endpoint-native regression tests and security review |

The candidate switch must restore exact baseline semantics for A/B and emergency
rollback. If bounded deferred capacity cannot meet the gate, revert the engine
and lab submodule pin; do not ship a partial state machine or raise the serial
guard as compensation.

## Exit handoff to Phase 05

Phase 05 receives:

- explicit, tested admission and waiting states;
- a bounded queue under temporary capacity pressure;
- capacity epochs and cancellation-safe lifecycle;
- reliable S5A/S5B/S8 scenarios;
- preserved baseline decode dispatcher and graph behavior;
- concrete measurements showing where prefill service still harms active decode.
