# Phase 03 — Observability Gap Audit

## Status

**Planned**

## Depends on

- [Phase 02](phase-02-benchmark-baseline.md) Qualified.
- Frozen baseline report and raw S1/S2/S3/S5A/S5B results available.
- V1 decision thresholds declared from observed baseline variance.

## Objective

Map the frozen `v0.5.6` engine/server behavior to its existing metrics, logs,
and tests, then add only the lowest-cost observations required to explain the
next admission and graph-preservation experiments.

This phase must not change request routing, admission, queueing, scheduling,
cancellation, fallback, cache, or execution semantics.

## Hypothesis

Existing `v0.5.6` observability already answers most V1 questions. A focused
source and benchmark audit will identify a small set of missing fixed-cardinality
observations without requiring a tracing platform or measurable hot-path cost.

## Questions the audit must answer

### Admission and overload

- At what exact engine/server decision does a deep continuous-path request fail
  placement today?
- Can the current evidence distinguish hard impossibility, current pressure,
  protected state, explicit operator bounds, and internal failure?
- Which outcomes enter serial fallback, return 429/503, or eventually run?
- Is the request's explicit or resolved default output budget observable?
- Are queue depth, queued bytes, queue age, client bounds, and shed reasons
  already available?

### Execution path

- Can S3 distinguish graph-eligible decode, graph replay, and eager fallback?
- Is a fallback reason available with bounded cardinality?
- Can the harness recover live rows/shape class and prefill service progress?
- Can scheduler/host decision cost be measured without high-frequency content
  tracing?

### Speculation attribution

This subsection becomes actionable only when Phase 02 records a concrete result
that configured policy plus existing aggregates cannot explain.

- Can existing evidence distinguish DSpark-eligible steps, live-count
  plain-decode fallback and re-entry, proposal/verification width, accepted
  prefixes, terminal quench, and the resulting graph path?
- Does the frozen continuous path consume the loaded confidence-head output when
  selecting verification width, or is another bounded controller the runtime
  owner?
- Can the gap be closed from run manifests and existing aggregates rather than
  adding request- or token-level traces?

### Correlation

- Can one benchmark run correlate client request IDs, server outcomes, capacity
  decisions, and execution-path aggregates without exposing prompt content?
- Which values are per request, per scheduler epoch, or process-global?

## Repositories

| Repository | Phase role |
|---|---|
| Engine fork | Source audit; minimal metric/log/test changes if proven necessary |
| Lab repository | Metrics inventory, scraper/parser updates, baseline/candidate comparison, submodule pin |
| Integration fork | No change expected |

## Entry criteria

- All baseline artifacts pass redaction review.
- The engine submodule is still based on exact V1 lineage.
- Phase 02 identifies concrete unexplained observations; speculative convenience
  metrics are not sufficient justification.
- A speculation-specific instrumentation gap is actionable only when Phase 02
  names the S1 or graph-preservation result it prevents the project from
  interpreting.
- Relevant existing metrics and tests in the frozen source are inventoried
  before a new name or label is proposed.

## Scope

### 1. Map the frozen source

Before editing, record the exact functions and structures responsible for:

- request parsing and output-budget resolution;
- endpoint routing and continuous/serial selection;
- queue insertion/removal, age, byte, and client limits;
- current continuous placement/admission result;
- bank lifecycle and protected-state handling;
- cancellation/disconnect cleanup;
- deep serial guard and HTTP error projection;
- continuous prefill service;
- DSpark eligibility, live-count fallback/re-entry, proposal and verification
  width, accepted-prefix and quench ownership, and whether confidence-head
  output participates in runtime width selection;
- decode/speculative packing and CUDA graph eligibility/replay/fallback;
- metrics declaration, update, export, and tests.

Search every callsite before modifying exported symbols or shared enums. The
roadmap deliberately does not guess exact symbols because the release lineage
moves independently of `main`.

### 2. Build an observability matrix

For each V1 question, record:

| Question/event | Existing source signal | Existing metric/log | Harness consumption | Gap | Cost/risk |
|---|---|---|---|---|---|

A gap is actionable only when it blocks Phase 04/05 attribution or acceptance.
Prefer an existing metric, a derived value, or a one-time run manifest over a
new hot-path counter.

For speculation attribution, first combine the resolved run configuration with
existing bounded counters, logs, and derived aggregates. Configuration alone is
not evidence that each step used that execution path.

### 3. Add minimal fixed-cardinality observations

Candidate concepts, only if the audit proves they are absent:

```text
current admission/placement outcome by bounded reason
current serial-fallback/deep-guard outcome
resolved output-budget class or run-level resolved default
capacity-related wait or retry timing when such an event already exists
decode graph eligible step
decode graph replay step
decode eager fallback step by bounded reason
prefill service quanta/tokens already performed by the frozen path
scheduler/host decision duration when it can be measured cheaply
speculative versus plain execution step by bounded class
verification-width class and proposed/accepted aggregate
terminal speculation quench aggregate
```

Rules:

- Do not add a `capacity_deferred` event before deferred capacity exists; that
  observation belongs to Phase 04 if there is no meaningful current event.
- Do not add a scheduler-policy counter before the scheduler exists.
- Do not add a standalone DFlash mode, confidence-pruning policy,
  verification-width policy, or quench-policy change under observability scope.
- Run configuration belongs in the run manifest, not arbitrary metric labels.
- Do not add per-token proposal/acceptance traces when bounded existing or
  derived aggregates answer the named question.
- Use bounded enums or fixed labels; never place request IDs, paths, prompt
  text, model text, error strings, or arbitrary configuration in metric labels.
- Aggregate counters remain cheap and thread-safe under the source's existing
  ownership model.
- Histograms are added only when buckets answer an acceptance question and
  their overhead is measured.
- A disabled feature does not report a misleading success or zero denominator.

### 4. Correlation contract

Use a benchmark run ID and request identifier that are safe to log and already
available or can be propagated with minimal API disruption. Correlation data
must be content-free and bounded. If existing server identifiers suffice, use
them rather than creating a distributed tracing header scheme.

The initial goal is to correlate:

```text
client request timeline
HTTP outcome and retry metadata
server route/lane outcome
capacity/admission aggregate or bounded reason
prefill progress
graph path aggregate
configured speculation policy and observed execution aggregate, when required
```

A full per-epoch JSONL trace is not part of this phase. Add it later only if
aggregate evidence cannot explain a specific failed decision gate.

### 5. Metrics schema/version

If the project adds or consumes metric names, record a small schema version or
engine source identity with the parsed snapshot. The lab parser must fail
clearly when required metrics are absent rather than silently interpreting zero.

### 6. Focused tests

Tests defend observable contracts:

- each instrumented event increments exactly at its real decision point;
- mutually exclusive outcomes do not double count;
- label/reason sets are bounded;
- cancellation and shed outcomes remain distinct;
- metric export remains valid under concurrent requests;
- feature-disabled or unsupported paths are represented honestly;
- configured DSpark with plain fallback is not reported as all-steps
  speculation;
- unavailable speculation signals remain distinct from observed zeroes.

Do not write tests that merely search source text or assert an implementation
constant without exercising the event.

## Explicit non-goals

- No admission-state or queue behavior change.
- No deferred-capacity implementation.
- No scheduler policy or prefill-quantum change.
- No DSpark/DFlash algorithm, eligibility, confidence-pruning,
  verification-width, or quench-policy change.
- No per-token speculative proposal/acceptance trace.
- No tracing platform, database, dashboard, or OpenTelemetry rollout.
- No prompt/token content in logs.
- No unbounded metric labels.
- No broad refactor of the metrics subsystem.
- No integration-fork release change.

## Deliverables

### Engine fork

- checked-in source/ownership map in the phase report or PR description;
- observability matrix;
- only proven-missing observations and focused tests;
- documentation of metric semantics and denominators;
- no request-semantic change.

### Lab repository

- parser/collector support for the final observed schema;
- submodule pin to the reviewed engine commit;
- repeated baseline/candidate evidence for overhead and semantic parity;
- updated phase status and compact report.

### Integration fork

- no change unless the existing packaging prevents metrics exposure required by
  the phase, in which case the smallest documented integration change is
  separately reviewed.

## Validation

### Semantic parity

Run the relevant upstream tests and Phase 02 smoke. Compare status codes,
response bodies, routing, cancellation, queue bounds, and output-budget behavior
against the exact baseline.

### Observability behavior

Trigger every new event with a real request/path and verify:

- the expected counter/timing changes;
- unrelated counters do not change incorrectly;
- reason cardinality remains fixed;
- the lab parser associates the snapshot with the correct run and source;
- absent/unsupported metrics do not become synthetic zeroes.

### Performance overhead

Run paired target-local controls plus S1 and S3 as needed. Default-on
instrumentation must remain within measured baseline noise for single-request
and concurrent behavior. If an observation is expensive, remove it or make it
explicitly opt-in and exclude it from qualified performance runs.

### Privacy

Scan metric names/labels, server logs, run artifacts, and failure output for
prompt content and private configuration. Safe request/run identifiers are
allowed; access details are not.

## Acceptance gate

Phase 03 is Qualified only when:

1. the frozen source ownership and existing observability are mapped;
2. configured speculation policy is not presented as execution evidence and,
   when Phase 02 names an attribution gap, existing or minimally added bounded
   data distinguishes the relevant speculative/plain execution;
3. every added observation closes a named Phase 04/05 evidence gap;
4. all new reasons/labels have bounded cardinality and documented semantics;
5. no request, queue, scheduling, fallback, or execution behavior changes;
6. relevant correctness and API tests pass;
7. paired performance remains within the predeclared measurement-noise gate;
8. S1/S3/S5 artifacts can distinguish the current admission/fallback and graph
   behavior needed by the next phases;
9. no content or private configuration leaks through metrics/logs/artifacts;
10. no JSONL trace or broader telemetry platform was added without demonstrated
    need.

## Artifacts

Retain:

- source ownership map with exact engine commit;
- observability matrix;
- speculation-path source map and the retained decision to reuse, derive, add,
  or reject each candidate execution signal;
- final metrics/reason schema and semantics;
- targeted test outcomes;
- paired overhead measurements;
- representative sanitized metric snapshots for S1/S3/S5;
- lab and engine commits plus umbrella submodule pin;
- decision listing rejected candidate metrics and why they were unnecessary.

## Risks and rollback

| Risk | Mitigation / rollback |
|---|---|
| Metrics alter hot-path timing | Prefer aggregate counters; measure overhead; remove expensive signal |
| Cardinality grows with traffic | Fixed enums only; tests enumerate allowed labels |
| Instrumentation changes ownership/races | Update at existing decision owner; focused concurrency tests |
| Zero is mistaken for unavailable | Schema/source identity and explicit absence handling |
| Audit becomes a telemetry project | Every addition maps to a Phase 04/05 question |
| Audit expands into speculative-algorithm research | Require a named Phase 02 attribution gap; prohibit policy or mode changes |
| Logs expose content or target details | Content-free correlation and artifact scan |

Every instrumentation change is independently revertible. If it cannot stay
inside the overhead gate, remove it and use a narrower opt-in diagnostic only
for non-performance debugging.

## Exit handoff to Phase 04

Phase 04 receives:

- exact source symbols for admission, queue, fallback, cancellation, and output
  budget handling;
- a tested bounded outcome vocabulary;
- baseline counts for current deep-capacity and deep-serial behavior;
- enough correlation to prove whether a transient request deferred, shed,
  failed, or completed;
- unchanged baseline request semantics and measured instrumentation overhead;
- the existing decode/speculative ownership boundary needed to preserve the
  baseline path through Phase 05.
