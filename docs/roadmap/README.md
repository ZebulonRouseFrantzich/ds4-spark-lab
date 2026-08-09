# DS4 Spark Lab Roadmap

This directory contains the dependency-ordered implementation plan for the
[DS4 Spark Agentic Serving Project](../../PROJECT.md). Each phase is an
independently reviewable work package with an entry gate, explicit scope,
validation evidence, and exit gate.

The roadmap is an ordering of evidence, not a calendar. A phase starts only
when its dependencies and entry criteria are satisfied. Performance work never
advances on an inferred or published baseline when a target measurement is
required.

## Current status

Phase 00 workspace bootstrap is **Qualified** as of 2026-08-08; retained
evidence is in its [qualification record](phase-00-qualification.md). Phase 01
and all later numbered phases remain **Planned**; the research backlog remains **Gated**.

| ID | Phase | Status | Primary repositories | Depends on |
|---|---|---|---|---|
| 00 | [Workspace bootstrap](phase-00-workspace-bootstrap.md) | Qualified — 2026-08-08 ([evidence](phase-00-qualification.md)) | lab, both forks | approved roadmap |
| 01 | [Execution target](phase-01-execution-target.md) | Planned | lab | Phase 00 |
| 02 | [Benchmark and baseline](phase-02-benchmark-baseline.md) | Planned | lab, pinned forks | Phase 01 |
| 03 | [Observability audit](phase-03-observability-audit.md) | Planned | engine, lab | Phase 02 |
| 04 | [Bounded deferred capacity](phase-04-deferred-capacity.md) | Planned | engine, lab | Phase 03 |
| 05 | [Graph-preserving scheduler](phase-05-graph-preserving-scheduler.md) | Planned | engine, lab | Phase 04 |
| 06 | [Fairness and V1 release](phase-06-fairness-and-v1-release.md) | Planned | all three | Phase 05 |
| 07 | [Prefix-aware scheduling](phase-07-prefix-aware-scheduling.md) | Planned | engine, lab | V1 release |
| 08 | [V4 capacity accounting](phase-08-v4-capacity-accounting.md) | Planned | engine, lab | Phase 07 |
| 09 | [Retention and V2 release](phase-09-retention-and-v2-release.md) | Planned | all three | Phase 08 |
| R | [Gated research backlog](research-backlog.md) | Gated | determined per track | measured entry gate |

## Dependency graph

```text
00 Workspace and source lineage
   |
   v
01 Generic execution target
   |
   v
02 Benchmark harness and frozen baseline
   |
   v
03 Observability gap audit
   |
   v
04 Bounded deferred capacity
   |
   v
05 Graph-preserving scheduler
   |
   v
06 Fairness and V1 release
   |
   v
07 Prefix-aware scheduling
   |
   v
08 V4 capacity accounting
   |
   v
09 Retention and V2 release
   |
   +--> research tracks only when their independent entry gates pass
```

Phases 03-06 are deliberately serial. They modify and measure the same serving
state machine, so concurrent implementation would invalidate attribution.
Phases 07-09 remain ordered until the V1 source audit shows a safe alternative.
Research tracks may run independently only after V2 or an explicit earlier gate
provides the required measurements.

## Why these are phases rather than specification sections

The master specification includes architecture, principles, risks, benchmark
methodology, comparisons, and definitions of done. Those are cross-cutting
constraints, not separate implementation stages. Creating one document for
each numbered source section would duplicate policy and allow it to drift.

The phase boundaries instead follow independently measurable changes:

1. reproducible workspace;
2. reproducible execution path;
3. authoritative baseline;
4. no-semantics observability;
5. one admission behavior change;
6. one scheduler behavior change;
7. one fairness and release gate;
8. V2 cache/capacity increments;
9. separately gated research.

## Phase status vocabulary

Every phase uses one of these statuses:

- **Planned:** scope is documented but entry criteria are not yet satisfied.
- **Ready:** dependencies and entry criteria are satisfied; work may begin.
- **Active:** implementation or qualification is in progress.
- **Blocked:** an external prerequisite is missing; the document names it.
- **Qualified:** all exit criteria passed and evidence is retained.
- **Rejected:** the candidate failed its decision gate and was reverted or not
  promoted.
- **Superseded:** a later approved plan replaced the phase before completion.

Status changes require evidence links or an explicit decision note. Do not mark
a performance phase Qualified based only on compilation or unit tests.

## Required phase-document contract

Each phase document contains:

1. **Status and dependencies** — where the phase sits and what must already be
   true.
2. **Objective and hypothesis** — the behavior being tested.
3. **Baseline and repositories** — exact source lineages and ownership.
4. **Entry criteria** — evidence required before implementation starts.
5. **Scope and non-goals** — the smallest meaningful change.
6. **Implementation plan** — expected integration points, refined against the
   frozen source before editing.
7. **Deliverables** — repository-specific outputs, including submodule updates.
8. **Validation** — functional, correctness, performance, and operational
   scenarios.
9. **Acceptance or decision gate** — a predeclared keep, retune, or revert rule.
10. **Artifacts** — exact evidence retained on the controller.
11. **Risk and rollback** — what can fail and how the candidate is removed.
12. **Exit handoff** — facts made available to the next phase.

Exact C symbols are intentionally not invented in advance. Each engine phase
starts by mapping the documented behavior to the frozen implementation and
records the discovered symbols before changing them.

## Cross-phase invariants

### Source and upstream lineage

The writable fork is always `origin`; Entrpi is always `upstream`:

```text
engine/ds4:
  origin    https://github.com/ZebulonRouseFrantzich/ds4.git
  upstream  https://github.com/Entrpi/ds4.git
  antirez   https://github.com/antirez/ds4.git

spark/ds4-on-spark:
  origin    https://github.com/ZebulonRouseFrantzich/ds4-on-spark.git
  upstream  https://github.com/Entrpi/ds4-on-spark.git
```

The V1 engine lineage begins at resolved `v0.5.6` commit
`df641a7c4358dd6ca3b5acb46cf884a7d42066ed`, not at the engine fork's current
`main`. Phase 00 makes that distinction mechanically visible with a `spark`
branch and exact submodule pin.

Upstream changes are fetched when useful but incorporated only at milestone
boundaries. Never move an active experiment to a floating branch or tag.

### Public clone and private push configuration

Committed submodule URLs use HTTPS. This makes recursive clone work without a
GitHub account or SSH credential. Contributors may configure SSH push URLs or a
Git URL rewrite locally; such preferences never enter `.gitmodules` or project
configuration.

### Generic target and privacy boundary

The only committed execution-target names are `spark` and `local`. Never commit
an operator-specific alias, address, username, identity path, credential,
private model path, or home directory. Real configuration lives in a gitignored
file and local SSH configuration.

Generated benchmark provenance may record physical vendor/model and generic
network characteristics. It must redact access and filesystem details before
artifacts are retained or published.

### Toolchain attribution

Nix pins userspace tools. The execution target owns NVIDIA driver, CUDA, NVCC,
and its validated host compiler during V1. A phase does not combine a
`flake.lock` update, upstream engine update, CUDA/compiler change, and scheduler
candidate in one performance comparison.

### DS4 execution substrate

Scheduler policy may change who gets service and how much bounded prefill work
runs. It must not casually replace DS4's graph-aware decode dispatcher, DSpark,
model-specific C/CUDA structures, warm-state behavior, or continuation
semantics.

### Bounded overload

Temporary capacity pressure is not an internal failure. It is also not
permission for an unbounded queue. Existing client, queue-depth, queued-byte,
queue-age, continuation, cancellation, and `Retry-After` behavior stays in force
unless a phase explicitly changes and qualifies that contract.

### Evidence before expansion

Do not add:

- a new benchmark scenario before a phase needs it;
- a configuration knob without an experiment that consumes it;
- an opt-in trace before counters and existing logs prove insufficient;
- a branch or directory for future work;
- a generalized abstraction for one supported target or model;
- a research implementation before its entry gate passes.

## Repository responsibilities

### `ds4-spark-lab`

Owns:

- exact submodule pairing;
- pinned Nix userspace and root Just workflow;
- generic local/remote target orchestration;
- deterministic benchmark scenarios and prompt corpus;
- baseline manifests, result schemas, comparisons, and reports;
- roadmap status and project decisions.

### `ZebulonRouseFrantzich/ds4`

Owns:

- engine and server request lifecycle;
- admission/capacity classification;
- execution scheduling and graph-path accounting;
- cancellation and overload integration;
- cache/reuse/capacity behavior;
- engine/server metrics and relevant tests.

### `ZebulonRouseFrantzich/ds4-on-spark`

Owns:

- validated GB10 installation and launch integration;
- released engine URL/ref defaults when promoted;
- safe example environment configuration;
- packaged release smoke validation.

Engine work is not considered packaged until the integration fork and umbrella
submodule pairing validate the intended release ref.

## Validation ownership

- The phase implementer owns narrow reproduction and targeted checks.
- The lab harness owns paired target measurements and retained artifacts.
- Integration qualification owns install/build/launch behavior for a released
  engine ref.
- Independent review is required for high-risk state-machine, concurrency,
  memory-lifetime, and graph-boundary changes.
- Focused security review is required for remote process lifecycle, network
  exposure, configuration secrecy, and artifact redaction.

A UI/UX design workstream is not expected; this project has no planned user
interface beyond command-line workflows and reports.

## Updating this roadmap

When evidence changes the plan:

1. update the affected phase's assumptions and gate;
2. update this index if dependencies or status changed;
3. update [`PROJECT.md`](../../PROJECT.md) if an architectural or release
   invariant changed;
4. add a concise decision record only when the choice is consequential and not
   obvious from the phase evidence;
5. preserve rejected results so the same hypothesis is not unknowingly repeated.

Do not silently rewrite a completed phase to match a later result. Record the
new decision and retain the prior evidence.
