# Phase 06 — Long/Short Fairness and V1 Release

## Status

**Planned**

## Depends on

- [Phase 05](phase-05-graph-preserving-scheduler.md) Qualified.
- One selected scheduler candidate and prefill quantum.
- All Phase 04 capacity/cancellation and Phase 05 graph gates remain green.

## Objective

Add the smallest long/short prefill selection policy that bounds starvation,
then qualify and package the complete V1 Agentic Scheduler Core across the
engine, integration, and umbrella repositories.

This phase is both a behavior increment and a release gate. It does not begin
V2 prefix-aware or memory-model work.

## Hypothesis

A two-class prefill policy with waiting-age/bypass credit can reduce TTFT for
shorter agent requests while guaranteeing progress for deep requests, without
materially harming aggregate goodput, active-decode latency, graph replay, or
single-request performance.

## Repositories

| Repository | Phase role |
|---|---|
| Engine fork | Long/short selection, age/bypass credit, starvation bound, V1 tests and release ref |
| Lab repository | S6, full V1 qualification, release report/tag, exact submodule pair |
| Integration fork | Pin and validate the released engine fork/ref; safe V1 launch defaults and smoke |

## Entry criteria

- S2 results show the selected Phase 05 scheduler's heterogeneous prefill
  behavior.
- S3 demonstrates acceptable active-decode cadence.
- The source exposes a stable estimate of remaining prefill work. If reliable
  reusable-prefix information is not yet available, V1 documents and uses the
  best conservative estimate; it does not invent V2 cache metadata.
- V1 numerical gates remain the values declared from the baseline.
- No upstream source, `flake.lock`, CUDA, compiler, or model update is mixed
  into the fairness experiment.
- Independent review and release qualification ownership are assigned.

## Scope

### 1. Long/short classification

Start with one experimental threshold near 64K remaining uncached prefill tokens.
The exact threshold is frozen before candidate comparison.

Classification input priority:

1. reliable engine-reported uncached/remaining prefill work, if already
   available and validated;
2. remaining prefill work under the current V1 representation;
3. conservative logical prompt remainder, documented as an approximation.

Do not introduce the V2 prefix matcher solely to improve this estimate.
Classification is recomputed only when its underlying remaining-work fact
changes meaningfully.

### 2. Selection policy

Keep the Phase 05 service invariant: at most one bounded prefill quantum before
the next normal decode opportunity when live decode exists.

The selector adds only:

- short/long class;
- arrival order within the base policy;
- waiting age or bypass credit;
- a hard starvation bound.

A short request may bypass an older long request within the bound. Each bypass
must make the skipped request more eligible. Once the bound is reached, the
long request receives service at the next safe opportunity for its class.

Do not add generic user priorities, deadlines, cache locality, or weighted fair
queueing in V1.

### 3. S6 scenario

Add a deterministic fairness case approximating:

```text
190K long
180K long
22K short
35K short
```

Use controlled arrival offsets that expose both directions of unfairness:

- long work arrives first, then short work;
- short work continues arriving while long work waits;
- long work must continue to make bounded progress;
- active decode, when present, retains the Phase 05 cadence guard.

Record:

- TTFT and completion for each request;
- wait duration and bypass count;
- long-request prefill progress over time;
- maximum time/service opportunities without progress;
- active-decoder ITL;
- aggregate committed goodput;
- graph path and scheduler decision time;
- failures, sheds, and cancellation.

### 4. Fairness metric

Do not rely on aggregate throughput alone. Report per-request slowdown or
another declared fairness measure relative to an appropriate isolated/control
runtime, plus direct starvation-bound evidence.

The release report must make it impossible for a high aggregate number to hide
a request that stopped making progress.

### 5. Configuration convergence

V1 release configuration contains only knobs that survived experiments:

- candidate/legacy policy switch retained only for documented rollback/A-B;
- selected prefill quantum;
- selected long-prefill threshold;
- selected small bypass/starvation bound.

Remove aliases, rejected experimental settings, and misleading names. Record
resolved values in every run. If the legacy switch is retained for one release,
document its removal criterion and ensure it restores the complete pre-V1
policy rather than a partial mix.

### 6. Full V1 qualification

Run the release candidate through:

- relevant upstream correctness/unit tests;
- CUDA logprob/golden-vector or equivalent quality gates;
- API surfaces used by agent clients;
- tool-call continuation and replay semantics;
- long-context correctness/retrieval gates;
- DSpark qualification;
- S1, S2, S3, S5A, S5B, S6, and S8;
- target-local single/representative-depth controls;
- graph eligibility/replay/fallback gate;
- focused admission/cancellation churn and release soak;
- remote and local lifecycle smoke;
- privacy/redaction checks.

A release candidate uses clean trees, exact committed lock, stable target
software, exact model/drafter hashes, and a constant network path.

### 7. Engine release ref

Create a project-namespaced annotated engine release tag only after engine
qualification, for example `spark-v1.0.0`. Do not reuse or move Entrpi's
`v0.5.6` tag and do not publish a floating branch as the integration default.

The tag annotation records:

- `v0.5.6` resolved base commit;
- qualified lab report/tag;
- primary behavior changes;
- rollback switch/ref;
- relevant source/test identity.

The final tag name is selected once before release and used consistently in all
three repositories.

### 8. Integration-fork release

Update `ZebulonRouseFrantzich/ds4-on-spark` so its validated default or explicit
V1 profile uses:

```text
DS4_REPO=https://github.com/ZebulonRouseFrantzich/ds4.git
DS4_REF=<immutable project V1 engine tag or exact release commit>
```

Requirements:

- preserve override support for other repos/refs;
- keep installer-managed source separate from development submodules;
- validate GB10 detection, target build, model/drafter pairing, launch, and
  deterministic smoke;
- document scheduler settings that differ from upstream defaults;
- avoid embedding any private target configuration;
- retain Entrpi as `upstream` for future synchronization.

An engine-only tag is not the packaged V1 release. Integration validation is
part of the gate.

### 9. Umbrella release

Update both submodule pins to the exact qualified engine and integration
commits. Create a lab release tag such as `release-v1` after the final report and
clean-clone reproduction pass.

The umbrella tag is the canonical pairing manifest. It records the engine
release tag/commit, integration commit, lock identity, baseline tag, and report.

### 10. Documentation and release notes

Update current README/status and user-facing configuration documentation to
state:

- what V1 changes;
- what it deliberately does not change;
- required target class and host-managed CUDA boundary;
- how overload, default output budgets, and rollback behave;
- exact tested commands and evidence;
- V2 remains future work.

Do not claim performance beyond the retained measurements.

## Explicit non-goals

- No prefix-aware locality or conversation affinity.
- No V4 state-lifetime byte model.
- No retention scoring or disk-tier redesign.
- No paged/ref-counted state.
- No host/scheduler overlap.
- No broad scenario matrix or OMP end-to-end release blocker.
- No upstream merge during release qualification.
- No target-specific configuration in integration defaults.

## Deliverables

### Engine fork

- two-class prefill policy;
- age/bypass credit and measured starvation bound;
- selected, cleaned V1 configuration surface;
- focused fairness tests plus all prior V1 tests;
- immutable annotated V1 release tag/commit;
- documented rollback path.

### Lab repository

- S6 scenario and fairness analysis;
- complete raw V1 qualification bundle;
- compact release report;
- exact final engine/integration submodule pins;
- clean-clone reproduction evidence;
- umbrella `release-v1` tag;
- roadmap status updates.

### Integration fork

- immutable engine fork/ref pin or validated V1 profile;
- safe public defaults/examples;
- install/build/launch/smoke evidence;
- release commit pinned by the umbrella.

## Validation

### Fairness candidate comparison

Compare Phase 05 policy against the fairness candidate using S2 and S6, with S1
and S3 guarding aggregate/decode behavior. Run long-arrives-first and sustained
short-arrival variants. Verify the declared bound directly from raw service
timelines.

### Full release battery

Execute all scoped V1 qualification items above from clean committed refs. Any
review-driven source fix invalidates later results in the release sequence;
rerun the affected targeted checks and all release gates that could change.

### Clean reproduction

From a fresh public recursive clone:

1. enter the pinned development environment;
2. verify remotes and exact submodule refs;
3. configure a local ignored target using the public schema;
4. run doctor, sync, target-native build, integration smoke, and benchmark smoke;
5. reproduce at least the release's narrow headline scenarios or documented
   subset without local source modifications.

### Review

DeepReview is required for the final engine delta from `v0.5.6`, emphasizing
fairness/starvation, state ownership, graph boundary, continuation behavior, and
configuration cleanup. Focused security review covers remote lifecycle, LAN
binding guidance, bounded overload, integration installer inputs, and artifact
redaction.

## V1 acceptance gate

V1 is released only when:

1. public recursive clone and pinned Nix/Just workspace are reproducible;
2. generic `spark` and supported `local` operations sync/build/run/collect as
   documented without committing access details;
3. exact controller/source/target/model/config/network identity is retained and
   sanitized;
4. relevant correctness, API, tool, long-context, CUDA quality, and DSpark gates
   pass;
5. S5A feasible transient pressure defers and completes without accidental deep
   serial failure;
6. S5B remains safe and explainable under the recorded default output budget;
7. existing overload bounds and endpoint-native `Retry-After` remain intact;
8. S8 proves cancellation-safe waiting and exactly-once cleanup;
9. S3 meets the predeclared decode-latency/progress gate;
10. S6 proves short-request improvement and a hard long-request starvation
    bound;
11. S1/S2 meet aggregate/workflow and fairness decision gates, or the release
    report explicitly demonstrates independently sufficient reliability/latency
    value under the predeclared policy;
12. single-request and graph-path behavior meet their predeclared non-regression
    gates;
13. no OOM, crash, deadlock, accounting leak, unknown server process, or secret
    leak appears in qualification;
14. integration install/build/launch/smoke passes against the immutable engine
    release ref;
15. required reviews have no unresolved blocking findings;
16. the umbrella tag pins the exact qualified pair and report.

A failed optimistic throughput target does not automatically reject V1 if the
predeclared reliability and latency release rule passes. A failed correctness,
safety, starvation, graph, privacy, or reproducibility gate always rejects it.

## Artifacts

Retain:

- fairness source map and invariant description;
- raw S2/S6 candidate comparisons and direct starvation evidence;
- complete V1 test/benchmark/reliability bundle;
- target-local controls and graph-path report;
- source/environment/model/target/network manifests;
- integration installation and smoke logs;
- review findings/resolutions;
- engine tag, integration commit, lab tag, and exact SHAs;
- V1 release report and rollback instructions.

## Risks and rollback

| Risk | Mitigation / rollback |
|---|---|
| Short preference starves deep requests | Hard service bound proven from raw timelines |
| Long protection removes short TTFT gain | Small threshold/credit policy; S2/S6 paired decision |
| Approximate uncached length misclassifies | Document source; use conservative estimate until V2 |
| Experiment knobs become permanent complexity | Remove rejected knobs and aliases before tag |
| Engine release is not installable | Integration fork pin and clean-install smoke are release gates |
| Release mixes upstream/toolchain changes | Freeze attribution domains throughout qualification |
| Headline hides failed requests | Include every request/failure in goodput and fairness |

Rollback is the exact Phase 04/05 legacy engine ref and prior integration pin,
documented before release. Never move the published release tag; issue a new
project-namespaced tag if a corrected release is needed.

## Exit handoff to Phase 07

Phase 07 receives:

- an immutable, packaged V1 release across all three repositories;
- validated admission, scheduling, fairness, cancellation, and graph invariants;
- reusable S1-S8 measurement infrastructure;
- raw evidence identifying remaining prefix-recompute and cache-locality costs;
- a stable source base on which V2 changes can be attributed independently.
