# Phase 02 — Benchmark Harness and Frozen Baseline

## Status

**Planned**

## Depends on

- [Phase 01](phase-01-execution-target.md) Qualified.
- Reproducible target-native build, lifecycle, and artifact return.
- Exact engine and integration baseline pins unchanged since Phase 01.

## Objective

Build the minimum benchmark system required to characterize the frozen
`v0.5.6` serving behavior and establish authoritative correctness, latency,
throughput, reliability, graph-path, and run-to-run-noise baselines before any
scheduler change.

The baseline is measured on the actual configured GB10 target. Published tables
and upstream claims remain context only.

## Hypothesis

A small deterministic async HTTP/SSE harness with five initial scenario IDs,
target-local controls, exact provenance, and paired-run statistics is sufficient
to evaluate the V1 admission and scheduler hypotheses without building a large
benchmark platform.

## Frozen source

Qualified baseline runs require clean worktrees and exact commits:

```text
engine
  Entrpi/ds4 v0.5.6 resolved commit
  df641a7c4358dd6ca3b5acb46cf884a7d42066ed

integration
  60c00afe24dc361c19e53037b599d98d27f32d7b

lab
  exact Phase 02 qualification commit

userspace
  exact committed flake.lock and locked nixpkgs revision
```

The engine fork's current `main` is not a substitute. A newer Entrpi tag or
branch is not adopted during this phase.

## Repositories

| Repository | Phase role |
|---|---|
| `ds4-spark-lab` | Benchmark package, scenarios, prompts, manifests, result schema, comparisons, baseline artifacts |
| Engine submodule | Frozen server/engine under measurement; no behavior changes |
| Integration submodule | Frozen build/launch integration and smoke reference; no behavior changes |

## Entry criteria

- Controller and target source hashes match.
- Target doctor and target-native frozen build pass.
- Server lifecycle and one functional request are reliable.
- Model and matching drafter content hashes are known locally.
- Target thermal/power state can be observed or held sufficiently stable.
- Controller and target clocks are synchronized well enough for cross-host
  correlation; duration metrics use monotonic clocks regardless.
- A trusted direct LAN path is available for the primary serving view.

## Scope

### 1. Minimal Python package

Create `benchmarks/pyproject.toml`, `benchmarks/uv.lock`, and a small package
under `benchmarks/src/ds4bench/`.

Initial runtime dependencies should remain narrow:

- Python from the locked Nix environment;
- uv from the locked Nix environment;
- `httpx` for async HTTP/SSE;
- `orjson` if measured serialization needs it.

Add schema frameworks, YAML libraries, NVML bindings, report engines, or other
dependencies only when the phase demonstrates a concrete need. Configure uv to
use the Nix-provided Python and reject managed Python downloads. Normal runs use
the frozen lock.

### 2. Stable async client

The client must support the actual OpenAI-compatible endpoint and streaming
shape used by the baseline. For every request, record at least:

```text
scenario run id
request id
scheduled offset
client monotonic send time
connection/HTTP acceptance time
first response byte time
first model token time
per-token monotonic timestamps or derived ITL samples
completion time
HTTP status and retry metadata
finish/error classification
prompt tokens
generated tokens
```

Requirements:

- parse SSE incrementally and correctly across arbitrary chunk boundaries;
- distinguish first byte from first model token;
- never let one slow response serialize unrelated requests;
- use explicit connection/read/overall deadlines;
- preserve endpoint-native error bodies after redaction;
- cancel all owned tasks and invoke target cleanup on harness failure;
- emit raw machine-readable samples before computing summaries.

### 3. Simple scenario format

Use JSON or YAML, selecting the smaller implementation after checking available
dependencies. One format is canonical; do not maintain two parsers.

A scenario describes:

- version and stable name;
- server context/profile;
- request identifiers and start offsets;
- prompt artifact and expected hash/token count;
- explicit or omitted output budget;
- sampling policy;
- concurrency/repetition/warm-up policy;
- client and server deadlines;
- required reset/cold/warm preconditions.

Validate unknown fields and impossible combinations before starting the server.
The schema remains intentionally small and versioned.

### 4. Deterministic prompt corpus

Create only prompts needed by V1:

```text
short general mixed text for S1
approximately 32K mixed text for S1
approximately 25K/35K/80K/180K repo-like material for S2
approximately 186K cold material for S3/S5A/S5B
```

Prompt requirements:

- synthetic or permissively licensed source material;
- committed provenance and license/attribution where required;
- deterministic content;
- content hash;
- exact token count produced by the frozen model tokenizer;
- no secrets, private repository content, personal paths, or generated access
  details;
- no pathological repeated-token filler in headline scenarios.

The target lengths are approximate until tokenized. Freeze actual counts in the
manifest; do not repeatedly edit text to imply false round-number precision.

### 5. Initial scenario family

The initial suite has five IDs in four behavioral families:

#### S1 — concurrency saturation

Start with concurrency:

```text
1, 2, 4, 8, 12, 16
```

Use short and approximately 32K prompts with a bounded generation request.
Record aggregate and per-request throughput, TTFT, ITL distribution, completion
time, fairness, peak memory, live rows, and graph-path data where currently
available.

#### S2 — realistic mixed-agent burst

Start a heterogeneous burst approximating:

```text
planner   ~180K
coder      ~80K
reviewer   ~25K
advisor    ~35K
```

Use an explicit realistic output budget. Record every request timeline,
aggregate goodput, waiting behavior, failures/retries, and total workflow time.

#### S3 — long prefill during active decode

Start several requests, wait until they are observably decoding, then inject an
approximately 186K cold request. Record active-decoder ITL before/during/after,
long-prefill progress, TTFT, completion, and graph path. If the frozen server
cannot expose a precise decode-ready signal, document and validate the smallest
stable external trigger rather than guessing.

#### S5A — explicit deep output budget

Run multiple approximately 186K prompts under an approximately 262K server
context with an explicit realistic generation budget, initially 512 tokens.
Record current admission/fallback/HTTP behavior without declaring it correct.

#### S5B — omitted/default deep output budget

Repeat the same prompt mix while omitting the request output budget. Record the
resolved server default and resulting behavior. S5A and S5B remain separate
because promised output liability is part of admission cost.

S6 and S8 are not implemented here. S8 arrives with deferred capacity; S6
arrives with fairness.

### 6. Two measurement vantage points

#### Primary: controller over trusted LAN

Use for S1/S2/S3/S5A/S5B because it represents the intended agent-serving path.
Report client-observed latency, streaming behavior, status/retry semantics, and
workflow goodput.

#### Control: target local

Use for current upstream engine microbenchmarks, localhost server reference
runs, and small latency/path investigations. Any claimed millisecond-scale
scheduler improvement in later phases must reproduce here.

Do not merge local and LAN samples into one distribution.

### 7. Correctness baseline

Inventory the frozen source's actual test and qualification commands before
running them. Reuse relevant upstream gates rather than inventing replacements.
Capture at least the applicable:

- server/unit tests;
- official or golden logprob/vector checks relevant to CUDA;
- long-context gate;
- API and tool/continuation tests for the measured server path;
- deterministic smoke prompts;
- DSpark qualification used by the frozen release.

Document unavailable or prohibitively expensive gates explicitly. Do not claim
an unexecuted upstream battery passed.

### 8. Result artifact contract

Each run produces a directory identified by scenario, source identity, and run
ID. It should contain:

```text
metadata.json
scenario.json              # normalized resolved scenario
source-manifest.json
requests.jsonl              # raw request samples
server.log                  # sanitized
client.log                  # sanitized
telemetry.jsonl             # only collected fields
summary.json
summary.md
```

Raw results are normally gitignored. Baseline manifests, compact summaries, and
approved reports may be tracked. Model paths, target addresses, usernames,
credentials, and private filesystem details never enter an artifact.

### 9. Statistics and comparison

Default to:

- at least one warm-up for initialization-sensitive scenarios;
- five measured repetitions where runtime permits;
- median plus p50/p95/p99 or max as appropriate;
- raw samples and per-request results, not only aggregates;
- paired baseline/candidate ordering in later phases, preferably alternating or
  ABBA when thermal/time drift matters;
- explicit failure counts and no survivor-only throughput statistics.

Measure baseline variance. Before Phase 03 ends, freeze practical regression and
material-improvement thresholds for V1. A candidate threshold cannot be selected
after viewing candidate results.

### 10. Just interface

Add only implemented recipes, expected to include equivalents of:

```text
bench-smoke [target]
bench-s1 [target]
bench-s2 [target]
bench-s3 [target]
bench-s5a [target]
bench-s5b [target]
bench-v1-baseline [target]
compare <baseline> <candidate>
```

Every recipe must resolve and retain exact source, environment, target, model,
scenario, and vantage-point identity.

## Explicit non-goals

- No engine/server behavior changes.
- No new engine telemetry solely because it would be convenient.
- No S4, S6, S7, S8, cache scenarios, chaos framework, or OMP end-to-end test.
- No automatic tuning or Cartesian parameter sweep.
- No dashboard or database.
- No generic load-testing framework.
- No performance target inferred from published Entrpi results.

## Deliverables

### Lab repository

- locked minimal benchmark Python package;
- stable async HTTP/SSE client;
- one canonical scenario schema;
- licensed deterministic V1 prompt corpus and token manifest;
- S1, S2, S3, S5A, and S5B scenarios;
- raw and summarized result formats;
- paired comparison tool;
- Just recipes;
- tracked frozen baseline manifest/report;
- baseline tag following the agreed naming policy.

### Forks

- no source changes;
- submodule pins remain at exact baseline commits.

## Validation

### Harness behavior

Use a deterministic local fixture or controlled server response only where
needed to validate SSE framing, timing boundaries, error classification,
timeouts, and cancellation. These checks protect the client contract; they do
not stand in for running DS4.

### Target smoke

Run `bench-smoke` through both controller/LAN and target-local paths. Confirm
source identity, lifecycle cleanup, result generation, and redaction.

### Frozen target baseline

On the exact frozen source:

1. run the selected upstream correctness/quality gates;
2. run target-local reference measurements;
3. run S1/S2/S3/S5A/S5B from the controller;
4. repeat enough times to characterize normal variance;
5. inspect every failure/retry rather than dropping it;
6. retain raw samples and a reviewed summary.

## Acceptance gate

Phase 02 is Qualified only when:

1. the exact engine/integration/lab/lock/model/drafter identities are retained;
2. the relevant upstream correctness and quality gates pass or any explicit
   exception is documented without overstating coverage;
3. all five V1 scenario IDs execute end to end and clean up the server;
4. prompt hashes and frozen-token counts are stable and licensed for public use;
5. LAN and target-local measurements are kept distinct;
6. raw samples reproduce every summary statistic;
7. failures, retry responses, and incomplete requests remain in results;
8. baseline variance and proposed V1 decision thresholds are recorded before
   scheduler candidate work;
9. artifacts pass privacy/redaction checks;
10. a clean umbrella baseline commit/tag pins the exact source pair.

## Artifacts

Retain:

- selected upstream command list and observed outcomes;
- source/environment/model/target manifests;
- prompt provenance, hashes, and token counts;
- every raw S1/S2/S3/S5A/S5B run;
- target-local controls;
- baseline variance analysis;
- frozen acceptance-threshold proposal;
- compact reviewed baseline report;
- baseline lab tag and exact commit.

## Risks and rollback

| Risk | Mitigation / rollback |
|---|---|
| Harness measures SSE parsing rather than model timing | Distinguish byte/token events; validate parser; retain raw timestamps |
| LAN noise is mistaken for engine behavior | Paired network path plus target-local controls |
| Prompt corpus cannot be redistributed | Synthetic/permissive sources and explicit provenance |
| Default output budget is misunderstood | Resolve and record it; keep S5A and S5B separate |
| Failed requests disappear from throughput | Include every scheduled request and failure in denominators |
| Benchmark framework grows ahead of features | Reject scenarios/dependencies without a current gate |
| Thermal or initialization drift biases results | Warm-up, alternation, repetitions, target state capture |
| Artifacts leak private target details | Structured redaction and retained-artifact scan |

If the harness cannot produce trustworthy repeatable raw measurements, fix or
reduce the harness. Do not begin engine observability or scheduling changes with
an ambiguous baseline.

## Exit handoff to Phase 03

Phase 03 receives:

- exact frozen source and environment identities;
- passing relevant correctness gates;
- reproducible S1/S2/S3/S5A/S5B scenarios;
- measured baseline behavior, including current deep-capacity outcomes;
- baseline variance and predeclared V1 thresholds;
- a list of observations the current server already exposes and the concrete
  questions it cannot answer.
