# DS4 Spark Agentic Serving Project

## Document status

This is the master project specification for `ds4-spark-lab`. It records the
program goal, architectural invariants, repository relationships, release
boundaries, and validation policy. The executable work breakdown lives in
[`docs/roadmap/`](docs/roadmap/README.md).

The documents have the following authority:

1. Measured behavior from a frozen source and environment baseline.
2. The active phase document and its acceptance gate.
3. This master specification.
4. Research comparisons and planning estimates.

When an upstream change or measurement invalidates an assumption, update the
relevant phase document and this specification before changing implementation
scope. Published performance figures are orientation, not acceptance truth.

## Mission

Build and qualify a DS4-native serving stack for agentic coding workloads on
the NVIDIA GB10 / SM121 target class. Improve scheduling, capacity handling,
cache reuse, fairness, and fleet goodput without turning DS4 into a generic
inference framework or sacrificing its specialized C/CUDA execution path.

The primary workload consists of multiple concurrent OpenAI-compatible agents
with long contexts, repeated prefixes, tool calls, multi-turn continuations,
and heterogeneous latency requirements. The primary optimization target is
useful completed agent work per wall-clock time, not an isolated single-stream
tokens-per-second headline.

## Program scope

### V1: Agentic Scheduler Core

V1 is the immediate release target:

- establish a reproducible three-repository workspace;
- support a generic controller-to-execution-target workflow plus local mode;
- freeze and measure an exact DS4 `v0.5.6`-derived baseline;
- add only observability required by the next scheduling experiment;
- distinguish immediate admission, temporary capacity pressure, impossible
  requests, and bounded overload shedding;
- schedule bounded eager prefill service around the existing graph-aware decode
  path;
- add long/short prefill fairness and a starvation bound;
- qualify correctness, reliability, graph behavior, latency, and performance.

### V2: Cache and Capacity Intelligence

V2 begins only after V1 is stable:

- schedule using uncached work and reusable-prefix information;
- represent DeepSeek-V4 compute and memory liability separately;
- account for heterogeneous state lifetimes in a common raw-token coordinate
  system;
- add conversation affinity where it reduces work without causing starvation;
- improve retention, aging, and persisted-cache policy.

### V3: Gated engine research

V3 is not a promised release. It contains independent research tracks that
start only after an entry measurement demonstrates a likely benefit:

- paged or ref-counted shared-prefix state with copy-on-write tails;
- deeper graph-shape experiments;
- scheduler/host overlap when profiling shows material host-side bubbles.

See [`docs/roadmap/research-backlog.md`](docs/roadmap/research-backlog.md).

## Non-goals

The initial project does not include:

- a generic model-serving framework;
- replacement of DSpark;
- arbitrary mixed execution shapes merely to imitate another runtime;
- prefill/decode disaggregation on a single GB10 device;
- distributed KV storage or cluster orchestration;
- Kubernetes, Slurm, or a custom deployment daemon;
- Nix ownership of the target's NVIDIA driver, CUDA toolkit, NVCC, or host
  compiler during V1;
- a comprehensive benchmark, tracing, chaos, or ADR platform before the
  corresponding feature needs it;
- vendor-specific target classes without measured evidence of a meaningful
  hardware or firmware difference.

## Baseline lineage

The engine baseline is not the current default branch of the engine fork.
This distinction is load-bearing.

Verified repository state on 2026-08-08:

| Repository/ref | Resolved commit | Role |
|---|---|---|
| `Entrpi/ds4` tag `v0.5.6` | `df641a7c4358dd6ca3b5acb46cf884a7d42066ed` | Engine baseline; tag is on Entrpi's `batched-serving` lineage |
| `Entrpi/ds4` `main` | `b0309611041655f4e45671cfd9c9886aff161406` | Different lineage; not the V1 baseline |
| `ZebulonRouseFrantzich/ds4` `main` | `b0309611041655f4e45671cfd9c9886aff161406` | Current fork default; must not be mistaken for `v0.5.6` |
| `Entrpi/ds4-on-spark` baseline | `60c00afe24dc361c19e53037b599d98d27f32d7b` | Integration baseline whose installer pins `v0.5.6` |
| `ZebulonRouseFrantzich/ds4-on-spark` `main` | `60c00afe24dc361c19e53037b599d98d27f32d7b` | Current synchronized integration fork |

Phase 00 will create the engine fork's `spark` branch from the exact resolved
`v0.5.6` commit and publish that branch to the writable fork. Scheduler work
must not start from the fork's current `main`.

Every baseline and qualified result records exact commits rather than relying
on a branch or tag name alone.

## Repository model

The project uses three repositories and one workspace:

| Repository | Responsibility |
|---|---|
| [`ZebulonRouseFrantzich/ds4`](https://github.com/ZebulonRouseFrantzich/ds4) | Engine scheduler, capacity, cache, and server behavior |
| [`ZebulonRouseFrantzich/ds4-on-spark`](https://github.com/ZebulonRouseFrantzich/ds4-on-spark) | Validated GB10 integration, installer defaults, and release smoke path |
| [`ZebulonRouseFrantzich/ds4-spark-lab`](https://github.com/ZebulonRouseFrantzich/ds4-spark-lab) | Workspace, submodule pairing, Nix/Just workflow, target orchestration, benchmarks, manifests, and reports |

The umbrella repository will contain both forks as Git submodules. Committed
`.gitmodules` entries use public HTTPS URLs so anonymous users and hosted CI
can clone recursively. Contributor authentication and SSH push preferences are
local configuration, not repository policy.

### Fork remote policy

Inside `engine/ds4`:

```text
origin    https://github.com/ZebulonRouseFrantzich/ds4.git
upstream  https://github.com/Entrpi/ds4.git
antirez   https://github.com/antirez/ds4.git
```

Inside `spark/ds4-on-spark`:

```text
origin    https://github.com/ZebulonRouseFrantzich/ds4-on-spark.git
upstream  https://github.com/Entrpi/ds4-on-spark.git
```

`origin` is the writable project fork. `upstream` is the corresponding Entrpi
repository and is the source for deliberate upstream synchronization. The
engine's optional `antirez` remote is an architectural comparison source, not
the V1 base.

Fetch upstream changes freely. Do not automatically merge, rebase, update a
submodule, or move an active experiment to a newer upstream ref. Upstream
integration occurs at milestone boundaries in an isolated change with
correctness and benchmark qualification.

### Branch and release policy

Start with:

```text
main   tracks the corresponding Entrpi default branch when deliberately synced
spark  known-good integrated project line
```

Create short-lived feature branches only when implementing their phase. A lab
commit pins an exact pair of submodule commits. Meaningful release or baseline
tags live on the lab repository; raw result metadata still carries every exact
commit and environment identity.

Engine and integration changes require a corresponding umbrella submodule-pin
update. A V1 or V2 release also includes a validated integration-fork update;
an engine-only change is not a complete packaged release.

## Platform terminology and portability

Use these canonical terms:

```text
Project repository:  ds4-spark-lab
Platform class:       DGX Spark
Execution target:     spark
SoC / GPU:            NVIDIA GB10 / SM121
Local mode:           local
```

`DGX Spark` names the supported GB10 target class. Compatible systems are one
platform abstraction unless measurements prove a relevant vendor-specific
difference. Code, scenarios, Just recipes, and documentation must not contain
operator-specific target names or vendor branches.

Generated benchmark provenance records the physical unit separately:

```text
hardware_vendor
hardware_model
soc
gpu
compute_capability
firmware
```

That provenance does not create a platform-specific code path.

## Privacy and secret boundary

The repository must never contain:

- LAN addresses or resolvable private hostnames;
- SSH usernames, keys, identity-file paths, or connection aliases tied to an
  operator's machine;
- credentials, tokens, passwords, or private endpoints;
- private model or drafter paths;
- home-directory paths copied from a contributor's workstation;
- secrets in benchmark logs, manifests, reports, or failure output.

Committed configuration contains schemas and placeholders only. Real target
configuration lives in a gitignored local file and may refer to a generic
logical SSH alias named `spark`. SSH identity and address details belong in the
operator's local SSH configuration. Model and drafter files remain outside the
repository.

## Planned workspace

```text
ds4-spark-lab/
├── PROJECT.md
├── README.md
├── AGENTS.md
├── flake.nix
├── flake.lock
├── nix/
│   ├── dev-shell.nix
│   ├── tooling.nix
│   └── checks.nix
├── Justfile
├── dev
├── engine/
│   └── ds4/                    # public-HTTPS submodule to the engine fork
├── spark/
│   └── ds4-on-spark/           # public-HTTPS submodule to the integration fork
├── benchmarks/
│   ├── pyproject.toml
│   ├── uv.lock
│   ├── src/ds4bench/
│   ├── scenarios/
│   ├── prompts/
│   ├── manifests/
│   ├── baselines/
│   ├── results/                # normally gitignored raw artifacts
│   └── reports/
├── configs/
│   └── targets.example.toml
├── targets/                    # gitignored local target definitions
├── scripts/
│   ├── remote/
│   └── bench/
└── docs/
    ├── roadmap/
    └── decisions/              # consequential decisions only, when needed
```

This is a target layout, not permission to scaffold unused directories. Each
phase adds only the files needed to pass its gate.

## Development environment boundary

Nix defines reproducible userspace development tools. Just defines the normal
project workflow. DS4's existing build system continues to build the engine.

V1 uses a pinned `nixpkgs-unstable` input and committed `flake.lock`. Project
Nix logic stays under `nix/`, with a thin root `flake.nix`. The development
shell uses `mkShellNoCC` or an equivalent no-compiler approach so it does not
silently replace the target's validated compiler toolchain.

Nix may provide tools such as Git, Just, Python, uv, jq, curl, OpenSSH, rsync,
ShellCheck, and formatters. During V1, it must not own or shadow:

- the NVIDIA driver;
- the CUDA runtime/toolkit;
- NVCC;
- the host C/C++ compiler selected for NVCC;
- target-specific firmware or runtime configuration.

`flake.lock`, upstream source, CUDA, compiler, and scheduler logic are separate
attribution domains. Do not change more than one domain in a performance A/B
experiment.

## Operating topology

The preferred topology separates control work from inference execution:

```text
controller/development/benchmark host
    source + Git + Nix + Just
    benchmark clients and reports
    authoritative results
             |
             | SSH control and source synchronization
             | HTTP/SSE workload traffic
             v
DGX Spark execution target
    disposable synchronized source/build tree
    host-managed CUDA/NVCC/compiler
    model and drafter files
    ds4-server and target-local controls
```

The target is an execution appliance, not a second independently edited source
checkout. Native builds occur where the GB10 runtime lives. The controller
retains authoritative source, manifests, raw results, and reports. A supported
`local` mode runs the same workflow directly on a compatible target.

Remote automation remains intentionally narrow: SSH, rsync, explicit process
lifecycle, and a named target configuration. Source deletion, when necessary,
is restricted to the dedicated disposable target work directory and can never
reach model files or unrelated data.

## Serving architecture

```text
OpenAI-compatible agent client
            |
            v
       ds4-server API
            |
            v
 request and admission state
            |
      +-----+------+
      |            |
      v            v
reuse metadata   capacity classification
      |            |
      +-----+------+
            |
            v
 execution scheduler
 dynamic policy, constrained shapes
      +-----+------+
      |            |
      v            v
bounded eager    graph-aware decode/spec pack
prefill service  with observable eager fallback
      +-----+------+
            |
            v
       DS4 C/CUDA engine
```

The central rule is:

> Make scheduling policy dynamic while keeping execution shapes deliberately
> constrained.

Borrow scheduling concepts from other runtimes without forcing DS4 to adopt
their physical batch construction or generality.

## V1 admission contract

Capacity classification and server overload policy are different decisions.
Conceptually:

```text
ADMIT_NOW          engine can place the request now
DEFER_CAPACITY     request is valid but current capacity is transiently busy
REJECT_IMPOSSIBLE  request cannot fit under the configured hard constraints
UNSUPPORTED        request needs an unsupported execution path
FATAL              internal failure

SHED_OVERLOAD      server policy rejected bounded queue/client/byte/age pressure
```

The exact C enum and names are chosen only after auditing the frozen source.
The documentation must consistently distinguish the one-shot
`DEFER_CAPACITY` result from a request's persistent `WAITING_CAPACITY` state.

Expected lifecycle:

```text
QUEUED
  +-- WAITING_CAPACITY -- retry after a meaningful capacity epoch
  +-- PREFILLING
  +-- DECODING
  +-- FINISHED

terminal/side outcomes:
  CANCELLED / ABORTED_CLIENT
  REJECT_IMPOSSIBLE
  SHED_OVERLOAD
  FAILED_INTERNAL
```

A temporary capacity condition must not accidentally enter the deep serial
fallback. Deferred work remains bounded by existing client, queue depth, queued
byte, queue age, continuation-protection, and cancellation semantics. Honest
429/503 responses with `Retry-After` remain valid outcomes under overload.

## V1 execution contract

V1 preserves the existing graph-aware decode dispatcher where possible:

1. process completions and cancellations;
2. reconsider deferred requests only after a meaningful capacity change;
3. select at most one pending prefill request initially;
4. run one allowed eager prefill quantum when decode-latency policy permits;
5. run the normal live decode/speculative pack through the existing graph-aware
   path;
6. update accounting and repeat.

The first experimental prefill ladder is deliberately small: 256, 512, and
1024 tokens. Wider quanta, multiple partial prefills, or alternative graph
classes require evidence from the prior experiment.

Graph eligibility, replay, eager fallback, fallback reason, live rows, and
scheduler decision time are first-class measurements. A scheduler win that
silently destroys graph replay is not accepted.

## Benchmark strategy

The benchmark system is a project asset, but it grows just in time.

### V1 scenarios

- **S1:** concurrency saturation sweep;
- **S2:** realistic mixed-agent burst;
- **S3:** long prefill arriving during active decode;
- **S5A:** deep-capacity pressure with an explicit realistic output budget;
- **S5B:** the same pressure with omitted/default output budget;
- **S6:** long/short prefill fairness, added with the fairness phase;
- **S8:** queued-client cancellation, added with deferred capacity.

### V2 scenarios

- **C1:** shared-prefix fan-out;
- **C2:** multi-turn agent simulation;
- **C3:** conversation suspend/resume;
- **C4:** retention pressure;
- **C5:** interrupted prefill and retry when the touched behavior requires it.

### Measurement layers

1. Existing upstream correctness and quality gates.
2. Target-local engine and server controls.
3. Controller-to-target HTTP/SSE workload measurements.
4. Cache/agentic workflow scenarios added with V2.
5. Targeted cancellation, soak, and reliability cases added with the behavior
   they protect.

LAN measurements are the headline serving view. Millisecond-scale scheduler or
server claims must also reproduce in a target-local control. Small differences
inside normal run-to-run noise are not wins.

### Required result identity

Every qualified run records at least:

- lab, engine, and integration repository URLs and exact commits;
- dirty/clean state and synchronized-source content identity;
- `flake.lock` hash and locked nixpkgs revision;
- controller OS/kernel/architecture and relevant tool versions;
- target OS/kernel/architecture, CUDA, driver, NVCC, and host compiler;
- physical hardware provenance without access details;
- model and drafter content hashes, never private paths;
- server arguments and environment with secret redaction;
- scenario and prompt hashes plus exact model token counts;
- client vantage point and generic network characteristics;
- warm-up policy, repetitions, raw samples, summaries, and failure outcomes.

Acceptance thresholds are frozen after baseline variance is measured and before
candidate results are interpreted.

## Roadmap and dependency order

```text
Phase 00  workspace bootstrap and correct source lineage
    -> Phase 01  generic execution target
    -> Phase 02  benchmark harness and frozen baseline
    -> Phase 03  observability gap audit
    -> Phase 04  bounded deferred capacity
    -> Phase 05  graph-preserving scheduler
    -> Phase 06  fairness and V1 release
    -> Phase 07  prefix-aware scheduling
    -> Phase 08  V4 capacity accounting
    -> Phase 09  retention and V2 release
    -> gated independent research only when measurements justify it
```

No engine-policy phase begins before Phase 02 establishes the baseline. A later
phase may be reordered only by an explicit decision that records its dependency
and validation impact.

## Release definitions of done

### V1

V1 is complete when:

1. all three repositories are reproducibly paired from the umbrella workspace;
2. public recursive clone, pinned Nix userspace, root Just workflow, generic
   remote target, and local mode work as documented;
3. exact source/environment/model/network identity is captured for qualified
   results without leaking access information;
4. relevant upstream correctness, API, tool, long-context, and DSpark gates pass;
5. feasible transient deep-capacity requests defer and eventually progress
   instead of accidentally reaching deep serial failure;
6. bounded overload and `Retry-After` semantics remain intact;
7. cancellation removes waiting work without beginning prompt computation or
   leaking capacity;
8. long prefill and active decode coexist under an explicit latency policy;
9. long and short requests have a measured starvation bound;
10. single-request performance remains within the predeclared regression gate;
11. graph eligibility/replay remains within its predeclared gate;
12. S1/S2 demonstrate useful throughput/workflow value, or the reliability and
    latency value independently justifies release;
13. the integration fork is updated and validates the released engine ref.

V1 does not require paged state, retention scoring, host overlap, or a large
benchmark matrix.

### V2

V2 is complete when:

- scheduling uses measured reusable-prefix and uncached-work information;
- compute and memory capacity are represented and validated separately;
- DeepSeek-V4 state-lifetime projections track observed high-water behavior;
- affinity and retention reduce recomputation without starvation or corruption;
- C1-C4 demonstrate useful end-to-end gains;
- the V1 reliability, correctness, graph, and non-regression gates remain green;
- the integration fork validates the V2 engine release.

### Research

A shared-prefix allocator succeeds only if it preserves exact model behavior,
reduces physical copy/residency cost, increases useful concurrency, and improves
real shared-prefix workload goodput. Host overlap succeeds only if profiling
first shows a material host bottleneck and the implementation measurably reduces
it.

## Risk and review policy

High-risk areas include C state-machine transitions, cancellation races, queue
ownership, CUDA graph eligibility, memory projection, cache lifetime, and
copy-on-write/refcount correctness. These phases require focused tests and
independent code review before release. Remote lifecycle, LAN exposure, target
configuration, and artifact redaction require focused security review.

Principal risks and responses:

| Risk | Required response |
|---|---|
| Scheduler flexibility destroys graph gains | Preserve dispatcher boundaries; measure eligible/replay/fallback behavior |
| Deferred capacity becomes an unbounded queue | Retain depth/byte/age/client bounds and honest shedding |
| Output liability is mistaken for a capacity defect | Keep explicit and default-budget scenarios separate |
| Throughput masks starvation | Report per-request latency, age, progress, and fairness |
| V4 memory projection is wrong | Compare projected and observed high-water marks before hard enforcement |
| Prefix locality starves cold work | Limit locality bypass and apply age/starvation credit |
| Shared pages corrupt state | Separate research gate with immutable prefixes, refcounts, COW, and deep correctness tests |
| Tooling changes contaminate performance attribution | Freeze source, lock, CUDA, compiler, and network domains independently |
| Remote synchronization damages target data | Restrict all destructive behavior to a dedicated disposable work directory |
| Public artifacts leak private configuration | Schema-only committed config, redaction checks, and generated-metadata review |
| Submodules impede contributors | Public HTTPS URLs and Just recipes; revisit only after measured friction |
| Upstream drift invalidates comparisons | Exact commits and milestone-boundary synchronization |

## Change discipline

Implement the minimum machinery needed to test the next hypothesis. Each phase
must state its scope, non-goals, exact repository changes, validation commands,
acceptance gate, artifacts, and rollback. Do not create future knobs, branches,
scenarios, abstractions, or directories merely because the long-term roadmap
mentions them.

A phase is complete only after its observable behavior is exercised on the
relevant target and its evidence is retained. A passing test written alongside
a change is not sufficient evidence for performance or operational claims.

## Research influences

The project borrows concepts selectively:

- [Entrpi/ds4](https://github.com/Entrpi/ds4): specialized execution substrate,
  continuous serving, DSpark, graph-aware decode, warm/persistent state;
- [Entrpi/ds4-on-spark](https://github.com/Entrpi/ds4-on-spark): GB10 build and
  integration path;
- [vLLM scheduler documentation](https://docs.vllm.ai/en/stable/api/vllm/config/scheduler/):
  bounded scheduling, partial prefill, and queue policy concepts;
- [TensorRT-LLM documentation](https://nvidia.github.io/TensorRT-LLM/):
  model-specific capacity and state-lifetime concepts;
- [SGLang documentation](https://docs.sglang.io/): prefix-aware locality and
  cache-policy concepts.

These are hypothesis sources, not implementation templates. DS4 remains a
small, specialized native engine at every release level.
