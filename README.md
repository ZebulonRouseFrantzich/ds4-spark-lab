# ds4-spark-lab

`ds4-spark-lab` is the umbrella workspace and measurement program for a
DS4-native agentic scheduler, capacity, cache, and benchmark stack on the
NVIDIA GB10 / SM121 target class.

The project extends the specialized
[`Entrpi/ds4`](https://github.com/Entrpi/ds4) serving substrate rather than
replacing it with a generic inference framework. Its primary workload is a
fleet of coding agents with long contexts, repeated prefixes, tool calls,
multi-turn continuations, and mixed latency requirements.

## Current status

**Planning and documentation.**

The implementation roadmap is defined, but the workspace submodules, Nix/Just
tooling, target orchestration, benchmark harness, and engine changes have not
yet landed. Commands described in later phase documents are acceptance targets,
not claims about the current checkout.

Start with:

- [Master project specification](PROJECT.md)
- [Roadmap and phase status](docs/roadmap/README.md)
- [Repository instructions for coding agents](AGENTS.md)

## Project goal

Improve useful multi-agent work per wall-clock time while preserving what makes
DS4 valuable:

- native, model-aware C/CUDA execution;
- DSpark speculative decoding;
- graph-aware continuous decode;
- bounded server and overload behavior;
- warm, forked, and persisted state;
- a narrow implementation surface optimized for DeepSeek-V4 on GB10.

The central architectural rule is:

> Make scheduling policy dynamic while keeping execution shapes deliberately
> constrained.

V1 schedules bounded eager prefill service around the existing graph-aware
decode path. It does not force arbitrary mixed batches into new CUDA graphs.

## Release scope

### V1 — Agentic Scheduler Core

- reproducible three-repository workspace;
- generic controller/target and local execution modes;
- frozen `v0.5.6`-derived baseline;
- minimal scheduler benchmark harness;
- observability gap audit;
- bounded deferred capacity;
- graph-preserving prefill/decode scheduling;
- long/short prefill fairness;
- full engine, integration, and benchmark release qualification.

### V2 — Cache and Capacity Intelligence

- reusable-prefix and uncached-work-aware scheduling;
- DeepSeek-V4 compute and memory capacity accounting;
- raw-token coordinate mapping to physical state;
- conversation affinity where justified;
- retention, aging, and existing disk-tier policy.

### Research

Paged/ref-counted shared prefixes, deeper graph shapes, and host overlap remain
measurement-gated experiments. They are not V1 or V2 promises.

## Repository topology

| Repository | Role |
|---|---|
| [`ZebulonRouseFrantzich/ds4`](https://github.com/ZebulonRouseFrantzich/ds4) | Engine and server fork |
| [`ZebulonRouseFrantzich/ds4-on-spark`](https://github.com/ZebulonRouseFrantzich/ds4-on-spark) | GB10 integration and release packaging fork |
| [`ZebulonRouseFrantzich/ds4-spark-lab`](https://github.com/ZebulonRouseFrantzich/ds4-spark-lab) | Workspace, source pairing, tooling, target orchestration, benchmarks, and reports |

The two forks will be public-HTTPS Git submodules in this repository.
Anonymous recursive clone and hosted CI must not require GitHub SSH
credentials.

Inside each fork, Git remotes follow the standard writable-fork/upstream model:

```text
engine/ds4:
  origin    https://github.com/ZebulonRouseFrantzich/ds4.git
  upstream  https://github.com/Entrpi/ds4.git
  antirez   https://github.com/antirez/ds4.git

spark/ds4-on-spark:
  origin    https://github.com/ZebulonRouseFrantzich/ds4-on-spark.git
  upstream  https://github.com/Entrpi/ds4-on-spark.git
```

`origin` is writable. Entrpi is always `upstream`. Upstream changes are fetched
as needed but incorporated only at deliberate milestone boundaries.

## Baseline warning

The current engine fork's `main` is **not** the V1 baseline.

```text
Entrpi/ds4 v0.5.6 resolved commit:
  df641a7c4358dd6ca3b5acb46cf884a7d42066ed

current engine fork main:
  b0309611041655f4e45671cfd9c9886aff161406
```

The `v0.5.6` commit is on Entrpi's `batched-serving` lineage. Phase 00 will seed
the fork's `spark` branch from the exact resolved commit before adding the
engine submodule. Scheduler work must not start from the fork's current `main`.

## Roadmap

| Phase | Deliverable |
|---|---|
| [00](docs/roadmap/phase-00-workspace-bootstrap.md) | Workspace bootstrap and correct source lineage |
| [01](docs/roadmap/phase-01-execution-target.md) | Generic execution target and local mode |
| [02](docs/roadmap/phase-02-benchmark-baseline.md) | Minimal harness and authoritative frozen baseline |
| [03](docs/roadmap/phase-03-observability-audit.md) | Source/metrics audit and minimal missing observations |
| [04](docs/roadmap/phase-04-deferred-capacity.md) | Bounded deferred capacity and cancellation |
| [05](docs/roadmap/phase-05-graph-preserving-scheduler.md) | Graph-preserving execution scheduler |
| [06](docs/roadmap/phase-06-fairness-and-v1-release.md) | Long/short fairness and packaged V1 release |
| [07](docs/roadmap/phase-07-prefix-aware-scheduling.md) | Prefix-aware and uncached-work scheduling |
| [08](docs/roadmap/phase-08-v4-capacity-accounting.md) | DeepSeek-V4 capacity accounting |
| [09](docs/roadmap/phase-09-retention-and-v2-release.md) | Retention policy and packaged V2 release |
| [Research](docs/roadmap/research-backlog.md) | Independently gated experimental tracks |

The dependency order is intentional. No engine-policy work starts before the
target workflow and frozen baseline are trustworthy.

## Planned operating model

```text
controller/development/benchmark host
  authoritative source
  Nix userspace + Just workflow
  benchmark clients, results, reports
             |
             | SSH/rsync control and source synchronization
             | HTTP/SSE serving workload
             v
DGX Spark execution target
  disposable synchronized source/build tree
  host-managed NVIDIA driver/CUDA/NVCC/compiler
  model and drafter outside the repository
  ds4-server and target-local controls
```

The controller owns source and evidence. The target builds and runs natively.
A compatible same-machine `local` mode follows the same operation contract.
This is a one-target abstraction, not a deployment or cluster framework.

## Reproducibility boundary

Nix will pin userspace development tools through `flake.lock`. Just will define
the normal project workflow. During V1, the execution target retains ownership
of:

- NVIDIA driver and runtime;
- CUDA toolkit and NVCC;
- host C/C++ compiler accepted by NVCC;
- target firmware and system configuration.

Qualified results record exact lab/engine/integration commits, dirty state,
source-content identity, Nix lock, target toolchain, model/drafter hashes,
scenario/prompt hashes, and measurement vantage point.

## Privacy and portability

Committed project files never contain:

- private hostnames or LAN addresses;
- SSH usernames, keys, or identity paths;
- credentials or private endpoints;
- operator-specific target aliases;
- private model/drafter paths;
- contributor home-directory paths;
- secrets in benchmark logs or reports.

The canonical logical target is `spark`; same-machine mode is `local`. Real
target configuration is gitignored and based on a committed placeholder-only
schema. Generated benchmark provenance may record physical hardware
vendor/model, but never access details.

## Benchmark philosophy

- Measure the actual configured GB10 target; published numbers are context.
- Keep LAN serving results separate from target-local controls.
- Retain raw samples and failures, not only successful aggregates.
- Freeze acceptance thresholds from baseline variance before candidate runs.
- Change one attribution domain at a time.
- Add scenarios, telemetry, and knobs only when the next hypothesis needs them.
- Correctness, cancellation, bounded overload, graph behavior, and
  reproducibility are release gates, not optional context.

## Contributing

Before implementation:

1. read [PROJECT.md](PROJECT.md);
2. read the active phase and its dependencies;
3. follow [AGENTS.md](AGENTS.md);
4. verify exact source lineage and repository ownership;
5. keep changes inside the active phase's scope;
6. run the phase's narrow validation before broader qualification;
7. retain evidence for behavioral or performance claims.

Do not pre-create future branches, knobs, scenarios, directories, or generic
abstractions. Implement the minimum complete change needed to test the active
hypothesis.

## License

This repository is licensed under the [MIT License](LICENSE). Git submodules
remain governed by their own license files.
