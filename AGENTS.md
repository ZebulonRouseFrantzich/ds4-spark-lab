# AGENTS.md

## Scope

These instructions apply to the entire `ds4-spark-lab` repository. Files inside
future Git submodules may contain their own instructions; follow the more local
instructions while preserving this workspace's source-lineage, privacy,
reproducibility, and evidence requirements.

## Project purpose

This repository coordinates a DS4-native agentic serving project for the NVIDIA
GB10 / SM121 target class. It will own exact engine/integration source pairing,
pinned userspace tooling, generic target orchestration, deterministic
benchmarks, result manifests, and release reports.

The project improves serving policy around DS4's specialized C/CUDA substrate.
It is not a mandate to generalize DS4, replace DSpark, or imitate another
runtime's physical batch architecture.

## Current state

The repository is currently in the documentation and planning stage. Do not
assume submodules, Nix files, Just recipes, target automation, benchmark code,
or engine changes exist because a roadmap document describes them.

Before every task, read:

1. [`PROJECT.md`](PROJECT.md);
2. [`docs/roadmap/README.md`](docs/roadmap/README.md);
3. the active phase document;
4. any more local instructions in the files or submodules being changed.

A planned phase is not active merely because it is next in sequence. Verify its
entry criteria and the user's requested scope.

## Source of truth

Use this precedence when documents or assumptions conflict:

1. observed behavior from the exact frozen source/environment;
2. the active phase's accepted evidence and gate;
3. `PROJECT.md` architectural/release invariants;
4. roadmap planning text;
5. external framework comparisons or published performance figures.

Never alter implementation to preserve a disproven planning assumption. Record
the evidence and update the relevant plan first.

## Load-bearing source lineage

The engine fork's current `main` is not the V1 baseline.

```text
Entrpi/ds4 v0.5.6 resolved commit:
  df641a7c4358dd6ca3b5acb46cf884a7d42066ed

current ZebulonRouseFrantzich/ds4 main:
  b0309611041655f4e45671cfd9c9886aff161406

integration baseline:
  60c00afe24dc361c19e53037b599d98d27f32d7b
```

The V1 engine line must be seeded from exact `v0.5.6` commit `df641a7…` on a
project `spark` branch. Never base V1 scheduler changes on the fork's current
`main` by accident. Re-resolve and verify immutable refs before branch or
submodule operations.

## Git remote policy

The writable project fork is `origin`. Entrpi is `upstream`.

```text
engine/ds4:
  origin    https://github.com/ZebulonRouseFrantzich/ds4.git
  upstream  https://github.com/Entrpi/ds4.git
  antirez   https://github.com/antirez/ds4.git

spark/ds4-on-spark:
  origin    https://github.com/ZebulonRouseFrantzich/ds4-on-spark.git
  upstream  https://github.com/Entrpi/ds4-on-spark.git
```

Rules:

- committed `.gitmodules` URLs use public HTTPS;
- SSH push URLs and Git URL rewrites are local contributor preferences;
- additional submodule remotes must be added/verified by an explicit,
  idempotent workspace operation because Git does not propagate them;
- fetch upstream changes when useful, but never merge, rebase, reset, retag, or
  move an active experiment automatically;
- integrate upstream only at a milestone boundary in its own attribution
  change;
- never force-update a shared `spark` or release ref;
- do not create future feature branches before their work begins;
- do not commit, push, tag, or open a PR unless the user requests it.

Treat unexpected worktree changes as contributor work. Do not discard, reset,
or overwrite them.

## Repository responsibilities

### Lab repository

Owns:

- submodule pairing and source manifests;
- Nix userspace and Just workflow;
- generic local/remote target operations;
- benchmark client, scenarios, prompts, schemas, and reports;
- roadmap status and project decisions.

### Engine fork

Owns:

- request/admission lifecycle;
- capacity classification and retry epochs;
- scheduling and graph-path accounting;
- cancellation, overload integration, cache/reuse, and memory policy;
- engine/server tests and metrics.

### Integration fork

Owns:

- validated GB10 install/build/launch path;
- immutable released engine defaults/refs;
- safe public configuration examples;
- packaged release smoke validation.

A multi-repository feature is not complete until the engine/integration changes,
lab harness/report changes, and umbrella submodule pins compose at exact refs.
Do not describe a repository-local PR number as a global phase identity.

## Canonical terminology

Use:

```text
platform class:    DGX Spark
execution target:  spark
same-machine mode: local
SoC/GPU target:    NVIDIA GB10 / SM121
```

Do not create vendor-specific code paths, target types, scenario names, or
documentation branches without measured evidence of a relevant difference.
Physical vendor/model belongs in generated benchmark provenance.

## Privacy and secret boundary

Never place any of the following in tracked files, patches, logs retained in the
repository, examples, tests, or reports:

- private hostnames or LAN addresses;
- SSH usernames, keys, fingerprints, identity paths, or control socket paths;
- operator-specific target aliases;
- credentials, tokens, passwords, or private endpoints;
- private model/drafter paths;
- contributor home-directory paths;
- source prompts, model outputs, or cache payloads that contain private data;
- unsanitized environment dumps;
- access details copied from conversation context.

Committed target configuration is schema/example only and uses placeholders.
Real target definitions live in gitignored local files. SSH address and identity
belong in local SSH configuration. Model/drafter files stay outside synchronized
source and the repository.

Do not print a whole target configuration for debugging. Redact values at the
producer before logs or artifacts are written. A final text replacement is not
a sufficient secret boundary.

## Target safety

Remote execution must use the logical configured target, never a hard-coded
host. Before any remote mutation:

- verify the active phase authorizes remote work;
- validate the dedicated disposable source and run roots;
- reject empty, root, home, parent, model, or otherwise unsafe paths;
- restrict any deletion to the validated disposable source root;
- identify a process before signaling it; never trust a stale PID alone;
- preserve model files and unrelated target data;
- collect/sanitize artifacts back to the controller;
- clean up owned server processes after success, failure, cancellation, or
  interruption.

Do not install target system packages, modify firewall policy, alter drivers,
change CUDA/compiler versions, or persist a service unless explicitly requested
and separately scoped.

## Nix, CUDA, and build boundary

During V1:

- Nix pins userspace development tools through `flake.lock`;
- Just defines normal workspace operations;
- DS4's existing build system builds the engine;
- the execution target owns NVIDIA driver, CUDA, NVCC, and its validated host
  compiler;
- use a no-compiler Nix shell such as `mkShellNoCC`;
- do not put Nix GCC/Clang/CUDA ahead of target tools;
- uv must use the Nix-provided Python and must not download another runtime;
- target doctor must record and compare actual tool paths/versions.

Do not change `flake.lock`, upstream source, target CUDA/compiler, model, and
scheduler policy in the same performance comparison. These are separate
attribution domains.

## Engineering rules

- Fix behavior at the owning source layer; do not special-case benchmark input
  or suppress an error to make a scenario pass.
- Reuse existing source patterns. A second queue, cache index, lifecycle owner,
  config parser, or metrics convention requires explicit evidence.
- Keep DS4 small and model-aware. Do not add generic framework abstractions for
  hypothetical models, targets, or clusters.
- Preserve graph-aware decode, DSpark, continuation, bounded overload, warm
  state, and API semantics unless the active phase explicitly changes and
  qualifies one.
- Prefer bounded enums and fixed-cardinality metrics. Never use request IDs,
  prompt hashes, paths, error strings, conversation IDs, or arbitrary config as
  metric labels.
- Avoid prompt/token copies in scheduler metadata. Store only bounded scalar or
  validated identity data needed by policy.
- Use overflow-checked arithmetic for token/byte projections and test exact
  rounding boundaries.
- Make cancellation and resource ownership explicit. Every request/state is
  settled and released exactly once.
- Preserve a clean comparison/rollback path during experiments. Remove rejected
  alternatives and aliases before release.
- Do not add placeholders, no-op branches, dead feature flags, speculative
  directories, or future scenario scaffolding.

## Research before editing engine code

For an engine phase:

1. freeze exact refs and environment;
2. map the actual symbols/owners in the frozen source;
3. find every caller/consumer before changing shared interfaces;
4. inventory existing tests and observability;
5. record state, lock, stream, graph, cancellation, and lifetime invariants;
6. update the phase's source map if the implementation differs from planning;
7. implement the smallest coherent cutover;
8. migrate all callers and remove obsolete paths.

Do not invent exact C identifiers from roadmap pseudocode. `ADMIT_NOW`,
`DEFER_CAPACITY`, and similar names describe observable concepts until the
source audit chooses the project identifiers.

## Validation contract

Proof depends on the change:

- **Documentation:** local links resolve, required files exist, terminology and
  refs are consistent, and privacy scans pass.
- **Workspace/tooling:** fresh public recursive clone plus the implemented Nix,
  doctor, remotes, and Just checks.
- **Remote operations:** exercise sync/build/lifecycle on the configured target,
  including failure and cleanup paths.
- **Benchmark harness:** run the real client/server path and retain raw samples;
  fixture tests cover parser/timing contracts only.
- **Bug fix:** reproduce the actual bug before and after.
- **Engine behavior:** targeted behavioral tests plus the phase scenarios and
  relevant upstream quality gates.
- **Performance:** paired runs on exact refs/environments, target-local controls
  for small latency claims, raw samples, declared noise/gates, and retained
  failures.
- **Release:** clean refs, full scoped battery, fresh-clone reproduction,
  integration install/smoke, review, exact tags/pins, and rollback evidence.

Never claim a command, target run, performance number, or test passed unless it
was directly observed. State unexecuted coverage explicitly.

## Benchmark discipline

- The actual configured GB10 target baseline is authoritative.
- Keep controller/LAN and target-local measurements separate.
- Use monotonic clocks for durations; synchronized wall time is correlation
  only.
- Record exact scenario/prompt/model/drafter/source/environment identities.
- Retain every scheduled request, error, retry, cancellation, and timeout in
  denominators.
- Do not report survivor-only throughput.
- Freeze thresholds from baseline variance before candidate results.
- Use paired/alternating order when drift matters.
- Reset or preserve cache state exactly as the scenario declares.
- Add a scenario, metric, trace, dependency, or knob only when a current gate
  needs it.
- Raw results are normally untracked; reviewed manifests, summaries, and reports
  may be tracked.
- Prompt corpora must be synthetic or permissively licensed with provenance,
  hash, and frozen token count.

## Review gates

Independent DeepReview is required for high-risk changes involving:

- concurrent C request state machines;
- admission/cancellation ownership;
- CUDA graph boundaries or execution shape;
- memory projection, allocation, refcounts, copy-on-write, or cache lifetime;
- persistence/restore and eviction;
- broad release integration.

Focused security review is required for:

- remote process and filesystem lifecycle;
- LAN binding/exposure guidance;
- configuration parsing and secret handling;
- overload/resource-exhaustion semantics;
- persisted state and artifact redaction;
- installer inputs and release packaging.

Resolve review findings with evidence and rerun affected targeted validation.
Do not accept reviewer output blindly, and do not waive a blocking finding
without a documented technical reason.

## Documentation conventions

- `PROJECT.md` owns stable program invariants and release definitions.
- `docs/roadmap/README.md` owns phase order and status.
- Each phase document owns its entry/scope/deliverables/gate/artifacts/rollback.
- Avoid copying cross-phase policy into new documents; link to the authority.
- Update status only with evidence.
- Do not rewrite a completed phase to hide a rejected result.
- Add a decision record only for a consequential choice not obvious from the
  retained evidence.
- Keep examples generic and executable only when the underlying files/commands
  exist.
- Never claim planned commands currently work in README or user instructions.

## Completion checklist

Before declaring a task complete:

- active phase and scope are satisfied;
- exact repository ownership and all affected callers/consumers are handled;
- no obsolete alias, branch, flag, path, or re-export remains;
- relevant docs/status/submodule pins are updated;
- required direct behavior was exercised;
- targeted and broader gates appropriate to risk passed;
- evidence and exact refs are retained;
- private access/model data is absent from tracked files and artifacts;
- remote owned processes and temporary state are clean;
- rollback is known for behavioral/release changes;
- claims precisely match what was observed.
