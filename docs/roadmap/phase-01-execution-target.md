# Phase 01 — Generic Execution Target

## Status

**Active — 2026-08-08.** Phase 00 is qualified; implementation and target
qualification are in progress on `phase/01_execution_target`. Core target
operations (doctor, sync, build, lifecycle, smoke, cleanup, artifact bundle)
and Phase 01 Just recipes are implemented. 77 tests pass.

## Depends on

- [Phase 00](phase-00-workspace-bootstrap.md) Qualified.
- Exact engine and integration submodule pins established.
- Pinned Nix userspace and functional root Just workflow.

## Objective

Implement a small, generic, reproducible control path from the authoritative
workspace to one GB10 execution target, while supporting the same operations in
`local` mode. Native build and runtime remain on the target. Source and results
remain authoritative on the controller.

This phase proves target synchronization, build, smoke serving, lifecycle, and
artifact return. It does not implement the custom benchmark suite or modify
engine behavior.

## Hypothesis

SSH, rsync, explicit manifests, and deterministic process lifecycle are enough
to operate one execution target safely and reproducibly. A custom daemon,
cluster abstraction, or target-specific code path is unnecessary.

## Repositories

| Repository | Phase role |
|---|---|
| `ds4-spark-lab` | Target schema, local config boundary, orchestration, doctor, sync, build, serve, stop, artifact collection |
| Engine submodule | Frozen source built natively; no source changes |
| Integration submodule | Existing GB10 build/install knowledge and smoke path; no behavior changes expected |

## Entry criteria

- A clean public clone passes Phase 00 checks.
- The execution target is reachable through operator-managed local SSH
  configuration.
- The operator has provisioned a dedicated disposable target work directory.
- Required model and drafter artifacts already exist outside the repository.
- The target has a supported NVIDIA driver, CUDA toolkit, NVCC, and host
  compiler.
- Direct LAN serving, if used, is restricted to a trusted network by local
  firewall policy.

None of those private values are copied into the repository or qualification
report.

## Operating contract

```text
controller
  authoritative source and submodule worktrees
  Nix/Just orchestration
  source manifests and returned artifacts
          |
          | SSH + rsync for control/source
          | HTTP/SSE for serving smoke
          v
execution target: spark
  disposable synchronized source tree
  target-native build output
  host-managed CUDA/NVCC/compiler
  model and drafter files outside synchronized tree
  explicit run directory and process identity
```

The execution target is not an independently edited Git checkout. A target
cleanup or reinstall must not destroy the authoritative source or evidence.

## Scope

### 1. Committed target schema and ignored local configuration

Commit a schema/example such as `configs/targets.example.toml`. Ignore real
files under `targets/`.

The schema needs only fields used by V1:

```toml
name = "spark"
mode = "ssh"
ssh_host = "<logical-ssh-alias>"
workdir = "<dedicated-disposable-work-directory>"
run_dir = "<dedicated-process-and-log-directory>"
api_base_url = "http://127.0.0.1:<port>"
model_path = "<target-local-model-path>"
drafter_path = "<target-local-drafter-path>"
```

Also support:

```toml
name = "local"
mode = "local"
```

The committed example is documentation, not a working local target. It contains
no real address, username, host alias, home directory, credential, or model
path. Configuration parsing must fail clearly on missing required values and
must never print secret-bearing values indiscriminately.

Phase 01 deliberately supports loopback serving only. In `ssh` mode the
controller functional smoke reaches that endpoint through a bounded,
operation-owned SSH forward. Direct trusted-LAN measurement remains a Phase 02
concern and is not enabled by a declarative configuration assertion.

### 2. Target doctor

Add a target-doctor operation that reports and validates the facts needed for
build/runtime attribution:

- target architecture and OS/kernel;
- GB10 / SM121 identity and compute capability;
- NVIDIA driver/runtime visibility;
- CUDA and NVCC path/version;
- host C and C++ compiler path/version accepted by NVCC;
- required build utilities;
- available memory and disk for the dedicated work/run directories;
- model and drafter existence/readability without printing private paths;
- time synchronization status;
- API/firewall assumptions that can be checked without changing policy;
- optional target Nix identity, if present.

The doctor must detect if entering the Nix shell changes the target compiler or
CUDA resolution. If Nix is absent on the target, native host utilities remain a
supported path.

Doctor output used in reports is sanitized before retention.

### 3. Source snapshot and synchronization

Synchronize the actual controller worktrees, including supported dirty and
untracked source files, into the dedicated disposable target directory.

Before transfer, generate a source snapshot manifest containing:

- lab, engine, and integration HEAD commits;
- dirty/clean state for each worktree;
- content identity for tracked modifications;
- inventory and hashes for included untracked files;
- exclusion list and version;
- aggregate content hash.

After transfer, compute an applied-source hash on the target and require it to
match. A qualified clean baseline still requires committed worktrees; dirty
support exists for development iteration and must identify itself honestly.

The implementation records two versioned identities: a snapshot identity over
repository state and exclusions, and an independently recomputable applied-tree
hash over the transferred file inventory. Qualification is clean-only.
Development builds from a dirty snapshot require an explicit per-invocation
acknowledgement bound to that snapshot identity; hash agreement is attribution,
not a sandbox for untrusted source.

Exclude:

- all Git metadata;
- model and drafter artifacts;
- private target configuration;
- raw results already held on the controller;
- build output unless explicitly part of an experiment;
- Nix store/cache data;
- editor, Python, and tooling caches.

Remote deletion requires more than lexical path validation. The target must
prove that the configured path is a non-symlink, target-user-owned directory
carrying this workspace's versioned ownership marker. An absent root may be
initialized only while empty; an existing non-empty unmarked root is never
adopted. Canonical work, run, model, and drafter locations must not overlap.
Every destructive invocation revalidates the marker and directory identity,
holds the per-target operation lock, and confines deletion to that exact
disposable source root.

### 4. Native target build

Implement target build operations that:

1. require a matching source manifest;
2. run the current upstream-supported GB10 build on the execution target;
3. capture command, exit status, duration, toolchain identity, and build output;
4. verify the resulting binaries contain or report the expected target path;
5. leave build artifacts only inside the dedicated source/build tree.

V1 does not cross-compile on the controller. It does not replace the engine's
Makefile or package CUDA through Nix.

Sync and build are serialized with lifecycle transitions and refuse to mutate
the source or binary while a validated server is running. Build and serve use
the controller-supplied, isolated helper rather than importing orchestration
code from the synchronized worktree.

### 5. Deterministic server lifecycle

Add serve, status, log, and stop operations with explicit lifecycle state:

```text
run manifest
PID or user-service identity
server log
startup timestamp
source/build identity
sanitized launch configuration
```

Prefer a user-level transient service where reliably available. The portable
fallback is a versioned, one-shot supervisor in the owned run directory with
atomic state, a preallocated run identity, process/socket ownership validation,
and a bounded startup or smoke lease. Never kill a PID solely because a stale
file contains its number.

Requirements:

- startup fails if the expected process does not become ready;
- status distinguishes running, stopped, stale identity, and failed startup;
- stop targets only the validated server process tree;
- failed smoke/benchmark commands install cleanup behavior;
- a prior unknown server is not silently replaced;
- logs are copied back to the controller and sanitized;
- commands are idempotent where safe and fail explicitly where not.

The owned run directory provides the single operation lock. Sync and build
refuse while the validated server is running. Status and stop validate the
recorded start identity and live socket owner; an ambiguous identity is stale
and is never signaled. Smoke retains target-side cleanup ownership until stop,
including across an ambiguous SSH result or controller interruption.

### 6. Network exposure

Phase 01 binds the unauthenticated server to IP-literal loopback. Remote
functional smoke uses an ephemeral SSH forward owned and cleaned up by the
controller operation. It does not accept a wildcard, hostname, public address,
or a configuration assertion as authorization for LAN exposure.

Official LAN benchmarks in Phase 02 use the intended direct network path after
the operator's trusted-interface and firewall prerequisites are separately
validated, and record only generic network provenance.

### 7. Local mode

Every target-facing operation introduced here has a `local` equivalent with the
same manifest, build, lifecycle, and artifact contracts, minus SSH and transfer.
Local source is the authoritative controller worktree: local sync only
generates and verifies its manifest and never copies or deletes source. Shared
operation semantics remain common while the genuine transport boundary stays
explicit.

### 8. Root workflow

Add only implemented recipes, expected to include equivalents of:

```text
target-doctor [target]
target-sync [target]
target-build [target]
target-serve [target]
target-status [target]
target-logs [target]
target-stop [target]
target-smoke [target]
```

Normal users should not need to remember raw SSH, rsync, process, or internal
script commands.

## Explicit non-goals

- No custom load generator or benchmark scenario.
- No broad telemetry framework.
- No automatic source push/pull or upstream merge.
- No target daemon or agent.
- No multi-target fleet abstraction.
- No cross-compilation.
- No Nix-managed CUDA/compiler stack.
- No scheduler, admission, cache, or kernel behavior change.
- No committed target instance.

## Deliverables

### Lab repository

- target schema/example and strict config loader;
- ignore rules for real target files;
- target/local operation abstraction;
- sanitized target doctor;
- source manifest and safe sync implementation;
- target-native build operation;
- deterministic serve/status/log/stop/smoke lifecycle;
- returned artifact bundle with source/build/target identity;
- implemented Just recipes and focused checks.

### Forks

- no source changes expected;
- exact submodule commits remain pinned;
- current upstream smoke/correctness commands are documented for target use.

## Validation

### Configuration and privacy

- Missing/invalid fields fail before any remote action.
- Unsafe work/run roots are rejected.
- Logs and manifests omit addresses, usernames, credentials, and private paths.
- A tracked-file scan finds no real target instance.

The isolated test battery and focused security review must pass before the
first destructive remote qualification run. Any later runtime correction
invalidates affected target evidence and requires that remote chain to run
again against the new clean candidate.

### Doctor

Run doctor against both `spark` and, where hardware-compatible, `local`.
Confirm the intended driver/CUDA/NVCC/compiler and that the Nix shell does not
shadow them.

### Synchronization

Exercise:

1. clean worktrees;
2. a tracked text change;
3. a tracked binary change or other binary-safe content;
4. one included untracked source file;
5. one excluded private or generated file;
6. deletion inside the disposable source root;
7. an intentionally unsafe configured root.

The controller and target hashes must match for valid cases. The unsafe case
must fail before transfer or deletion.

### Build and smoke

- Build the exact frozen engine on the execution target using the supported
  GB10 target.
- Run the relevant upstream deterministic smoke on the target.
- Start the server, observe readiness, issue one functional request, collect
  logs, stop it, and verify no server process remains.
- Repeat lifecycle after an induced startup failure and after a client-side
  interruption.
- Exercise the same semantic operations in local mode when a compatible local
  target is available.

### Artifact return

Delete or move aside target-side temporary logs after copying the qualification
bundle to the controller. Verify the returned bundle is sufficient to identify
source, build, target toolchain, launch, outcome, and cleanup without exposing
private access details.

## Acceptance gate

Phase 01 is Qualified only when:

1. controller and target source hashes match for clean and supported dirty
   snapshots;
2. unsafe sync/delete roots are rejected;
3. target doctor proves the intended GB10 and host-managed toolchain;
4. frozen source builds natively on the target;
5. server start/readiness/request/log/stop works deterministically;
6. failure and interruption cleanup leave no unknown server process;
7. local mode follows the same operation contract;
8. authoritative artifacts return to the controller;
9. committed files and retained artifacts contain no private access or model
   location information;
10. no engine behavior changed.

## Artifacts

Retain:

- sanitized controller and target doctor reports;
- source snapshot and applied-source hashes;
- exact source commits and dirty-state identity;
- build command, toolchain versions, result, and binary identity;
- sanitized run manifest and lifecycle log;
- smoke request/result;
- cleanup confirmation;
- security/privacy validation output.

## Risks and rollback

| Risk | Mitigation / rollback |
|---|---|
| Sync deletes unrelated target data | Canonical marked root, operation lock, identity recheck, and refusal tests; no deletion outside it |
| Dirty worktree executes untrusted code | Remote execution refuses dirty source by default; development opt-in is bound to the manifest and never qualifies |
| Stale PID stops the wrong process | Atomic owned state plus process and socket ownership validation before signaling |
| SSH session death kills or strands server | Preallocated run identity, target-side supervisor/lease, reconciliation, and interruption cleanup tests |
| Nix changes CUDA/compiler attribution | Doctor compares paths/versions; fail qualification on drift |
| LAN endpoint is exposed too broadly | Phase 01 is loopback-only and owns its temporary SSH forward |
| Logs leak paths or addresses | Producer-side structured sanitization, bounded streaming redaction, and retained-artifact scan |
| Local and remote modes drift | Shared operation/state contracts with an explicit no-transfer local source path |

Rollback removes the Phase 01 scripts/config schema/recipes and target disposable
work directory. It does not alter models, target system packages, or fork
source.

## Exit handoff to Phase 02

Phase 02 receives:

- a validated generic target configuration contract;
- reproducible source synchronization;
- a target-native build and deterministic server lifecycle;
- source/build/target manifests returned to the controller;
- a working functional smoke path;
- no scheduler or benchmark behavior changes.
