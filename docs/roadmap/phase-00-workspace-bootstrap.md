# Phase 00 — Workspace Bootstrap and Source Lineage

## Status

**Planned**

## Depends on

- Approved project specification and roadmap.
- The three public GitHub repositories remaining available.

## Objective

Create the smallest reproducible umbrella workspace that makes the correct
engine lineage, fork/upstream relationships, userspace tooling boundary, and
normal developer workflow explicit.

This phase changes no engine behavior and performs no remote-target execution.

## Hypothesis

A public-HTTPS submodule workspace, exact baseline branch, pinned Nix userspace,
and narrow Just interface can give contributors one reproducible entry point
without obscuring the independent histories of the engine and integration
forks or perturbing the target CUDA toolchain.

## Load-bearing baseline fact

The current engine fork's `main` is not the V1 baseline:

```text
ZebulonRouseFrantzich/ds4 main
  b0309611041655f4e45671cfd9c9886aff161406

Entrpi/ds4 v0.5.6 resolved commit
  df641a7c4358dd6ca3b5acb46cf884a7d42066ed
  lineage: Entrpi/batched-serving
```

The fork currently has no `v0.5.6` tag or `spark` branch. Phase 00 must publish a
`spark` branch from the exact resolved `v0.5.6` commit before the umbrella
submodule points at it. Starting from fork `main` would create the workspace on
the wrong source lineage.

The integration baseline is:

```text
ZebulonRouseFrantzich/ds4-on-spark main
  60c00afe24dc361c19e53037b599d98d27f32d7b
```

That commit is synchronized with Entrpi and its installer pins engine
`v0.5.6`.

## Repositories

| Repository | Phase role |
|---|---|
| `ZebulonRouseFrantzich/ds4-spark-lab` | Workspace, submodules, Nix/Just entry point |
| `ZebulonRouseFrantzich/ds4` | Publish the exact `v0.5.6`-based `spark` branch |
| `ZebulonRouseFrantzich/ds4-on-spark` | Establish remote policy; retain exact integration baseline |

## Entry criteria

- Fork ownership and public visibility are confirmed.
- The resolved commits above are rechecked immediately before branch creation.
- No active experiment depends on a different engine ref.
- The controller has Git and Nix available to create and validate the lock.

If the upstream tag moves or becomes unavailable, stop. Resolve the tag object
and compare its commit with the recorded baseline; never silently substitute a
new branch tip.

## Scope

### 1. Establish the fork remote policy

Inside the engine fork checkout:

```text
origin    https://github.com/ZebulonRouseFrantzich/ds4.git
upstream  https://github.com/Entrpi/ds4.git
antirez   https://github.com/antirez/ds4.git
```

Inside the integration fork checkout:

```text
origin    https://github.com/ZebulonRouseFrantzich/ds4-on-spark.git
upstream  https://github.com/Entrpi/ds4-on-spark.git
```

`origin` remains the writable fork. `upstream` is always the Entrpi source from
which deliberate synchronization occurs. The optional engine `antirez` remote
supports source comparison only.

Additional remotes are local Git configuration; submodules do not propagate
them automatically. The root bootstrap/status workflow must add or verify them
idempotently after clone.

### 2. Seed the engine `spark` branch correctly

The intended operation is equivalent to:

```bash
git fetch upstream --tags
git switch --create spark df641a7c4358dd6ca3b5acb46cf884a7d42066ed
git push --set-upstream origin spark
```

Before pushing, verify that the resolved commit is still the intended
`v0.5.6` baseline. Do not force-update an existing `spark` branch. If it already
exists, compare its history and stop on mismatch.

The fork's `main` remains available for deliberate tracking of Entrpi's default
branch. V1 features branch from `spark`, not `main`.

For the integration fork, create a `spark` branch only if the branch policy is
being activated in this phase. Its initial commit must be the exact validated
integration baseline. Do not create placeholder feature branches.

### 3. Add public-HTTPS submodules

Planned paths and URLs:

```text
engine/ds4
  https://github.com/ZebulonRouseFrantzich/ds4.git

spark/ds4-on-spark
  https://github.com/ZebulonRouseFrantzich/ds4-on-spark.git
```

`.gitmodules` must not use SSH URLs. Anonymous recursive clone and hosted CI
should not require a GitHub account or key. Maintainers may configure an SSH
`pushurl` or URL rewrite locally.

Pin the engine submodule to the exact `spark` baseline commit and the
integration submodule to its exact baseline commit. A configured submodule
branch is advisory only; the umbrella commit remains the source of truth.

### 4. Add the minimal Nix userspace

Create only:

```text
flake.nix
flake.lock
nix/tooling.nix
nix/dev-shell.nix
nix/checks.nix
```

Requirements:

- pin `nixpkgs-unstable` through `flake.lock`;
- support the controller's Linux system and keep the design compatible with
  `aarch64-linux` helper tooling;
- use `mkShellNoCC` or an equivalent no-compiler shell;
- centralize the userspace tool list in `nix/tooling.nix`;
- keep `nix flake check` cheap and host-independent;
- prevent uv from downloading an unmanaged Python runtime;
- do not include NVIDIA driver, CUDA, NVCC, GCC, or Clang as V1 shell
  replacements.

The initial tool closure should contain only tools needed by the documented
workspace workflow, such as Git, Just, Python, uv, jq, curl, OpenSSH, rsync,
ShellCheck, and the selected Nix formatter.

### 5. Add a narrow root workflow

Create the root `Justfile` and optional `./dev` wrapper. At this phase they own
only workspace-level operations that exist:

```text
help/default
status
doctor
tool-versions
submodules
remotes-check
flake-check
```

Future target, build, serve, and benchmark recipes are added in the phase that
implements them. Do not add non-functional placeholder recipes.

`remotes-check` should verify the expected fetch URLs and report mismatches. It
must not mutate or synchronize branches implicitly.

### 6. Establish ignore and configuration boundaries

Add only ignore rules required by files introduced in this phase and the known
private boundary. At minimum, plan for:

- local target configuration under `targets/`;
- raw benchmark results;
- build outputs;
- Python/Nix/editor caches;
- local environment files;
- model and drafter artifacts.

Do not add broad patterns that could hide source, phase documents, manifests,
or summary reports.

## Explicit non-goals

- No SSH connection or remote target configuration.
- No remote synchronization, build, serve, or process lifecycle.
- No benchmark client, scenarios, prompts, or result schema.
- No engine or integration source changes beyond creating the known-good branch.
- No automatic upstream merge or rebase.
- No scheduler feature flags.
- No CUDA compilation.
- No future directory forest.

## Deliverables

### Engine fork

- `spark` branch published from exact commit
  `df641a7c4358dd6ca3b5acb46cf884a7d42066ed`.
- Standard `origin`/`upstream`/`antirez` remote policy documented.
- No engine file changes.

### Integration fork

- Standard `origin`/`upstream` remote policy documented.
- Optional `spark` branch created only from exact integration baseline.
- No installer or integration behavior changes.

### Lab repository

- public-HTTPS `.gitmodules`;
- exact initial submodule pins;
- thin `flake.nix` and committed `flake.lock`;
- `nix/tooling.nix`, `nix/dev-shell.nix`, and `nix/checks.nix`;
- functional root `Justfile` and optional `./dev`;
- narrowly scoped `.gitignore`;
- README updates reflecting what now exists;
- no private target information.

## Validation

### Public clone

From a clean temporary location with no GitHub SSH credential:

```bash
git clone --recurse-submodules \
  https://github.com/ZebulonRouseFrantzich/ds4-spark-lab.git
```

Verify both submodules initialize from public HTTPS URLs.

### Source lineage

Verify:

```text
engine submodule HEAD
  df641a7c4358dd6ca3b5acb46cf884a7d42066ed

integration submodule HEAD
  60c00afe24dc361c19e53037b599d98d27f32d7b
```

Verify engine `origin/spark` contains the baseline and that the `upstream`
remote resolves to Entrpi. Verify no assertion equates `origin/main` with the
V1 baseline.

### Development environment

Run the implemented equivalents of:

```bash
nix flake check
nix develop --command just doctor
nix develop --command just tool-versions
nix develop --command just remotes-check
```

Confirm the shell does not provide or reorder a Nix CUDA/NVCC/compiler ahead of
host tools. Phase 00 verifies controller behavior only; target compiler
verification belongs to Phase 01.

### Privacy and repository shape

Verify:

- no private target config is tracked;
- no operator-specific host alias, address, username, home path, credential, or
  model path appears in committed files;
- the only added directories contain files required by this phase;
- no empty future implementation scaffolding is committed.

## Acceptance gate

Phase 00 is Qualified only when all of the following are true:

1. a public recursive clone succeeds without SSH credentials;
2. the engine submodule resolves to exact `v0.5.6` commit `df641a7…`;
3. Entrpi is consistently named `upstream` in both fork worktrees;
4. the fork remains the writable `origin`;
5. Nix evaluation/checks and the implemented doctor/remotes workflow pass;
6. Nix does not claim ownership of the target CUDA/compiler stack;
7. committed files contain no private target or model access information;
8. no engine behavior changed.

## Artifacts

Retain in the Phase 00 qualification record:

- exact lab and submodule commits;
- `.gitmodules` content;
- resolved remote URL report;
- `flake.lock` hash and locked nixpkgs revision;
- resolved userspace tool versions;
- public-clone verification output;
- doctor/check output;
- privacy scan result.

Do not retain credentials, local SSH configuration, or private filesystem
paths in those artifacts.

## Risks and rollback

| Risk | Mitigation / rollback |
|---|---|
| `spark` starts from the wrong lineage | Verify exact commit before push; delete an unconsumed incorrect branch only after explicit review |
| SSH submodule URLs block contributors | Require HTTPS in `.gitmodules`; keep push authentication local |
| Remotes drift after clone | Idempotent non-mutating `remotes-check`; explicit bootstrap action |
| Nix shadows the target toolchain | No compiler/CUDA packages; target verification deferred to Phase 01 |
| Workspace scaffolding grows prematurely | Reject placeholders and empty future directories |
| A broad ignore hides important evidence | Review each ignore pattern against tracked manifests/reports |

If the workspace cannot preserve the correct lineage or public clone behavior,
do not proceed to remote execution. Revert the lab bootstrap rather than
building later phases on an ambiguous source base.

## Exit handoff to Phase 01

Phase 01 receives:

- a reproducible public workspace;
- exact engine and integration submodule pins;
- verified fork/upstream remote relationships;
- pinned userspace tools;
- a working root workflow that can be extended with real target operations;
- an explicit private configuration boundary.
