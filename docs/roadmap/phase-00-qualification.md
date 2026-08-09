# Phase 00 qualification record

**Status:** Qualified
**Qualification date:** 2026-08-08
**Observed implementation branch:** `phase/00_workspace_bootstrap`
**Implementation / qualification commit:** `69af8ea605972ba79430db3d92dbf1940f824df2`

This is a retained record of observations made **before documentation was added**. It qualifies the unmerged implementation branch above; it is not evidence that the plain default-branch clone command was run. Later phases remain **Planned**.

## Checkpoints and published source pins

| Checkpoint | Commit |
|---|---|
| Source lineage | `40c571a24b7035f974fdd38a76fabfdbe7932b0e` |
| Nix userspace | `ad507e0f1ca25f41a49698cc1bf35110ca8145cf` |
| Root workflow | `0babb71e8089a8be1d8fc614ec02a12b095a1fc2` |
| Remote-policy hardening | `706797ceb996e276b7f64401b2c3004ceb88f31b` |
| Boundary hardening / implementation qualification | `69af8ea605972ba79430db3d92dbf1940f824df2` |

| Submodule | Published branch ref | Exact gitlink | Observed publication fact |
|---|---|---|---|
| `engine/ds4` | `refs/heads/spark` = `df641a7c4358dd6ca3b5acb46cf884a7d42066ed` | `df641a7c4358dd6ca3b5acb46cf884a7d42066ed` | The peeled Entrpi `v0.5.6` tag resolved to the same commit. |
| `spark/ds4-on-spark` | `refs/heads/spark` = `60c00afe24dc361c19e53037b599d98d27f32d7b` | `60c00afe24dc361c19e53037b599d98d27f32d7b` | The fork and Entrpi main had resolved to the same baseline before publication. |

Both submodule worktrees were clean; no source file was changed.

## Recorded submodule and remote configuration

Committed `.gitmodules` (verbatim):

```ini
[submodule "engine/ds4"]
	path = engine/ds4
	url = https://github.com/ZebulonRouseFrantzich/ds4.git
	branch = spark
[submodule "spark/ds4-on-spark"]
	path = spark/ds4-on-spark
	url = https://github.com/ZebulonRouseFrantzich/ds4-on-spark.git
	branch = spark
```

Resolved fetch-URL report:

```text
engine/ds4 origin https://github.com/ZebulonRouseFrantzich/ds4.git
engine/ds4 upstream https://github.com/Entrpi/ds4.git
engine/ds4 antirez https://github.com/antirez/ds4.git
spark/ds4-on-spark origin https://github.com/ZebulonRouseFrantzich/ds4-on-spark.git
spark/ds4-on-spark upstream https://github.com/Entrpi/ds4-on-spark.git
```

`just submodules` was run twice without changing configured remote hashes, and `just remotes-check` did not change them. In a disposable nonrecursive clone, a mismatched registered URL failed before either uninitialized submodule cloned; after its removal, initialization succeeded twice. An initialized origin with an extra URL also failed before update. The diagnostics omitted the actual configured values.

## Reproducibility and tool observations

| Item | Observed result |
|---|---|
| `flake.lock` SHA-256 | `f4ba9a8afbe31fbf46a5d71fb7ee1b79c0c07d00f1597595eb1b860ab45917bf` |
| nixpkgs revision | `70ce234312134a463ba7728e94da2486a1d237ac` |
| nixpkgs `narHash` | `sha256-X44cn5rzytELc3NNoQsh0aLkjWA/QzPfc6HPQmsG3sU=` |
| Nix checks | Current-system `nix flake check` passed; its formatting derivation traversed all four Nix files. A clean clone also passed `nix flake check` and `just flake-check`. |
| Cross-platform evaluation | `aarch64-linux` dev-shell and check derivation paths evaluated successfully without being built on `x86_64`. |
| Just and doctor | In the clean clone, `just doctor` passed. After `just submodules`, `just doctor`, `just tool-versions`, `just remotes-check`, and `just flake-check`, the clone remained clean. |
| Empty-HOME Nix qualification | `NIX_CONFIG='experimental-features = nix-command flakes'` was supplied because user Nix configuration was intentionally absent. |
| uv interpreter selection | `UV_PYTHON_DOWNLOADS=never`, `UV_NO_MANAGED_PYTHON=1`, and `UV_PYTHON` designated a Nix-provided Python; `uv python find` selected that Python. |
| Controller toolchain boundary | Compiler lookup stayed outside `/nix/store`; no Nix compiler, CUDA, or NVCC was added. `nvcc` was absent on the controller, as expected for Phase 00. |

Observed versions:

```text
nix (Nix) 2.32.4
git version 2.55.0
just 1.57.0
Python 3.14.6
uv 0.12.1 (x86_64-unknown-linux-gnu)
jq-1.8.2
curl 8.21.0
OpenSSH_10.4p1
rsync 3.4.4
ShellCheck 0.11.0
treefmt v2.5.0
```

## Anonymous recursive-clone evidence

The qualification clone used an empty home, no global or system Git configuration, terminal prompting disabled, SSH disabled, and an empty credential helper. It explicitly selected the unmerged implementation branch:

```sh
git clone --branch phase/00_workspace_bootstrap --recurse-submodules https://github.com/ZebulonRouseFrantzich/ds4-spark-lab.git
```


The final anonymous clone was at `69af8ea605972ba79430db3d92dbf1940f824df2` and passed the existing listed gates.
Both public HTTPS submodules cloned and checked out the exact gitlinks recorded above. The observed command is intentionally branch-qualified; no claim is made that a plain default-branch clone command was executed. **Post-merge expectation:** a default-branch clone must be independently exercised after the qualified implementation is merged; it is not covered by this record.

## Privacy and repository shape

Regex scans found no private IPv4 literals, contributor home paths, private-key or token signatures, or tracked SSH URLs in lab-owned tracked text. `git ls-files` over targets, models, drafters, benchmark results, and local environment-file paths produced no output. Ignore probes confirmed that private targets, raw benchmark results, build outputs, Python/Nix/editor caches, local environment overrides, models, and drafters are ignored, while manifests, baselines, reports, locks, source, roadmap documentation, `.env.example`, and editor settings remain visible. The Emacs auto-save probe `nested/#.env#` was ignored.

The only added implementation directories are the `engine/` and `spark/` gitlinks plus `nix/`; no future scaffolding or private configuration exists.

## Acceptance gates

| # | Phase 00 criterion | Qualified evidence |
|---:|---|---|
| 1 | A public recursive clone succeeds without SSH credentials. | The anonymous, empty-credential recursive clone explicitly selected the unmerged `phase/00_workspace_bootstrap` implementation branch and cloned both public HTTPS submodules at their exact gitlinks; no plain default-branch clone is claimed. |
| 2 | The engine submodule resolves to exact `v0.5.6` commit `df641a7…`. | `engine/ds4` is pinned to `df641a7c4358dd6ca3b5acb46cf884a7d42066ed`, the commit to which the peeled Entrpi `v0.5.6` tag resolved. |
| 3 | Entrpi is consistently named `upstream` in both fork worktrees. | The resolved fetch-URL report records `engine/ds4 upstream https://github.com/Entrpi/ds4.git` and `spark/ds4-on-spark upstream https://github.com/Entrpi/ds4-on-spark.git`. |
| 4 | The fork remains the writable `origin`. | Successful exact `spark` branch publications are recorded for both fork origins, and the resolved fetch-URL report records the configured public fork `origin` URLs for both worktrees. |
| 5 | Nix evaluation/checks and the implemented doctor/remotes workflow pass. | Current-system and clean-clone `nix flake check` passed; in the clean clone, `just doctor` passed and the completed `just submodules`, `just doctor`, `just tool-versions`, `just remotes-check`, and `just flake-check` workflow left the clone clean. |
| 6 | Nix does not claim ownership of the target CUDA/compiler stack. | Compiler lookup stayed outside `/nix/store`; no Nix compiler, CUDA, or NVCC was added, and controller `nvcc` was absent as expected for Phase 00. |
| 7 | Committed files contain no private target or model access information. | Privacy scans found no private target/model access information or related private signatures in lab-owned tracked text, and `git ls-files` over targets and models produced no output. |
| 8 | No engine behavior changed. | The exact baseline gitlinks are `engine/ds4` `df641a7c4358dd6ca3b5acb46cf884a7d42066ed` and `spark/ds4-on-spark` `60c00afe24dc361c19e53037b599d98d27f32d7b`; both submodule worktrees were clean and unchanged. |

## Rollback note

[INFERENCE] If Phase 00 must be rolled back, use the implementation qualification commit `69af8ea605972ba79430db3d92dbf1940f824df2` as the scope boundary and restore the workspace to the approved preceding state. The recorded evidence shows no source-file change in either submodule worktree, so this workspace rollback does not imply a source-submodule rollback.
