# Phase 01 qualification record

**Status:** Qualified
**Qualification date:** 2026-08-09
**Observed implementation branch:** `phase/01_execution_target`
**Qualified implementation candidate:** `e82ed34b5bfd08bbc96031fa36c11eb2054d8e14`

This record qualifies the Phase 01 implementation candidate above. The status and
this record are a later documentation-only change. Generated evidence remains in
the gitignored controller artifact tree; this document retains only sanitized
identities and outcomes.

## Frozen identities

| Identity | Value |
|---|---|
| Lab candidate | `e82ed34b5bfd08bbc96031fa36c11eb2054d8e14` |
| Engine gitlink | `df641a7c4358dd6ca3b5acb46cf884a7d42066ed` (`v0.5.6`) |
| Integration gitlink | `60c00afe24dc361c19e53037b599d98d27f32d7b` |
| `flake.lock` SHA-256 | `f4ba9a8afbe31fbf46a5d71fb7ee1b79c0c07d00f1597595eb1b860ab45917bf` |
| Clean source snapshot | `116349e35447b02460d86caded27c549f251233f083bf9a63a7e37355df864c0` |
| Applied tree | `1877a3eb7b13dbf76a76c239b1c8675d0c2fc538edd432f43c6f8b23d8ae7be2` |
| Qualified bundle | `artifacts/phase-01-runs/spark/bundle-1786329742496359581-c3cdd8cef99a` |

The bundle is intentionally untracked. Its validated index contains nine files
and the required controller, source, doctor, build, run, smoke, cleanup, and
bounded text evidence.

## Observed target facts

The configured `spark` target reported Linux `aarch64`, NVIDIA GB10,
`sm_121`, driver `595.71.05`, CUDA/NVCC `13.0`, GCC/G++ `13.3.0`, GNU Make
`4.3`, Python `3.12.3`, Git `2.43.0`, rsync `3.2.7`, and cuobjdump `13.0`.
Clock synchronization was active. Nix was absent on the target, so no Nix
compiler shadowing was possible; native tools remained host-managed.

No target system package, driver, CUDA toolkit, compiler, firewall, or service
configuration was changed.

## Validation evidence

| Gate | Directly observed evidence |
|---|---|
| Workspace | `nix develop --command just doctor`, `just tool-versions`, and `just remotes-check` passed on the candidate. The two submodule worktrees remained at the frozen gitlinks. |
| Automated contracts | `python3 -m unittest discover -s tests -v` ran 225 tests successfully. Coverage includes strict/private configuration, local and SSH transport equivalence, binary-safe clean/dirty source identity, guarded deletion, descriptor-pinned target roots, target doctor, native-build provenance, SASS verification, deterministic lifecycle, interruption/reconciliation, bounded redaction, and artifact validation. |
| Nix | `nix flake check` passed on `x86_64-linux`; the declared `aarch64-linux` incompatibility warning remained expected because the formatting check is controller-host scoped. |
| Source synchronization | The final clean Spark sync returned matching controller/target snapshot and applied-tree identities shown above. Focused clean/dirty, tracked text, binary, included-untracked, excluded-private/generated, deletion, unsafe-root, and exact-inventory cases passed in the test battery. Dirty source can be synchronized only with explicit authorization and cannot qualify executable doctor/build/smoke work. |
| Doctor | Spark doctor succeeded and proved the intended GB10 / SM121 platform, target-native tool paths and versions, weight identities, available resources, and active time synchronization without exposing private locations. |
| Native build | The frozen engine built on Spark with `make-cuda-spark`; build `ecab93c8d8380941569a2f2c8bb3633095246d61b10149c2fd2790d7bf8d2dfa` reported version `0.5.6`, a bounded sanitized build log, and verified actual `sm_121` SASS. |
| Functional smoke | The final clean bundle started the loopback-only server, observed readiness and `/v1/models`, completed the bounded deterministic chat request, returned `contract: passed`, retained the sanitized server log, and stopped with process and socket cleared. Final status was `active: false`, `state: stopped`. |
| Startup failure | Against the same clean candidate, a one-second induced startup deadline returned `startup_timeout` with `failed_startup` state; cleanup succeeded with the process cleared and no socket, lock, or temporary file left. |
| Controller interruption | A controller-side SIGINT during Spark serve returned the structured `interrupted` error. Target status retained the owned running identity; `target-cleanup` then cleared its process and socket, and final status was inactive/stopped. |
| Local contract | Local-mode tests exercised the same operation/result schemas, source no-transfer behavior, deterministic serve/status/log/stop/smoke lifecycle with real loopback test servers, idempotent cleanup, and complete bundle promotion. Native DS4 execution was not attempted on the incompatible controller GPU/architecture. |
| Artifact and privacy | The final bundle index validated completely. A producer-canary scan of all bundle files found no configured model, drafter, work, or run path. Tracked-file scans found no real target instance, retained generated artifact, private access value, credential, or private model location. |
| Independent review | Required DeepReview and focused security review both returned `APPROVE` after remediation. The final reviews covered lock/install races, response-loss reconciliation, descriptor-pinned source/build checks, hard-link and symlink safety, lifecycle ownership, bounded output, SSH isolation, redaction, and artifact promotion. |

## Acceptance-gate result

| Phase 01 gate | Result |
|---|---|
| 1. Matching clean and supported dirty source identities | Passed |
| 2. Unsafe sync/delete roots rejected | Passed |
| 3. Intended GB10 and host-managed toolchain proven | Passed |
| 4. Frozen source builds natively | Passed |
| 5. Start/readiness/request/log/stop deterministic | Passed |
| 6. Failure/interruption cleanup leaves no unknown process | Passed |
| 7. Local mode follows the same contract | Passed within the controller's hardware compatibility boundary |
| 8. Authoritative artifacts returned | Passed |
| 9. No private access/model-location information retained | Passed |
| 10. No engine behavior changed | Passed; both fork source trees and gitlinks remained unchanged |

Phase 01 is **Qualified**. Phase 02 may use the generic target contract and
qualified functional smoke path, but Phase 01 establishes no benchmark result,
performance threshold, scheduler behavior, or release claim.

## Rollback

Rollback removes the lab-owned Phase 01 target controller modules, tests,
configuration example, Just recipes, and disposable target source/run roots. It
does not alter model files, target system packages, target drivers/toolchains,
or either fork's source. Generated controller state and bundles remain ignored
and can be removed independently after evidence retention requirements are met.
