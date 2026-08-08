# Gated Research Backlog

## Status

**Gated**

This document preserves high-value experiments without making them V1 or V2
release commitments. No track begins because an implementation is interesting.
It begins only when retained measurements satisfy its entry gate and show that
the targeted bottleneck is material after the shipped V1/V2 improvements.

Research work uses separate branches/specifications, immutable comparison refs,
and explicit stop conditions. A negative result is retained and closes the
track until new evidence changes its premise.

## Shared research rules

Every track must:

1. name the measured bottleneck and its contribution to workflow cost;
2. freeze the exact V1/V2 comparison ref, environment, model, and scenarios;
3. state one falsifiable hypothesis;
4. implement the smallest experiment capable of testing it;
5. preserve DS4 correctness and specialized execution unless the experiment
   explicitly tests that boundary;
6. separate observation/prototype from production integration;
7. declare keep, continue, or stop thresholds before candidate results;
8. retain raw evidence, including failed and negative results;
9. use an isolated branch and never become a default through an umbrella pin
   before qualification;
10. receive independent review appropriate to its memory, concurrency, CUDA,
    and security risk.

Research prototypes are not released as hidden no-ops, incomplete scaffolds, or
permanent disabled code. If a prototype fails its gate, remove it from the
integrated line and retain the report.

## Track R1 — Paged or ref-counted shared-prefix state

### Motivation

Current DS4 warm/fork behavior may avoid substantial prefill computation while
still copying or duplicating physical state for branch fan-out. A
DeepSeek-V4-aware immutable shared-prefix representation could reduce physical
copy/residency cost and support more useful concurrent branches.

A generic PagedAttention clone is not assumed to fit. DS4 state is
model-specific, heterogeneous, compressed, windowed, and coupled to
speculative/rollback and graph behavior.

### Entry gate

All conditions must hold:

- V2 is released and its capacity accounting is trusted;
- C1/C2 show physical state duplication or copy cost remains a material limiter
  after prefix-aware scheduling and retention;
- the limiting pools and bytes are identified, not inferred from logical token
  counts;
- projected additional useful concurrency or workflow gain is large enough to
  justify allocator/lifetime complexity;
- existing fork-by-copy behavior and correctness baseline are fully measured;
- no simpler retention, copy scheduling, or allocation-granularity change can
  address the measured bottleneck.

If memory duplication is not a material limiter, do not start.

### Hypothesis

Immutable prefix state shared by validated lineages, with reference counting and
copy-on-write mutable tails, can reduce branch memory/copy cost and increase
useful deep-agent concurrency without changing logits, continuation behavior,
rollback, graph safety, or lifecycle correctness.

### Required design questions

Before implementation, produce a source-grounded design covering:

- which DS4 pools can be immutable and physically shared;
- raw-token-to-physical boundaries for every shared pool;
- minimum share/page granularity and alignment;
- ownership and refcount concurrency model;
- generation/frontier identity and ABA prevention;
- mutable tail and copy-on-write boundary;
- speculative checkpoint/rollback interaction;
- windowed/compressed state expiration;
- graph-captured pointer/address stability;
- cancellation, branch divergence, retirement, eviction, persistence, and
  shutdown;
- error recovery if allocation or copy-on-write fails;
- accounting integration with Phase 08;
- invariant checks and leak detection.

If one pool cannot be safely shared, the design must state whether it remains
copied and how mixed shared/copied ownership is charged.

### Minimum experiment

Start with one narrowly supported case:

- one validated immutable prefix;
- two branches;
- a controlled divergence point;
- no disk tier and no broad scheduler integration unless required;
- exact before/after physical bytes and copy time;
- deterministic output/logprob comparison;
- forced cancellation and branch teardown.

Expand branch count, context depth, pool coverage, or persistence only after the
prior step passes.

### Qualification

Require:

- official/golden logprob or equivalent exact quality checks;
- long-context retrieval/correctness;
- deterministic copied-versus-shared branch comparison;
- branch divergence and independent continuation;
- tool continuation and replay;
- cancellation at each ownership transition;
- refcount underflow/overflow/double-free/stale-generation tests;
- allocation-failure and copy-on-write-failure recovery;
- memory leak and churn soak;
- C1/C2/C3/C4 workflow comparison;
- V1/V2 admission/fairness/graph regression;
- independent DeepReview focused on memory lifetime and CUDA pointer safety.

### Success gate

Keep the track only if it:

1. preserves exact supported model behavior and lifecycle correctness;
2. materially reduces measured physical branch memory or copy cost;
3. increases useful deep-agent concurrency or workflow goodput under the
   predeclared threshold;
4. does not introduce unacceptable graph, single-request, or scheduler
   regression;
5. has an understandable ownership model that can be maintained in DS4's C/CUDA
   codebase.

A memory reduction without end-to-end value is not automatically sufficient.

### Stop conditions

Stop and retain results if:

- pointer stability makes graph integration unsafe;
- mixed state lifetimes require a generalized allocator larger than the proven
  benefit;
- correctness cannot be demonstrated across divergence/rollback;
- copy cost is not material in real workflows;
- retention/capacity changes already recover most of the expected value.

## Track R2 — Deeper graph-shape scheduling

### Motivation

V1 deliberately preserves a constrained graph-aware decode path and bounded
eager prefill. After V2, measurements may show repeated eager fallback or idle
execution opportunity concentrated in a small number of stable shapes.

### Entry gate

All conditions must hold:

- V1/V2 graph eligibility/replay/fallback telemetry is trusted;
- a bounded fallback reason/shape accounts for material lost goodput or latency;
- target-local controls isolate the loss from LAN, host, memory pressure, and
  cache effects;
- the candidate shape occurs frequently enough to amortize capture/storage and
  complexity;
- changing scheduler selection alone cannot solve the issue.

### Hypothesis

Adding one evidence-selected graph class or packing rule can recover a measured
execution-path loss without generalizing DS4 into arbitrary dynamic graph
construction.

### Minimum experiment

- select one dominant unsupported shape;
- prototype one capture/dispatch path;
- retain exact eager fallback;
- measure capture cost, replay rate, memory overhead, latency, and goodput;
- run deterministic output and graph-invalidation tests;
- do not combine with a new scheduler policy or cache allocator.

### Qualification

Require target-local and LAN S1/S2/S3 comparisons, graph memory/capture
accounting, invalidation and pointer-lifetime tests, DSpark/plain decode coverage,
long-context correctness, and independent CUDA/graph review.

### Success gate

Keep only if the new class materially improves the predeclared workload metric,
occurs reliably, stays inside memory headroom, preserves correctness, and adds a
bounded maintainable dispatch path. Reject a general graph-shape framework.

### Stop conditions

Stop if capture overhead, graph memory, invalidation complexity, rare occurrence,
or scheduler instability consumes the measured benefit.

## Track R3 — Scheduler/host overlap

### Motivation

Large runtimes overlap scheduling, output processing, and GPU execution. DS4's
native C server may already have much lower host overhead, so overlap is not
assumed valuable.

### Entry gate

All conditions must hold:

- post-V2 target-local profiling shows repeatable GPU idle/bubble time caused by
  host scheduling/output work;
- the host contribution is material relative to the end-to-end S1/S2/C2/C3
  workload;
- instrumentation overhead is measured and removed from the estimate;
- network and slow-client behavior are excluded as the primary cause;
- a plausible bounded overlap could recover enough time to meet a predeclared
  value threshold.

If profiling shows the GPU or memory path dominates, do not start.

### Hypothesis

Preparing the next scheduler decision or draining bounded output concurrently
with current GPU execution can reduce proven host-induced bubbles without
racing request lifecycle, CUDA stream/graph state, cancellation, or output
ordering.

### Required design questions

- which state is immutable/readable while GPU work is in flight;
- one-step-ahead plan validity and invalidation;
- ownership of completions, cancellations, and capacity epochs;
- CUDA stream/event synchronization;
- graph capture/replay thread requirements;
- output-buffer backpressure and slow clients;
- lock ordering and shutdown;
- plan discard cost when arrivals or cancellations change state;
- how overlap is disabled for exact baseline comparison.

### Minimum experiment

First overlap only one measured host component with one stable execution window.
Retain the single-threaded path and compare identical source/configuration apart
from the overlap switch. Do not redesign the server into a general task runtime.

### Qualification

Require race/thread sanitization where supported for host code, deterministic
ordering tests, cancellation/shutdown churn, slow-client backpressure, CUDA
error/invalidation handling, S1/S2/S3/C2 target-local profiling, LAN workflow
comparison, and independent concurrency/CUDA review.

### Success gate

Keep only if profiling proves the host bubble shrinks and an end-to-end
predeclared workload metric materially improves without correctness, latency
tail, graph, CPU, or maintainability regression.

### Stop conditions

Stop if plans are frequently invalidated, synchronization replaces the saved
bubble, tail latency worsens, the measured host share is small, or concurrency
complexity exceeds the recoverable value.

## Deferred ideas without active tracks

These remain out of scope until the project definition changes:

- multi-device or multi-node prefill/decode disaggregation;
- distributed KV/cache systems;
- generic model/runtime support;
- cluster scheduling or remote agents;
- replacing DSpark;
- production multi-tenant authentication/authorization architecture;
- Nix ownership of the target NVIDIA stack.

If the project expands beyond one GB10 target or one model family, create a new
program-level design and impact matrix rather than stretching a V3 track beyond
its assumptions.

## Research decision record

Every attempted track report answers:

```text
Measured bottleneck
Exact baseline refs and environment
Hypothesis and predeclared threshold
Minimum experiment
Correctness and safety evidence
Raw performance/memory/profile evidence
Complexity and maintenance impact
Decision: continue / keep / stop
Integrated refs or reverted branch
What new evidence would reopen a stopped track
```

Negative results are first-class project knowledge. They remain linked from
this backlog even when prototype code is removed.
