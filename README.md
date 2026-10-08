# Media Inference Lab

Rust-first, reproducible image and video inference benchmarks, GPU profiling, and optimization evidence. Apple Silicon is the first supported development target; platform-specific collectors and runtime adapters must remain separate from the portable comparison core.

## Purpose

Measure whether a change improves a complete media-generation workload, locate the affected pipeline stages and GPU operations, and report what happened to the outputs. A faster kernel is not automatically a faster application; numerical similarity is not a visual-quality score.

The project takes inspiration from [The Grill](https://github.com/plotarmordev/thegrill)'s saved-evidence and controlled-comparison approach. This is an independent image/video project, not a fork or an LLM-serving benchmark.

## Architecture

- **Rust CLI and core:** workload definitions, runtime execution, resource guards, capture manifests, offline comparisons, and reports. Start with one Cargo package and ordinary modules, using Clap and Serde/JSON; no initial plugin framework or embedded Python.
- **MFLUX adapter:** a thin Python process in an explicitly selected environment, using the native generation API. Start with Qwen Image 2.1; record the actual imported implementation and resolved model/settings.
- **H3 adapter:** Rust launches the existing `h3.c` CLI for MiniMax-H3 and translates available native measurements. Do not rewrite the inference engine or require a chat-completions server.
- **GPU experiments:** Metal kernels and small native host programs where needed. Keep microbenchmarks separate from end-to-end claims and runtime defaults.
- **Media inspection:** existing FFmpeg/ffprobe tools with recorded versions, plus full image/video/audio decoding where required.

Share the measurement contract, not the inference implementation. Runtime progress/logs and structured results are separate; unknown or unsupported measurements stay explicit rather than becoming zeroes or estimates.

## Measurement contract

Every capture identifies its workload, hardware/OS, model revision or fingerprint, runtime/source revision, resolved generation settings, timing boundaries, cache/process policy, samples, outcomes, and artifacts. Record host end-to-end time separately from runtime phases and GPU measurements.

Use repeated baseline/candidate/unchanged-control measurements. Distinguish cold initialization from warm execution and separate throughput from latency. Keep individual samples and ordering; comparisons may be inconclusive or invalid. Failures must remain in the evidence, not disappear through automatic retries or successful-only filtering.

| Workload | Settings and output checks | Performance |
| --- | --- | --- |
| Image | Prompt, seed, resolution, steps, scheduler, guidance, batch, precision, reference inputs; actual decoding, dimensions, pixel/latent differences, visual inspection | Seconds/image and images/second at an explicitly stated batch and timing boundary |
| Video | Image-equivalent settings plus frame count, playback FPS, duration, temporal reuse, conditioning, and audio; full frame/audio decoding and temporal/output inspection | Seconds/clip and generated frames or media duration per elapsed second, never confused with playback FPS |

Fixed seeds alone do not prove determinism. Measure baseline-versus-baseline variation. Keep exact-output checks, numerical tolerances, and visual/temporal assessments separate, and disclose approximations or changed settings rather than crediting them as equivalent-work speedups.

Memory observations must state their source and scope. Process RSS, tracked tensor allocations, driver allocations, system pressure, and swap are different measurements; unavailable total GPU memory is not inferred from RSS.

## Scope and boundaries

- First complete workflow: capture real image and video runs, retain evidence, compare saved runs offline, and inspect outputs and limitations.
- Prioritize production-shape attention benchmarks, then decoder matrix work; investigate supported runtime/kernel selection before writing replacement kernels.
- Real model weights and runtimes are user-provided. No weights, credentials, private logs, or automatic artifact uploads belong in the repository.
- No new generation UI, duplicate performance website, runtime rewrite, or universal model framework. The existing performance-lab website can consume explicitly approved, sanitized reports later.
- Do not change live application deployments or workstation infrastructure as a side effect of benchmarking.

## Roadmap

Each epic has three native GitHub sub-issues with implementation steps, dependencies, and observable acceptance criteria.

| Epic | Implementation issues |
| --- | --- |
| [Rust capture core, evidence contract, and safe execution](https://github.com/jerryfane/media-inference-lab/issues/3) | [Schemas #9](https://github.com/jerryfane/media-inference-lab/issues/9), [capture lifecycle #10](https://github.com/jerryfane/media-inference-lab/issues/10), [resource guards #11](https://github.com/jerryfane/media-inference-lab/issues/11) |
| [Real MFLUX image capture and validation](https://github.com/jerryfane/media-inference-lab/issues/1) | [Native adapter #12](https://github.com/jerryfane/media-inference-lab/issues/12), [timing and validation #13](https://github.com/jerryfane/media-inference-lab/issues/13), [workloads #14](https://github.com/jerryfane/media-inference-lab/issues/14) |
| [Native H3 video capture and validation](https://github.com/jerryfane/media-inference-lab/issues/7) | [Native adapter #15](https://github.com/jerryfane/media-inference-lab/issues/15), [stream validation #16](https://github.com/jerryfane/media-inference-lab/issues/16), [workloads #17](https://github.com/jerryfane/media-inference-lab/issues/17) |
| [Controlled comparisons and honest reports](https://github.com/jerryfane/media-inference-lab/issues/8) | [Comparison engine #18](https://github.com/jerryfane/media-inference-lab/issues/18), [output evidence #19](https://github.com/jerryfane/media-inference-lab/issues/19), [reports #20](https://github.com/jerryfane/media-inference-lab/issues/20) |
| [Production-shape Metal optimization studies](https://github.com/jerryfane/media-inference-lab/issues/2) | [Kernel profiling #21](https://github.com/jerryfane/media-inference-lab/issues/21), [attention #22](https://github.com/jerryfane/media-inference-lab/issues/22), [decoder #23](https://github.com/jerryfane/media-inference-lab/issues/23) |
| [Portable verification, usage, and approved publication](https://github.com/jerryfane/media-inference-lab/issues/6) | [CI #24](https://github.com/jerryfane/media-inference-lab/issues/24), [reproduction #25](https://github.com/jerryfane/media-inference-lab/issues/25), [sanitized export #26](https://github.com/jerryfane/media-inference-lab/issues/26) |

Begin with the evidence schema and capture lifecycle, then resource guards and a real MFLUX image capture. Bring H3 into the same contract, prove offline comparison/reporting, and only then draw optimization conclusions from production-shaped studies. CPU-only verification can progress alongside those integrations; GPU runs require exclusive scheduling and explicit prerequisites.

## Implementation status

The first Rust slice implements versioned image/video evidence contracts and a CPU-only subprocess supervisor (`mil`), with offline inspection. **There is no guarded model-capture command yet.** GPU serialization, live-job/memory/swap guards (#11), native adapters (#12/#15), and actual media decoding (#13/#16) remain prerequisites for inference. No image/video generation or performance claim is established by the CPU examples.

### Build and CPU verification

Use a Rust toolchain supporting edition 2024. The observed checks used Rust/Cargo 1.98.0 on Darwin arm64. The supervisor implements macOS/Linux process ownership; Linux has not been exercised yet. Default checks require no models, Python environment, GPU, or model downloads.

```sh
cargo build --locked
cargo test --all-targets
cargo clippy --all-targets -- -D warnings
target/debug/mil validate examples/image-workload.json
target/debug/mil validate examples/video-workload.json
target/debug/mil validate-result \
  --workload examples/image-workload.json tests/fixtures/image-result.json
```

The examples and result fixtures are **schema-only**, not inference workloads verified against a runtime. Their artifact is a text file explicitly stating that no inference occurred. A successful CPU protocol example:

```sh
target/debug/mil supervise --cpu-only \
  --workload examples/image-workload.json \
  --root runs/cpu-example \
  --executable /bin/sh \
  --env "RESULT_FIXTURE=$PWD/tests/fixtures/image-result.json" \
  -- -eu -c '/bin/mkdir artifacts; printf "CPU schema fixture only; no inference was performed.\n" > artifacts/schema-output.txt; /bin/cp "$RESULT_FIXTURE" "$MIL_RESULT_PATH"'
```

The command prints its unique run directory. Pass that path to `target/debug/mil inspect PATH` to validate and print saved evidence offline. Inspect rechecks successful artifacts' hashes/sizes, the separate result document, and log sizes; it does not generate media. Exit codes: `0` for valid/completed evidence, `1` for a retained non-success or unresolved running capture, `2` for invalid input/evidence or an infrastructure error.

For a missing-result example, run `target/debug/mil supervise --cpu-only --workload examples/image-workload.json --root runs/cpu-example --executable /usr/bin/true`. It deliberately exits `1` and records `incomplete`: a zero child exit without adapter evidence is not a completed capture.

### Version 1 evidence contract

- `src/schema.rs` defines workload and adapter-result documents; `src/capture.rs` defines the capture/sample record. Only version 1 is accepted, with unknown fields rejected. Future incompatible changes require an explicit version change, not silent defaulting.
- Workload identity is SHA-256 of Rust's typed JSON serialization of **all** declared fields, including prompts, reference hashes, precision/quantization, optimizations, batching, process/cache policy, video layers, reuse intervals, playback FPS, and audio. Whitespace in strings is significant; JSON formatting/key order is not. Adapters copy the supervisor-supplied identity rather than reimplement its serialization.
- Declared and resolved settings remain separate. Explicit settings cannot change. Only requested `precision: "auto"` and `compute_precision: null` can resolve to concrete choices; results must record those choices. Observed model/source/module/executable identity and actual cache state are separate from requests. Native adapters must reject unsupported settings; the shared schema alone does not prove a runtime supports them.
- Unavailable observations carry a reason. Timings retain units, method, scope, and boundaries; RSS, tensor bytes, driver allocation, system pressure, and swap cannot substitute for each other. Host execution, cleanup, and artifact-inspection durations are separate. A null lifecycle stage duration means that stage never began; zero is a measured, millisecond-rounded duration.
- Artifact references are safe relative paths with SHA-256, byte count, and role. Traversal, reserved control-file names, symlinks, and duplicate path aliases are rejected. Exact output evidence means artifact-hash agreement; numerical/approximate/unassessed evidence is distinct and makes no visual-quality claim.
- A run is one ordered sample (`sample_index: 0`) in a fresh process, without retries. In-process policy is representable but rejected by this supervisor. Declaring a cold/warm policy does not prove that cache state was achieved.

### Subprocess protocol and safety limits

`supervise` requires the explicit `--cpu-only` acknowledgment. It is **not** a sandbox or a GPU-idleness check; do not use it for model/GPU work before the guarded native capture path exists.

The supervisor launches an explicit executable and literal argument vector in a new per-run directory. It clears the inherited environment, retains only explicit `--env KEY=VALUE` entries, and supplies:

| Variable | Meaning |
| --- | --- |
| `MIL_REQUEST_PATH` | Absolute path to the persisted workload JSON |
| `MIL_RESULT_PATH` | Absolute destination for the adapter's versioned result JSON |
| `MIL_RUN_DIR` | Absolute run directory, also the child working directory |
| `MIL_WORKLOAD_IDENTITY` | Identity of the requested workload |

Progress belongs on stdout/stderr, retained in separate logs. The adapter writes `result.json` and its relative artifacts; success requires exit zero, valid matching structured evidence, and artifact size/hash verification. This layer verifies files, **not decoded image/video/audio correctness**. Invocation argument/environment values are redacted in the manifest, but workload documents, paths, artifacts, and raw logs are private evidence and may still contain sensitive content. Nothing is automatically uploaded.

Requested/running/final manifests use atomic replacement and file/directory synchronization. Existing runs are never reused. Supply canonical real-directory roots: symlink ancestors (including macOS `/tmp` and `/var` aliases) are rejected. SIGINT/SIGTERM finalize cancellation and clean up only the owned process group. SIGKILL or power loss may leave a durable `running` record: it means unresolved owner liveness, not success or proof that the child stopped. Offline inspection never signals a process or rewrites that record.

Process ownership pins the unreaped leader until group cleanup completes. On Darwin, zombie-only groups can return `EPERM`; cleanup accepts that case only after confirming the exited owned leader is the sole listed member. Actual signal delivery and observed group quiescence are recorded separately. Trusted children must not escape with `setsid`/`setpgid`; embedding applications must not install competing child reapers. Group signaling does not prove that every descendant has exited.

Execution has an explicit deadline, bounded stdout/stderr, and polled output-size limits. Disk polling is **not a filesystem quota** and can overshoot between observations. Cleanup uses a 100 ms TERM grace and a 1 s KILL observation bound; artifact hashing has a separate 30 s cooperative deadline. Stalled filesystem I/O is not bounded by an OS-enforced timeout. These CPU supervisor bounds do not replace #11's memory, swap, disk, live-job, and exclusive-GPU guards.

Observed verification: 28 CPU regression tests passed (12 schema, 16 lifecycle). Actual CLI smoke covered image/video protocol records, nonzero exit, missing/malformed result, spawn failure, timeout, log overflow, SIGINT cancellation, abrupt supervisor death, and offline artifact corruption. No real runtime/model capture was run.

The repository is private initially. Public release, licensing, and sharing local artifacts require an explicit owner decision; this repository does not grant rights to third-party runtimes, model weights, or unpublished patches.
