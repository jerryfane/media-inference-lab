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

The Rust CLI implements versioned image/video evidence contracts, CPU-only subprocess supervision, offline inspection and repeated-study comparison, macOS resource observations and a cooperating-process lease, plus read-only MFLUX metadata preflight. **There is no authorized model-capture command yet.** `supervise-guarded` still requires `--cpu-only`; passing guards, static preflight or comparison never grants GPU access. Native inference adapters (#12/#15) and actual media decoding (#13/#16) remain prerequisites. No image/video generation or performance claim is established by these CPU examples.

### Build and CPU verification

Use a Rust toolchain supporting edition 2024 and an existing Python 3 for metadata-fixture tests. Observed checks used Rust/Cargo 1.98.0 on Darwin arm64. The supervisor implements macOS/Linux process ownership; Linux has not been exercised. Native collectors support macOS only and fail closed elsewhere. Default checks require no models, MLX/MFLUX installation, GPU, or model downloads.

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

### Versioned evidence contract

- `src/schema.rs` defines **workload version 1** and **adapter-result version 2**; `src/capture.rs` defines **capture-record version 2**, adding optional guard-report provenance. Unknown fields and unsupported versions are rejected. Capture-record v1 evidence remains unchanged on disk but requires the earlier reader; no automatic migration occurs. Adapter-result v1 is no longer accepted: v2 makes model-level fingerprint evidence explicit instead of treating a partial file inventory as an exhaustive model fingerprint. Workload identities are unchanged by these cutovers.
- Workload identity is SHA-256 of Rust's typed JSON serialization of **all** declared fields, including prompts, reference hashes, precision/quantization, optimizations, batching, process/cache policy, video layers, reuse intervals, playback FPS, and audio. Whitespace in strings is significant; JSON formatting/key order is not. Adapters copy the supervisor-supplied identity rather than reimplement its serialization.
- Declared and resolved settings remain separate. Explicit settings cannot change. Only requested `precision: "auto"` and `compute_precision: null` can resolve to concrete choices; results must record those choices. Observed model/source/module/executable identity and actual cache state are separate from requests. Native adapters must reject unsupported settings; the shared schema alone does not prove a runtime supports them.
- An available observed model requires `fingerprint`, either `{"status":"unavailable","reason":"Model fingerprint was not measured"}` or an available value containing `sha256` and its derivation `method`. A requested `model.sha256` is compared only with that available model-level observation. Independent `model.files` hashes remain partial provenance: an unrelated config hash cannot contradict an unmeasured weights fingerprint. A concrete model-level mismatch still fails validation.
- Compatibility preserves signed-zero identity in nested reference strengths, video reuse ratios, and audio-reference strengths as well as the top-level floating-point settings. A `0.0` → `-0.0` change cannot pass compatibility while changing workload identity.
- Unavailable observations carry a reason. Timings retain units, method, scope, and boundaries; RSS, tensor bytes, driver allocation, system pressure, and swap cannot substitute for each other. Host execution, cleanup, and artifact-inspection durations are separate. A null lifecycle stage duration means that stage never began; zero is a measured, millisecond-rounded duration.
- Artifact references are safe relative paths with SHA-256, byte count, and role. Traversal, reserved control-file names, symlinks, and duplicate path aliases are rejected. Duplicate and ancestor checks share Unicode canonical-normalization and lowercase keys, without changing the stored spelling. Unix capture also rejects repeated device/inode identities, including differently named hardlinks; distinct files with equal contents remain valid. Exact output evidence means artifact-hash agreement; numerical/approximate/unassessed evidence is distinct and makes no visual-quality claim.
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

Each requested/result JSON document and terminal manifest is bounded at 16 MiB. The initial running manifest reserves 64 KiB for terminal metadata before any child starts; retained failure text is capped at 8 KiB with an explicit truncation marker. If valid requested and result documents together exceed the terminal manifest bound, capture records `failed`, prints the run directory, and preserves actual exit/cleanup/timing evidence. Only the embedded result copy is omitted; the original `result.json`, artifacts, and logs remain intact. Ordinary filesystem errors are not reclassified as size failures.

Process ownership pins the unreaped leader until group cleanup completes. On Darwin, zombie-only groups can return `EPERM`; cleanup accepts that case only after confirming the exited owned leader is the sole listed member. Actual signal delivery and observed group quiescence are recorded separately. Trusted children must not escape with `setsid`/`setpgid`; embedding applications must not install competing child reapers. Group signaling does not prove that every descendant has exited.

Execution has an explicit deadline, bounded stdout/stderr, and polled output-size limits. Disk polling is **not a filesystem quota** and can overshoot between observations. Cleanup uses a 100 ms TERM grace and a 1 s KILL observation bound; artifact hashing has a separate 30 s cooperative deadline. Stalled filesystem I/O is not bounded by an OS-enforced timeout. Unguarded `supervise` does not perform the checks described below.

Established baseline verification at `0346b2d`: 28 CPU regression tests passed (12 schema, 16 lifecycle), with the original CLI lifecycle smoke. Review corrections were verified separately with `cargo test --test review_capture --test review_schema`: **11 new regressions passed**, and Clippy passed with warnings denied. The original suites were not rerun merely to confirm the review observations.

Actual before/after CLI proof reproduced and corrected the 9 MiB combined-manifest failure (64 MiB output budget), composed/decomposed APFS alias acceptance, partial model-file evidence rejection, and nested signed-zero compatibility. After correction, the combined-size case retains an inspectable terminal failure; aliases are rejected; unrelated config evidence leaves an unavailable model fingerprint unknown; concrete fingerprint mismatches and nested signed-zero changes fail validation. No real runtime/model capture was run.

### CPU-only guarded supervision

`mil guard-check --config GUARD.json --output NEW-REPORT.json` acquires the project lease, collects a launch snapshot, writes a non-overwriting report, and releases the lease. Exit `0` means these observations passed, **not that a GPU window is reserved**. Contention returns `2`; a recorded denial returns `1`.

The guard config has five required fields:

| Field | Meaning |
| --- | --- |
| `live_app_pid` | Freshly observed reference application PID |
| `live_app_command_sha256` | Lowercase SHA-256 of its trimmed command column from `/bin/ps -axo pid=,ppid=,command=` |
| `min_disk_free_bytes` | Positive filesystem available-space floor; smoke used 10 GiB |
| `max_disk_growth_bytes` | Positive maximum decrease from baseline filesystem available bytes; ordinary smoke used 256 MiB |
| `sample_interval_ms` | Target observation interval, 100–1000 ms; smoke used 100 ms |

Do not store workstation PID/configuration in a committed example. The live reference signature is the existing `uvicorn backend.app:app` application on port 7860. Its PID/command identity must match exactly and uniquely. Any observed descendant or recognized image/video/H3 worker denies launch or cancels this project's owned capture. Raw process commands are not serialized. The live API lacks aggregate queue/idleness state; worker absence cannot exclude queued/in-process jobs, unrelated GPU work, PID reuse, or activity between polls.

For a trusted CPU fixture, use the earlier `supervise` example with `supervise-guarded --guard-config GUARD.json` instead. Keep `--cpu-only`, the same schema fixture and literal arguments. Guarded execution is capped at 600 seconds. `guards.json` records methods, config, launch baseline, subsequent observations and decisions; terminal manifests reference its SHA-256/byte count. Offline `inspect` checks that evidence and rejects completed captures containing denied observations. The report is capture-owned, excluded from adapter output accounting, separately bounded at 16 MiB, and cannot be an adapter artifact.

Fixed memory policy: launch requires at least 30% from `/usr/bin/memory_pressure -Q`; running capture cancels below 15% or when `/usr/sbin/sysctl vm.swapusage` indicates more than 512 MiB growth from baseline. These are rounded system indications, **not GPU-memory measurements**. `statvfs` supplies filesystem available bytes, not a per-run quota. Missing/malformed required observations deny execution. Each command collector has a 2-second bound and bounded output; sequential collection is not atomic and can delay polling.

The persistent owner-private lease is `$HOME/.local/share/media-inference-lab/gpu.lock`. Kernel `flock` contention never triggers retries or killing another owner. Never unlink/replace the inode to “clear” a lease. Close-only release permits an owned child retaining the inherited descriptor to hold the lock after supervisor death; ownership recovers when all such descriptors close. Descendants that escape their process group or close that descriptor are outside these guarantees. The lease covers cooperating project processes only.

Before any later heavy run: deliver the exact isolated environment/model identities, no-download evidence, full-shape command/settings and execution/disk bounds; obtain a fresh explicit `mac-studio` scheduling grant; immediately recheck live-job/unrelated-GPU state, lease contention, memory and swap. Existing reports are historical evidence, not a reusable grant.

### Read-only native MFLUX preflight

```sh
target/debug/mil mflux-preflight \
  --python /absolute/isolated-venv/bin/python \
  --model-dir /absolute/existing/local-snapshot \
  --workload /absolute/native-workload.json \
  --output /absolute/new-preflight-report.json \
  --timeout-seconds 60
```

Choose an existing isolated venv (`include-system-site-packages = false`); nothing is installed into it. Workload schema remains v1. Unlike the schema-only example, set `model.name` to `Qwen/Qwen-Image-2.1` or `qwen-image-2.1`, precision to `bfloat16` or `auto`, scheduler to `linear`, and dimensions to positive multiples of 16. Only batch-one text-to-image is supported. Compute precision may be null or explicit `float16`; unsupported reference/strength/cache flags fail before checkpoint traversal. Quantization is never added implicitly. Declared model payload hashes cannot be verified in this mode and are rejected. The CPU smoke inspected a 1536×864, 40-step, guidance-4, unquantized request without executing it.

Shared-contract optional fields accept omission exactly like explicit null: model `revision`/`sha256`, generation `strength`/`compute_precision`/`negative_prompt`, and each member of `optimizations`. The `optimizations` object itself remains required, as do other non-optional workload fields. Equivalent forms preserve workload identity and resolved native arguments.

Rust launches the selected Python with `-I -S -B`, cleared environment and explicit offline variables. The stdlib-only adapter disables site hooks and blocks network operations, subprocess execution, native MLX/MFLUX imports and filesystem writes through its audit hook. The report records blocked network-resolution and subprocess probes, actual interpreter executable hash, venv config, installed distribution metadata, separately selected static MFLUX source/API hashes, local config/tokenizer metadata and safetensors header/index observations. Executable `.pth` lines are reported but never run. No third-party runtime is imported, no model/tensor payload is loaded, and no package/model download is attempted.

Bounds: 1 MiB workload, 16 MiB per metadata/header read, 128 MiB cumulative reads, 4096 file reads, 200000 tensors per header, 64 MiB interpreter-hash limit, 4 MiB stdout, 64 KiB diagnostics, and 1–120 seconds execution. Existing reports are never overwritten; dependency/model/request/launcher failures retain actionable JSON reports and return `1`. Native imported-code identity, dependency ABI compatibility, complete parameter compatibility, shared-library identity and weight-payload integrity remain explicitly unavailable. This is not an adapter-result document or a working inference benchmark.

The metadata reader uses unbuffered descriptor reads, checks the remaining cumulative budget before each read, and accounts actual returned bytes even on truncated input. Safetensors reads stop after the 8-byte length and declared header; Python buffering cannot read ahead into tensor payloads. This bounds userspace file reads, not the operating system's disk/page-cache prefetch.

CPU verification for this slice: `cargo test --test guards --test guard_capture --test preflight` (20 cases passed across focused runs), `cargo clippy --all-targets -- -D warnings`, and `cargo build --bin mil`. The migrated capture-version rejection case was checked separately. Actual CLI proof observed guard-check success, lease contention rejection, completed guarded capture plus offline inspect, and a disk-growth interruption after a bounded 4 MiB owned write, retaining a cancelled outcome and owned-group cleanup. Selected real-environment/local-model static preflight passed; a missing local model produced an actionable failure without downloads. No live service/configuration was changed and no GPU window, native import, model execution or benchmark was exercised.

PR28 review correction: the earlier `14d31bb` reader was buffered. Its reported 37,509,546 bytes were logical accounting, not verified physical read volume; the earlier “no tensor payload reads” claim is withdrawn for those historical reports. They are preserved unchanged. Corrected verification used only generated toy metadata: `cargo test --test preflight review_` passed two new regressions (the original ten were filtered out), followed by Clippy/build. A 76-byte toy checkpoint left descriptor offsets/accounting at 8 then 72, before its four payload bytes. Actual `mil validate`/`mflux-preflight` accepted eleven explicit-null/omitted-option forms with identical identities and resolved arguments; three missing-required-field controls still failed. No real weight files were reread for this correction.


### Bounded offline baseline/candidate/control studies

`study-plan` and `compare` do not execute an adapter, import a runtime, download weights, or grant execution authorization:

```sh
mkdir -p runs
target/debug/mil study-plan examples/cpu-study-plan.json \
  --output runs/cpu-study.json
target/debug/mil compare runs/cpu-study.json \
  --output runs/cpu-study-report.json --inspection-seconds 60
```

The example declares a **CPU schema fixture study, not inference**. Its generated template initially contains twelve missing bindings, so the second command produces an `inconclusive` report and exits `1`. Before collecting a study, retain the intended plan; populate each binding afterward with its saved capture directory and `missing_reason: null`, or keep `capture: null` and an explicit missing reason. There is no automatic study executor or retry. Authorized CPU captures can use `supervise --cpu-only`; these commands do not make a native/GPU capture authorized.

`src/study.rs` defines strict plan/input schema v1. The plan embeds the complete requested workload and names baseline/candidate variants, mode, metric, repetitions, warmups, and minimum sample count. Ordering is fixed: all declared warmup cycles first, then measured cycles; each cycle is **baseline → candidate → unchanged-baseline control**. Every slot has a zero-based index and must remain in order, including failures and warmups. Repetitions are 1–30 per role, warmups 0–3 per role, minimum samples 3–30, with at most 99 slots. Fewer repetitions than the declared minimum are allowed but cannot produce a complete study.

Bindings use absolute paths or paths relative to the study JSON's directory. Existing capture inspection rules still require real directory components: use canonical absolute paths instead of symlinks or `..`. Plan JSON is capped at 1 MiB; populated studies and output JSON are capped at 16 MiB, so template expansion does not make a valid generated file unreadable. Outputs are private, create-new files and never overwrite existing evidence. Output I/O/size failure returns `2` and may leave a partial file; it is not a valid report. The 1–120 second inspection budget is cooperative between slots: existing per-capture inspection or stalled filesystem calls can overrun it. Remaining slots are retained with explicit unavailable observations.

Select `{"kind":"host_execution"}` for the saved monotonic spawn-to-leader-exit/stop boundary, **not inference time**. Or select an adapter timing with `{"kind":"adapter","phase":"generation","scope":"native","method":"EXACT_RECORDED_METHOD","boundary":"EXACT_RECORDED_BOUNDARY"}`. Phase, scope, method and boundary must match exactly; duplicate matches or unavailable observations are not measurements. Seconds/milliseconds/nanoseconds normalize to seconds without silently underflowing a positive value to zero.

`same_work` requires matching requested/resolved workload identities, observed model-level fingerprint and derivation, host/device/cache evidence, stable per-role runtime identity and unchanged baseline/control runtime. Named candidate runtime/source changes are disclosed. Strict unchanged-runtime checks require clean recorded source and available executable/module hashes; a dirty source revision does not fingerprint its working tree. Missing evidence and partial model-file inventories never establish equality. Measured cache state is compared against the measured baseline; warmup cache transitions remain visible but do not redefine that boundary. Declared warmups do not prove a warm cache.

Launch configuration is also checked against baseline/control and within every role. Executable identity, observed argument count, and environment-key changes are retained as differences; named candidate launch changes can be disclosed without requiring baseline equality, but within-role stability still applies. Capture v2 redacts all argument/environment values: matching placeholders never prove equal user configuration. Any user argument or non-protocol environment key therefore leaves launch compatibility unknown, even when every recorded invocation hash matches. Only the supervisor-derived `MIL_RUN_DIR`, `MIL_REQUEST_PATH`, `MIL_RESULT_PATH`, and `MIL_WORKLOAD_IDENTITY` fields are exempt; their workload identity is checked separately. No other `MIL_` prefix is exempt. Strict ratios are suppressed for unknown launch configuration; descriptive ratios may remain available with an inconclusive status. This comparison does not change capture redaction or record secrets.

Reports retain every row, outcome/reason, listed timestamp order, provenance and selected metric or unavailability. Duplicate canonical directories and copied typed manifests cannot count as independent samples. Full typed-JSON hashes accompany bounded 512-byte provenance previews with explicit truncation; the previews are not identities. Each role reports planned/measured/failed/missing/warmup/excluded counts, individual included values, median and min/max. Candidate/baseline median ratios and control/baseline drift are **descriptive**, with change fraction `ratio - 1`; zero denominators and numeric overflow/underflow remain unavailable. Same-work ratios are suppressed when compatibility/order is not established. `descriptive` mode can expose cross-runtime/device or unknown-provenance ratios, but retains incompatibilities and an inconclusive status.

Each role also exposes `median_unavailable_reason`. If an even-sample midpoint is mathematically positive but rounds to zero, the median and dependent comparisons are unavailable and the report is inconclusive; all original values, counts and extrema remain intact. An unavailable baseline median suppresses both candidate and control comparisons. Genuine zero medians remain measured zero, including all-zero samples or a zero central pair with a positive tail; representable subnormal medians remain available.

Exit `0` means the declared plan/report is structurally valid and, for comparison, its evidence is complete under the configured policy. It is **not** a statistical significance, causal speedup, reproducibility, inference-performance or quality verdict. Exit `1` retains an inconclusive report; exit `2` indicates invalid study input or output/infrastructure failure. Hashes are not authentication, matching host metadata is not physical machine identity, and offline bindings cannot prove predeclaration, detect unlisted runs, or authorize execution.

Focused CPU verification: 22 comparison fixtures and seven plan cases passed with `cargo test --test comparison --test study_plan`; the generated near-limit template regression passed with `cargo test --test study_cli`; Clippy/build passed. Integration regressions caught and corrected warmup-cache cohort selection, dirty-source identity, positive-ratio underflow and template expansion beyond the original input limit. Actual CLI proof retained twelve fresh CPU subprocess captures (three warmups, nine measured), then compared them without changing any of their 72 evidence files. Host medians were 0.068/0.087/0.058 seconds for baseline/candidate/control; the report correctly remained inconclusive because native model/runtime/device/cache provenance was unavailable. Strict ratios were suppressed, an unreadable slot remained visible, and an existing report was preserved on overwrite rejection. These are CPU fixture timings, not a real image/video study; #18's real-study acceptance remains unexecuted.

PR29 review corrections were checked after implementation with `cargo test --test comparison review_`: six new regressions passed (the filter also selected the existing bounded-preview regression; seven passed, 21 filtered out). Clippy/build passed. Nine generated persisted-fixture studies exercised the real `compare` CLI: changed control environment and within-role arguments failed compatibility; equal redactions remained unknown; a known stable candidate launcher change remained disclosed and comparable. Positive candidate/baseline median underflow retained the original values and unavailable medians/ratios, while genuine-zero and representable-subnormal controls stayed valid. All 558 synthetic evidence files remained byte-identical. No established full suite, FIFO probe, real image/video study, model or native runtime was rerun for this correction.

The repository is private initially. Public release, licensing, and sharing local artifacts require an explicit owner decision; this repository does not grant rights to third-party runtimes, model weights, or unpublished patches.
