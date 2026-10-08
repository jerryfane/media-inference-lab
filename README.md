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

The Rust CLI implements versioned image/video evidence contracts, CPU-only subprocess supervision, offline comparisons/reports, macOS resource observations and a cooperating-process lease, read-only MFLUX metadata preflight, and a thin native Qwen Image 2.1 adapter with explicit `mflux-run` preparation/launch handling. **Native execution is blocked, not ready for a scheduling slot:** authoritative aggregate live-queue and unrelated-GPU readiness integrations are absent. Native imports, allocation, generation and result acceptance have not been exercised. `supervise` and `supervise-guarded` remain CPU-only; neither is an inference entry point. Real-runtime acceptance for #11/#12, video integration (#15), capture-integrated image checks (#13) and full video/audio validation (#16) remain open. No inference-performance claim is established by CPU examples.

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

`supervise` requires the explicit `--cpu-only` acknowledgment. It is **not** a sandbox or a GPU-idleness check. Never route inference through either CPU supervision command; the separate native path below is currently fail-closed.

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

Before any later native import or heavy run, the missing authoritative readiness/coordination integrations must be separately scoped and authorized. Health, per-known-job lookup, worker absence, files/logs, memory/process observations and the cooperating lease cannot establish global readiness or prevent new admissions. Do not add a manual-ready file, callback, fabricated producer or manager-reference override. After genuine integration exists, deliver exact environment/source/model/workload/command identities and execution/disk bounds, obtain a fresh explicit `mac-studio` grant, and check authoritative readiness plus resource/lease guards. Historical reports and grants are not reusable readiness. `guard-check` acquires the shared lease and writes output; it is not a read-only readiness inquiry.

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


### Native Qwen runner: preparation and blocked launch

`adapters/mflux_native.py` calls the actual `QwenImage21` constructor and `generate_image`, synchronizes MLX, and serializes the returned PIL image. It does not emulate inference or shell out to the MFLUX CLI. Use an existing isolated venv, explicit editable-package root, expected Python-source-tree hash, and existing local snapshot:

```sh
target/debug/mil mflux-run --check-only \
  --python /absolute/isolated-venv/bin/python \
  --source-dir /absolute/source/src/mflux \
  --source-sha256 "$EXPECTED_PYTHON_TREE_SHA256" \
  --model-dir /absolute/existing/local-snapshot \
  --workload /absolute/native-workload.json \
  --guard-config /absolute/guard-config.json \
  --root /absolute/owned-native-runs \
  --output /absolute/new-native-preparation.json \
  --timeout-seconds 600 --check-timeout-seconds 60 \
  --max-output-bytes 67108864
```

The two modes are mutually exclusive and mandatory. `--check-only` returns `0` for static validation, **not authorization or native success**; its report explicitly says `checked_not_executed`. `--execute` currently returns `1` with both missing readiness reasons **before Python, native imports, shared-lease acquisition or capture-directory creation**. `--manager-grant-reference TEXT` records external provenance only; it is not authenticated authorization and cannot change readiness. Replacing the mode is not a valid scheduling request until the missing integrations exist. No producer/override input is offered.

The preparation report records a deterministic SHA-256 identity over the typed workload, selected venv invocation and resolved executable hash, expected source hash, adapter/helper hashes, local model selection, arguments/environment, output root, bounds, and selected resource-guard config. The canonical base executable is **never substituted for the venv invocation**. Dynamic run paths, report destination, timestamps and external grant reference are excluded from that identity. A selected guard config or model-directory name is not a fresh process observation or an attested model revision.

Native support is batch-one text-to-image, Qwen Image 2.1, linear scheduler, unquantized BF16 model precision (`auto` may resolve to BF16), null or explicit float16 compute override, dimensions divisible by 16, fresh process and unspecified cache state. References/strength, other quantization, KV-cache and cache-threshold settings are rejected. The API's step-cache ratio is forwarded only when explicitly requested; none is added implicitly. The approved baseline retains **1536×864, 40 steps, guidance 4, seed 17, null negative prompt, BF16, null compute override, no quantization and all optimization fields null**. In the selected native implementation, null/empty negative prompt disables true CFG even when guidance exceeds 1; the runner records this without changing the request.

Rust uses `-I -S -B`, clears inherited environment, and applies the macOS sandbox: no network, and no writes during CPU checks; a future authorized native child may write only inside its private run. Site hooks and executable `.pth` lines are never executed. A new empty private bytecode prefix prevents loading old source-tree `.pyc` files. Native cache/home/temp directories are run-owned. Python audit restrictions are defense in depth, not native-extension isolation. Nothing installs packages, changes source/model stores or live services, downloads weights, retries or uploads evidence.

The native supervisor retains fixed launch ≥30%, abort <15% and swap-growth >512 MiB system guards, the close-only cooperating lease, continuous observations and owned-process-group cleanup. Native guard reports use schema 2 with independently recomputed resource and required-readiness decisions; existing CPU guard reports remain schema 1. Workload 1, adapter-result 2 and capture-record 2 are retained. Capture invocations add optional native command/sandbox provenance. Bounds: native 1–600 seconds, CPU check 1–120 seconds, output/log budget 1 byte–1 GiB; the example selects 64 MiB. Polling/individual-file limits are not an atomic filesystem quota, and blocked filesystem syscalls have no forced deadline.

Handled validation/launch failures retain a new mode-0600 attempt report and return `1`; existing reports are never overwritten. Infrastructure/parser errors return `2`. A spawned native child journals `native-status.json`; failed/cancelled runs retain partial outcomes, not fabricated successful results. Successful native code writes `artifacts/image.png`, hashed `artifacts/native-provenance.json`, and adapter-result v2. A child exit alone does not establish native execution: the attempt field is null for unsuccessful spawned captures where execution cannot be established.

Provenance separates installed distribution metadata from actual imported module paths/hashes and source-tree identity. It records returned settings, host import/constructor/synchronized-generation timing boundaries, process RSS and available MLX allocator readings; native tqdm duration is not substituted for complete generation time. Lazy constructor timing does not assert completed weight evaluation. Device identity, actual cache warmth, unattested revisions and full weight-payload fingerprint remain explicitly unavailable; metadata/header hashes and stat stability are **not** payload integrity. Native ABI/parameter compatibility and resource APIs require a real authorized run. These unknowns cannot establish strict same-work identity or a controlled speedup. Generated PNG evidence remains unassessed until separately compared; numerical differences are not quality verdicts.

Observed CPU verification: five adapter safety/validation cases, two new CLI denial/retention cases and four native-guard cases passed; Clippy all-targets and `cargo build --bin mil` passed. The new CLI's check-only path passed against the selected existing venv/source/snapshot and unchanged full-shape workload, with native import identity unavailable and readiness denied. No native import, model allocation, inference, benchmark, shared-lease acquisition or readiness-source re-probe occurred in that CLI smoke. #11/#12 remain open.

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

### Readable repeated-study metadata bundles

`study-report` uses the same comparison policy and saved captures, without executing an adapter:

```sh
target/debug/mil study-report runs/cpu-study.json \
  --output-dir runs/cpu-study-bundle --inspection-seconds 60
```

Open `runs/cpu-study-bundle/report.md` in a local Markdown reader. The unpopulated template above produces an **INCONCLUSIVE** bundle and exits `1`. Exit `0` means complete saved evidence under the existing comparison policy, not a performance, quality, statistical or reproducibility verdict. Invalid input or output failure exits `2`; no retries or execution authorization are added. The compact `compare --output` command and comparison schema remain unchanged.

The readable report exposes requested settings and timing boundaries; role counts, every included value, medians/extrema and their actual denominators; candidate/baseline comparisons and unchanged-control drift; and every ordered slot, including failures, warmups, duplicates, missing/invalid records and exclusions. Strict suppression and descriptive-mode incompatibility remain visible. Host/application/native/kernel scopes are not interchangeable; resource observations retain their original scope and availability. No throughput, playback-FPS equivalence or combined modality score is invented.

Bundle schema v1 (`kind: "offline_study_comparison_bundle"`) contains the complete typed study input, original source directory, unchanged comparison report, slot-indexed optional capture-snapshot artifacts, and a hashed `report.md` reference. Every successfully loaded record is serialized from the **same inspected object**, including failed/excluded captures, into `captures/slot-NNN.json`. These full typed snapshots preserve metadata beyond the comparison's explicitly truncated 512-byte previews. Their file hashes differ from typed-manifest identities because the byte representations differ. Missing/invalid/uninspected records have explicit null inventory entries, not fabricated snapshots. Markdown reloads and verifies one snapshot at a time rather than rereading original capture sources.

This is a portable **metadata report, not a replayable capture archive**: media, logs and guard payloads are not copied. Their recorded references/hashes and original capture locations remain provenance; payload access still requires the original evidence. Only fixed local JSON/snapshot links are emitted. Caller strings remain literal fenced data with terminal controls escaped, using the same renderer as PNG reports; JSON preserves original strings. Hashes are integrity checks, not authenticated provenance.

Input is capped at 16 MiB. Snapshots are bounded at 16 MiB each and 256 MiB total, Markdown at 64 MiB and final JSON at 32 MiB: at most 352 MiB of bundle file payload. Directories are private (0700), files private (0600), subject to a stricter umask; existing directories are never reused. Invalid plans fail before directory creation. Snapshot/output/quota failure may leave a partial private directory and is not a complete report; `report.json` is written last. The 1–120 second inspection budget remains cooperative between slots and includes archive writes; snapshot verification/rendering and stalled filesystem calls have no forced I/O deadline.

Observed CPU verification: five archive tests (`cargo test --lib capture_archive::tests`) and three bundle regressions (`cargo test --test study_report`) passed, including hash/size/symlink/quota rejection, full metadata after original-source removal, tamper rejection, all-slot preservation, safe Markdown links, relocation and no overwrite. `cargo clippy --all-targets -- -D warnings` and `cargo build --bin mil` passed. Seven fresh actual `study-report` CLI scenarios covered complete synthetic control drift, mixed failed/missing/invalid evidence, strict versus descriptive unknown-device evidence, all-uncollected slots, malformed input and existing output. Generated complete medians were 4/3/5 seconds (ratios 0.75/1.25); these are deliberately synthetic, not measurements. All 281 generated source evidence files remained byte-identical. Artifact hashes, sizes and private modes were checked; emitted Markdown was inspected. Previous accepted PR29–31 probes were not rerun.

This completes the readable saved-study metadata slice, not native inference integration or the full #20 acceptance. Real-runtime image/video studies, media-specific inspection and remaining audio/video reporting stay open with #18/#19/#20.

### Offline PNG comparison and inspection bundles

`compare-images` reads existing files only; it does not execute an adapter or load a model. Static PNG is the supported format: unchanged 8/16-bit grayscale, grayscale-alpha, RGB or RGBA samples, including Adam7. Indexed/sub-byte PNG, APNG, other formats, mismatched dimensions/channel layout/bit depth, malformed/truncated chunks, CRC failures, incomplete or extra zlib data and trailing bytes are rejected rather than resized, converted, truncated or assigned similarity.

Transparency (`tRNS`) structure is checked explicitly, not inferred from decoder ancillary events: exactly two payload bytes for grayscale or six for RGB (at either supported bit depth), at most one occurrence, before any `IDAT` and after `PLTE` if a palette is present. `tRNS` is forbidden for grayscale-alpha/RGBA. Valid transparency metadata remains byte-for-byte in the original snapshot; transparent-color keys are not expanded into alpha or applied to the raw sample comparison.

```sh
mkdir -p runs
target/debug/mil compare-images \
  --baseline /absolute/baseline.png \
  --candidate /absolute/candidate.png \
  --baseline-repeat /absolute/separate-baseline-repeat.png \
  --output-dir runs/png-comparison
```

The baseline-repeat input is optional; without it, baseline variation is explicitly unavailable, never substituted from the candidate. A supplied repeat retains its own identity and full numerical comparison with the baseline. These files alone do not establish independently generated repetitions, identical operator inputs/seeds, runtime/workload compatibility, or a controlled experiment. This command does not change the repeated-study `compare` policy.

The new directory contains private, create-new `baseline.png`, `candidate.png`, optional `baseline-repeat.png`, `sheet.png`, `report.md` and `report.json`. Original copies come from the **same retained bytes** hashed and decoded, not a later source reread. Bundle schema v1 includes the versioned PNG comparison, shared artifact references with safe relative names, SHA-256/byte counts (including the readable report), and sheet layout. Source paths are provenance; use the bundled copies after moving the report. The sheet places baseline left and candidate right, with unchanged sample values and no scaling. It intentionally omits ancillary metadata; inspect originals for color-managed appearance. No gamma/profile conversion, EXIF reorientation, transparency expansion, compositing or premultiplication is performed. Text/ICC payload semantics and unknown ancillary semantics are not interpreted; their chunk envelopes/CRCs are checked and original bytes retained.

Metrics cover **every stored sample**, including all alpha-channel samples and RGB codes under transparent pixels. The report separates encoded-file equality from decoded-sample equality, records dimensions/color layout/bit depth, raw row-major sample hashes (big-endian for 16-bit), pixel/channel/sample counts, exact integer absolute/squared error totals, maximum absolute error, MAE/RMSE in integer sample-code units, and PSNR in decibels with peak `2^bit_depth - 1`. Zero squared error has the explicit `positive_infinity` PSNR tag, not a fake finite value. Exact totals and `sample_count` recover every floating metric's denominator.

No numerical tolerance is supplied by default. To apply one, provide **both** `--max-absolute-error N` and `--tolerance-rationale TEXT`; `N` is a per-sample integer-code bound within the input dtype's range. Declare and justify it before inspecting outcomes; do not relax it to obtain a pass. A nonblank rationale is required but its scientific validity is not automatically established. Classifications are `exact_decoded`, `within_tolerance`, `outside_tolerance`, and `different_unbounded`. Exit `0` means only exact decoded samples or compliance with the explicit candidate bound; exit `1` retains a valid differing/out-of-bound report. Baseline-repeat variation remains separate and does not redefine the candidate threshold. None of these results is a visual-quality, reproducibility or performance verdict.

Optional `--assessment /absolute/review.json` retains a **separate, caller-supplied record**, never synthesizes a quality judgment from the metrics, and never overrides their classification. The strict assessment schema requires:

- `schema_version: 1`, `baseline_sha256` and `candidate_sha256` matching the actual **encoded** inputs;
- nonblank `reviewer` and `protocol`;
- `prompt_adherence` and `artifacts`, each an existing observation object: `status: "available"` with a nonblank `value`, or `status: "unavailable"` with a nonblank `reason`;
- 1–64 nonblank `limitations`, with each text field at most 8192 UTF-8 bytes.

The CLI assessment document is capped at 64 KiB. Review identity/protocol/observations are not authenticated or independently verified. Missing review remains explicitly unavailable even for exact samples; matching hashes bind an assessment to files, not to a trusted reviewer. Assistant observations and low error/high PSNR do not establish perceptual equivalence.

Input bounds per PNG: regular non-symlink file, at most 32 MiB encoded, axes at most 16384, at most 16,777,216 pixels and 128 MiB decoded bytes; the PNG raster decoder has a 128 MiB internal allocation limit. A growing input can consume one additional oversize-sentinel byte before rejection. The zlib verification pass uses fixed 32 KiB scratch space and bounds decompressed production against the expected full raster; no extra full raster is retained for it. Up to three decoded inputs and their encoded snapshots are retained. These are allocation/data bounds, not an OS wall-clock timeout or a total-process RSS claim; stalled regular-file I/O can still block. A snapshot does not guarantee atomicity against concurrent in-place writers.

Sheet output is capped at 270 MiB, Markdown at 1 MiB and JSON at 16 MiB; with three maximum-size source copies, bundle file payload is bounded at 383 MiB. Sheets may have twice the input width/pixel count and consequently exceed this command's input limits. Output directories are mode 0700 and files mode 0600 (subject to a stricter umask). Existing directories are never reused or overwritten. Invalid/unsupported inputs fail with exit `2` before creating the bundle; output I/O failures return `2`, may leave a partial private directory, and never imply success. The JSON report is written last, after the readable report's hash/size is known. Paths, originals and reviewer text are private evidence; nothing is uploaded automatically.

Observed CPU verification: `cargo test --test png_image --test image_comparison --test image_comparison_cli` passed 28 new regressions (12 decoder, 14 numerical/assessment, 2 bundle CLI). Clippy identified three Rust idiom changes; after replacing constant `chunks_exact` with array chunks and using `is_multiple_of`, Clippy with warnings denied and the binary build passed. Fourteen actual CLI scenarios exercised generated PNGs, including encoded-vs-decoded equality, tolerance boundaries, baseline variation, low-order 16-bit differences, malformed streams/APNG/shape rejection, assessment binding and overwrite refusal. All eleven original generated PNGs remained unchanged; emitted artifact hashes/sizes/private modes were verified. The actual 512×128 sheet was visually inspected for left/right layout, and a separate CLI comparison verified all eight 16-bit sheet samples against independently encoded expected rows. No actual quality review, native inference, image/video model execution, or inference-performance measurement was performed. #19 remains open: video/audio/latent comparison and the real image/video study are not covered by this PNG slice.

PR30 transparency correction: the earlier pinned decoder accepted overlong and post-IDAT `tRNS` despite the strict contract. Explicit envelope checks now enforce its color-dependent lengths and ordering without transforming transparency. After coherent edits, `cargo test --test png_image review_trns_` passed three new regressions (12 existing decoder tests filtered out), followed by Clippy with warnings denied and the binary build. Nineteen new bounded CLI cases observed 13 malformed inputs exiting `2` before bundle creation, including malformed baseline/candidate/repeat inputs, and six valid grayscale/RGB 8/16-bit controls exiting `0`. Valid original transparency bytes and raw sheet samples were preserved; all 21 generated inputs and the tested binary stayed unchanged. Previously accepted suites and CLI evidence were not rerun.

### Readable local PNG reports

After the `compare-images` command above, open `runs/png-comparison/report.md` with a local Markdown reader. It is emitted for both exact/within-bound (exit `0`) and differing/out-of-bound (exit `1`) comparisons. CLI stdout still names `report.json`; its artifact inventory identifies `report.md` with role `readable_comparison_report`. Existing bundles are never rewritten. There is no hosted UI or new inference command.

The readable view leads with the numerical outcome and an explicit **not-quality/not-performance verdict** warning. Missing reviewer assessment and baseline-repeat variation are prominent; supplied reviewer identities/protocols/observations remain marked unverified. It presents the candidate and optional repeat separately, with source dimensions/channel layout/bit depth, encoded/raw-sample hashes, complete integer error totals, denominators, full-precision floating metrics, tolerance rationale, method/alignment/units and all reviewer/measurement limitations. Positive-infinite PSNR is shown as infinity for identical samples, not as zero or missing.

Links target only the fixed relative bundle filenames: JSON, original PNG copies and the raw A/B sheet. They survive moving the complete directory; original source paths are literal provenance, not links. Caller text is placed inside code fences longer than any embedded backtick run, so Markdown links/headings and HTML in notes stay data. Control characters other than newline/tab are displayed as Unicode escapes to avoid terminal actions; the JSON retains the original text. This is a readable view, not authentication or independent review.

This PNG view reports **PNG-output evidence only**. It explicitly marks hardware/model/runtime identity, generation settings/order/outcomes, application/pipeline/kernel timing, cache state, control drift and resource measurements unavailable rather than inventing values; saved-study metadata is handled separately by `study-report` above. It explains the distinction between kernel and whole-generation latency, but supplies no timing or throughput estimate, playback-FPS conflation, or combined modality score. Video/audio report workflows and the full #20 acceptance remain open alongside #18/#19.

Observed verification: after coherent edits, `cargo test --test png_report` passed three new regressions using a CommonMark parser (test-only dependency) to check literal untrusted fields, embedded fences/control characters, and offline link integrity after bundle relocation and source removal. Clippy with warnings denied and the binary build passed. Seven fresh bounded actual CLI scenarios exercised all four numerical outcomes, unavailable and supplied review records, long embedded fences, baseline-repeat reporting and overwrite refusal. Six readable bundles were produced; artifact hashes/sizes/private modes and a relocated bundle were checked. All three generated PNG inputs and the tested binary stayed unchanged during smoke; actual Markdown output was inspected. Previously cleared PR30 decoder checks, including the parent's empty-IDAT cases, were accepted without rerun. No real quality review, model/native inference/GPU execution, merge or infrastructure/policy/live-service action occurred.

### Full declared PNG-frame sequence comparisons

`compare-frames` compares **every frame in explicitly declared PNG sequences**, using the existing Rust PNG decoder without invoking an external video/audio codec process, model or inference runtime. It is not compressed-video decoding or verification that an original video was completely/correctly exported. Supply a schema-v1 manifest for each role; paths are absolute or relative to that manifest's directory:

```json
{
  "schema_version": 1,
  "frame_count": 2,
  "provenance": "Describe the source and extraction/alignment method; this declaration is unverified.",
  "frames": [
    {"index": 0, "path": "frames/0000.png", "pts_ns": 0, "duration_ns": 40000000},
    {"index": 1, "path": "frames/0001.png", "pts_ns": 40000000, "duration_ns": 40000000}
  ]
}
```

```sh
target/debug/mil compare-frames \
  --baseline /absolute/baseline-frames.json \
  --candidate /absolute/candidate-frames.json \
  --baseline-repeat /absolute/separate-repeat-frames.json \
  --output-dir runs/frame-comparison
```

The repeat is optional and is never substituted from the candidate. Indices must be exactly `0..frame_count-1`; count must match the complete list. Presentation timestamps and positive durations are integer nanoseconds, start at zero, and form contiguous intervals without gaps, overlaps or overflow. All roles must have identical counts and intervals. Variable frame durations are supported only with exactly matching declared alignment. Every PNG must retain constant width, height, channel layout and bit depth across all frames and roles, using the strict static-PNG formats/bounds above. There is no frame selection, dropping, matching, interpolation, crop, resize or sample conversion. Unsupported or late-invalid frames fail the entire comparison rather than yielding a shortened result.

The report preserves every frame's original/decoded identity and metrics, complete input declarations, all timing intervals, separate repeat results and whole-sequence totals. Aggregate integer absolute/squared errors and `N` include **all stored samples in all frames**, including alpha; they are not time-weighted. MAE is the total absolute error divided by `N`, RMSE uses the total squared error divided by `N`, and PSNR uses that same mean squared error—not an average of per-frame PSNR. No FPS, inference throughput or temporal-quality metric is inferred. Equality and low error do not establish quality, prompt adherence, a controlled experiment or matching generation settings.

Optionally declare `--max-absolute-error N --tolerance-rationale TEXT`; the rationale is mandatory and the bound must fit the sample-code range. Exit `0` means all decoded samples are exact or within this declared maximum, `1` means different without a bound or outside it, and `2` means invalid input, quota or I/O failure. Bounds are never adjusted to pass a candidate.

Sequence SHA-256 binds the complete ordered encoded PNG contents **and timing**, excluding paths/provenance: domain bytes `mil-png-sequence-v1\0` (final byte NUL), frame count and total duration as u64 big-endian, then each frame's index/PTS/duration as u64 big-endian followed by its encoded PNG SHA-256 as 64 lowercase ASCII bytes. Encoded metadata changes therefore change this identity even when decoded samples are identical. This is not a container identity or authenticated provenance.

Optional `--assessment review.json` accepts schema version 1 with `baseline_sha256` and `candidate_sha256` bound to those complete sequence identities; nonblank `reviewer` and `protocol`; `prompt_adherence`, `artifacts`, `temporal_consistency` and `audio` observations; and a `limitations` string array. Observations use `{"status":"available","value":"..."}` or `{"status":"unavailable","reason":"..."}`. Audio **must be unavailable** because this command has no decoded audio to bind. Reviewer/protocol/observations remain unverified, distinct from numerical evidence, and cannot change classification. Absence remains explicitly unassessed; no assistant quality leaderboard is produced.

The private create-new bundle includes all original PNG snapshots, an unscaled baseline-left/candidate-right sheet for **every** frame, `report.md` and final `report.json` (bundle v1, kind `offline_png_sequence_comparison_bundle`). Names are fixed under `frames/0000-baseline.png`, `0000-candidate.png`, optional `0000-repeat.png`, and `0000-sheet.png`, continuing by index. Copies come from the same retained bytes hashed/decoded, not later source rereads. Sheets omit ancillary metadata and are not color-managed quality evidence. The Markdown contains fixed local links, literal caller text, all numerical denominators and prominent unassessed/unverified warnings. Artifact hashes/byte counts support relocation independently of original source paths.

Limits: 1–1024 frames per role; manifest/assessment JSON at most 1 MiB each; cumulative encoded PNG bytes at most 512 MiB across all roles; cumulative decoded samples at most 512 MiB **per role**. Individual PNG limits still apply. Only the current two/three decoded frames are retained, not the entire raster sequence. Output frame payload (originals plus sheets) is capped at 1 GiB, with 270 MiB per sheet; Markdown at 8 MiB and final JSON at 16 MiB, for at most 1048 MiB of bundle file payload. These are byte/count bounds, not a total-RSS or wall-clock guarantee. Directory/file modes are 0700/0600 subject to a stricter umask. Existing output paths are rejected. Manifest/timeline/basic assessment errors occur before output; a late frame error, mismatched final assessment binding or output failure can leave a partial private directory. Final report generation starts only after every frame and assessment binding succeeds.

Observed CPU verification: `cargo test --lib frame_sequence::tests` passed one cumulative-quota regression; `cargo test --test frame_sequence --test frame_sequence_cli` passed 14 new cases, including the 1024th frame, full 16-bit totals/low bits, alignment/late errors, complete identity binding, independent temporal records, source removal, relocation and safe local Markdown links. Clippy with warnings denied and the binary build passed. Twelve fresh actual CLI scenarios covered all four numerical outcomes, separate repeat, supplied temporal records, encoded-different/decoded-exact frames, full 16-bit sequences, timeline/count errors, late invalid data, wrong binding, unsupported audio claims and overwrite refusal. All 33 generated source files and the tested binary remained unchanged. Artifact hashes/sizes/private modes and independent sequence identities were checked; all four RGB sheets and a 16-bit sheet were independently inflated/unfiltered and matched exact expected rows. The emitted Markdown and one actual raw A/B PNG sheet were inspected; no browser visual or temporal-quality proof is claimed.

The four-frame generated fixture compared 98,304 samples: absolute/squared totals 12,288/147,456, maximum 12, and separate repeat absolute total 1. Bound 12 passed; bound 11 and no bound retained differences. The two-frame 16-bit fixture retained a one-code low-bit difference over eight samples. These are generated CPU fixtures and synthetic review records, not real inference/video or actual reviewer evidence. Exact local commands/results are retained at `runs/frame-sequence-20261008-222922/receipt.json`. Cleared PR32 checks and its parent's zero-baseline probe were accepted without rerun. #18/#19/#20 remain open for real-runtime evidence and remaining container/audio/latent/media acceptance; no model/native/GPU execution or authorization change is added.

The repository is private initially. Public release, licensing, and sharing local artifacts require an explicit owner decision; this repository does not grant rights to third-party runtimes, model weights, or unpublished patches.
