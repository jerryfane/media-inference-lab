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

This repository contains the agreed project charter and implementation roadmap. There is no released benchmark CLI yet; executable commands and installation claims will be documented only after they are implemented and exercised. Parent issues and their native GitHub sub-issues define acceptance criteria and implementation order.

The repository is private initially. Public release, licensing, and sharing local artifacts require an explicit owner decision; this repository does not grant rights to third-party runtimes, model weights, or unpublished patches.
