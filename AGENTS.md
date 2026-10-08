# Implementation contract

## Ownership

This repository is the implementation workspace for Media Inference Lab. The dedicated `media-inference` OMP session owns implementation and issue updates. The `mac-studio` management session coordinates the workstation and reviews milestones; do not take over its existing projects.

The owner requested a Rust-first combined image/video benchmark lab, detailed issues, and autonomous implementation by this session. Implement coherent, runnable issue slices on feature branches; local commits and pushes to feature branches of this repository are in scope. Do not force-push, merge into main without review, change repository visibility, publish releases, or modify unrelated repositories/PRs.

## Design

- One Rust Cargo package initially, with Clap, Serde/JSON, ordinary modules, and subprocess-based adapters. Add dependencies for demonstrated requirements, not speculative infrastructure.
- Thin Python for native MFLUX APIs in an explicitly chosen environment. Native `h3.c` remains an external process. Metal/native hosts are for GPU experiments. Do not embed Python or rewrite the inference runtimes.
- Version the workload/result contract. Preserve actual runtime/model/source identity, resolved settings, timing boundaries, per-sample outcomes, and artifact provenance. Never report unavailable measurements as zero, invent throughput, or silently drop failed samples.
- Shared capture/comparison machinery; modality-specific settings, metrics, and validation. A numerical difference is not a quality verdict. Same seeds are not proof of reproducibility.
- No production flags/settings changes, extra quantization, smaller workloads, or greater approximate reuse hidden inside a claimed optimization.

## Execution safety

- Treat existing image/video services, deployments, model stores, and benchmark evidence as read-only. Use isolated environments and per-run directories.
- Do not change DNS, Cloudflare/Access, Tailscale, credentials, LaunchAgents, global environment, or unrelated services. Do not restart or stop the live Studio application.
- Serialize GPU-heavy work. Coordinate with `mac-studio` before full-model runs or benchmarks, check live generation is idle, and stop only this project's owned process group if a live job starts. Do not benchmark alongside another GPU workload.
- Preserve the existing guard policy for the first integration: at least 30% free-system-memory indication before a heavy run; abort if it drops below 15% or swap grows by more than 512 MiB. Record platform/method and unavailable readings. These are safety guards, not GPU-memory measurements. Do not silently disable a missing guard.
- Bound execution and disk use, preserve failed/cancelled outcomes, avoid automatic retries, and never kill unrelated processes. No automatic weight downloads or benchmark uploads.
- Do not push local MLX patches, write an MLX PR description, or open an MLX PR. Existing MFLUX PRs and the live combined runtime are outside this assignment. Learn from approved evidence without importing unpublished code or host-specific configuration.

## Verification and handoff

Read the issue acceptance criteria before editing. Plan multi-file changes and reuse existing conventions. Run focused checks after a coherent change and exercise the real CLI/adapter path; tests alone do not establish working integration. Keep permanent tests for consumer-visible behavior, invariants, boundaries, errors, and state transitions—not source wording or mock forwarding.

Keep default tests deterministic and free of model downloads/GPU requirements. Real-runtime/GPU checks are explicit, serialized, and identify their prerequisites and coverage. Record observed evidence, not expected outcomes. Update actual usage documentation and remove temporary probes after proof.

Comment on issues with implementation commits, exact commands/results, limitations, and blockers. Do not close an issue until every acceptance criterion is met. Report milestone evidence and GPU scheduling requests to `mac-studio` through the existing Herdr agent channel. Never claim a scaffold or a mocked adapter is a working benchmark tool.
