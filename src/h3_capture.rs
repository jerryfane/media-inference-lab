//! Authorized H3 capture; native and codec actors remain direct guardian children.
use crate::{
    capture::{self, CaptureLimits, CaptureRecord, CaptureState, ChildExit, Cleanup, GuardEvidence,
        Invocation, LogEvidence, NativeCaptureControl, NativeInvocation, JSON_LIMIT, RECORD_VERSION},
    guards::{GuardMonitor, Lease},
    h3, h3_native::PreparedPlan,
    h3_owned::{self, CodecOperation, NativeBrokerInput, PinnedExecutable, RealCodecPlan},
    native_guard::{SANDBOX_EXECUTABLE, SANDBOX_PROFILE},
    schema::{AdapterResult, Artifact, FileIdentity, MediaSettings, Observation, ObservedModel,
        OutputEvidence, ReferenceRole, ResourceKind, ResourceMeasurement, ResourceScope, ResourceUnit,
        RuntimeIdentity, Timing, TimingScope, TimingUnit, RESULT_SCHEMA_VERSION},
    video_inspection::{self, VideoInspectionOptions},
};
use anyhow::{Context, Result, ensure};
use serde_json::json;
use sha2::{Digest, Sha256};
use std::{fs::{self, OpenOptions}, io::{Read, Write}, os::unix::fs::{DirBuilderExt, OpenOptionsExt, PermissionsExt},
    path::{Path, PathBuf}, time::{Duration, Instant}};

fn unavailable<T>(reason: &str) -> Observation<T> {
    Observation::Unavailable { reason: reason.into() }
}
fn pin(file: &h3::Fingerprint) -> PinnedExecutable {
    PinnedExecutable { path: file.path.clone(), sha256: file.sha256.clone() }
}
fn identity(file: &h3::Fingerprint) -> FileIdentity {
    FileIdentity { path: file.path.to_string_lossy().into_owned(),
        sha256: Observation::Available { value: file.sha256.clone() } }
}

/// Only the output operand changes. Do not rewrite conditioning or native flags.
fn invocation(plan: &h3::Plan, output: &Path) -> Result<Vec<String>> {
    ensure!(plan.argv.first().is_some_and(|p| Path::new(p) == plan.binary.path), "H3 argv executable mismatch");
    // build_plan fixes this prefix; searching all arguments could mistake prompt text for a flag.
    ensure!(plan.argv.get(5).map(String::as_str) == Some("-o")
        && plan.argv.get(6).is_some_and(|p| Path::new(p) == plan.preparation_dir.join("h3-output.mp4")),
        "H3 output operand differs from enrolled command");
    let mut argv = plan.argv.clone();
    argv[6] = output.to_str().context("non-UTF8 run output path")?.into();
    Ok(argv)
}

fn codecs(plan: &h3::Plan, output: &Path) -> Result<RealCodecPlan> {
    let MediaSettings::Video { generation, render_resolution, .. } = &plan.workload.settings else {
        anyhow::bail!("H3 capture requires video");
    };
    let canvas = render_resolution.as_ref().unwrap_or(&generation.resolution);
    let mut operations = Vec::with_capacity(plan.conditioning.len() + 1);
    // h3.c generation calls, not the interactive h3_cli.c probe recipes.
    for anchor in &plan.conditioning {
        ensure!(matches!(anchor.role, ReferenceRole::FirstFrame | ReferenceRole::LastFrame),
            "unsupported native conditioning role");
        operations.push(CodecOperation::ReadImage { path: anchor.input.path.clone(),
            width: canvas.width, height: canvas.height, crop: anchor.role == ReferenceRole::LastFrame });
    }
    operations.push(CodecOperation::WriteAv { path: output.into(), width: generation.resolution.width,
        height: generation.resolution.height, fps: 24, channels: 2, sample_rate: 32000 });
    Ok(RealCodecPlan { ffmpeg: pin(&plan.ffmpeg), ffprobe: pin(&plan.ffprobe), operations })
}

fn snapshot_shader(plan: &h3::Plan, directory: &Path) -> Result<h3::Fingerprint> {
    ensure!(plan.shader.bytes <= JSON_LIMIT, "shader exceeds metadata bound");
    let mut bytes = Vec::new();
    capture::regular_file(&plan.shader.path)?.take(JSON_LIMIT + 1).read_to_end(&mut bytes)?;
    let digest = format!("{:x}", Sha256::digest(&bytes));
    ensure!(bytes.len() as u64 == plan.shader.bytes && digest == plan.shader.sha256,
        "selected shader changed during snapshot");
    let path = directory.join("h3_shaders.metal");
    let mut file = OpenOptions::new().write(true).create_new(true).mode(0o600).open(&path)?;
    file.write_all(&bytes)?;
    file.sync_all()?;
    Ok(h3::Fingerprint { path, sha256: digest, bytes: bytes.len() as u64 })
}

fn artifact(directory: &Path, relative: &str, role: &str, limit: u64, deadline: Instant) -> Result<Artifact> {
    crate::schema::validate_artifact_path(relative)?;
    let (sha256, bytes) = capture::hash_file(&directory.join(relative), limit, deadline, None)?;
    Ok(Artifact { path: relative.into(), sha256, bytes, role: role.into() })
}

fn result(plan: &h3::Plan, profile: &h3::ParsedProfile, record: &CaptureRecord,
    artifacts: Vec<Artifact>) -> AdapterResult {
    let mut timings = profile.timings.clone();
    // Parser spans overlap. Preserve the parser's conservative provenance verbatim.
    timings.push(Timing { phase: "owned_native_host".into(), scope: TimingScope::Host,
        unit: TimingUnit::Milliseconds, method: "guardian monotonic broker observation".into(),
        boundary: "root creation through root exit/stop decision; includes native codecs and their in-loop settlement, excludes terminal root cleanup and subsequent media inspection; not pure model inference".into(),
        measurement: record.host_elapsed_ms.map_or_else(|| unavailable("root host interval was not observed"),
            |elapsed| Observation::Available { value: elapsed as f64 }) });
    for phase in ["text_encoding", "model_load", "denoising", "audio_vae", "video_vae", "mux_encode"] {
        timings.push(Timing { phase: phase.into(), scope: TimingScope::Native, unit: TimingUnit::Seconds,
            method: h3::PARSER_ID.into(), boundary: "no independently exposed complete non-overlapping phase boundary".into(),
            measurement: unavailable("native profile context marks are not attested complete phase intervals; playback FPS is not generation throughput") });
    }
    let mut resources = profile.resources.clone();
    for resource in &mut resources {
        if matches!(&resource.measurement, Observation::Available { value } if value.fract() != 0.0) {
            resource.measurement = unavailable("rounded native GiB counter does not identify an integral byte count; raw parsed estimate retained in native-profile.json");
        }
    }
    resources.push(ResourceMeasurement { kind: ResourceKind::ProcessRss, scope: ResourceScope::Process,
        unit: ResourceUnit::Bytes, method: "not measured".into(), boundary: "native root lifetime".into(),
        measurement: unavailable("native tensor counters and system guards do not measure root peak RSS") });
    AdapterResult { schema_version: RESULT_SCHEMA_VERSION, workload_identity: plan.workload_identity.clone(),
        resolved: plan.workload.clone(), runtime: RuntimeIdentity {
            name: "H3 / guardian-owned native codecs".into(), version: unavailable("no native runtime version record"),
            source: unavailable("selected source content/build identities are in native-execution.json; no VCS revision independently observed"),
            executable: Observation::Available { value: identity(&plan.binary) },
            modules: plan.selected_source.iter().chain(std::iter::once(&plan.shader)).map(identity).collect(),
            model: Observation::Available { value: ObservedModel { name: plan.workload.model.name.clone(),
                revision: unavailable("requested revision is a declaration, not an observed checkpoint revision"),
                fingerprint: unavailable("weight payload identity unavailable; model metadata is not a full weight fingerprint"),
                files: plan.model_metadata.iter().map(identity).collect() } },
            device: unavailable("no parsed native device identity"), cache_state: unavailable("fresh process does not establish cold model, filesystem or GPU caches"),
        }, timings, resources, artifacts,
        output_evidence: OutputEvidence::Unassessed { reason: "Full video/audio decode validates structure, raster/frame/FPS/audio coherence only; no reference numerical or visual-quality comparison".into() } }
}

/// Called only by the enrolled guardian while its native authority and lease live.
pub(crate) fn run(plan: &PreparedPlan, lease: &Lease, control: &mut NativeCaptureControl<'_>) -> Result<PathBuf> {
    control.check_prelaunch()?;
    plan.validate_enrolled()?;
    plan.verify_files()?;
    control.check_prelaunch()?;
    let selected = &plan.command.preparation;
    let directory = capture::unique_run(&plan.command.output_root)?;
    control.directory = Some(directory.clone());
    fs::set_permissions(&directory, fs::Permissions::from_mode(0o700))?;
    let start = Instant::now();
    // One absolute capture ceiling, including broker cleanup and all inspection helpers.
    // No stage obtains another timeout after an earlier stage spends its allocation.
    let cleanup_deadline = start.checked_add(Duration::from_millis(plan.command.timeout_ms))
        .context("H3 capture deadline overflow")?.min(control.automation_deadline);
    let execution_deadline = cleanup_deadline.checked_sub(control.cleanup_budget)
        .context("H3 cleanup reserve exceeds capture bound")?;
    let output = directory.join("h3-output.mp4");
    let argv = invocation(selected, &output)?;
    let mut root = h3_owned::sandbox_command(&selected.binary.path, &directory, argv.iter().skip(1).cloned(), true);
    root.environment = h3_owned::native_environment(plan, &directory, control.binding.guardian_pid)?;
    let mut record = CaptureRecord {
        record_version: RECORD_VERSION, sample_index: 0, state: CaptureState::Running,
        request: selected.workload.clone(), workload_identity: selected.workload_identity.clone(),
        host: capture::unix::host_identity()?, invocation: Invocation {
            executable: selected.binary.path.to_string_lossy().into_owned(), executable_sha256: Some(selected.binary.sha256.clone()),
            executable_hash_unavailable: None, args: argv.iter().skip(1).map(|_| "[redacted]".into()).collect(),
            environment: root.environment.keys().map(|k| (k.clone(), "[redacted]".into())).collect(),
            native: Some(NativeInvocation { invocation_sha256: control.binding.invocation_sha256.clone(),
                transaction_sha256: control.binding.transaction_sha256.clone(), guardian_pid: control.binding.guardian_pid,
                omlx_unmanaged: control.binding.omlx_unmanaged, sandbox_executable: SANDBOX_EXECUTABLE.into(), sandbox_profile: SANDBOX_PROFILE.into() }),
        }, limits: CaptureLimits { timeout_ms: plan.command.timeout_ms, max_output_bytes: plan.command.max_output_bytes,
            platform_limits: vec!["Existing fork-denying native sandbox; all codecs are independently enrolled direct guardian children".into(),
                "Cooperative absolute deadline shared by generation, cleanup and full-stream inspection; output polling is not a filesystem quota".into(),
                "No competing SIGCHLD reaper; original root and helper settlement receipts are independent and final".into()] },
        started_unix_ms: capture::now_ms()?, ended_unix_ms: None, host_elapsed_ms: None, artifact_inspection_ms: None,
        cleanup_elapsed_ms: None, exit: None, cleanup: None, logs: LogEvidence::default(), failure: None, adapter_result: None,
        guard_evidence: Some(GuardEvidence { path: "guards.json".into(), lease_path: lease.path().to_string_lossy().into_owned(), sha256: None, bytes: None }),
    };
    capture::atomic_json(&directory, "requested.json", &record.request, JSON_LIMIT)?;
    capture::atomic_json(&directory, "manifest.json", &record, JSON_LIMIT - 65536)?;
    let mut monitor = None;
    let mut root_disposition = None;
    let execution = (|| -> Result<AdapterResult> {
        control.check_prelaunch()?;
        monitor = Some(GuardMonitor::start(plan.command.guard_config.clone(), &directory)?);
        let monitor = monitor.as_mut().context("mandatory H3 monitor missing")?;
        capture::atomic_json(&directory, "guards.json", monitor.report(), JSON_LIMIT)?;
        monitor.initial_decision()?;
        ensure!(Instant::now() < execution_deadline, "H3 capture has no execution time after cleanup reserve");
        for subdir in ["home", "tmp", "cache", "huggingface"] {
            fs::DirBuilder::new().mode(0o700).create(directory.join(subdir))?;
        }
        control.check_prelaunch()?;
        let staged = snapshot_shader(selected, &directory)?;
        let codec_plan = codecs(selected, &output)?;
        capture::atomic_json(&directory, "native-execution.json", &json!({
            "kind":"h3_authorized_execution", "schema_version":1, "enrolled_plan":plan,
            "argv":argv, "command":root, "clear_environment":true, "actual_cwd":directory,
            "selected_shader":selected.shader, "staged_shader":staged,
            "codec_operations":codec_plan, "profile":selected.profile, "conditioning":selected.conditioning,
            "limits":{"capture_total_ms":plan.command.timeout_ms,"cleanup_reserve_ms":capture::millis(control.cleanup_budget)},
            "generation_throughput":unavailable::<f64>("no isolated generation denominator; host interval includes native codec work and codec settlement, playback FPS is not generation speed"),
            "limitations":["Resolution/profile are exact enrolled native arguments, not independently observed internal tensors.",
                "Weight payload identity, runtime device and cache state are unavailable."]
        }), JSON_LIMIT)?;
        control.check_prelaunch()?;
        let mut authority = || -> Result<()> {
            (control.tick)()?;
            let previous = monitor.sample_count();
            let decision = monitor.check();
            if monitor.sample_count() != previous {
                capture::atomic_json(&directory, "guards.json", monitor.report(), JSON_LIMIT)?;
            }
            decision?;
            capture::output_bytes(&directory, plan.command.max_output_bytes)?;
            ensure!(Instant::now() < execution_deadline, "H3 capture execution deadline expired");
            Ok(())
        };
        let mut scoped = NativeCaptureControl {
            binding: control.binding.clone(), tick: &mut authority, recovery_tick: &mut *control.recovery_tick,
            cleanup_budget: control.cleanup_budget, automation_deadline: cleanup_deadline,
            prelaunch_deadline: control.prelaunch_deadline.min(execution_deadline), creation_attempted: false,
            directory: Some(directory.clone()), settlement: None, helper_accounting_complete: true, helper_dispositions: Vec::new(),
        };
        // All fallible post-creation work is enclosed until custody is copied back below.
        let captured = (|| -> Result<AdapterResult> {
            let broker = h3_owned::run_native(NativeBrokerInput { root, root_identity: pin(&selected.binary),
                codecs: codec_plan.clone(), run_directory: directory.clone(), execution_deadline,
                max_log_bytes: plan.command.max_output_bytes.min(8 * 1024 * 1024) }, plan, &mut scoped, lease)?;
            scoped.creation_attempted |= broker.creation_attempted;
            scoped.helper_accounting_complete &= broker.complete;
            record.host_elapsed_ms = Some(broker.host_elapsed_ms);
            record.logs = LogEvidence { stdout_bytes: broker.stdout.bytes, stderr_bytes: broker.stderr.bytes,
                truncated: broker.stdout.truncated || broker.stderr.truncated };
            if let Some(actor) = &broker.root {
                scoped.settlement = actor.settlement.clone();
                let settlement = actor.settlement.as_ref();
                record.cleanup_elapsed_ms = Some(broker.cleanup_elapsed_ms);
                record.cleanup = Some(Cleanup { process_group: Some(actor.pid),
                    group_signalled: settlement.is_some_and(|s| s.group_signalled),
                    group_quiescent: settlement.is_some_and(|s| s.group_absent),
                    leader_reaped: settlement.is_some_and(|s| s.leader_reaped) });
                record.exit = settlement.filter(|s| s.leader_reaped).and_then(|s|
                    (s.exit_code.is_some() != s.exit_signal.is_some()).then_some(ChildExit { code: s.exit_code, signal: s.exit_signal }));
            }
            let retained = capture::atomic_json(&directory, "native-broker.json", &broker, JSON_LIMIT);
            let successful = broker.complete && broker.failure.is_none() && broker.evidence_error.is_none()
                && broker.root.as_ref().is_some_and(|a| a.spawn_failure.is_none()
                    && a.settlement.as_ref().is_some_and(|s| s.complete && s.exit_code == Some(0)))
                && broker.helpers.iter().all(|a| a.spawn_failure.is_none()
                    && a.settlement.as_ref().is_some_and(|s| s.complete && s.exit_code == Some(0)));
            let failure = format!("H3 broker failed: {:?}; evidence: {:?}; actor completeness: {}",
                broker.failure, broker.evidence_error, broker.complete);
            scoped.helper_dispositions.extend(broker.helpers);
            root_disposition = broker.root;
            retained?;
            ensure!(successful, "{failure}");
            ensure!(!record.logs.truncated, "H3 raw logs were truncated");
            (scoped.tick)()?;
            let inspection_start = Instant::now();
            let inspected = video_inspection::inspect_guarded(VideoInspectionOptions {
                workload: selected.workload.clone(), input: output.clone(), ffmpeg: selected.ffmpeg.path.clone(),
                ffprobe: selected.ffprobe.path.clone(), output_dir: directory.join("inspection"),
                timeout: execution_deadline.saturating_duration_since(Instant::now()).min(Duration::from_secs(120)),
            }, &codec_plan.ffmpeg, &codec_plan.ffprobe, execution_deadline, cleanup_deadline, &mut scoped, lease);
            record.artifact_inspection_ms = Some(capture::millis(inspection_start.elapsed()));
            let inspected = inspected?;
            scoped.creation_attempted |= inspected.creation_attempted;
            scoped.helper_accounting_complete &= inspected.complete;
            let retained = capture::atomic_json(&directory, "native-inspection.json", &inspected, JSON_LIMIT);
            let mut artifacts = Vec::new();
            let media_artifacts = inspected.report.get("artifacts").cloned();
            let valid = inspected.valid;
            let failure = inspected.failure.clone();
            scoped.helper_dispositions.extend(inspected.helpers.into_iter().map(|h| h.actor));
            retained?;
            ensure!(valid, "full H3 video/audio validation failed: {failure:?}");
            (scoped.tick)()?;
            let mut stderr = Vec::new();
            capture::regular_file(&directory.join("stderr.log"))?.take(8 * 1024 * 1024 + 1).read_to_end(&mut stderr)?;
            let profile = h3::parse_profile(&stderr);
            capture::atomic_json(&directory, "native-profile.json", &profile, JSON_LIMIT)?;
            for (relative, role) in [("h3-output.mp4", "generated-video"), ("native-execution.json", "native-execution-provenance"),
                ("native-broker.json", "original-native-actor-receipts"), ("native-inspection.json", "original-inspection-actor-receipts"),
                ("native-profile.json", "native-profile-parser-report"), ("inspection/report.json", "full-video-audio-validation"),
                ("h3_shaders.metal", "staged-native-shader")] {
                (scoped.tick)()?;
                artifacts.push(artifact(&directory, relative, role, plan.command.max_output_bytes, execution_deadline)?);
            }
            for entry in media_artifacts.context("missing inspected media artifacts")?.as_array().context("invalid inspected artifact list")? {
                let mut item: Artifact = serde_json::from_value(entry.clone())?;
                item.path = format!("inspection/{}", item.path);
                crate::schema::validate_artifact_path(&item.path)?;
                artifacts.push(item);
            }
            let result = result(selected, &profile, &record, artifacts);
            result.validate(&record.request)?;
            (scoped.tick)()?;
            Ok(result)
        })();
        control.creation_attempted |= scoped.creation_attempted;
        control.settlement = scoped.settlement.take(); // ORIGINAL root only; never aggregate helpers into it.
        control.helper_accounting_complete &= scoped.helper_accounting_complete;
        if captured.is_err() && scoped.creation_attempted && control.settlement.is_none() {
            control.helper_accounting_complete = false;
        }
        control.helper_dispositions.append(&mut scoped.helper_dispositions);
        captured
    })();
    record.state = CaptureState::Failed;
    record.host_elapsed_ms.get_or_insert(capture::millis(start.elapsed()));
    record.cleanup.get_or_insert(Cleanup { process_group: None, group_signalled: false, group_quiescent: false, leader_reaped: false });
    match execution {
        Ok(result) => { record.state = CaptureState::Completed; record.adapter_result = Some(result); }
        Err(error) => record.failure = Some(format!("{error:#}")),
    }
    // Finalization never launches anything. Independent publication attempts preserve
    // original receipts in control even if the evidence filesystem itself fails.
    let mut publication_errors = Vec::new();
    if let Some(monitor) = &monitor {
        let saved = (|| -> Result<()> {
            capture::atomic_json(&directory, "guards.json", monitor.report(), JSON_LIMIT)?;
            let mut bytes = serde_json::to_vec_pretty(monitor.report())?;
            bytes.push(b'\n');
            let evidence = record.guard_evidence.as_mut().context("missing guard evidence")?;
            evidence.sha256 = Some(format!("{:x}", Sha256::digest(&bytes)));
            evidence.bytes = Some(bytes.len() as u64);
            Ok(())
        })();
        if let Err(error) = saved { publication_errors.push(format!("guard publication: {error:#}")); }
    } else { publication_errors.push("mandatory resource monitor could not start".into()); }
    match capture::now_ms() {
        Ok(ended) => record.ended_unix_ms = Some(ended),
        Err(error) => publication_errors.push(format!("terminal clock: {error:#}")),
    }
    let saved = if publication_errors.is_empty() && let Some(result) = &record.adapter_result {
        capture::atomic_json(&directory, "result.json", result, JSON_LIMIT)
    } else {
        capture::atomic_json(&directory, "result.json", &json!({"schema_version":1,
            "kind":"h3_capture_failure", "failure":record.failure, "publication_errors":publication_errors,
            "workload_identity":record.workload_identity, "capture_eligible":false,
            "original_root":root_disposition, "root_settlement":control.settlement,
            "helper_accounting_complete":control.helper_accounting_complete,
            "helper_dispositions":control.helper_dispositions}), JSON_LIMIT)
    };
    if let Err(error) = saved { publication_errors.push(format!("result publication: {error:#}")); }
    if let Err(error) = capture::output_bytes(&directory, plan.command.max_output_bytes) {
        publication_errors.push(format!("final output bound: {error:#}"));
    }
    if !publication_errors.is_empty() {
        record.state = CaptureState::Failed;
        record.adapter_result = None;
        record.failure = Some(format!("{}; {}", record.failure.as_deref().unwrap_or("capture evidence publication failed"), publication_errors.join("; ")));
    }
    if let Some(failure) = &mut record.failure { capture::bound_failure(failure); }
    let validation = record.validate();
    capture::atomic_json(&directory, "manifest.json", &record, JSON_LIMIT)?;
    validation?;
    ensure!(publication_errors.is_empty(), "{}", publication_errors.join("; "));
    Ok(directory)
}
