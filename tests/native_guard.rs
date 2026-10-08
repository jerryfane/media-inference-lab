#![cfg(any(target_os = "macos", target_os = "linux"))]

use media_inference_lab::{
    capture::{CaptureOptions, CaptureState, capture_native_guarded, inspect},
    guards::{
        GuardConfig, GuardDecision, GuardPolicy, GuardReport, GuardSample, GuardSnapshot, Lease,
        LiveObservation, MAX_SWAP_GROWTH_BYTES, Observation, evaluate_launch, evaluate_running,
    },
    native_guard::{
        self, LiveQueueReadiness, NativeGuardConfig, NativeGuardReading, NativeGuardReport,
        NativeReadiness, UnrelatedGpuReadiness,
    },
    schema::Workload,
};
use std::{
    collections::BTreeMap,
    fs,
    os::unix::fs::PermissionsExt,
    process::{Child, Command},
    sync::{Arc, atomic::AtomicBool},
    time::Duration,
};

fn available<T>(value: T) -> Observation<T> {
    Observation::Available { value }
}
fn native_config() -> NativeGuardConfig {
    NativeGuardConfig {
        invocation_sha256: "1".repeat(64),
        manager_grant_reference: Some("external-reference-is-not-authorization".into()),
    }
}
fn config() -> GuardConfig {
    GuardConfig {
        live_app_pid: 100,
        live_app_command_sha256: "2".repeat(64),
        min_disk_free_bytes: 100,
        max_disk_growth_bytes: 1000,
        sample_interval_ms: 100,
    }
}
fn snapshot() -> GuardSnapshot {
    GuardSnapshot {
        epoch_ms: 100,
        platform: "deterministic_cpu_evidence".into(),
        free_system_memory_percent: available(30.0),
        swap_used_bytes: available(0),
        disk_free_bytes: available(10_000),
        live: available(LiveObservation {
            app_pid: 100,
            app_command_sha256: config().live_app_command_sha256,
            worker_pids: vec![],
        }),
    }
}
// Hypothetical typed observations only exercise the pure evaluator. No production
// producer or capture injection point exists and no inference success is mocked.
fn fresh_reading() -> NativeReadiness {
    NativeReadiness {
        epoch_ms: 100,
        live_queue: available(LiveQueueReadiness {
            source: "unit:authoritative-queue".into(),
            observed_unix_ms: 100,
            valid_until_unix_ms: 200,
            queued_jobs: 0,
            active_jobs: 0,
        }),
        unrelated_gpu: available(UnrelatedGpuReadiness {
            source: "unit:global-ownership".into(),
            observed_unix_ms: 100,
            valid_until_unix_ms: 200,
            unrelated_gpu_owners: vec![],
        }),
    }
}
fn native_sample(readiness: NativeReadiness) -> NativeGuardReading {
    NativeGuardReading {
        decision: native_guard::evaluate(&native_config(), &readiness),
        readiness,
    }
}
fn combine(mut resources: GuardDecision, native: &GuardDecision) -> GuardDecision {
    resources.allowed &= native.allowed;
    resources.reasons.extend(native.reasons.iter().cloned());
    resources
}
fn report(readiness: NativeReadiness) -> GuardReport {
    let baseline = snapshot();
    let native = native_sample(readiness);
    GuardReport {
        schema_version: 2,
        config: config(),
        policy: GuardPolicy::default(),
        initial_decision: combine(evaluate_launch(&config(), &baseline), &native.decision),
        baseline,
        samples: vec![],
        native: Some(NativeGuardReport {
            config: native_config(),
            baseline: native,
            samples: vec![],
        }),
    }
}

#[test]
fn each_missing_integration_denies_despite_reference_and_valid_cpu_history() {
    let production = native_guard::readiness();
    assert!(matches!(
        production.live_queue,
        Observation::Unavailable { .. }
    ));
    assert!(matches!(
        production.unrelated_gpu,
        Observation::Unavailable { .. }
    ));
    let denied = report(production.clone());
    denied.validate().unwrap();
    assert!(evaluate_launch(&config(), &denied.baseline).allowed);
    assert!(!denied.initial_decision.allowed);
    assert!(
        denied
            .initial_decision
            .reasons
            .iter()
            .any(|reason| reason.contains("live_queue unavailable"))
    );
    assert!(
        denied
            .initial_decision
            .reasons
            .iter()
            .any(|reason| reason.contains("unrelated_gpu unavailable"))
    );
    let mut missing_queue = fresh_reading();
    missing_queue.live_queue = production.live_queue;
    assert!(!native_guard::evaluate(&native_config(), &missing_queue).allowed);
    let mut missing_gpu = fresh_reading();
    missing_gpu.unrelated_gpu = production.unrelated_gpu;
    assert!(!native_guard::evaluate(&native_config(), &missing_gpu).allowed);
    let mut without_reference = native_config();
    without_reference.manager_grant_reference = None;
    assert_eq!(
        native_guard::evaluate(&native_config(), &missing_gpu),
        native_guard::evaluate(&without_reference, &missing_gpu)
    );
}

#[test]
fn readiness_expiry_queue_activity_and_unrelated_ownership_deny() {
    let mut reading = fresh_reading();
    assert!(native_guard::evaluate(&native_config(), &reading).allowed);
    reading.epoch_ms = 200;
    assert!(!native_guard::evaluate(&native_config(), &reading).allowed);
    reading.epoch_ms = 99;
    assert!(!native_guard::evaluate(&native_config(), &reading).allowed);
    reading = fresh_reading();
    if let Observation::Available { value } = &mut reading.live_queue {
        value.queued_jobs = 1;
    }
    assert!(!native_guard::evaluate(&native_config(), &reading).allowed);
    reading = fresh_reading();
    if let Observation::Available { value } = &mut reading.live_queue {
        value.active_jobs = 1;
    }
    assert!(!native_guard::evaluate(&native_config(), &reading).allowed);
    reading = fresh_reading();
    if let Observation::Available { value } = &mut reading.unrelated_gpu {
        value.unrelated_gpu_owners.push("another-owner".into());
    }
    assert!(!native_guard::evaluate(&native_config(), &reading).allowed);
}

#[test]
fn native_report_recomputes_denials_and_preserves_resource_thresholds() {
    let denied = report(native_guard::readiness());
    let mut forged = denied.clone();
    forged.initial_decision = GuardDecision {
        allowed: true,
        reasons: vec![],
    };
    assert!(forged.validate().is_err());
    let mut forged = denied;
    forged.native.as_mut().unwrap().baseline.decision = GuardDecision {
        allowed: true,
        reasons: vec![],
    };
    assert!(forged.validate().is_err());
    let mut launch = report(fresh_reading());
    launch.baseline.free_system_memory_percent = available(29.999);
    assert!(
        launch.validate().is_err(),
        "native readiness cannot excuse a CPU threshold breach"
    );
    let mut running = report(fresh_reading());
    let mut snapshot = running.baseline.clone();
    snapshot.free_system_memory_percent = available(15.0);
    snapshot.swap_used_bytes = available(MAX_SWAP_GROWTH_BYTES);
    let native = native_sample(fresh_reading());
    running.samples.push(GuardSample {
        elapsed_ms: 100,
        stop_reason: None,
        decision: combine(
            evaluate_running(&config(), &running.baseline, &snapshot),
            &native.decision,
        ),
        snapshot,
    });
    running.native.as_mut().unwrap().samples.push(native);
    running.validate().unwrap();
    let mut low_memory = running.clone();
    low_memory.samples[0].snapshot.free_system_memory_percent = available(14.999);
    assert!(low_memory.validate().is_err());
    let mut excess_swap = running.clone();
    excess_swap.samples[0].snapshot.swap_used_bytes = available(MAX_SWAP_GROWTH_BYTES + 1);
    assert!(excess_swap.validate().is_err());
    let mut lost_readiness = running.clone();
    let mut unavailable = native_guard::readiness();
    unavailable.epoch_ms = 101;
    lost_readiness.native.as_mut().unwrap().samples[0] = native_sample(unavailable);
    assert!(
        lost_readiness.validate().is_err(),
        "running resource success cannot override missing readiness"
    );
    let last = &lost_readiness.native.as_ref().unwrap().samples[0].decision;
    lost_readiness.samples[0].decision = combine(
        evaluate_running(
            &config(),
            &lost_readiness.baseline,
            &lost_readiness.samples[0].snapshot,
        ),
        last,
    );
    lost_readiness.validate().unwrap();
    assert!(!lost_readiness.samples[0].decision.allowed);
    running.native.as_mut().unwrap().samples.clear();
    assert!(running.validate().is_err());
}

struct Sentinel(Child);
impl Drop for Sentinel {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

#[test]
fn library_denial_retains_private_inspectable_evidence_without_spawning_or_signalling() {
    let temporary = tempfile::tempdir().unwrap();
    let root = fs::canonicalize(temporary.path()).unwrap();
    let lease_path = root.join("isolated-test.lock");
    let mut sentinel = Sentinel(Command::new("/bin/sleep").arg("30").spawn().unwrap());
    let request: Workload =
        serde_json::from_str(include_str!("../examples/image-workload.json")).unwrap();
    let run = capture_native_guarded(
        request,
        CaptureOptions {
            root: root.join("captures"),
            executable: "/bin/sh".into(),
            args: vec![
                "-c".into(),
                "printf unexpected > \"$MIL_RUN_DIR/must-not-execute\"".into(),
            ],
            env: BTreeMap::new(),
            timeout: Duration::from_secs(10),
            max_output_bytes: 1024 * 1024,
        },
        Arc::new(AtomicBool::new(false)),
        config(),
        Lease::acquire(&lease_path).unwrap(),
        native_config(),
    )
    .unwrap();
    let record = inspect(&run).unwrap();
    assert_eq!(record.state, CaptureState::Cancelled);
    assert!(record.exit.is_none());
    let cleanup = record.cleanup.unwrap();
    assert!(cleanup.process_group.is_none());
    assert!(!cleanup.group_signalled && !cleanup.leader_reaped);
    assert!(record.cleanup_elapsed_ms.is_none());
    assert!(record.adapter_result.is_none());
    assert!(!run.join("must-not-execute").exists());
    assert!(
        sentinel.0.try_wait().unwrap().is_none(),
        "unowned sentinel must remain alive"
    );
    let report_path = run.join("guards.json");
    let bytes = fs::read(&report_path).unwrap();
    let report: GuardReport = serde_json::from_slice(&bytes).unwrap();
    let native = report.native.as_ref().unwrap();
    assert_eq!(native.config, native_config());
    assert!(!native.baseline.decision.allowed);
    assert!(
        native
            .baseline
            .decision
            .reasons
            .iter()
            .any(|reason| reason.contains("live_queue unavailable"))
    );
    assert!(
        native
            .baseline
            .decision
            .reasons
            .iter()
            .any(|reason| reason.contains("unrelated_gpu unavailable"))
    );
    assert!(record.invocation.native.is_some());
    assert_eq!(record.invocation.executable, "/bin/sh");
    assert!(record.failure.unwrap().contains("launch guard rejected"));
    assert_eq!(
        fs::metadata(&run).unwrap().permissions().mode() & 0o777,
        0o700
    );
    for name in [
        "guards.json",
        "manifest.json",
        "requested.json",
        "stdout.log",
        "stderr.log",
    ] {
        assert_eq!(
            fs::metadata(run.join(name)).unwrap().permissions().mode() & 0o777,
            0o600
        );
    }
    let mut changed = bytes;
    changed.push(b'\n');
    fs::write(report_path, changed).unwrap();
    assert!(
        inspect(&run)
            .unwrap_err()
            .to_string()
            .contains("guard report hash/size")
    );
    let _lease = Lease::acquire(&lease_path).unwrap();
}
