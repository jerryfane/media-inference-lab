#![cfg(any(target_os = "macos", target_os = "linux"))]

use media_inference_lab::{
    capture::{CaptureOptions, CaptureState, capture_guarded, inspect},
    guards::{GuardConfig, GuardReport, Lease},
    schema::Workload,
};
use std::{
    collections::BTreeMap,
    fs,
    sync::{Arc, atomic::AtomicBool},
    time::Duration,
};

#[test]
fn denied_launch_never_spawns_and_retains_integrity_checked_guard_evidence() {
    let temporary = tempfile::tempdir().unwrap();
    let root = fs::canonicalize(temporary.path()).unwrap();
    let lease_path = root.join("gpu.lock");
    let marker = root.join("must-not-execute");
    let request: Workload =
        serde_json::from_str(include_str!("../examples/image-workload.json")).unwrap();
    // Impossible disk minimum guarantees denial independent of host observations.
    let config = GuardConfig {
        live_app_pid: u32::MAX,
        live_app_command_sha256: "0".repeat(64),
        min_disk_free_bytes: u64::MAX,
        max_disk_growth_bytes: 1,
        sample_interval_ms: 100,
    };
    let run = capture_guarded(
        request,
        CaptureOptions {
            root: root.join("captures"),
            executable: "/bin/sh".into(),
            args: vec!["-c".into(), "printf unexpected > \"$MARKER\"".into()],
            env: BTreeMap::from([("MARKER".into(), marker.to_string_lossy().into_owned())]),
            timeout: Duration::from_secs(10),
            max_output_bytes: 1024,
        },
        Arc::new(AtomicBool::new(false)),
        config,
        Lease::acquire(&lease_path).unwrap(),
    )
    .unwrap();
    let record = inspect(&run).unwrap();
    assert_eq!(record.state, CaptureState::Cancelled);
    assert!(record.failure.unwrap().contains("launch guard rejected"));
    assert!(record.exit.is_none());
    assert!(record.cleanup.unwrap().process_group.is_none());
    assert!(!marker.exists());
    let report_path = run.join("guards.json");
    let bytes = fs::read(&report_path).unwrap();
    let report: GuardReport = serde_json::from_slice(&bytes).unwrap();
    assert!(!report.initial_decision.allowed);
    assert!(report.samples.is_empty());
    assert!(record.guard_evidence.unwrap().sha256.is_some());
    // Equivalent JSON with changed physical bytes still violates finalized provenance.
    let mut changed = bytes;
    changed.push(b'\n');
    fs::write(report_path, changed).unwrap();
    assert!(
        inspect(&run)
            .unwrap_err()
            .to_string()
            .contains("guard report hash/size")
    );
    let _recovered = Lease::acquire(&lease_path).unwrap();
}
