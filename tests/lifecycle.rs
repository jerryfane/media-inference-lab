#![cfg(any(target_os = "macos", target_os = "linux"))]

use media_inference_lab::{
    capture::{CaptureOptions, CaptureRecord, CaptureState, capture, inspect},
    schema::{ProcessPolicy, Workload},
};
use serde_json::{Value, json};
use std::{
    collections::BTreeMap,
    fs,
    path::{Path, PathBuf},
    process::{Child, Command, Stdio},
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    thread,
    time::{Duration, Instant},
};
use tempfile::TempDir;

const SUCCESS: &str = r#"
set -eu
test "$PWD" = "$MIL_RUN_DIR"
test -f "$MIL_REQUEST_PATH"
test -f manifest.json
test -z "${HOME+x}"
test "$MIL_WORKLOAD_IDENTITY" = "$EXPECTED_IDENTITY"
/bin/mkdir artifacts
printf 'CPU schema fixture only; no inference was performed.\n' > artifacts/schema-output.txt
/bin/cp "$RESULT_FIXTURE" "$MIL_RESULT_PATH"
printf 'progress only\n'
printf 'diagnostic only\n' >&2
"#;

struct Sandbox {
    _temporary: TempDir,
    root: PathBuf,
}

impl Sandbox {
    fn new() -> Self {
        let temporary = tempfile::tempdir().unwrap();
        // Darwin's /var temporary path is an OS symlink; evidence roots are
        // deliberately canonical, so application-controlled links stay rejected.
        let root = fs::canonicalize(temporary.path()).unwrap();
        Self {
            _temporary: temporary,
            root,
        }
    }

    fn options(&self, script: &str) -> CaptureOptions {
        let fixture =
            Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/image-result.json");
        CaptureOptions {
            root: self.root.clone(),
            executable: "/bin/sh".into(),
            args: vec!["-c".into(), script.into()],
            env: BTreeMap::from([
                ("RESULT_FIXTURE".into(), fixture.to_string_lossy().into()),
                ("EXPECTED_IDENTITY".into(), request().identity().unwrap()),
            ]),
            timeout: Duration::from_secs(3),
            max_output_bytes: 1024 * 1024,
        }
    }

    fn run(&self, script: &str) -> PathBuf {
        capture(
            request(),
            self.options(script),
            Arc::new(AtomicBool::new(false)),
        )
        .unwrap()
    }
}

fn request() -> Workload {
    serde_json::from_str(include_str!("../examples/image-workload.json")).unwrap()
}

fn manifest(path: &Path) -> Value {
    serde_json::from_slice(&fs::read(path.join("manifest.json")).unwrap()).unwrap()
}

fn wait_for_file(root: &Path, filename: &str) -> PathBuf {
    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        for entry in fs::read_dir(root).unwrap() {
            let path = entry.unwrap().path();
            if path.is_dir() && path.join(filename).is_file() {
                return path;
            }
        }
        assert!(Instant::now() < deadline, "child never produced {filename}");
        thread::sleep(Duration::from_millis(5));
    }
}

struct TestChild(Child);
impl Drop for TestChild {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

#[test]
fn accepts_actual_protocol_artifacts_and_unavailable_native_phases() {
    let sandbox = Sandbox::new();
    let run = sandbox.run(SUCCESS);
    let record = inspect(&run).unwrap();
    assert!(record.is_success());
    assert_eq!(record.state, CaptureState::Completed);
    assert_eq!(record.exit.as_ref().unwrap().code, Some(0));
    assert_eq!(
        fs::read(run.join("stdout.log")).unwrap(),
        b"progress only\n"
    );
    assert_eq!(
        fs::read(run.join("stderr.log")).unwrap(),
        b"diagnostic only\n"
    );
    assert_eq!(
        record.adapter_result.as_ref().unwrap().workload_identity,
        request().identity().unwrap()
    );
    assert!(record.host_elapsed_ms.is_some());
    assert!(record.cleanup_elapsed_ms.is_some());
    assert!(record.artifact_inspection_ms.is_some());
    assert!(record.cleanup.as_ref().unwrap().leader_reaped);
    assert_eq!(record.sample_index, 0);
}

#[test]
fn redacts_argument_and_environment_values_without_shell_interpolation() {
    let sandbox = Sandbox::new();
    let mut options = sandbox.options("");
    options.executable = "/usr/bin/printf".into();
    options.args = vec!["%s".into(), "$(touch not-executed); secret-value".into()];
    options
        .env
        .insert("TOKEN".into(), "environment-secret".into());
    let run = capture(request(), options, Arc::new(AtomicBool::new(false))).unwrap();
    let record = inspect(&run).unwrap();
    assert_eq!(record.state, CaptureState::Incomplete);
    assert_eq!(
        fs::read_to_string(run.join("stdout.log")).unwrap(),
        "$(touch not-executed); secret-value"
    );
    assert!(!run.join("not-executed").exists());
    let persisted = fs::read_to_string(run.join("manifest.json")).unwrap();
    assert!(!persisted.contains("secret-value"));
    assert!(!persisted.contains("environment-secret"));
    assert_eq!(record.invocation.environment["TOKEN"], "[redacted]");
}

#[test]
fn retains_spawn_failure_without_invented_native_or_cleanup_measurements() {
    let sandbox = Sandbox::new();
    let mut options = sandbox.options("");
    options.executable = sandbox.root.join("does-not-exist");
    let run = capture(request(), options, Arc::new(AtomicBool::new(false))).unwrap();
    let record = inspect(&run).unwrap();
    assert_eq!(record.state, CaptureState::Failed);
    assert!(record.exit.is_none());
    assert!(record.host_elapsed_ms.is_some());
    assert!(record.cleanup_elapsed_ms.is_none());
    assert!(record.artifact_inspection_ms.is_none());
    assert!(record.cleanup.as_ref().unwrap().process_group.is_none());
    assert!(run.join("requested.json").is_file());
}

#[test]
fn crash_nonzero_missing_and_malformed_results_never_succeed() {
    let sandbox = Sandbox::new();
    for (script, state, code, signal) in [
        ("exit 0".to_owned(), CaptureState::Incomplete, Some(0), None),
        ("exit 7".to_owned(), CaptureState::Failed, Some(7), None),
        (
            "kill -KILL $$".to_owned(),
            CaptureState::Failed,
            None,
            Some(libc::SIGKILL),
        ),
        (
            "printf '{broken' > \"$MIL_RESULT_PATH\"".to_owned(),
            CaptureState::Failed,
            Some(0),
            None,
        ),
        (
            format!("{SUCCESS}\nexit 9"),
            CaptureState::Failed,
            Some(9),
            None,
        ),
    ] {
        let run = sandbox.run(&script);
        let record = inspect(&run).unwrap();
        assert_eq!(record.state, state);
        assert_eq!(record.exit.as_ref().unwrap().code, code);
        assert_eq!(record.exit.as_ref().unwrap().signal, signal);
        assert!(!record.is_success());
        assert!(record.adapter_result.is_none());
        assert!(record.failure.is_some());
        assert!(run.join("stdout.log").is_file());
    }
}

#[test]
fn rejects_hash_size_missing_and_symlink_artifacts() {
    let sandbox = Sandbox::new();
    for modification in [
        "printf X > artifacts/schema-output.txt",
        // Equal byte length catches implementations that only check sizes.
        "printf 'cpu schema fixture only; no inference was performed.\\n' > artifacts/schema-output.txt",
        "/bin/rm artifacts/schema-output.txt",
        "/bin/rm artifacts/schema-output.txt; /bin/ln -s /etc/hosts artifacts/schema-output.txt",
        "/bin/rm -r artifacts; /bin/ln -s /tmp artifacts",
    ] {
        let run = sandbox.run(&format!("{SUCCESS}\n{modification}"));
        let record = inspect(&run).unwrap();
        assert_eq!(
            record.state,
            CaptureState::Failed,
            "accepted {modification}"
        );
        assert!(record.adapter_result.is_none());
    }
}

#[test]
fn timeout_kills_term_ignoring_group_but_not_an_unrelated_process() {
    let sandbox = Sandbox::new();
    let mut unrelated = TestChild(Command::new("/bin/sleep").arg("5").spawn().unwrap());
    let mut options = sandbox.options(
        "trap '' TERM; (/bin/sleep 0.7; printf leaked > late) & printf ready > ready; wait",
    );
    options.timeout = Duration::from_millis(150);
    let start = Instant::now();
    let run = capture(request(), options, Arc::new(AtomicBool::new(false))).unwrap();
    assert!(start.elapsed() < Duration::from_secs(3));
    let record = inspect(&run).unwrap();
    assert_eq!(record.state, CaptureState::TimedOut);
    assert_eq!(record.exit.as_ref().unwrap().signal, Some(libc::SIGKILL));
    assert!(record.cleanup.as_ref().unwrap().group_signalled);
    assert!(unrelated.0.try_wait().unwrap().is_none());
    thread::sleep(Duration::from_millis(800));
    assert!(
        !run.join("late").exists(),
        "owned descendant survived deadline cleanup"
    );
}

#[test]
fn cancellation_retains_live_running_then_terminal_evidence() {
    let sandbox = Sandbox::new();
    let cancelled = Arc::new(AtomicBool::new(false));
    let worker_cancelled = Arc::clone(&cancelled);
    let options = sandbox.options("printf ready > ready; exec /bin/sleep 10");
    let worker = thread::spawn(move || capture(request(), options, worker_cancelled).unwrap());
    let run = wait_for_file(&sandbox.root, "ready");
    let before = fs::read(run.join("manifest.json")).unwrap();
    let running = inspect(&run).unwrap();
    assert_eq!(running.state, CaptureState::Running);
    assert!(running.host_elapsed_ms.is_none());
    assert!(!running.is_success());
    assert_eq!(fs::read(run.join("manifest.json")).unwrap(), before);
    cancelled.store(true, Ordering::Relaxed);
    assert_eq!(worker.join().unwrap(), run);
    let terminal = inspect(&run).unwrap();
    assert_eq!(terminal.state, CaptureState::Cancelled);
    assert!(terminal.exit.as_ref().unwrap().signal.is_some());
    assert!(terminal.artifact_inspection_ms.is_none());
}

#[test]
fn pre_cancelled_capture_never_spawns_a_child() {
    let sandbox = Sandbox::new();
    let run = capture(
        request(),
        sandbox.options("printf spawned > spawned"),
        Arc::new(AtomicBool::new(true)),
    )
    .unwrap();
    let record = inspect(&run).unwrap();
    assert_eq!(record.state, CaptureState::Cancelled);
    assert!(!run.join("spawned").exists());
    assert!(record.exit.is_none());
    assert!(record.cleanup_elapsed_ms.is_none());
    assert!(record.artifact_inspection_ms.is_none());
}

#[test]
fn normal_leader_exit_cleans_descendants_holding_output_pipes() {
    let sandbox = Sandbox::new();
    let start = Instant::now();
    let run = sandbox.run("(trap '' TERM; /bin/sleep 0.7; printf escaped > late) & exit 0");
    assert!(start.elapsed() < Duration::from_secs(3));
    let record = inspect(&run).unwrap();
    assert_eq!(record.state, CaptureState::Incomplete);
    assert_eq!(record.exit.as_ref().unwrap().code, Some(0));
    assert!(record.cleanup.as_ref().unwrap().group_signalled);
    thread::sleep(Duration::from_millis(800));
    assert!(!run.join("late").exists());
}

#[test]
fn bounds_combined_logs_and_adapter_created_files() {
    let sandbox = Sandbox::new();
    let mut options = sandbox
        .options("while :; do printf '0123456789abcdef'; printf 'fedcba9876543210' >&2; done");
    options.max_output_bytes = 1024;
    let run = capture(request(), options, Arc::new(AtomicBool::new(false))).unwrap();
    let record = inspect(&run).unwrap();
    assert_eq!(record.state, CaptureState::Failed);
    assert!(record.logs.truncated);
    assert!(
        fs::metadata(run.join("stdout.log")).unwrap().len()
            + fs::metadata(run.join("stderr.log")).unwrap().len()
            <= 1024
    );
    let mut options = sandbox.options(
        "/bin/dd if=/dev/zero of=large.bin bs=4096 count=1 2>/dev/null; exec /bin/sleep 10",
    );
    options.max_output_bytes = 1024;
    let run = capture(request(), options, Arc::new(AtomicBool::new(false))).unwrap();
    let record = inspect(&run).unwrap();
    assert_eq!(record.state, CaptureState::Failed);
    assert!(fs::metadata(run.join("large.bin")).unwrap().len() > 1024);
    assert!(record.cleanup.as_ref().unwrap().leader_reaped);
}

#[test]
fn unique_directories_preserve_existing_evidence_and_reject_directory_links() {
    use std::os::unix::fs::symlink;
    let sandbox = Sandbox::new();
    fs::write(sandbox.root.join("keep.txt"), "existing evidence").unwrap();
    let first = sandbox.run("printf first; exit 0");
    let first_manifest = fs::read(first.join("manifest.json")).unwrap();
    let second = sandbox.run("printf second; exit 0");
    assert_ne!(first, second);
    assert_eq!(
        fs::read_to_string(sandbox.root.join("keep.txt")).unwrap(),
        "existing evidence"
    );
    assert_eq!(
        fs::read(first.join("manifest.json")).unwrap(),
        first_manifest
    );
    let alias = sandbox.root.join("linked-root");
    symlink(&first, &alias).unwrap();
    let mut options = sandbox.options("exit 0");
    options.root = alias.clone();
    assert!(capture(request(), options, Arc::new(AtomicBool::new(false))).is_err());
    assert!(inspect(&alias).is_err());
    let mut options = sandbox.options("exit 0");
    options.root = sandbox.root.join("keep.txt");
    assert!(capture(request(), options, Arc::new(AtomicBool::new(false))).is_err());
    assert_eq!(
        fs::read(first.join("manifest.json")).unwrap(),
        first_manifest
    );
}

#[test]
fn rejects_unsupported_execution_policy_and_reserved_environment() {
    let sandbox = Sandbox::new();
    let mut in_process = request();
    in_process.process_policy = ProcessPolicy::InProcess;
    assert!(
        capture(
            in_process,
            sandbox.options("exit 0"),
            Arc::new(AtomicBool::new(false))
        )
        .is_err()
    );
    let mut options = sandbox.options("exit 0");
    options
        .env
        .insert("MIL_RESULT_PATH".into(), "/tmp/not-owned".into());
    assert!(capture(request(), options, Arc::new(AtomicBool::new(false))).is_err());
    let mut options = sandbox.options("exit 0");
    options.executable = "sh".into();
    assert!(capture(request(), options, Arc::new(AtomicBool::new(false))).is_err());
    assert_eq!(fs::read_dir(&sandbox.root).unwrap().count(), 0);
}

#[test]
fn inspect_rejects_malformed_record_invariants_without_rewriting() {
    let sandbox = Sandbox::new();
    let run = sandbox.run(SUCCESS);
    let good = manifest(&run);
    for (pointer, invalid) in [
        ("/record_version", json!(3)),
        ("/sample_index", json!(1)),
        ("/state", json!("running")),
        ("/workload_identity", json!("0".repeat(64))),
        ("/adapter_result", Value::Null),
        ("/adapter_result/schema_version", json!(3)),
        ("/adapter_result/workload_identity", json!("0".repeat(64))),
        ("/exit/code", json!(9)),
        ("/exit/signal", json!(9)),
        ("/host_elapsed_ms", Value::Null),
        ("/artifact_inspection_ms", Value::Null),
        ("/cleanup_elapsed_ms", Value::Null),
        ("/cleanup/process_group", json!(1)),
        ("/cleanup/leader_reaped", json!(false)),
        ("/failure", json!("contradictory success")),
        ("/logs/truncated", json!(true)),
        ("/invocation/args/0", json!("unredacted")),
    ] {
        let mut bad = good.clone();
        *bad.pointer_mut(pointer).unwrap() = invalid;
        let bytes = serde_json::to_vec(&bad).unwrap();
        fs::write(run.join("manifest.json"), &bytes).unwrap();
        assert!(inspect(&run).is_err(), "accepted malformed field {pointer}");
        assert_eq!(fs::read(run.join("manifest.json")).unwrap(), bytes);
    }
    fs::write(
        run.join("manifest.json"),
        serde_json::to_vec(&good).unwrap(),
    )
    .unwrap();
    let mut requested: Value =
        serde_json::from_slice(&fs::read(run.join("requested.json")).unwrap()).unwrap();
    requested["id"] = json!("different-request");
    fs::write(
        run.join("requested.json"),
        serde_json::to_vec(&requested).unwrap(),
    )
    .unwrap();
    assert!(inspect(&run).is_err());
}

#[test]
fn inspect_rechecks_persisted_result_artifact_and_log_evidence() {
    let sandbox = Sandbox::new();
    let run = sandbox.run(SUCCESS);
    let result_path = run.join("result.json");
    let original = fs::read(&result_path).unwrap();
    let mut altered: Value = serde_json::from_slice(&original).unwrap();
    altered["runtime"]["name"] = json!("different-runtime");
    fs::write(&result_path, serde_json::to_vec(&altered).unwrap()).unwrap();
    assert!(inspect(&run).is_err());
    fs::write(&result_path, original).unwrap();
    let artifact = run.join("artifacts/schema-output.txt");
    let original = fs::read(&artifact).unwrap();
    fs::write(&artifact, b"tampered").unwrap();
    assert!(inspect(&run).is_err());
    fs::write(&artifact, original).unwrap();
    fs::write(
        run.join("stdout.log"),
        b"different size from recorded stdout",
    )
    .unwrap();
    assert!(inspect(&run).is_err());
}

#[test]
fn killed_supervisor_leaves_read_only_unresolved_running_manifest() {
    let sandbox = Sandbox::new();
    let workload = Path::new(env!("CARGO_MANIFEST_DIR")).join("examples/image-workload.json");
    let child = Command::new(env!("CARGO_BIN_EXE_mil"))
        .args(["supervise", "--cpu-only", "--workload"])
        .arg(workload)
        .arg("--root")
        .arg(&sandbox.root)
        .args([
            "--executable",
            "/bin/sh",
            "--timeout-seconds",
            "3",
            "--",
            "-c",
            "printf ready > ready; exec /bin/sleep 0.7",
        ])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    let mut supervisor = TestChild(child);
    let run = wait_for_file(&sandbox.root, "ready");
    supervisor.0.kill().unwrap();
    supervisor.0.wait().unwrap();
    let before = fs::read(run.join("manifest.json")).unwrap();
    let record: CaptureRecord = inspect(&run).unwrap();
    assert_eq!(record.state, CaptureState::Running);
    assert!(!record.is_success());
    assert!(record.ended_unix_ms.is_none());
    assert!(record.host_elapsed_ms.is_none());
    thread::sleep(Duration::from_millis(800));
    assert_eq!(inspect(&run).unwrap().state, CaptureState::Running);
    assert_eq!(fs::read(run.join("manifest.json")).unwrap(), before);
}

#[test]
fn inspect_rejects_signed_zero_request_identity_tampering() {
    let sandbox = Sandbox::new();
    let mut declared = serde_json::to_value(request()).unwrap();
    declared["settings"]["generation"]["guidance"] = json!(0.0);
    let declared: Workload = serde_json::from_value(declared).unwrap();
    let run = capture(
        declared.clone(),
        sandbox.options("exit 0"),
        Arc::new(AtomicBool::new(false)),
    )
    .unwrap();
    assert_eq!(inspect(&run).unwrap().state, CaptureState::Incomplete);
    let mut altered = serde_json::to_value(&declared).unwrap();
    altered["settings"]["generation"]["guidance"] = json!(-0.0);
    let altered: Workload = serde_json::from_value(altered).unwrap();
    assert_eq!(altered, declared);
    assert_ne!(altered.identity().unwrap(), declared.identity().unwrap());
    fs::write(
        run.join("requested.json"),
        serde_json::to_vec(&altered).unwrap(),
    )
    .unwrap();
    assert!(inspect(&run).is_err());
}
