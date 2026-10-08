#![cfg(any(target_os = "macos", target_os = "linux"))]

use media_inference_lab::{
    capture::{CaptureOptions, CaptureRecord, CaptureState, capture, inspect},
    schema::{AdapterResult, Workload},
};
use serde_json::{Value, json};
use std::{
    collections::BTreeMap,
    fs::{self, File},
    path::{Path, PathBuf},
    sync::{Arc, atomic::AtomicBool},
    time::Duration,
};
use tempfile::TempDir;

const JSON_LIMIT: u64 = 16 * 1024 * 1024;
const OUTPUT: &[u8] = b"CPU schema fixture only; no inference was performed.\n";
const ADAPTER: &str = r#"
set -eu
/bin/mkdir artifacts
printf 'CPU schema fixture only; no inference was performed.\n' > artifacts/schema-output.txt
/bin/cp "$RESULT_FIXTURE" "$MIL_RESULT_PATH"
printf 'retained stdout\n'
printf 'retained stderr\n' >&2
"#;

struct Sandbox {
    _temporary: TempDir,
    root: PathBuf,
}

impl Sandbox {
    fn new() -> Self {
        let temporary = tempfile::tempdir().unwrap();
        let root = fs::canonicalize(temporary.path()).unwrap();
        Self {
            _temporary: temporary,
            root,
        }
    }

    fn fixture(&self, result: &Value) -> PathBuf {
        let path = self.root.join("adapter-result.json");
        serde_json::to_writer(File::create(&path).unwrap(), result).unwrap();
        path
    }

    fn options(&self, fixture: &Path, script: &str) -> CaptureOptions {
        CaptureOptions {
            root: self.root.clone(),
            executable: "/bin/sh".into(),
            args: vec!["-c".into(), script.into()],
            env: BTreeMap::from([(
                "RESULT_FIXTURE".into(),
                fixture.to_string_lossy().into_owned(),
            )]),
            timeout: Duration::from_secs(15),
            max_output_bytes: 64 * 1024 * 1024,
        }
    }
}

fn request(prompt_bytes: Option<usize>) -> Workload {
    let mut value: Value =
        serde_json::from_str(include_str!("../examples/image-workload.json")).unwrap();
    if let Some(bytes) = prompt_bytes {
        value["settings"]["generation"]["prompt"] = json!("p".repeat(bytes));
    }
    serde_json::from_value(value).unwrap()
}

fn result(request: &Workload) -> Value {
    let mut value: Value =
        serde_json::from_str(include_str!("fixtures/image-result.json")).unwrap();
    value["workload_identity"] = json!(request.identity().unwrap());
    value["resolved"]["settings"]["generation"]["prompt"] =
        serde_json::to_value(request).unwrap()["settings"]["generation"]["prompt"].clone();
    value
}

fn assert_clean_exit(record: &CaptureRecord) {
    assert_eq!(record.exit.as_ref().unwrap().code, Some(0));
    assert_eq!(record.exit.as_ref().unwrap().signal, None);
    let cleanup = record.cleanup.as_ref().unwrap();
    assert!(cleanup.process_group.is_some());
    assert!(cleanup.leader_reaped);
    assert!(cleanup.group_signalled || cleanup.group_quiescent);
    assert!(record.ended_unix_ms.is_some());
    assert!(record.host_elapsed_ms.is_some());
    assert!(record.cleanup_elapsed_ms.is_some());
    assert!(record.artifact_inspection_ms.is_some());
}

#[test]
fn aggregate_manifest_overflow_retains_inspectable_terminal_failure_and_raw_evidence() {
    let sandbox = Sandbox::new();
    let request = request(Some(9 * 1024 * 1024));
    let result = result(&request);
    serde_json::from_value::<AdapterResult>(result.clone())
        .unwrap()
        .validate(&request)
        .unwrap();
    let fixture = sandbox.fixture(&result);
    assert!(fs::metadata(&fixture).unwrap().len() < JSON_LIMIT);
    let run = capture(
        request,
        sandbox.options(&fixture, ADAPTER),
        Arc::new(AtomicBool::new(false)),
    )
    .unwrap();
    assert!(fs::metadata(run.join("requested.json")).unwrap().len() < JSON_LIMIT);
    assert!(fs::metadata(run.join("manifest.json")).unwrap().len() <= JSON_LIMIT);
    let record = inspect(&run).unwrap();
    assert_eq!(record.state, CaptureState::Failed);
    assert_clean_exit(&record);
    assert!(record.adapter_result.is_none());
    assert!(record.failure.as_ref().unwrap().contains("result.json"));
    assert_eq!(
        fs::read(run.join("result.json")).unwrap(),
        fs::read(fixture).unwrap()
    );
    assert_eq!(
        fs::read(run.join("artifacts/schema-output.txt")).unwrap(),
        OUTPUT
    );
    assert_eq!(
        fs::read(run.join("stdout.log")).unwrap(),
        b"retained stdout\n"
    );
    assert_eq!(
        fs::read(run.join("stderr.log")).unwrap(),
        b"retained stderr\n"
    );
}

#[test]
fn running_manifest_reserves_terminal_headroom_before_spawning() {
    let sandbox = Sandbox::new();
    let marker = sandbox.root.join("spawned");
    let mut options = sandbox.options(&marker, "printf spawned > \"$SPAWN_MARKER\"");
    options
        .env
        .insert("SPAWN_MARKER".into(), marker.to_string_lossy().into_owned());
    let request = request(Some(JSON_LIMIT as usize - 32 * 1024));
    assert!(serde_json::to_vec_pretty(&request).unwrap().len() < JSON_LIMIT as usize);
    assert!(capture(request, options, Arc::new(AtomicBool::new(false))).is_err());
    assert!(
        !marker.exists(),
        "a request without terminal headroom must not spawn"
    );
    let run = fs::read_dir(&sandbox.root)
        .unwrap()
        .map(|entry| entry.unwrap().path())
        .find(|path| path.is_dir())
        .unwrap();
    assert!(run.join("requested.json").is_file());
    assert!(!run.join("manifest.json").exists());
}

#[test]
fn near_limit_request_retains_bounded_unicode_failure_and_cleanup() {
    let sandbox = Sandbox::new();
    let request = request(Some(JSON_LIMIT as usize - 96 * 1024));
    // An unknown field yields an adapter-controlled deserialization diagnostic.
    // It must not consume the reserve needed for actual terminal observations.
    let mut invalid = serde_json::Map::new();
    invalid.insert("界\u{0001}".repeat(8192), Value::Null);
    let fixture = sandbox.fixture(&Value::Object(invalid));
    let run = capture(
        request,
        sandbox.options(&fixture, ADAPTER),
        Arc::new(AtomicBool::new(false)),
    )
    .unwrap();
    let record = inspect(&run).unwrap();
    assert_eq!(record.state, CaptureState::Failed);
    assert_clean_exit(&record);
    let reason = record.failure.unwrap();
    assert!(reason.len() <= 8 * 1024);
    assert!(reason.ends_with(" [truncated]"));
    assert!(fs::metadata(run.join("manifest.json")).unwrap().len() <= JSON_LIMIT);
    assert_eq!(
        fs::read(run.join("result.json")).unwrap(),
        fs::read(fixture).unwrap()
    );
}

#[test]
fn hardlinked_artifacts_are_rejected_but_distinct_files_with_equal_content_are_valid() {
    for hardlinked in [true, false] {
        let sandbox = Sandbox::new();
        let request = request(None);
        let mut result = result(&request);
        let mut second = result["artifacts"][0].clone();
        second["path"] = json!("artifacts/second-output.txt");
        result["artifacts"].as_array_mut().unwrap().push(second);
        serde_json::from_value::<AdapterResult>(result.clone())
            .unwrap()
            .validate(&request)
            .unwrap();
        let fixture = sandbox.fixture(&result);
        let operation = if hardlinked { "/bin/ln" } else { "/bin/cp" };
        let script = format!(
            "{ADAPTER}\n{operation} artifacts/schema-output.txt artifacts/second-output.txt\n"
        );
        let run = capture(
            request,
            sandbox.options(&fixture, &script),
            Arc::new(AtomicBool::new(false)),
        )
        .unwrap();
        let record = inspect(&run).unwrap();
        assert_clean_exit(&record);
        assert_eq!(
            record.state,
            if hardlinked {
                CaptureState::Failed
            } else {
                CaptureState::Completed
            }
        );
        assert_eq!(
            fs::read(run.join("artifacts/schema-output.txt")).unwrap(),
            OUTPUT
        );
        assert_eq!(
            fs::read(run.join("artifacts/second-output.txt")).unwrap(),
            OUTPUT
        );
        if hardlinked {
            assert!(record.adapter_result.is_none());
            assert!(
                record
                    .failure
                    .as_ref()
                    .unwrap()
                    .contains("second-output.txt")
            );
        } else {
            assert_eq!(record.adapter_result.unwrap().artifacts.len(), 2);
        }
    }
}
