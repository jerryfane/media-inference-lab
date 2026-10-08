#[path = "support/capture_fixture.rs"]
mod capture_fixture;
use capture_fixture::{persist, record};
use media_inference_lab::{
    capture::CaptureRecord,
    capture_archive::CaptureArchive,
    comparison::{self, InspectionState},
    schema::TimingScope,
    study::{ComparisonMode, Metric, Role, SampleBinding, StudyInput, StudyPlan},
    study_report,
};
use pulldown_cmark::{Event, Options, Parser, Tag};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::{fs, path::Path, process::Command, time::Duration};
use tempfile::TempDir;

struct Fixture {
    root: TempDir,
    input: StudyInput,
    long_device: String,
}
impl Fixture {
    fn new() -> Self {
        let root = tempfile::tempdir_in(fs::canonicalize(std::env::temp_dir()).unwrap()).unwrap();
        let plan = StudyPlan {
            schema_version: 1,
            id: "synthetic-readable-study".into(),
            workload: serde_json::from_str(include_str!("../examples/image-workload.json"))
                .unwrap(),
            mode: ComparisonMode::SameWork,
            metric: Metric::Adapter {
                phase: "synthetic".into(),
                scope: TimingScope::Host,
                method: "generated fixture".into(),
                boundary: "synthetic start to synthetic end".into(),
            },
            repetitions: 3,
            warmups: 1,
            minimum_samples: 3,
            baseline_label: "synthetic baseline".into(),
            candidate_label: "synthetic candidate".into(),
        };
        let long_device = format!(
            "{}\n```\n# SPOOFED\n<script>not executable</script>\n[external](https://invalid.example)\n\u{9d}hidden\u{9c}\nfull-device-tail",
            "界".repeat(512)
        );
        let samples = plan
            .slots()
            .unwrap()
            .into_iter()
            .map(|slot| {
                let relative = format!("capture-{}", slot.index);
                let seconds = if slot.role == Role::Candidate {
                    2.0
                } else {
                    4.0
                };
                let mut value = record(&plan.workload, slot.index, seconds);
                value["adapter_result"]["runtime"]["device"]["value"] = json!(long_device);
                persist(&root.path().join(&relative), &value);
                SampleBinding {
                    index: slot.index,
                    capture: Some(relative.into()),
                    missing_reason: None,
                }
            })
            .collect();
        Self {
            root,
            input: StudyInput {
                schema_version: 1,
                plan,
                samples,
            },
            long_device,
        }
    }
    fn input_path(&self) -> std::path::PathBuf {
        let path = self.root.path().join("study.json");
        fs::write(&path, serde_json::to_vec(&self.input).unwrap()).unwrap();
        path
    }
    fn change(&self, index: usize, change: impl FnOnce(&mut Value)) {
        let directory = self.root.path().join(format!("capture-{index}"));
        let mut value =
            serde_json::from_slice(&fs::read(directory.join("manifest.json")).unwrap()).unwrap();
        change(&mut value);
        persist(&directory, &value);
    }
}

fn links(markdown: &str) -> Vec<String> {
    let mut links = Vec::new();
    for event in Parser::new_ext(markdown, Options::ENABLE_TABLES) {
        match event {
            Event::Html(_) | Event::InlineHtml(_) => panic!("captured metadata escaped into HTML"),
            Event::Start(Tag::Image { .. }) => panic!("metadata-only report embedded media"),
            Event::Start(Tag::Link { dest_url, .. }) => {
                assert!(
                    dest_url.as_ref() == "report.json"
                        || dest_url
                            .strip_prefix("captures/slot-")
                            .and_then(|s| s.strip_suffix(".json"))
                            .is_some_and(|s| s.len() == 3 && s.bytes().all(|b| b.is_ascii_digit())),
                    "unexpected link: {dest_url}"
                );
                links.push(dest_url.into_string());
            }
            _ => {}
        }
    }
    links
}

#[test]
fn archived_records_remain_exact_after_original_sources_change_or_disappear() {
    let fixture = Fixture::new();
    let output = fixture.root.path().join("bundle");
    let mut archive = CaptureArchive::new(output.clone());
    let comparison = comparison::compare(
        &fixture.input,
        fixture.root.path(),
        Duration::from_secs(10),
        Some(&mut archive),
    )
    .unwrap();
    assert!(comparison.is_complete());
    for row in &comparison.rows {
        let index = row.slot.index as usize;
        let text = archive.text(index).unwrap().unwrap();
        let snapshot: CaptureRecord = serde_json::from_str(&text).unwrap();
        assert_eq!(
            Some(format!(
                "{:x}",
                Sha256::digest(serde_json::to_vec(&snapshot).unwrap())
            ))
            .as_ref(),
            row.manifest_identity.as_ref()
        );
        let value: Value = serde_json::from_str(&text).unwrap();
        assert_eq!(
            value["adapter_result"]["runtime"]["device"]["value"],
            fixture.long_device
        );
        assert_eq!(value["adapter_result"]["resources"][0]["scope"], "process");
        fs::remove_dir_all(fixture.root.path().join(format!("capture-{index}"))).unwrap();
    }
    let mut markdown = Vec::new();
    study_report::write(&mut markdown, &fixture.input, &comparison, &archive).unwrap();
    let markdown = String::from_utf8(markdown).unwrap();
    assert!(markdown.contains("full-device-tail"));
    assert!(!markdown.contains('\u{9d}'));
    for target in links(&markdown)
        .into_iter()
        .filter(|target| target != "report.json")
    {
        assert!(output.join(target).is_file());
    }
    let path = output.join("captures/slot-000.json");
    let mut changed = fs::read(&path).unwrap();
    changed[0] = b'[';
    fs::write(&path, changed).unwrap();
    assert!(study_report::write(&mut Vec::new(), &fixture.input, &comparison, &archive).is_err());
}

#[test]
fn mixed_cli_outcomes_keep_all_slots_and_only_loaded_snapshots_after_relocation() {
    let mut fixture = Fixture::new();
    fixture.change(0, |value| {
        value["state"] = json!("failed");
        value["failure"] = json!("generated warmup failure");
        value["adapter_result"] = Value::Null;
    });
    fixture.input.samples[4].capture = None;
    fixture.input.samples[4].missing_reason = Some("explicitly not collected".into());
    fixture.change(5, |value| value["record_version"] = json!(999));
    let output = fixture.root.path().join("bundle");
    let result = Command::new(env!("CARGO_BIN_EXE_mil"))
        .arg("study-report")
        .arg(fixture.input_path())
        .arg("--output-dir")
        .arg(&output)
        .args(["--inspection-seconds", "10"])
        .output()
        .unwrap();
    assert_eq!(
        result.status.code(),
        Some(1),
        "{}",
        String::from_utf8_lossy(&result.stderr)
    );
    let report: Value =
        serde_json::from_slice(&fs::read(output.join("report.json")).unwrap()).unwrap();
    let rows = report["comparison"]["rows"].as_array().unwrap();
    assert_eq!(rows.len(), 12);
    assert_eq!(rows[0]["state"], "failed");
    assert_eq!(rows[4]["inspection"], "missing");
    assert_eq!(rows[5]["inspection"], "invalid");
    assert!(report["comparison"]["candidate_vs_baseline"]["median_ratio"].is_null());
    let snapshots = report["capture_snapshots"].as_array().unwrap();
    assert_eq!(snapshots.len(), rows.len());
    for (index, artifact) in snapshots.iter().enumerate() {
        assert_eq!(artifact.is_null(), index == 4 || index == 5);
        if !artifact.is_null() {
            verify_artifact(&output, artifact);
        }
        fs::remove_dir_all(fixture.root.path().join(format!("capture-{index}"))).unwrap();
    }
    verify_artifact(&output, &report["readable"]);
    let moved = fixture.root.path().join("moved");
    fs::rename(&output, &moved).unwrap();
    let markdown = fs::read_to_string(moved.join("report.md")).unwrap();
    for target in links(&markdown) {
        assert!(moved.join(target).is_file());
    }
    assert!(
        !moved
            .join("captures/slot-000.json")
            .with_file_name("artifacts")
            .exists()
    );
}

fn verify_artifact(base: &Path, artifact: &Value) {
    let path = base.join(artifact["path"].as_str().unwrap());
    let bytes = fs::read(&path).unwrap();
    assert_eq!(artifact["bytes"], bytes.len() as u64);
    assert_eq!(artifact["sha256"], format!("{:x}", Sha256::digest(&bytes)));
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(
            fs::metadata(path).unwrap().permissions().mode() & 0o777,
            0o600
        );
    }
}

#[test]
fn invalid_study_never_prepares_a_bundle_and_existing_bundles_are_never_reused() {
    let mut fixture = Fixture::new();
    let omitted = fixture.input.samples.pop().unwrap();
    let output = fixture.root.path().join("bundle");
    let mut archive = CaptureArchive::new(output.clone());
    assert!(
        comparison::compare(
            &fixture.input,
            fixture.root.path(),
            Duration::from_secs(10),
            Some(&mut archive)
        )
        .is_err()
    );
    assert!(!output.exists());
    fixture.input.samples.push(omitted);
    let comparison = comparison::compare(
        &fixture.input,
        fixture.root.path(),
        Duration::from_secs(10),
        Some(&mut archive),
    )
    .unwrap();
    assert!(
        comparison
            .rows
            .iter()
            .all(|r| matches!(r.inspection, InspectionState::Loaded))
    );
    let before = fs::read(output.join("captures/slot-000.json")).unwrap();
    assert!(
        comparison::compare(
            &fixture.input,
            fixture.root.path(),
            Duration::from_secs(10),
            Some(&mut CaptureArchive::new(output.clone()))
        )
        .is_err()
    );
    assert_eq!(
        fs::read(output.join("captures/slot-000.json")).unwrap(),
        before
    );
}
