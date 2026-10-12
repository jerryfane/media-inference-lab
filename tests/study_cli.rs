use media_inference_lab::{
    schema::Workload,
    study::{ComparisonMode, Metric, StudyPlan},
};
use serde_json::Value;
use std::{fs, process::Command};

#[test]
fn generated_template_near_plan_limit_remains_readable_with_all_slots() {
    let root = tempfile::tempdir().unwrap();
    let mut workload: Value =
        serde_json::from_str(include_str!("../examples/image-workload.json")).unwrap();
    workload["settings"]["generation"]["prompt"] = Value::String("x".repeat(1024 * 1024 - 4096));
    let plan = StudyPlan {
        schema_version: 1,
        id: "bounded-template".into(),
        workload: serde_json::from_value::<Workload>(workload).unwrap(),
        mode: ComparisonMode::Descriptive,
        metric: Metric::HostExecution,
        repetitions: 30,
        warmups: 3,
        minimum_samples: 3,
        baseline_label: "CPU baseline".into(),
        candidate_label: "CPU candidate".into(),
    };
    let bytes = serde_json::to_vec(&plan).unwrap();
    assert!(bytes.len() < 1024 * 1024);
    let input = root.path().join("plan.json");
    let study = root.path().join("study.json");
    let output = root.path().join("report.json");
    fs::write(&input, bytes).unwrap();
    let planned = Command::new(env!("CARGO_BIN_EXE_mil"))
        .arg("study-plan")
        .arg(input)
        .arg("--output")
        .arg(&study)
        .output()
        .unwrap();
    assert!(
        planned.status.success(),
        "{}",
        String::from_utf8_lossy(&planned.stderr)
    );
    assert!(fs::metadata(&study).unwrap().len() > 1024 * 1024);
    let compared = Command::new(env!("CARGO_BIN_EXE_mil"))
        .arg("compare")
        .arg(study)
        .arg("--output")
        .arg(&output)
        .output()
        .unwrap();
    // Missing captures are an inspectable inconclusive report, not an unreadable generated file.
    assert_eq!(
        compared.status.code(),
        Some(1),
        "{}",
        String::from_utf8_lossy(&compared.stderr)
    );
    let report: Value = serde_json::from_slice(&fs::read(output).unwrap()).unwrap();
    assert_eq!(report["rows"].as_array().unwrap().len(), 99);
    assert_eq!(report["status"], "inconclusive");
    for row in report["rows"].as_array().unwrap() {
        assert_eq!(row["inspection"], "missing");
        assert!(row["metric_seconds"].is_null());
    }
}
