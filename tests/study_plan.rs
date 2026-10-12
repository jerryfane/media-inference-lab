use media_inference_lab::schema::{TimingScope, Workload};
use media_inference_lab::study::{ComparisonMode, Metric, Role, StudyInput, StudyPlan};
use serde_json::{Value, json};
use std::path::PathBuf;

fn plan() -> StudyPlan {
    StudyPlan {
        schema_version: 1,
        id: "cpu-study".to_owned(),
        workload: serde_json::from_str::<Workload>(include_str!("../examples/image-workload.json"))
            .unwrap(),
        mode: ComparisonMode::SameWork,
        metric: Metric::HostExecution,
        repetitions: 3,
        warmups: 1,
        minimum_samples: 3,
        baseline_label: "baseline-runtime".to_owned(),
        candidate_label: "candidate-runtime".to_owned(),
    }
}

fn adapter_plan() -> StudyPlan {
    StudyPlan {
        metric: Metric::Adapter {
            phase: "denoise".to_owned(),
            scope: TimingScope::Native,
            method: "monotonic".to_owned(),
            boundary: "denoise entry to synchronized return".to_owned(),
        },
        ..plan()
    }
}

fn changed_plan(pointer: &str, value: Value) -> StudyPlan {
    let mut encoded = serde_json::to_value(adapter_plan()).unwrap();
    *encoded.pointer_mut(pointer).unwrap() = value;
    serde_json::from_value(encoded).unwrap()
}

#[test]
fn warmups_and_measurements_preserve_explicit_role_cycles() {
    let mut plan = plan();
    plan.warmups = 2;
    plan.repetitions = 2;
    // A stricter reporting threshold than the planned repetitions is valid, not clamped.
    plan.minimum_samples = 3;
    let actual: Vec<_> = plan
        .slots()
        .unwrap()
        .into_iter()
        .map(|sample| (sample.index, sample.role, sample.warmup, sample.repetition))
        .collect();
    assert_eq!(
        actual,
        vec![
            (0, Role::Baseline, true, 0),
            (1, Role::Candidate, true, 0),
            (2, Role::Control, true, 0),
            (3, Role::Baseline, true, 1),
            (4, Role::Candidate, true, 1),
            (5, Role::Control, true, 1),
            (6, Role::Baseline, false, 0),
            (7, Role::Candidate, false, 0),
            (8, Role::Control, false, 0),
            (9, Role::Baseline, false, 1),
            (10, Role::Candidate, false, 1),
            (11, Role::Control, false, 1),
        ]
    );
    let input = plan.template().unwrap();
    input.validate().unwrap();
    assert_eq!(input.samples.len(), 12);
    assert_eq!(input.plan.minimum_samples, 3);
    for (index, binding) in input.samples.iter().enumerate() {
        assert_eq!(binding.index as usize, index);
        assert!(binding.capture.is_none());
    }
    let encoded = serde_json::to_vec(&input).unwrap();
    let restored: StudyInput = serde_json::from_slice(&encoded).unwrap();
    restored.validate().unwrap();
}

#[test]
fn plan_bounds_reject_extreme_counts_before_slot_or_template_allocation() {
    for (pointer, value) in [
        ("/schema_version", json!(0)),
        ("/schema_version", json!(2)),
        ("/repetitions", json!(0)),
        ("/repetitions", json!(31)),
        ("/repetitions", json!(u32::MAX)),
        ("/warmups", json!(4)),
        ("/warmups", json!(u32::MAX)),
        ("/minimum_samples", json!(0)),
        ("/minimum_samples", json!(2)),
        ("/minimum_samples", json!(31)),
        ("/workload/schema_version", json!(2)),
        ("/workload/settings/generation/steps", json!(0)),
    ] {
        let invalid = changed_plan(pointer, value);
        assert!(invalid.validate().is_err(), "accepted {pointer}");
        assert!(invalid.slots().is_err(), "allocated slots for {pointer}");
        assert!(
            invalid.template().is_err(),
            "created template for {pointer}"
        );
        assert!(invalid.identity().is_err(), "identified invalid {pointer}");
    }
    let mut maximum = plan();
    maximum.repetitions = 30;
    maximum.warmups = 3;
    maximum.minimum_samples = 30;
    maximum.template().unwrap().validate().unwrap();
    let slots = maximum.slots().unwrap();
    assert_eq!(slots.len(), 99);
    assert_eq!(slots.iter().filter(|slot| slot.warmup).count(), 9);
    assert_eq!(slots[98].index, 98);
    assert_eq!(slots[98].role, Role::Control);
    assert_eq!(slots[98].repetition, 29);
    let mut minimum = plan();
    minimum.repetitions = 1;
    minimum.warmups = 0;
    let slots = minimum.slots().unwrap();
    assert_eq!(slots.len(), 3);
    assert!(
        slots
            .iter()
            .all(|slot| !slot.warmup && slot.repetition == 0)
    );
    minimum.template().unwrap().validate().unwrap();
}

#[test]
fn labels_and_metric_selectors_are_nonblank_nul_free_and_byte_bounded() {
    for (pointer, maximum) in [
        ("/id", 128),
        ("/baseline_label", 128),
        ("/candidate_label", 128),
        ("/metric/phase", 128),
        ("/metric/method", 1024),
        ("/metric/boundary", 1024),
    ] {
        for text in [
            String::new(),
            " \t\n".to_owned(),
            "has\0nul".to_owned(),
            "x".repeat(maximum + 1),
            "é".repeat(maximum / 2 + 1),
        ] {
            assert!(changed_plan(pointer, json!(text)).validate().is_err());
        }
        changed_plan(pointer, json!("é".repeat(maximum / 2)))
            .validate()
            .unwrap();
    }
}

#[test]
fn bindings_cannot_omit_duplicate_reorder_or_append_slots() {
    let input = plan().template().unwrap();
    for removed in [0, 4, input.samples.len() - 1] {
        let mut changed = input.clone();
        changed.samples.remove(removed);
        assert!(changed.validate().is_err());
    }
    let mut duplicate = input.clone();
    duplicate.samples[2] = duplicate.samples[1].clone();
    assert!(duplicate.validate().is_err());
    let mut reordered = input.clone();
    reordered.samples.swap(0, 1);
    assert!(reordered.validate().is_err());
    let mut appended = input.clone();
    appended.samples.push(appended.samples[0].clone());
    assert!(appended.validate().is_err());
    let mut bad_index = input;
    bad_index.samples[0].index = u32::MAX;
    assert!(bad_index.validate().is_err());
}

#[test]
fn capture_paths_and_missing_reasons_are_exclusive_and_validated() {
    let input = plan().template().unwrap();
    for path in ["runs/baseline", "../captures/control", "/saved/candidate"] {
        let mut present = input.clone();
        present.samples[0].capture = Some(PathBuf::from(path));
        present.samples[0].missing_reason = None;
        present.validate().unwrap();
        assert_eq!(
            present.plan.identity().unwrap(),
            input.plan.identity().unwrap()
        );
    }
    for path in [String::new(), "bad\0path".to_owned(), "x".repeat(4097)] {
        let mut invalid = input.clone();
        invalid.samples[0].capture = Some(PathBuf::from(path));
        invalid.samples[0].missing_reason = None;
        assert!(invalid.validate().is_err());
    }
    let mut boundary = input.clone();
    boundary.samples[0].capture = Some(PathBuf::from("x".repeat(4096)));
    boundary.samples[0].missing_reason = None;
    boundary.validate().unwrap();
    let mut both = input.clone();
    both.samples[0].capture = Some(PathBuf::from("runs/baseline"));
    assert!(both.validate().is_err());
    let mut neither = input.clone();
    neither.samples[0].missing_reason = None;
    assert!(neither.validate().is_err());
    for reason in ["", " \n\t", "bad\0reason"] {
        let mut invalid = input.clone();
        invalid.samples[0].missing_reason = Some(reason.to_owned());
        assert!(invalid.validate().is_err());
    }
}

#[test]
fn versions_unknown_fields_and_missing_required_policy_are_rejected() {
    let encoded = serde_json::to_value(adapter_plan()).unwrap();
    for key in encoded.as_object().unwrap().keys() {
        let mut missing = encoded.clone();
        missing.as_object_mut().unwrap().remove(key);
        assert!(
            serde_json::from_value::<StudyPlan>(missing).is_err(),
            "accepted missing {key}"
        );
    }
    for key in ["kind", "phase", "scope", "method", "boundary"] {
        let mut missing = encoded.clone();
        missing["metric"].as_object_mut().unwrap().remove(key);
        assert!(
            serde_json::from_value::<StudyPlan>(missing).is_err(),
            "accepted missing metric {key}"
        );
    }
    for pointer in ["", "/metric", "/workload"] {
        let mut unknown = encoded.clone();
        unknown
            .pointer_mut(pointer)
            .unwrap()
            .as_object_mut()
            .unwrap()
            .insert("unexpected".to_owned(), json!(true));
        assert!(serde_json::from_value::<StudyPlan>(unknown).is_err());
    }
    let mut unknown_host = serde_json::to_value(plan()).unwrap();
    unknown_host["metric"]["unexpected"] = json!(true);
    assert!(serde_json::from_value::<StudyPlan>(unknown_host).is_err());
    let input = plan().template().unwrap();
    for version in [0, 2, u32::MAX] {
        let mut unsupported = input.clone();
        unsupported.schema_version = version;
        assert!(unsupported.validate().is_err());
    }
    for pointer in ["", "/samples/0"] {
        let mut unknown = serde_json::to_value(&input).unwrap();
        unknown
            .pointer_mut(pointer)
            .unwrap()
            .as_object_mut()
            .unwrap()
            .insert("unexpected".to_owned(), json!(true));
        assert!(serde_json::from_value::<StudyInput>(unknown).is_err());
    }
    for key in ["schema_version", "plan", "samples"] {
        let mut missing = serde_json::to_value(&input).unwrap();
        missing.as_object_mut().unwrap().remove(key);
        assert!(serde_json::from_value::<StudyInput>(missing).is_err());
    }
    for mode in ["speedup", "same-work"] {
        let mut invalid = encoded.clone();
        invalid["mode"] = json!(mode);
        assert!(serde_json::from_value::<StudyPlan>(invalid).is_err());
    }
}

#[test]
fn complete_typed_policy_and_workload_participate_in_study_identity() {
    let original = adapter_plan().identity().unwrap();
    for (pointer, value) in [
        ("/id", json!("other-study")),
        ("/baseline_label", json!("other-baseline")),
        ("/candidate_label", json!("other-candidate")),
        ("/mode", json!("descriptive")),
        ("/metric/phase", json!("generation")),
        ("/metric/scope", json!("gpu")),
        ("/metric/method", json!("events")),
        ("/metric/boundary", json!("events around phase")),
        ("/repetitions", json!(4)),
        ("/warmups", json!(0)),
        ("/minimum_samples", json!(4)),
        ("/workload/settings/generation/seed", json!(18)),
    ] {
        assert_ne!(
            changed_plan(pointer, value).identity().unwrap(),
            original,
            "identity omitted {pointer}"
        );
    }
    assert_ne!(plan().identity().unwrap(), original);
    let encoded = serde_json::to_value(adapter_plan()).unwrap();
    let mut pairs: Vec<_> = encoded.as_object().unwrap().iter().collect();
    pairs.reverse();
    let reordered = format!(
        "{{{}}}",
        pairs
            .into_iter()
            .map(|(key, value)| format!("{}:{}", serde_json::to_string(key).unwrap(), value))
            .collect::<Vec<_>>()
            .join(",")
    );
    let restored: StudyPlan = serde_json::from_str(&reordered).unwrap();
    assert_eq!(restored.identity().unwrap(), original);
}
