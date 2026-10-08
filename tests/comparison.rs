#[path = "support/capture_fixture.rs"]
mod capture_fixture;
use capture_fixture::{persist, record};
use media_inference_lab::{
    comparison::{ComparisonReport, compare},
    schema::TimingScope,
    study::{ComparisonMode, Metric, Role, SampleBinding, StudyInput, StudyPlan},
};
use serde_json::{Value, json};
use std::{fs, time::Duration};
use tempfile::TempDir;

fn plan(warmups: u32) -> StudyPlan {
    StudyPlan {
        schema_version: 1,
        id: "generated-offline-comparison".into(),
        workload: serde_json::from_str(include_str!("../examples/image-workload.json")).unwrap(),
        mode: ComparisonMode::SameWork,
        metric: Metric::Adapter {
            phase: "synthetic".into(),
            scope: TimingScope::Host,
            method: "generated fixture".into(),
            boundary: "synthetic start to synthetic end".into(),
        },
        repetitions: 3,
        warmups,
        minimum_samples: 3,
        baseline_label: "synthetic baseline".into(),
        candidate_label: "synthetic candidate".into(),
    }
}

struct Fixture {
    root: TempDir,
    input: StudyInput,
}
impl Fixture {
    fn new(warmups: u32, values: impl Fn(Role, u32, bool) -> f64) -> Self {
        Self::with_repetitions(warmups, 3, values)
    }

    fn with_repetitions(
        warmups: u32,
        repetitions: u32,
        values: impl Fn(Role, u32, bool) -> f64,
    ) -> Self {
        let root = tempfile::tempdir_in(fs::canonicalize(std::env::temp_dir()).unwrap()).unwrap();
        let mut plan = plan(warmups);
        plan.repetitions = repetitions;
        let samples = plan
            .slots()
            .unwrap()
            .into_iter()
            .map(|slot| {
                let relative = format!("capture-{}", slot.index);
                let record = record(
                    &plan.workload,
                    slot.index,
                    values(slot.role, slot.repetition, slot.warmup),
                );
                persist(&root.path().join(&relative), &record);
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
        }
    }
    fn change(&self, index: usize, change: impl FnOnce(&mut Value)) {
        let path = self
            .root
            .path()
            .join(self.input.samples[index].capture.as_ref().unwrap());
        let mut value =
            serde_json::from_slice(&fs::read(path.join("manifest.json")).unwrap()).unwrap();
        change(&mut value);
        persist(&path, &value);
    }
    fn report(&self) -> ComparisonReport {
        compare(&self.input, self.root.path(), Duration::from_secs(10), None).unwrap()
    }
}

#[test]
fn slower_candidate_and_control_drift_are_descriptive_median_ratios() {
    let fixture = Fixture::new(0, |role, repetition, _| match role {
        Role::Baseline => [1.0, 2.0, 3.0][repetition as usize],
        Role::Candidate => [3.0, 4.0, 5.0][repetition as usize],
        Role::Control => [1.0, 2.0, 4.0][repetition as usize],
    });
    let report = fixture.report();
    assert!(report.is_complete(), "{:?}", report.issues);
    assert_eq!(report.candidate_vs_baseline.median_ratio, Some(2.0));
    assert_eq!(
        report.candidate_vs_baseline.median_change_fraction,
        Some(1.0)
    );
    assert_eq!(report.control_vs_baseline.median_ratio, Some(1.0));
    assert_eq!(report.summaries[0].values_seconds, vec![1.0, 2.0, 3.0]);
    assert_eq!(report.summaries[2].max_seconds, Some(4.0));
    assert!(report.persisted_order_verified);
}

#[test]
fn noisy_unchanged_candidate_and_declared_warmups_are_not_hidden() {
    let fixture = Fixture::new(1, |role, repetition, warmup| {
        if warmup {
            return 900.0;
        }
        match role {
            Role::Candidate => [3.0, 1.0, 2.0][repetition as usize],
            _ => [1.0, 2.0, 3.0][repetition as usize],
        }
    });
    let report = fixture.report();
    assert!(report.is_complete(), "{:?}", report.issues);
    assert_eq!(report.candidate_vs_baseline.median_ratio, Some(1.0));
    assert_eq!(report.rows.len(), 12);
    for row in &report.rows[..3] {
        assert!(row.slot.warmup);
        assert_eq!(row.metric_seconds, Some(900.0));
        assert!(!row.included_in_summary);
    }
    for summary in &report.summaries {
        assert_eq!(
            (summary.planned, summary.measured, summary.warmups),
            (4, 3, 1)
        );
        assert_eq!(summary.excluded_measurements, 1);
    }
}

#[test]
fn minimum_samples_applies_to_each_role_after_warmup_exclusion() {
    let mut fixture = Fixture::new(1, |_, _, _| 1.0);
    fixture.input.plan.minimum_samples = 4;
    let report = fixture.report();
    assert!(!report.is_complete());
    assert!(
        report
            .issues
            .iter()
            .any(|issue| issue.contains("minimum_samples"))
    );
    assert_eq!(report.summaries[0].measured, 3);
}

#[test]
fn failed_cancelled_missing_invalid_and_running_rows_are_retained() {
    let mut fixture = Fixture::new(0, |_, _, _| 1.0);
    for (index, state) in [(0, "failed"), (1, "cancelled")] {
        fixture.change(index, |record| {
            record["state"] = json!(state);
            record["failure"] = json!("generated terminal failure");
            record["adapter_result"] = Value::Null;
        });
    }
    fixture.input.samples[2].capture = None;
    fixture.input.samples[2].missing_reason = Some("not captured deliberately".into());
    fixture.change(3, |record| record["record_version"] = json!(999));
    fixture.change(4, |record| {
        record["state"] = json!("running");
        for field in [
            "ended_unix_ms",
            "host_elapsed_ms",
            "artifact_inspection_ms",
            "cleanup_elapsed_ms",
            "exit",
            "cleanup",
            "adapter_result",
        ] {
            record[field] = Value::Null;
        }
    });
    fixture.input.samples[5].capture = Some("absent-capture".into());
    let report = fixture.report();
    assert!(!report.is_complete());
    assert_eq!(report.rows.len(), 9);
    assert!(
        report.rows[..6]
            .iter()
            .all(|row| row.metric_seconds.is_none())
    );
    assert!(report.rows[..6].iter().all(|row| row.reason.is_some()));
    assert!(
        report.rows[3]
            .reason
            .as_ref()
            .unwrap()
            .contains("unsupported")
    );
    assert_eq!(report.summaries[0].failed, 1);
    assert_eq!(report.summaries[1].failed, 2);
    assert_eq!(report.summaries[2].missing, 2);
    assert!(!report.persisted_order_verified);
    assert_eq!(report.candidate_vs_baseline.median_ratio, None);
}

#[test]
fn directory_aliases_and_copied_manifests_cannot_create_replicates() {
    let mut fixture = Fixture::new(0, |_, _, _| 1.0);
    fixture.input.samples[3].capture = fixture.input.samples[0].capture.clone();
    let original: Value = serde_json::from_slice(
        &fs::read(fixture.root.path().join("capture-0/manifest.json")).unwrap(),
    )
    .unwrap();
    persist(&fixture.root.path().join("capture-6"), &original);
    let report = fixture.report();
    assert!(!report.is_complete());
    assert_eq!(report.summaries[0].measured, 1);
    assert_eq!(report.rows[3].metric_seconds, Some(1.0));
    assert!(!report.rows[3].included_in_summary);
    assert!(
        report.rows[3]
            .issues
            .iter()
            .any(|issue| issue.contains("canonical"))
    );
    assert!(
        report.rows[6]
            .issues
            .iter()
            .any(|issue| issue.contains("manifest identity"))
    );
}

#[test]
fn workload_mismatch_is_not_included_as_the_requested_work() {
    let fixture = Fixture::new(0, |_, _, _| 1.0);
    let mut other = fixture.input.plan.workload.clone();
    other.id = "different-request".into();
    persist(
        &fixture.root.path().join("capture-1"),
        &record(&other, 1, 100.0),
    );
    let report = fixture.report();
    assert!(!report.is_complete());
    assert_eq!(report.rows[1].metric_seconds, Some(100.0));
    assert!(!report.rows[1].included_in_summary);
    assert_eq!(report.summaries[1].measured, 2);
    assert!(
        report.rows[1]
            .issues
            .iter()
            .any(|issue| issue.contains("requested workload"))
    );
}

#[test]
fn cache_mismatch_and_timing_boundary_mismatch_prevent_same_work_ratios() {
    let fixture = Fixture::new(0, |_, _, _| 1.0);
    fixture.change(1, |record| {
        record["adapter_result"]["runtime"]["cache_state"]["value"] = json!("synthetic warm")
    });
    fixture.change(4, |record| {
        record["adapter_result"]["timings"][0]["boundary"] = json!("different timing boundary")
    });
    let report = fixture.report();
    assert!(!report.same_work_compatible);
    assert_eq!(report.candidate_vs_baseline.median_ratio, None);
    assert!(
        report
            .issues
            .iter()
            .any(|issue| issue.contains("cache state differs"))
    );
    assert!(
        report.rows[4]
            .metric_unavailable_reason
            .as_ref()
            .unwrap()
            .contains("phase/scope/method/boundary")
    );
}

#[test]
fn unavailable_model_device_and_partial_file_hashes_never_establish_equality() {
    let fixture = Fixture::new(0, |_, _, _| 1.0);
    for index in 0..9 {
        fixture.change(index, |record| {
            record["adapter_result"]["runtime"]["device"] = json!({"status":"unavailable", "reason":"same unknown device"});
            record["adapter_result"]["runtime"]["model"]["value"]["fingerprint"] = json!({"status":"unavailable", "reason":"only partial file identity exists"});
            record["adapter_result"]["runtime"]["model"]["value"]["files"] = json!([{"path":"/synthetic/partial-weight", "sha256":{"status":"available", "value":"b".repeat(64)}}]);
        });
    }
    let report = fixture.report();
    assert!(!report.is_complete());
    assert!(!report.same_work_compatible);
    assert_eq!(report.summaries[0].median_seconds, Some(1.0));
    assert_eq!(report.candidate_vs_baseline.median_ratio, None);
    assert!(
        report
            .issues
            .iter()
            .any(|issue| issue.contains("model-level fingerprint"))
    );
    assert!(
        report
            .issues
            .iter()
            .any(|issue| issue.contains("device unavailable"))
    );
}

#[test]
fn control_mutation_is_inconclusive_but_named_candidate_runtime_change_is_disclosed() {
    let fixture = Fixture::new(
        0,
        |role, _, _| if role == Role::Candidate { 2.0 } else { 1.0 },
    );
    for index in [1, 4, 7] {
        fixture.change(index, |record| {
            record["adapter_result"]["runtime"]["version"]["value"] = json!("candidate-v2")
        });
    }
    let report = fixture.report();
    assert!(report.is_complete(), "{:?}", report.issues);
    assert_eq!(report.candidate_vs_baseline.median_ratio, Some(2.0));
    assert!(
        report
            .differences
            .iter()
            .any(|difference| difference.contains("runtime/source"))
    );
    fixture.change(2, |record| {
        record["adapter_result"]["runtime"]["version"]["value"] = json!("mutated-control")
    });
    let report = fixture.report();
    assert!(!report.is_complete());
    assert!(
        report
            .issues
            .iter()
            .any(|issue| issue.contains("control runtime identity"))
    );
    assert!(
        report
            .issues
            .iter()
            .any(|issue| issue.contains("within role"))
    );
}

#[test]
fn descriptive_mode_discloses_cross_device_ratios_without_claiming_same_work() {
    let mut fixture = Fixture::new(
        0,
        |role, _, _| if role == Role::Candidate { 2.0 } else { 1.0 },
    );
    fixture.input.plan.mode = ComparisonMode::Descriptive;
    for index in [1, 4, 7] {
        fixture.change(index, |record| {
            record["adapter_result"]["runtime"]["device"]["value"] =
                json!("different synthetic CPU")
        });
    }
    let report = fixture.report();
    assert!(!report.is_complete());
    assert!(!report.same_work_compatible);
    assert_eq!(report.candidate_vs_baseline.median_ratio, Some(2.0));
    assert!(
        report
            .differences
            .iter()
            .any(|difference| difference.contains("device differs"))
    );
}

#[test]
fn zero_measurements_are_kept_and_zero_denominator_is_explicit() {
    let fixture = Fixture::new(
        0,
        |role, _, _| if role == Role::Candidate { 1.0 } else { 0.0 },
    );
    let report = fixture.report();
    assert!(report.is_complete(), "{:?}", report.issues);
    assert_eq!(report.summaries[0].values_seconds, vec![0.0, 0.0, 0.0]);
    assert_eq!(report.candidate_vs_baseline.median_ratio, None);
    assert!(
        report
            .candidate_vs_baseline
            .unavailable_reason
            .unwrap()
            .contains("zero")
    );
    serde_json::to_string(&report.rows).unwrap();
}

#[test]
fn mixed_units_normalize_but_ambiguous_exact_selectors_are_unavailable() {
    let fixture = Fixture::new(0, |_, _, _| 2.0);
    fixture.change(1, |record| {
        record["adapter_result"]["timings"][0]["unit"] = json!("milliseconds");
        record["adapter_result"]["timings"][0]["measurement"]["value"] = json!(2000.0);
    });
    fixture.change(4, |record| {
        record["adapter_result"]["timings"][0]["unit"] = json!("nanoseconds");
        record["adapter_result"]["timings"][0]["measurement"]["value"] = json!(2_000_000_000.0);
    });
    assert_eq!(
        fixture.report().summaries[1].values_seconds,
        vec![2.0, 2.0, 2.0]
    );
    fixture.change(7, |record| {
        let timing = record["adapter_result"]["timings"][0].clone();
        record["adapter_result"]["timings"]
            .as_array_mut()
            .unwrap()
            .push(timing);
    });
    let report = fixture.report();
    assert!(!report.is_complete());
    assert!(
        report.rows[7]
            .metric_unavailable_reason
            .as_ref()
            .unwrap()
            .contains("ambiguous")
    );
}

#[test]
fn reversed_and_overlapping_persisted_order_is_not_repaired_by_sorting() {
    let fixture = Fixture::new(0, |_, _, _| 1.0);
    fixture.change(1, |record| {
        record["started_unix_ms"] = json!(100500);
        record["ended_unix_ms"] = json!(100600);
    });
    let report = fixture.report();
    assert!(!report.persisted_order_verified);
    assert!(!report.is_complete());
    assert_eq!(report.rows[1].started_unix_ms, Some(100500));
    assert_eq!(report.rows[1].slot.index, 1);
    assert_eq!(report.candidate_vs_baseline.median_ratio, None);
}

#[test]
fn host_execution_uses_saved_spawn_to_exit_boundary_not_adapter_timing() {
    let mut fixture = Fixture::new(0, |_, _, _| 999.0);
    fixture.input.plan.metric = Metric::HostExecution;
    fixture.change(1, |record| record["host_elapsed_ms"] = json!(2500));
    let report = fixture.report();
    assert_eq!(report.rows[1].metric_seconds, Some(2.5));
    assert_eq!(report.summaries[1].values_seconds, vec![2.5, 1.0, 1.0]);
    assert!(report.metric_boundary.contains("not inference time"));
}

#[test]
fn metadata_preview_is_bounded_but_full_identity_detects_hidden_differences() {
    let fixture = Fixture::new(0, |_, _, _| 1.0);
    for index in 0..9 {
        fixture.change(index, |record| {
            record["adapter_result"]["runtime"]["device"]["value"] = json!("界".repeat(2048))
        });
    }
    fixture.change(1, |record| {
        record["adapter_result"]["runtime"]["device"]["value"] =
            json!(format!("{}suffix", "界".repeat(2048)))
    });
    let report = fixture.report();
    let first = report.rows[0]
        .provenance
        .as_ref()
        .unwrap()
        .device
        .as_ref()
        .unwrap();
    let second = report.rows[1]
        .provenance
        .as_ref()
        .unwrap()
        .device
        .as_ref()
        .unwrap();
    assert!(first.truncated && second.truncated);
    assert!(first.display.len() <= 512);
    assert_eq!(first.display, second.display);
    assert_ne!(first.sha256, second.sha256);
    assert!(!report.same_work_compatible);
}

#[test]
fn unsupported_budget_and_structurally_omitted_slots_are_errors() {
    let mut fixture = Fixture::new(0, |_, _, _| 1.0);
    assert!(compare(&fixture.input, fixture.root.path(), Duration::ZERO, None).is_err());
    assert!(
        compare(
            &fixture.input,
            fixture.root.path(),
            Duration::from_secs(121),
            None
        )
        .is_err()
    );
    fixture.input.samples.pop();
    assert!(
        compare(
            &fixture.input,
            fixture.root.path(),
            Duration::from_secs(1),
            None
        )
        .is_err()
    );
}

#[test]
fn model_fingerprint_method_and_host_changes_are_not_same_work() {
    let fixture = Fixture::new(0, |_, _, _| 1.0);
    fixture.change(1, |record| {
        record["adapter_result"]["runtime"]["model"]["value"]["fingerprint"]["value"]["method"] =
            json!("different synthetic model fingerprint derivation")
    });
    fixture.change(4, |record| {
        record["host"]["kernel_release"] = json!("different synthetic host")
    });
    let report = fixture.report();
    assert!(!report.same_work_compatible);
    assert_eq!(report.candidate_vs_baseline.median_ratio, None);
    assert!(
        report
            .issues
            .iter()
            .any(|issue| issue.contains("model fingerprint/method differs"))
    );
    assert!(
        report
            .issues
            .iter()
            .any(|issue| issue.contains("host differs"))
    );
}

#[test]
fn finite_extreme_samples_do_not_produce_infinite_ratios_or_overflowed_medians() {
    let mut fixture = Fixture::new(0, |role, _, _| {
        if role == Role::Candidate {
            1.0e308
        } else {
            1.0e-308
        }
    });
    fixture.input.plan.mode = ComparisonMode::Descriptive;
    let report = fixture.report();
    assert_eq!(report.summaries[1].median_seconds, Some(1.0e308));
    assert_eq!(report.candidate_vs_baseline.median_ratio, None);
    assert!(
        report
            .candidate_vs_baseline
            .unavailable_reason
            .as_ref()
            .unwrap()
            .contains("finite")
    );
    let serialized = serde_json::to_value(&report).unwrap();
    assert_eq!(
        serialized["candidate_vs_baseline"]["median_ratio"],
        Value::Null
    );
}

#[test]
fn unavailable_selected_timing_and_failed_warmup_remain_inconclusive() {
    let fixture = Fixture::new(1, |_, _, _| 1.0);
    fixture.change(0, |record| {
        record["state"] = json!("failed");
        record["failure"] = json!("synthetic warmup failed");
        record["adapter_result"] = Value::Null;
    });
    fixture.change(4, |record| {
        record["adapter_result"]["timings"][0]["measurement"] =
            json!({"status":"unavailable", "reason":"synthetic timer unavailable"})
    });
    let report = fixture.report();
    assert!(!report.is_complete());
    assert!(report.rows[0].slot.warmup);
    assert!(report.rows[0].failure.is_some());
    assert_eq!(report.summaries[0].measured, 3);
    assert_eq!(report.summaries[0].failed, 1);
    assert_eq!(report.summaries[1].measured, 2);
}

#[test]
fn integration_warmup_cache_transition_does_not_redefine_measured_cache_boundary() {
    let fixture = Fixture::new(1, |_, _, warmup| if warmup { 9.0 } else { 1.0 });
    for index in 3..12 {
        fixture.change(index, |record| {
            record["adapter_result"]["runtime"]["cache_state"]["value"] = json!("synthetic warm")
        });
    }
    let report = fixture.report();
    assert!(report.is_complete(), "{:?}", report.issues);
    assert!(report.same_work_compatible);
    assert_eq!(report.summaries[0].values_seconds, vec![1.0; 3]);
    assert_eq!(report.control_vs_baseline.median_ratio, Some(1.0));
}

#[test]
fn integration_dirty_source_revision_is_not_an_unchanged_runtime_fingerprint() {
    let fixture = Fixture::new(0, |_, _, _| 1.0);
    for index in 0..9 {
        fixture.change(index, |record| {
            record["adapter_result"]["runtime"]["source"]["value"]["dirty"]["value"] = json!(true)
        });
    }
    let report = fixture.report();
    assert!(!report.is_complete());
    assert!(!report.same_work_compatible);
    assert!(report.candidate_vs_baseline.median_ratio.is_none());
    assert!(
        report
            .rows
            .iter()
            .all(|row| !row.provenance.as_ref().unwrap().runtime_known)
    );
}

#[test]
fn integration_positive_ratio_underflow_does_not_become_a_zero_measurement() {
    let fixture = Fixture::new(0, |role, _, _| {
        if role == Role::Candidate {
            1.0e-308
        } else {
            1.0e308
        }
    });
    let report = fixture.report();
    assert_eq!(report.summaries[1].median_seconds, Some(1.0e-308));
    assert!(report.candidate_vs_baseline.median_ratio.is_none());
    assert!(
        report
            .candidate_vs_baseline
            .median_change_fraction
            .is_none()
    );
    assert!(report.candidate_vs_baseline.unavailable_reason.is_some());
}

#[test]
fn review_launch_changes_gate_controls_and_within_role_stability() {
    // Control environment, baseline argument count, and candidate environment changes.
    for (index, argument) in [(2, false), (3, true), (4, false)] {
        let fixture = Fixture::new(0, |_, _, _| 1.0);
        fixture.change(index, |record| {
            if argument {
                record["invocation"]["args"] = json!(["[redacted]"]);
            } else {
                record["invocation"]["environment"]["OMP_NUM_THREADS"] = json!("[redacted]");
            }
        });
        let report = fixture.report();
        assert!(!report.is_complete());
        assert!(!report.same_work_compatible);
        assert!(report.candidate_vs_baseline.median_ratio.is_none());
        assert!(report.control_vs_baseline.median_ratio.is_none());
        let changed = report.rows[index].provenance.as_ref().unwrap();
        assert!(!changed.launch_configuration_known);
        assert_ne!(
            changed.invocation.sha256,
            report.rows[0]
                .provenance
                .as_ref()
                .unwrap()
                .invocation
                .sha256
        );
        assert!(
            report
                .differences
                .iter()
                .any(|difference| difference.contains(&format!("slot {index} "))
                    && difference.contains("launch configuration"))
        );
        assert!(
            report
                .issues
                .iter()
                .any(|issue| issue.contains("launch configuration"))
        );
        assert_eq!(
            report
                .summaries
                .iter()
                .map(|s| s.measured)
                .collect::<Vec<_>>(),
            vec![3, 3, 3]
        );
    }
}

#[test]
fn review_equal_redactions_do_not_prove_equal_launch_values() {
    for key in [None, Some("OMP_NUM_THREADS"), Some("MIL_CUSTOM")] {
        let mut fixture = Fixture::new(0, |_, _, _| 1.0);
        for index in 0..9 {
            fixture.change(index, |record| {
                if let Some(key) = key {
                    record["invocation"]["environment"][key] = json!("[redacted]");
                } else {
                    record["invocation"]["args"] = json!(["[redacted]"]);
                }
            });
        }
        let report = fixture.report();
        assert!(!report.is_complete());
        assert!(!report.same_work_compatible);
        assert!(report.candidate_vs_baseline.median_ratio.is_none());
        let first = &report.rows[0]
            .provenance
            .as_ref()
            .unwrap()
            .invocation
            .sha256;
        assert!(report.rows.iter().all(|row| {
            let provenance = row.provenance.as_ref().unwrap();
            !provenance.launch_configuration_known && &provenance.invocation.sha256 == first
        }));
        fixture.input.plan.mode = ComparisonMode::Descriptive;
        let descriptive = fixture.report();
        assert!(!descriptive.is_complete());
        assert!(!descriptive.same_work_compatible);
        assert_eq!(descriptive.candidate_vs_baseline.median_ratio, Some(1.0));
    }
}

#[test]
fn review_protocol_fields_and_known_candidate_launch_variant_remain_comparable() {
    let fixture = Fixture::new(0, |_, _, _| 1.0);
    for index in [1, 4, 7] {
        fixture.change(index, |record| {
            record["invocation"]["executable"] = json!("/synthetic/candidate-launcher");
            record["invocation"]["executable_sha256"] = json!("c".repeat(64));
        });
    }
    let report = fixture.report();
    assert!(report.is_complete(), "{:?}", report.issues);
    assert!(report.same_work_compatible);
    assert!(
        report
            .rows
            .iter()
            .all(|row| row.provenance.as_ref().unwrap().launch_configuration_known)
    );
    assert_eq!(report.candidate_vs_baseline.median_ratio, Some(1.0));
    assert_eq!(report.control_vs_baseline.median_ratio, Some(1.0));
    assert!(
        report
            .differences
            .iter()
            .any(|difference| difference.contains("slot 1 ")
                && difference.contains("launch configuration"))
    );
}

#[test]
fn review_positive_median_underflow_preserves_values_and_unavailability() {
    let smallest = f64::from_bits(1);
    let fixture = Fixture::with_repetitions(0, 4, |role, repetition, _| {
        if role == Role::Candidate {
            [0.0, 0.0, smallest, smallest][repetition as usize]
        } else {
            1.0
        }
    });
    let report = fixture.report();
    assert!(!report.is_complete());
    assert!(report.same_work_compatible);
    let candidate = &report.summaries[1];
    assert_eq!(candidate.values_seconds, vec![0.0, 0.0, smallest, smallest]);
    assert_eq!(candidate.measured, 4);
    assert_eq!(candidate.min_seconds, Some(0.0));
    assert_eq!(candidate.max_seconds, Some(smallest));
    assert!(candidate.median_seconds.is_none());
    assert!(candidate.median_unavailable_reason.is_some());
    assert!(report.candidate_vs_baseline.median_ratio.is_none());
    assert!(
        report
            .candidate_vs_baseline
            .median_change_fraction
            .is_none()
    );
    assert!(report.candidate_vs_baseline.unavailable_reason.is_some());
    assert_eq!(report.control_vs_baseline.median_ratio, Some(1.0));
}

#[test]
fn review_genuine_zero_and_representable_subnormal_medians_remain_available() {
    let smallest = f64::from_bits(1);
    for (values, expected) in [
        ([0.0; 4], 0.0),
        ([0.0, 0.0, 0.0, smallest], 0.0),
        ([0.0, 0.0, smallest * 2.0, smallest * 2.0], smallest),
        ([smallest; 4], smallest),
    ] {
        let fixture = Fixture::with_repetitions(0, 4, |role, repetition, _| {
            if role == Role::Candidate {
                values[repetition as usize]
            } else {
                1.0
            }
        });
        let report = fixture.report();
        assert!(report.is_complete(), "{:?}", report.issues);
        assert_eq!(report.summaries[1].values_seconds, values);
        assert_eq!(report.summaries[1].median_seconds, Some(expected));
        assert!(report.summaries[1].median_unavailable_reason.is_none());
        assert_eq!(report.candidate_vs_baseline.median_ratio, Some(expected));
        assert_eq!(
            report.candidate_vs_baseline.median_change_fraction,
            Some(expected - 1.0)
        );
        assert!(report.candidate_vs_baseline.unavailable_reason.is_none());
    }
}

#[test]
fn review_baseline_median_underflow_suppresses_both_comparisons() {
    let smallest = f64::from_bits(1);
    let fixture = Fixture::with_repetitions(0, 4, |role, repetition, _| {
        if role == Role::Baseline {
            [0.0, 0.0, smallest, smallest][repetition as usize]
        } else {
            1.0
        }
    });
    let report = fixture.report();
    assert!(!report.is_complete());
    assert!(report.summaries[0].median_seconds.is_none());
    assert!(report.summaries[0].median_unavailable_reason.is_some());
    for comparison in [&report.candidate_vs_baseline, &report.control_vs_baseline] {
        assert!(comparison.median_ratio.is_none());
        assert!(comparison.median_change_fraction.is_none());
        assert!(comparison.unavailable_reason.is_some());
    }
}
