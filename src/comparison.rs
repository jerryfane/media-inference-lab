//! Read-only, descriptive comparisons of independently retained capture evidence.
use crate::{
    capture::{self, CaptureRecord, CaptureState},
    schema::{Observation, RuntimeIdentity, TimingUnit},
    study::{ComparisonMode, Metric, PlannedSample, Role, StudyInput},
};
use anyhow::{Result, ensure};
use serde::Serialize;
use sha2::{Digest, Sha256};
use std::{
    collections::{BTreeMap, HashSet},
    io::{self, Write},
    path::Path,
    time::{Duration, Instant},
};

const DISPLAY_BYTES: usize = 512;

/// Full typed-JSON digest plus a bounded display, never a truncated identity.
#[derive(Debug, Serialize)]
pub struct Evidence {
    pub sha256: String,
    pub display: String,
    pub truncated: bool,
}

struct EvidenceWriter {
    hash: Sha256,
    preview: Vec<u8>,
    bytes: usize,
}
impl Write for EvidenceWriter {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        self.hash.update(bytes);
        let remaining = DISPLAY_BYTES.saturating_sub(self.preview.len());
        self.preview
            .extend_from_slice(&bytes[..bytes.len().min(remaining)]);
        self.bytes += bytes.len();
        Ok(bytes.len())
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}
fn evidence(value: &impl Serialize) -> Result<Evidence> {
    let mut writer = EvidenceWriter {
        hash: Sha256::new(),
        preview: Vec::with_capacity(DISPLAY_BYTES),
        bytes: 0,
    };
    serde_json::to_writer(&mut writer, value)?;
    // Remove an incomplete trailing UTF-8 codepoint rather than enlarging the preview.
    let mut end = writer.preview.len();
    while std::str::from_utf8(&writer.preview[..end]).is_err() {
        end -= 1;
    }
    writer.preview.truncate(end);
    Ok(Evidence {
        sha256: format!("{:x}", writer.hash.finalize()),
        display: String::from_utf8(writer.preview).expect("checked UTF-8"),
        truncated: writer.bytes > end,
    })
}
fn bounded(text: &str) -> String {
    if text.len() <= DISPLAY_BYTES {
        return text.to_owned();
    }
    let mut end = DISPLAY_BYTES;
    while !text.is_char_boundary(end) {
        end -= 1;
    }
    format!("{} [truncated]", &text[..end])
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum InspectionState {
    Missing,
    Unavailable,
    Invalid,
    Loaded,
}

#[derive(Debug, Serialize)]
pub struct Provenance {
    pub host: Evidence,
    pub invocation: Evidence,
    pub runtime: Option<Evidence>,
    pub runtime_identity: Option<Evidence>,
    pub model: Option<Evidence>,
    pub model_fingerprint: Option<Evidence>,
    pub device: Option<Evidence>,
    pub cache: Option<Evidence>,
    pub adapter_timings: Option<Evidence>,
    pub host_known: bool,
    pub runtime_known: bool,
    pub launch_configuration_known: bool,
    pub model_known: bool,
    pub device_known: bool,
    pub cache_known: bool,
}

#[derive(Debug, Serialize)]
pub struct ComparisonRow {
    pub slot: PlannedSample,
    pub capture: Option<Evidence>,
    pub canonical_directory: Option<Evidence>,
    pub inspection: InspectionState,
    pub state: Option<CaptureState>,
    pub reason: Option<String>,
    pub failure: Option<Evidence>,
    pub manifest_identity: Option<String>,
    pub requested_identity: Option<String>,
    pub resolved_identity: Option<String>,
    pub started_unix_ms: Option<u64>,
    pub ended_unix_ms: Option<u64>,
    pub metric_seconds: Option<f64>,
    pub metric_unavailable_reason: Option<String>,
    pub included_in_summary: bool,
    pub exclusion_reasons: Vec<String>,
    pub provenance: Option<Provenance>,
    pub issues: Vec<String>,
}

#[derive(Debug, Serialize)]
pub struct RoleSummary {
    pub role: Role,
    pub planned: usize,
    pub measured: usize,
    pub failed: usize,
    pub missing: usize,
    pub warmups: usize,
    pub excluded_measurements: usize,
    pub values_seconds: Vec<f64>,
    pub median_seconds: Option<f64>,
    pub median_unavailable_reason: Option<String>,
    pub min_seconds: Option<f64>,
    pub max_seconds: Option<f64>,
}

#[derive(Debug, Serialize)]
pub struct MedianComparison {
    pub median_ratio: Option<f64>,
    pub median_change_fraction: Option<f64>,
    pub unavailable_reason: Option<String>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ReportStatus {
    Complete,
    Inconclusive,
}

#[derive(Debug, Serialize)]
pub struct ComparisonReport {
    pub schema_version: u32,
    pub plan_identity: String,
    pub study_id: String,
    pub baseline_label: String,
    pub candidate_label: String,
    pub mode: ComparisonMode,
    pub metric: Metric,
    pub metric_boundary: String,
    pub minimum_samples: u32,
    pub inspection_budget_ms: u128,
    pub status: ReportStatus,
    pub same_work_compatible: bool,
    pub persisted_order_verified: bool,
    pub rows: Vec<ComparisonRow>,
    pub summaries: Vec<RoleSummary>,
    pub candidate_vs_baseline: MedianComparison,
    pub control_vs_baseline: MedianComparison,
    pub issues: Vec<String>,
    pub differences: Vec<String>,
    pub limitations: Vec<String>,
}
impl ComparisonReport {
    pub fn is_complete(&self) -> bool {
        matches!(self.status, ReportStatus::Complete)
    }
}

fn available<T>(observation: &Observation<T>) -> bool {
    matches!(observation, Observation::Available { .. })
}
fn runtime_known(runtime: &RuntimeIdentity) -> bool {
    available(&runtime.version)
        && matches!(&runtime.source, Observation::Available { value } if matches!(&value.dirty, Observation::Available { value: false }))
        && matches!(&runtime.executable, Observation::Available { value } if available(&value.sha256))
        && runtime
            .modules
            .iter()
            .all(|module| available(&module.sha256))
}
fn provenance(record: &CaptureRecord) -> Result<Provenance> {
    let mut result = Provenance {
        host: evidence(&record.host)?,
        invocation: evidence(&record.invocation)?,
        runtime: None,
        runtime_identity: None,
        model: None,
        model_fingerprint: None,
        device: None,
        cache: None,
        adapter_timings: None,
        host_known: record.host.logical_cpus.is_some(),
        runtime_known: false,
        // These four values are supervisor-derived protocol locations/identity, not
        // user-selected launch knobs. All other v2 invocation values are redacted.
        launch_configuration_known: record.invocation.args.is_empty()
            && record.invocation.environment.keys().all(|key| {
                matches!(
                    key.as_str(),
                    "MIL_RUN_DIR"
                        | "MIL_REQUEST_PATH"
                        | "MIL_RESULT_PATH"
                        | "MIL_WORKLOAD_IDENTITY"
                )
            }),
        model_known: false,
        device_known: false,
        cache_known: false,
    };
    if let Some(adapter) = &record.adapter_result {
        let runtime = &adapter.runtime;
        result.runtime = Some(evidence(runtime)?);
        result.runtime_identity = Some(evidence(&(
            &runtime.name,
            &runtime.version,
            &runtime.source,
            &runtime.executable,
            &runtime.modules,
            &record.invocation.executable,
            &record.invocation.executable_sha256,
        ))?);
        result.runtime_known =
            runtime_known(runtime) && record.invocation.executable_sha256.is_some();
        result.model = Some(evidence(&runtime.model)?);
        if let Observation::Available { value: model } = &runtime.model
            && let Observation::Available { value: fingerprint } = &model.fingerprint
        {
            result.model_known = true;
            result.model_fingerprint = Some(evidence(&(
                fingerprint.sha256.to_ascii_lowercase(),
                &fingerprint.method,
            ))?);
        }
        result.device = Some(evidence(&runtime.device)?);
        result.cache = Some(evidence(&runtime.cache_state)?);
        result.device_known = available(&runtime.device);
        result.cache_known = available(&runtime.cache_state);
        result.adapter_timings = Some(evidence(&adapter.timings)?);
    }
    Ok(result)
}

fn metric(record: &CaptureRecord, selector: &Metric) -> (Option<f64>, Option<String>) {
    if !record.is_success() {
        return (None, Some("capture did not complete successfully".into()));
    }
    match selector {
        Metric::HostExecution => match record.host_elapsed_ms {
            Some(value) => (Some(value as f64 / 1000.0), None),
            None => (None, Some("host execution boundary unavailable".into())),
        },
        Metric::Adapter {
            phase,
            scope,
            method,
            boundary,
        } => {
            let Some(adapter) = &record.adapter_result else {
                return (None, Some("adapter result unavailable".into()));
            };
            let mut matches = adapter.timings.iter().filter(|timing| {
                timing.phase == *phase
                    && timing.scope == *scope
                    && timing.method == *method
                    && timing.boundary == *boundary
            });
            let selected = matches.next();
            if matches.next().is_some() {
                return (None, Some("ambiguous duplicate timing selector".into()));
            }
            let Some(timing) = selected else {
                return (
                    None,
                    Some("no timing matches exact phase/scope/method/boundary".into()),
                );
            };
            match &timing.measurement {
                Observation::Unavailable { reason } => (None, Some(bounded(reason))),
                Observation::Available { value } => {
                    let seconds = value
                        / match timing.unit {
                            TimingUnit::Seconds => 1.0,
                            TimingUnit::Milliseconds => 1000.0,
                            TimingUnit::Nanoseconds => 1_000_000_000.0,
                        };
                    if seconds.is_finite() && seconds >= 0.0 && !(*value > 0.0 && seconds == 0.0) {
                        (Some(seconds), None)
                    } else {
                        (None, Some("selected timing cannot be represented as finite nonnegative seconds without underflow".into()))
                    }
                }
            }
        }
    }
}

fn summary(role: Role, rows: &[ComparisonRow]) -> RoleSummary {
    let mut summary = RoleSummary {
        role,
        planned: 0,
        measured: 0,
        failed: 0,
        missing: 0,
        warmups: 0,
        excluded_measurements: 0,
        values_seconds: Vec::new(),
        median_seconds: None,
        median_unavailable_reason: None,
        min_seconds: None,
        max_seconds: None,
    };
    for row in rows.iter().filter(|row| row.slot.role == role) {
        summary.planned += 1;
        summary.warmups += usize::from(row.slot.warmup);
        summary.failed += usize::from(
            row.state
                .is_some_and(|state| state != CaptureState::Completed),
        );
        summary.missing += usize::from(row.state.is_none());
        if row.included_in_summary {
            if let Some(value) = row.metric_seconds {
                summary.values_seconds.push(value);
            }
        } else if row.metric_seconds.is_some() {
            summary.excluded_measurements += 1;
        }
    }
    summary.measured = summary.values_seconds.len();
    let mut sorted = summary.values_seconds.clone();
    sorted.sort_by(f64::total_cmp);
    summary.min_seconds = sorted.first().copied();
    summary.max_seconds = sorted.last().copied();
    if !sorted.is_empty() {
        let mid = sorted.len() / 2;
        let median = if sorted.len() % 2 == 1 {
            sorted[mid]
        } else {
            sorted[mid - 1] + (sorted[mid] - sorted[mid - 1]) / 2.0
        };
        if median == 0.0 && sorted[mid] > 0.0 {
            summary.median_unavailable_reason =
                Some("positive median underflows finite numeric range".into());
        } else {
            summary.median_seconds = Some(median);
        }
    } else {
        summary.median_unavailable_reason = Some("no included measurements".into());
    }
    summary
}
fn median_comparison(
    numerator: &RoleSummary,
    denominator: &RoleSummary,
    suppression: Option<&str>,
) -> MedianComparison {
    let unavailable = |reason: &str| MedianComparison {
        median_ratio: None,
        median_change_fraction: None,
        unavailable_reason: Some(reason.into()),
    };
    if let Some(reason) = suppression {
        return unavailable(reason);
    }
    let Some(denominator_value) = denominator.median_seconds else {
        return unavailable(&format!(
            "{:?} median unavailable: {}",
            denominator.role,
            denominator
                .median_unavailable_reason
                .as_deref()
                .unwrap_or("not measured")
        ));
    };
    let Some(numerator_value) = numerator.median_seconds else {
        return unavailable(&format!(
            "{:?} median unavailable: {}",
            numerator.role,
            numerator
                .median_unavailable_reason
                .as_deref()
                .unwrap_or("not measured")
        ));
    };
    let (numerator, denominator) = (numerator_value, denominator_value);
    if denominator == 0.0 {
        return unavailable("baseline median is zero; ratio is undefined");
    }
    let ratio = numerator / denominator;
    let change = ratio - 1.0;
    if !ratio.is_finite() || !change.is_finite() {
        return unavailable("ratio exceeds finite numeric range");
    }
    if numerator > 0.0 && ratio == 0.0 {
        return unavailable("positive ratio underflows finite numeric range");
    }
    MedianComparison {
        median_ratio: Some(ratio),
        median_change_fraction: Some(change),
        unavailable_reason: None,
    }
}

/// Inspects one capture at a time. The deadline is cooperative between inspections,
/// not a promise to interrupt a stalled filesystem call or an ongoing inspection.
pub fn compare(
    input: &StudyInput,
    base_dir: &Path,
    inspection_budget: Duration,
) -> Result<ComparisonReport> {
    input.validate()?;
    ensure!(
        (Duration::from_secs(1)..=Duration::from_secs(120)).contains(&inspection_budget),
        "inspection budget must be 1..=120 seconds"
    );
    let start = Instant::now();
    let requested_identity = input.plan.workload.identity()?;
    let slots = input.plan.slots()?;
    let mut rows = Vec::with_capacity(slots.len());
    let mut directories = HashSet::new();
    let mut manifests = HashSet::new();
    let mut previous_end = None;
    let mut order_verified = true;
    for (slot, binding) in slots.into_iter().zip(&input.samples) {
        let mut row = ComparisonRow {
            slot,
            capture: binding.capture.as_ref().map(evidence).transpose()?,
            canonical_directory: None,
            inspection: InspectionState::Missing,
            state: None,
            reason: None,
            failure: None,
            manifest_identity: None,
            requested_identity: None,
            resolved_identity: None,
            started_unix_ms: None,
            ended_unix_ms: None,
            metric_seconds: None,
            metric_unavailable_reason: None,
            included_in_summary: false,
            exclusion_reasons: Vec::new(),
            provenance: None,
            issues: Vec::new(),
        };
        if row.slot.warmup {
            row.exclusion_reasons.push("declared warmup".into());
        }
        if start.elapsed() >= inspection_budget {
            row.inspection = InspectionState::Unavailable;
            row.reason =
                Some("total cooperative inspection budget exhausted before this slot".into());
        } else if let Some(path) = &binding.capture {
            let path = if path.is_absolute() {
                path.clone()
            } else {
                base_dir.join(path)
            };
            match std::fs::canonicalize(&path) {
                Ok(canonical) => {
                    row.canonical_directory = Some(evidence(&canonical)?);
                    if !directories.insert(canonical) {
                        row.issues.push(
                            "duplicate canonical capture directory; not an independent sample"
                                .into(),
                        );
                        row.exclusion_reasons
                            .push("duplicate capture directory".into());
                    }
                    match capture::inspect(&path) {
                        Ok(record) => {
                            row.inspection = InspectionState::Loaded;
                            row.state = Some(record.state);
                            let identity = evidence(&record)?.sha256;
                            if !manifests.insert(identity.clone()) {
                                row.issues.push(
                                    "reused manifest identity; not an independent sample".into(),
                                );
                                row.exclusion_reasons
                                    .push("reused manifest identity".into());
                            }
                            row.manifest_identity = Some(identity);
                            row.requested_identity = Some(record.workload_identity.clone());
                            if record.workload_identity != requested_identity {
                                row.issues.push(
                                    "requested workload identity differs from study plan".into(),
                                );
                                row.exclusion_reasons
                                    .push("requested workload mismatch".into());
                            }
                            row.resolved_identity = record
                                .adapter_result
                                .as_ref()
                                .map(|adapter| adapter.resolved.identity())
                                .transpose()?;
                            row.started_unix_ms = Some(record.started_unix_ms);
                            row.ended_unix_ms = record.ended_unix_ms;
                            match record.ended_unix_ms {
                                Some(end)
                                    if end >= record.started_unix_ms
                                        && previous_end.is_none_or(|previous| {
                                            record.started_unix_ms >= previous
                                        }) => {}
                                _ => {
                                    row.issues.push("persisted timestamps do not establish declared nonoverlapping order".into());
                                    order_verified = false;
                                }
                            }
                            if let Some(end) = record.ended_unix_ms {
                                previous_end = Some(
                                    previous_end.map_or(end, |previous: u64| previous.max(end)),
                                );
                            }
                            row.failure = record.failure.as_ref().map(evidence).transpose()?;
                            if !record.is_success() {
                                row.reason = Some(format!(
                                    "capture state {:?}: {}",
                                    record.state,
                                    bounded(
                                        record
                                            .failure
                                            .as_deref()
                                            .unwrap_or("unresolved running capture")
                                    )
                                ));
                            }
                            (row.metric_seconds, row.metric_unavailable_reason) =
                                metric(&record, &input.plan.metric);
                            row.provenance = Some(provenance(&record)?);
                        }
                        Err(error) => {
                            row.inspection = InspectionState::Invalid;
                            row.reason = Some(bounded(&format!(
                                "capture inspection rejected evidence: {error:#}"
                            )));
                        }
                    }
                }
                Err(error) => {
                    row.inspection = InspectionState::Unavailable;
                    row.reason = Some(bounded(&format!("capture directory unavailable: {error}")));
                }
            }
        } else {
            row.reason = binding.missing_reason.as_deref().map(bounded);
        }
        if row.state.is_none() {
            order_verified = false;
            row.metric_unavailable_reason = row.reason.clone();
        }
        if row.metric_seconds.is_none() {
            row.exclusion_reasons
                .push("selected measurement unavailable".into());
        }
        row.included_in_summary = row.exclusion_reasons.is_empty();
        rows.push(row);
    }

    let mut issues = Vec::new();
    let mut differences = Vec::new();
    let mut compatible = true;
    let reference = rows.iter().find(|row| {
        !row.slot.warmup && row.slot.role == Role::Baseline && row.provenance.is_some()
    });
    let mut role_runtime: BTreeMap<Role, &str> = BTreeMap::new();
    let mut role_invocation: BTreeMap<Role, &str> = BTreeMap::new();
    for row in &rows {
        let mut compatibility = Vec::new();
        if let Some(provenance) = &row.provenance {
            for (name, known) in [
                ("host", provenance.host_known),
                ("clean runtime identity", provenance.runtime_known),
                (
                    "launch configuration values",
                    provenance.launch_configuration_known,
                ),
                ("model-level fingerprint and method", provenance.model_known),
                ("device", provenance.device_known),
                (
                    "measured cache state",
                    row.slot.warmup || provenance.cache_known,
                ),
            ] {
                if !known {
                    compatibility.push(format!("{name} unavailable; equality is not established"));
                }
            }
            if let Some(runtime) = &provenance.runtime_identity {
                if let Some(previous) = role_runtime.get(&row.slot.role) {
                    if *previous != runtime.sha256 {
                        compatibility.push("runtime identity changed within role".into());
                    }
                } else {
                    role_runtime.insert(row.slot.role, &runtime.sha256);
                }
            }
            if let Some(previous) = role_invocation.get(&row.slot.role) {
                if *previous != provenance.invocation.sha256 {
                    compatibility.push("observed launch configuration changed within role".into());
                    differences.push(format!(
                        "slot {} {:?}: observed launch configuration changed within role",
                        row.slot.index, row.slot.role
                    ));
                }
            } else {
                role_invocation.insert(row.slot.role, &provenance.invocation.sha256);
            }
            if let Some(reference) = reference {
                let baseline = reference.provenance.as_ref().expect("selected provenance");
                if provenance.invocation.sha256 != baseline.invocation.sha256 {
                    differences.push(format!(
                        "slot {} {:?}: observed launch configuration differs from baseline",
                        row.slot.index, row.slot.role
                    ));
                    if row.slot.role != Role::Candidate {
                        compatibility.push("baseline/control launch configuration differs; control is not unchanged baseline".into());
                    }
                }
                for (name, current, expected, applicable) in [
                    (
                        "host",
                        Some(provenance.host.sha256.as_str()),
                        Some(baseline.host.sha256.as_str()),
                        true,
                    ),
                    (
                        "resolved workload",
                        row.resolved_identity.as_deref(),
                        reference.resolved_identity.as_deref(),
                        true,
                    ),
                    (
                        "model fingerprint/method",
                        provenance
                            .model_fingerprint
                            .as_ref()
                            .map(|v| v.sha256.as_str()),
                        baseline
                            .model_fingerprint
                            .as_ref()
                            .map(|v| v.sha256.as_str()),
                        true,
                    ),
                    (
                        "device",
                        provenance.device.as_ref().map(|v| v.sha256.as_str()),
                        baseline.device.as_ref().map(|v| v.sha256.as_str()),
                        true,
                    ),
                    (
                        "cache state",
                        provenance.cache.as_ref().map(|v| v.sha256.as_str()),
                        baseline.cache.as_ref().map(|v| v.sha256.as_str()),
                        !row.slot.warmup,
                    ),
                ] {
                    if !applicable {
                        continue;
                    }
                    match (current, expected) {
                        (Some(current), Some(expected)) if current == expected => {}
                        (Some(_), Some(_)) => {
                            compatibility.push(format!("{name} differs from baseline"));
                            differences.push(format!(
                                "slot {} {:?}: {name} differs from baseline",
                                row.slot.index, row.slot.role
                            ));
                        }
                        _ => compatibility.push(format!("{name} comparison unavailable")),
                    }
                }
                if let (Some(current), Some(expected)) =
                    (&provenance.runtime_identity, &baseline.runtime_identity)
                    && current.sha256 != expected.sha256
                {
                    differences.push(format!(
                        "slot {} {:?}: runtime/source identity differs from baseline",
                        row.slot.index, row.slot.role
                    ));
                    if row.slot.role != Role::Candidate {
                        compatibility.push("baseline/control runtime identity differs; control is not unchanged baseline".into());
                    }
                }
            } else {
                compatibility.push("baseline provenance unavailable".into());
            }
        } else {
            compatibility.push("capture provenance unavailable".into());
        }
        if row.metric_seconds.is_none() {
            compatibility.push("exact selected timing unavailable".into());
        }
        if !row.issues.is_empty() {
            compatible = false;
        }
        for issue in &row.issues {
            issues.push(format!("slot {}: {issue}", row.slot.index));
        }
        if row.state != Some(CaptureState::Completed) {
            issues.push(format!(
                "slot {}: {}",
                row.slot.index,
                row.reason.as_deref().unwrap_or("capture unavailable")
            ));
        }
        if !compatibility.is_empty() {
            compatible = false;
        }
        for issue in compatibility {
            issues.push(format!("slot {}: {issue}", row.slot.index));
        }
    }
    if !order_verified {
        issues.push(
            "persisted order is unverified or invalid; declaration alone is not observed order"
                .into(),
        );
    }
    let summaries: Vec<_> = [Role::Baseline, Role::Candidate, Role::Control]
        .into_iter()
        .map(|role| summary(role, &rows))
        .collect();
    for summary in &summaries {
        if let Some(reason) = &summary.median_unavailable_reason {
            issues.push(format!("{:?} median unavailable: {reason}", summary.role));
        }
    }
    let sufficient = summaries
        .iter()
        .all(|summary| summary.measured >= input.plan.minimum_samples as usize);
    if !sufficient {
        issues.push("one or more roles has fewer independent measured non-warmup samples than minimum_samples".into());
    }
    let suppression =
        if input.plan.mode == ComparisonMode::SameWork && (!compatible || !order_verified) {
            Some("same-work comparability/order is not established; ratios suppressed")
        } else {
            None
        };
    let candidate_vs_baseline = median_comparison(&summaries[1], &summaries[0], suppression);
    let control_vs_baseline = median_comparison(&summaries[2], &summaries[0], suppression);
    let status = if issues.is_empty() && sufficient {
        ReportStatus::Complete
    } else {
        ReportStatus::Inconclusive
    };
    Ok(ComparisonReport {
        schema_version: 1, plan_identity: input.plan.identity()?, study_id: input.plan.id.clone(),
        baseline_label: input.plan.baseline_label.clone(), candidate_label: input.plan.candidate_label.clone(),
        mode: input.plan.mode, metric: input.plan.metric.clone(), minimum_samples: input.plan.minimum_samples,
        metric_boundary: match &input.plan.metric {
            Metric::HostExecution => "host monotonic spawn-to-leader-exit/stop-decision; not inference time".into(),
            Metric::Adapter { boundary, .. } => boundary.clone(),
        },
        inspection_budget_ms: inspection_budget.as_millis(), status, same_work_compatible: compatible,
        persisted_order_verified: order_verified, rows, summaries, candidate_vs_baseline, control_vs_baseline, issues, differences,
        limitations: vec![
            "Descriptive finite sample statistics only; no significance, confidence, causality, inference-speedup, or perceptual-quality verdict.".into(),
            "Warmups are excluded only by declared slot flag. Counts cover every slot; values contain only independent, requested-workload, available non-warmup measurements in declared order. Failures remain visible.".into(),
            "Hashes identify full typed serialized evidence, not signed provenance. Copies with altered metadata cannot be proven independent. Matching observed host fields do not prove physical machine identity.".into(),
            "Unavailable metadata never proves equality; matching partial model-file hashes do not establish model identity. Candidate runtime/source differences are declared variants, not controlled causal evidence.".into(),
            "Unchanged runtime identity requires recorded clean source and available executable/module hashes; a dirty revision is not a fingerprint of its working tree.".into(),
            "Launch configuration is checked within every role and against baseline/control. Equal redacted user arguments/environment do not prove equal values; they leave compatibility unknown. Only the four supervisor-owned MIL protocol variables are exempt, with workload identity checked separately.".into(),
            "Cache compatibility uses measured baseline samples, not warmup cache state. Warmup cache observations remain in rows but do not redefine the measured cache boundary.".into(),
            "Inspection is streaming with existing per-capture read/verification bounds. The total budget is checked between slots; a capture inspection or filesystem stall can exceed it and is not forcibly cancelled.".into(),
            "Persisted wall-clock timestamps are checked without reordering; they are not an independent clock or authenticity guarantee.".into(),
            "Offline bindings cannot prove plan predeclaration or detect unlisted extra captures. Listed chronology does not establish execution authorization.".into(),
        ],
    })
}
