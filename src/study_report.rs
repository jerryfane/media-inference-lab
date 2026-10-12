//! Readable, descriptive view of a saved comparison and its archived capture metadata.
//! The comparison owns all inclusion, compatibility and statistical decisions.
use std::io::Write;

use anyhow::{Context, Result};
use serde::Serialize;

use crate::{
    capture::CaptureState,
    capture_archive::CaptureArchive,
    comparison::{
        ComparisonReport, ComparisonRow, Evidence, InspectionState, MedianComparison, RoleSummary,
    },
    markdown::literal,
    study::{ComparisonMode, Role, StudyInput},
};

fn json(output: &mut impl Write, value: &impl Serialize) -> Result<()> {
    literal(output, &serde_json::to_string_pretty(value)?)?;
    Ok(())
}

fn strings(output: &mut impl Write, values: &[String]) -> Result<()> {
    if values.is_empty() {
        writeln!(output, "None recorded.\n")?;
    } else {
        for (index, value) in values.iter().enumerate() {
            writeln!(output, "Record {}:\n", index + 1)?;
            literal(output, value)?;
        }
    }
    Ok(())
}

fn role_name(role: Role) -> &'static str {
    match role {
        Role::Baseline => "Baseline",
        Role::Candidate => "Candidate",
        Role::Control => "Unchanged-baseline control",
    }
}

fn inspection_name(inspection: &InspectionState) -> &'static str {
    match inspection {
        InspectionState::Missing => "MISSING",
        InspectionState::Unavailable => "UNAVAILABLE",
        InspectionState::Invalid => "INVALID",
        InspectionState::Loaded => "LOADED",
    }
}

fn state_name(state: Option<CaptureState>) -> &'static str {
    match state {
        None => "UNAVAILABLE",
        Some(CaptureState::Running) => "RUNNING",
        Some(CaptureState::Completed) => "COMPLETED",
        Some(CaptureState::Failed) => "FAILED",
        Some(CaptureState::TimedOut) => "TIMED OUT",
        Some(CaptureState::Cancelled) => "CANCELLED",
        Some(CaptureState::Incomplete) => "INCOMPLETE",
    }
}

fn number(output: &mut impl Write, value: Option<f64>) -> Result<()> {
    match value {
        Some(value) => write!(output, "{value}")?,
        None => write!(output, "UNAVAILABLE")?,
    }
    Ok(())
}

fn measurement(
    output: &mut impl Write,
    label: &str,
    value: Option<f64>,
    reason: Option<&str>,
) -> Result<()> {
    // Labels are renderer-owned, never caller-supplied field values.
    write!(output, "{label}: ")?;
    number(output, value)?;
    writeln!(output, "\n")?;
    if let Some(reason) = reason {
        literal(output, reason)?;
    } else if value.is_none() {
        writeln!(
            output,
            "No availability reason was supplied by the comparison report.\n"
        )?;
    }
    Ok(())
}

fn role_summary(output: &mut impl Write, summary: &RoleSummary) -> Result<()> {
    writeln!(output, "### {}\n", role_name(summary.role))?;
    writeln!(output, "| Count | Slots / samples |\n| --- | ---: |")?;
    for (label, count) in [
        ("Planned slots", summary.planned),
        ("Included measured samples", summary.measured),
        ("Failed / non-completed captures", summary.failed),
        ("Missing capture state", summary.missing),
        ("Declared warmup slots", summary.warmups),
        (
            "Excluded available measurements",
            summary.excluded_measurements,
        ),
    ] {
        writeln!(output, "| {label} | {count} |")?;
    }
    writeln!(
        output,
        "\nEvery included sample value, in declared slot order (seconds):\n"
    )?;
    json(output, &summary.values_seconds)?;
    measurement(
        output,
        "Median (seconds)",
        summary.median_seconds,
        summary.median_unavailable_reason.as_deref(),
    )?;
    measurement(
        output,
        "Minimum (seconds)",
        summary.min_seconds,
        summary
            .min_seconds
            .is_none()
            .then_some("No minimum is available in the comparison report."),
    )?;
    measurement(
        output,
        "Maximum (seconds)",
        summary.max_seconds,
        summary
            .max_seconds
            .is_none()
            .then_some("No maximum is available in the comparison report."),
    )
}

fn median_operand(
    output: &mut impl Write,
    label: &str,
    summary: Option<&RoleSummary>,
) -> Result<()> {
    if let Some(summary) = summary {
        writeln!(
            output,
            "{label}: {}; {} included samples / {} planned slots.\n",
            role_name(summary.role),
            summary.measured,
            summary.planned
        )?;
        measurement(
            output,
            "Operand median (seconds)",
            summary.median_seconds,
            summary.median_unavailable_reason.as_deref(),
        )?;
    } else {
        writeln!(
            output,
            "{label}: UNAVAILABLE; role summary absent from comparison report.\n"
        )?;
    }
    Ok(())
}

fn median_comparison(
    output: &mut impl Write,
    report: &ComparisonReport,
    numerator: Role,
    comparison: &MedianComparison,
) -> Result<()> {
    writeln!(output, "### {} / baseline\n", role_name(numerator))?;
    median_operand(
        output,
        "Numerator",
        report
            .summaries
            .iter()
            .find(|summary| summary.role == numerator),
    )?;
    median_operand(
        output,
        "Denominator",
        report
            .summaries
            .iter()
            .find(|summary| summary.role == Role::Baseline),
    )?;
    measurement(
        output,
        "Median ratio (numerator / denominator; dimensionless)",
        comparison.median_ratio,
        comparison.unavailable_reason.as_deref(),
    )?;
    measurement(
        output,
        "Median change fraction (ratio - 1; not a percentage)",
        comparison.median_change_fraction,
        comparison.unavailable_reason.as_deref(),
    )?;
    Ok(())
}

fn truncated(output: &mut impl Write, label: &str, evidence: Option<&Evidence>) -> Result<()> {
    if evidence.is_some_and(|evidence| evidence.truncated) {
        writeln!(
            output,
            "**TRUNCATED preview: {label}.** Its display is not the full identity or metadata; see its typed-evidence hash and the archived record where available.\n"
        )?;
    }
    Ok(())
}

fn row_details(output: &mut impl Write, row: &ComparisonRow) -> Result<()> {
    writeln!(
        output,
        "### Slot {}: {}\n",
        row.slot.index,
        role_name(row.slot.role)
    )?;
    writeln!(
        output,
        "Repetition {} (zero-based); declared warmup: {}; inspection: **{}**; capture state: **{}**; included in summary: **{}**.\n",
        row.slot.repetition,
        row.slot.warmup,
        inspection_name(&row.inspection),
        state_name(row.state),
        row.included_in_summary
    )?;
    measurement(
        output,
        "Selected metric (seconds)",
        row.metric_seconds,
        row.metric_unavailable_reason
            .as_deref()
            .or(row.reason.as_deref()),
    )?;
    if let Some(reason) = &row.reason {
        writeln!(output, "Capture / inspection reason:\n")?;
        literal(output, reason)?;
    }
    writeln!(
        output,
        "Exclusion reasons (an available metric is not necessarily included):\n"
    )?;
    strings(output, &row.exclusion_reasons)?;
    writeln!(output, "Slot issues:\n")?;
    strings(output, &row.issues)?;
    for (label, evidence) in [
        ("capture binding", row.capture.as_ref()),
        (
            "canonical source directory",
            row.canonical_directory.as_ref(),
        ),
        ("failure", row.failure.as_ref()),
    ] {
        truncated(output, label, evidence)?;
    }
    if let Some(provenance) = &row.provenance {
        writeln!(
            output,
            "Provenance-known flags: host={}; runtime={}; launch configuration={}; model={}; device={}; cache={}. Known flags are comparison checks, not authentication.\n",
            provenance.host_known,
            provenance.runtime_known,
            provenance.launch_configuration_known,
            provenance.model_known,
            provenance.device_known,
            provenance.cache_known
        )?;
        for (label, evidence) in [
            ("host", Some(&provenance.host)),
            ("invocation", Some(&provenance.invocation)),
            ("runtime", provenance.runtime.as_ref()),
            ("runtime identity", provenance.runtime_identity.as_ref()),
            ("model", provenance.model.as_ref()),
            ("model fingerprint", provenance.model_fingerprint.as_ref()),
            ("device", provenance.device.as_ref()),
            ("cache", provenance.cache.as_ref()),
            ("adapter timings", provenance.adapter_timings.as_ref()),
        ] {
            truncated(output, label, evidence)?;
        }
    } else {
        writeln!(
            output,
            "Provenance: **UNAVAILABLE**; no known-provenance flags can be established for this slot.\n"
        )?;
    }
    writeln!(
        output,
        "Complete comparison row, including timestamps (Unix milliseconds), identities, failures, evidence previews, provenance flags and availability reasons. A null field means unavailable / not recorded, never zero or a verified match. Preview objects marked `truncated: true` omit text; their SHA-256 identifies the full typed value, not the preview.\n"
    )?;
    json(output, row)
}

/// Render a previously computed report; read only its verified local metadata snapshots.
/// The caller owns bounded output, persistence, private permissions and artifact inventory.
/// No caller-supplied string is interpreted as Markdown, HTML or a link destination.
pub fn write(
    output: &mut impl Write,
    input: &StudyInput,
    report: &ComparisonReport,
    archive: &CaptureArchive,
) -> Result<()> {
    writeln!(output, "# Offline saved-evidence study comparison\n")?;
    writeln!(
        output,
        "**{} — saved-evidence status, not a performance or quality verdict.**\n",
        if report.is_complete() {
            "COMPLETE"
        } else {
            "INCONCLUSIVE"
        }
    )?;
    writeln!(
        output,
        "**No statistical significance, confidence, causal, inference-speedup, perceptual-quality or reproducibility judgment is made.** COMPLETE means only the comparison's recorded evidence checks passed. Invalid, missing, uninspected, failed and excluded slots remain visible below; INCONCLUSIVE evidence must not be treated as a successful experiment.\n"
    )?;
    writeln!(
        output,
        "[Complete machine-readable report, study input and artifact inventory](report.json). Comparison schema version {}.\n",
        report.schema_version
    )?;
    writeln!(output, "## Declaration and evidence checks\n")?;
    for (label, value) in [
        ("Study ID", report.study_id.as_str()),
        ("Baseline label", report.baseline_label.as_str()),
        ("Candidate label", report.candidate_label.as_str()),
        (
            "Full typed plan SHA-256 identity",
            report.plan_identity.as_str(),
        ),
    ] {
        writeln!(output, "{label}:\n")?;
        literal(output, value)?;
    }
    writeln!(
        output,
        "Control means unchanged baseline, not a separate optimized candidate.\n"
    )?;
    match report.mode {
        ComparisonMode::SameWork => writeln!(
            output,
            "Mode: **same_work**. Ratios are suppressed by the comparison when same-work compatibility or persisted order is not established.\n"
        )?,
        ComparisonMode::Descriptive => writeln!(
            output,
            "Mode: **descriptive**. Ratios may describe incompatible or unverified work; they do not establish a controlled same-work comparison.\n"
        )?,
    }
    writeln!(
        output,
        "Same-work compatible: **{}**. Persisted order verified: **{}**. Minimum included non-warmup samples per role: **{}**.\n",
        report.same_work_compatible, report.persisted_order_verified, report.minimum_samples
    )?;
    writeln!(
        output,
        "Inspection budget: {} milliseconds, **cooperative, not a hard deadline**. Checks occur between slots; capture inspection, archival work or a stalled filesystem call can exceed the budget. Snapshot verification and report output also have no forced I/O timeout.\n",
        report.inspection_budget_ms
    )?;
    writeln!(
        output,
        "## Requested workload and selected measurement\n\nExact typed plan, including requested workload/settings, declared repetitions/warmups, labels and timing selection:\n"
    )?;
    json(output, &input.plan)?;
    writeln!(
        output,
        "Selected report metric (adapter phase, method, scope and boundary when applicable):\n"
    )?;
    json(output, &report.metric)?;
    writeln!(output, "Recorded metric boundary:\n")?;
    literal(output, &report.metric_boundary)?;
    writeln!(
        output,
        "All summary and slot timing values below are **seconds**. Original timing units and availability remain in each archived record. Host spawn-to-exit/stop-decision is **not inference time**. Host, native and GPU scopes are distinct; application, pipeline and kernel boundaries are not interchangeable. A faster kernel may barely affect whole-generation latency if that kernel accounts for little of the whole boundary; no kernel or application speedup is inferred here.\n\nNo throughput is derived. Images/second and seconds/image are different quantities; video-generation throughput is not playback FPS. Modalities are never combined into one performance score.\n"
    )?;
    writeln!(
        output,
        "## Role statistics\n\nValues are the comparison's existing finite descriptive summaries, not a new analysis. Counts cover every planned slot and may overlap: warmups can also be failed or missing; failed counts include every known non-completed state; missing counts mean no capture state was available. Excluded-measurement counts cover only excluded slots with an available metric. Included values are independent, requested-workload, non-warmup measurements in declared order under the comparison's existing checks. Each value maps to its included slot below. No unavailable value is replaced with zero.\n"
    )?;
    for summary in &report.summaries {
        role_summary(output, summary)?;
    }
    writeln!(
        output,
        "## Median comparisons and unchanged-control drift\n\nOperands below are the actual role medians and sample denominators. Ratios, change fractions and suppression reasons are copied from the comparison without recalculation or override. A ratio below one describes a lower selected-time median, not proven inference acceleration. The unchanged-control comparison exposes observed drift; it does not correct candidate numbers or prove its cause.\n"
    )?;
    median_comparison(
        output,
        report,
        Role::Candidate,
        &report.candidate_vs_baseline,
    )?;
    median_comparison(output, report, Role::Control, &report.control_vs_baseline)?;
    writeln!(
        output,
        "## Every declared slot, in order\n\n| Slot | Role | Repetition (0-based) | Warmup | Inspection | Capture state | Metric seconds | Included |\n| ---: | --- | ---: | --- | --- | --- | ---: | --- |"
    )?;
    for row in &report.rows {
        write!(
            output,
            "| {} | {} | {} | {} | {} | {} | ",
            row.slot.index,
            role_name(row.slot.role),
            row.slot.repetition,
            row.slot.warmup,
            inspection_name(&row.inspection),
            state_name(row.state)
        )?;
        number(output, row.metric_seconds)?;
        writeln!(output, " | {} |", row.included_in_summary)?;
    }
    writeln!(
        output,
        "\n## Recorded issues, differences and limitations\n\n### Issues\n"
    )?;
    strings(output, &report.issues)?;
    writeln!(output, "### Differences\n")?;
    strings(output, &report.differences)?;
    writeln!(output, "### Comparison limitations (complete)\n")?;
    strings(output, &report.limitations)?;
    writeln!(
        output,
        "### Archive and interpretation limits\n\nWarmup cache observations remain in the full records below, separately from measured-cache comparisons; a warmup cache state does not redefine the measured boundary. Review the recorded differences and control drift, including suppressed or unavailable values, rather than assuming steady cache or unchanged conditions.\n\nSnapshot hashes verify the archived bytes against this bundle's inventory; hashes are **not authenticated provenance**. Typed-evidence/manifest identities hash different representations from the archived-file SHA-256. Caller-supplied settings, outcomes and metadata remain observations, not authorization or independent verification. Unknown metadata never proves equality.\n\nArchived records retain the complete **typed capture metadata that was inspected**, including any already-redacted or unavailable fields; this is not a copy of the full capture/media/guard/log bundle. Original model/source/media/artifact paths are provenance text only and may not exist offline. Artifact references are not fetched, embedded, or independently assessed by this renderer. Numerical media comparisons and visual/temporal/audio quality assessments are not performed here. No default upload, remote resource or hosted UI is used.\n"
    )?;
    writeln!(
        output,
        "## Per-slot evidence and full archived metadata\n\nThe following metadata is read and verified one slot at a time from fixed local snapshots, not reread from original captures. A missing snapshot is explicitly unavailable; no record is invented.\n"
    )?;
    for row in &report.rows {
        row_details(output, row)?;
        if let Some(binding) = input.samples.get(row.slot.index as usize) {
            writeln!(
                output,
                "Original declared binding (path is literal provenance, not a link):\n"
            )?;
            json(output, binding)?;
        }
        match archive.text(row.slot.index as usize)? {
            Some(text) => {
                let artifact = archive
                    .snapshots()
                    .get(row.slot.index as usize)
                    .and_then(Option::as_ref)
                    .context("archived metadata has no snapshot inventory entry")?;
                writeln!(
                    output,
                    "[Full local capture metadata JSON](captures/slot-{:03}.json). Snapshot byte count and SHA-256:\n",
                    row.slot.index
                )?;
                json(output, artifact)?;
                writeln!(
                    output,
                    "Full typed archived record: host/hardware, invocation, runtime/source/model/cache, requested and resolved workload/settings, timing/resource scope, units and availability, capture outcome and artifact references wherever recorded. Explicit unavailable fields remain unavailable.\n"
                )?;
                literal(output, &text)?;
            }
            None => {
                writeln!(
                    output,
                    "**ARCHIVED CAPTURE METADATA UNAVAILABLE** — no loaded record was archived for this slot. Inspection state: {}.\n",
                    inspection_name(&row.inspection)
                )?;
                if let Some(reason) = row
                    .reason
                    .as_deref()
                    .or(row.metric_unavailable_reason.as_deref())
                {
                    literal(output, reason)?;
                } else {
                    writeln!(
                        output,
                        "No additional reason was recorded; consult the complete row and its exclusions above.\n"
                    )?;
                }
            }
        }
    }
    Ok(())
}
