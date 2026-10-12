//! Readable view of an already-computed, full declared PNG-sequence comparison.
//! Rendering does not inspect sources, recompute measurements or verify observations.
use std::io::{self, Write};

use anyhow::Result;
use serde::Serialize;

use crate::{
    frame_sequence::{SequenceIdentity, SequenceInput, SequenceReport},
    image_comparison::{ImageMetrics, NumericalClassification, Psnr},
    markdown::literal,
    png_image::PngIdentity,
    schema::Observation,
};

fn json(output: &mut impl Write, value: &impl Serialize) -> Result<()> {
    literal(output, &serde_json::to_string_pretty(value)?)?;
    Ok(())
}

fn limitations(output: &mut impl Write, values: &[String]) -> io::Result<()> {
    if values.is_empty() {
        output.write_all(b"None recorded. This does not establish absence of limitations.\n\n")?;
    }
    for value in values {
        literal(output, value)?;
    }
    Ok(())
}

fn observation(output: &mut impl Write, value: &Observation<String>) -> io::Result<()> {
    match value {
        Observation::Available { value } => {
            output.write_all(
                b"Caller-supplied observation: **UNVERIFIED**, not a computed verdict.\n\n",
            )?;
            literal(output, value)
        }
        Observation::Unavailable { reason } => {
            output.write_all(b"**UNAVAILABLE / UNASSESSED**\n\n")?;
            literal(output, reason)
        }
    }
}

fn png_identity(output: &mut impl Write, identity: &PngIdentity) -> io::Result<()> {
    writeln!(
        output,
        "{} x {} pixels; {:?}; {}-bit integer samples; {} encoded bytes.\n",
        identity.width, identity.height, identity.color, identity.bit_depth, identity.bytes
    )?;
    output.write_all(b"Original source path (provenance only, not a link):\n\n")?;
    literal(output, &identity.source_path.to_string_lossy())?;
    output.write_all(b"Encoded PNG SHA-256:\n\n")?;
    literal(output, &identity.sha256)?;
    output.write_all(b"Raw-sample SHA-256 (row-major channels; 16-bit big-endian):\n\n")?;
    literal(output, &identity.decoded_sha256)
}

fn sequence_identity(output: &mut impl Write, identity: &SequenceIdentity) -> io::Result<()> {
    writeln!(
        output,
        "Declared frame count: **{}**. Declared duration: **{} ns**.\n\nComplete ordered sequence SHA-256:\n",
        identity.frame_count, identity.duration_ns
    )?;
    literal(output, &identity.sha256)
}

fn input(output: &mut impl Write, input: &SequenceInput) -> Result<()> {
    output.write_all(
        b"Caller-declared provenance / extraction and alignment method (**UNVERIFIED**):\n\n",
    )?;
    literal(output, &input.provenance)?;
    output.write_all(b"Full declared input, including every index, original path, presentation timestamp and duration (nanoseconds). Paths are provenance, not links:\n\n")?;
    json(output, input)
}

fn metrics(output: &mut impl Write, metrics: &ImageMetrics) -> io::Result<()> {
    output.write_all(b"| Measurement | Value | Unit / denominator |\n| --- | ---: | --- |\n")?;
    writeln!(
        output,
        "| Encoded PNG bytes equal | {} | every corresponding encoded PNG in this scope; not manifest/container equality |",
        metrics.encoded_equal
    )?;
    writeln!(
        output,
        "| Decoded samples equal | {} | every corresponding stored channel sample in this scope |",
        metrics.decoded_equal
    )?;
    writeln!(
        output,
        "| Pixels | {} | pixels across this scope |",
        metrics.pixel_count
    )?;
    writeln!(
        output,
        "| Channels per pixel | {} | all stored channels, including alpha when present |",
        metrics.channel_count
    )?;
    writeln!(
        output,
        "| Compared samples (N) | {} | all pixels x channels in this scope; no duration weighting |",
        metrics.sample_count
    )?;
    writeln!(
        output,
        "| Peak sample code | {} | integer sample-code units |",
        metrics.peak_sample_value
    )?;
    writeln!(
        output,
        "| Sum of absolute errors | {} | sample-code units |",
        metrics.absolute_error_sum
    )?;
    writeln!(
        output,
        "| Sum of squared errors | {} | sample-code units squared |",
        metrics.squared_error_sum
    )?;
    writeln!(
        output,
        "| Maximum absolute error | {} | sample-code units |",
        metrics.max_absolute_error
    )?;
    writeln!(
        output,
        "| Mean absolute error | {} | sample-code units; absolute sum / N |",
        metrics.mean_absolute_error
    )?;
    writeln!(
        output,
        "| Root mean squared error | {} | sample-code units; sqrt(squared sum / N) |",
        metrics.root_mean_squared_error
    )?;
    match metrics.psnr {
        Psnr::Finite { decibels } => writeln!(
            output,
            "| PSNR | {decibels} | dB; 10 log10(peak squared / (squared sum / N)) |"
        )?,
        Psnr::PositiveInfinity => output
            .write_all(b"| PSNR | +infinity | dB; identical samples, zero squared error |\n")?,
    }
    output.write_all(b"\n")
}

fn repeat_metrics(output: &mut impl Write, value: &Observation<ImageMetrics>) -> io::Result<()> {
    match value {
        Observation::Available { value } => {
            output.write_all(b"Separate baseline-repeat versus baseline comparison. Not a candidate substitute or an independently established baseline experiment.\n\n")?;
            metrics(output, value)
        }
        Observation::Unavailable { reason } => {
            output.write_all(b"**UNAVAILABLE**\n\n")?;
            literal(output, reason)
        }
    }
}

/// Render the fixed local bundle layout without choosing frames or recomputing results.
/// The caller enforces output quotas, persistence and artifact inventory integrity.
/// Only renderer-owned relative destinations become links; field text is literal.
pub fn write(output: &mut impl Write, report: &SequenceReport) -> Result<()> {
    output.write_all(b"# Offline declared PNG-sequence comparison\n\n")?;
    let status = match report.classification {
        NumericalClassification::ExactDecoded => "EXACT DECODED SAMPLES",
        NumericalClassification::WithinTolerance => "WITHIN CALLER-DECLARED NUMERICAL BOUND",
        NumericalClassification::OutsideTolerance => "OUTSIDE CALLER-DECLARED NUMERICAL BOUND",
        NumericalClassification::DifferentUnbounded => {
            "DIFFERENT SAMPLES — NO NUMERICAL BOUND DECLARED"
        }
    };
    writeln!(output, "**Numerical classification: {status}**\n")?;
    output.write_all(b"**Not a visual-quality, temporal-quality, reproducibility or inference-performance verdict.** Every frame in the declared PNG sequences is compared; no hidden frame subset is selected. This scope does not establish original-container completeness, successful video-codec decoding or how these outputs were generated.\n\n")?;
    match &report.assessment {
        Observation::Available { .. } => output.write_all(b"**Reviewer record supplied: identity and observations are UNVERIFIED.** Temporal observations are separate from, and cannot change, the numerical classification.\n\n")?,
        Observation::Unavailable { .. } => output.write_all(b"**Reviewer assessment, including temporal observations: UNAVAILABLE / UNASSESSED.**\n\n")?,
    }
    output.write_all(b"**Decoded audio and audio assessment: UNAVAILABLE.**\n\n")?;
    writeln!(
        output,
        "Comparison schema version {}. [Complete machine-readable evidence and artifact inventory](report.json).\n\nRecorded report kind:\n",
        report.schema_version
    )?;
    literal(output, &report.kind)?;

    output.write_all(b"## Complete declared sequence identities and inputs\n\nSequence identities bind the complete ordered encoded PNG contents and declared timing, not paths or provenance. SHA-256 input is domain bytes `mil-png-sequence-v1\\0` (the final byte is NUL), frame count as u64 big-endian, total duration in ns as u64 big-endian, then for every frame in order: index, presentation timestamp in ns and duration in ns, each as u64 big-endian, followed by the encoded PNG SHA-256 as 64 ASCII bytes. This is not an original-container or decoded-video identity.\n\n### Baseline\n\n")?;
    sequence_identity(output, &report.baseline)?;
    input(output, &report.baseline_input)?;
    output.write_all(b"### Candidate\n\n")?;
    sequence_identity(output, &report.candidate)?;
    input(output, &report.candidate_input)?;
    output.write_all(b"### Baseline repeat\n\n")?;
    match &report.baseline_repeat {
        Some(value) => sequence_identity(output, value)?,
        None => output.write_all(
            b"Sequence identity: **UNAVAILABLE**; no baseline-repeat identity recorded.\n\n",
        )?,
    }
    match &report.baseline_repeat_input {
        Some(value) => input(output, value)?,
        None => output.write_all(
            b"Declared input: **UNAVAILABLE**; no baseline-repeat manifest recorded.\n\n",
        )?,
    }

    output.write_all(b"## Aggregate candidate versus baseline\n\nScope: ALL corresponding frames and ALL stored channels, including alpha when present. The recorded integer error sums and pixel/sample counts cover the complete declared sequences. N below is the actual total compared sample count, not the frame count or duration. MAE and RMSE use the whole-sequence sums and N; PSNR uses the whole-sequence squared sum and N. These are not averages of per-frame metrics and are not time-weighted. The maximum is over every compared sample. Equality means all corresponding frames are equal. No color transforms, interpolation or frame matching are performed.\n\n")?;
    metrics(output, &report.metrics)?;
    output.write_all(b"### Caller-declared numerical tolerance\n\n")?;
    match &report.tolerance {
        Some(value) => {
            writeln!(output, "Maximum permitted absolute error: **{} integer sample-code units per sample**. Caller rationale (not a validated quality threshold):\n", value.max_absolute_error)?;
            literal(output, &value.rationale)?;
        }
        None => output.write_all(b"No numerical bound declared. Different samples are not assigned an implicit passing tolerance.\n\n")?,
    }
    output.write_all(b"## Aggregate baseline-repeat versus baseline\n\nScope: all corresponding baseline and baseline-repeat frames, independently of candidate metrics.\n\n")?;
    repeat_metrics(output, &report.baseline_repeat_metrics)?;

    output.write_all(b"## Every declared frame\n\nAll recorded frames follow in declared order; no selection or sampling. Each interval is specified by its start presentation timestamp and positive duration in nanoseconds, representing [start, start + duration). Metrics in each frame section use only that frame's pixels and all stored channels; its actual N is reported.\n\nLocal original copies preserve encoded PNG bytes. Each raw A/B sheet places baseline LEFT and candidate RIGHT with no resizing or sample conversion. Sheets omit ancillary metadata and do not apply color management, transparency keys or orientation. They are raw-sample inspection aids, not color-managed quality evidence. Open original copies for color-managed inspection.\n\n")?;
    for frame in &report.frames {
        writeln!(
            output,
            "### Frame {}\n\nPresentation timestamp: **{} ns**. Duration: **{} ns**.\n",
            frame.index, frame.pts_ns, frame.duration_ns
        )?;
        writeln!(
            output,
            "[Baseline original](frames/{0:04}-baseline.png) | [Candidate original](frames/{0:04}-candidate.png) | [Raw A/B sheet](frames/{0:04}-sheet.png)\n",
            frame.index
        )?;
        if frame.baseline_repeat.is_some() {
            writeln!(
                output,
                "[Baseline-repeat original](frames/{:04}-repeat.png)\n",
                frame.index
            )?;
        }
        output.write_all(b"#### Candidate versus baseline metrics\n\n")?;
        metrics(output, &frame.metrics)?;
        output.write_all(b"#### Baseline-repeat versus baseline metrics\n\n")?;
        repeat_metrics(output, &frame.baseline_repeat_metrics)?;
        output.write_all(b"#### Baseline PNG identity\n\n")?;
        png_identity(output, &frame.baseline)?;
        output.write_all(b"#### Candidate PNG identity\n\n")?;
        png_identity(output, &frame.candidate)?;
        output.write_all(b"#### Baseline-repeat PNG identity\n\n")?;
        match &frame.baseline_repeat {
            Some(value) => png_identity(output, value)?,
            None => {
                output.write_all(b"**UNAVAILABLE**; no baseline-repeat identity recorded.\n\n")?
            }
        }
    }

    output.write_all(b"## Separate unverified reviewer record\n\nSupplied observations are not computed image-quality or temporal-quality measurements, are not authenticated and never alter the numerical result.\n\n")?;
    match &report.assessment {
        Observation::Unavailable { reason } => {
            output.write_all(b"**UNAVAILABLE / UNASSESSED**\n\n")?;
            literal(output, reason)?;
        }
        Observation::Available { value } => {
            writeln!(
                output,
                "Assessment schema version {}.\n\n### Reviewer (caller-supplied, unauthenticated)\n",
                value.schema_version
            )?;
            literal(output, &value.reviewer)?;
            output.write_all(b"### Protocol\n\n")?;
            literal(output, &value.protocol)?;
            output.write_all(b"### Bound complete baseline sequence SHA-256\n\n")?;
            literal(output, &value.baseline_sha256)?;
            output.write_all(b"### Bound complete candidate sequence SHA-256\n\n")?;
            literal(output, &value.candidate_sha256)?;
            output.write_all(b"### Prompt adherence\n\n")?;
            observation(output, &value.prompt_adherence)?;
            output.write_all(b"### Artifacts\n\n")?;
            observation(output, &value.artifacts)?;
            output.write_all(b"### Temporal consistency\n\n")?;
            observation(output, &value.temporal_consistency)?;
            output.write_all(b"### Audio\n\n**UNAVAILABLE**: this comparison has no decoded audio and cannot bind audio observations. Recorded audio field (literal data, not an accepted audio assessment):\n\n")?;
            json(output, &value.audio)?;
            output.write_all(b"### Reviewer limitations\n\n")?;
            limitations(output, &value.limitations)?;
        }
    }
    output.write_all(b"## Performance, generation and original media evidence\n\n**UNAVAILABLE:** decoded audio, latent tensors, compressed-video decoding/completeness evidence, model/runtime/hardware identity, generation settings, execution order/outcomes, application/pipeline/kernel timing, cache state, resource measurements and an independently established baseline experiment. No playback FPS, inference throughput, quality score or temporal/performance verdict is inferred from declared durations or pixel differences. Source metadata and provenance remain unverified.\n\n## Recorded comparison limitations\n\n")?;
    limitations(output, &report.limitations)?;
    output.write_all(b"This is a local view of report.json, not an authenticated report. Caller text is literal code, never executable Markdown/HTML or a destination. Control characters other than newline/tab are displayed as Unicode escapes; JSON retains original text. Links refer only to fixed local bundle paths. Nothing is uploaded.\n")?;
    Ok(())
}
