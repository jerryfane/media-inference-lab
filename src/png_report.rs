//! Readable view of a computed PNG comparison, for the CLI's fixed bundle layout.
//! This renderer neither inspects files nor authenticates caller-supplied evidence.
use std::io::{self, Write};

use crate::{
    image_comparison::{ImageComparisonReport, ImageMetrics, NumericalClassification, Psnr},
    png_image::PngIdentity,
    schema::Observation,
};

fn fence(output: &mut impl Write, mut length: usize) -> io::Result<()> {
    const TICKS: &[u8] = b"````````````````````````````````````````````````````````````````";
    while length > 0 {
        let count = length.min(TICKS.len());
        output.write_all(&TICKS[..count])?;
        length -= count;
    }
    Ok(())
}

// All strings, including paths and hashes, are data, never Markdown or URLs.
// A delimiter longer than every embedded run cannot be closed by field content.
fn literal(output: &mut impl Write, value: &str) -> io::Result<()> {
    let mut longest = 0;
    let mut run = 0;
    for byte in value.bytes() {
        run = if byte == b'`' { run + 1 } else { 0 };
        longest = longest.max(run);
    }
    let length = (longest + 1).max(3);
    fence(output, length)?;
    output.write_all(b"\n")?;
    let mut start = 0;
    for (index, character) in value.char_indices() {
        if character.is_control() && character != '\n' && character != '\t' {
            output.write_all(&value.as_bytes()[start..index])?;
            write!(output, "\\u{{{:x}}}", character as u32)?;
            start = index + character.len_utf8();
        }
    }
    output.write_all(&value.as_bytes()[start..])?;
    output.write_all(b"\n")?;
    fence(output, length)?;
    output.write_all(b"\n\n")
}

fn observation(output: &mut impl Write, observation: &Observation<String>) -> io::Result<()> {
    match observation {
        Observation::Available { value } => {
            output.write_all(b"Caller-supplied observation (not independently verified):\n\n")?;
            literal(output, value)
        }
        Observation::Unavailable { reason } => {
            output.write_all(b"**UNAVAILABLE / UNASSESSED**\n\n")?;
            literal(output, reason)
        }
    }
}

fn identity(output: &mut impl Write, identity: &PngIdentity) -> io::Result<()> {
    writeln!(
        output,
        "{} x {} pixels; {:?}; {}-bit integer samples; {} encoded bytes.\n",
        identity.width, identity.height, identity.color, identity.bit_depth, identity.bytes
    )?;
    output.write_all(b"Original source path (provenance only; open the bundled copy):\n\n")?;
    literal(output, &identity.source_path.to_string_lossy())?;
    output.write_all(b"Encoded-file SHA-256:\n\n")?;
    literal(output, &identity.sha256)?;
    output.write_all(b"Raw-sample SHA-256 (row-major channels; 16-bit big-endian):\n\n")?;
    literal(output, &identity.decoded_sha256)
}

fn metrics(output: &mut impl Write, metrics: &ImageMetrics) -> io::Result<()> {
    output.write_all(b"| Measurement | Value | Unit / denominator |\n| --- | ---: | --- |\n")?;
    writeln!(
        output,
        "| Encoded bytes equal | {} | SHA-256 identity |",
        metrics.encoded_equal
    )?;
    writeln!(
        output,
        "| Decoded samples equal | {} | every stored channel |",
        metrics.decoded_equal
    )?;
    writeln!(output, "| Pixels | {} | pixels |", metrics.pixel_count)?;
    writeln!(
        output,
        "| Channels per pixel | {} | including alpha when present |",
        metrics.channel_count
    )?;
    writeln!(
        output,
        "| Compared samples (N) | {} | pixels x channels; no excluded samples |",
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

/// Render an already-computed comparison into the fixed local PNG bundle layout.
/// Links are literal bundle filenames; no caller text becomes a link or raw HTML.
/// The caller owns output size limits, durable persistence and artifact inventory.
pub fn write(output: &mut impl Write, report: &ImageComparisonReport) -> io::Result<()> {
    output.write_all(b"# Offline PNG comparison\n\n")?;
    let status = match report.classification {
        NumericalClassification::ExactDecoded => "EXACT DECODED SAMPLES",
        NumericalClassification::WithinTolerance => "WITHIN CALLER-DECLARED NUMERICAL BOUND",
        NumericalClassification::OutsideTolerance => "OUTSIDE CALLER-DECLARED NUMERICAL BOUND",
        NumericalClassification::DifferentUnbounded => {
            "DIFFERENT SAMPLES — NO NUMERICAL BOUND DECLARED"
        }
    };
    writeln!(output, "**{status}**\n")?;
    output.write_all(
        b"**Not a visual-quality, reproducibility or inference-performance verdict.**\n\n",
    )?;
    match &report.assessment {
        Observation::Unavailable { .. } => {
            output.write_all(b"**Reviewer assessment: UNAVAILABLE / UNASSESSED.**\n\n")?
        }
        Observation::Available { .. } => output.write_all(
            b"**Reviewer record supplied; identity and observations are UNVERIFIED.**\n\n",
        )?,
    }
    if matches!(
        report.baseline_repeat_metrics,
        Observation::Unavailable { .. }
    ) {
        output.write_all(b"**Baseline-repeat variation: UNAVAILABLE.**\n\n")?;
    }
    writeln!(
        output,
        "PNG comparison schema version {}. [Complete machine-readable evidence and artifact inventory](report.json).\n",
        report.schema_version
    )?;
    output.write_all(b"## Local images\n\n[Baseline original](baseline.png) | [Candidate original](candidate.png) | [Raw A/B sheet](sheet.png)\n\n")?;
    if report.baseline_repeat.is_some() {
        output.write_all(b"[Baseline-repeat original](baseline-repeat.png)\n\n")?;
    }
    output.write_all(b"![Raw sample A/B sheet](sheet.png)\n\nBaseline left; candidate right. No resizing or sample conversion. The sheet omits ancillary metadata and does not apply color management, transparency keys or orientation. Use the original copies for color-managed inspection.\n\n## Candidate versus baseline\n\n")?;
    metrics(output, &report.metrics)?;
    output.write_all(b"### Declared tolerance\n\n")?;
    if let Some(tolerance) = &report.tolerance {
        writeln!(
            output,
            "Maximum permitted absolute error: **{} integer sample-code units per sample**. Caller rationale (not automatically validated as a quality threshold):\n",
            tolerance.max_absolute_error
        )?;
        literal(output, &tolerance.rationale)?;
    } else {
        output.write_all(b"No numerical bound was declared. Different samples are not assigned an implicit passing tolerance.\n\n")?;
    }
    output.write_all(b"## Baseline-repeat versus baseline\n\n")?;
    match &report.baseline_repeat_metrics {
        Observation::Available { value } => {
            output.write_all(b"Separate output variation; not an independent-generation guarantee or a replacement for the candidate threshold.\n\n")?;
            metrics(output, value)?;
        }
        Observation::Unavailable { reason } => {
            output.write_all(b"**UNAVAILABLE**\n\n")?;
            literal(output, reason)?;
        }
    }
    output.write_all(b"## Exact input identities\n\n### Baseline\n\n")?;
    identity(output, &report.baseline)?;
    output.write_all(b"### Candidate\n\n")?;
    identity(output, &report.candidate)?;
    if let Some(repeat) = &report.baseline_repeat {
        output.write_all(b"### Baseline repeat\n\n")?;
        identity(output, repeat)?;
    }
    output.write_all(b"## Method, alignment and units\n\n")?;
    for value in [
        &report.method,
        &report.alignment,
        &report.units,
        &report.denominator,
    ] {
        literal(output, value)?;
    }
    output.write_all(b"## Separate reviewer record\n\n")?;
    match &report.assessment {
        Observation::Unavailable { reason } => {
            output.write_all(b"**UNAVAILABLE / UNASSESSED**\n\n")?;
            literal(output, reason)?;
        }
        Observation::Available { value } => {
            output.write_all(b"### Reviewer (caller-supplied, unauthenticated)\n\n")?;
            literal(output, &value.reviewer)?;
            output.write_all(b"### Protocol\n\n")?;
            literal(output, &value.protocol)?;
            output.write_all(b"### Bound encoded baseline / candidate SHA-256\n\n")?;
            literal(output, &value.baseline_sha256)?;
            literal(output, &value.candidate_sha256)?;
            output.write_all(b"### Prompt adherence\n\n")?;
            observation(output, &value.prompt_adherence)?;
            output.write_all(b"### Artifacts\n\n")?;
            observation(output, &value.artifacts)?;
            output.write_all(b"### Reviewer limitations\n\n")?;
            for limitation in &value.limitations {
                literal(output, limitation)?;
            }
        }
    }
    output.write_all(b"## Performance and generation evidence\n\n**UNAVAILABLE in this standalone PNG comparison:** hardware/model/runtime identity, generation settings, sample execution order/outcomes, application/pipeline/kernel timings, cache state, control drift and resource measurements. Original PNG samples and their comparison are evidence, not proof of how they were generated.\n\nNo images/second, seconds/image, video-generation throughput, playback FPS or combined modality score is inferred. A faster kernel can have little effect on whole-generation latency when other pipeline work dominates; there are no timing measurements here to assess that claim.\n\n## Comparison limitations\n\n")?;
    for limitation in &report.limitations {
        literal(output, limitation)?;
    }
    output.write_all(b"This is a local view of report.json, not an authenticated report. Field text is literal code, not executable Markdown/HTML or a URL. Control characters other than newline/tab are displayed as Unicode escapes; JSON retains original text. Nothing is uploaded.\n")
}
