use anyhow::{Result, ensure};
use serde::{Deserialize, Serialize};

use crate::{
    png_image::{DecodedPng, PngIdentity},
    schema::Observation,
};

pub const IMAGE_COMPARISON_SCHEMA_VERSION: u32 = 1;
pub const MAX_TEXT_BYTES: usize = 8192;
pub const MAX_ASSESSMENT_LIMITATIONS: usize = 64;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Tolerance {
    pub max_absolute_error: u16,
    pub rationale: String,
}

/// Caller-supplied observations, bound to the encoded input snapshots.
/// Numerical agreement neither creates nor overrides this assessment.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ImageAssessment {
    pub schema_version: u32,
    pub baseline_sha256: String,
    pub candidate_sha256: String,
    pub reviewer: String,
    pub protocol: String,
    pub prompt_adherence: Observation<String>,
    pub artifacts: Observation<String>,
    pub limitations: Vec<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ImageComparisonKind {
    PngOutputComparison,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum NumericalClassification {
    ExactDecoded,
    WithinTolerance,
    OutsideTolerance,
    DifferentUnbounded,
}

/// JSON cannot represent infinity as a number. Zero error has an explicit tag.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum Psnr {
    Finite { decibels: f64 },
    PositiveInfinity,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ImageMetrics {
    pub encoded_equal: bool,
    pub decoded_equal: bool,
    pub pixel_count: u64,
    pub channel_count: u8,
    pub sample_count: u64,
    pub peak_sample_value: u16,
    pub absolute_error_sum: u64,
    pub squared_error_sum: u64,
    pub max_absolute_error: u16,
    pub mean_absolute_error: f64,
    pub root_mean_squared_error: f64,
    pub psnr: Psnr,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ImageComparisonReport {
    pub schema_version: u32,
    pub kind: ImageComparisonKind,
    pub baseline: PngIdentity,
    pub candidate: PngIdentity,
    pub baseline_repeat: Option<PngIdentity>,
    pub metrics: ImageMetrics,
    pub baseline_repeat_metrics: Observation<ImageMetrics>,
    pub classification: NumericalClassification,
    pub tolerance: Option<Tolerance>,
    pub assessment: Observation<ImageAssessment>,
    pub method: String,
    pub alignment: String,
    pub units: String,
    pub denominator: String,
    pub limitations: Vec<String>,
}

impl ImageComparisonReport {
    /// CLI numerical-bound status only; not a quality or performance verdict.
    pub fn is_within_numerical_bound(&self) -> bool {
        matches!(
            self.classification,
            NumericalClassification::ExactDecoded | NumericalClassification::WithinTolerance
        )
    }
}

fn text(value: &str, field: &str) -> Result<()> {
    ensure!(
        !value.trim().is_empty() && !value.contains('\0') && value.len() <= MAX_TEXT_BYTES,
        "{field} must be nonblank, contain no NUL, and be at most {MAX_TEXT_BYTES} UTF-8 bytes"
    );
    Ok(())
}

fn observation(value: &Observation<String>, field: &str) -> Result<()> {
    match value {
        Observation::Available { value } => text(value, field),
        Observation::Unavailable { reason } => text(reason, field),
    }
}

fn validate_assessment(
    assessment: &ImageAssessment,
    baseline: &PngIdentity,
    candidate: &PngIdentity,
) -> Result<()> {
    ensure!(
        assessment.schema_version == IMAGE_COMPARISON_SCHEMA_VERSION,
        "unsupported image assessment schema version"
    );
    ensure!(
        assessment
            .baseline_sha256
            .eq_ignore_ascii_case(&baseline.sha256)
            && assessment
                .candidate_sha256
                .eq_ignore_ascii_case(&candidate.sha256),
        "assessment hashes must match the baseline and candidate encoded PNG snapshots"
    );
    text(&assessment.reviewer, "assessment.reviewer")?;
    text(&assessment.protocol, "assessment.protocol")?;
    observation(&assessment.prompt_adherence, "assessment.prompt_adherence")?;
    observation(&assessment.artifacts, "assessment.artifacts")?;
    ensure!(
        !assessment.limitations.is_empty()
            && assessment.limitations.len() <= MAX_ASSESSMENT_LIMITATIONS,
        "assessment must declare 1..={MAX_ASSESSMENT_LIMITATIONS} limitations"
    );
    for limitation in &assessment.limitations {
        text(limitation, "assessment.limitations entry")?;
    }
    Ok(())
}

pub(crate) fn validate_alignment(baseline: &DecodedPng, other: &DecodedPng) -> Result<()> {
    let left = baseline.identity();
    let right = other.identity();
    ensure!(
        left.width == right.width
            && left.height == right.height
            && left.color == right.color
            && left.bit_depth == right.bit_depth,
        "PNG comparison requires identical width, height, channel layout, and bit depth"
    );
    Ok(())
}

pub(crate) fn metrics(baseline: &DecodedPng, other: &DecodedPng) -> ImageMetrics {
    let identity = baseline.identity();
    let pixel_count = u64::from(identity.width) * u64::from(identity.height);
    let channel_count = identity.color.channels() as u8;
    let sample_count = pixel_count * u64::from(channel_count);
    let peak_sample_value = if identity.bit_depth == 8 { 255 } else { 65535 };
    let mut absolute_error_sum = 0_u64;
    let mut squared_error_sum = 0_u64;
    let mut max_absolute_error = 0_u16;
    // At most 2^24 pixels * 4 channels * (2^16 - 1)^2 < 2^58.
    // Validated image bounds therefore make both integer totals overflow-proof.
    let mut accumulate = |left: u16, right: u16| {
        let error = left.abs_diff(right);
        max_absolute_error = max_absolute_error.max(error);
        absolute_error_sum += u64::from(error);
        squared_error_sum += u64::from(error) * u64::from(error);
    };
    if identity.bit_depth == 8 {
        for (&left, &right) in baseline.samples().iter().zip(other.samples()) {
            accumulate(u16::from(left), u16::from(right));
        }
    } else {
        for (left, right) in baseline
            .samples()
            .as_chunks::<2>()
            .0
            .iter()
            .zip(other.samples().as_chunks::<2>().0)
        {
            accumulate(u16::from_be_bytes(*left), u16::from_be_bytes(*right));
        }
    }
    let mean_squared_error = squared_error_sum as f64 / sample_count as f64;
    let psnr = if squared_error_sum == 0 {
        Psnr::PositiveInfinity
    } else {
        Psnr::Finite {
            decibels: 10.0 * (f64::from(peak_sample_value).powi(2) / mean_squared_error).log10(),
        }
    };
    ImageMetrics {
        encoded_equal: baseline.identity().sha256 == other.identity().sha256,
        decoded_equal: squared_error_sum == 0,
        pixel_count,
        channel_count,
        sample_count,
        peak_sample_value,
        absolute_error_sum,
        squared_error_sum,
        max_absolute_error,
        mean_absolute_error: absolute_error_sum as f64 / sample_count as f64,
        root_mean_squared_error: mean_squared_error.sqrt(),
        psnr,
    }
}

pub fn compare(
    baseline: &DecodedPng,
    candidate: &DecodedPng,
    baseline_repeat: Option<&DecodedPng>,
    tolerance: Option<Tolerance>,
    assessment: Option<ImageAssessment>,
) -> Result<ImageComparisonReport> {
    validate_alignment(baseline, candidate)?;
    if let Some(repeat) = baseline_repeat {
        validate_alignment(baseline, repeat)?;
    }
    if let Some(tolerance) = &tolerance {
        text(&tolerance.rationale, "tolerance.rationale")?;
        ensure!(
            baseline.identity().bit_depth == 16 || tolerance.max_absolute_error <= 255,
            "tolerance exceeds the maximum sample code for the input bit depth"
        );
    }
    if let Some(assessment) = &assessment {
        validate_assessment(assessment, baseline.identity(), candidate.identity())?;
    }
    let metrics = metrics(baseline, candidate);
    let classification = if metrics.decoded_equal {
        NumericalClassification::ExactDecoded
    } else {
        match &tolerance {
            Some(tolerance) if metrics.max_absolute_error <= tolerance.max_absolute_error => {
                NumericalClassification::WithinTolerance
            }
            Some(_) => NumericalClassification::OutsideTolerance,
            None => NumericalClassification::DifferentUnbounded,
        }
    };
    let baseline_repeat_metrics = match baseline_repeat {
        Some(repeat) => Observation::Available {
            value: self::metrics(baseline, repeat),
        },
        None => Observation::Unavailable {
            reason:
                "No separate baseline-repeat PNG was supplied; baseline variation is unmeasured."
                    .into(),
        },
    };
    Ok(ImageComparisonReport {
        schema_version: IMAGE_COMPARISON_SCHEMA_VERSION,
        kind: ImageComparisonKind::PngOutputComparison,
        baseline: baseline.identity().clone(),
        candidate: candidate.identity().clone(),
        baseline_repeat: baseline_repeat.map(|repeat| repeat.identity().clone()),
        metrics,
        baseline_repeat_metrics,
        classification,
        tolerance,
        assessment: match assessment {
            Some(value) => Observation::Available { value },
            None => Observation::Unavailable {
                reason: "No hash-bound reviewer assessment was supplied; visual quality and prompt adherence are unassessed."
                    .into(),
            },
        },
        method: "Unsigned integer PNG sample-code differences; exact integer absolute/squared totals; MAE=sum(abs)/N; RMSE=sqrt(sum(square)/N); PSNR=10*log10(peak^2/(sum(square)/N)), peak=2^bit_depth-1; zero squared error gives positive infinity."
            .into(),
        alignment: "Identical stored width, height, channel layout and bit depth; corresponding row-major pixels/channels, including every alpha sample; 16-bit samples read big-endian."
            .into(),
        units: "Absolute totals, maximum, MAE and RMSE: sample-code units; squared totals: sample-code units squared; PSNR: decibels."
            .into(),
        denominator: "N=sample_count=pixel_count*channel_count, including alpha; no masked or excluded samples."
            .into(),
        limitations: vec![
            "Static PNG output comparison only; no video frames, temporal consistency, audio or latent tensors are assessed.".into(),
            "Encoded equality and decoded sample equality are distinct; neither establishes visual or perceptual equivalence. No gamma, ICC/profile, color-space, EXIF orientation, compositing, premultiplication, resizing or cropping transform is applied.".into(),
            "Numerical bounds are caller-declared sample-code limits, not quality thresholds; low error or high PSNR does not establish prompt adherence or absence of artifacts.".into(),
            "Output files do not establish identical operator inputs, seeds, model, runtime or workload, or a controlled baseline experiment; no speed, memory or performance equivalence is measured.".into(),
            "Reviewer identity, protocol and observations are caller-supplied and not authenticated or independently verified by this tool; the assessment remains independent of numerical classification.".into(),
            "The side-by-side inspection sheet preserves sample values but omits ancillary metadata; it is not evidence of color-managed visual equivalence.".into(),
        ],
    })
}
