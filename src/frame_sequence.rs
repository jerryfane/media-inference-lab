use std::path::{Path, PathBuf};

use anyhow::{Context, Result, ensure};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::{
    image_comparison::{
        self, ImageMetrics, MAX_ASSESSMENT_LIMITATIONS, MAX_TEXT_BYTES, NumericalClassification,
        Psnr, Tolerance,
    },
    png_image::{self, DecodedPng, PngIdentity},
    schema::Observation,
};

pub const MAX_FRAMES: usize = 1024;
pub const MAX_ENCODED_TOTAL: u64 = 512 * 1024 * 1024;
pub const MAX_DECODED_PER_ROLE: u64 = 512 * 1024 * 1024;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FrameInput {
    pub index: u32,
    pub path: PathBuf,
    pub pts_ns: u64,
    pub duration_ns: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SequenceInput {
    pub schema_version: u32,
    pub frame_count: u32,
    pub provenance: String,
    pub frames: Vec<FrameInput>,
}

impl SequenceInput {
    pub fn validate(&self) -> Result<()> {
        ensure!(
            self.schema_version == 1,
            "unsupported sequence schema version"
        );
        ensure!(
            (1..=MAX_FRAMES).contains(&(self.frame_count as usize))
                && self.frames.len() == self.frame_count as usize,
            "declared frame_count must be 1..={MAX_FRAMES} and match every listed frame"
        );
        text(&self.provenance, "sequence.provenance")?;
        let mut next_pts = 0_u64;
        for (index, frame) in self.frames.iter().enumerate() {
            ensure!(
                frame.index as usize == index,
                "frame indices must be ordered 0..frame_count-1"
            );
            ensure!(
                frame.duration_ns > 0,
                "frame {index} duration must be positive"
            );
            ensure!(
                frame.pts_ns == next_pts,
                "frame {index} timeline must start at zero and be contiguous without gaps or overlaps"
            );
            next_pts = frame
                .pts_ns
                .checked_add(frame.duration_ns)
                .with_context(|| format!("frame {index} end time overflows u64"))?;
            let path = frame.path.to_str().context("frame path must be UTF-8")?;
            ensure!(
                !path.is_empty() && !path.contains('\0') && path.len() <= MAX_TEXT_BYTES,
                "frame {index} path must be nonempty, contain no NUL, and be at most {MAX_TEXT_BYTES} UTF-8 bytes"
            );
        }
        Ok(())
    }

    // Called only after validation, including checked last-frame end time.
    fn duration_ns(&self) -> u64 {
        let last = self.frames.last().expect("validated nonempty sequence");
        last.pts_ns + last.duration_ns
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SequenceAssessment {
    pub schema_version: u32,
    pub baseline_sha256: String,
    pub candidate_sha256: String,
    pub reviewer: String,
    pub protocol: String,
    pub prompt_adherence: Observation<String>,
    pub artifacts: Observation<String>,
    pub temporal_consistency: Observation<String>,
    pub audio: Observation<String>,
    pub limitations: Vec<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct SequenceIdentity {
    pub sha256: String,
    pub frame_count: u32,
    pub duration_ns: u64,
}

#[derive(Debug, Clone, Serialize)]
pub struct SequenceFrame {
    pub index: u32,
    pub pts_ns: u64,
    pub duration_ns: u64,
    pub baseline: PngIdentity,
    pub candidate: PngIdentity,
    pub baseline_repeat: Option<PngIdentity>,
    pub metrics: ImageMetrics,
    pub baseline_repeat_metrics: Observation<ImageMetrics>,
}

#[derive(Debug, Clone, Serialize)]
pub struct SequenceReport {
    pub schema_version: u32,
    pub kind: String,
    pub baseline_input: SequenceInput,
    pub candidate_input: SequenceInput,
    pub baseline_repeat_input: Option<SequenceInput>,
    pub baseline: SequenceIdentity,
    pub candidate: SequenceIdentity,
    pub baseline_repeat: Option<SequenceIdentity>,
    pub frames: Vec<SequenceFrame>,
    pub metrics: ImageMetrics,
    pub baseline_repeat_metrics: Observation<ImageMetrics>,
    pub classification: NumericalClassification,
    pub tolerance: Option<Tolerance>,
    pub assessment: Observation<SequenceAssessment>,
    pub limitations: Vec<String>,
}

impl SequenceReport {
    /// Numerical agreement only, not a visual, temporal or performance verdict.
    pub fn is_within_numerical_bound(&self) -> bool {
        matches!(
            self.classification,
            NumericalClassification::ExactDecoded | NumericalClassification::WithinTolerance
        )
    }
}

pub struct SequenceSource<'a> {
    pub input: &'a SequenceInput,
    pub directory: &'a Path,
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

fn validate_assessment(assessment: &SequenceAssessment) -> Result<()> {
    ensure!(
        assessment.schema_version == 1,
        "unsupported sequence assessment schema version"
    );
    for hash in [&assessment.baseline_sha256, &assessment.candidate_sha256] {
        ensure!(
            hash.len() == 64
                && hash
                    .bytes()
                    .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte)),
            "assessment sequence hashes must be 64 lowercase hexadecimal characters"
        );
    }
    text(&assessment.reviewer, "assessment.reviewer")?;
    text(&assessment.protocol, "assessment.protocol")?;
    observation(&assessment.prompt_adherence, "assessment.prompt_adherence")?;
    observation(&assessment.artifacts, "assessment.artifacts")?;
    observation(
        &assessment.temporal_consistency,
        "assessment.temporal_consistency",
    )?;
    ensure!(
        matches!(assessment.audio, Observation::Unavailable { .. }),
        "assessment audio must be unavailable: this comparison has no decoded audio to bind"
    );
    observation(&assessment.audio, "assessment.audio")?;
    ensure!(
        assessment.limitations.len() <= MAX_ASSESSMENT_LIMITATIONS,
        "assessment must declare at most {MAX_ASSESSMENT_LIMITATIONS} limitations"
    );
    for limitation in &assessment.limitations {
        text(limitation, "assessment.limitations entry")?;
    }
    Ok(())
}

pub fn validate_inputs(
    baseline: &SequenceInput,
    candidate: &SequenceInput,
    repeat: Option<&SequenceInput>,
    tolerance: Option<&Tolerance>,
    assessment: Option<&SequenceAssessment>,
) -> Result<()> {
    baseline.validate().context("invalid baseline sequence")?;
    candidate.validate().context("invalid candidate sequence")?;
    if let Some(repeat) = repeat {
        repeat
            .validate()
            .context("invalid baseline-repeat sequence")?;
    }
    for (role, other) in std::iter::once(("candidate", candidate))
        .chain(repeat.map(|input| ("baseline-repeat", input)))
    {
        ensure!(
            baseline.frame_count == other.frame_count,
            "{role} frame count must match baseline"
        );
        for (left, right) in baseline.frames.iter().zip(&other.frames) {
            ensure!(
                left.pts_ns == right.pts_ns && left.duration_ns == right.duration_ns,
                "{role} frame {} must have exactly the baseline presentation time and duration",
                left.index
            );
        }
    }
    if let Some(tolerance) = tolerance {
        text(&tolerance.rationale, "tolerance.rationale")?;
    }
    if let Some(assessment) = assessment {
        validate_assessment(assessment)?;
    }
    Ok(())
}

#[derive(Default)]
struct ByteBudget {
    encoded: u64,
    decoded: [u64; 3],
}

impl ByteBudget {
    fn charge(&mut self, role: usize, encoded: u64, decoded: u64) -> Result<()> {
        let encoded = self
            .encoded
            .checked_add(encoded)
            .context("encoded byte total overflow")?;
        let decoded = self.decoded[role]
            .checked_add(decoded)
            .context("decoded byte total overflow")?;
        ensure!(
            encoded <= MAX_ENCODED_TOTAL,
            "sequence exceeds cumulative encoded byte limit across all supplied roles"
        );
        ensure!(
            decoded <= MAX_DECODED_PER_ROLE,
            "sequence exceeds cumulative decoded byte limit for a role"
        );
        self.encoded = encoded;
        self.decoded[role] = decoded;
        Ok(())
    }
}

fn decode_frame(
    source: &SequenceSource<'_>,
    index: usize,
    role: usize,
    budget: &mut ByteBudget,
) -> Result<DecodedPng> {
    let path = &source.input.frames[index].path;
    let decoded = if path.is_absolute() {
        png_image::decode(path)
    } else {
        png_image::decode(&source.directory.join(path))
    }
    .with_context(|| format!("decoding role {role} frame {index}"))?;
    budget.charge(
        role,
        decoded.identity().bytes,
        decoded.samples().len() as u64,
    )?;
    Ok(decoded)
}

fn identity_hasher(input: &SequenceInput) -> Sha256 {
    let mut hasher = Sha256::new();
    hasher.update(b"mil-png-sequence-v1\0");
    hasher.update(u64::from(input.frame_count).to_be_bytes());
    hasher.update(input.duration_ns().to_be_bytes());
    hasher
}

fn hash_frame(hasher: &mut Sha256, input: &FrameInput, png: &PngIdentity) {
    hasher.update(u64::from(input.index).to_be_bytes());
    hasher.update(input.pts_ns.to_be_bytes());
    hasher.update(input.duration_ns.to_be_bytes());
    hasher.update(png.sha256.as_bytes());
}

fn finish_identity(hasher: Sha256, input: &SequenceInput) -> SequenceIdentity {
    SequenceIdentity {
        sha256: format!("{:x}", hasher.finalize()),
        frame_count: input.frame_count,
        duration_ns: input.duration_ns(),
    }
}

fn accumulate(total: &mut Option<ImageMetrics>, frame: &ImageMetrics) -> Result<()> {
    let Some(total) = total else {
        *total = Some(frame.clone());
        return Ok(());
    };
    ensure!(
        total.channel_count == frame.channel_count
            && total.peak_sample_value == frame.peak_sample_value,
        "cannot aggregate different sample layouts"
    );
    total.pixel_count = total
        .pixel_count
        .checked_add(frame.pixel_count)
        .context("pixel count overflow")?;
    total.sample_count = total
        .sample_count
        .checked_add(frame.sample_count)
        .context("sample count overflow")?;
    total.absolute_error_sum = total
        .absolute_error_sum
        .checked_add(frame.absolute_error_sum)
        .context("absolute error total overflow")?;
    total.squared_error_sum = total
        .squared_error_sum
        .checked_add(frame.squared_error_sum)
        .context("squared error total overflow")?;
    total.max_absolute_error = total.max_absolute_error.max(frame.max_absolute_error);
    total.encoded_equal &= frame.encoded_equal;
    total.decoded_equal &= frame.decoded_equal;
    Ok(())
}

fn finish_metrics(mut total: ImageMetrics) -> ImageMetrics {
    let mean_squared_error = total.squared_error_sum as f64 / total.sample_count as f64;
    total.mean_absolute_error = total.absolute_error_sum as f64 / total.sample_count as f64;
    total.root_mean_squared_error = mean_squared_error.sqrt();
    total.psnr = if total.squared_error_sum == 0 {
        Psnr::PositiveInfinity
    } else {
        Psnr::Finite {
            decibels: 10.0
                * (f64::from(total.peak_sample_value).powi(2) / mean_squared_error).log10(),
        }
    };
    total
}

fn repeat_metrics(metrics: Option<ImageMetrics>) -> Observation<ImageMetrics> {
    match metrics {
        Some(value) => Observation::Available { value },
        None => Observation::Unavailable {
            reason: "No separate baseline-repeat sequence was supplied; baseline variation is unmeasured.".into(),
        },
    }
}

pub fn compare(
    baseline: SequenceSource<'_>,
    candidate: SequenceSource<'_>,
    repeat: Option<SequenceSource<'_>>,
    tolerance: Option<Tolerance>,
    assessment: Option<SequenceAssessment>,
    mut visit: impl FnMut(u32, &DecodedPng, &DecodedPng, Option<&DecodedPng>) -> Result<()>,
) -> Result<SequenceReport> {
    validate_inputs(
        baseline.input,
        candidate.input,
        repeat.as_ref().map(|source| source.input),
        tolerance.as_ref(),
        assessment.as_ref(),
    )?;
    let mut baseline_hash = identity_hasher(baseline.input);
    let mut candidate_hash = identity_hasher(candidate.input);
    let mut repeat_hash = repeat.as_ref().map(|source| identity_hasher(source.input));
    let mut frames = Vec::with_capacity(baseline.input.frames.len());
    let mut budget = ByteBudget::default();
    let mut shape = None;
    let mut totals = None;
    let mut repeat_totals = None;
    for (index, input) in baseline.input.frames.iter().enumerate() {
        // Only this frame's two or three rasters and encoded snapshots are retained.
        let left = decode_frame(&baseline, index, 0, &mut budget)?;
        let right = decode_frame(&candidate, index, 1, &mut budget)?;
        let repeated = repeat
            .as_ref()
            .map(|source| decode_frame(source, index, 2, &mut budget))
            .transpose()?;
        image_comparison::validate_alignment(&left, &right)
            .with_context(|| format!("candidate frame {index} alignment"))?;
        if let Some(repeated) = &repeated {
            image_comparison::validate_alignment(&left, repeated)
                .with_context(|| format!("baseline-repeat frame {index} alignment"))?;
        }
        let identity = left.identity();
        let current_shape = (
            identity.width,
            identity.height,
            identity.color,
            identity.bit_depth,
        );
        if let Some(shape) = shape {
            ensure!(
                shape == current_shape,
                "frame {index} changes sequence width, height, channel layout or bit depth"
            );
        } else {
            shape = Some(current_shape);
            if let Some(tolerance) = &tolerance {
                ensure!(
                    identity.bit_depth == 16 || tolerance.max_absolute_error <= 255,
                    "tolerance exceeds the maximum sample code for the input bit depth"
                );
            }
        }
        let metrics = image_comparison::metrics(&left, &right);
        accumulate(&mut totals, &metrics)?;
        let frame_repeat_metrics = repeated
            .as_ref()
            .map(|repeated| image_comparison::metrics(&left, repeated));
        if let Some(metrics) = &frame_repeat_metrics {
            accumulate(&mut repeat_totals, metrics)?;
        }
        hash_frame(&mut baseline_hash, input, identity);
        hash_frame(
            &mut candidate_hash,
            &candidate.input.frames[index],
            right.identity(),
        );
        if let (Some(hasher), Some(source), Some(decoded)) = (&mut repeat_hash, &repeat, &repeated)
        {
            hash_frame(hasher, &source.input.frames[index], decoded.identity());
        }
        visit(input.index, &left, &right, repeated.as_ref())
            .with_context(|| format!("visiting frame {index}"))?;
        frames.push(SequenceFrame {
            index: input.index,
            pts_ns: input.pts_ns,
            duration_ns: input.duration_ns,
            baseline: identity.clone(),
            candidate: right.identity().clone(),
            baseline_repeat: repeated.as_ref().map(|decoded| decoded.identity().clone()),
            metrics,
            baseline_repeat_metrics: repeat_metrics(frame_repeat_metrics),
        });
    }
    let baseline_identity = finish_identity(baseline_hash, baseline.input);
    let candidate_identity = finish_identity(candidate_hash, candidate.input);
    let repeat_identity = repeat_hash
        .zip(repeat.as_ref())
        .map(|(hasher, source)| finish_identity(hasher, source.input));
    if let Some(assessment) = &assessment {
        ensure!(
            assessment.baseline_sha256 == baseline_identity.sha256
                && assessment.candidate_sha256 == candidate_identity.sha256,
            "assessment hashes must match the complete baseline and candidate sequence identities"
        );
    }
    let metrics = finish_metrics(totals.expect("validated nonempty sequence"));
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
    Ok(SequenceReport {
        schema_version: 1,
        kind: "png_sequence_output_comparison".into(),
        baseline_input: baseline.input.clone(),
        candidate_input: candidate.input.clone(),
        baseline_repeat_input: repeat.as_ref().map(|source| source.input.clone()),
        baseline: baseline_identity,
        candidate: candidate_identity,
        baseline_repeat: repeat_identity,
        frames,
        metrics,
        baseline_repeat_metrics: repeat_metrics(repeat_totals.map(finish_metrics)),
        classification,
        tolerance,
        assessment: match assessment {
            Some(value) => Observation::Available { value },
            None => Observation::Unavailable {
                reason: "No hash-bound assessment was supplied; prompt adherence, artifacts and temporal consistency are unassessed. Audio is unavailable.".into(),
            },
        },
        limitations: vec![
            "Every declared PNG frame is compared in order without sampling. This verifies only the declared sequence, not original container completeness, extraction correctness, frame rate or decoding fidelity. No compressed video, audio or latent tensors are decoded or assessed.".into(),
            "Sequence identity is SHA-256 over domain bytes b\"mil-png-sequence-v1\\0\", frame_count as u64 big-endian, total duration_ns as u64 big-endian, then for every ordered frame: index, pts_ns and duration_ns each as u64 big-endian, followed by its encoded PNG SHA-256 as 64 lowercase ASCII bytes. Paths and provenance are excluded; encoded contents and declared timing are bound.".into(),
            "Integer absolute and squared error totals include all corresponding frames, pixels and channels including alpha. N is total sample_count, not time-weighted; MAE=sum(abs)/N; RMSE=sqrt(sum(square)/N); PSNR=10*log10(peak^2/(sum(square)/N)), peak=2^bit_depth-1, with positive infinity for zero error. Per-frame MAE or PSNR is never averaged. Encoded and decoded equality each require equality in every corresponding frame, not manifest or container equality.".into(),
            "Stored width, height, channel layout and bit depth must remain constant across all frames and roles, with exactly matching declared intervals. No alignment search, interpolation, gamma, ICC/profile, color-space, orientation, compositing, premultiplication, resizing or cropping transform is applied; 16-bit samples retain full big-endian precision.".into(),
            "Numerical classification and caller-declared tolerance are sample-code comparisons, not image quality, prompt adherence, temporal quality or performance verdicts. Independent supplied observations never change numerical classification.".into(),
            "Source paths, extraction/alignment provenance, reviewer identity, protocol and observations are unverified caller declarations, not authentication. Output agreement does not establish identical seeds, models, workloads, runtimes or an independent controlled baseline experiment. A separate repeat measures only its supplied output differences; absence means unmeasured variation.".into(),
            "Limits: 1..=1024 frames per declared sequence; at most 512 MiB cumulative encoded PNG bytes across all supplied roles and 512 MiB cumulative decoded sample bytes per role. Each PNG also obeys the strict decoder's 32 MiB encoded, 16,777,216 pixel and 128 MiB decoded limits. At most three decoded frame rasters are retained simultaneously. There is no wallclock deadline; bounded bytes/counts do not prevent filesystem stalls.".into(),
        ],
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn byte_limits_include_every_role_and_reject_before_committing_overage() {
        let mut budget = ByteBudget::default();
        budget
            .charge(0, MAX_ENCODED_TOTAL - 2, MAX_DECODED_PER_ROLE)
            .unwrap();
        budget.charge(1, 1, MAX_DECODED_PER_ROLE).unwrap();
        budget.charge(2, 1, MAX_DECODED_PER_ROLE).unwrap();
        assert!(budget.charge(0, 1, 0).is_err());
        assert!(budget.charge(1, 0, 1).is_err());
        assert!(budget.charge(2, u64::MAX, 0).is_err());
        assert!(budget.charge(0, 0, u64::MAX).is_err());
        assert_eq!(budget.encoded, MAX_ENCODED_TOTAL);
        assert_eq!(budget.decoded, [MAX_DECODED_PER_ROLE; 3]);
    }
}
