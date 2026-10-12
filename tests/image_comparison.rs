use std::fs::File;

use media_inference_lab::{
    image_comparison::{
        ImageAssessment, ImageComparisonReport, MAX_ASSESSMENT_LIMITATIONS, MAX_TEXT_BYTES,
        NumericalClassification, Psnr, Tolerance, compare,
    },
    png_image::{DecodedPng, SampleColor, decode},
    schema::Observation,
};
use serde_json::json;

fn image(width: u32, height: u32, color: SampleColor, bit_depth: u8, samples: &[u8]) -> DecodedPng {
    image_with_text(width, height, color, bit_depth, samples, None)
}

fn image_with_text(
    width: u32,
    height: u32,
    color: SampleColor,
    bit_depth: u8,
    samples: &[u8],
    text: Option<&str>,
) -> DecodedPng {
    let root = tempfile::tempdir().unwrap();
    let path = root.path().join("generated.png");
    let mut encoder = png::Encoder::new(File::create(&path).unwrap(), width, height);
    encoder.set_color(match color {
        SampleColor::Gray => png::ColorType::Grayscale,
        SampleColor::GrayAlpha => png::ColorType::GrayscaleAlpha,
        SampleColor::Rgb => png::ColorType::Rgb,
        SampleColor::Rgba => png::ColorType::Rgba,
    });
    encoder.set_depth(match bit_depth {
        8 => png::BitDepth::Eight,
        16 => png::BitDepth::Sixteen,
        _ => panic!("test helper requires supported sample depth"),
    });
    if let Some(text) = text {
        encoder
            .add_text_chunk("fixture".into(), text.into())
            .unwrap();
    }
    let mut writer = encoder.write_header().unwrap();
    writer.write_image_data(samples).unwrap();
    writer.finish().unwrap();
    decode(&path).unwrap()
}

fn bound(max_absolute_error: u16) -> Tolerance {
    Tolerance {
        max_absolute_error,
        rationale: "Generated CPU fixture permits this many integer sample-code steps; not a visual threshold."
            .into(),
    }
}

fn assessment(baseline: &DecodedPng, candidate: &DecodedPng) -> ImageAssessment {
    ImageAssessment {
        schema_version: 1,
        baseline_sha256: baseline.identity().sha256.clone(),
        candidate_sha256: candidate.identity().sha256.clone(),
        reviewer: "Synthetic test record, not an actual human reviewer".into(),
        protocol:
            "Schema fixture for externally supplied observations; no visual evaluation performed."
                .into(),
        prompt_adherence: Observation::Unavailable {
            reason: "Generated samples have no source prompt.".into(),
        },
        artifacts: Observation::Available {
            value:
                "Fixture observation: artifacts remain reported even with exact numerical samples."
                    .into(),
        },
        limitations: vec!["Synthetic record does not establish image quality.".into()],
    }
}

fn near(actual: f64, expected: f64) {
    assert!((actual - expected).abs() < 1e-10, "{actual} != {expected}");
}

#[test]
fn eight_bit_metrics_preserve_integer_totals_and_all_sample_denominators() {
    let baseline = image(2, 1, SampleColor::Rgba, 8, &[0, 10, 20, 30, 40, 50, 60, 70]);
    let candidate = image(2, 1, SampleColor::Rgba, 8, &[0, 12, 17, 34, 35, 56, 53, 78]);
    let report = compare(&baseline, &candidate, None, None, None).unwrap();
    let metrics = &report.metrics;
    assert_eq!(metrics.pixel_count, 2);
    assert_eq!(metrics.channel_count, 4);
    assert_eq!(metrics.sample_count, 8);
    assert_eq!(metrics.peak_sample_value, 255);
    assert_eq!(metrics.absolute_error_sum, 35);
    assert_eq!(metrics.squared_error_sum, 203);
    assert_eq!(metrics.max_absolute_error, 8);
    near(metrics.mean_absolute_error, 4.375);
    near(metrics.root_mean_squared_error, 25.375_f64.sqrt());
    match metrics.psnr {
        Psnr::Finite { decibels } => near(decibels, 10.0 * (65025.0_f64 / 25.375).log10()),
        Psnr::PositiveInfinity => panic!("different samples must have finite PSNR"),
    }
    assert!(!metrics.decoded_equal);
    assert!(!metrics.encoded_equal);
    assert_eq!(
        report.classification,
        NumericalClassification::DifferentUnbounded
    );
    assert!(!report.is_within_numerical_bound());
}

#[test]
fn alpha_is_compared_without_compositing_or_masking() {
    let baseline = image(1, 1, SampleColor::Rgba, 8, &[10, 20, 30, 0]);
    let candidate = image(1, 1, SampleColor::Rgba, 8, &[10, 20, 30, 1]);
    let report = compare(&baseline, &candidate, None, None, None).unwrap();
    assert_eq!(report.metrics.sample_count, 4);
    assert_eq!(report.metrics.absolute_error_sum, 1);
    near(report.metrics.mean_absolute_error, 0.25);
    near(report.metrics.root_mean_squared_error, 0.5);

    let transparent_changed = image(1, 1, SampleColor::Rgba, 8, &[11, 20, 30, 0]);
    let transparent = compare(&baseline, &transparent_changed, None, None, None).unwrap();
    assert_eq!(transparent.metrics.absolute_error_sum, 1);
    assert!(!transparent.metrics.decoded_equal);
}

#[test]
fn sixteen_bit_low_order_differences_are_not_quantized_to_eight_bits() {
    let baseline = image(2, 1, SampleColor::Gray, 16, &[0x12, 0x34, 0xff, 0xff]);
    let candidate = image(2, 1, SampleColor::Gray, 16, &[0x12, 0x35, 0xff, 0xfe]);
    let report = compare(&baseline, &candidate, None, Some(bound(1)), None).unwrap();
    assert_eq!(report.metrics.sample_count, 2);
    assert_eq!(report.metrics.peak_sample_value, 65535);
    assert_eq!(report.metrics.absolute_error_sum, 2);
    assert_eq!(report.metrics.squared_error_sum, 2);
    assert_eq!(report.metrics.max_absolute_error, 1);
    near(report.metrics.mean_absolute_error, 1.0);
    near(report.metrics.root_mean_squared_error, 1.0);
    match report.metrics.psnr {
        Psnr::Finite { decibels } => near(decibels, 20.0 * 65535.0_f64.log10()),
        Psnr::PositiveInfinity => panic!("low-order differences must be retained"),
    }
    assert_eq!(
        report.classification,
        NumericalClassification::WithinTolerance
    );
}

#[test]
fn sixteen_bit_endianness_and_large_squared_error_use_integer_precision() {
    let baseline = image(4, 1, SampleColor::Gray, 16, &[0, 0, 0, 255, 1, 0, 255, 255]);
    let candidate = image(4, 1, SampleColor::Gray, 16, &[255, 255, 1, 0, 0, 255, 0, 0]);
    let report = compare(&baseline, &candidate, None, Some(bound(65535)), None).unwrap();
    assert_eq!(report.metrics.absolute_error_sum, 131072);
    assert_eq!(report.metrics.squared_error_sum, 8589672452);
    assert_eq!(report.metrics.max_absolute_error, 65535);
    near(report.metrics.mean_absolute_error, 32768.0);
    assert!(report.is_within_numerical_bound());
}

#[test]
fn sixteen_bit_gray_alpha_counts_full_precision_alpha_samples() {
    let baseline = image(1, 1, SampleColor::GrayAlpha, 16, &[0x12, 0x34, 0xab, 0xcd]);
    let candidate = image(1, 1, SampleColor::GrayAlpha, 16, &[0x12, 0x34, 0xab, 0xce]);
    let report = compare(&baseline, &candidate, None, None, None).unwrap();
    assert_eq!(report.metrics.channel_count, 2);
    assert_eq!(report.metrics.sample_count, 2);
    assert_eq!(report.metrics.absolute_error_sum, 1);
    assert_eq!(report.metrics.squared_error_sum, 1);
    assert_eq!(report.metrics.max_absolute_error, 1);
    near(report.metrics.mean_absolute_error, 0.5);
    near(report.metrics.root_mean_squared_error, 0.5_f64.sqrt());
}

#[test]
fn encoded_identity_is_separate_from_exact_decoded_samples_and_infinite_psnr() {
    let baseline = image(1, 1, SampleColor::Gray, 8, &[42]);
    let candidate = image_with_text(1, 1, SampleColor::Gray, 8, &[42], Some("metadata differs"));
    assert_ne!(baseline.identity().sha256, candidate.identity().sha256);
    assert_eq!(
        baseline.identity().decoded_sha256,
        candidate.identity().decoded_sha256
    );
    let report = compare(&baseline, &candidate, None, None, None).unwrap();
    assert_eq!(report.classification, NumericalClassification::ExactDecoded);
    assert!(report.is_within_numerical_bound());
    assert!(!report.metrics.encoded_equal);
    assert!(report.metrics.decoded_equal);
    assert_eq!(report.metrics.psnr, Psnr::PositiveInfinity);
    assert_eq!(report.metrics.absolute_error_sum, 0);
    assert_eq!(report.metrics.squared_error_sum, 0);
    let encoded = serde_json::to_value(&report).unwrap();
    assert_eq!(
        encoded["metrics"]["psnr"],
        json!({"kind": "positive_infinity"})
    );
    let decoded: ImageComparisonReport = serde_json::from_value(encoded).unwrap();
    assert_eq!(decoded.metrics.psnr, Psnr::PositiveInfinity);
    let same = compare(&baseline, &baseline, None, None, None).unwrap();
    assert!(same.metrics.encoded_equal);
}

#[test]
fn numerical_classification_requires_an_explicit_nonrelaxed_maximum_bound() {
    let baseline = image(2, 1, SampleColor::Gray, 8, &[10, 10]);
    let candidate = image(2, 1, SampleColor::Gray, 8, &[10, 12]);
    for (tolerance, classification, within) in [
        (None, NumericalClassification::DifferentUnbounded, false),
        (
            Some(bound(0)),
            NumericalClassification::OutsideTolerance,
            false,
        ),
        (
            Some(bound(1)),
            NumericalClassification::OutsideTolerance,
            false,
        ),
        (
            Some(bound(2)),
            NumericalClassification::WithinTolerance,
            true,
        ),
    ] {
        let report = compare(&baseline, &candidate, None, tolerance.clone(), None).unwrap();
        assert_eq!(report.classification, classification);
        assert_eq!(report.is_within_numerical_bound(), within);
        assert_eq!(
            report.tolerance.map(|value| value.max_absolute_error),
            tolerance.map(|value| value.max_absolute_error)
        );
    }
}

#[test]
fn tolerance_rejects_invalid_rationale_and_out_of_dtype_bound_even_when_exact() {
    let baseline = image(1, 1, SampleColor::Gray, 8, &[10]);
    for rationale in [
        "".into(),
        " \n".into(),
        "bad\0text".into(),
        "x".repeat(MAX_TEXT_BYTES + 1),
    ] {
        let tolerance = Tolerance {
            max_absolute_error: 0,
            rationale,
        };
        assert!(compare(&baseline, &baseline, None, Some(tolerance), None).is_err());
    }
    assert!(compare(&baseline, &baseline, None, Some(bound(256)), None).is_err());
    let report = compare(&baseline, &baseline, None, Some(bound(0)), None).unwrap();
    assert_eq!(report.classification, NumericalClassification::ExactDecoded);
}

#[test]
fn shape_color_and_depth_mismatches_are_rejected_for_candidates_and_repeats() {
    let baseline = image(2, 1, SampleColor::Gray, 8, &[0, 1]);
    let wrong_shapes = [
        image(1, 2, SampleColor::Gray, 8, &[0, 1]),
        image(1, 1, SampleColor::Gray, 8, &[0]),
        image(2, 1, SampleColor::GrayAlpha, 8, &[0, 255, 1, 255]),
        image(2, 1, SampleColor::Gray, 16, &[0, 0, 0, 1]),
    ];
    for other in wrong_shapes {
        assert!(compare(&baseline, &other, None, None, None).is_err());
        assert!(compare(&baseline, &baseline, Some(&other), None, None).is_err());
    }
}

#[test]
fn baseline_variation_is_retained_without_changing_candidate_classification() {
    let baseline = image(2, 1, SampleColor::Gray, 8, &[10, 20]);
    let candidate = image(2, 1, SampleColor::Gray, 8, &[10, 21]);
    let repeat = image(2, 1, SampleColor::Gray, 8, &[30, 20]);
    let report = compare(&baseline, &candidate, Some(&repeat), Some(bound(1)), None).unwrap();
    assert!(report.is_within_numerical_bound());
    assert_eq!(report.metrics.max_absolute_error, 1);
    assert_eq!(
        report.baseline_repeat.as_ref().unwrap().sha256,
        repeat.identity().sha256
    );
    match report.baseline_repeat_metrics {
        Observation::Available { value } => {
            assert_eq!(value.absolute_error_sum, 20);
            assert_eq!(value.squared_error_sum, 400);
            assert_eq!(value.max_absolute_error, 20);
            near(value.mean_absolute_error, 10.0);
        }
        Observation::Unavailable { .. } => panic!("repeat must be independently measured"),
    }
    let absent = compare(&baseline, &candidate, None, None, None).unwrap();
    assert!(absent.baseline_repeat.is_none());
    match absent.baseline_repeat_metrics {
        Observation::Unavailable { reason } => assert!(!reason.trim().is_empty()),
        Observation::Available { .. } => panic!("variation must not be invented"),
    }
}

#[test]
fn reviewer_observations_remain_independent_of_exact_numerical_results() {
    let baseline = image(1, 1, SampleColor::Rgb, 8, &[10, 20, 30]);
    let supplied = assessment(&baseline, &baseline);
    let report = compare(&baseline, &baseline, None, None, Some(supplied.clone())).unwrap();
    assert!(report.is_within_numerical_bound());
    match report.assessment {
        Observation::Available { value } => {
            assert_eq!(value.prompt_adherence, supplied.prompt_adherence);
            assert_eq!(value.artifacts, supplied.artifacts);
            assert_eq!(value.limitations, supplied.limitations);
            assert_eq!(value.baseline_sha256, baseline.identity().sha256);
        }
        Observation::Unavailable { .. } => panic!("supplied observations must be retained"),
    }
    let unassessed = compare(&baseline, &baseline, None, None, None).unwrap();
    match unassessed.assessment {
        Observation::Unavailable { reason } => assert!(!reason.trim().is_empty()),
        Observation::Available { .. } => panic!("exactness must not invent a reviewer assessment"),
    }
}

#[test]
fn assessment_hashes_bind_encoded_inputs_not_just_equal_decoded_samples() {
    let baseline = image(1, 1, SampleColor::Gray, 8, &[42]);
    let candidate = image_with_text(1, 1, SampleColor::Gray, 8, &[42], Some("different input"));
    let valid = assessment(&baseline, &candidate);
    let mut wrong_candidate = valid.clone();
    wrong_candidate.candidate_sha256 = baseline.identity().sha256.clone();
    assert!(compare(&baseline, &candidate, None, None, Some(wrong_candidate)).is_err());
    let mut wrong_baseline = valid.clone();
    wrong_baseline.baseline_sha256 = candidate.identity().sha256.clone();
    assert!(compare(&baseline, &candidate, None, None, Some(wrong_baseline)).is_err());
    let mut decoded_hash = valid.clone();
    decoded_hash.baseline_sha256 = baseline.identity().decoded_sha256.clone();
    assert!(compare(&baseline, &candidate, None, None, Some(decoded_hash)).is_err());
    let report = compare(&baseline, &candidate, None, None, Some(valid)).unwrap();
    assert_eq!(report.baseline.sha256, baseline.identity().sha256);
    assert_eq!(report.candidate.sha256, candidate.identity().sha256);
    assert_eq!(report.classification, NumericalClassification::ExactDecoded);
}

#[test]
fn assessment_rejects_unsupported_version_missing_disclosures_and_empty_observations() {
    let baseline = image(1, 1, SampleColor::Gray, 8, &[0]);
    let valid = assessment(&baseline, &baseline);
    let alterations: [fn(&mut ImageAssessment); 12] = [
        |value| value.schema_version = 2,
        |value| value.reviewer.clear(),
        |value| value.protocol = " \n".into(),
        |value| value.reviewer = "x".repeat(MAX_TEXT_BYTES + 1),
        |value| value.protocol = "bad\0protocol".into(),
        |value| value.limitations.clear(),
        |value| value.limitations = vec![" ".into()],
        |value| value.limitations = vec!["limitation".into(); MAX_ASSESSMENT_LIMITATIONS + 1],
        |value| value.limitations = vec!["x".repeat(MAX_TEXT_BYTES + 1)],
        |value| value.prompt_adherence = Observation::Available { value: "".into() },
        |value| value.artifacts = Observation::Unavailable { reason: "".into() },
        |value| {
            value.artifacts = Observation::Available {
                value: "x".repeat(MAX_TEXT_BYTES + 1),
            }
        },
    ];
    for alter in alterations {
        let mut invalid = valid.clone();
        alter(&mut invalid);
        assert!(compare(&baseline, &baseline, None, None, Some(invalid)).is_err());
    }
}

#[test]
fn strict_schemas_reject_unknown_assessment_tolerance_report_and_metric_fields() {
    let baseline = image(1, 1, SampleColor::Gray, 8, &[0]);
    let mut assessment_json = serde_json::to_value(assessment(&baseline, &baseline)).unwrap();
    assessment_json["automatic_quality_verdict"] = json!("equivalent");
    assert!(serde_json::from_value::<ImageAssessment>(assessment_json).is_err());
    assert!(
        serde_json::from_value::<Tolerance>(json!({
            "max_absolute_error": 1, "rationale": "one code step", "relax": true
        }))
        .is_err()
    );
    let report = compare(&baseline, &baseline, None, None, None).unwrap();
    let mut report_json = serde_json::to_value(&report).unwrap();
    report_json["visual_equivalence"] = json!(true);
    assert!(serde_json::from_value::<ImageComparisonReport>(report_json).is_err());
    let mut metrics_json = serde_json::to_value(&report).unwrap();
    metrics_json["metrics"]["ignored_alpha"] = json!(true);
    assert!(serde_json::from_value::<ImageComparisonReport>(metrics_json).is_err());
}
