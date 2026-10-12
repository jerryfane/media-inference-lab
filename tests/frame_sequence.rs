use std::{
    fs::{self, File},
    path::{Path, PathBuf},
};

use media_inference_lab::{
    frame_sequence::{
        FrameInput, MAX_FRAMES, SequenceAssessment, SequenceInput, SequenceReport, SequenceSource,
        compare, validate_inputs,
    },
    image_comparison::{NumericalClassification, Psnr, Tolerance},
    schema::Observation,
};
use sha2::{Digest, Sha256};

fn png(
    root: &Path,
    name: &str,
    width: u32,
    color: png::ColorType,
    depth: png::BitDepth,
    samples: &[u8],
    metadata: Option<&str>,
) -> PathBuf {
    let path = root.join(name);
    let mut encoder = png::Encoder::new(File::create(&path).unwrap(), width, 1);
    encoder.set_color(color);
    encoder.set_depth(depth);
    if let Some(text) = metadata {
        encoder
            .add_text_chunk("fixture".into(), text.into())
            .unwrap();
    }
    let mut writer = encoder.write_header().unwrap();
    writer.write_image_data(samples).unwrap();
    writer.finish().unwrap();
    PathBuf::from(name)
}

fn gray(root: &Path, name: &str, value: u8) -> PathBuf {
    png(
        root,
        name,
        1,
        png::ColorType::Grayscale,
        png::BitDepth::Eight,
        &[value],
        None,
    )
}

fn input(paths: &[PathBuf], durations: &[u64]) -> SequenceInput {
    assert_eq!(paths.len(), durations.len());
    let mut pts_ns = 0;
    SequenceInput {
        schema_version: 1,
        frame_count: paths.len() as u32,
        provenance: "Synthetic CPU fixture; listed frames aligned by declared index and intervals, no original container.".into(),
        frames: paths.iter().zip(durations).enumerate().map(|(index, (path, &duration_ns))| {
            let frame = FrameInput { index: index as u32, path: path.clone(), pts_ns, duration_ns };
            pts_ns += duration_ns;
            frame
        }).collect(),
    }
}

fn source<'a>(input: &'a SequenceInput, directory: &'a Path) -> SequenceSource<'a> {
    SequenceSource { input, directory }
}

fn run(
    root: &Path,
    baseline: &SequenceInput,
    candidate: &SequenceInput,
    repeat: Option<&SequenceInput>,
    tolerance: Option<Tolerance>,
    assessment: Option<SequenceAssessment>,
) -> anyhow::Result<SequenceReport> {
    compare(
        source(baseline, root),
        source(candidate, root),
        repeat.map(|input| source(input, root)),
        tolerance,
        assessment,
        |_, _, _, _| Ok(()),
    )
}

fn bound(max_absolute_error: u16) -> Tolerance {
    Tolerance {
        max_absolute_error,
        rationale: "Synthetic integer sample-code bound; not a quality threshold.".into(),
    }
}

fn unavailable(reason: &str) -> Observation<String> {
    Observation::Unavailable {
        reason: reason.into(),
    }
}

fn assessment(report: &SequenceReport) -> SequenceAssessment {
    SequenceAssessment {
        schema_version: 1,
        baseline_sha256: report.baseline.sha256.clone(),
        candidate_sha256: report.candidate.sha256.clone(),
        reviewer: "Synthetic unverified reviewer".into(),
        protocol: "Schema fixture only, no actual quality review performed".into(),
        prompt_adherence: unavailable("No source prompt"),
        artifacts: Observation::Available {
            value: "Synthetic observation: severe artifacts despite numerical agreement".into(),
        },
        temporal_consistency: Observation::Available {
            value: "Synthetic observation: discontinuous motion despite numerical agreement".into(),
        },
        audio: unavailable("No decoded audio"),
        limitations: vec!["Synthetic fixture does not assess quality".into()],
    }
}

fn near(actual: f64, expected: f64) {
    assert!((actual - expected).abs() < 1e-10, "{actual} != {expected}");
}

#[test]
fn declared_timeline_count_and_text_boundaries_are_strict() {
    let valid = input(&["a.png".into(), "b.png".into()], &[1, 2]);
    valid.validate().unwrap();
    let invalid: &[fn(&mut SequenceInput)] = &[
        |s| s.schema_version = 2,
        |s| s.frame_count = 0,
        |s| s.frame_count = 1,
        |s| s.frame_count = 3,
        |s| s.frames[0].index = 1,
        |s| s.frames[1].index = 0,
        |s| s.frames[0].pts_ns = 1,
        |s| s.frames[0].duration_ns = 0,
        |s| s.frames[1].pts_ns = 0,
        |s| s.frames[1].pts_ns = 2,
        |s| s.frames[1].duration_ns = u64::MAX,
        |s| s.provenance = " \n\t".into(),
        |s| s.provenance = "null\0byte".into(),
        |s| s.provenance = "é".repeat(4097),
        |s| s.frames[0].path = PathBuf::new(),
        |s| s.frames[0].path = "null\0byte".into(),
        |s| s.frames[0].path = "x".repeat(8193).into(),
    ];
    for (index, mutate) in invalid.iter().enumerate() {
        let mut manifest = valid.clone();
        mutate(&mut manifest);
        assert!(manifest.validate().is_err(), "invalid case {index}");
    }
    let mut boundary = input(&["x".repeat(8192).into()], &[u64::MAX]);
    boundary.provenance = "é".repeat(4096);
    boundary.validate().unwrap();
    let mut max = input(&vec!["same.png".into(); MAX_FRAMES], &vec![1; MAX_FRAMES]);
    max.validate().unwrap();
    max.frames.push(FrameInput {
        index: MAX_FRAMES as u32,
        path: "same.png".into(),
        pts_ns: MAX_FRAMES as u64,
        duration_ns: 1,
    });
    max.frame_count += 1;
    assert!(max.validate().is_err());
    let mut json = serde_json::to_value(&valid).unwrap();
    json["frames"][0]["undeclared"] = true.into();
    assert!(serde_json::from_value::<SequenceInput>(json).is_err());
}

#[cfg(unix)]
#[test]
fn non_utf8_paths_are_rejected_before_io() {
    use std::os::unix::ffi::OsStringExt;
    let invalid = input(&[std::ffi::OsString::from_vec(vec![0xff]).into()], &[1]);
    assert!(invalid.validate().is_err());
}

#[test]
fn alignment_rejects_different_counts_and_intervals_before_any_visit() {
    let root = tempfile::tempdir().unwrap();
    let baseline = input(&["missing-a.png".into(), "missing-b.png".into()], &[1, 2]);
    let different_intervals = input(&["missing-c.png".into(), "missing-d.png".into()], &[2, 1]);
    let different_count = input(&["missing.png".into()], &[3]);
    for other in [&different_intervals, &different_count] {
        assert!(validate_inputs(&baseline, other, None, None, None).is_err());
        assert!(validate_inputs(&baseline, &baseline, Some(other), None, None).is_err());
        let mut visited = false;
        let result = compare(
            source(&baseline, root.path()),
            source(other, root.path()),
            None,
            None,
            None,
            |_, _, _, _| {
                visited = true;
                Ok(())
            },
        );
        assert!(!visited);
        assert!(result.is_err());
    }
}

#[test]
fn every_frame_including_last_at_count_limit_contributes_and_visits_exact_snapshots() {
    let root = tempfile::tempdir().unwrap();
    let zero = gray(root.path(), "zero.png", 0);
    let changed = gray(root.path(), "changed.png", 1);
    let zero_bytes = fs::read(root.path().join(&zero)).unwrap();
    let changed_bytes = fs::read(root.path().join(&changed)).unwrap();
    let baseline = input(&vec![zero.clone(); MAX_FRAMES], &vec![1; MAX_FRAMES]);
    let mut candidate = baseline.clone();
    candidate.frames[MAX_FRAMES - 1].path = changed.clone();
    let mut visited = 0;
    let report = compare(
        source(&baseline, root.path()),
        source(&candidate, root.path()),
        None,
        None,
        None,
        |index, left, right, repeat| {
            assert_eq!(index as usize, visited);
            assert_eq!(left.samples(), &[0]);
            assert_eq!(left.encoded(), zero_bytes);
            let last = visited == MAX_FRAMES - 1;
            assert_eq!(right.samples(), &[u8::from(last)]);
            assert_eq!(
                right.encoded(),
                if last { &changed_bytes } else { &zero_bytes }
            );
            assert_eq!(
                right.identity().sha256,
                format!("{:x}", Sha256::digest(right.encoded()))
            );
            assert!(repeat.is_none());
            visited += 1;
            Ok(())
        },
    )
    .unwrap();
    assert_eq!(visited, MAX_FRAMES);
    assert_eq!(report.frames.last().unwrap().index, (MAX_FRAMES - 1) as u32);
    assert_eq!(report.metrics.sample_count, MAX_FRAMES as u64);
    assert_eq!(report.metrics.absolute_error_sum, 1);
    assert_eq!(report.metrics.squared_error_sum, 1);
    assert_eq!(report.frames[MAX_FRAMES - 1].metrics.max_absolute_error, 1);
    assert_eq!(
        report.classification,
        NumericalClassification::DifferentUnbounded
    );
    assert!(!report.metrics.encoded_equal);
    assert!(!report.metrics.decoded_equal);
    assert_ne!(report.baseline.sha256, report.candidate.sha256);
    assert!(matches!(
        report.baseline_repeat_metrics,
        Observation::Unavailable { .. }
    ));
    assert_eq!(fs::read(root.path().join(zero)).unwrap(), zero_bytes);
    assert_eq!(fs::read(root.path().join(changed)).unwrap(), changed_bytes);
}

#[test]
fn aggregate_metrics_use_all_samples_not_duration_or_average_psnr_and_repeat_is_separate() {
    let root = tempfile::tempdir().unwrap();
    let make = |name, samples: &[u8]| {
        png(
            root.path(),
            name,
            1,
            png::ColorType::Rgba,
            png::BitDepth::Eight,
            samples,
            None,
        )
    };
    let zero = make("zero.png", &[0, 0, 0, 0]);
    let first = make("first.png", &[1, 2, 3, 4]);
    let last = make("last.png", &[0, 0, 0, 8]);
    let repeated = make("repeat.png", &[0, 0, 0, 1]);
    let baseline = input(&[zero.clone(), zero.clone()], &[1, 9999]);
    let candidate = input(&[first, last], &[1, 9999]);
    let repeat = input(&[zero, repeated], &[1, 9999]);
    let report = run(
        root.path(),
        &baseline,
        &candidate,
        Some(&repeat),
        Some(bound(8)),
        None,
    )
    .unwrap();
    let metrics = &report.metrics;
    assert_eq!(metrics.pixel_count, 2);
    assert_eq!(metrics.channel_count, 4);
    assert_eq!(metrics.sample_count, 8);
    assert_eq!(metrics.absolute_error_sum, 18);
    assert_eq!(metrics.squared_error_sum, 94);
    assert_eq!(metrics.max_absolute_error, 8);
    near(metrics.mean_absolute_error, 2.25);
    near(metrics.root_mean_squared_error, (94.0_f64 / 8.0).sqrt());
    match metrics.psnr {
        Psnr::Finite { decibels } => near(decibels, 10.0 * (65025.0_f64 / (94.0 / 8.0)).log10()),
        _ => panic!("nonzero error must be finite"),
    }
    assert_eq!(
        report.classification,
        NumericalClassification::WithinTolerance
    );
    assert!(report.is_within_numerical_bound());
    let Observation::Available { value } = report.baseline_repeat_metrics else {
        panic!("separate repeat required")
    };
    assert_eq!(value.absolute_error_sum, 1);
    assert_eq!(value.squared_error_sum, 1);
    assert_eq!(value.sample_count, 8);
    assert_ne!(
        report.baseline_repeat.unwrap().sha256,
        report.candidate.sha256
    );
    let Observation::Available { value } = &report.frames[0].baseline_repeat_metrics else {
        panic!("missing frame repeat")
    };
    assert_eq!(value.psnr, Psnr::PositiveInfinity);
    for (limit, expected) in [
        (0, NumericalClassification::OutsideTolerance),
        (7, NumericalClassification::OutsideTolerance),
        (255, NumericalClassification::WithinTolerance),
    ] {
        assert_eq!(
            run(
                root.path(),
                &baseline,
                &candidate,
                None,
                Some(bound(limit)),
                None
            )
            .unwrap()
            .classification,
            expected
        );
    }
    assert!(
        run(
            root.path(),
            &baseline,
            &candidate,
            None,
            Some(bound(256)),
            None
        )
        .is_err()
    );
    let mut bad_bound = bound(8);
    bad_bound.rationale = " ".into();
    assert!(validate_inputs(&baseline, &candidate, None, Some(&bad_bound), None).is_err());
}

#[test]
fn full_sixteen_bit_integer_aggregation_does_not_overflow_or_quantize_low_bits() {
    let root = tempfile::tempdir().unwrap();
    let left = png(
        root.path(),
        "left.png",
        2,
        png::ColorType::Grayscale,
        png::BitDepth::Sixteen,
        &[0, 0, 255, 255],
        None,
    );
    let right = png(
        root.path(),
        "right.png",
        2,
        png::ColorType::Grayscale,
        png::BitDepth::Sixteen,
        &[255, 255, 0, 0],
        None,
    );
    let baseline = input(&[left.clone(), left], &[1, 1]);
    let candidate = input(&[right.clone(), right], &[1, 1]);
    let report = run(
        root.path(),
        &baseline,
        &candidate,
        None,
        Some(bound(65535)),
        None,
    )
    .unwrap();
    assert_eq!(report.metrics.sample_count, 4);
    assert_eq!(report.metrics.peak_sample_value, 65535);
    assert_eq!(report.metrics.absolute_error_sum, 262140);
    assert_eq!(report.metrics.squared_error_sum, 17179344900);
    assert_eq!(report.metrics.max_absolute_error, 65535);
    near(report.metrics.mean_absolute_error, 65535.0);
    near(report.metrics.root_mean_squared_error, 65535.0);
    assert_eq!(report.metrics.psnr, Psnr::Finite { decibels: 0.0 });
    let low_left = png(
        root.path(),
        "low-left.png",
        1,
        png::ColorType::GrayscaleAlpha,
        png::BitDepth::Sixteen,
        &[0x12, 0x34, 0xab, 0xcd],
        None,
    );
    let low_right = png(
        root.path(),
        "low-right.png",
        1,
        png::ColorType::GrayscaleAlpha,
        png::BitDepth::Sixteen,
        &[0x12, 0x34, 0xab, 0xce],
        None,
    );
    let low = run(
        root.path(),
        &input(&[low_left], &[1]),
        &input(&[low_right], &[1]),
        None,
        Some(bound(1)),
        None,
    )
    .unwrap();
    assert_eq!(low.metrics.absolute_error_sum, 1);
    assert_eq!(low.metrics.sample_count, 2);
    assert_eq!(low.metrics.squared_error_sum, 1);
    assert_eq!(low.classification, NumericalClassification::WithinTolerance);
}

#[test]
fn late_decode_and_geometry_failures_abort_without_visiting_bad_frame() {
    let root = tempfile::tempdir().unwrap();
    let first = gray(root.path(), "first.png", 0);
    let width = png(
        root.path(),
        "width.png",
        2,
        png::ColorType::Grayscale,
        png::BitDepth::Eight,
        &[0, 0],
        None,
    );
    let layout = png(
        root.path(),
        "layout.png",
        1,
        png::ColorType::GrayscaleAlpha,
        png::BitDepth::Eight,
        &[0, 0],
        None,
    );
    let depth = png(
        root.path(),
        "depth.png",
        1,
        png::ColorType::Grayscale,
        png::BitDepth::Sixteen,
        &[0, 0],
        None,
    );
    let unsupported = png(
        root.path(),
        "one-bit.png",
        1,
        png::ColorType::Grayscale,
        png::BitDepth::One,
        &[0],
        None,
    );
    fs::write(root.path().join("corrupt.png"), b"not a PNG").unwrap();
    let baseline = input(&[first.clone(), first.clone()], &[1, 1]);
    for late in [
        width,
        layout,
        depth,
        unsupported,
        "corrupt.png".into(),
        "missing.png".into(),
    ] {
        let other = input(&[first.clone(), late], &[1, 1]);
        // Both roles changing together must still fail the cross-frame invariant.
        for (left, right, repeat) in [
            (&baseline, &other, None),
            (&other, &other, None),
            (&baseline, &baseline, Some(&other)),
        ] {
            let mut visited = Vec::new();
            let result = compare(
                source(left, root.path()),
                source(right, root.path()),
                repeat.map(|r| source(r, root.path())),
                None,
                None,
                |index, _, _, _| {
                    visited.push(index);
                    Ok(())
                },
            );
            assert!(result.is_err());
            assert_eq!(visited, vec![0]);
        }
    }
}

#[test]
fn visitor_failure_stops_in_order_and_propagates_without_skipping() {
    let root = tempfile::tempdir().unwrap();
    let frame = gray(root.path(), "frame.png", 3);
    let manifest = input(&[frame.clone(), frame, "missing.png".into()], &[1, 1, 1]);
    let mut visited = Vec::new();
    let failure = compare(
        source(&manifest, root.path()),
        source(&manifest, root.path()),
        None,
        None,
        None,
        |index, _, _, _| {
            visited.push(index);
            if index == 1 {
                anyhow::bail!("synthetic output quota exhausted");
            }
            Ok(())
        },
    )
    .unwrap_err();
    assert_eq!(visited, vec![0, 1]);
    assert!(format!("{failure:#}").contains("synthetic output quota exhausted"));
}

#[test]
fn whole_sequence_identity_binds_encoded_contents_order_and_timing_not_provenance_or_paths() {
    let root = tempfile::tempdir().unwrap();
    let a = gray(root.path(), "a.png", 7);
    let b = gray(root.path(), "b.png", 9);
    let baseline = input(&[a.clone(), b.clone()], &[2, 3]);
    let report = run(root.path(), &baseline, &baseline, None, None, None).unwrap();
    let mut identity_bytes = b"mil-png-sequence-v1\0".to_vec();
    identity_bytes.extend_from_slice(&2_u64.to_be_bytes());
    identity_bytes.extend_from_slice(&5_u64.to_be_bytes());
    for (index, pts, duration, path) in [(0_u64, 0_u64, 2_u64, &a), (1, 2, 3, &b)] {
        identity_bytes.extend_from_slice(&index.to_be_bytes());
        identity_bytes.extend_from_slice(&pts.to_be_bytes());
        identity_bytes.extend_from_slice(&duration.to_be_bytes());
        let bytes = fs::read(root.path().join(path)).unwrap();
        identity_bytes.extend_from_slice(format!("{:x}", Sha256::digest(bytes)).as_bytes());
    }
    assert_eq!(
        report.baseline.sha256,
        format!("{:x}", Sha256::digest(identity_bytes))
    );
    assert_eq!(report.baseline.frame_count, 2);
    assert_eq!(report.baseline.duration_ns, 5);
    let copy_dir = tempfile::tempdir().unwrap();
    fs::copy(root.path().join(&a), copy_dir.path().join("renamed-a.png")).unwrap();
    fs::copy(root.path().join(&b), copy_dir.path().join("renamed-b.png")).unwrap();
    let mut renamed = input(
        &[
            "renamed-a.png".into(),
            copy_dir.path().join("renamed-b.png"),
        ],
        &[2, 3],
    );
    renamed.provenance = "Different unverified extraction description".into();
    let same = compare(
        source(&baseline, root.path()),
        source(&renamed, copy_dir.path()),
        None,
        None,
        None,
        |_, _, _, _| Ok(()),
    )
    .unwrap();
    assert_eq!(same.baseline.sha256, same.candidate.sha256);
    let reordered = input(&[b, a.clone()], &[2, 3]);
    assert_ne!(
        run(root.path(), &baseline, &reordered, None, None, None)
            .unwrap()
            .candidate
            .sha256,
        report.baseline.sha256
    );
    let mut retimed = baseline.clone();
    retimed.frames[0].duration_ns = 3;
    retimed.frames[1].pts_ns = 3;
    retimed.frames[1].duration_ns = 2;
    assert_ne!(
        run(root.path(), &retimed, &retimed, None, None, None)
            .unwrap()
            .baseline
            .sha256,
        report.baseline.sha256
    );
    let metadata = png(
        root.path(),
        "metadata.png",
        1,
        png::ColorType::Grayscale,
        png::BitDepth::Eight,
        &[7],
        Some("different encoded metadata"),
    );
    let encoded = run(
        root.path(),
        &input(&[a], &[1]),
        &input(&[metadata], &[1]),
        None,
        None,
        None,
    )
    .unwrap();
    assert_eq!(
        encoded.classification,
        NumericalClassification::ExactDecoded
    );
    assert!(encoded.metrics.decoded_equal);
    assert!(!encoded.metrics.encoded_equal);
    assert_ne!(encoded.baseline.sha256, encoded.candidate.sha256);
    assert_eq!(encoded.metrics.psnr, Psnr::PositiveInfinity);
}

#[test]
fn assessments_bind_complete_sequences_and_never_override_numerical_classification() {
    let root = tempfile::tempdir().unwrap();
    let zero = gray(root.path(), "zero.png", 0);
    let one = gray(root.path(), "one.png", 1);
    let baseline = input(&[zero.clone(), zero.clone()], &[1, 1]);
    let candidate = input(&[zero, one], &[1, 1]);
    let exact = run(root.path(), &baseline, &baseline, None, None, None).unwrap();
    let reviewed = run(
        root.path(),
        &baseline,
        &baseline,
        None,
        None,
        Some(assessment(&exact)),
    )
    .unwrap();
    assert_eq!(
        reviewed.classification,
        NumericalClassification::ExactDecoded
    );
    assert!(reviewed.is_within_numerical_bound());
    let Observation::Available { value } = reviewed.assessment else {
        panic!("missing supplied assessment")
    };
    assert!(matches!(
        value.temporal_consistency,
        Observation::Available { .. }
    ));
    assert!(matches!(value.audio, Observation::Unavailable { .. }));
    let different = run(
        root.path(),
        &baseline,
        &candidate,
        None,
        Some(bound(0)),
        None,
    )
    .unwrap();
    let mut glowing = assessment(&different);
    glowing.temporal_consistency = Observation::Available {
        value: "Synthetic observation: excellent temporal quality".into(),
    };
    let different_reviewed = run(
        root.path(),
        &baseline,
        &candidate,
        None,
        Some(bound(0)),
        Some(glowing),
    )
    .unwrap();
    assert_eq!(
        different_reviewed.classification,
        NumericalClassification::OutsideTolerance
    );
    assert!(!different_reviewed.is_within_numerical_bound());
    let mut visited = Vec::new();
    let mismatch = compare(
        source(&baseline, root.path()),
        source(&candidate, root.path()),
        None,
        None,
        Some(assessment(&exact)),
        |index, _, _, _| {
            visited.push(index);
            Ok(())
        },
    )
    .unwrap_err();
    assert_eq!(visited, vec![0, 1]);
    assert!(
        mismatch
            .to_string()
            .contains("complete baseline and candidate sequence identities")
    );
    let mut per_png = assessment(&exact);
    per_png.baseline_sha256 = exact.frames[0].baseline.sha256.clone();
    assert!(run(root.path(), &baseline, &baseline, None, None, Some(per_png)).is_err());
}

#[test]
fn malformed_assessment_and_audio_claims_fail_before_visiting() {
    let root = tempfile::tempdir().unwrap();
    let frame = gray(root.path(), "frame.png", 2);
    let manifest = input(&[frame], &[1]);
    let exact = run(root.path(), &manifest, &manifest, None, None, None).unwrap();
    let valid = assessment(&exact);
    let mutations: &[fn(&mut SequenceAssessment)] = &[
        |a| a.schema_version = 2,
        |a| a.baseline_sha256 = "a".repeat(63),
        |a| a.candidate_sha256 = "A".repeat(64),
        |a| a.baseline_sha256 = "g".repeat(64),
        |a| a.reviewer = "\0".into(),
        |a| a.protocol = " ".into(),
        |a| {
            a.artifacts = Observation::Available {
                value: "x".repeat(8193),
            }
        },
        |a| a.prompt_adherence = unavailable(""),
        |a| a.temporal_consistency = unavailable(" \n"),
        |a| {
            a.audio = Observation::Available {
                value: "Audio matches".into(),
            }
        },
        |a| a.audio = unavailable(""),
        |a| a.limitations = vec!["x".into(); 65],
        |a| a.limitations = vec!["".into()],
    ];
    for (index, mutate) in mutations.iter().enumerate() {
        let mut invalid = valid.clone();
        mutate(&mut invalid);
        let mut visited = false;
        let result = compare(
            source(&manifest, root.path()),
            source(&manifest, root.path()),
            None,
            None,
            Some(invalid),
            |_, _, _, _| {
                visited = true;
                Ok(())
            },
        );
        assert!(result.is_err(), "invalid assessment case {index}");
        assert!(!visited);
    }
    let mut boundary = valid;
    boundary.reviewer = "x".repeat(8192);
    boundary.limitations = vec!["x".repeat(8192); 64];
    validate_inputs(&manifest, &manifest, None, None, Some(&boundary)).unwrap();
    let mut json = serde_json::to_value(&boundary).unwrap();
    json["confidence"] = 1.into();
    assert!(serde_json::from_value::<SequenceAssessment>(json).is_err());
}
