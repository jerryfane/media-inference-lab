//! Deterministic CPU-produced PNGs only; no Python/native imports or model runs.
use media_inference_lab::{
    capture::{self, CaptureOptions, CaptureState},
    image_inspection::{ImageInspectionOptions, inspect},
    schema::{MediaSettings, Precision, Workload},
};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::{
    collections::BTreeMap,
    fs,
    os::unix::fs::PermissionsExt,
    path::{Path, PathBuf},
    sync::{Arc, atomic::AtomicBool},
    time::Duration,
};

fn workload(batch: u32) -> Workload {
    let mut request: Workload =
        serde_json::from_str(include_str!("../examples/image-workload.json")).unwrap();
    let MediaSettings::Image { generation } = &mut request.settings else {
        unreachable!()
    };
    generation.resolution.width = 2;
    generation.resolution.height = 1;
    generation.batch_size = batch;
    generation.precision = Precision::Bfloat16;
    generation.compute_precision = Some(Precision::Float16);
    request
}

fn png(width: u32, color: png::ColorType, depth: png::BitDepth) -> Vec<u8> {
    let mut bytes = Vec::new();
    {
        let mut encoder = png::Encoder::new(&mut bytes, width, 1);
        encoder.set_color(color);
        encoder.set_depth(depth);
        let mut writer = encoder.write_header().unwrap();
        let samples = vec![23; width as usize * color.samples() * (depth as usize / 8)];
        writer.write_image_data(&samples).unwrap();
        writer.finish().unwrap();
    }
    bytes
}

fn crc(bytes: &[u8]) -> u32 {
    let mut value = !0u32;
    for &byte in bytes {
        value ^= byte as u32;
        for _ in 0..8 {
            value = (value >> 1) ^ (0xedb88320 & 0u32.wrapping_sub(value & 1));
        }
    }
    !value
}

// Preserve IHDR and chunk CRCs but invalidate the full zlib checksum in IDAT.
fn corrupt_idat(mut bytes: Vec<u8>) -> Vec<u8> {
    let mut offset = 8;
    loop {
        let length = u32::from_be_bytes(bytes[offset..offset + 4].try_into().unwrap()) as usize;
        let end = offset + 8 + length;
        if &bytes[offset + 4..offset + 8] == b"IDAT" {
            bytes[end - 1] ^= 1;
            let checksum = crc(&bytes[offset + 4..end]);
            bytes[end..end + 4].copy_from_slice(&checksum.to_be_bytes());
            return bytes;
        }
        offset = end + 4;
    }
}

fn run(root: &Path, name: &str, request: Workload, inputs: Vec<PathBuf>) -> (bool, Value) {
    let output_dir = root.join(name);
    let ok = inspect(ImageInspectionOptions {
        workload: request,
        inputs,
        output_dir: output_dir.clone(),
        timeout: Duration::from_secs(10),
    })
    .unwrap();
    let report =
        serde_json::from_slice(&fs::read(output_dir.join("report.json")).unwrap()).unwrap();
    (ok, report)
}

#[test]
fn full_decode_retains_originals_and_distinguishes_bf16_from_png_sample_dtype() {
    let root = tempfile::tempdir().unwrap();
    let bytes = png(2, png::ColorType::Rgb, png::BitDepth::Sixteen);
    let source = root.path().join("input.any-extension");
    fs::write(&source, &bytes).unwrap();
    let request = workload(1);
    let identity = request.identity().unwrap();
    let (ok, report) = run(root.path(), "inspection", request, vec![source]);
    assert!(ok);
    assert_eq!(report["workload_identity"], identity);
    assert_eq!(
        report["declared_workload"]["settings"]["generation"]["seed"],
        17
    );
    assert_eq!(
        report["declared_workload"]["settings"]["generation"]["precision"],
        "bfloat16"
    );
    assert_eq!(report["inputs"][0]["stored_sample_dtype"], "uint16");
    assert_eq!(report["inputs"][0]["decoded"]["color"], "rgb");
    assert_eq!(report["inputs"][0]["decoded"]["width"], 2);
    assert_eq!(report["inputs"][0]["decoded"]["height"], 1);
    assert_eq!(
        report["inputs"][0]["decoded"]["sha256"],
        format!("{:x}", Sha256::digest(&bytes))
    );
    assert_eq!(
        report["inputs"][0]["decoded"]["decoded_sha256"],
        format!("{:x}", Sha256::digest([23u8; 12]))
    );
    assert_eq!(report["native_phases"]["status"], "unavailable");
    let snapshot = root.path().join("inspection/original-0000.png");
    assert_eq!(fs::read(&snapshot).unwrap(), bytes);
    assert_eq!(
        fs::metadata(snapshot).unwrap().permissions().mode() & 0o777,
        0o600
    );
    assert_eq!(
        fs::metadata(root.path().join("inspection"))
            .unwrap()
            .permissions()
            .mode()
            & 0o777,
        0o700
    );
}

#[test]
fn corrupt_full_idat_wrong_dimensions_and_unsupported_format_retain_failed_snapshots() {
    let root = tempfile::tempdir().unwrap();
    let cases = [
        (
            "corrupt",
            corrupt_idat(png(2, png::ColorType::Rgb, png::BitDepth::Eight)),
            "zlib",
        ),
        (
            "wrong-size",
            png(3, png::ColorType::Rgb, png::BitDepth::Eight),
            "dimensions",
        ),
        (
            "unsupported",
            b"not a PNG".to_vec(),
            "unsupported image format",
        ),
    ];
    for (name, bytes, error) in cases {
        let source = root.path().join(format!("{name}.png"));
        fs::write(&source, &bytes).unwrap();
        let (ok, report) = run(root.path(), name, workload(1), vec![source]);
        assert!(!ok);
        assert!(
            report["inputs"][0]["error"]
                .as_str()
                .unwrap()
                .contains(error),
            "{report}"
        );
        assert_eq!(
            fs::read(root.path().join(name).join("original-0000.png")).unwrap(),
            bytes
        );
        if name == "wrong-size" {
            assert_eq!(report["inputs"][0]["decoded"]["width"], 3);
        } else {
            assert!(report["inputs"][0]["decoded"].is_null());
        }
    }
}

#[test]
fn absent_inputs_batch_mismatch_and_physical_duplicates_fail_without_overwrite() {
    let root = tempfile::tempdir().unwrap();
    let (ok, missing) = run(
        root.path(),
        "missing",
        workload(1),
        vec![root.path().join("absent.png")],
    );
    assert!(!ok);
    assert!(missing["inputs"][0]["original"].is_null());
    assert!(missing["inputs"][0]["error"].is_string());
    let (ok, empty) = run(root.path(), "empty", workload(1), vec![]);
    assert!(!ok);
    assert!(empty["errors"][0].as_str().unwrap().contains("batch count"));
    let source = root.path().join("source.png");
    fs::write(&source, png(2, png::ColorType::Rgb, png::BitDepth::Eight)).unwrap();
    let alias = root.path().join("hardlink.png");
    fs::hard_link(&source, &alias).unwrap();
    let (ok, duplicate) = run(
        root.path(),
        "duplicate",
        workload(2),
        vec![source.clone(), alias],
    );
    assert!(!ok);
    assert!(
        duplicate["inputs"][1]["error"]
            .as_str()
            .unwrap()
            .contains("duplicate physical")
    );
    let (ok, count) = run(root.path(), "count", workload(2), vec![source.clone()]);
    assert!(!ok);
    assert_eq!(count["accepted_image_count"], 1);
    assert!(count["errors"][0].as_str().unwrap().contains("batch count"));
    let before = fs::read(root.path().join("count/report.json")).unwrap();
    assert!(
        inspect(ImageInspectionOptions {
            workload: workload(1),
            inputs: vec![source],
            output_dir: root.path().join("count"),
            timeout: Duration::from_secs(10),
        })
        .is_err()
    );
    assert_eq!(
        fs::read(root.path().join("count/report.json")).unwrap(),
        before
    );
}

#[test]
fn batch_requires_consistent_stored_color_and_bit_depth() {
    let root = tempfile::tempdir().unwrap();
    let baseline = root.path().join("baseline.png");
    fs::write(&baseline, png(2, png::ColorType::Rgb, png::BitDepth::Eight)).unwrap();
    for (name, color, depth) in [
        ("color", png::ColorType::Rgba, png::BitDepth::Eight),
        ("dtype", png::ColorType::Rgb, png::BitDepth::Sixteen),
    ] {
        let other = root.path().join(format!("{name}.png"));
        fs::write(&other, png(2, color, depth)).unwrap();
        let (ok, report) = run(
            root.path(),
            name,
            workload(2),
            vec![baseline.clone(), other],
        );
        assert!(!ok);
        assert_eq!(report["fully_decoded_count"], 2);
        assert!(
            report["inputs"][1]["error"]
                .as_str()
                .unwrap()
                .contains("inconsistent")
        );
    }
}

#[test]
fn video_workload_is_not_accepted_as_an_image_batch() {
    let root = tempfile::tempdir().unwrap();
    let request: Workload =
        serde_json::from_str(include_str!("../examples/video-workload.json")).unwrap();
    let (ok, report) = run(root.path(), "video", request, vec![]);
    assert!(!ok);
    assert!(
        report["errors"][0]
            .as_str()
            .unwrap()
            .contains("image modality")
    );
}

fn captured(
    root: &Path,
    name: &str,
    request: Workload,
    images: &[Vec<u8>],
    role: &str,
    native_contract: bool,
) -> capture::CaptureRecord {
    let root = fs::canonicalize(root).unwrap();
    let fixture_dir = root.join(format!("fixtures-{name}"));
    fs::create_dir(&fixture_dir).unwrap();
    let mut result: Value =
        serde_json::from_str(include_str!("fixtures/image-result.json")).unwrap();
    result["workload_identity"] = json!(request.identity().unwrap());
    result["resolved"] = json!(request);
    if native_contract {
        // Exercise the declared result contract only; no native executable is run.
        result["runtime"]["name"] = json!("MFLUX QwenImage21 / MLX");
    }
    result["artifacts"] = json!(images.iter().enumerate().map(|(index, bytes)| {
        let name = format!("output-{index}.png");
        fs::write(fixture_dir.join(&name), bytes).unwrap();
        json!({"path": name, "sha256": format!("{:x}", Sha256::digest(bytes)), "bytes": bytes.len(), "role": role})
    }).collect::<Vec<_>>());
    let fixture = root.join(format!("result-{name}.json"));
    fs::write(&fixture, serde_json::to_vec(&result).unwrap()).unwrap();
    let run = capture::capture(request, CaptureOptions {
        root: root.join(format!("captures-{name}")),
        executable: "/bin/sh".into(),
        args: vec!["-c".into(), "set -eu; /bin/cp \"$IMAGE_FIXTURES\"/* .; /bin/cp \"$RESULT_FIXTURE\" \"$MIL_RESULT_PATH\"".into()],
        env: BTreeMap::from([
            ("IMAGE_FIXTURES".into(), fixture_dir.to_string_lossy().into_owned()),
            ("RESULT_FIXTURE".into(), fixture.to_string_lossy().into_owned()),
        ]),
        timeout: Duration::from_secs(10), max_output_bytes: 1024 * 1024,
    }, Arc::new(AtomicBool::new(false))).unwrap();
    capture::inspect(&run).unwrap()
}

#[test]
fn actual_cpu_capture_rejects_corrupt_matching_hashes_and_wrong_image_contracts() {
    let root = tempfile::tempdir().unwrap();
    let good = png(2, png::ColorType::Rgb, png::BitDepth::Eight);
    let cases = [
        (
            "corrupt",
            workload(1),
            vec![corrupt_idat(good.clone())],
            "generated-image",
            false,
            "zlib",
        ),
        (
            "dimensions",
            workload(1),
            vec![png(3, png::ColorType::Rgb, png::BitDepth::Eight)],
            "generated-image",
            false,
            "dimensions",
        ),
        (
            "batch",
            workload(2),
            vec![good.clone()],
            "generated-image",
            false,
            "batch count",
        ),
        (
            "color",
            workload(2),
            vec![
                good.clone(),
                png(2, png::ColorType::Rgba, png::BitDepth::Eight),
            ],
            "generated-image",
            false,
            "inconsistent",
        ),
        (
            "dtype",
            workload(2),
            vec![
                good.clone(),
                png(2, png::ColorType::Rgb, png::BitDepth::Sixteen),
            ],
            "generated-image",
            false,
            "inconsistent",
        ),
        (
            "missing-role",
            workload(1),
            vec![good.clone()],
            "native-runtime-provenance",
            true,
            "batch count",
        ),
    ];
    for (name, request, images, role, native_contract, expected) in cases {
        let record = captured(root.path(), name, request, &images, role, native_contract);
        assert_eq!(record.state, CaptureState::Failed, "{name}");
        assert_eq!(record.exit.as_ref().unwrap().code, Some(0));
        assert!(
            record.failure.as_ref().unwrap().contains(expected),
            "{name}: {:?}",
            record.failure
        );
    }
    let success = captured(
        root.path(),
        "valid",
        workload(1),
        &[good],
        "generated-image",
        false,
    );
    assert_eq!(success.state, CaptureState::Completed);
    let generic = captured(
        root.path(),
        "generic",
        workload(1),
        &[b"generic CPU artifact, not media".to_vec()],
        "cpu-schema-example-text-not-generated-media",
        false,
    );
    assert_eq!(generic.state, CaptureState::Completed);
}
