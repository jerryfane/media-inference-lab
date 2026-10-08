use media_inference_lab::{png_image, schema::Artifact};
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::{fs, path::Path, process::Command};
use tempfile::TempDir;

fn png(path: &Path, samples: &[u8]) {
    let mut encoder = png::Encoder::new(fs::File::create(path).unwrap(), 2, 1);
    encoder.set_color(png::ColorType::Rgb);
    encoder.set_depth(png::BitDepth::Eight);
    let mut writer = encoder.write_header().unwrap();
    writer.write_image_data(samples).unwrap();
    writer.finish().unwrap();
}

#[test]
fn bundle_retains_originals_and_integrity_after_sources_are_removed_and_refuses_overwrite() {
    let root = TempDir::new().unwrap();
    let baseline = root.path().join("a.png");
    let candidate = root.path().join("b.png");
    let repeat = root.path().join("repeat.png");
    png(&baseline, &[0, 0, 0, 255, 255, 255]);
    png(&candidate, &[1, 0, 0, 255, 255, 255]);
    png(&repeat, &[0, 0, 1, 255, 255, 255]);
    let originals: Vec<_> = [&baseline, &candidate, &repeat]
        .iter()
        .map(|p| fs::read(p).unwrap())
        .collect();
    let output = root.path().join("bundle");
    let mut command = Command::new(env!("CARGO_BIN_EXE_mil"));
    command
        .arg("compare-images")
        .arg("--baseline")
        .arg(&baseline)
        .arg("--candidate")
        .arg(&candidate)
        .arg("--baseline-repeat")
        .arg(&repeat)
        .arg("--output-dir")
        .arg(&output)
        .args([
            "--max-absolute-error",
            "1",
            "--tolerance-rationale",
            "One integer code value per channel; this is not a visual-quality bound.",
        ]);
    let result = command.output().unwrap();
    assert!(
        result.status.success(),
        "{}",
        String::from_utf8_lossy(&result.stderr)
    );
    let report_bytes = fs::read(output.join("report.json")).unwrap();
    let report: Value = serde_json::from_slice(&report_bytes).unwrap();
    let inventory: Vec<Artifact> = serde_json::from_value(report["artifacts"].clone()).unwrap();
    assert_eq!(report["comparison"]["metrics"]["absolute_error_sum"], 1);
    assert_eq!(report["comparison"]["metrics"]["sample_count"], 6);
    assert_eq!(
        report["comparison"]["baseline_repeat_metrics"]["value"]["absolute_error_sum"],
        1
    );
    let conflict = command.output().unwrap();
    assert_eq!(conflict.status.code(), Some(2));
    assert_eq!(fs::read(output.join("report.json")).unwrap(), report_bytes);
    for path in [&baseline, &candidate, &repeat] {
        fs::remove_file(path).unwrap();
    }
    for artifact in &inventory {
        media_inference_lab::schema::validate_artifact_path(&artifact.path).unwrap();
        let bytes = fs::read(output.join(&artifact.path)).unwrap();
        assert_eq!(bytes.len() as u64, artifact.bytes);
        assert_eq!(format!("{:x}", Sha256::digest(&bytes)), artifact.sha256);
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(
                fs::metadata(output.join(&artifact.path))
                    .unwrap()
                    .permissions()
                    .mode()
                    & 0o777,
                0o600
            );
        }
    }
    for (name, original) in ["baseline.png", "candidate.png", "baseline-repeat.png"]
        .iter()
        .zip(originals)
    {
        assert_eq!(fs::read(output.join(name)).unwrap(), original);
    }
    let sheet = png_image::decode(&output.join("sheet.png")).unwrap();
    assert_eq!(sheet.identity().width, 4);
    assert_eq!(
        sheet.samples(),
        &[0, 0, 0, 255, 255, 255, 1, 0, 0, 255, 255, 255]
    );
}

#[test]
fn differing_samples_retain_evidence_with_exit_one_and_invalid_shape_creates_no_bundle() {
    let root = TempDir::new().unwrap();
    let baseline = root.path().join("a.png");
    let candidate = root.path().join("b.png");
    png(&baseline, &[0, 0, 0, 255, 255, 255]);
    png(&candidate, &[0, 0, 0, 255, 255, 254]);
    let output = root.path().join("different");
    let result = Command::new(env!("CARGO_BIN_EXE_mil"))
        .arg("compare-images")
        .arg("--baseline")
        .arg(&baseline)
        .arg("--candidate")
        .arg(&candidate)
        .arg("--output-dir")
        .arg(&output)
        .output()
        .unwrap();
    assert_eq!(result.status.code(), Some(1));
    let report: Value =
        serde_json::from_slice(&fs::read(output.join("report.json")).unwrap()).unwrap();
    assert_eq!(report["comparison"]["metrics"]["absolute_error_sum"], 1);
    assert_eq!(report["comparison"]["assessment"]["status"], "unavailable");

    let mut encoder = png::Encoder::new(fs::File::create(&candidate).unwrap(), 1, 2);
    encoder.set_color(png::ColorType::Rgb);
    encoder.set_depth(png::BitDepth::Eight);
    let mut writer = encoder.write_header().unwrap();
    writer.write_image_data(&[0, 0, 0, 255, 255, 254]).unwrap();
    writer.finish().unwrap();
    let invalid = root.path().join("invalid");
    let result = Command::new(env!("CARGO_BIN_EXE_mil"))
        .arg("compare-images")
        .arg("--baseline")
        .arg(&baseline)
        .arg("--candidate")
        .arg(&candidate)
        .arg("--output-dir")
        .arg(&invalid)
        .output()
        .unwrap();
    assert_eq!(result.status.code(), Some(2));
    assert!(!invalid.exists());
}
