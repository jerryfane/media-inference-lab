use media_inference_lab::{png_image, schema::Artifact};
use pulldown_cmark::{Event, Options, Parser, Tag};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::{
    collections::{BTreeMap, BTreeSet},
    fs,
    path::{Path, PathBuf},
    process::{Command, Output},
};
use tempfile::TempDir;

fn png(path: &Path, samples: &[u8]) {
    let mut encoder = png::Encoder::new(fs::File::create(path).unwrap(), 2, 1);
    encoder.set_color(png::ColorType::Rgb);
    encoder.set_depth(png::BitDepth::Eight);
    let mut writer = encoder.write_header().unwrap();
    writer.write_image_data(samples).unwrap();
    writer.finish().unwrap();
}

struct Fixture {
    root: TempDir,
    originals: BTreeMap<String, Vec<u8>>,
}
impl Fixture {
    fn new() -> Self {
        let root = TempDir::new().unwrap();
        let source = root.path().join("sources");
        fs::create_dir(&source).unwrap();
        let mut originals = BTreeMap::new();
        for role in ["baseline", "candidate", "repeat"] {
            let mut frames = Vec::new();
            for index in 0..3_u8 {
                let mut samples: Vec<_> = (0..6).map(|n| n + index).collect();
                if role == "candidate" && index == 2 {
                    samples[5] += 5;
                }
                if role == "repeat" && index == 0 {
                    samples[0] += 1;
                }
                let name = format!("{index:04}-{role}.png");
                png(&source.join(&name), &samples);
                originals.insert(name.clone(), fs::read(source.join(&name)).unwrap());
                frames.push(json!({"index":index,"path":name,"pts_ns":([0,10,30][index as usize]),"duration_ns":([10,20,30][index as usize])}));
            }
            fs::write(source.join(format!("{role}.json")), serde_json::to_vec(&json!({"schema_version":1,"frame_count":3,"provenance":"Generated CPU frame fixtures; no original video or inference.","frames":frames})).unwrap()).unwrap();
        }
        Self { root, originals }
    }
    fn bundle(&self, name: &str) -> PathBuf {
        self.root.path().join(name)
    }
    fn command(&self, name: &str) -> Command {
        let mut command = Command::new(env!("CARGO_BIN_EXE_mil"));
        command
            .arg("compare-frames")
            .arg("--baseline")
            .arg(self.root.path().join("sources/baseline.json"))
            .arg("--candidate")
            .arg(self.root.path().join("sources/candidate.json"))
            .arg("--baseline-repeat")
            .arg(self.root.path().join("sources/repeat.json"))
            .arg("--output-dir")
            .arg(self.bundle(name));
        command
    }
    fn report(&self, name: &str) -> Value {
        serde_json::from_slice(&fs::read(self.bundle(name).join("report.json")).unwrap()).unwrap()
    }
}
fn exit(result: Output, code: i32) {
    assert_eq!(
        result.status.code(),
        Some(code),
        "{}",
        String::from_utf8_lossy(&result.stderr)
    );
}
fn local_links(markdown: &str, expected: &BTreeSet<String>) {
    let mut actual = BTreeSet::new();
    for event in Parser::new_ext(markdown, Options::ENABLE_TABLES) {
        match event {
            Event::Html(_) | Event::InlineHtml(_) => panic!("untrusted metadata became HTML"),
            Event::Start(Tag::Link { dest_url, .. } | Tag::Image { dest_url, .. }) => {
                assert!(
                    expected.contains(dest_url.as_ref()),
                    "unexpected target {dest_url}"
                );
                actual.insert(dest_url.into_string());
            }
            _ => {}
        }
    }
    assert_eq!(&actual, expected);
}

#[test]
fn every_frame_snapshot_and_sheet_survives_relocation_with_exact_metrics_and_local_links() {
    let fixture = Fixture::new();
    let mut command = fixture.command("bundle");
    command.args([
        "--max-absolute-error",
        "5",
        "--tolerance-rationale",
        "Predeclared five-code synthetic bound; not a quality threshold.",
    ]);
    exit(command.output().unwrap(), 0);
    let bundle = fixture.bundle("bundle");
    let report = fixture.report("bundle");
    assert_eq!(report["comparison"]["frames"].as_array().unwrap().len(), 3);
    assert_eq!(report["comparison"]["metrics"]["sample_count"], 18);
    assert_eq!(report["comparison"]["metrics"]["absolute_error_sum"], 5);
    assert_eq!(report["comparison"]["metrics"]["squared_error_sum"], 25);
    assert_eq!(
        report["comparison"]["metrics"]["mean_absolute_error"],
        5.0 / 18.0
    );
    assert_eq!(
        report["comparison"]["baseline_repeat_metrics"]["value"]["absolute_error_sum"],
        1
    );
    let inventory: Vec<Artifact> = serde_json::from_value(report["artifacts"].clone()).unwrap();
    let mut expected = BTreeSet::from(["report.json".to_string()]);
    let bytes_before: BTreeMap<_, _> = inventory
        .iter()
        .map(|a| (a.path.clone(), fs::read(bundle.join(&a.path)).unwrap()))
        .collect();
    exit(command.output().unwrap(), 2);
    for artifact in &inventory {
        assert_eq!(
            fs::read(bundle.join(&artifact.path)).unwrap(),
            bytes_before[&artifact.path]
        );
        if artifact.path != "report.md" {
            expected.insert(artifact.path.clone());
        }
    }
    for (name, bytes) in &fixture.originals {
        assert_eq!(
            fs::read(fixture.root.path().join("sources").join(name)).unwrap(),
            *bytes
        );
        assert_eq!(fs::read(bundle.join("frames").join(name)).unwrap(), *bytes);
    }
    fs::remove_dir_all(fixture.root.path().join("sources")).unwrap();
    let moved = fixture.bundle("moved");
    fs::rename(&bundle, &moved).unwrap();
    for artifact in &inventory {
        let path = moved.join(&artifact.path);
        let bytes = fs::read(&path).unwrap();
        assert_eq!(artifact.bytes, bytes.len() as u64);
        assert_eq!(artifact.sha256, format!("{:x}", Sha256::digest(&bytes)));
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(
                fs::metadata(path).unwrap().permissions().mode() & 0o777,
                0o600
            );
        }
    }
    local_links(
        &fs::read_to_string(moved.join("report.md")).unwrap(),
        &expected,
    );
    let sheet = png_image::decode(&moved.join("frames/0002-sheet.png")).unwrap();
    assert_eq!(sheet.samples(), &[2, 3, 4, 5, 6, 7, 2, 3, 4, 5, 6, 12]);
}

#[test]
fn timeline_errors_prevent_output_and_a_late_corrupt_frame_never_yields_a_complete_report() {
    let fixture = Fixture::new();
    let manifest = fixture.root.path().join("sources/candidate.json");
    let original = fs::read(&manifest).unwrap();
    let mut value: Value = serde_json::from_slice(&original).unwrap();
    value["frames"][2]["pts_ns"] = json!(31);
    fs::write(&manifest, serde_json::to_vec(&value).unwrap()).unwrap();
    exit(fixture.command("unaligned").output().unwrap(), 2);
    assert!(!fixture.bundle("unaligned").exists());
    fs::write(&manifest, original).unwrap();
    fs::write(
        fixture.root.path().join("sources/0002-candidate.png"),
        b"not PNG",
    )
    .unwrap();
    exit(fixture.command("late-invalid").output().unwrap(), 2);
    assert!(
        fixture
            .bundle("late-invalid/frames/0000-sheet.png")
            .is_file()
    );
    assert!(!fixture.bundle("late-invalid/report.json").exists());
    assert!(!fixture.bundle("late-invalid/report.md").exists());
}

#[test]
fn bound_temporal_notes_remain_literal_and_never_override_numerical_difference() {
    let fixture = Fixture::new();
    exit(fixture.command("unassessed").output().unwrap(), 1);
    let first = fixture.report("unassessed");
    let hostile = "```\n# SPOOFED\n<script>not executable</script>\n[external](https://invalid.example)\n\u{1b}]0;unsafe\u{7}";
    let mut assessment = json!({
        "schema_version":1,
        "baseline_sha256":first["comparison"]["baseline"]["sha256"],
        "candidate_sha256":first["comparison"]["candidate"]["sha256"],
        "reviewer":hostile,"protocol":"Generated binding/safety fixture, not an actual review",
        "prompt_adherence":{"status":"unavailable","reason":"No generated prompt evidence"},
        "artifacts":{"status":"available","value":hostile},
        "temporal_consistency":{"status":"available","value":"Synthetic observation does not establish temporal quality"},
        "audio":{"status":"unavailable","reason":"No decoded audio inputs"},"limitations":[hostile]
    });
    let path = fixture.root.path().join("assessment.json");
    fs::write(&path, serde_json::to_vec(&assessment).unwrap()).unwrap();
    exit(
        fixture
            .command("assessed")
            .arg("--assessment")
            .arg(&path)
            .output()
            .unwrap(),
        1,
    );
    let second = fixture.report("assessed");
    assert_eq!(
        second["comparison"]["classification"],
        first["comparison"]["classification"]
    );
    assert_eq!(second["comparison"]["assessment"]["value"], assessment);
    let expected = second["artifacts"]
        .as_array()
        .unwrap()
        .iter()
        .filter_map(|a| a["path"].as_str())
        .filter(|p| *p != "report.md")
        .map(String::from)
        .chain(["report.json".into()])
        .collect();
    let markdown = fs::read_to_string(fixture.bundle("assessed/report.md")).unwrap();
    local_links(&markdown, &expected);
    assert!(!markdown.contains('\u{1b}'));
    assessment["audio"] = json!({"status":"available","value":"Unbound audio claims are invalid"});
    fs::write(&path, serde_json::to_vec(&assessment).unwrap()).unwrap();
    exit(
        fixture
            .command("invalid-audio")
            .arg("--assessment")
            .arg(&path)
            .output()
            .unwrap(),
        2,
    );
    assert!(!fixture.bundle("invalid-audio").exists());
}
