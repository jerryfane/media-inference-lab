use media_inference_lab::{
    image_comparison::{self, ImageAssessment, ImageComparisonReport, Tolerance},
    png_image, png_report,
    schema::Observation,
};
use pulldown_cmark::{Event, Options, Parser, Tag, TagEnd};
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::{fs, path::Path, process::Command};

fn png(path: &Path, samples: &[u8]) {
    let mut encoder = png::Encoder::new(fs::File::create(path).unwrap(), 2, 1);
    encoder.set_color(png::ColorType::Grayscale);
    encoder.set_depth(png::BitDepth::Eight);
    let mut writer = encoder.write_header().unwrap();
    writer.write_image_data(samples).unwrap();
    writer.finish().unwrap();
}

fn report() -> ImageComparisonReport {
    let root = tempfile::tempdir().unwrap();
    let a = root.path().join("a.png");
    let b = root.path().join("b.png");
    png(&a, &[42, 17]);
    png(&b, &[43, 17]);
    image_comparison::compare(
        &png_image::decode(&a).unwrap(),
        &png_image::decode(&b).unwrap(),
        None,
        None,
        None,
    )
    .unwrap()
}

fn parsed_data(markdown: &str) -> (Vec<String>, Vec<String>) {
    let mut inside_code = false;
    let mut code = String::new();
    let mut blocks = Vec::new();
    let mut links = Vec::new();
    for event in Parser::new_ext(markdown, Options::ENABLE_TABLES) {
        match event {
            Event::Start(Tag::CodeBlock(_)) => {
                inside_code = true;
                code.clear();
            }
            Event::End(TagEnd::CodeBlock) => {
                inside_code = false;
                blocks.push(code.clone());
            }
            Event::Text(text) if inside_code => code.push_str(&text),
            Event::Html(_) | Event::InlineHtml(_) => panic!("field escaped into executable HTML"),
            Event::Start(Tag::Link { dest_url, .. } | Tag::Image { dest_url, .. }) => {
                assert!(
                    matches!(
                        dest_url.as_ref(),
                        "report.json"
                            | "baseline.png"
                            | "candidate.png"
                            | "baseline-repeat.png"
                            | "sheet.png"
                    ),
                    "unsafe link: {dest_url}"
                );
                links.push(dest_url.into_string());
            }
            _ => {}
        }
    }
    (blocks, links)
}

#[test]
fn caller_fields_cannot_escape_into_markdown_html_or_external_resources() {
    let attack = "literal data\n```\n# spoofed status\n[leak](https://invalid.example/leak)\n![image](file:///private/data)\n<script>alert(1)</script>\n~~~\n``````\n";
    let mut report = report();
    report.tolerance = Some(Tolerance {
        max_absolute_error: 1,
        rationale: attack.into(),
    });
    report.baseline.source_path = attack.into();
    report.baseline.sha256 = attack.into();
    report.candidate.decoded_sha256 = attack.into();
    report.method = attack.into();
    report.alignment = attack.into();
    report.units = attack.into();
    report.denominator = attack.into();
    report.limitations = vec![attack.into()];
    report.assessment = Observation::Available {
        value: ImageAssessment {
            schema_version: 1,
            baseline_sha256: attack.into(),
            candidate_sha256: attack.into(),
            reviewer: attack.into(),
            protocol: attack.into(),
            prompt_adherence: Observation::Available {
                value: attack.into(),
            },
            artifacts: Observation::Unavailable {
                reason: attack.into(),
            },
            limitations: vec![attack.into()],
        },
    };
    report.baseline_repeat_metrics = Observation::Unavailable {
        reason: attack.into(),
    };
    let mut bytes = Vec::new();
    png_report::write(&mut bytes, &report).unwrap();
    let markdown = String::from_utf8(bytes).unwrap();
    let (blocks, _) = parsed_data(&markdown);
    // Each malicious field remains literal data, rather than being dropped to make
    // the no-HTML/no-external-link assertions trivially pass.
    assert_eq!(
        blocks
            .iter()
            .filter(|block| block.trim_end() == attack.trim_end())
            .count(),
        17
    );
}

#[test]
fn maximum_embedded_fence_and_terminal_controls_remain_inert_readable_data() {
    let mut report = report();
    let attack = format!(
        "{}\n![exfil](https://invalid.example)\n\u{1b}[2J\r\u{7}\tend",
        "`".repeat(8000)
    );
    report.assessment = Observation::Unavailable {
        reason: attack.clone(),
    };
    let mut bytes = Vec::new();
    png_report::write(&mut bytes, &report).unwrap();
    let markdown = String::from_utf8(bytes).unwrap();
    assert!(
        !markdown
            .chars()
            .any(|c| c.is_control() && c != '\n' && c != '\t')
    );
    let (blocks, _) = parsed_data(&markdown);
    let displayed = attack
        .replace('\u{1b}', "\\u{1b}")
        .replace('\r', "\\u{d}")
        .replace('\u{7}', "\\u{7}");
    assert!(
        blocks
            .iter()
            .any(|block| block.trim_end() == displayed.trim_end())
    );
}

#[test]
fn readable_bundle_survives_relocation_and_source_removal_with_verified_local_links() {
    let root = tempfile::tempdir().unwrap();
    let a = root.path().join("baseline [private] #42.png");
    let b = root.path().join("candidate (private).png");
    let repeat = root.path().join("repeat.png");
    png(&a, &[42, 17]);
    png(&b, &[43, 17]);
    png(&repeat, &[42, 18]);
    let output = root.path().join("original-bundle");
    let result = Command::new(env!("CARGO_BIN_EXE_mil"))
        .arg("compare-images")
        .arg("--baseline")
        .arg(&a)
        .arg("--candidate")
        .arg(&b)
        .arg("--baseline-repeat")
        .arg(&repeat)
        .arg("--output-dir")
        .arg(&output)
        .output()
        .unwrap();
    assert_eq!(
        result.status.code(),
        Some(1),
        "{}",
        String::from_utf8_lossy(&result.stderr)
    );
    for path in [&a, &b, &repeat] {
        fs::remove_file(path).unwrap();
    }
    let moved = root.path().join("moved-bundle");
    fs::rename(&output, &moved).unwrap();
    let markdown_bytes = fs::read(moved.join("report.md")).unwrap();
    let report: Value =
        serde_json::from_slice(&fs::read(moved.join("report.json")).unwrap()).unwrap();
    let artifact = report["artifacts"]
        .as_array()
        .unwrap()
        .iter()
        .find(|a| a["path"] == "report.md")
        .unwrap();
    assert_eq!(artifact["bytes"], markdown_bytes.len() as u64);
    assert_eq!(
        artifact["sha256"],
        format!("{:x}", Sha256::digest(&markdown_bytes))
    );
    let (_, links) = parsed_data(std::str::from_utf8(&markdown_bytes).unwrap());
    for link in links {
        assert!(moved.join(link).is_file());
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(
            fs::metadata(moved.join("report.md"))
                .unwrap()
                .permissions()
                .mode()
                & 0o777,
            0o600
        );
    }
}
