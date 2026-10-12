use super::*;

fn deadline() -> Instant { Instant::now() + Duration::from_secs(120) }
fn synthetic_original(samples: u64) -> Value {
    // Parser/arithmetic fixture only. Never used as native evidence or admission.
    json!({"schema_version":1,"kind":"offline_h3_video_inspection","valid":true,"errors":[],
        "workload_identity":WORKLOAD,"helpers":[{"fixture":"synthetic parser record, not an actor"}],
        "expected_output":{"width":WIDTH,"height":HEIGHT,"frames":FRAMES,"playback_fps":24.0,"sample_rate_hz":32000,"channels":2},
        "video":{"width":WIDTH,"height":HEIGHT,"frames":FRAMES,"playback_fps":24.0,"decoded_rgb_bytes":RGB_BYTES,"decoded_rgb_sha256":"0".repeat(64)},
        "audio":{"sample_rate_hz":32000,"channels":2,"validation":"passed","sample_frames":samples,"probed_sample_frames":samples,
            "decoded_pcm_bytes":samples*8,"decoded_pcm_sha256":"0".repeat(64)}})
}
fn synthetic_probe() -> Value {
    let mut frames = Vec::new();
    for i in 0..FRAMES {
        // These are generated metadata fixtures matching ffprobe's decimal
        // serialization, not an extraction fallback used by production code.
        frames.push(json!({"media_type":"video","stream_index":0,"width":WIDTH,"height":HEIGHT,
            "best_effort_timestamp_time":format!("{:.6}", i as f64 / 24.0)}));
    }
    for i in 0..73 {
        frames.push(json!({"media_type":"audio","stream_index":1,"channels":2,"nb_samples":if i == 72 { 672 } else { 1024 },
            "best_effort_timestamp_time":format!("{:.6}", i as f64 * 0.032)}));
    }
    json!({"streams":[{"index":0,"codec_type":"video","width":WIDTH,"height":HEIGHT,"r_frame_rate":"24/1","avg_frame_rate":"24/1","duration":"2.333333"},
        {"index":1,"codec_type":"audio","channels":2,"sample_rate":"32000","duration":"2.325000"}],"frames":frames})
}
fn pcm(values: &[f32]) -> Vec<u8> { values.iter().flat_map(|v| v.to_le_bytes()).collect() }
fn small_png(path: &Path, rgb: &[u8], width: u32) {
    let mut encoder = png::Encoder::new(io::private(path).unwrap(), width, 1);
    encoder.set_color(png::ColorType::Rgb);
    encoder.set_depth(png::BitDepth::Eight);
    let mut writer = encoder.write_header().unwrap();
    writer.write_image_data(rgb).unwrap();
    writer.finish().unwrap();
}

#[test]
fn media_exact_decimal_timeline_and_late_mismatch() {
    let original = synthetic_original(74400);
    let probe = synthetic_probe();
    let a = alignment(&probe, &original, deadline()).unwrap();
    assert_eq!(a.sequence.frames[1].pts_ns, 41_667_000);
    assert_eq!(a.sequence.frames[1].duration_ns, 41_666_000);
    assert_eq!(a.sequence.frames[55].pts_ns + a.sequence.frames[55].duration_ns, 2_333_333_000);
    let mut changed = probe.clone();
    // Within original probe's precision allowance, but not equal pair timing.
    changed["frames"][55]["best_effort_timestamp_time"] = json!("2.291666");
    let b = alignment(&changed, &original, deadline()).unwrap();
    assert!(pair_alignment(&a, &b).is_err());
    changed["frames"][55]["best_effort_timestamp_time"] = json!("2.350000");
    assert!(alignment(&changed, &original, deadline()).is_err());
    assert!(nanoseconds(&json!("0.0000000001")).is_err());
    assert!(nanoseconds(&json!("-0.000001")).is_err());
}

#[test]
fn media_late_frame_count_and_dimension_errors() {
    let original = synthetic_original(74400);
    let mut probe = synthetic_probe();
    probe["frames"][55]["width"] = json!(863);
    assert!(alignment(&probe, &original, deadline()).is_err());
    let mut probe = synthetic_probe();
    probe["frames"].as_array_mut().unwrap().remove(55);
    assert!(alignment(&probe, &original, deadline()).is_err());
}

#[test]
fn media_pcm_finite_count_channels_and_denominators() {
    let left = pcm(&[0.0, 0.0, 0.0, 0.0]);
    let right = pcm(&[1.0, 2.0, 3.0, 4.0]);
    let result = compare_pcm(&left, &right, 2, deadline()).unwrap();
    assert_eq!(result["full_stream_equal"], false);
    assert_eq!(result["aggregate"]["sample_count"], 4);
    assert_eq!(result["aggregate"]["absolute_error_sum"], 10.0);
    assert_eq!(result["aggregate"]["squared_error_sum"], 30.0);
    assert_eq!(result["aggregate"]["max_absolute_error"], 4.0);
    assert_eq!(result["aggregate"]["mean_absolute_error"], 2.5);
    assert_eq!(result["aggregate"]["root_mean_squared_error"], 7.5f64.sqrt());
    assert_eq!(result["per_channel"][0]["metrics"]["sample_count"], 2);
    assert_eq!(result["per_channel"][0]["metrics"]["mean_absolute_error"], 2.0);
    assert_eq!(result["per_channel"][1]["metrics"]["mean_absolute_error"], 3.0);
    assert!(validate_pcm(&pcm(&[f32::NAN, 0.0]), 1, 2).is_err());
    assert!(validate_pcm(&pcm(&[0.0, f32::INFINITY]), 1, 2).is_err());
    assert!(validate_pcm(&pcm(&[0.0, f32::NEG_INFINITY]), 1, 2).is_err());
    assert!(compare_pcm(&left, &right[..12], 2, deadline()).is_err());
    assert!(compare_pcm(&left, &right, 3, deadline()).is_err());
    assert!(validate_pcm(&left, 2, 1).is_err());
    assert!(validate_pcm(&[], 0, 2).is_err());
    assert!(validate_pcm(&right[..15], 2, 2).is_err());
}

#[test]
fn media_pcm_original_count_and_alignment_errors() {
    let probe = synthetic_probe();
    let original = synthetic_original(74400);
    let a = alignment(&probe, &original, deadline()).unwrap();
    let mut changed = probe.clone();
    let last = changed["frames"].as_array().unwrap().len() - 1;
    changed["frames"][last]["best_effort_timestamp_time"] = json!("2.304001");
    let b = alignment(&changed, &original, deadline()).unwrap();
    assert!(pair_alignment(&a, &b).is_err());
    changed["frames"][last]["best_effort_timestamp_time"] = json!("2.400000");
    assert!(alignment(&changed, &original, deadline()).is_err());
    let mut changed = probe.clone();
    changed["frames"][last]["nb_samples"] = json!(671);
    assert!(alignment(&changed, &original, deadline()).is_err());
    let mut changed = probe;
    changed["frames"][last]["channels"] = json!(1);
    assert!(alignment(&changed, &original, deadline()).is_err());
}

#[test]
fn media_late_png_hash_is_checked_after_every_frame() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("frame.png");
    let pixels = vec![0; FRAME_BYTES];
    write_png(&path, &pixels, &mut Budget::new(), deadline()).unwrap();
    let decoded = png_image::decode(&path).unwrap();
    let id = decoded.identity();
    let encoded = std::fs::read(&path).unwrap();
    for index in 0..FRAMES {
        io::private(&dir.path().join(format!("frame-{index:02}.png"))).unwrap().write_all(&encoded).unwrap();
    }
    let mut records: Vec<Value> = (0..FRAMES).map(|index| json!({"index":index,"sha256":id.sha256,"bytes":id.bytes,
        "decoded_sha256":id.decoded_sha256})).collect();
    records[55]["sha256"] = json!("f".repeat(64));
    let input = SequenceInput { schema_version:1, frame_count:FRAMES as u32, provenance:"synthetic all-frame regression, not native evidence".into(),
        frames:(0..FRAMES).map(|i| FrameInput { index:i as u32,path:format!("frame-{i:02}.png").into(),pts_ns:i as u64,duration_ns:1 }).collect() };
    let mut visited = 0;
    let result = frame_sequence::compare(SequenceSource { input:&input,directory:dir.path() },
        SequenceSource { input:&input,directory:dir.path() },None,None,None,|index,a,_,_| {
            visited += 1;
            check_frame(a, &records[index as usize], index as usize)
        });
    assert!(result.is_err());
    assert_eq!(visited, 56);
}

#[test]
fn media_image_numerics_use_actual_channel_denominator() {
    let dir = tempfile::tempdir().unwrap();
    let left = dir.path().join("left.png");
    let right = dir.path().join("right.png");
    small_png(&left, &[0,0,0,0,0,0], 2);
    small_png(&right, &[1,2,3,4,5,6], 2);
    let compared = compare_images(&left, &right, deadline()).unwrap();
    assert_eq!(compared["metrics"]["sample_count"], 6);
    assert_eq!(compared["metrics"]["absolute_error_sum"], 21);
    assert_eq!(compared["metrics"]["squared_error_sum"], 91);
    assert_eq!(compared["metrics"]["mean_absolute_error"], 3.5);
    assert!(compared.get("candidate").is_none());
    assert!(compared.get("classification").is_none());
}

#[test]
fn media_failed_derive_retains_private_report_without_overwrite() {
    use std::os::unix::fs::PermissionsExt;
    let dir = tempfile::tempdir().unwrap();
    let inputs = dir.path().join("inputs");
    std::fs::create_dir(&inputs).unwrap();
    let source = inputs.join("missing.mp4");
    let output = dir.path().join("new-bundle");
    assert!(!derive(&source, &inputs.join("missing.json"), &output, Path::new("/unavailable/ffmpeg"), deadline()).unwrap());
    let report = output.join("report.json");
    assert_eq!(std::fs::metadata(&output).unwrap().permissions().mode() & 0o777, 0o700);
    assert_eq!(std::fs::metadata(&report).unwrap().permissions().mode() & 0o777, 0o600);
    assert!(derive(&source, &source, &output, &source, deadline()).is_err());
}

#[test]
fn media_combined_metadata_budget_fails_closed() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("metadata.json");
    io::private(&path).unwrap().write_all(b"{}\n").unwrap();
    set_metadata_budget(2);
    assert!(io::read(&path, METADATA_LIMIT, deadline()).is_err());
    set_metadata_budget(256 * MIB);
}


#[test]
fn review_output_nested_and_aliased_inputs_rejected_before_mutation() {
    use std::os::unix::fs::symlink;
    let dir = tempfile::tempdir().unwrap();
    let source_dir = dir.path().join("source");
    let inspection_dir = dir.path().join("inspection");
    for path in [&source_dir, &inspection_dir] { std::fs::create_dir(path).unwrap(); }
    let source = source_dir.join("original.mp4");
    let inspection = inspection_dir.join("report.json");
    std::fs::write(&source, b"immutable synthetic source").unwrap();
    std::fs::write(&inspection, b"immutable synthetic inspection").unwrap();
    for (index, input) in [&source_dir, &inspection_dir].iter().enumerate() {
        let nested = input.join("nested");
        std::fs::create_dir(&nested).unwrap();
        let alias = dir.path().join(format!("alias-{index}"));
        symlink(&nested, &alias).unwrap();
        for parent in [input.to_path_buf(), nested, alias] {
            let output = parent.join("must-not-exist");
            let error = derive(&source, &inspection, &output, Path::new("/not-invoked"), deadline()).unwrap_err();
            assert!(error.to_string().contains("outside immutable input directories"), "{error:#}");
            assert!(!output.exists());
        }
    }
    assert_eq!(std::fs::read(&source).unwrap(), b"immutable synthetic source");
    assert_eq!(std::fs::read(&inspection).unwrap(), b"immutable synthetic inspection");
}

#[test]
fn review_separate_failed_derivation_retains_report_and_originals() {
    use std::os::unix::fs::PermissionsExt;
    let dir = tempfile::tempdir().unwrap();
    let inputs = dir.path().join("inputs");
    std::fs::create_dir(&inputs).unwrap();
    let source = inputs.join("original.mp4");
    let inspection = inputs.join("report.json");
    std::fs::write(&source, b"synthetic source, no decoding").unwrap();
    std::fs::write(&inspection, b"synthetic invalid inspection").unwrap();
    let output = dir.path().join("separate-failure");
    assert!(!derive(&source, &inspection, &output, Path::new("/not-invoked"), deadline()).unwrap());
    let retained = std::fs::read(output.join("report.json")).unwrap();
    let report: Value = serde_json::from_slice(&retained).unwrap();
    assert_eq!(report["valid"], false);
    assert_eq!(report["helpers"], json!([]));
    assert!(!report["errors"].as_array().unwrap().is_empty());
    assert_eq!(std::fs::metadata(&output).unwrap().permissions().mode() & 0o777, 0o700);
    assert_eq!(std::fs::metadata(output.join("report.json")).unwrap().permissions().mode() & 0o777, 0o600);
    assert!(derive(&source, &inspection, &output, Path::new("/not-invoked"), deadline()).is_err());
    assert_eq!(std::fs::read(output.join("report.json")).unwrap(), retained);
    assert_eq!(std::fs::read(source).unwrap(), b"synthetic source, no decoding");
    assert_eq!(std::fs::read(inspection).unwrap(), b"synthetic invalid inspection");
}

fn review_save_report(root: &Path, report: &Value) {
    std::fs::write(root.join("report.json"), serde_json::to_vec(report).unwrap()).unwrap();
}

// Entirely synthetic: fixture bytes are created directly, without any process,
// native receipt, probe invocation, decoder binary, or historical evidence.
fn review_bundle_fixture(with_sheet: bool) -> (tempfile::TempDir, PathBuf, Value) {
    set_metadata_budget(256 * MIB);
    let dir = tempfile::tempdir().unwrap();
    let base = dir.path().canonicalize().unwrap();
    let inputs = base.join("originals");
    let root = base.join("bundle");
    std::fs::create_dir(&inputs).unwrap();
    std::fs::create_dir(&root).unwrap();
    let source = inputs.join("synthetic.mp4");
    std::fs::write(&source, b"synthetic binding only; not an encoded video").unwrap();
    let source_id = identity(&source, SOURCE_LIMIT, deadline()).unwrap();
    let probe = synthetic_probe();
    let probe_bytes = serde_json::to_vec(&probe).unwrap();
    std::fs::write(inputs.join("probe.json"), &probe_bytes).unwrap();
    std::fs::write(root.join("probe.json"), &probe_bytes).unwrap();
    let samples = 72 * 1024 + 672;
    let pcm = vec![0; samples * 8];
    std::fs::write(root.join("audio.f32le"), &pcm).unwrap();
    let mut original = synthetic_original(samples as u64);
    original["source"] = source_id.clone();
    original["audio"]["decoded_pcm_sha256"] = json!(io::digest(&pcm));
    original["tools"] = json!([{"name":"ffmpeg","path":"/synthetic/not-invoked/ffmpeg","sha256":FFMPEG_SHA256,"version":"synthetic"}]);
    original["artifacts"] = json!([{"role":"frame_metadata","path":"probe.json","sha256":io::digest(&probe_bytes),"bytes":probe_bytes.len()}]);
    let aligned = alignment(&probe, &original, deadline()).unwrap();
    let mut budget = Budget::new();
    let pixels = vec![0; FRAME_BYTES];
    write_png(&root.join("frame-00.png"), &pixels, &mut budget, deadline()).unwrap();
    let encoded = std::fs::read(root.join("frame-00.png")).unwrap();
    let mut frames = Vec::with_capacity(FRAMES);
    let mut rgb = Sha256::new();
    for index in 0..FRAMES {
        let path = format!("frame-{index:02}.png");
        if index > 0 { std::fs::write(root.join(&path), &encoded).unwrap(); }
        rgb.update(&pixels);
        frames.push(json!({"index":index,"path":path,"sha256":io::digest(&encoded),"bytes":encoded.len(),
            "decoded_sha256":io::digest(&pixels),"pts_ns":aligned.sequence.frames[index].pts_ns,
            "duration_ns":aligned.sequence.frames[index].duration_ns}));
    }
    let rgb_sha = format!("{:x}", rgb.finalize());
    original["video"]["decoded_rgb_sha256"] = json!(rgb_sha);
    let inspection_bytes = serde_json::to_vec(&original).unwrap();
    let inspection = inputs.join("inspection.json");
    std::fs::write(&inspection, &inspection_bytes).unwrap();
    std::fs::write(root.join("original-inspection.json"), &inspection_bytes).unwrap();
    let mut helpers = Vec::new();
    for label in ["video-decode", "audio-decode"] {
        let path = format!("{label}.stderr");
        std::fs::write(root.join(&path), b"").unwrap();
        let command = media_process::command(Path::new("/synthetic/not-invoked/ffmpeg"), &source, &root, label == "audio-decode").unwrap();
        helpers.push(json!({"label":label,"created":true,"spawn_failure":null,"execution_error":null,
            "settlement_error":null,"diagnostic_error":null,
            "command":command,"stdout_bytes":if label == "video-decode" { RGB_BYTES } else { pcm.len() as u64 },
            "stderr_bytes":0,"diagnostics_truncated":false,
            "settlement":{"complete":true,"leader_reaped":true,"group_absent":true,"exit_code":0},
            "stderr":{"path":path,"sha256":io::digest(b""),"bytes":0}}));
    }
    let contact_sheet = if with_sheet { sheet(&root, &frames, &mut budget, deadline()).unwrap() } else { Value::Null };
    let report = json!({"schema_version":1,"kind":"unchanged_h3_offline_derived_media","valid":true,"errors":[],
        "source":source_id,"inspection":{"path":inspection,"sha256":io::digest(&inspection_bytes),"bytes":inspection_bytes.len()},
        "original_inspection_path":"original-inspection.json","original_tools":original["tools"],
        "decoder":{"path":"/synthetic/not-invoked/ffmpeg","sha256":FFMPEG_SHA256,"bytes":1},
        "probe":{"path":"probe.json","original_path":inputs.join("probe.json"),"sha256":io::digest(&probe_bytes),"bytes":probe_bytes.len()},
        "sequence":aligned.sequence,"video_timeline":aligned.video_timeline,"audio_timeline":aligned.audio_timeline,
        "video_stream":aligned.video_stream,"audio_stream":aligned.audio_stream,"timing_method":TIMELINE_METHOD,
        "video":{"decoded_rgb_bytes":RGB_BYTES,"completed_frames":FRAMES,"decoded_rgb_sha256":rgb_sha,"reconstructed_rgb_sha256":rgb_sha},
        "frames":frames,"audio":{"path":"audio.f32le","sha256":io::digest(&pcm),"bytes":pcm.len(),
            "sample_frames":samples,"channels":2,"sample_rate_hz":32000},
        "contact_sheet":contact_sheet,"helpers":helpers});
    review_save_report(&root, &report);
    (dir, root, report)
}

#[test]
fn review_bundle_validates_all_actual_pngs_and_reconstructed_hash() {
    let (_dir, root, mut report) = review_bundle_fixture(true);
    let before = metadata_bytes_read();
    let valid = validate_bundle(&root, deadline()).unwrap();
    assert_eq!(valid["video"]["frame_count"], FRAMES);
    assert_eq!(valid["video"]["decoded_rgb_bytes"], RGB_BYTES);
    assert_eq!(valid["contact_sheet_validated"], true);
    assert_eq!(valid["source"], report["source"]);
    assert_eq!(valid["inspection"], report["inspection"]);
    assert!(metadata_bytes_read() > before);
    // A corrupt last actual PNG cannot inherit availability from valid metadata.
    let last = root.join("frame-55.png");
    std::fs::write(&last, b"not a PNG").unwrap();
    assert!(validate_bundle(&root, deadline()).is_err());
    std::fs::remove_file(&last).unwrap();
    let mut pixels = vec![0; FRAME_BYTES];
    pixels[FRAME_BYTES - 1] = 1;
    write_png(&last, &pixels, &mut Budget::new(), deadline()).unwrap();
    let id = identity(&last, 16 * MIB, deadline()).unwrap();
    report["frames"][55]["sha256"] = id["sha256"].clone();
    report["frames"][55]["bytes"] = id["bytes"].clone();
    report["frames"][55]["decoded_sha256"] = json!(io::digest(&pixels));
    review_save_report(&root, &report);
    let error = validate_bundle(&root, deadline()).unwrap_err();
    assert!(error.to_string().contains("re-concatenated PNG RGB hash mismatch"), "{error:#}");
}

#[test]
fn review_bundle_rejects_actual_pcm_and_declared_hash_count_corruption() {
    let (_dir, root, report) = review_bundle_fixture(true);
    assert!(validate_bundle(&root, deadline()).is_ok());
    let pcm_path = root.join("audio.f32le");
    let original_pcm = std::fs::read(&pcm_path).unwrap();
    let mut corrupt_pcm = original_pcm.clone();
    let end = corrupt_pcm.len();
    corrupt_pcm[end - 4..].copy_from_slice(&f32::NAN.to_le_bytes());
    std::fs::write(&pcm_path, &corrupt_pcm).unwrap();
    assert!(validate_bundle(&root, deadline()).is_err());
    std::fs::write(&pcm_path, &original_pcm[..original_pcm.len() - 8]).unwrap();
    assert!(validate_bundle(&root, deadline()).is_err());
    std::fs::write(&pcm_path, &original_pcm).unwrap();
    for (section, field, value) in [
        ("audio", "sha256", json!("f".repeat(64))),
        ("audio", "bytes", json!(original_pcm.len() - 8)),
        ("audio", "sample_frames", json!(1)),
        ("video", "completed_frames", json!(55)),
        ("video", "decoded_rgb_bytes", json!(RGB_BYTES - 3)),
        ("video", "reconstructed_rgb_sha256", json!("f".repeat(64))),
    ] {
        let mut corrupt = report.clone();
        corrupt[section][field] = value;
        review_save_report(&root, &corrupt);
        assert!(validate_bundle(&root, deadline()).is_err(), "{section}.{field}");
    }
    let mut corrupt = report.clone();
    corrupt["frames"][55]["bytes"] = json!(1);
    review_save_report(&root, &corrupt);
    assert!(validate_bundle(&root, deadline()).is_err());
    review_save_report(&root, &report);
    // Even coherently rebound synthetic hashes cannot make NaN PCM available.
    let mut nonfinite = report.clone();
    std::fs::write(&pcm_path, &corrupt_pcm).unwrap();
    nonfinite["audio"]["sha256"] = json!(io::digest(&corrupt_pcm));
    let original_path = root.join("original-inspection.json");
    let mut original: Value = serde_json::from_slice(&std::fs::read(&original_path).unwrap()).unwrap();
    original["audio"]["decoded_pcm_sha256"] = nonfinite["audio"]["sha256"].clone();
    let original_bytes = serde_json::to_vec(&original).unwrap();
    std::fs::write(&original_path, &original_bytes).unwrap();
    std::fs::write(Path::new(nonfinite["inspection"]["path"].as_str().unwrap()), &original_bytes).unwrap();
    nonfinite["inspection"]["sha256"] = json!(io::digest(&original_bytes));
    nonfinite["inspection"]["bytes"] = json!(original_bytes.len());
    review_save_report(&root, &nonfinite);
    let error = validate_bundle(&root, deadline()).unwrap_err();
    assert!(error.to_string().contains("nonfinite PCM sample"), "{error:#}");
}

#[test]
fn review_bundle_rejects_truncated_contact_sheet_terminal_chunks() {
    let (_dir, root, mut report) = review_bundle_fixture(true);
    let path = root.join("all-frames.png");
    let bytes = std::fs::read(&path).unwrap();
    assert_eq!(&bytes[bytes.len() - 8..bytes.len() - 4], b"IEND");
    // Keep every encoded sample but remove the terminal chunk. Rebind the
    // claimed artifact hash/count so only complete PNG parsing can reject it.
    let truncated = &bytes[..bytes.len() - 12];
    std::fs::write(&path, truncated).unwrap();
    report["contact_sheet"]["sha256"] = json!(io::digest(truncated));
    report["contact_sheet"]["bytes"] = json!(truncated.len());
    review_save_report(&root, &report);
    assert!(validate_bundle(&root, deadline()).is_err());
}

#[test]
fn final_review_missing_contact_sheet_makes_bundle_unavailable() {
    let (_dir, root, mut report) = review_bundle_fixture(false);
    assert!(load_bundle(&root, deadline()).is_err());
    assert!(validate_bundle(&root, deadline()).is_err());
    report.as_object_mut().unwrap().remove("contact_sheet");
    review_save_report(&root, &report);
    assert!(validate_bundle(&root, deadline()).is_err());
}
