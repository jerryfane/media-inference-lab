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
    let source = dir.path().join("missing.mp4");
    let output = dir.path().join("new-bundle");
    assert!(!derive(&source, &dir.path().join("missing.json"), &output, Path::new("/unavailable/ffmpeg"), deadline()).unwrap());
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

