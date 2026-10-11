//! Synthetic metadata and saved logs only; none of these fixtures are inference proof.
use media_inference_lab::{
    h3::{self, InspectOptions, PrepareOptions, Profile},
    schema::*,
};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::{fs, os::unix::fs::PermissionsExt, path::Path, time::Duration};
use tempfile::TempDir;

fn workload(profile: Profile) -> Workload {
    let (width, height, steps, every) = match profile {
        Profile::Draft => (864, 480, 8, 1),
        Profile::Standard => (1344, 768, 20, 2),
        Profile::Detailed => (1344, 768, 20, 1),
    };
    serde_json::from_value(json!({
        "schema_version":1,"id":"synthetic-h3-contract","model":{"name":"synthetic-not-a-model","revision":"caller-declared-synthetic","sha256":null},
        "settings":{"modality":"video","generation":{"prompt":"literal ; $(not-a-shell)\ntext", "negative_prompt":null,"seed":17,"resolution":{"width":width,"height":height},"steps":steps,"scheduler":"euler","guidance":1.0,"precision":"bfloat16","compute_precision":null,"quantization":{"kind":"none"},"batch_size":1,"references":[],"strength":null,"optimizations":{"use_kv_cache":null,"step_cache_ratio":null,"step_cache_threshold":null}},"frames":56,"layers":50,"playback_fps":24.0,"render_resolution":null,"reuse":{"kind":"interval","every":every,"core_every":1},"audio":{"kind":"generate","sample_rate_hz":32000,"channels":2}},
        "process_policy":"fresh_process","cache_policy":"unspecified"
    })).unwrap()
}
fn fixture(root: &Path, profile: Profile) -> PrepareOptions {
    for dir in [
        "model/FL2VA/transformer",
        "model/FL2VA/tokenizer",
        "model/FL2VA/text_encoder",
        "model/FL2VA/video_vae/source",
        "model/FL2VA/audio_vae",
        "source",
        "shaders",
    ] {
        fs::create_dir_all(root.join(dir)).unwrap();
    }
    for dir in [
        "transformer",
        "text_encoder",
        "video_vae/source",
        "audio_vae",
    ] {
        fs::write(
            root.join(format!("model/FL2VA/{dir}/synthetic.safetensors")),
            b"not a tensor payload; metadata-only fixture",
        )
        .unwrap();
    }
    for name in [
        "transformer/config.json",
        "tokenizer/tokenizer.json",
        "video_vae/config.json",
        "audio_vae/config.json",
    ] {
        fs::write(
            root.join(format!("model/FL2VA/{name}")),
            b"{\"synthetic\":true}",
        )
        .unwrap();
    }
    for name in [
        "main.c",
        "h3.h",
        "h3.c",
        "h3_gpu.m",
        "h3_host.c",
        "h3_host.h",
        "h3_ffmpeg.c",
        "h3_audio_vae.c",
        "h3_video_encoder.c",
        "h3_dit.c",
        "h3_text_encoder.c",
        "h3_video_vae.c",
        "h3_vision_encoder.c",
    ] {
        fs::write(
            root.join("source").join(name),
            b"synthetic selected-source bytes, not build proof",
        )
        .unwrap();
    }
    fs::write(root.join("shaders/h3_shaders.metal"), b"synthetic shader").unwrap();
    for name in ["native", "ffmpeg", "ffprobe"] {
        // Deliberately not runnable code. Preparation must only read these bytes.
        fs::write(
            root.join(name),
            format!("synthetic {name}, must never execute"),
        )
        .unwrap();
        fs::set_permissions(root.join(name), fs::Permissions::from_mode(0o700)).unwrap();
    }
    PrepareOptions {
        workload: workload(profile),
        profile,
        binary: root.join("native"),
        model_dir: root.join("model"),
        shader_cwd: root.join("shaders"),
        source_dir: root.join("source"),
        input_dir: root.to_path_buf(),
        ffmpeg: root.join("ffmpeg"),
        ffprobe: root.join("ffprobe"),
        output_dir: root.join("prepared"),
    }
}
fn generation(workload: &mut Workload) -> &mut GenerationSettings {
    match &mut workload.settings {
        MediaSettings::Video { generation, .. } => generation,
        _ => unreachable!(),
    }
}
fn row(label: &str, wall: &str) -> String {
    format!(
        "h3 profile: {label:24} total          wall={wall:>8}s encode=  0.125s wait=   0.250s root-gpu=  0.500s peak=  1.500GiB alloc=  2.000GiB submissions=2 direct=3 linear=4 conv=5 attention=6\n"
    )
}

#[test]
fn profiles_preserve_exact_request_and_shell_free_prompt() {
    for profile in [Profile::Draft, Profile::Standard, Profile::Detailed] {
        let temp = TempDir::new().unwrap();
        let options = fixture(temp.path(), profile);
        let plan = h3::build_plan(&options).unwrap();
        assert_eq!(plan.workload, options.workload);
        assert_eq!(plan.workload_identity, options.workload.identity().unwrap());
        assert!(plan.clear_environment);
        assert_eq!(
            plan.environment.keys().cloned().collect::<Vec<_>>(),
            ["H3_FFMPEG", "H3_FFPROBE", "H3_PROFILE"]
        );
        let prompt_index = plan.argv.iter().position(|a| a == "-p").unwrap();
        assert_eq!(
            plan.argv[prompt_index + 1],
            "literal ; $(not-a-shell)\ntext"
        );
        assert!(!plan.argv.iter().any(|a| a == "--render-width"));
        let output_index = plan.argv.iter().position(|a| a == "-o").unwrap();
        let output = Path::new(&plan.argv[output_index + 1]);
        assert!(output.is_absolute());
        assert_eq!(output.parent(), Some(options.output_dir.as_path()));
        assert!(!output.starts_with(&plan.shader_cwd));
        assert!(!output.starts_with(&plan.model_dir));
        assert!(
            !output.exists(),
            "preparation must not create or overwrite a media output"
        );
        assert_eq!(
            plan.declarations["full_observed_model_fingerprint"]["status"],
            "unavailable"
        );
        assert_eq!(
            plan.declarations["compiled_from_selected_source"]["status"],
            "unavailable"
        );
    }
}

#[test]
fn rejects_hidden_overrides_and_unsupported_requests() {
    let temp = TempDir::new().unwrap();
    let mut options = fixture(temp.path(), Profile::Draft);
    let valid = options.workload.clone();
    let invalid: Vec<Box<dyn Fn(&mut Workload)>> = vec![
        Box::new(|w| generation(w).steps = 20),
        Box::new(|w| generation(w).negative_prompt = Some("anything".into())),
        Box::new(|w| generation(w).scheduler = "linear".into()),
        Box::new(|w| generation(w).guidance = 4.0),
        Box::new(|w| generation(w).compute_precision = Some(Precision::Bfloat16)),
        Box::new(|w| generation(w).precision = Precision::Float32),
        Box::new(|w| {
            generation(w).quantization = Quantization::Weights {
                bits: 8,
                method: "native".into(),
            }
        }),
        Box::new(|w| generation(w).optimizations.use_kv_cache = Some(false)),
        Box::new(|w| {
            if let MediaSettings::Video { frames, .. } = &mut w.settings {
                *frames = 23;
            }
        }),
        Box::new(|w| {
            if let MediaSettings::Video { frames, .. } = &mut w.settings {
                *frames = 22;
            }
        }),
        Box::new(|w| {
            if let MediaSettings::Video { audio, .. } = &mut w.settings {
                *audio = AudioConfiguration::Disabled;
            }
        }),
        Box::new(|w| w.cache_policy = CachePolicy::Warm),
    ];
    for change in invalid {
        options.workload = valid.clone();
        change(&mut options.workload);
        assert!(h3::build_plan(&options).is_err());
    }
}

#[test]
fn explicit_internal_canvas_is_separate_from_output() {
    let temp = TempDir::new().unwrap();
    let mut options = fixture(temp.path(), Profile::Standard);
    if let MediaSettings::Video {
        render_resolution, ..
    } = &mut options.workload.settings
    {
        *render_resolution = Some(Resolution {
            width: 672,
            height: 384,
        });
    }
    let plan = h3::build_plan(&options).unwrap();
    assert_eq!(plan.workload, options.workload);
    let index = plan
        .argv
        .iter()
        .position(|a| a == "--render-width")
        .unwrap();
    assert_eq!(plan.argv[index + 1], "672");
    assert_eq!(plan.declarations["modified_internal_canvas"], true);
    if let MediaSettings::Video {
        render_resolution, ..
    } = &mut options.workload.settings
    {
        *render_resolution = Some(Resolution {
            width: 864,
            height: 480,
        });
    }
    assert!(h3::build_plan(&options).is_err());
}

#[test]
fn missing_selected_inputs_identify_the_failed_path_and_preserve_request() {
    for field in ["binary", "model_dir", "shader_cwd", "ffmpeg", "ffprobe"] {
        let temp = TempDir::new().unwrap();
        let mut options = fixture(temp.path(), Profile::Draft);
        let missing = temp.path().join(format!("absent-{field}"));
        match field {
            "binary" => options.binary = missing.clone(),
            "model_dir" => options.model_dir = missing.clone(),
            "shader_cwd" => options.shader_cwd = missing.clone(),
            "ffmpeg" => options.ffmpeg = missing.clone(),
            "ffprobe" => options.ffprobe = missing.clone(),
            _ => unreachable!(),
        }
        let requested = options.workload.clone();
        assert!(!h3::prepare(options).unwrap());
        let report: Value =
            serde_json::from_slice(&fs::read(temp.path().join("prepared/report.json")).unwrap())
                .unwrap();
        assert_eq!(report["requested_workload"], json!(requested));
        assert_eq!(report["selected_paths"][field], json!(missing));
        assert!(
            report["errors"][0]
                .as_str()
                .unwrap()
                .contains(missing.to_str().unwrap())
        );
        assert!(!temp.path().join("prepared/plan.json").exists());
    }
}

#[test]
fn missing_assets_and_invalid_metadata_leave_failed_preparation() {
    let temp = TempDir::new().unwrap();
    let options = fixture(temp.path(), Profile::Draft);
    fs::remove_file(options.shader_cwd.join("h3_shaders.metal")).unwrap();
    assert!(!h3::prepare(options).unwrap());
    let report: Value =
        serde_json::from_slice(&fs::read(temp.path().join("prepared/report.json")).unwrap())
            .unwrap();
    assert_eq!(report["valid"], false);
    assert_eq!(report["execution_attested"], false);
    assert!(!temp.path().join("prepared/plan.json").exists());
    assert_eq!(
        fs::metadata(temp.path().join("prepared"))
            .unwrap()
            .permissions()
            .mode()
            & 0o777,
        0o700
    );
    let temp = TempDir::new().unwrap();
    let options = fixture(temp.path(), Profile::Draft);
    fs::write(
        options.model_dir.join("FL2VA/transformer/config.json"),
        b"[]",
    )
    .unwrap();
    assert!(h3::build_plan(&options).is_err());
    fs::write(
        options.model_dir.join("FL2VA/transformer/config.json"),
        b"{\"synthetic\":true}",
    )
    .unwrap();
    fs::remove_file(
        options
            .model_dir
            .join("FL2VA/audio_vae/synthetic.safetensors"),
    )
    .unwrap();
    assert!(h3::build_plan(&options).is_err());
}

#[test]
fn first_last_anchors_require_exact_png_hashes_and_supported_roles() {
    let temp = TempDir::new().unwrap();
    let mut options = fixture(temp.path(), Profile::Draft);
    let path = temp.path().join("frame.png");
    {
        let mut encoder = png::Encoder::new(fs::File::create(&path).unwrap(), 2, 1);
        encoder.set_color(png::ColorType::Rgb);
        encoder.set_depth(png::BitDepth::Eight);
        encoder
            .write_header()
            .unwrap()
            .write_image_data(&[255, 0, 0, 0, 255, 0])
            .unwrap();
    }
    let bytes = fs::read(&path).unwrap();
    let reference = ReferenceInput {
        path: "frame.png".into(),
        sha256: format!("{:x}", Sha256::digest(&bytes)),
        bytes: bytes.len() as u64,
        role: ReferenceRole::FirstFrame,
        strength: None,
    };
    generation(&mut options.workload).references = vec![reference.clone()];
    let plan = h3::build_plan(&options).unwrap();
    assert_eq!(plan.conditioning[0].input.sha256, reference.sha256);
    assert_eq!(
        (plan.conditioning[0].width, plan.conditioning[0].height),
        (2, 1)
    );
    let mut last = reference.clone();
    last.role = ReferenceRole::LastFrame;
    generation(&mut options.workload).references.push(last);
    assert_eq!(
        h3::build_plan(&options).unwrap().conditioning[1].role,
        ReferenceRole::LastFrame
    );
    generation(&mut options.workload).references[0].sha256 = "0".repeat(64);
    assert!(h3::build_plan(&options).is_err());
    generation(&mut options.workload).references = vec![ReferenceInput {
        role: ReferenceRole::Reference,
        ..reference
    }];
    assert!(h3::build_plan(&options).is_err());
}

#[test]
fn saved_profiles_keep_overlapping_spans_separate_without_inference_total() {
    let logs = row("H3 DiT", "2.000") + &row("audio VAE decoder", "1.000");
    let parsed = h3::parse_profile(logs.as_bytes());
    assert!(matches!(parsed.status, Observation::Available { .. }));
    let wall: Vec<_> = parsed
        .timings
        .iter()
        .filter(|t| t.phase.ends_with("/wall"))
        .map(|t| (&t.phase, &t.measurement))
        .collect();
    assert_eq!(wall.len(), 2);
    assert_eq!(*wall[0].1, Observation::Available { value: 2.0 });
    assert_eq!(*wall[1].1, Observation::Available { value: 1.0 });
    assert_eq!(
        parsed.resources[0].measurement,
        Observation::Available {
            value: 1.5 * 1073741824.0
        }
    );
    assert_eq!(
        parsed.resources[1].measurement,
        Observation::Available {
            value: 2.0 * 1073741824.0
        }
    );
    assert!(parsed.timings.iter().all(|t| t.scope != TimingScope::Host));
    assert_eq!(parsed.dispatch_counts["H3 DiT total"]["submissions"], 2);
}

#[test]
fn unknown_malformed_partial_and_duplicate_profiles_fail_closed() {
    let good = row("H3 DiT", "2.000");
    let allocation_overflow = good.replace("peak=  1.500GiB", &format!("peak= {:.3}GiB", f64::MAX));
    for log in [
        String::new(),
        row("unknown context", "2.000"),
        row("H3 DiT", "NaN"),
        allocation_overflow,
        good.replace("wait=   0.250s ", ""),
        good.replace("attention=6", "attention=6 extra=1"),
        format!("{good}{good}"),
        format!("{good}h3 profile: partial wall=1.000s\n"),
    ] {
        let parsed = h3::parse_profile(log.as_bytes());
        assert!(matches!(parsed.status, Observation::Unavailable { .. }));
        assert!(parsed.timings.is_empty());
        assert!(parsed.resources.is_empty());
    }
}

#[test]
fn nonzero_exit_and_missing_video_retain_raw_unattested_failure() {
    let temp = TempDir::new().unwrap();
    let options = fixture(temp.path(), Profile::Draft);
    let plan = h3::build_plan(&options).unwrap();
    let plan_path = temp.path().join("supplied-plan.json");
    fs::write(&plan_path, serde_json::to_vec(&plan).unwrap()).unwrap();
    let stdout = temp.path().join("supplied-stdout.log");
    let stderr = temp.path().join("supplied-stderr.log");
    fs::write(
        &stdout,
        b"synthetic saved evidence, not inference proof\xff",
    )
    .unwrap();
    fs::write(&stderr, row("H3 DiT", "2.000")).unwrap();
    let output_dir = temp.path().join("inspection");
    assert!(
        !h3::inspect_saved(InspectOptions {
            plan: plan_path,
            stdout: stdout.clone(),
            stderr: stderr.clone(),
            exit_code: 7,
            video: temp.path().join("absent.mp4"),
            output_dir: output_dir.clone(),
            timeout: Duration::from_secs(30)
        })
        .unwrap()
    );
    assert_eq!(
        fs::read(output_dir.join("stdout.log")).unwrap(),
        fs::read(stdout).unwrap()
    );
    assert_eq!(
        fs::read(output_dir.join("stderr.log")).unwrap(),
        fs::read(stderr).unwrap()
    );
    let report: Value =
        serde_json::from_slice(&fs::read(output_dir.join("report.json")).unwrap()).unwrap();
    assert_eq!(report["caller_reported_exit_code"], 7);
    assert_eq!(report["valid"], false);
    assert_eq!(report["capture_eligible"], false);
    assert_eq!(report["execution_attested"], false);
    assert_eq!(report["native_host_duration"]["status"], "unavailable");
    assert!(!output_dir.join("result.json").exists());
    assert_eq!(
        fs::metadata(output_dir.join("stderr.log"))
            .unwrap()
            .permissions()
            .mode()
            & 0o777,
        0o600
    );
}

#[test]
fn native_binary_alias_cannot_be_used_as_offline_media_tool() {
    let temp = TempDir::new().unwrap();
    let options = fixture(temp.path(), Profile::Draft);
    fs::copy(&options.binary, &options.ffmpeg).unwrap();
    assert!(h3::build_plan(&options).is_err());
}

#[test]
fn tampered_saved_plan_is_rejected_before_any_tool_execution() {
    let temp = TempDir::new().unwrap();
    let options = fixture(temp.path(), Profile::Draft);
    let mut plan = h3::build_plan(&options).unwrap();
    plan.environment
        .insert("H3_INT8_MLP_STAGE".into(), "1".into());
    let plan_path = temp.path().join("supplied-plan.json");
    fs::write(&plan_path, serde_json::to_vec(&plan).unwrap()).unwrap();
    let stdout = temp.path().join("stdout.log");
    let stderr = temp.path().join("stderr.log");
    fs::write(&stdout, b"synthetic, not native output").unwrap();
    fs::write(&stderr, b"").unwrap();
    let output_dir = temp.path().join("inspection");
    assert!(
        !h3::inspect_saved(InspectOptions {
            plan: plan_path,
            stdout,
            stderr,
            exit_code: 0,
            video: temp.path().join("absent.mp4"),
            output_dir: output_dir.clone(),
            timeout: Duration::from_secs(30)
        })
        .unwrap()
    );
    let report: Value =
        serde_json::from_slice(&fs::read(output_dir.join("report.json")).unwrap()).unwrap();
    assert_eq!(report["valid"], false);
    assert_eq!(report["video_inspection"], Value::Null);
    assert_eq!(report["observed_runtime_identity"]["status"], "unavailable");
    assert!(!output_dir.join("video").exists());
}
