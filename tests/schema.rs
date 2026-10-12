use media_inference_lab::schema::{
    AdapterResult, MediaSettings, Observation, OutputEvidence, Precision, ResourceScope,
    ReusePolicy, Workload, validate_artifact_path,
};
use serde_json::{Value, json};

fn image() -> Workload {
    serde_json::from_str(include_str!("../examples/image-workload.json")).unwrap()
}

fn video() -> Workload {
    serde_json::from_str(include_str!("../examples/video-workload.json")).unwrap()
}

fn image_result() -> AdapterResult {
    serde_json::from_str(include_str!("fixtures/image-result.json")).unwrap()
}

fn error_contains<T>(result: anyhow::Result<T>, expected: &str) {
    let error = result.err().expect("invalid evidence was accepted");
    assert!(
        format!("{error:#}").contains(expected),
        "expected {expected:?}, got {error:#}"
    );
}

#[test]
fn complete_image_and_video_contracts_roundtrip_without_losing_evidence() {
    for (workload, fixture) in [
        (image(), include_str!("fixtures/image-result.json")),
        (video(), include_str!("fixtures/video-result.json")),
    ] {
        let result: AdapterResult = serde_json::from_str(fixture).unwrap();
        result.validate(&workload).unwrap();
        assert_eq!(result.workload_identity, workload.identity().unwrap());
        let restored: AdapterResult =
            serde_json::from_slice(&serde_json::to_vec(&result).unwrap()).unwrap();
        assert_eq!(restored, result);
        restored.validate(&workload).unwrap();
        assert!(matches!(
            restored.runtime.model,
            Observation::Unavailable { .. }
        ));
        assert!(matches!(
            restored.output_evidence,
            OutputEvidence::Unassessed { .. }
        ));
    }
}

#[test]
fn all_declared_identity_dimensions_affect_identity() {
    let request = image();
    let original = request.identity().unwrap();
    let value = serde_json::to_value(&request).unwrap();
    let mutations = [
        ("/id", json!("another-sample")),
        ("/model/name", json!("other-model")),
        ("/model/revision", json!("revision-two")),
        ("/model/sha256", json!("a".repeat(64))),
        (
            "/settings/generation/prompt",
            json!(" A geometric paper sculpture on a plain background."),
        ),
        ("/settings/generation/negative_prompt", json!("blur")),
        ("/settings/generation/seed", json!(18)),
        ("/settings/generation/resolution/width", json!(513)),
        ("/settings/generation/resolution/height", json!(513)),
        ("/settings/generation/steps", json!(5)),
        ("/settings/generation/scheduler", json!("other-scheduler")),
        ("/settings/generation/guidance", json!(1.1)),
        ("/settings/generation/precision", json!("float16")),
        ("/settings/generation/compute_precision", json!("bfloat16")),
        (
            "/settings/generation/quantization",
            json!({"kind":"weights","bits":8,"method":"declared-test"}),
        ),
        ("/settings/generation/batch_size", json!(2)),
        ("/settings/generation/strength", json!(0.5)),
        (
            "/settings/generation/optimizations/use_kv_cache",
            json!(true),
        ),
        (
            "/settings/generation/optimizations/step_cache_ratio",
            json!(0.2),
        ),
        (
            "/settings/generation/optimizations/step_cache_threshold",
            json!(0.1),
        ),
        (
            "/settings/generation/references",
            json!([{"path":"inputs/reference.png","sha256":"b".repeat(64),"bytes":100,"role":"reference","strength":0.7}]),
        ),
        ("/process_policy", json!("in_process")),
        ("/cache_policy", json!("warm")),
    ];
    for (pointer, replacement) in mutations {
        let mut changed = value.clone();
        *changed.pointer_mut(pointer).unwrap() = replacement;
        let changed: Workload = serde_json::from_value(changed).unwrap();
        assert_ne!(
            changed.identity().unwrap(),
            original,
            "identity omitted {pointer}"
        );
        error_contains(image_result().validate(&changed), "workload_identity");
    }
    let original = video().identity().unwrap();
    let value = serde_json::to_value(video()).unwrap();
    for (pointer, replacement) in [
        ("/settings/frames", json!(23)),
        ("/settings/playback_fps", json!(30.0)),
        (
            "/settings/render_resolution",
            json!({"width":320,"height":180}),
        ),
        ("/settings/layers", json!(49)),
        (
            "/settings/reuse",
            json!({"kind":"approximate","method":"declared-test","ratio":0.3,"core_ratio":0.1,"layers":[1,3]}),
        ),
        (
            "/settings/audio",
            json!({"kind":"generate","sample_rate_hz":48000,"channels":2}),
        ),
    ] {
        let mut changed = value.clone();
        *changed.pointer_mut(pointer).unwrap() = replacement;
        let changed: Workload = serde_json::from_value(changed).unwrap();
        assert_ne!(
            changed.identity().unwrap(),
            original,
            "identity omitted {pointer}"
        );
    }
}

#[test]
fn resolved_settings_cannot_silently_change_even_with_matching_claimed_identity() {
    let request = image();
    let mut result = image_result();
    if let MediaSettings::Image { generation } = &mut result.resolved.settings {
        generation.steps += 1;
    }
    error_contains(result.validate(&request), "resolved workload differs");
    let mut result = image_result();
    result.workload_identity = "0".repeat(64);
    error_contains(
        result.validate(&request),
        "workload_identity does not match",
    );
}

#[test]
fn nullable_compute_override_preserves_image_and_video_fidelity() {
    for fixture in [
        include_str!("fixtures/image-result.json"),
        include_str!("fixtures/video-result.json"),
    ] {
        let original: AdapterResult = serde_json::from_str(fixture).unwrap();
        for (requested_compute, resolved_compute, accepted) in [
            (None, None, true),
            (None, Some(Precision::Float16), true),
            (None, Some(Precision::Bfloat16), true),
            (None, Some(Precision::Auto), false),
            (Some(Precision::Float16), None, false),
            (Some(Precision::Float16), Some(Precision::Float16), true),
            (Some(Precision::Float16), Some(Precision::Bfloat16), false),
            (Some(Precision::Float16), Some(Precision::Auto), false),
        ] {
            let mut request = original.resolved.clone();
            let generation = match &mut request.settings {
                MediaSettings::Image { generation } | MediaSettings::Video { generation, .. } => {
                    generation
                }
            };
            generation.precision = Precision::Bfloat16;
            generation.compute_precision = requested_compute;
            let mut result = original.clone();
            result.workload_identity = request.identity().unwrap();
            result.resolved = request.clone();
            let generation = match &mut result.resolved.settings {
                MediaSettings::Image { generation }
                | MediaSettings::Video { generation, .. } => generation,
            };
            generation.compute_precision = resolved_compute;
            assert_eq!(
                result.validate(&request).is_ok(),
                accepted,
                "requested {requested_compute:?}, resolved {resolved_compute:?}"
            );
            if accepted {
                let generation = match &mut result.resolved.settings {
                    MediaSettings::Image { generation }
                    | MediaSettings::Video { generation, .. } => generation,
                };
                generation.seed += 1;
                error_contains(result.validate(&request), "resolved workload differs");
            }
        }
    }
}

#[test]
fn nonfinite_and_out_of_range_workloads_are_rejected_before_identity() {
    for (pointer, replacement, message) in [
        (
            "/settings/generation/resolution/width",
            json!(0),
            "resolution",
        ),
        ("/settings/generation/steps", json!(0), "steps"),
        ("/settings/generation/batch_size", json!(0), "batch_size"),
        ("/settings/generation/guidance", json!(-1.0), "guidance"),
        ("/settings/generation/strength", json!(1.1), "strength"),
        (
            "/settings/generation/optimizations/step_cache_ratio",
            json!(1.1),
            "step_cache_ratio",
        ),
        (
            "/settings/generation/optimizations/step_cache_threshold",
            json!(-0.1),
            "step_cache_threshold",
        ),
        ("/settings/generation/scheduler", json!(" "), "scheduler"),
        ("/model/sha256", json!("not-a-hash"), "sha256"),
    ] {
        let mut value = serde_json::to_value(image()).unwrap();
        *value.pointer_mut(pointer).unwrap() = replacement;
        let request: Workload = serde_json::from_value(value).unwrap();
        error_contains(request.identity(), message);
    }
    for number in [f64::NAN, f64::INFINITY, f64::NEG_INFINITY] {
        let mut request = image();
        if let MediaSettings::Image { generation } = &mut request.settings {
            generation.guidance = number;
        }
        error_contains(request.identity(), "guidance");
    }
}

#[test]
fn video_constraints_are_modality_specific_not_h3_specific() {
    let mut request = video();
    if let MediaSettings::Video {
        frames,
        playback_fps,
        ..
    } = &mut request.settings
    {
        *frames = 1;
        *playback_fps = 29.97;
    }
    request.validate().unwrap();
    if let MediaSettings::Video { frames, .. } = &mut request.settings {
        *frames = 0;
    }
    error_contains(request.validate(), "frames");
    let mut value = serde_json::to_value(image()).unwrap();
    value["settings"]["generation"]["references"] = json!([{"path":"inputs/first.png","sha256":"b".repeat(64),"bytes":100,"role":"first_frame","strength":null}]);
    let request: Workload = serde_json::from_value(value).unwrap();
    error_contains(request.validate(), "image references");
    let mut value = serde_json::to_value(video()).unwrap();
    value["settings"]["audio"] = json!({"kind":"reference","input":{"path":"inputs/audio.wav","sha256":"b".repeat(64),"bytes":100,"role":"reference","strength":null}});
    let request: Workload = serde_json::from_value(value).unwrap();
    error_contains(request.validate(), "audio role");
}

#[test]
fn unsafe_artifact_paths_and_cross_platform_aliases_are_rejected() {
    for path in [
        "",
        "/absolute",
        "../escape",
        "a/../b",
        "./a",
        "a/./b",
        "a//b",
        "a/",
        "C:/file",
        "C:file",
        "a\\b",
        "\\\\server\\share",
        "a\0b",
        "a\nb",
        "a:stream",
        "a?b",
        "a*b",
        "a|b",
        "a< b",
        "a> b",
        "a\"b",
        "CON",
        "nul.png",
        "com1.txt",
        "LPT9",
        "COM¹",
        "conin$",
        "name.",
        "name ",
        "manifest.json",
        "RESULT.JSON",
        "stdout.log/child",
        "requested.json",
        "stderr.log",
    ] {
        assert!(
            validate_artifact_path(path).is_err(),
            "unsafe path accepted: {path:?}"
        );
    }
    for path in [
        "artifacts/image.png",
        "video/frames/frame-00001.png",
        "nested/COM10.png",
        "image with spaces.png",
    ] {
        validate_artifact_path(path).unwrap();
    }
    let mut result = image_result();
    let mut duplicate = result.artifacts[0].clone();
    duplicate.path = duplicate.path.to_uppercase();
    result.artifacts.push(duplicate);
    error_contains(result.validate(&image()), "duplicate artifact path");
    let mut result = image_result();
    let mut child = result.artifacts[0].clone();
    child.path.push_str("/child.txt");
    result.artifacts.push(child);
    error_contains(result.validate(&image()), "used as its directory");
}

#[test]
fn unsupported_versions_and_unknown_contract_fields_are_not_accepted() {
    let mut request = image();
    request.schema_version = 2;
    error_contains(request.validate(), "unsupported workload schema_version");
    let mut result = image_result();
    result.schema_version = 3;
    error_contains(
        result.validate(&image()),
        "unsupported adapter result schema_version",
    );
    for pointer in [
        "",
        "/model",
        "/settings",
        "/settings/generation",
        "/settings/generation/optimizations",
    ] {
        let mut value = serde_json::to_value(image()).unwrap();
        value
            .pointer_mut(pointer)
            .unwrap()
            .as_object_mut()
            .unwrap()
            .insert("future_setting".into(), json!(true));
        assert!(
            serde_json::from_value::<Workload>(value).is_err(),
            "unknown field accepted at {pointer}"
        );
    }
    let mut value = serde_json::to_value(image()).unwrap();
    value["settings"]["frames"] = json!(22);
    assert!(
        serde_json::from_value::<Workload>(value).is_err(),
        "image accepted a video-only field"
    );
    let mut value = serde_json::to_value(image_result()).unwrap();
    value["runtime"]["device"]["status"] = json!("assumed");
    assert!(serde_json::from_value::<AdapterResult>(value).is_err());
}

#[test]
fn malformed_measurements_and_missing_evidence_cannot_be_success_results() {
    let valid = serde_json::to_value(image_result()).unwrap();
    for (pointer, replacement, expected) in [
        ("/artifacts", json!([]), "at least one artifact"),
        ("/artifacts/0/sha256", json!("bad"), "artifact sha256"),
        ("/artifacts/0/role", json!(""), "artifact role"),
        ("/timings", json!([]), "timing measurements"),
        (
            "/timings/0/measurement",
            json!({"status":"available","value":-1.0}),
            "timing value",
        ),
        ("/timings/0/measurement/reason", json!(""), "reason"),
        ("/timings/0/boundary", json!(""), "boundary"),
        ("/resources", json!([]), "resource measurements"),
        (
            "/resources/0/measurement",
            json!({"status":"available","value":0.5}),
            "integral",
        ),
        (
            "/resources/0/measurement",
            json!({"status":"available","value":-1.0}),
            "nonnegative",
        ),
        ("/runtime/model/reason", json!(""), "reason"),
        (
            "/runtime/version",
            json!({"status":"available","value":""}),
            "version",
        ),
        ("/output_evidence/reason", json!(""), "unassessed reason"),
    ] {
        let mut changed = valid.clone();
        *changed.pointer_mut(pointer).unwrap() = replacement;
        let result: AdapterResult = serde_json::from_value(changed).unwrap();
        error_contains(result.validate(&image()), expected);
    }
    let mut result = image_result();
    result.resources[0].scope = ResourceScope::Device;
    error_contains(result.validate(&image()), "requires scope");
    let mut result = image_result();
    result.timings[0].measurement = Observation::Available { value: f64::NAN };
    error_contains(result.validate(&image()), "finite");
    let mut value = valid;
    value["timings"][0]
        .as_object_mut()
        .unwrap()
        .remove("measurement");
    assert!(
        serde_json::from_value::<AdapterResult>(value).is_err(),
        "missing measurement accepted"
    );
}

#[test]
fn observed_model_contradictions_are_not_hidden_as_declared_settings() {
    let mut value = serde_json::to_value(image_result()).unwrap();
    value["runtime"]["model"] = json!({"status":"available","value":{"name":"different-model","revision":{"status":"unavailable","reason":"not exposed"},"fingerprint":{"status":"unavailable","reason":"not measured"},"files":[]}});
    let result: AdapterResult = serde_json::from_value(value).unwrap();
    error_contains(result.validate(&image()), "observed model name differs");
}

#[test]
fn output_comparison_evidence_requires_provenance_without_quality_claims() {
    let mut value = serde_json::to_value(image_result()).unwrap();
    let reference =
        json!({"sha256":"b".repeat(64),"provenance":"isolated baseline capture artifact"});
    value["output_evidence"] = json!({"kind":"numerical","reference":reference,"metric":"maximum_absolute_error","value":0.2,"tolerance":0.1,"method":"decoded float tensor comparison","provenance":"CPU comparison example"});
    let result: AdapterResult = serde_json::from_value(value.clone()).unwrap();
    // Exceeding a declared tolerance is valid comparison evidence, not malformed data or a quality verdict.
    result.validate(&image()).unwrap();
    value["output_evidence"]["provenance"] = Value::String(String::new());
    let result: AdapterResult = serde_json::from_value(value).unwrap();
    error_contains(result.validate(&image()), "provenance");
    let mut result = image_result();
    result.output_evidence = OutputEvidence::Exact {
        reference: media_inference_lab::schema::ComparisonReference {
            sha256: "b".repeat(64),
            provenance: "baseline artifact".into(),
        },
        method: "bytewise sha256".into(),
        provenance: "CPU comparator".into(),
    };
    error_contains(result.validate(&image()), "must match an output artifact");
}

#[test]
fn automatic_precision_resolves_but_explicit_precision_cannot_change() {
    let mut request = image();
    if let MediaSettings::Image { generation } = &mut request.settings {
        generation.precision = Precision::Auto;
    }
    let mut result = image_result();
    result.resolved = request.clone();
    result.workload_identity = request.identity().unwrap();
    error_contains(result.validate(&request), "resolved workload differs");
    if let MediaSettings::Image { generation } = &mut result.resolved.settings {
        generation.precision = Precision::Bfloat16;
        generation.compute_precision = Some(Precision::Float32);
    }
    result.validate(&request).unwrap();
    assert_ne!(
        result.resolved.identity().unwrap(),
        result.workload_identity
    );
    if let MediaSettings::Image { generation } = &mut request.settings {
        generation.precision = Precision::Float32;
    }
    result.workload_identity = request.identity().unwrap();
    error_contains(result.validate(&request), "resolved workload differs");
    if let MediaSettings::Image { generation } = &mut result.resolved.settings {
        generation.precision = Precision::Float32;
    }
    if let MediaSettings::Image { generation } = &mut request.settings {
        generation.compute_precision = Some(Precision::Float16);
    }
    result.workload_identity = request.identity().unwrap();
    error_contains(result.validate(&request), "resolved workload differs");
    if let MediaSettings::Image { generation } = &mut result.resolved.settings {
        generation.compute_precision = Some(Precision::Float16);
    }
    result.validate(&request).unwrap();
}

#[test]
fn video_layers_and_independent_reuse_intervals_are_declared_and_validated() {
    let mut request = video();
    if let MediaSettings::Video { reuse, .. } = &mut request.settings {
        *reuse = ReusePolicy::Interval {
            every: 2,
            core_every: 4,
        };
    }
    request.validate().unwrap();
    let identity = request.identity().unwrap();
    if let MediaSettings::Video { reuse, .. } = &mut request.settings {
        *reuse = ReusePolicy::Interval {
            every: 2,
            core_every: 5,
        };
    }
    assert_ne!(request.identity().unwrap(), identity);
    if let MediaSettings::Video { reuse, .. } = &mut request.settings {
        *reuse = ReusePolicy::Interval {
            every: 0,
            core_every: 4,
        };
    }
    error_contains(request.validate(), "intervals must be positive");
    if let MediaSettings::Video { layers, reuse, .. } = &mut request.settings {
        *layers = 0;
        *reuse = ReusePolicy::Disabled;
    }
    error_contains(request.validate(), "layers must be positive");
}
