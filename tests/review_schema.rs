use media_inference_lab::schema::{
    AdapterResult, FileIdentity, ModelFingerprint, Observation, ObservedModel, Workload,
};
use serde_json::{Value, json};

fn image_result() -> AdapterResult {
    let mut result: AdapterResult =
        serde_json::from_str(include_str!("fixtures/image-result.json")).unwrap();
    result.workload_identity = result.resolved.identity().unwrap();
    result
}

fn error_contains<T>(result: anyhow::Result<T>, expected: &str) {
    let error = result.err().expect("invalid evidence was accepted");
    assert!(
        format!("{error:#}").contains(expected),
        "expected {expected:?}, got {error:#}"
    );
}

fn with_paths(first: &str, second: &str) -> AdapterResult {
    let mut result = image_result();
    result.artifacts[0].path = first.into();
    let mut artifact = result.artifacts[0].clone();
    artifact.path = second.into();
    result.artifacts.push(artifact);
    result
}

#[test]
fn canonical_unicode_artifact_duplicates_are_rejected() {
    for (first, second) in [
        ("artifacts/café.txt", "artifacts/cafe\u{301}.txt"),
        ("artifacts/cafe\u{301}.txt", "ARTIFACTS/CAFÉ.TXT"),
        (
            "artifacts/a\u{301}\u{323}.txt",
            "artifacts/a\u{323}\u{301}.txt",
        ),
    ] {
        let result = with_paths(first, second);
        error_contains(result.validate(&result.resolved), "duplicate artifact path");
    }
}

#[test]
fn canonical_unicode_artifact_ancestors_are_rejected_in_either_order() {
    for (first, second) in [
        ("artifacts/café", "artifacts/cafe\u{301}/image.png"),
        ("ARTIFACTS/CAFE\u{301}/image.png", "artifacts/café"),
    ] {
        let result = with_paths(first, second);
        error_contains(result.validate(&result.resolved), "used as its directory");
    }
}

#[test]
fn distinct_unicode_artifact_names_remain_valid() {
    let result = with_paths("artifacts/café.txt", "artifacts/cafè.txt");
    result.validate(&result.resolved).unwrap();
    assert_eq!(result.artifacts[0].path, "artifacts/café.txt");
    assert_eq!(result.artifacts[1].path, "artifacts/cafè.txt");
}

fn model_result() -> AdapterResult {
    let mut result = image_result();
    result.resolved.model.sha256 = Some("a".repeat(64));
    result.workload_identity = result.resolved.identity().unwrap();
    result.runtime.model = Observation::Available {
        value: ObservedModel {
            name: result.resolved.model.name.clone(),
            revision: Observation::Unavailable {
                reason: "Revision not exposed".into(),
            },
            fingerprint: Observation::Unavailable {
                reason: "Model fingerprint was not measured".into(),
            },
            files: vec![
                FileIdentity {
                    path: "/models/weights.safetensors".into(),
                    sha256: Observation::Unavailable {
                        reason: "Weights were not hashed".into(),
                    },
                },
                FileIdentity {
                    path: "/models/config.json".into(),
                    sha256: Observation::Unavailable {
                        reason: "Config was not hashed".into(),
                    },
                },
            ],
        },
    };
    result
}

fn observed_model(result: &mut AdapterResult) -> &mut ObservedModel {
    match &mut result.runtime.model {
        Observation::Available { value } => value,
        Observation::Unavailable { .. } => panic!("expected model evidence"),
    }
}

#[test]
fn partial_file_evidence_cannot_contradict_an_unavailable_model_fingerprint() {
    let mut result = model_result();
    result.validate(&result.resolved).unwrap();
    observed_model(&mut result).files[1].sha256 = Observation::Available {
        value: "b".repeat(64),
    };
    result.validate(&result.resolved).unwrap();
}

#[test]
fn concrete_model_fingerprint_controls_matching_independently_of_file_inventory() {
    let mut result = model_result();
    observed_model(&mut result).fingerprint = Observation::Available {
        value: ModelFingerprint {
            sha256: "A".repeat(64),
            method: "SHA-256 of model weight bundle".into(),
        },
    };
    observed_model(&mut result).files[1].sha256 = Observation::Available {
        value: "b".repeat(64),
    };
    result.validate(&result.resolved).unwrap();

    // A matching individual file cannot override a contradictory model observation.
    observed_model(&mut result).files[0].sha256 = Observation::Available {
        value: "a".repeat(64),
    };
    observed_model(&mut result).fingerprint = Observation::Available {
        value: ModelFingerprint {
            sha256: "b".repeat(64),
            method: "SHA-256 of model weight bundle".into(),
        },
    };
    error_contains(
        result.validate(&result.resolved),
        "observed model fingerprint differs",
    );
}

#[test]
fn model_fingerprint_requires_valid_explicit_evidence_and_result_v2() {
    let valid = serde_json::to_value(model_result()).unwrap();
    for fingerprint in [
        json!({"status":"available","value":{"sha256":"bad","method":"bundle SHA-256"}}),
        json!({"status":"available","value":{"sha256":"a".repeat(64),"method":" "}}),
        json!({"status":"unavailable","reason":""}),
    ] {
        let mut value = valid.clone();
        value["runtime"]["model"]["value"]["fingerprint"] = fingerprint;
        let result: AdapterResult = serde_json::from_value(value).unwrap();
        assert!(result.validate(&result.resolved).is_err());
    }
    let mut missing = valid;
    missing["runtime"]["model"]["value"]
        .as_object_mut()
        .unwrap()
        .remove("fingerprint");
    assert!(serde_json::from_value::<AdapterResult>(missing).is_err());

    let mut result = image_result();
    result.schema_version = 1;
    error_contains(
        result.validate(&result.resolved),
        "unsupported adapter result schema_version",
    );
}

fn reference(role: &str) -> Value {
    json!({
        "path": "inputs/reference.bin", "sha256": "a".repeat(64), "bytes": 1,
        "role": role, "strength": 0.0
    })
}

#[test]
fn nested_signed_zero_changes_identity_and_cannot_pass_compatibility() {
    let image = serde_json::to_value(image_result()).unwrap();
    let video: Value = serde_json::from_str(include_str!("fixtures/video-result.json")).unwrap();
    let mut reference_case = image;
    reference_case["resolved"]["settings"]["generation"]["references"] =
        json!([reference("reference")]);
    let mut reuse_case = video.clone();
    reuse_case["resolved"]["settings"]["reuse"] = json!({
        "kind": "approximate", "method": "review reuse", "ratio": 0.0,
        "core_ratio": 0.0, "layers": [0]
    });
    let mut audio_case = video;
    audio_case["resolved"]["settings"]["audio"] = json!({
        "kind": "reference", "input": reference("audio")
    });
    for (mut value, pointer) in [
        (
            reference_case,
            "/resolved/settings/generation/references/0/strength",
        ),
        (reuse_case.clone(), "/resolved/settings/reuse/ratio"),
        (reuse_case, "/resolved/settings/reuse/core_ratio"),
        (audio_case, "/resolved/settings/audio/input/strength"),
    ] {
        let requested: Workload = serde_json::from_value(value["resolved"].clone()).unwrap();
        value["workload_identity"] = json!(requested.identity().unwrap());
        let unchanged: AdapterResult = serde_json::from_value(value.clone()).unwrap();
        unchanged.validate(&requested).unwrap();
        *value.pointer_mut(pointer).unwrap() = json!(-0.0);
        let changed: AdapterResult = serde_json::from_value(value).unwrap();
        assert_ne!(
            changed.resolved.identity().unwrap(),
            requested.identity().unwrap()
        );
        error_contains(changed.validate(&requested), "resolved workload differs");

        // Automatic precision may still resolve while preserving the nested float bits.
        let mut auto = serde_json::to_value(&requested).unwrap();
        auto["settings"]["generation"]["precision"] = json!("auto");
        auto["settings"]["generation"]["compute_precision"] = Value::Null;
        let auto: Workload = serde_json::from_value(auto).unwrap();
        let mut resolved = unchanged;
        resolved.workload_identity = auto.identity().unwrap();
        resolved.validate(&auto).unwrap();
    }
}
