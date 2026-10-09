use media_inference_lab::schema::Workload;
use serde_json::{Value, json};
use std::{fs, path::Path};

const OUTPUT: &[u8] = b"CPU schema fixture only; no inference was performed.\n";

/// Generated persisted CPU evidence, not actual measurements or model files.
pub fn record(workload: &Workload, index: u32, seconds: f64) -> Value {
    let mut result: Value =
        serde_json::from_str(include_str!("../fixtures/image-result.json")).unwrap();
    result["workload_identity"] = json!(workload.identity().unwrap());
    result["resolved"] = serde_json::to_value(workload).unwrap();
    result["resolved"]["settings"]["generation"]["compute_precision"] = json!("float32");
    result["runtime"] = json!({
        "name": "synthetic-cpu-fixture",
        "version": {"status":"available", "value":"fixture-v1"},
        "source": {"status":"available", "value":{"repository":"synthetic-local-fixture", "revision":"fixture-revision", "dirty":{"status":"available", "value":false}}},
        "executable": {"status":"available", "value":{"path":"/synthetic/cpu-fixture", "sha256":{"status":"available", "value":"a".repeat(64)}}},
        "modules": [],
        "model": {"status":"available", "value":{"name":workload.model.name, "revision":{"status":"unavailable", "reason":"no real model exists"}, "fingerprint":{"status":"available", "value":{"sha256":"b".repeat(64), "method":"synthetic generated model-level identity; not real model evidence"}}, "files":[]}},
        "device": {"status":"available", "value":"synthetic CPU device"},
        "cache_state": {"status":"available", "value":"synthetic cold"}
    });
    result["timings"] = json!([{"phase":"synthetic", "scope":"host", "unit":"seconds", "method":"generated fixture", "boundary":"synthetic start to synthetic end", "measurement":{"status":"available", "value":seconds}}]);
    json!({
        "record_version":3, "sample_index":0, "state":"completed", "request":workload,
        "workload_identity":workload.identity().unwrap(),
        "host":{"os":"synthetic", "architecture":"cpu", "kernel_release":"fixture", "logical_cpus":1, "observation_method":"generated fixture"},
        "invocation":{"executable":"/synthetic/cpu-fixture", "executable_sha256":"a".repeat(64), "executable_hash_unavailable":null, "args":[], "environment":{"MIL_RUN_DIR":"[redacted]", "MIL_REQUEST_PATH":"[redacted]", "MIL_RESULT_PATH":"[redacted]", "MIL_WORKLOAD_IDENTITY":"[redacted]"}},
        "limits":{"timeout_ms":60000, "max_output_bytes":1048576, "platform_limits":[]},
        "started_unix_ms":100000 + u64::from(index)*10000, "ended_unix_ms":101000 + u64::from(index)*10000,
        "host_elapsed_ms":1000, "artifact_inspection_ms":0, "cleanup_elapsed_ms":0,
        "exit":{"code":0, "signal":null},
        "cleanup":{"process_group":42, "group_signalled":false, "group_quiescent":true, "leader_reaped":true},
        "logs":{"stdout_bytes":0, "stderr_bytes":0, "truncated":false},
        "failure":null, "adapter_result":result, "guard_evidence":null
    })
}

pub fn persist(path: &Path, record: &Value) {
    fs::create_dir_all(path.join("artifacts")).unwrap();
    fs::write(
        path.join("manifest.json"),
        serde_json::to_vec(record).unwrap(),
    )
    .unwrap();
    fs::write(
        path.join("requested.json"),
        serde_json::to_vec(&record["request"]).unwrap(),
    )
    .unwrap();
    if !record["adapter_result"].is_null() {
        fs::write(
            path.join("result.json"),
            serde_json::to_vec(&record["adapter_result"]).unwrap(),
        )
        .unwrap();
    }
    fs::write(path.join("artifacts/schema-output.txt"), OUTPUT).unwrap();
    fs::write(path.join("stdout.log"), []).unwrap();
    fs::write(path.join("stderr.log"), []).unwrap();
}
