//! Tiny local metadata fixtures only: these tests make no inference claims.
use media_inference_lab::preflight::{PreflightOptions, run};
use serde_json::Value;
use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::PathBuf;
use std::process::Command;
use std::time::Duration;
use tempfile::tempdir;

fn python_case(body: &str) {
    let script = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("adapters/mflux_preflight.py");
    let program = format!("{FIXTURE}\n{body}");
    let output = Command::new("python3")
        .args(["-I", "-S", "-B", "-c", &program])
        .arg(script)
        .output()
        .expect("CPU tests require an existing Python 3 executable");
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
}

const FIXTURE: &str = r#"
import json, pathlib, runpy, struct, sys, tempfile
api = runpy.run_path(sys.argv[1])
Reader, Invalid = api['Reader'], api['Invalid']
def rejects(action, text):
    try:
        action()
    except (Invalid, OSError) as exc:
        assert text in str(exc), str(exc)
    else:
        raise AssertionError('expected rejection: ' + text)
def tensor(path, header=None, payload=b'\0\0\0\0'):
    header = header or {'weight': {'dtype': 'F32', 'shape': [1], 'data_offsets': [0, 4]}}
    raw = json.dumps(header).encode()
    path.write_bytes(struct.pack('<Q', len(raw)) + raw + payload)
def model(root):
    for name in ('vae', 'transformer', 'text_encoder', 'processor'):
        (root / name).mkdir()
    for name in ('vae', 'transformer', 'text_encoder'):
        tensor(root / name / 'model.safetensors')
    (root / 'text_encoder/model.safetensors.index.json').write_text(json.dumps({'weight_map': {'weight': 'model.safetensors'}}))
    (root / 'processor/tokenizer_config.json').write_text('{}')
    (root / 'processor/tokenizer.json').write_text('{}')
def request():
    return {'schema_version': 1, 'model': {'name': 'Qwen/Qwen-Image-2.1', 'revision': None, 'sha256': None},
      'settings': {'modality': 'image', 'generation': {'prompt': 'CPU metadata fixture', 'negative_prompt': None,
      'seed': 1, 'resolution': {'width': 512, 'height': 512}, 'steps': 4, 'scheduler': 'linear',
      'guidance': 1.0, 'precision': 'bfloat16', 'compute_precision': None, 'quantization': {'kind': 'none'},
      'batch_size': 1, 'references': [], 'strength': None,
      'optimizations': {'use_kv_cache': None, 'step_cache_ratio': None, 'step_cache_threshold': None}}}}
"#;

#[test]
fn local_headers_and_inventory_do_not_claim_payload_integrity() {
    python_case(
        r#"
with tempfile.TemporaryDirectory() as tmp:
    root = pathlib.Path(tmp).resolve()
    model(root)
    report = api['inspect_model'](Reader(), root)
    assert {item['component'] for item in report['checkpoints']} == {'vae', 'transformer', 'text_encoder'}
    assert all(item['dtypes'] == ['F32'] and item['payload_sha256']['status'] == 'unavailable' for item in report['checkpoints'])
    assert report['native_parameter_compatibility']['status'] == 'unavailable'
    shard = root / 'transformer/model.safetensors'
    target = root / 'blob'
    shard.rename(target)
    shard.symlink_to(target)
    report = api['inspect_model'](Reader(), root)
    record = next(item for item in report['checkpoints'] if item['component'] == 'transformer')
    assert record['is_symlink'] and record['canonical_path'] == str(target)
"#,
    );
}

#[test]
fn missing_model_tokenizer_and_index_shards_fail_without_downloads() {
    python_case(
        r#"
with tempfile.TemporaryDirectory() as tmp:
    root = pathlib.Path(tmp)
    rejects(lambda: api['inspect_model'](Reader(), root / 'absent'), 'never downloads')
    model(root)
    index = root / 'text_encoder/model.safetensors.index.json'
    index.write_text(json.dumps({'weight_map': {'weight': 'missing.safetensors'}}))
    rejects(lambda: api['inspect_model'](Reader(), root), 'missing index-referenced shard')
    index.write_text(json.dumps({'weight_map': {'weight': '../model.safetensors'}}))
    rejects(lambda: api['inspect_model'](Reader(), root), 'local safetensors basename')
    index.unlink()
    rejects(lambda: api['inspect_model'](Reader(), root), 'missing text_encoder/model.safetensors.index.json')
    (root / 'processor/tokenizer_config.json').unlink()
    rejects(lambda: api['inspect_model'](Reader(), root), 'missing local tokenizer')
"#,
    );
}

#[test]
fn malformed_headers_are_bounded_and_rejected() {
    python_case(
        r#"
with tempfile.TemporaryDirectory() as tmp:
    path = pathlib.Path(tmp) / 'weights.safetensors'
    path.write_bytes(struct.pack('<Q', 2**63))
    rejects(lambda: api['safetensors'](Reader(), path), 'header boundary/size')
    tensor(path, {'weight': {'dtype': 'F32', 'shape': [2], 'data_offsets': [0, 4]}})
    rejects(lambda: api['safetensors'](Reader(), path), 'range/shape mismatch')
    tensor(path, {'weight': {'dtype': 'UNKNOWN', 'shape': [1], 'data_offsets': [0, 4]}})
    rejects(lambda: api['safetensors'](Reader(), path), 'unsupported safetensors dtype')
    tensor(path, {'a': {'dtype': 'F32', 'shape': [1], 'data_offsets': [0, 4]}, 'b': {'dtype': 'F32', 'shape': [1], 'data_offsets': [0, 4]}})
    rejects(lambda: api['safetensors'](Reader(), path), 'overlapping')
    rejects(lambda: api['decode'](b'{"a":1,"a":2}'), 'duplicate JSON key')
    reader = Reader()
    reader.total = api['MAX_TOTAL']
    rejects(lambda: reader.bytes(path), 'total metadata')
"#,
    );
}

#[test]
fn incompatible_requests_fail_before_loading() {
    python_case(
        r#"
root = pathlib.Path('/not-a-model')
for field, value, reason in [('precision', 'float32', 'model precision'), ('compute_precision', 'bfloat16', 'compute_precision'), ('scheduler', 'external.Class', 'scheduler'), ('batch_size', 2, 'batch_size'), ('seed', 2**32, 'uint32')]:
    workload = request()
    workload['settings']['generation'][field] = value
    rejects(lambda: api['request_settings'](workload, root), reason)
workload = request()
workload['settings']['generation']['optimizations']['use_kv_cache'] = False
rejects(lambda: api['request_settings'](workload, root), 'not QwenImage21 options')
resolved = api['request_settings'](request(), root)
assert resolved['model_precision'] == 'bfloat16' and resolved['execution'] == 'not_performed'
"#,
    );
}

#[test]
fn selected_environment_reports_missing_dependencies_and_skips_pth_execution() {
    python_case(
        r#"
with tempfile.TemporaryDirectory() as tmp:
    root = pathlib.Path(tmp).resolve()
    (root / 'pyvenv.cfg').write_text('include-system-site-packages = false\n')
    site = root / 'lib' / ('python%d.%d' % sys.version_info[:2]) / 'site-packages'
    site.mkdir(parents=True)
    (site / 'unsafe.pth').write_text('import mlx; raise RuntimeError("MUST NOT EXECUTE")\n')
    source = root / 'source'
    (source / 'mflux').mkdir(parents=True)
    (source / 'mflux/__init__.py').write_text('raise RuntimeError("MUST NOT IMPORT")')
    (site / 'mflux.pth').write_text(str(source))
    dist = site / 'mflux-1.0.dist-info'
    dist.mkdir()
    (dist / 'METADATA').write_text('Name: mflux\nVersion: 1.0\n')
    report, selected, missing = api['environment'](Reader(), root / 'bin/python')
    assert selected == source / 'mflux'
    assert 'mlx' in missing and 'mflux' not in missing
    assert report['distribution_metadata']['mflux']['version'] == '1.0'
    assert report['actual_native_import_identity']['status'] == 'unavailable'
    assert sum(record['executable_lines_skipped'] for record in report['pth_files']) == 1
"#,
    );
}

#[test]
fn audit_blocks_network_execution_native_import_and_writes() {
    python_case(
        r#"
api['install_audit']()
proof = api['audit_proof']()
assert set(proof) == {'network_resolution', 'subprocess_execution'}
for operation in (lambda: __import__('mlx'), lambda: open('/tmp/mil-preflight-must-not-create', 'w')):
    try:
        operation()
    except PermissionError:
        pass
    else:
        raise AssertionError('forbidden operation was allowed')
"#,
    );
}

#[test]
fn launcher_preserves_existing_reports_and_records_missing_python() {
    let directory = tempdir().unwrap();
    let workload = directory.path().join("workload.json");
    fs::copy(
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("examples/image-workload.json"),
        &workload,
    )
    .unwrap();
    let output = directory.path().join("report.json");
    let options = || PreflightOptions {
        python: directory.path().join("missing-python"),
        model_dir: directory.path().join("missing-model"),
        workload: workload.clone(),
        output: output.clone(),
        timeout: Duration::from_secs(2),
    };
    assert!(!run(options()).unwrap());
    let original = fs::read(&output).unwrap();
    let report: Value = serde_json::from_slice(&original).unwrap();
    assert_eq!(report["errors"][0]["stage"], "launcher");
    assert!(
        report["errors"][0]["message"]
            .as_str()
            .unwrap()
            .contains("launching selected Python")
    );
    assert!(run(options()).is_err());
    assert_eq!(fs::read(&output).unwrap(), original);
}

#[test]
fn executable_identity_distinguishes_bytes_and_reports_unreadable_targets() {
    python_case(
        r#"
import hashlib
with tempfile.TemporaryDirectory() as tmp:
    root = pathlib.Path(tmp).resolve()
    executable = root / 'interpreter'
    executable.write_bytes(b'first executable bytes')
    link = root / 'selected-python'
    link.symlink_to(executable)
    first = api['executable_identity'](Reader(), link)
    assert first['status'] == 'observed'
    assert first['sha256'] == hashlib.sha256(b'first executable bytes').hexdigest()
    assert first['canonical_path'] == str(executable)
    executable.write_bytes(b'changed executable bytes')
    second = api['executable_identity'](Reader(), link)
    assert first['sha256'] != second['sha256']
    executable.unlink()
    unavailable = api['executable_identity'](Reader(), link)
    assert unavailable['status'] == 'unavailable' and 'sha256' not in unavailable
    with executable.open('wb') as file:
        file.truncate(64 * 1024 * 1024 + 1)
    oversized = api['executable_identity'](Reader(), executable)
    assert oversized['status'] == 'unavailable' and 'hashing bound' in oversized['reason']
"#,
    );
}

fn setup_static_fixture(directory: &std::path::Path) {
    let script = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("adapters/mflux_preflight.py");
    let setup = format!(
        "{FIXTURE}\n{}",
        r#"
root = pathlib.Path(sys.argv[2])
venv = root / 'venv'
(venv / 'bin').mkdir(parents=True)
executable = pathlib.Path(sys.executable).resolve()
(venv / 'bin/python').symlink_to(executable)
(venv / 'pyvenv.cfg').write_text('home = ' + str(executable.parent) + '\ninclude-system-site-packages = false\n')
site = venv / 'lib' / ('python%d.%d' % sys.version_info[:2]) / 'site-packages'
site.mkdir(parents=True)
for name in ('mflux', 'mlx', 'numpy', 'transformers', 'tokenizers', 'huggingface-hub', 'safetensors', 'pillow', 'tqdm'):
    metadata = site / (name + '-1.0.dist-info')
    metadata.mkdir()
    (metadata / 'METADATA').write_text('Name: ' + name + '\nVersion: 1.0\n')
source = site / 'mflux'
source.mkdir()
(source / '__init__.py').write_text('raise RuntimeError("MUST NOT IMPORT")')
for name in api['SOURCE_FILES']:
    path = source / name
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text('# Static fixture: no executable inference implementation.\n')
(source / api['SOURCE_FILES'][0]).write_text('class QwenImage21:\n def __init__(self, quantize, model_path, compute_precision): pass\n def generate_image(self, seed, prompt, num_inference_steps, height, width, guidance, scheduler, negative_prompt, step_cache_ratio): pass\n')
model_root = root / 'model'
model_root.mkdir()
model(model_root)
workload = request()
workload.update({'id': 'cpu-static-fixture', 'process_policy': 'fresh_process', 'cache_policy': 'unspecified'})
(root / 'workload.json').write_text(json.dumps(workload))
"#
    );
    let setup = Command::new("python3")
        .args(["-I", "-S", "-B", "-c", &setup])
        .arg(script)
        .arg(directory)
        .output()
        .unwrap();
    assert!(
        setup.status.success(),
        "{}",
        String::from_utf8_lossy(&setup.stderr)
    );
}

#[test]
fn launcher_completes_static_fixture_and_preserves_unrelated_process() {
    let directory = tempdir().unwrap();
    setup_static_fixture(directory.path());
    let mut unrelated = TestChild(Command::new("/bin/sleep").arg("30").spawn().unwrap());
    let output = directory.path().join("report.json");
    assert!(
        run(PreflightOptions {
            python: directory.path().join("venv/bin/python"),
            model_dir: directory.path().join("model"),
            workload: directory.path().join("workload.json"),
            output: output.clone(),
            timeout: Duration::from_secs(10),
        })
        .unwrap()
    );
    let report: Value = serde_json::from_slice(&fs::read(output).unwrap()).unwrap();
    assert_eq!(
        report["environment"]["executable_identity"]["status"],
        "observed"
    );
    assert_eq!(
        report["model"]["payload_integrity"]["status"],
        "unavailable"
    );
    assert_eq!(
        report["safety"]["audit"]["subprocess_execution"],
        "blocked_by_audit_hook_before_operation"
    );
    assert!(unrelated.0.try_wait().unwrap().is_none());
}

struct TestChild(std::process::Child);
impl Drop for TestChild {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

#[test]
fn launcher_timeout_reaps_owned_process_without_touching_unrelated_process() {
    let directory = tempdir().unwrap();
    let python = directory.path().join("slow-python");
    let pid_file = directory.path().join("owned.pid");
    fs::write(
        &python,
        format!(
            "#!/bin/sh\nprintf '%s' \"$$\" > '{}'\nexec /bin/sleep 30\n",
            pid_file.display()
        ),
    )
    .unwrap();
    fs::set_permissions(&python, fs::Permissions::from_mode(0o700)).unwrap();
    let workload = directory.path().join("workload.json");
    fs::copy(
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("examples/image-workload.json"),
        &workload,
    )
    .unwrap();
    let mut unrelated = TestChild(Command::new("/bin/sleep").arg("30").spawn().unwrap());
    let output = directory.path().join("report.json");
    let started = std::time::Instant::now();
    assert!(
        !run(PreflightOptions {
            python,
            workload,
            model_dir: directory.path().join("model"),
            output: output.clone(),
            timeout: Duration::from_secs(1),
        })
        .unwrap()
    );
    assert!(started.elapsed() < Duration::from_secs(5));
    let report: Value = serde_json::from_slice(&fs::read(output).unwrap()).unwrap();
    assert!(
        report["errors"][0]["message"]
            .as_str()
            .unwrap()
            .contains("exceeded timeout")
    );
    let pid: i32 = fs::read_to_string(pid_file).unwrap().parse().unwrap();
    let mut status = 0;
    assert_eq!(
        unsafe { libc::waitpid(pid, &mut status, libc::WNOHANG) },
        -1
    );
    assert_eq!(
        std::io::Error::last_os_error().raw_os_error(),
        Some(libc::ECHILD)
    );
    assert!(unrelated.0.try_wait().unwrap().is_none());
}

#[test]
fn review_header_reads_stop_before_payload_and_account_actual_bytes() {
    python_case(
        r#"
import os
with tempfile.TemporaryDirectory() as tmp:
    path = pathlib.Path(tmp) / 'toy.safetensors'
    header = json.dumps({'w': {'dtype': 'F32', 'shape': [1], 'data_offsets': [0, 4]}}, separators=(',', ':')).encode().ljust(64, b' ')
    assert len(header) == 64
    path.write_bytes(struct.pack('<Q', 64) + header + b'TOY!')
    reader = Reader()
    with reader.open(path) as file:
        assert reader.take(file, 8) == struct.pack('<Q', 64)
        assert os.lseek(file.fileno(), 0, os.SEEK_CUR) == reader.total == 8
        assert reader.take(file, 64) == header
        assert os.lseek(file.fileno(), 0, os.SEEK_CUR) == reader.total == 72
    class BoundaryReader(Reader):
        def take(self, file, count):
            data = super().take(file, count)
            assert os.lseek(file.fileno(), 0, os.SEEK_CUR) == self.total <= 72
            return data
    checked = BoundaryReader()
    record, names = api['safetensors'](checked, path)
    assert checked.total == 72 and names == {'w'} and record['bytes'] == 76
    short = pathlib.Path(tmp) / 'short'
    short.write_bytes(b'abc')
    reader = Reader()
    with reader.open(short) as file:
        rejects(lambda: reader.take(file, 8), 'truncated')
        assert reader.total == os.lseek(file.fileno(), 0, os.SEEK_CUR) == 3
    reader.total = api['MAX_TOTAL'] - 2
    with reader.open(short) as file:
        rejects(lambda: reader.take(file, 3), 'total metadata')
        assert os.lseek(file.fileno(), 0, os.SEEK_CUR) == 0
        assert reader.total == api['MAX_TOTAL'] - 2
        assert reader.take(file, 2) == b'ab'
        assert reader.total == api['MAX_TOTAL']
        rejects(lambda: reader.take(file, 1), 'total metadata')
        assert os.lseek(file.fileno(), 0, os.SEEK_CUR) == 2
"#,
    );
}

#[test]
fn review_optional_fields_preserve_identity_and_native_resolution() {
    use media_inference_lab::schema::Workload;
    let directory = tempdir().unwrap();
    setup_static_fixture(directory.path());
    let workload = directory.path().join("workload.json");
    let base: Value = serde_json::from_slice(&fs::read(&workload).unwrap()).unwrap();
    let identity = serde_json::from_value::<Workload>(base.clone())
        .unwrap()
        .identity()
        .unwrap();
    let optional = [
        ("/model", "revision"),
        ("/model", "sha256"),
        ("/settings/generation", "strength"),
        ("/settings/generation", "compute_precision"),
        ("/settings/generation", "negative_prompt"),
        ("/settings/generation/optimizations", "use_kv_cache"),
        ("/settings/generation/optimizations", "step_cache_ratio"),
        ("/settings/generation/optimizations", "step_cache_threshold"),
    ];
    let mut cases = vec![base.clone()];
    for (parent, key) in optional {
        let mut value = base.clone();
        value
            .pointer_mut(parent)
            .unwrap()
            .as_object_mut()
            .unwrap()
            .remove(key);
        cases.push(value);
    }
    let mut empty = base.clone();
    empty["settings"]["generation"]["optimizations"] = serde_json::json!({});
    cases.push(empty);
    let mut omitted = base.clone();
    for (parent, key) in optional {
        omitted
            .pointer_mut(parent)
            .unwrap()
            .as_object_mut()
            .unwrap()
            .remove(key);
    }
    cases.push(omitted);
    let options = |output| PreflightOptions {
        python: directory.path().join("venv/bin/python"),
        model_dir: directory.path().join("model"),
        workload: workload.clone(),
        output,
        timeout: Duration::from_secs(10),
    };
    let mut resolved = None;
    for (index, value) in cases.into_iter().enumerate() {
        let parsed: Workload = serde_json::from_value(value.clone()).unwrap();
        assert_eq!(parsed.identity().unwrap(), identity);
        fs::write(&workload, serde_json::to_vec(&value).unwrap()).unwrap();
        let output = directory.path().join(format!("optional-{index}.json"));
        assert!(
            run(options(output.clone())).unwrap(),
            "optional case {index}"
        );
        let report: Value = serde_json::from_slice(&fs::read(output).unwrap()).unwrap();
        if let Some(expected) = &resolved {
            assert_eq!(&report["resolved"], expected);
        } else {
            resolved = Some(report["resolved"].clone());
        }
    }
    // Required fields stay required at the shared Rust contract boundary.
    for key in ["steps", "optimizations", "references"] {
        let mut value = base.clone();
        value["settings"]["generation"]
            .as_object_mut()
            .unwrap()
            .remove(key);
        assert!(serde_json::from_value::<Workload>(value.clone()).is_err());
        fs::write(&workload, serde_json::to_vec(&value).unwrap()).unwrap();
        let output = directory.path().join(format!("missing-{key}.json"));
        assert!(!run(options(output.clone())).unwrap());
        let report: Value = serde_json::from_slice(&fs::read(output).unwrap()).unwrap();
        assert_eq!(report["errors"][0]["stage"], "launcher");
        assert!(report["resolved"].is_null());
    }
}
