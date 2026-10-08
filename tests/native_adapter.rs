//! Generated metadata fixtures only. No MLX/MFLUX imports or successful inference mocks.
use std::path::PathBuf;
use std::process::Command;
use tempfile::tempdir;

fn python_case(body: &str) {
    let directory = tempdir().unwrap();
    let adapter = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("adapters/mflux_native.py");
    let output = Command::new("python3")
        .args(["-I", "-S", "-B", "-c", &format!("{FIXTURE}\n{body}")])
        .arg(adapter)
        .arg(directory.path())
        .arg(env!("CARGO_BIN_EXE_mil"))
        .output()
        .expect("CPU adapter tests require an existing stdlib Python 3");
    assert!(
        output.status.success(),
        "stdout: {}\nstderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}

const FIXTURE: &str = r#"
import copy, json, os, pathlib, runpy, struct, subprocess, sys
adapter = pathlib.Path(sys.argv[1])
root = pathlib.Path(sys.argv[2]).resolve()
api = runpy.run_path(str(adapter))
helper = api['preflight']
venv = root / 'venv'
(venv / 'bin').mkdir(parents=True)
python = venv / 'bin/python'
python.symlink_to(pathlib.Path(sys.executable).resolve())
(venv / 'pyvenv.cfg').write_text('include-system-site-packages = false\n')
site = venv / 'lib' / ('python%d.%d' % sys.version_info[:2]) / 'site-packages'
site.mkdir(parents=True)
source = root / 'source/mflux'
source.mkdir(parents=True)
marker = root / 'forbidden-execution'
poison = 'from pathlib import Path; Path(%r).write_text("executed"); raise RuntimeError("FORBIDDEN IMPORT")\n' % str(marker)
(source / '__init__.py').write_text(poison)
(site / 'mflux.pth').write_text(str(source.parent) + '\n')
(site / 'poison.pth').write_text('import sitecustomize\n')
(site / 'sitecustomize.py').write_text(poison)
for name in ('mlx', 'numpy', 'transformers', 'tokenizers', 'huggingface_hub', 'safetensors', 'PIL', 'tqdm'):
    (site / (name + '.py')).write_text(poison)
for name in ('mflux', 'mlx', 'numpy', 'transformers', 'tokenizers', 'huggingface-hub', 'safetensors', 'pillow', 'tqdm'):
    dist = site / (name + '-0.0.dist-info')
    dist.mkdir()
    (dist / 'METADATA').write_text('Name: ' + name + '\nVersion: 0.0\n')
for name in helper.SOURCE_FILES:
    path = source / name
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text('# Static CPU fixture, never an inference implementation.\n')
(source / helper.SOURCE_FILES[0]).write_text('''class QwenImage21:
    def __init__(self, quantize=None, model_path=None, compute_precision=None):
        raise RuntimeError("CPU fixture must never execute")
    def generate_image(self, seed, prompt, num_inference_steps, height, width, guidance, scheduler, negative_prompt, step_cache_ratio):
        raise RuntimeError("CPU fixture must never execute")
''')
source_hash = helper.source_identity(helper.Reader(), source)['python_tree_sha256']
model = root / 'model'
model.mkdir()
for name in ('vae', 'transformer', 'text_encoder', 'processor'):
    (model / name).mkdir()
def tensor(path, dtype='BF16', metadata=None):
    count = 2 if dtype == 'BF16' else 4
    header = {'weight': {'dtype': dtype, 'shape': [1], 'data_offsets': [0, count]}}
    if metadata is not None:
        header['__metadata__'] = metadata
    raw = json.dumps(header).encode()
    path.write_bytes(struct.pack('<Q', len(raw)) + raw + bytes(count))
    return 8 + len(raw)
for name in ('vae', 'transformer', 'text_encoder'):
    tensor(model / name / 'model.safetensors')
(model / 'text_encoder/model.safetensors.index.json').write_text(json.dumps({'weight_map': {'weight': 'model.safetensors'}}))
(model / 'processor/tokenizer_config.json').write_text('{}')
(model / 'processor/tokenizer.json').write_text('{}')
workload = {'schema_version': 1, 'id': 'native-cpu-metadata', 'model': {'name': 'Qwen/Qwen-Image-2.1', 'revision': None, 'sha256': None},
  'settings': {'modality': 'image', 'generation': {'prompt': 'metadata fixture', 'negative_prompt': None, 'seed': 17,
  'resolution': {'width': 512, 'height': 512}, 'steps': 4, 'scheduler': 'linear', 'guidance': 4.0,
  'precision': 'bfloat16', 'compute_precision': None, 'quantization': {'kind': 'none'}, 'batch_size': 1,
  'references': [], 'strength': None, 'optimizations': {'use_kv_cache': None, 'step_cache_ratio': None, 'step_cache_threshold': None}}},
  'process_policy': 'fresh_process', 'cache_policy': 'unspecified'}
request_path = root / 'request.json'
def invoke(request=None, expected_hash=None, selected_source=None, selected_model=None, check_only=True):
    request_path.write_text(json.dumps(workload if request is None else request))
    command = [str(python), '-I', '-S', '-B', str(adapter), '--python', str(python), '--source-dir', str(selected_source or source),
               '--model-dir', str(selected_model or model), '--source-sha256', expected_hash or source_hash,
               '--timeout-seconds', '10', '--max-output-bytes', '16777216']
    if check_only:
        command += ['--check-only', '--workload', str(request_path)]
    result = subprocess.run(command, capture_output=True, text=True, timeout=15, env={'PATH': '/usr/bin:/bin'})
    assert not marker.exists(), 'site or native import executed'
    assert not list(root.rglob('*.png')) and not list(root.rglob('result.json')), 'check/error fabricated output'
    if check_only:
        report = json.loads(result.stdout)
        assert result.returncode == (0 if report['ok'] else 2), (result.returncode, result.stderr, report)
        return report
    return result
def reject(action, fragment):
    try:
        action()
    except (ValueError, OSError, TypeError, KeyError) as exc:
        assert fragment in str(exc), (fragment, str(exc))
    else:
        raise AssertionError('expected rejection: ' + fragment)
"#;

#[test]
fn check_only_keeps_native_and_site_hooks_unexecuted_and_metadata_honest() {
    python_case(
        r#"
report = invoke()
assert report['ok'], report['errors']
assert report['mode'] == 'cpu_native_adapter_check' and report['schema_version'] == 1
assert report['environment']['actual_native_import_identity']['status'] == 'unavailable'
assert report['environment']['distribution_metadata']['mflux']['version'] == '0.0'
assert report['source']['python_tree_sha256'] == source_hash
assert report['model']['payload_integrity']['status'] == 'unavailable'
assert report['resolved']['generate_image']['negative_prompt'] is None
assert report['resolved']['generate_image']['guidance'] == 4.0
assert not list(root.rglob('__pycache__'))
# Missing Option fields and explicit null have the same supported native arguments.
omitted = copy.deepcopy(workload)
for field in ('revision', 'sha256'):
    omitted['model'].pop(field)
for field in ('negative_prompt', 'compute_precision', 'strength'):
    omitted['settings']['generation'].pop(field)
omitted['settings']['generation']['optimizations'] = {}
assert invoke(omitted)['resolved'] == report['resolved']
"#,
    );
}

#[test]
fn unsupported_requests_fail_before_model_traversal() {
    python_case(
        r#"
cases = []
for field, value in [('scheduler', 'other'), ('batch_size', True), ('guidance', '4'), ('seed', True), ('steps', 0),
                     ('precision', 'float32'), ('compute_precision', 'bfloat16'), ('references', None),
                     ('strength', 0.0), ('unknown', 1), ('quantization', {'kind': 'weights', 'bits': 4, 'method': 'mlx'})]:
    changed = copy.deepcopy(workload)
    changed['settings']['generation'][field] = value
    cases.append(changed)
for field, value in [('cache_policy', 'warm'), ('process_policy', 'in_process')]:
    changed = copy.deepcopy(workload)
    changed[field] = value
    cases.append(changed)
changed = copy.deepcopy(workload)
changed['model']['sha256'] = '0' * 64
cases.append(changed)
changed = copy.deepcopy(workload)
changed['settings']['generation']['optimizations']['step_cache_ratio'] = True
cases.append(changed)
changed = copy.deepcopy(workload)
del changed['settings']['generation']['optimizations']
cases.append(changed)
for changed in cases:
    report = invoke(changed, selected_model=root / 'does-not-exist')
    assert not report['ok'] and any(e['stage'] == 'request' for e in report['errors']), report
    assert report['model'] is None, 'unsupported request traversed model'
for value in (float('nan'), float('inf'), -1):
    changed = copy.deepcopy(workload)
    changed['settings']['generation']['guidance'] = value
    reject(lambda: api['request_settings'](changed, model), 'guidance')
"#,
    );
}

#[test]
fn missing_dependencies_model_and_source_mismatch_are_actionable_errors() {
    python_case(
        r#"
report = invoke(expected_hash='0' * 64)
assert not report['ok'] and any(e['stage'] == 'source' and 'SHA256 mismatch' in e['message'] for e in report['errors'])
other = root / 'different-source'
other.mkdir()
report = invoke(selected_source=other)
assert any(e['stage'] == 'source' and 'differs' in e['message'] for e in report['errors'])
report = invoke(selected_model=root / 'absent-model')
assert any(e['stage'] == 'model' and 'never downloads' in e['message'] for e in report['errors'])
metadata = site / 'mlx-0.0.dist-info/METADATA'
metadata.unlink()
metadata.parent.rmdir()
report = invoke()
assert any(e['stage'] == 'dependencies' and 'mlx' in e['message'] for e in report['errors'])
result = invoke(check_only=False)
assert result.returncode == 2 and 'dedicated guarded supervisor' in result.stderr
"#,
    );
}

#[test]
fn real_filesystem_headers_symlinks_and_mutations_are_validated() {
    python_case(
        r#"
shard = model / 'transformer/model.safetensors'
header_end = tensor(shard)
class ObservedReader(helper.Reader):
    def take(self, file, count):
        data = super().take(file, count)
        if pathlib.Path('/dev/fd/' + str(file.fileno())).exists():
            assert os.lseek(file.fileno(), 0, os.SEEK_CUR) <= header_end
        return data
reader = ObservedReader()
record, names = helper.safetensors(reader, shard)
assert reader.total == header_end and record['bytes'] == header_end + 2 and names == {'weight'}
blob = root / 'local-weight-blob'
shard.rename(blob)
shard.symlink_to(blob)
report = invoke()
assert report['ok'], report['errors']
assert report['model']['stat_inventory']['transformer/model.safetensors'][0] == str(blob)
before = api['inventory'](model)
blob.write_bytes(blob.read_bytes() + b'x')
assert before != api['inventory'](model)
report = invoke()
assert any(e['stage'] == 'model' and 'unaccounted' in e['message'] for e in report['errors'])
tensor(blob, dtype='I32')
report = invoke()
assert any(e['stage'] == 'model' and 'unquantized' in e['message'] for e in report['errors'])
shard.unlink()
os.mkfifo(shard)
report = invoke()
assert any(e['stage'] == 'model' and 'regular file' in e['message'] for e in report['errors'])
"#,
    );
}

#[test]
fn check_only_audit_denies_import_network_execution_and_filesystem_mutations() {
    python_case(
        r#"
import socket
existing = root / 'existing'
existing.write_text('unchanged')
api['install_audit']()
operations = [lambda: __import__('mlx'), lambda: __import__('mflux'), lambda: __import__('sitecustomize'),
              lambda: socket.getaddrinfo('invalid.example', 80), lambda: subprocess.run(['/usr/bin/true']),
              lambda: (root / 'new').write_text('forbidden'), lambda: existing.unlink(),
              lambda: existing.rename(root / 'renamed'), lambda: os.mkdir(root / 'directory')]
for action in operations:
    try:
        action()
    except PermissionError:
        pass
    else:
        raise AssertionError('forbidden operation was permitted')
assert existing.read_text() == 'unchanged'
assert not (root / 'new').exists() and not (root / 'directory').exists()
"#,
    );
}

#[test]
#[cfg(target_os = "macos")]
fn native_cli_denies_before_python_lease_or_capture_even_with_external_reference() {
    python_case(
        r#"
mil = pathlib.Path(sys.argv[3])
request_path.write_text(json.dumps(workload))
sentinel = root / 'must-not-execute'
sentinel.write_text('#!/bin/sh\nprintf executed > "' + str(marker) + '"\nexit 97\n')
sentinel.chmod(0o700)
output = root / 'denied.json'
home = root / 'isolated-home'
capture_root = root / 'captures'
command = [str(mil), 'mflux-run', '--execute', '--python', str(sentinel),
    '--source-dir', str(source), '--model-dir', str(model), '--source-sha256', source_hash,
    '--workload', str(request_path), '--root', str(capture_root), '--output', str(output),
    '--manager-grant-reference', 'untrusted-reference-is-not-readiness']
result = subprocess.run(command, capture_output=True, text=True, timeout=15, env={'HOME': str(home)})
report = json.loads(output.read_text())
assert result.returncode == 1, (result.returncode, result.stderr, report)
assert report['status'] == 'not_launched' and report['native_execution'] is False
assert report['check'] is None and report['capture_directory'] is None
assert report['readiness']['live_queue']['status'] == 'unavailable'
assert report['readiness']['unrelated_gpu']['status'] == 'unavailable'
assert report['decision']['allowed'] is False
assert report['manager_grant_reference'] == 'untrusted-reference-is-not-readiness'
assert not marker.exists() and not home.exists() and not capture_root.exists()
assert output.stat().st_mode & 0o777 == 0o600
"#,
    );
}

#[test]
#[cfg(target_os = "macos")]
fn native_cli_retains_invalid_request_and_never_overwrites_an_attempt() {
    python_case(
        r#"
mil = pathlib.Path(sys.argv[3])
workload['settings']['generation']['precision'] = 'float16'
request_path.write_text(json.dumps(workload))
output = root / 'invalid.json'
command = [str(mil), 'mflux-run', '--check-only', '--python', str(python),
    '--source-dir', str(source), '--model-dir', str(model), '--source-sha256', source_hash,
    '--workload', str(request_path), '--output', str(output)]
result = subprocess.run(command, capture_output=True, text=True, timeout=15)
report = json.loads(output.read_text())
assert result.returncode == 1, (result.returncode, result.stderr, report)
assert report['status'] == 'preparation_failed' and report['native_execution'] is False
assert report['check'] is None and report['errors']
before = output.read_bytes()
result = subprocess.run(command, capture_output=True, text=True, timeout=15)
assert result.returncode != 0 and output.read_bytes() == before
assert not marker.exists() and not list(root.rglob('*.png'))
"#,
    );
}
