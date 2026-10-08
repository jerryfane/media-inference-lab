#!/usr/bin/env python3
"""Read-only CPU metadata preflight. Never import the native inference runtime."""
import argparse
import ast
import email.parser
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import struct
import sys

MAX_METADATA = 16 * 1024 * 1024
MAX_FILES = 4096
MAX_TOTAL = 128 * 1024 * 1024
MAX_TENSORS = 200000
UNAVAILABLE_IMPORT = {"status": "unavailable", "reason": "Native imports are deliberately prohibited: importing MLX/MFLUX may initialize GPU state."}
UNAVAILABLE_PAYLOAD = {"status": "unavailable", "reason": "Only safetensors headers are read; weight payload bytes are neither loaded nor hashed."}


class Invalid(ValueError):
    pass


def require(condition, message):
    if not condition:
        raise Invalid(message)


def install_audit():
    def audit(event, args):
        if event.startswith("socket.") or event in {"subprocess.Popen", "os.system", "os.fork", "os.forkpty", "os.exec", "os.posix_spawn"}:
            raise PermissionError("preflight prohibits network and child execution: " + event)
        if event == "import" and args[0].split(".")[0] in {"mlx", "mflux"}:
            raise PermissionError("preflight prohibits native imports")
        if event == "open":
            mode, flags = args[1:3]
            if (isinstance(mode, str) and any(c in mode for c in "wax+")) or (isinstance(flags, int) and flags & (os.O_WRONLY | os.O_RDWR | os.O_CREAT | os.O_TRUNC)):
                raise PermissionError("preflight prohibits filesystem writes")
    sys.addaudithook(audit)


def audit_proof():
    import socket
    import subprocess
    results = {}
    for name, operation in (("network_resolution", lambda: socket.getaddrinfo("localhost", 9)),
                            ("subprocess_execution", lambda: subprocess.Popen([sys.executable, "-c", "pass"]))):
        try:
            operation()
        except PermissionError:
            results[name] = "blocked_by_audit_hook_before_operation"
        else:
            raise Invalid("audit enforcement failed: " + name)
    return results


class Reader:
    def __init__(self):
        self.total = 0
        self.files = 0

    def open(self, path):
        self.files += 1
        require(self.files <= MAX_FILES, "file count exceeds preflight bound")
        fd = os.open(path, os.O_RDONLY | os.O_NONBLOCK)
        try:
            require(stat.S_ISREG(os.fstat(fd).st_mode), "not a regular file: " + str(path))
            return os.fdopen(fd, "rb")
        except BaseException:
            os.close(fd)
            raise

    def take(self, file, count):
        require(0 <= count <= MAX_METADATA, "metadata/header size exceeds preflight bound")
        self.total += count
        require(self.total <= MAX_TOTAL, "total metadata exceeds preflight bound")
        data = file.read(count)
        require(len(data) == count, "truncated metadata/header")
        return data

    def bytes(self, path):
        with self.open(path) as file:
            return self.take(file, os.fstat(file.fileno()).st_size)

    def json(self, path):
        data = self.bytes(path)
        return decode(data), evidence(path, data)


def decode(data):
    def pairs(items):
        result = {}
        for key, value in items:
            require(key not in result, "duplicate JSON key: " + key[:120])
            result[key] = value
        return result
    value = json.loads(data, object_pairs_hook=pairs, parse_constant=lambda value: (_ for _ in ()).throw(Invalid("non-finite JSON number")))
    require(isinstance(value, dict), "metadata must be a JSON object")
    return value


def evidence(path, data=None):
    result = {"path": str(path), "canonical_path": str(path.resolve(strict=True)), "bytes": path.stat().st_size,
              "is_symlink": path.is_symlink()}
    if data is not None:
        result["sha256"] = hashlib.sha256(data).hexdigest()
    return result


def entries(path):
    with os.scandir(path) as iterator:
        result = []
        for item in iterator:
            require(len(result) < MAX_FILES, "directory entry count exceeds preflight bound: " + str(path))
            result.append(Path(item.path))
    return sorted(result)


def normalized(name):
    return re.sub(r"[-_.]+", "-", name).lower()


def executable_identity(reader, path):
    """Hash the observed interpreter executable, not its venv config or native modules."""
    path = Path(path)
    limit = 64 * 1024 * 1024
    try:
        canonical = path.resolve(strict=True)
        with reader.open(canonical) as file:
            before = os.fstat(file.fileno())
            require(0 < before.st_size <= limit, "Python executable exceeds 64 MiB hashing bound or is empty")
            digest = hashlib.sha256()
            remaining = before.st_size
            while remaining:
                block = reader.take(file, min(remaining, 1024 * 1024))
                digest.update(block)
                remaining -= len(block)
            after = os.fstat(file.fileno())
            require((before.st_size, before.st_mtime_ns, before.st_ctime_ns) ==
                    (after.st_size, after.st_mtime_ns, after.st_ctime_ns),
                    "Python executable changed during hashing")
        return {"status": "observed", "path": str(path), "canonical_path": str(canonical),
                "bytes": before.st_size, "sha256": digest.hexdigest(),
                "method": "streaming read of sys.executable target; not shared-library identity",
                "hash_byte_limit": limit}
    except (OSError, ValueError) as exc:
        return {"status": "unavailable", "path": str(path), "reason": str(exc)[:2000],
                "hash_byte_limit": limit}


def environment(reader, selected):
    selected = Path(os.path.abspath(selected))
    root = selected.parent.parent
    cfg = root / "pyvenv.cfg"
    require(cfg.is_file(), "select an explicit existing virtual-environment Python (pyvenv.cfg missing)")
    cfg_bytes = reader.bytes(cfg)
    require(not re.search(r"include-system-site-packages\s*=\s*true", cfg_bytes.decode(), re.I), "venv includes system packages; isolated static resolution is unsupported")
    site = root / "lib" / ("python%d.%d" % sys.version_info[:2]) / "site-packages"
    require(site.is_dir(), "selected venv site-packages directory is missing: " + str(site))
    paths, pths = [site], []
    children = entries(site)
    for path in children:
        if path.suffix == ".pth":
            raw = reader.bytes(path)
            record = evidence(path, raw)
            record.update({"path_entries": [], "executable_lines_skipped": 0})
            for line in raw.decode("utf-8-sig").splitlines():
                line = line.rstrip()
                if not line or line.startswith("#"):
                    continue
                if line.startswith(("import ", "import\t")):
                    record["executable_lines_skipped"] += 1
                else:
                    candidate = (site / line).resolve()
                    record["path_entries"].append({"path": str(candidate), "exists": candidate.is_dir()})
                    if candidate.is_dir() and candidate not in paths:
                        paths.append(candidate)
            pths.append(record)
    distributions = {}
    for path in children:
        if path.name.endswith(".dist-info"):
            metadata = path / "METADATA"
            raw = reader.bytes(metadata)
            msg = email.parser.BytesParser().parsebytes(raw, headersonly=True)
            name = normalized(msg.get("Name", ""))
            require(name and name not in distributions, "missing/ambiguous distribution identity: " + name)
            distributions[name] = {"name": msg["Name"], "version": msg.get("Version"), "metadata": evidence(metadata, raw), "requires_dist": msg.get_all("Requires-Dist", [])}
    required = ("mflux", "mlx", "numpy", "transformers", "tokenizers", "huggingface-hub", "safetensors", "pillow", "tqdm")
    missing = [name for name in required if name not in distributions]
    source = next((path / "mflux" for path in paths if (path / "mflux" / "__init__.py").is_file()), None)
    result = {"selected_python": str(selected), "executable": sys.executable, "canonical_executable": str(Path(sys.executable).resolve()),
              "version": sys.version, "prefix": sys.prefix, "base_prefix": sys.base_prefix, "venv_root": str(root),
              "executable_identity": executable_identity(reader, sys.executable),
              "pyvenv_config": evidence(cfg, cfg_bytes), "site_packages": str(site), "pth_files": pths,
              "static_search_paths": [str(path) for path in paths], "distribution_metadata": distributions,
              "dependency_presence_checked": list(required),
              "resolution_method": "-I -S -B; no site initialization; inspect venv site-packages and non-executable .pth path lines in order; never add these paths to sys.path",
              "actual_native_import_identity": UNAVAILABLE_IMPORT,
              "dependency_version_compatibility": {"status": "unavailable", "reason": "Distribution versions and declared requirements are recorded, not executed or resolved; native ABI/import compatibility remains unobserved."}}
    return result, source, missing


SOURCE_FILES = (
    "models/qwen21/variants/txt2img/qwen_image_21.py",
    "models/qwen21/qwen21_initializer.py",
    "models/qwen21/weights/qwen21_weight_definition.py",
    "models/common/weights/loading/weight_loader.py",
    "models/common/tokenizer/tokenizer_loader.py",
    "models/common/compute_precision/compute_precision.py",
    "models/common/config/model_config.py",
)


def source_identity(reader, root):
    require(root is not None, "mflux source package cannot be resolved without executing .pth hooks")
    files = []
    digest = hashlib.sha256()
    pending = [root]
    while pending:
        directory = pending.pop()
        for path in entries(directory):
            if path.is_dir() and not path.is_symlink() and path.name != "__pycache__":
                pending.append(path)
                require(len(pending) < MAX_FILES, "source directory bound exceeded")
            elif path.suffix == ".py":
                raw = reader.bytes(path)
                relative = str(path.relative_to(root))
                digest.update(relative.encode() + b"\0" + hashlib.sha256(raw).digest())
                files.append(evidence(path, raw))
    api_path = root / SOURCE_FILES[0]
    tree = ast.parse(reader.bytes(api_path))
    cls = next((node for node in tree.body if isinstance(node, ast.ClassDef) and node.name == "QwenImage21"), None)
    require(cls is not None, "QwenImage21 native class is absent")
    signatures = {node.name: [arg.arg for arg in node.args.args + node.args.kwonlyargs] for node in cls.body if isinstance(node, ast.FunctionDef)}
    for method, expected in {"__init__": {"quantize", "model_path", "compute_precision"}, "generate_image": {"seed", "prompt", "num_inference_steps", "height", "width", "guidance", "scheduler", "negative_prompt", "step_cache_ratio"}}.items():
        require(expected <= set(signatures.get(method, [])), "unsupported native API signature: " + method)
    critical = {name: evidence(root / name, reader.bytes(root / name)) for name in SOURCE_FILES}
    return {"package_root": str(root.resolve()), "method": "bounded static source inspection, not import resolution", "python_file_count": len(files),
            "python_tree_sha256": digest.hexdigest(), "critical_files": critical, "api_parameters": signatures,
            "revision": {"status": "unavailable", "reason": "Working-tree source hashes identify observed code; no git execution or assumption that HEAD equals working tree."}}


def request_settings(workload, model_dir):
    require(workload.get("schema_version") == 1, "unsupported workload schema version")
    settings = workload["settings"]
    require(settings["modality"] == "image", "QwenImage21 preflight supports image requests only")
    generation = settings["generation"]
    require(generation["batch_size"] == 1 and not generation["references"] and generation["strength"] is None, "only batch_size=1 text-to-image without references/strength is supported")
    require(generation["scheduler"] == "linear", "only native linear scheduler is supported; external scheduler imports are prohibited")
    require(generation["precision"] in ("auto", "bfloat16"), "native QwenImage21 model precision is bfloat16; no precision override is supported")
    require(generation["compute_precision"] in (None, "float16"), "native compute_precision must be null or float16")
    optimization = generation["optimizations"]
    require(optimization["use_kv_cache"] is None and optimization["step_cache_threshold"] is None, "use_kv_cache/step_cache_threshold are not QwenImage21 options")
    ratio = optimization["step_cache_ratio"]
    require(ratio is None or (type(ratio) in (int, float) and 0 <= ratio <= 1), "step_cache_ratio must be null or between zero and one")
    quantization = generation["quantization"]
    require(quantization == {"kind": "none"} or (quantization.get("kind") == "weights" and quantization.get("method") == "mlx" and quantization.get("bits") in (4, 8)), "quantization must be none or explicit mlx 4/8-bit weights")
    resolution = generation["resolution"]
    require(all(type(resolution[k]) is int and 0 < resolution[k] <= 16384 and resolution[k] % 16 == 0 for k in ("width", "height")), "dimensions must be positive multiples of 16, at most 16384; no silent native rounding")
    require(type(generation["steps"]) is int and 0 < generation["steps"] <= 10000, "steps must be 1..10000")
    require(type(generation["seed"]) is int and 0 <= generation["seed"] <= 0xffffffff, "native seed must fit uint32")
    require(workload["model"]["name"] in ("Qwen/Qwen-Image-2.1", "qwen-image-2.1"), "model name must explicitly identify Qwen-Image-2.1")
    require(workload["model"].get("sha256") is None, "requested model payload sha256 cannot be verified without reading weights")
    revision = workload["model"].get("revision")
    require(revision is None or revision == model_dir.name, "requested revision does not match selected local snapshot directory")
    return {"constructor": {"model_path": str(model_dir), "quantize": quantization.get("bits"), "compute_precision": generation["compute_precision"]},
            "generate_image": {"prompt": generation["prompt"], "negative_prompt": generation["negative_prompt"], "seed": generation["seed"], "width": resolution["width"], "height": resolution["height"], "num_inference_steps": generation["steps"], "guidance": generation["guidance"], "scheduler": generation["scheduler"], "step_cache_ratio": ratio},
            "model_precision": "bfloat16", "execution": "not_performed", "cache_policy": "local_files_only_no_download"}


DTYPE_BYTES = {"BOOL": 1, "U8": 1, "I8": 1, "I16": 2, "U16": 2, "I32": 4, "U32": 4, "I64": 8, "U64": 8, "F16": 2, "BF16": 2, "F32": 4, "F64": 8, "F8_E4M3": 1, "F8_E5M2": 1}


def safetensors(reader, path):
    with reader.open(path) as file:
        size = os.fstat(file.fileno()).st_size
        header_size = struct.unpack("<Q", reader.take(file, 8))[0]
        require(2 <= header_size <= MAX_METADATA and header_size <= size - 8, "safetensors header boundary/size invalid: " + str(path))
        raw = reader.take(file, header_size)
    header = decode(raw)
    require(len(header) <= MAX_TENSORS, "safetensors tensor-count bound exceeded")
    metadata = header.pop("__metadata__", {})
    require(isinstance(metadata, dict) and all(isinstance(k, str) and isinstance(v, str) for k, v in metadata.items()), "invalid safetensors string metadata")
    require(header, "safetensors checkpoint has no tensors")
    intervals, dtypes = [], set()
    for name, tensor in header.items():
        require(isinstance(tensor, dict), "invalid tensor descriptor")
        dtype, shape, offsets = tensor.get("dtype"), tensor.get("shape"), tensor.get("data_offsets")
        require(isinstance(dtype, str) and dtype in DTYPE_BYTES, "unsupported safetensors dtype: " + str(dtype))
        require(isinstance(shape, list) and len(shape) <= 16 and all(type(d) is int and 0 <= d <= 2**40 for d in shape), "invalid tensor shape")
        require(isinstance(offsets, list) and len(offsets) == 2 and all(type(d) is int for d in offsets), "invalid tensor offsets")
        elements = 1
        for dimension in shape:
            elements *= dimension
            require(elements <= 2**63, "tensor shape product exceeds bound")
        start, end = offsets
        require(0 <= start <= end <= size - 8 - header_size and end - start == elements * DTYPE_BYTES[dtype], "tensor byte range/shape mismatch: " + name[:120])
        intervals.append((start, end))
        dtypes.add(dtype)
    end = 0
    for start, stop in sorted(intervals):
        require(start == end, "overlapping or non-contiguous safetensors payload ranges")
        end = stop
    require(end == size - 8 - header_size, "safetensors payload has unaccounted bytes")
    record = evidence(path)
    record.update({"header_bytes": header_size, "header_sha256": hashlib.sha256(raw).hexdigest(), "tensor_count": len(header), "dtypes": sorted(dtypes), "metadata": metadata, "payload_sha256": UNAVAILABLE_PAYLOAD})
    return record, set(header)


def inspect_model(reader, root):
    require(root.is_dir(), "local model directory is missing; obtain it separately under an authorized workflow; preflight never downloads")
    report = {"path": str(root), "canonical_path": str(root.resolve()), "snapshot_directory": root.name, "metadata_files": [], "checkpoints": [],
              "payload_integrity": UNAVAILABLE_PAYLOAD,
              "native_parameter_compatibility": {"status": "unavailable", "reason": "Header structure/index membership only; native parameter names/shapes are not instantiated or validated against a model."},
              "loader_requirements": {"vae": "single safetensors", "transformer": "safetensors glob", "text_encoder": "model.safetensors.index.json", "tokenizer": "processor/tokenizer_config.json and tokenizer.json or vocab.json plus merges.txt", "component_configs": "inventoried when present; text-only native models use code-defined configurations, not these JSON configs"}}
    processor = root / "processor"
    required = [processor / "tokenizer_config.json"]
    if (processor / "tokenizer.json").is_file():
        required.append(processor / "tokenizer.json")
    else:
        required += [processor / "vocab.json", processor / "merges.txt"]
    for path in required:
        require(path.is_file(), "missing local tokenizer file: " + str(path))
    scanned = 0
    for subdir in (root, processor, root / "vae", root / "transformer", root / "text_encoder", root / "scheduler"):
        if not subdir.is_dir():
            continue
        for path in entries(subdir):
            scanned += 1
            require(scanned <= MAX_FILES, "model inventory file bound exceeded")
            if path.suffix in (".json", ".txt", ".jinja"):
                raw = reader.bytes(path)
                if path.suffix == ".json":
                    decode(raw)
                report["metadata_files"].append(evidence(path, raw))
    for component in ("vae", "transformer", "text_encoder"):
        directory = root / component
        require(directory.is_dir(), "missing checkpoint component: " + component)
        children = entries(directory)
        shards = [path for path in children if path.suffix == ".safetensors" and not path.name.startswith("._")]
        require(shards, "missing safetensors checkpoint component: " + component)
        require(component != "vae" or len(shards) == 1, "native VAE single-file loader requires exactly one safetensors file")
        require(component != "text_encoder" or (directory / "model.safetensors.index.json").is_file(), "missing text_encoder/model.safetensors.index.json")
        headers = {}
        for path in shards:
            record, names = safetensors(reader, path)
            record["component"] = component
            report["checkpoints"].append(record)
            headers[path.name] = names
        for path in children:
            if path.name.endswith(".safetensors.index.json"):
                index, _ = reader.json(path)
                weight_map = index.get("weight_map")
                require(isinstance(weight_map, dict) and 0 < len(weight_map) <= MAX_TENSORS, "invalid or empty safetensors index weight_map")
                for tensor, filename in weight_map.items():
                    require(isinstance(filename, str) and filename not in (".", "..") and Path(filename).name == filename and "/" not in filename and "\\" not in filename and filename.endswith(".safetensors"), "index shard path must be a local safetensors basename")
                    require(filename in headers, "missing index-referenced shard: " + component + "/" + filename)
                    require(tensor in headers[filename], "index tensor missing from shard header: " + tensor[:120])
    return report


def perform(args):
    reader = Reader()
    report = {"schema_version": 1, "mode": "cpu_static_preflight", "ok": False, "errors": [], "environment": None, "source": None, "model": None, "requested": None, "resolved": None,
              "limitations": ["No native imports, model allocation, tensor payload reads, generation, or GPU work.", "Static checks are not proof of native dependency ABI compatibility or complete model parameter compatibility.", "This report is not GPU authorization."],
              "safety": {"offline_environment": {key: os.environ.get(key) for key in ("HF_HUB_OFFLINE", "HF_HUB_DISABLE_IMPLICIT_TOKEN", "TRANSFORMERS_OFFLINE")}, "audit": audit_proof(), "site_hooks_executed": False, "downloads_attempted": False},
              "bounds": {"metadata_file_bytes": MAX_METADATA, "total_read_bytes": MAX_TOTAL, "file_reads": MAX_FILES, "tensors_per_header": MAX_TENSORS}}
    def check(stage, action):
        try:
            return action()
        except (OSError, ValueError, KeyError, TypeError, RecursionError, OverflowError, SyntaxError, StopIteration) as exc:
            report["errors"].append({"stage": stage, "message": str(exc)[:2000]})
            return None
    workload = check("request", lambda: reader.json(Path(args.workload))[0])
    report["requested"] = workload
    if workload is not None:
        report["resolved"] = check("request", lambda: request_settings(workload, Path(args.model_dir)))
    env = check("environment", lambda: environment(reader, args.python))
    if env:
        report["environment"], source, missing = env
        if missing:
            report["errors"].append({"stage": "dependencies", "message": "Missing installed distributions: " + ", ".join(missing)})
        report["source"] = check("source", lambda: source_identity(reader, source))
    # Reject incompatible requests before traversing checkpoint metadata.
    if report["resolved"] is not None:
        report["model"] = check("model", lambda: inspect_model(reader, Path(args.model_dir)))
    report["observed_read_bytes"] = reader.total
    report["ok"] = not report["errors"]
    return report


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--python", required=True)
    parser.add_argument("--model-dir", required=True)
    parser.add_argument("--workload", required=True)
    args = parser.parse_args()
    install_audit()
    report = perform(args)
    print(json.dumps(report, separators=(",", ":"), allow_nan=False))
    return 0 if report["ok"] else 2


if __name__ == "__main__":
    sys.exit(main())
