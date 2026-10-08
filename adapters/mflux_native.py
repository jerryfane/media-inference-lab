#!/usr/bin/env python3
"""Thin QwenImage21 runner. Check-only is stdlib metadata inspection, not inference."""
import argparse
import copy
import hashlib
import importlib.util
import json
import math
import os
from pathlib import Path
import resource
import signal
import stat
import sys
import threading
import time
import traceback

# Loading this repository's stdlib helper never initializes site or native packages.
_spec = importlib.util.spec_from_file_location("mil_preflight", Path(__file__).with_name("mflux_preflight.py"))
preflight = importlib.util.module_from_spec(_spec)
# Compile the helper's source, not an existing timestamp-valid .pyc.
exec(compile(_spec.loader.get_source(_spec.name), _spec.origin, "exec"), preflight.__dict__)
require = preflight.require

OFFLINE = {"HF_HUB_OFFLINE": "1", "TRANSFORMERS_OFFLINE": "1",
           "HF_HUB_DISABLE_IMPLICIT_TOKEN": "1", "HF_HUB_DISABLE_TELEMETRY": "1",
           "TOKENIZERS_PARALLELISM": "false", "LC_ALL": "C"}
LIMITATIONS = [
    "Static metadata checks do not prove native import/ABI or model parameter compatibility.",
    "Check-only does not import MLX/MFLUX, read tensor payloads, allocate tensors or generate media.",
    "This diagnostic is neither GPU authorization nor a successful native capture.",
    "Installed distribution metadata is separate from actual imported implementation identity.",
]


def unavailable(reason):
    return {"status": "unavailable", "reason": reason}


def available(value):
    return {"status": "available", "value": value}


def object_fields(value, required, optional=(), label="object"):
    require(type(value) is dict, label + " must be an object")
    require(set(required) <= value.keys(), label + " missing required fields: " + ", ".join(sorted(set(required) - value.keys())))
    require(value.keys() <= set(required) | set(optional), label + " has unknown fields: " + ", ".join(sorted(value.keys() - set(required) - set(optional))))


def text(value, label, empty=False):
    require(isinstance(value, str) and "\0" not in value and (empty or value.strip()), label + " must be a valid string")


def request_settings(workload, model_dir):
    object_fields(workload, ("schema_version", "id", "model", "settings", "process_policy", "cache_policy"), label="workload")
    require(type(workload["schema_version"]) is int and workload["schema_version"] == 1, "unsupported workload schema version")
    text(workload["id"], "workload id")
    require(workload["process_policy"] == "fresh_process", "native adapter requires fresh_process")
    require(workload["cache_policy"] == "unspecified", "cache_policy must be unspecified; cold/warm cannot be established")
    model = workload["model"]
    object_fields(model, ("name",), ("revision", "sha256"), "model")
    text(model["name"], "model name")
    if model.get("revision") is not None:
        text(model["revision"], "model revision")
    require(model.get("sha256") is None, "requested model payload sha256 is unsupported without full payload verification")
    settings = workload["settings"]
    object_fields(settings, ("modality", "generation"), label="settings")
    generation = settings["generation"]
    object_fields(generation, ("prompt", "seed", "resolution", "steps", "scheduler", "guidance", "precision", "quantization", "batch_size", "references", "optimizations"),
                  ("negative_prompt", "compute_precision", "strength"), "generation")
    text(generation["prompt"], "prompt", empty=True)
    if generation.get("negative_prompt") is not None:
        text(generation["negative_prompt"], "negative_prompt", empty=True)
    require(type(generation["guidance"]) in (int, float) and math.isfinite(generation["guidance"]) and generation["guidance"] >= 0, "guidance must be finite and nonnegative")
    require(type(generation["batch_size"]) is int and generation["batch_size"] == 1, "batch_size must be integer one")
    require(type(generation["references"]) is list and not generation["references"], "references must be an empty array")
    object_fields(generation["resolution"], ("width", "height"), label="resolution")
    object_fields(generation["quantization"], ("kind",), label="quantization")
    require(generation["quantization"]["kind"] == "none", "only unquantized BF16 weights are supported")
    object_fields(generation["optimizations"], (), ("use_kv_cache", "step_cache_ratio", "step_cache_threshold"), "optimizations")
    return preflight.request_settings(workload, model_dir)


def install_audit(run_dir=None):
    """Defense in depth; native extensions additionally require the OS sandbox."""
    def writable(path, dir_fd=None):
        if run_dir is None:
            raise PermissionError("check-only prohibits filesystem mutations")
        require(dir_fd in (None, -1), "relative descriptor mutations are unsupported")
        if isinstance(path, int):
            raise PermissionError("descriptor mutation cannot establish owned path")
        resolved = Path(os.fsdecode(path)).resolve()
        if not resolved.is_relative_to(run_dir):
            raise PermissionError("mutation outside owned run: " + str(resolved))

    def audit(event, args):
        if event.startswith("socket.") or event in {"subprocess.Popen", "os.system", "os.fork", "os.forkpty", "os.exec", "os.posix_spawn", "os.posix_spawnp"}:
            raise PermissionError("native adapter prohibits network and child execution: " + event)
        if run_dir is None and event == "import" and args[0].split(".")[0] in {"mlx", "mflux", "numpy", "transformers", "tokenizers", "huggingface_hub", "safetensors", "PIL", "tqdm", "site", "sitecustomize", "usercustomize"}:
            raise PermissionError("check-only prohibits native/third-party/site imports")
        if run_dir is None and event.startswith("ctypes."):
            raise PermissionError("check-only prohibits dynamic native loading")
        if event == "open":
            mode, flags = args[1:3]
            if (isinstance(mode, str) and any(c in mode for c in "wax+")) or (isinstance(flags, int) and flags & (os.O_WRONLY | os.O_RDWR | os.O_CREAT | os.O_TRUNC | os.O_APPEND)):
                writable(args[0])
        if event in {"os.remove", "os.rmdir", "os.mkdir", "os.chmod", "os.chown", "os.utime", "os.truncate"}:
            descriptor = args[2] if event in {"os.mkdir", "os.chmod"} and len(args) > 2 else None
            if event in {"os.remove", "os.rmdir"} and len(args) > 1:
                descriptor = args[1]
            writable(args[0], descriptor)
        if event in {"os.rename", "os.link"}:
            writable(args[0], args[2] if len(args) > 2 else None)
            writable(args[1], args[3] if len(args) > 3 else None)
        if event == "os.symlink":
            raise PermissionError("adapter prohibits creating symlinks")
        if event == "os.kill" and args[0] != os.getpid():
            raise PermissionError("adapter may signal only its own process")
        if event == "os.killpg":
            raise PermissionError("adapter never signals process groups")
    sys.addaudithook(audit)


def inventory(root):
    """Stat-only change detector, including symlink targets; not payload integrity."""
    require(root.is_dir(), "local model directory is missing; native adapter never downloads")
    pending, records = [root], {}
    while pending:
        directory = pending.pop()
        for path in preflight.entries(directory):
            require(len(records) + len(pending) < preflight.MAX_FILES, "model inventory exceeds file bound")
            if path.is_dir():
                require(not path.is_symlink(), "model directory symlinks are unsupported")
                pending.append(path)
            else:
                target = path.resolve(strict=True)
                info = target.stat()
                require(stat.S_ISREG(info.st_mode), "model entry is not a regular file: " + str(path))
                records[str(path.relative_to(root))] = [str(target), info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns, info.st_ctime_ns]
    return records


def inspect_model(reader, root):
    before = inventory(root)
    model = preflight.inspect_model(reader, root)
    for checkpoint in model["checkpoints"]:
        require(set(checkpoint["dtypes"]) <= {"BF16", "F32"}, "checkpoint is not unquantized BF16/F32: " + checkpoint["path"])
        require(not any("quant" in key.lower() and value.lower() not in {"none", "null", "false", "0"}
                        for key, value in checkpoint["metadata"].items()), "checkpoint declares quantization")
    for item in model["metadata_files"]:
        path = Path(item["path"])
        if path.suffix == ".json":
            metadata, _ = reader.json(path)
            require(all(metadata.get(key) is None for key in ("quantization", "quantization_config", "quantization_level")),
                    "local model metadata declares unsupported quantization: " + str(path))
    require(before == inventory(root), "model changed during static inspection")
    model["stat_inventory"] = before
    return model


def check(args):
    reader = preflight.Reader()
    report = {"schema_version": 1, "mode": "cpu_native_adapter_check", "ok": False, "errors": [],
              "limitations": LIMITATIONS, "requested": None, "resolved": None, "environment": None,
              "source": None, "model": None,
              "safety": {"site_hooks_executed": False, "native_imports_performed": False,
                         "offline_environment": {key: os.environ.get(key) for key in OFFLINE}}}
    def stage(name, action):
        try:
            return action()
        except (OSError, ValueError, KeyError, TypeError, RecursionError, OverflowError, SyntaxError, StopIteration) as exc:
            report["errors"].append({"stage": name, "message": str(exc)[:2000]})
            return None
    def bootstrap():
        require(sys.flags.isolated and sys.flags.no_site and sys.dont_write_bytecode, "invoke selected Python with -I -S -B")
        selected = Path(args.python)
        require(selected.is_absolute() and selected.is_file(), "select an absolute existing venv Python")
        require(selected.resolve(strict=True) == Path(sys.executable).resolve(strict=True), "selected Python does not match running executable")
        require(selected.parent.parent.resolve() == Path(sys.executable).parent.parent.resolve(), "selected venv invocation differs from running Python; do not substitute base interpreter")
        require(1 <= args.timeout_seconds <= 600, "timeout must be 1..600 seconds")
        require(0 < args.max_output_bytes <= 2**63 - 1, "max output bytes must be positive and fit int64")
        require(len(args.source_sha256) == 64 and all(c in "0123456789abcdef" for c in args.source_sha256), "expected source SHA256 must be lowercase hex")
        require(Path(args.source_dir).is_absolute() and Path(args.model_dir).is_absolute(), "source and model paths must be absolute")
        return True
    if not stage("bootstrap", bootstrap):
        return report
    workload = stage("request", lambda: reader.json(Path(args.workload))[0])
    report["requested"] = workload
    if workload is not None:
        report["resolved"] = stage("request", lambda: request_settings(workload, Path(args.model_dir)))
    environment = stage("environment", lambda: preflight.environment(reader, args.python))
    if environment:
        report["environment"], source, missing = environment
        if missing:
            report["errors"].append({"stage": "dependencies", "message": "Missing installed distributions: " + ", ".join(missing)})
        def dependencies():
            paths = [Path(path) for path in report["environment"]["static_search_paths"]]
            locations = {}
            for name in ("mlx", "numpy", "transformers", "tokenizers", "huggingface_hub", "safetensors", "PIL", "tqdm"):
                found = next((candidate for root in paths for candidate in (root / name, root / (name + ".py"))
                              if candidate.is_dir() or candidate.is_file()), None)
                require(found is not None, "installed dependency module files missing: " + name)
                locations[name] = str(found.resolve(strict=True))
            return locations
        report["environment"]["static_dependency_locations"] = stage("dependencies", dependencies)
        def selected_source():
            require(source is not None and source.resolve(strict=True) == Path(args.source_dir).resolve(strict=True), "explicit source differs from statically resolved mflux package")
            value = preflight.source_identity(reader, source)
            require(value["python_tree_sha256"] == args.source_sha256, "selected source tree SHA256 mismatch")
            return value
        report["source"] = stage("source", selected_source)
    if report["resolved"] is not None:
        report["model"] = stage("model", lambda: inspect_model(reader, Path(args.model_dir)))
    report["observed_read_bytes"] = reader.total
    report["ok"] = not report["errors"]
    return report


def hash_file(path, maximum=256 * 1024 * 1024):
    digest = hashlib.sha256()
    with preflight.Reader().open(path) as file:
        before = os.fstat(file.fileno())
        require(before.st_size <= maximum, "file exceeds provenance hash bound: " + str(path))
        remaining = before.st_size
        while remaining:
            block = file.read(min(remaining, 1024 * 1024))
            require(block, "file truncated during hashing")
            remaining -= len(block)
            digest.update(block)
        after = os.fstat(file.fileno())
        require((before.st_size, before.st_mtime_ns, before.st_ctime_ns) == (after.st_size, after.st_mtime_ns, after.st_ctime_ns), "file changed during hashing")
    current = path.stat()
    require((current.st_dev, current.st_ino, current.st_size, current.st_mtime_ns, current.st_ctime_ns) ==
            (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns, after.st_ctime_ns), "file changed after hashing")
    return digest.hexdigest(), before.st_size


def atomic_json(path, data, replace=False):
    temporary = path.with_name(path.name + ".partial")
    raw = (json.dumps(data, ensure_ascii=False, allow_nan=False, indent=2) + "\n").encode()
    with open(temporary, "xb") as file:
        file.write(raw)
        file.flush()
        os.fsync(file.fileno())
    if replace:
        os.replace(temporary, path)
    else:
        os.link(temporary, path)  # Exclusive publication; never clobber a prior result.
        temporary.unlink()


class Cancelled(BaseException):
    pass


class Session:
    def __init__(self, args):
        require(os.environ.get("MIL_NATIVE_GUARDED") == "1", "native launch requires dedicated guarded supervisor; marker is not authorization")
        require(sys.platform == "darwin", "native execution requires macOS OS sandbox")
        self.root = Path(os.environ["MIL_RUN_DIR"]).resolve(strict=True)
        require(self.root.is_dir() and self.root.stat().st_uid == os.getuid(), "run directory must be owned by adapter user")
        require(os.getpgrp() == os.getpid(), "native adapter requires its own process group")
        self.parent = int(os.environ["MIL_SUPERVISOR_PID"])
        require(self.parent > 1 and os.getppid() == self.parent, "native supervisor PID mismatch")
        self.result = Path(os.environ["MIL_RESULT_PATH"])
        require(self.result.is_absolute() and self.result.parent.resolve() == self.root and not self.result.exists(), "result must be a fresh owned-run file")
        require(Path(args.workload).resolve(strict=True).is_relative_to(self.root), "native workload must be inside owned run")
        self.identity = os.environ["MIL_WORKLOAD_IDENTITY"]
        require(len(self.identity) == 64 and all(c in "0123456789abcdef" for c in self.identity), "invalid supervisor workload identity")
        require(1 <= args.timeout_seconds <= 600 and 0 < args.max_output_bytes <= 2**63 - 1, "invalid native bounds")
        self.deadline = time.monotonic() + args.timeout_seconds
        self.limit = args.max_output_bytes
        self.stop = threading.Event()
        self.failure = None
        self.status = {"schema_version": 1, "workload_identity": self.identity, "state": "starting", "stages": [], "provenance": None}
        os.umask(0o077)
        install_audit(self.root)
        for key, directory in {"HOME": "home", "TMPDIR": "tmp", "XDG_CACHE_HOME": "cache", "HF_HOME": "huggingface"}.items():
            path = self.root / directory
            path.mkdir(mode=0o700, exist_ok=True)
            require(path.resolve().is_relative_to(self.root), "cache directory escaped run")
            os.environ[key] = str(path)
        # -B alone still reads source-tree .pyc. This new empty prefix prevents that.
        bytecode = self.root / "python-bytecode"
        bytecode.mkdir(mode=0o700)
        sys.pycache_prefix = str(bytecode)
        sys.dont_write_bytecode = True
        resource.setrlimit(resource.RLIMIT_FSIZE, (self.limit, self.limit))
        for number in (signal.SIGTERM, signal.SIGINT):
            signal.signal(number, self.cancel)
        self.journal("starting")
        threading.Thread(target=self.watch, name="owned-native-watchdog", daemon=True).start()

    def cancel(self, number, _frame):
        raise Cancelled(self.failure or "received signal " + str(number))

    def journal(self, stage, state="running", error=None):
        self.status["state"] = state
        self.status["stages"].append({"stage": stage, "monotonic_seconds": time.monotonic()})
        if error is not None:
            self.status["error"] = error
        atomic_json(self.root / "native-status.json", self.status, replace=True)

    def watch(self):
        while not self.stop.wait(0.2):
            reason = None
            if os.getppid() != self.parent:
                reason = "supervisor lost"
            elif time.monotonic() >= self.deadline:
                reason = "native deadline expired"
            else:
                try:
                    total = 0
                    for directory, dirs, files in os.walk(self.root, followlinks=False):
                        for name in files:
                            total += (Path(directory) / name).lstat().st_size
                        if total > self.limit:
                            reason = "owned run exceeds output byte bound"
                            break
                except OSError as exc:
                    reason = "output bound observation failed: " + str(exc)
            if reason:
                self.failure = reason
                os.kill(os.getpid(), signal.SIGTERM)
                if not self.stop.wait(2):
                    os.kill(os.getpid(), signal.SIGKILL)
                return


def imported_files(source_root):
    records = []
    for name, module in sorted(list(sys.modules.items())):
        if name.split(".")[0] not in {"mflux", "mlx", "numpy", "transformers", "tokenizers", "huggingface_hub", "safetensors", "PIL", "tqdm"}:
            continue
        filename = getattr(module, "__file__", None)
        if filename:
            path = Path(filename).resolve(strict=True)
            if name.split(".")[0] == "mflux":
                require(path.is_relative_to(source_root), "imported MFLUX module escaped selected source: " + name)
            digest, size = hash_file(path)
            records.append({"module": name, "path": str(path), "sha256": digest, "bytes": size})
    return records


def timing(phase, start, boundary):
    return {"phase": phase, "scope": "host", "unit": "seconds", "method": "time.monotonic (host wall clock, not GPU events)",
            "boundary": boundary, "measurement": available(time.monotonic() - start)}


def resources(mx):
    result = [{"kind": "process_rss", "scope": "process", "unit": "bytes", "method": "resource.getrusage(RUSAGE_SELF).ru_maxrss; Darwin bytes",
               "boundary": "process lifetime high-water RSS sampled after synchronized generation; not GPU/unified memory",
               "measurement": available(resource.getrusage(resource.RUSAGE_SELF).ru_maxrss)}]
    observations = {}
    for name in ("get_active_memory", "get_peak_memory", "get_cache_memory", "get_driver_memory"):
        function = getattr(mx, name, None)
        if function is None:
            observations[name] = unavailable("installed mlx.core does not expose this allocator API")
        else:
            try:
                value = function()
                require(type(value) is int and value >= 0, "invalid allocator byte observation")
                observations[name] = available(value)
            except Exception as exc:
                observations[name] = unavailable(str(exc))
    for name, kind, scope in (("get_active_memory", "tensor_bytes", "runtime"), ("get_driver_memory", "driver_allocation", "device")):
        result.append({"kind": kind, "scope": scope, "unit": "bytes", "method": "mlx.core." + name + "(); MLX allocator only, not total GPU/unified memory",
                       "boundary": "after generate_image and mx.synchronize; before PNG serialization", "measurement": observations[name]})
    return result, {"scope": "MLX process allocator only", "boundary": "after synchronized generation, before serialization", "unit": "bytes", "methods": observations}


def execute(args, report, session):
    """The only native-import boundary. Production guards currently cannot authorize it."""
    require(report["ok"], "static native checks failed: " + json.dumps(report["errors"]))
    source_root = Path(args.source_dir).resolve(strict=True)
    initial_inventory = report["model"]["stat_inventory"]
    session.status["provenance"] = report
    session.journal("import")
    # Explicit paths only: never call site.addsitedir or execute a .pth hook.
    sys.path.extend(report["environment"]["static_search_paths"])
    started = time.monotonic()
    import mlx.core as mx
    from mflux.models.qwen21.variants.txt2img.qwen_image_21 import QwenImage21
    from mflux.models.common.config import ModelConfig
    timings = [timing("import", started, "before mlx.core/QwenImage21 imports to import completion")]
    actual_class = Path(sys.modules[QwenImage21.__module__].__file__).resolve(strict=True)
    require(actual_class == source_root / preflight.SOURCE_FILES[0], "actual QwenImage21 class does not match selected source")
    require(ModelConfig.precision == mx.bfloat16, "actual ModelConfig precision is not BF16")
    require(preflight.source_identity(preflight.Reader(), source_root)["python_tree_sha256"] == args.source_sha256, "source changed during imports")
    session.journal("constructor")
    requested = report["requested"]
    generation = requested["settings"]["generation"]
    compute = None if generation.get("compute_precision") is None else mx.float16
    started = time.monotonic()
    model = QwenImage21(model_path=str(Path(args.model_dir).resolve(strict=True)), quantize=None, compute_precision=compute)
    timings.append(timing("constructor", started, "QwenImage21 constructor only; lazy weight evaluation is NOT asserted complete"))
    require(model.bits is None, "native model is quantized despite unquantized request")
    require(model.model_config.model_name == "Qwen/Qwen-Image-2.1", "native model configuration is not Qwen-Image-2.1")
    require(not model.lora_paths, "native model unexpectedly enabled LoRA")
    require(model.model_config.precision == mx.bfloat16 and model.compute_precision.dtype == compute, "native precision differs from request")
    require(initial_inventory == inventory(Path(args.model_dir)), "model changed before generation")
    session.journal("generation")
    mx.synchronize()
    started = time.monotonic()
    generated = model.generate_image(**report["resolved"]["generate_image"])
    mx.synchronize()
    timings.append(timing("generation", started, "generate_image through mx.synchronize; prompt, denoise, VAE and native PIL materialization included; serialization and provenance hashing excluded"))
    measurements, allocator = resources(mx)
    require(generated.image.size == (generation["resolution"]["width"], generation["resolution"]["height"]), "returned image size differs from request")
    expected = {"width": generation["resolution"]["width"], "height": generation["resolution"]["height"], "seed": generation["seed"], "prompt": generation["prompt"], "steps": generation["steps"],
                "guidance": generation["guidance"], "negative_prompt": generation.get("negative_prompt"), "precision": mx.bfloat16, "quantization": None}
    for name, value in expected.items():
        require(getattr(generated, name) == value, "returned image setting mismatch: " + name)
    require(not generated.lora_paths, "returned image unexpectedly reports LoRA")
    parameters = generated.generation_parameters
    require(parameters.get("compute_precision") == generation.get("compute_precision"), "returned compute_precision mismatch")
    require(parameters.get("step_cache_ratio") == generation["optimizations"].get("step_cache_ratio"), "returned step_cache_ratio mismatch")
    require(parameters.get("scheduler", "linear") == "linear", "returned scheduler mismatch")
    resolved = copy.deepcopy(requested)
    resolved_generation = resolved["settings"]["generation"]
    resolved_generation.update({"seed": generated.seed, "prompt": generated.prompt, "negative_prompt": generated.negative_prompt,
                                "steps": generated.steps, "guidance": generated.guidance, "precision": "bfloat16",
                                "compute_precision": "float16" if model.compute_precision.dtype == mx.float16 else "bfloat16",
                                "resolution": {"width": generated.width, "height": generated.height}})
    session.journal("serialization")
    artifacts_dir = session.root / "artifacts"
    artifacts_dir.mkdir(mode=0o700, exist_ok=True)
    png = artifacts_dir / "image.png"
    with open(png, "xb") as file:
        generated.image.save(file, format="PNG")
        file.flush()
        os.fsync(file.fileno())
    session.journal("provenance")
    final_source = preflight.source_identity(preflight.Reader(), source_root)
    require(final_source["python_tree_sha256"] == args.source_sha256, "source changed during native execution")
    final_model = inspect_model(preflight.Reader(), Path(args.model_dir))
    require(final_model == report["model"], "model metadata/stat inventory changed during execution")
    modules = imported_files(source_root)
    executable = report["environment"]["executable_identity"]
    require(executable["status"] == "observed", "executable hash unavailable")
    require(hash_file(Path(executable["canonical_path"]))[0] == executable["sha256"], "Python executable changed")
    provenance = {"schema_version": 1, "installed_distribution_metadata": report["environment"]["distribution_metadata"],
                  "actual_imported_modules": modules, "source": final_source, "model": final_model,
                  "native_model_name": model.model_config.model_name,
                  "bytecode_policy": "-I -S -B; explicit static search paths; new empty private sys.pycache_prefix; no site/.pth execution",
                  "native_returned_generation_parameters": parameters,
                  "true_cfg_enabled": generated.guidance > 1 and bool(generated.negative_prompt),
                  "true_cfg_note": "Native QwenImage21 disables true CFG for null/empty negative_prompt even with guidance > 1; request is not altered.",
                  "allocator_observations": allocator,
                  "model_payload_fingerprint": unavailable("No full payload hashing performed; stat stability and metadata/header hashes are not weight payload integrity."),
                  "native_tqdm_generation_time": {"value": generated.generation_time, "used_as_capture_timing": False},
                  "containment": "Supervisor OS sandbox required; Python audit is defense in depth, not native-extension isolation."}
    provenance_path = artifacts_dir / "native-provenance.json"
    atomic_json(provenance_path, provenance)
    artifacts = []
    for path, role in ((png, "generated-image"), (provenance_path, "native-runtime-provenance")):
        digest, size = hash_file(path, maximum=session.limit)
        artifacts.append({"path": str(path.relative_to(session.root)), "sha256": digest, "bytes": size, "role": role})
    result = {"schema_version": 2, "workload_identity": session.identity, "resolved": resolved,
              "runtime": {"name": "MFLUX QwenImage21 / MLX", "version": unavailable("Installed distribution versions are recorded separately in native-provenance.json; editable source has no attested release version."),
                          "source": available({"repository": str(source_root), "revision": "python-tree-sha256:" + args.source_sha256, "dirty": unavailable("No git subprocess; source tree hash, not HEAD, identifies implementation.")}),
                          "executable": available({"path": executable["canonical_path"], "sha256": available(executable["sha256"])}),
                          "modules": [{"path": item["path"], "sha256": available(item["sha256"])} for item in modules],
                          "model": available({"name": requested["model"]["name"], "revision": unavailable("Local snapshot directory selection is recorded in provenance; basename is not an independently attested model revision."),
                                              "fingerprint": provenance["model_payload_fingerprint"],
                                              "files": [{"path": item["canonical_path"], "sha256": available(item["sha256"])} for item in final_model["metadata_files"]] + [{"path": item["canonical_path"], "sha256": unavailable("Only header read; full checkpoint payload hash unavailable.")} for item in final_model["checkpoints"]]}),
                          "device": unavailable("No device identity API is asserted by this adapter; imported MLX is not proof of a particular GPU."),
                          "cache_state": unavailable("Fresh process/offline flags do not establish OS/model/Metal cache warmth; no cold/warm claim.")},
              "timings": timings, "resources": measurements, "artifacts": artifacts,
              "output_evidence": {"kind": "unassessed", "reason": "Actual generated PNG; no reference comparison or quality assessment performed."}}
    require(session.failure is None, session.failure or "native cancelled")
    session.journal("publishing_result")
    atomic_json(session.result, result)
    session.journal("completed", state="completed")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("python", "source-dir", "model-dir", "source-sha256"):
        parser.add_argument("--" + name, required=True)
    parser.add_argument("--timeout-seconds", type=int, required=True)
    parser.add_argument("--max-output-bytes", type=int, required=True)
    parser.add_argument("--check-only", action="store_true")
    parser.add_argument("--workload")
    args = parser.parse_args()
    # The supervisor also clears environment. Never inherit credentials into libraries.
    retained = {key: value for key, value in os.environ.items() if key in {"MIL_REQUEST_PATH", "MIL_RESULT_PATH", "MIL_WORKLOAD_IDENTITY", "MIL_RUN_DIR", "MIL_NATIVE_GUARDED", "MIL_SUPERVISOR_PID"}}
    os.environ.clear()
    os.environ.update(OFFLINE)
    os.environ.update(retained)
    if args.check_only:
        install_audit()
        report = check(args)
        print(json.dumps(report, allow_nan=False))
        return 0 if report["ok"] else 2
    session = None
    try:
        require(args.workload is None, "native workload is supplied only by MIL_REQUEST_PATH")
        args.workload = os.environ.get("MIL_REQUEST_PATH")
        session = Session(args)
        session.journal("static_checks")
        report = check(args)
        session.status["provenance"] = report
        execute(args, report, session)
        return 0
    except BaseException as exc:
        traceback.print_exc()
        if session is not None:
            try:
                if session.result.exists():
                    os.rename(session.result, session.root / "native-result-incomplete.json")
                session.journal("cancelled" if isinstance(exc, Cancelled) else "failed", state="cancelled" if isinstance(exc, Cancelled) else "failed", error={"type": type(exc).__name__, "message": str(exc)[:4000]})
            except BaseException:
                traceback.print_exc()
        return 2
    finally:
        if session is not None:
            session.stop.set()


if __name__ == "__main__":
    sys.exit(main())
