"""Own exactly one frozen clock recorder outside the Eval client.

Run a frozen copy alongside observation_clock.py inside the private study root.
The child is only the clock recorder, never a caller-selected command. This
owner retains its original Popen handle, caps output, and records its actual
wait outcome. Source/domain reconstruction or restart is not supported.
"""
import argparse
import hashlib
import importlib.util
import json
import os
import pathlib
import selectors
import signal
import stat
import subprocess
import sys
import time

OUTPUT_LIMIT = 512 * 1024
CLEANUP_SECONDS = 10

def verified_source(path, expected):
    if not path.is_absolute() or path.resolve(strict=True) != path:
        raise ValueError("source must be canonical and absolute")
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(fd, "rb") as source:
        before = os.fstat(source.fileno())
        if (not stat.S_ISREG(before.st_mode) or before.st_size > 16 * 1024 * 1024
                or stat.S_IMODE(before.st_mode) != 0o600
                or before.st_uid != os.getuid() or before.st_nlink != 1):
            raise ValueError("source must be bounded, private, owned and unaliased")
        data = source.read(16 * 1024 * 1024 + 1)
        after = os.fstat(source.fileno())
    fields = lambda info: (info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns, info.st_ctime_ns)
    if (len(data) != before.st_size or fields(before) != fields(after)
            or fields(after) != fields(path.stat())
            or hashlib.sha256(data).hexdigest() != expected):
        raise ValueError("frozen source changed or differs from expected SHA256")
    return data


def main():
    os.umask(0o077)
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", required=True)
    parser.add_argument("--source-sha256", required=True)
    parser.add_argument("--owner-sha256", required=True)
    parser.add_argument("--lifetime-seconds", type=int, default=10800)
    args = parser.parse_args()
    source = pathlib.Path(__file__).with_name("observation_clock.py")
    verified_source(pathlib.Path(__file__).absolute(), args.owner_sha256)
    source_bytes = verified_source(source.absolute(), args.source_sha256)
    spec = importlib.util.spec_from_file_location("frozen_clock_recorder", source)
    clock = importlib.util.module_from_spec(spec)
    exec(compile(source_bytes, str(source), "exec"), clock.__dict__)
    root = clock.private_dir(args.root)
    deadline = time.monotonic() + clock.REQUEST_SECONDS
    own_identity, _ = clock.identity(clock.inside(root, pathlib.Path(__file__).absolute()), deadline)
    source_identity, _ = clock.identity(clock.inside(root, source.absolute()), deadline)
    clock.require(own_identity["sha256"] == args.owner_sha256, "owner source identity mismatch")
    clock.require(source_identity["sha256"] == args.source_sha256, "collector source identity mismatch")
    clock.require(0 < args.lifetime_seconds <= clock.MAX_LIFETIME, "invalid collector lifetime")
    directory = root / "clock-owner"
    directory.mkdir(mode=0o700)  # Original owner activation is never overwritten.
    argv = [sys.executable, "-I", "-S", "-B", str(source), "serve", "--root", str(root),
            "--source-sha256", args.source_sha256, "--lifetime-seconds", str(args.lifetime_seconds)]
    started = time.monotonic()
    record = {"kind": "original_external_clock_owner", "owner_pid": os.getpid(), "argv": argv,
              "cwd": str(root), "environment": {"LC_ALL": "C"}, "source_identity": source_identity,
              "owner_source_identity": own_identity, "original_child_created": False,
              "native_model_service_observer_activity": False, "signals_sent": [], "errors": [],
              "scope_limit": "Original direct child and its own group snapshot only; no arbitrary-descendant or whole-host assertion.",
              "timing_limit": "Finite cooperative deadlines; kernel/filesystem calls are not hard-cancellable."}
    clock.publish(directory / "invocation.json", record)
    process = None
    streams = {}
    selector = selectors.DefaultSelector()
    interrupted = []
    previous = {sig: signal.signal(sig, lambda signum, frame: interrupted.append(signum))
                for sig in (signal.SIGTERM, signal.SIGINT)}
    total = 0
    try:
        for label in ("stdout", "stderr"):
            path = directory / label
            fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            streams[label] = {"file": os.fdopen(fd, "wb"), "path": str(path),
                              "hash": hashlib.sha256(), "bytes": 0}
        process = subprocess.Popen(argv, cwd=root, env={"LC_ALL": "C"}, stdin=subprocess.DEVNULL,
                                   stdout=subprocess.PIPE, stderr=subprocess.PIPE, start_new_session=True)
        record.update(original_child_created=True, original_pid=process.pid, original_pgid=process.pid)
        clock.publish(directory / "creation.json", record)
        for label, pipe in (("stdout", process.stdout), ("stderr", process.stderr)):
            os.set_blocking(pipe.fileno(), False)
            selector.register(pipe, selectors.EVENT_READ, label)
        execution_end = started + args.lifetime_seconds + clock.REQUEST_SECONDS
        while selector.get_map() or process.poll() is None:
            clock.require(not interrupted, "external owner interrupted")
            clock.require(time.monotonic() < execution_end, "collector ownership deadline exhausted")
            for key, _ in selector.select(timeout=min(0.1, max(0, execution_end - time.monotonic()))):
                chunk = os.read(key.fd, 65536)
                if not chunk:
                    selector.unregister(key.fileobj)
                    continue
                clock.require(total + len(chunk) <= OUTPUT_LIMIT, "collector output bound exceeded")
                total += len(chunk)
                item = streams[key.data]
                item["file"].write(chunk)
                item["hash"].update(chunk)
                item["bytes"] += len(chunk)
                # Relay the actual ready message to the independent tool owner.
                destination = sys.stdout.buffer if key.data == "stdout" else sys.stderr.buffer
                destination.write(chunk)
                destination.flush()
        record["exit_code"] = process.wait(timeout=CLEANUP_SECONDS)
    except BaseException as error:
        record["errors"].append(f"{type(error).__name__}: {error}")
    finally:
        cleanup_end = time.monotonic() + CLEANUP_SECONDS
        if process is not None:
            if process.poll() is None:
                process.terminate()  # Only this still-owned original child, never a looked-up PID.
                record["signals_sent"].append("SIGTERM")
            try:
                record["exit_code"] = process.wait(timeout=max(0.001, min(5, cleanup_end - time.monotonic())))
            except subprocess.TimeoutExpired:
                process.kill()
                record["signals_sent"].append("SIGKILL")
                try:
                    record["exit_code"] = process.wait(timeout=max(0.001, cleanup_end - time.monotonic()))
                except subprocess.TimeoutExpired:
                    record["errors"].append("original child did not settle in finite cleanup reserve")
            record["leader_reaped"] = process.returncode is not None
            try:
                os.killpg(process.pid, 0)
                record["group_absent"] = False
            except ProcessLookupError:
                record["group_absent"] = True
            except OSError as error:
                record["group_absent"] = False
                record["group_observation_error"] = str(error)
            for pipe in (process.stdout, process.stderr):
                if pipe:
                    pipe.close()
        record["output_complete"] = not selector.get_map()
        selector.close()
        for label, item in streams.items():
            item["file"].flush()
            os.fsync(item["file"].fileno())
            item["file"].close()
            record[label] = {"path": item["path"], "bytes": item["bytes"], "sha256": item["hash"].hexdigest()}
        for sig, handler in previous.items():
            signal.signal(sig, handler)
        record["wall_seconds"] = time.monotonic() - started
        record["complete"] = (record.get("leader_reaped") is True and record.get("group_absent") is True
                              and record["output_complete"] and not record["errors"])
        clock.publish(directory / "outcome.json", record)
    return 0 if record["complete"] and record.get("exit_code") == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
