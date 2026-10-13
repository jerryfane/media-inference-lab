"""Own one pinned study command; never orchestrate clocks, grants or retries.

The caller supplies a private SHA256-pinned JSON launch binding with cwd,
literal_cli_argv and an optional explicit allowlisted environment. Study mode
also requires event and collector (the frozen common collector binding), plus
the original clock start path/hash. CPU mode
is only a declared test scope, never model/service authority or absence proof.
All evidence is create-only in a NEW --output-dir under the bound cwd; that
output location can never select the execution cwd. The co-located clock
module supplies only file/record helpers; its CLI/actor is never invoked.
"""
import argparse
import hashlib
import importlib.util
import os
import pathlib
import selectors
import signal
import stat
import subprocess
import sys
import time

SOURCE = pathlib.Path(__file__).with_name("observation_clock.py")
SPEC = importlib.util.spec_from_file_location("study_clock_records", SOURCE)
CLOCK = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(CLOCK)
OUTPUT_LIMIT = 512 * 1024
CLEANUP_SECONDS = 10
MAX_SECONDS = 1900


def pinned_record(raw_path, expected):
    CLOCK.require(isinstance(expected, str) and len(expected) == 64
                  and all(c in "0123456789abcdef" for c in expected), "invalid pinned SHA256")
    path = CLOCK.canonical(raw_path)
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(fd, "rb") as source:
        before = os.fstat(source.fileno())
        CLOCK.require(stat.S_ISREG(before.st_mode) and before.st_size <= CLOCK.REQUEST_LIMIT
                      and stat.S_IMODE(before.st_mode) == 0o600
                      and before.st_uid == os.getuid() and before.st_nlink == 1,
                      "binding/reference must be bounded, private, owned and unaliased")
        data = source.read(CLOCK.REQUEST_LIMIT + 1)
        after = os.fstat(source.fileno())
    CLOCK.require(len(data) == before.st_size
                  and CLOCK.fingerprint(before) == CLOCK.fingerprint(after)
                  and CLOCK.fingerprint(after) == CLOCK.fingerprint(path.stat())
                  and hashlib.sha256(data).hexdigest() == expected,
                  "binding/reference changed or differs from pinned SHA256")
    return CLOCK.parse(data), {"path": str(path), "sha256": expected, "bytes": len(data)}


def bounded_text(value):
    return isinstance(value, str) and 0 < len(value.encode()) <= 65536 and "\0" not in value


def launch(args):
    binding, binding_identity = pinned_record(args.launch_binding, args.launch_binding_sha256)
    argv = binding.get("literal_cli_argv")
    CLOCK.require(isinstance(argv, list) and 0 < len(argv) <= 4096
                  and all(bounded_text(value) for value in argv)
                  and sum(len(value.encode()) + 1 for value in argv) <= 65536
                  and pathlib.Path(argv[0]).is_absolute(), "invalid bounded literal CLI argv")
    CLOCK.require(bounded_text(binding.get("cwd")), "missing bounded launch cwd")
    cwd = CLOCK.private_dir(binding["cwd"])
    CLOCK.inside(cwd, args.launch_binding)
    environment = binding.get("environment", {"LC_ALL": "C"})
    allowed_environment = {"HOME", "USER", "LOGNAME", "TMPDIR", "PATH", "LC_ALL"}
    CLOCK.require(isinstance(environment, dict)
                  and set(environment) <= allowed_environment
                  and all(bounded_text(value) for value in environment.values())
                  and sum(len(value.encode()) for value in environment.values()) <= 65536
                  and environment.get("LC_ALL") == "C"
                  and environment.get("PATH", "/usr/bin:/bin:/usr/sbin:/sbin") == "/usr/bin:/bin:/usr/sbin:/sbin",
                  "invalid pinned allowlisted command environment")
    CLOCK.require(0 < args.timeout_seconds <= MAX_SECONDS, "invalid finite execution ceiling")
    bracket = None
    if args.mode == "study":
        CLOCK.require(args.bracket_start and args.bracket_start_sha256,
                      "study command requires a pinned original bracket start")
        start, start_identity = pinned_record(args.bracket_start, args.bracket_start_sha256)
        event = binding.get("event")
        CLOCK.require(event in CLOCK.ORDER, "invalid bound study event")
        collector = binding.get("collector")
        CLOCK.require(isinstance(collector, dict), "missing pinned collector binding")
        CLOCK.require(collector.get("study_root") == str(cwd)
                      and collector.get("protocol_sha256") == CLOCK.PROTOCOL_SHA256
                      and bounded_text(collector.get("monotonic_clock_id")),
                      "invalid pinned collector root/protocol/domain")
        for key in ("study_root", "protocol_sha256", "source_identity", "monotonic_clock_id"):
            CLOCK.require(start.get(key) == collector.get(key), "original bracket binding differs: " + key)
        kind = event.split("/")[1]
        expected_start = cwd / "observation-clock" / (event.replace("/", ".") + ".start.json")
        CLOCK.require(args.bracket_start == str(expected_start)
                      and start.get("event") == event and start.get("literal_cli_argv") == argv
                      and start.get("boundary") == CLOCK.BOUNDARIES[kind]
                      and start.get("clock") == "unix_ms" and start.get("elapsed_clock") == "monotonic"
                      and type(start.get("started_unix_ms")) is int and start["started_unix_ms"] > 0
                      and type(start.get("monotonic_started_ns")) is int
                      and 0 < start["monotonic_started_ns"] <= time.monotonic_ns()
                      and "ended_unix_ms" not in start and "exit_code" not in start,
                      "reference is not the matching original command start")
        CLOCK.inside(cwd, expected_start)
        CLOCK.require(not (expected_start.parent / (event.replace("/", ".") + ".json")).exists()
                      and not (expected_start.parent / "final.json").exists(),
                      "original bracket or collector already settled")
        source = collector.get("source_identity")
        CLOCK.require(isinstance(source, dict) and bounded_text(source.get("path")),
                      "missing pinned collector source identity")
        deadline = time.monotonic() + CLOCK.REQUEST_SECONDS
        actual_source, _ = CLOCK.identity(CLOCK.inside(cwd, source["path"]), deadline)
        CLOCK.require(actual_source == source, "saved collector source differs from pinned binding")
        protocol, _ = CLOCK.identity(CLOCK.inside(cwd, str(cwd / "predeclaration.json")), deadline)
        CLOCK.require(protocol["sha256"] == collector["protocol_sha256"], "saved protocol differs from pinned binding")
        bracket = {"identity": start_identity, "record": start}
    else:
        CLOCK.require(not args.bracket_start and not args.bracket_start_sha256,
                      "CPU scope cannot claim an original study bracket")
    directory = CLOCK.inside(cwd, args.output_dir, missing=True)
    CLOCK.private_dir(directory.parent)
    directory.mkdir(mode=0o700)  # Never reopen an earlier attempt, even if it failed before spawn.
    return binding, binding_identity, cwd, directory, bracket, environment


def own(args):
    binding, binding_identity, cwd, directory, bracket, environment = launch(args)
    argv = binding["literal_cli_argv"]
    started = time.monotonic()
    record = {"kind": "original_study_command_owner", "owner_pid": os.getpid(),
              "argv": argv, "cwd": str(cwd), "environment": environment,
              "launch_binding_identity": binding_identity, "declared_scope": args.mode,
              "original_study_bracket": bracket is not None, "original_bracket_reference": bracket,
              "activity_classification": ("original_bracket_" + binding["event"].split("/")[1]
                                          if bracket else "caller_declared_cpu_command"),
              "authority_limit": "Pinned caller command only; scope labels and clock records confer no model, service or grant authority and prove no absence of such activity.",
              "scope_limit": "Original direct child and original session group only; no arbitrary-descendant or whole-host assertion.",
              "timing_limit": "Finite cooperative deadlines; kernel/filesystem calls are not hard-cancellable.",
              "timeout_seconds": args.timeout_seconds, "original_child_created": False,
              "signals_sent": [], "errors": []}
    CLOCK.publish(directory / "invocation.json", record)
    process = None
    streams = {}
    selector = selectors.DefaultSelector()
    interrupted = []
    previous = {sig: signal.signal(sig, lambda signum, frame: interrupted.append(signum))
                for sig in (signal.SIGTERM, signal.SIGINT)}
    observed = 0
    retained = 0

    def drain(deadline, enforce_bound):
        nonlocal observed, retained
        if not selector.get_map():
            # Darwin's kqueue backend cannot select with max_events == 0.
            time.sleep(min(0.1, max(0, deadline - time.monotonic())))
            return
        for key, _ in selector.select(timeout=min(0.1, max(0, deadline - time.monotonic()))):
            chunk = os.read(key.fd, 65536)
            if not chunk:
                selector.unregister(key.fileobj)
                continue
            observed += len(chunk)
            kept = chunk[:max(0, OUTPUT_LIMIT - retained)]
            item = streams[key.data]
            item["file"].write(kept)
            item["hash"].update(kept)
            item["bytes"] += len(kept)
            retained += len(kept)
            if enforce_bound:
                CLOCK.require(observed <= OUTPUT_LIMIT, "command output bound exceeded")

    def signal_owned_group(sig):
        # NEVER poll/wait between creation and this signal: the original leader
        # is still unreaped, including if zombie, so its PID/PGID cannot be reused.
        # A successful wait permanently disables all later group signalling.
        CLOCK.require(process.returncode is None, "cannot signal a reaped original group")
        try:
            os.killpg(process.pid, sig)
            record["signals_sent"].append({"signal": signal.Signals(sig).name, "pgid": process.pid})
        except ProcessLookupError:
            pass

    try:
        for label in ("stdout", "stderr"):
            path = directory / label
            fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
            streams[label] = {"file": os.fdopen(fd, "wb"), "path": str(path),
                              "hash": hashlib.sha256(), "bytes": 0}
        # The cwd is not the output path. Enter and check it before spawn so the
        # receipt records the actual inherited cwd rather than an intended value.
        os.chdir(cwd)
        CLOCK.require(os.getcwd() == str(cwd), "actual cwd differs from pinned launch cwd")
        record["cwd"] = os.getcwd()
        process = subprocess.Popen(argv, env=environment,
                                   stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                                   stderr=subprocess.PIPE, start_new_session=True)
        record.update(original_child_created=True, original_pid=process.pid, original_pgid=process.pid)
        for label, pipe in (("stdout", process.stdout), ("stderr", process.stderr)):
            os.set_blocking(pipe.fileno(), False)
            selector.register(pipe, selectors.EVENT_READ, label)
        CLOCK.publish(directory / "creation.json", record)
        deadline = started + args.timeout_seconds
        while selector.get_map():
            CLOCK.require(not interrupted, "command owner interrupted")
            CLOCK.require(time.monotonic() < deadline, "command ownership deadline exhausted")
            drain(deadline, True)
        CLOCK.require(not interrupted, "command owner interrupted")
        # Waiting in short bounded intervals keeps owner signals responsive. No
        # wait succeeds before pipes close; failures leave the original unreaped.
        while process.returncode is None:
            CLOCK.require(not interrupted, "command owner interrupted")
            CLOCK.require(time.monotonic() < deadline, "command ownership deadline exhausted")
            try:
                process.wait(timeout=min(0.1, max(0.001, deadline - time.monotonic())))
            except subprocess.TimeoutExpired:
                pass
    except BaseException as error:
        record["errors"].append(f"{type(error).__name__}: {error}"[:4096])
    finally:
        cleanup_end = time.monotonic() + CLEANUP_SECONDS
        if process is not None:
            if process.returncode is None:
                try:
                    signal_owned_group(signal.SIGTERM)
                    grace = min(cleanup_end - 2, time.monotonic() + 2)
                    while time.monotonic() < grace:
                        drain(grace, False)
                except BaseException as error:
                    record["errors"].append(f"TERM/drain cleanup {type(error).__name__}: {error}"[:4096])
                # Output accounting must never skip original group escalation
                # or the final wait. The leader remains unreaped throughout.
                try:
                    signal_owned_group(signal.SIGKILL)
                except BaseException as error:
                    record["errors"].append(f"KILL cleanup {type(error).__name__}: {error}"[:4096])
                try:
                    while selector.get_map() and time.monotonic() < cleanup_end - 1:
                        drain(cleanup_end - 1, False)
                except BaseException as error:
                    record["errors"].append(f"drain cleanup {type(error).__name__}: {error}"[:4096])
                try:
                    process.wait(timeout=max(0.001, cleanup_end - time.monotonic()))
                except BaseException as error:
                    record["errors"].append(f"wait cleanup {type(error).__name__}: {error}"[:4096])
            record["exit_code"] = process.returncode
            record["leader_reaped"] = process.returncode is not None
            # Zero signal is only an absence snapshot, never authority to send
            # a real signal after reaping. A surviving group fails closed.
            try:
                os.killpg(process.pid, 0)
                record["group_absent"] = False
            except ProcessLookupError:
                record["group_absent"] = True
            except OSError as error:
                record["group_absent"] = False
                record["group_observation_error"] = str(error)
            for pipe in (process.stdout, process.stderr):
                pipe.close()
        record["output_complete"] = not selector.get_map() and observed == retained
        record["observed_output_bytes"] = observed
        record["output_truncated"] = observed > retained
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
        CLOCK.publish(directory / "command-outcome.json", record)
    return 0 if record["complete"] and record.get("exit_code") == 0 else 1


def main():
    os.umask(0o077)
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--launch-binding", required=True)
    parser.add_argument("--launch-binding-sha256", required=True)
    parser.add_argument("--output-dir", required=True)
    parser.add_argument("--timeout-seconds", type=int, required=True)
    parser.add_argument("--mode", choices=("cpu", "study"), required=True)
    parser.add_argument("--bracket-start")
    parser.add_argument("--bracket-start-sha256")
    args = parser.parse_args()
    try:
        return own(args)
    except (OSError, ValueError) as error:
        print(f"study command rejected: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
