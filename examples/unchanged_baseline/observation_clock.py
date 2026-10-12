"""Finite H3-only clock recorder. This module NEVER executes recorded commands.

Outer owner (not this collector) starts a frozen mode-600 copy inside ROOT:
  python3 ROOT/source/observation_clock.py serve --root ROOT \
      --source-sha256 SHA256 --lifetime-seconds 10800
The owner retains the original child handle and must actually wait/reap it within
its finite ownership deadline. final.json is collector state, NOT proof of reaping.
Do not restart after activation, loss, expiry, or an ambiguous client outcome.

Read observation-clock/activation.json to retain the ORIGINAL domain and socket.
A separate bounded client uses the same frozen copy, root and source digest:
  python3 ROOT/source/observation_clock.py client --root ROOT \
      --source-sha256 SHA256 --domain ORIGINAL_DOMAIN --request-json JSON
JSON operations (one request per client; no retries):
  {"op":"status"}
  {"op":"begin","event":"H0/execution","literal_cli_argv":["/absolute/tool"],
   "receipt_path":"ROOT/new-receipt.json","companion_path":"ROOT/new-attempt.json"}
  {"op":"finish","event":"H0/execution","exit_code":0,"errors":[]}
  {"op":"close"}
Repeat begin/finish in H0/execution,H0/readiness,...,H3/readiness order.
Execution receipt/companion inputs MUST be absent at begin and newly published
before finish. Readiness MUST reuse the unchanged original receipt from the
immediately preceding same-slot execution; only its readiness-report companion
must be fresh and absent at begin. Only the outer owner runs commands. Literal
argv may name the old immutable guardian, but evidence and this source must be
within ROOT. Output records use the original observation schema.

Each exchange has one absolute five-second deadline including response/ack.
The actor requires a response acknowledgement, otherwise stops. Any client error
(including an uncertain final acknowledgement) requires the owner to STOP and
settle the original actor, never retry or issue/reissue native commands. Status
checks original identities but creates no bracket or observation timestamps.
Admission reserves bounded IPC phases as well as command ceilings: readiness
requires 55 seconds; execution requires 1970, including the next readiness
begin before its admission check. These reserves do NOT cover unbounded caller
scheduling or think time; delay or lost availability still requires stopping.
Close may preserve an incomplete cohort; only eight successful finishes complete
collection. All partial evidence is retained; only this actor's IPC is removed.
Serve exits zero ONLY after complete close; incomplete close/expiry/error exits
one. Client zero means the exchange settled, not that collection succeeded:
inspect collection_complete, stopping and terminal_errors. No response is a
native grant. Outer-owner actual settlement remains mandatory in every case.
The CPU-only regression suite exercises these exact CLI entry points in isolated
synthetic roots using unchanged predeclaration bytes, never the production root.
"""

import argparse
import hashlib
import json
import os
import pathlib
import signal
import socket
import stat
import struct
import sys
import tempfile
import time
import uuid

PROTOCOL_SHA256 = "d860f868b2955701d2aaccdbbf0e8e5ee6d767167f9cd19b6dfaa3e0bec6affc"
LIMIT = 16 * 1024 * 1024
REQUEST_LIMIT = 131072
REQUEST_SECONDS = 5
MAX_LIFETIME = 10800
ORDER = tuple(f"H{slot}/{kind}" for slot in range(4) for kind in ("execution", "readiness"))
BOUNDARIES = {
    "execution": "before_command_spawn_through_command_settlement_and_receipt_read",
    "readiness": "before_observer_spawn_through_observer_settlement_and_report_read",
}
# Readiness reserves its begin response/ack, 15-second work, finish exchange
# and 30-second cleanup. Execution additionally reserves its begin response/ack,
# 1900-second work, finish exchange and the next readiness begin before checking
# that readiness's complete reserve still remains. Caller delay is NOT bounded.
ADMISSION_SECONDS = {
    "execution": 1900 + 15 + 30 + 5 * REQUEST_SECONDS,
    "readiness": 15 + 30 + 2 * REQUEST_SECONDS,
}


class ClockError(ValueError):
    pass


def require(condition, message):
    if not condition:
        raise ClockError(message)


def check_deadline(deadline):
    require(time.monotonic() < deadline, "clock/request deadline exhausted")


def canonical(path, missing=False):
    require(isinstance(path, (str, pathlib.Path)), "path must be a string")
    raw = str(path)
    path = pathlib.Path(raw)
    require(path.is_absolute() and str(path) == raw and ".." not in path.parts,
            "path must be canonical and absolute")
    prefix = pathlib.Path(path.anchor)
    for part in path.parts[1:]:
        prefix = prefix / part
        try:
            info = prefix.lstat()
        except FileNotFoundError:
            require(missing, "missing path ancestor")
            break
        require(not stat.S_ISLNK(info.st_mode), "symlink path rejected")
    require(path.resolve(strict=not missing) == path, "aliased path rejected")
    return path


def private_dir(path):
    path = canonical(path)
    info = path.stat()
    require(stat.S_ISDIR(info.st_mode) and stat.S_IMODE(info.st_mode) == 0o700
            and info.st_uid == os.getuid(), "directory must be owned and mode 700")
    return path


def inside(root, path, missing=False):
    path = canonical(path, missing=missing)
    require(path != root and root in path.parents, "evidence must belong to this fresh study root")
    # Existing study-local ancestors are private. Missing future ancestors are
    # allowed only while reserving a path; finish requires the entire path.
    parent = path.parent
    while parent != root:
        if missing:
            try:
                parent.lstat()
            except FileNotFoundError:
                parent = parent.parent
                continue
        private_dir(parent)
        parent = parent.parent
    private_dir(root)
    return path


def fingerprint(info):
    return (info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns,
            info.st_ctime_ns, info.st_mode, info.st_uid, info.st_nlink)


def identity(path, deadline, remaining=LIMIT):
    bound = min(LIMIT, remaining)
    path = canonical(path)
    check_deadline(deadline)
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(fd, "rb") as source:
        before = os.fstat(source.fileno())
        require(stat.S_ISREG(before.st_mode) and before.st_size <= bound,
                "record is not a bounded regular file")
        require(stat.S_IMODE(before.st_mode) == 0o600 and before.st_uid == os.getuid()
                and before.st_nlink == 1, "record must be private, owned and unaliased")
        digest = hashlib.sha256()
        count = 0
        while True:
            check_deadline(deadline)
            block = source.read(min(1024 * 1024, bound + 1 - count))
            if not block:
                break
            count += len(block)
            require(count <= bound, "record exceeds metadata bound")
            digest.update(block)
        after = os.fstat(source.fileno())
        require(count == before.st_size and fingerprint(before) == fingerprint(after)
                and fingerprint(path.stat()) == fingerprint(after), "record changed during observation")
    check_deadline(deadline)
    return ({"path": str(path), "sha256": digest.hexdigest(), "bytes": count}, fingerprint(after))


def encode(value, limit):
    data = (json.dumps(value, allow_nan=False, separators=(",", ":")) + "\n").encode()
    require(len(data) <= limit, "JSON byte bound exceeded")
    return data


def parse(data):
    def pairs(items):
        result = {}
        for key, value in items:
            require(key not in result, "duplicate JSON key")
            result[key] = value
        return result
    def invalid_constant(value):
        raise ClockError("nonfinite JSON constant: " + value)
    value = json.loads(data, object_pairs_hook=pairs, parse_constant=invalid_constant)
    require(isinstance(value, dict), "JSON object required")
    return value


def publish(path, value):
    data = encode(value, LIMIT)
    fd = os.open(path, os.O_CREAT | os.O_EXCL | os.O_WRONLY | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, "wb") as output:
        output.write(data)
        output.flush()
        os.fsync(output.fileno())
    # Persist the create-only directory entry as well as the contents.
    directory = os.open(path.parent, os.O_RDONLY)
    try:
        os.fsync(directory)
    finally:
        os.close(directory)


def recv_exact(connection, size, deadline):
    chunks = bytearray()
    while len(chunks) < size:
        check_deadline(deadline)
        connection.settimeout(max(0.001, deadline - time.monotonic()))
        chunk = connection.recv(size - len(chunks))
        require(bool(chunk), "client/actor disconnected during exchange")
        chunks.extend(chunk)
    return bytes(chunks)


def receive(connection, deadline):
    size = struct.unpack("!I", recv_exact(connection, 4, deadline))[0]
    require(0 < size <= REQUEST_LIMIT, "IPC request/response exceeds byte bound")
    return parse(recv_exact(connection, size, deadline))


def send(connection, value, deadline):
    data = encode(value, REQUEST_LIMIT)
    check_deadline(deadline)
    connection.settimeout(max(0.001, deadline - time.monotonic()))
    connection.sendall(struct.pack("!I", len(data)) + data)
    check_deadline(deadline)


class Collector:
    def __init__(self, root, source_sha256, lifetime_seconds, ipc_parent):
        require(type(lifetime_seconds) is int and 0 < lifetime_seconds <= MAX_LIFETIME,
                "lifetime must be 1..10800 seconds")
        self.created_ns = time.monotonic_ns()
        self.deadline = time.monotonic() + lifetime_seconds
        self.root = private_dir(root)
        self.source = inside(self.root, str(pathlib.Path(__file__).absolute()))
        setup_deadline = min(self.deadline, time.monotonic() + REQUEST_SECONDS)
        self.source_identity, source_stamp = identity(self.source, setup_deadline)
        require(self.source_identity["sha256"] == source_sha256, "frozen collector source SHA mismatch")
        self.protocol = inside(self.root, str(self.root / "predeclaration.json"))
        protocol_identity, protocol_stamp = identity(self.protocol, setup_deadline)
        require(protocol_identity["sha256"] == PROTOCOL_SHA256, "fixed predeclaration SHA mismatch")
        self.domain = f"python-monotonic-process-{os.getpid()}-{uuid.uuid4()}"
        self.binding = {"study_root": str(self.root), "protocol_sha256": PROTOCOL_SHA256,
                        "source_sha256": source_sha256, "monotonic_clock_id": self.domain}
        self.evidence = {str(self.source): (self.source_identity, source_stamp),
                         str(self.protocol): (protocol_identity, protocol_stamp)}
        self.index = 0
        self.active = None
        self.last_execution_receipt = None
        self.used_paths = set(self.evidence)
        self.request_ids = set()
        self.errors = []
        self.stopping = False
        self.reason = None
        self.listener = None
        self.ipc = None
        self.ipc_inode = None
        self.socket_path = None
        self.socket_stamp = None
        self.activated = False
        self.records = self.root / "observation-clock"
        # Reserving this directory is also create-only: even an activation that
        # died before publishing its record cannot be reconstructed or resumed.
        self.records.mkdir(mode=0o700)
        private_dir(self.records)
        self.activation_path = self.records / "activation.json"
        self.final_path = self.records / "final.json"
        self.lifetime_seconds = lifetime_seconds
        self.ipc_parent = canonical(ipc_parent)
        require(self.ipc_parent.is_dir(), "IPC parent is not a directory")

    def remember(self, path, deadline):
        value = identity(path, deadline)
        self.evidence[str(path)] = value
        return value[0]

    def validate_evidence(self, deadline):
        private_dir(self.records)
        total = 0
        for path, expected in self.evidence.items():
            inside(self.root, path)
            actual = identity(path, deadline, 256 * 1024 * 1024 - total)
            total += actual[0]["bytes"]
            require(total <= 256 * 1024 * 1024, "aggregate metadata read bound exceeded")
            require(actual == expected, "original evidence missing, replaced or mutated: " + path)
        if self.active:
            for path in self.active["pending_paths"]:
                # Fresh inputs may appear during the bracket. The reused
                # readiness receipt was already checked among retained evidence.
                inside(self.root, path, missing=True)

    def status(self):
        return {**self.binding, "original_pid": os.getpid(), "completed_brackets": self.index,
                "active_event": self.active["event"] if self.active else None,
                "next_event": ORDER[self.index] if self.index < len(ORDER) else None,
                "collection_complete": self.index == len(ORDER) and not self.errors,
                "terminal_errors": list(self.errors), "stopping": self.stopping,
                "shutdown_reason": self.reason,
                "outer_owner_settlement": "required; not observed or asserted by collector"}

    def stop(self, reason, error=None):
        self.stopping = True
        self.reason = reason
        if error:
            self.errors.append(str(error)[:4096])

    def handle(self, request, deadline):
        require(not self.stopping, "collector already terminal")
        for key, value in self.binding.items():
            require(request.get(key) == value, "actor binding/domain mismatch: " + key)
        request_id = request.get("request_id")
        require(isinstance(request_id, str) and 0 < len(request_id) <= 128
                and request_id not in self.request_ids, "missing or replayed request identity")
        self.request_ids.add(request_id)
        # Bounded even if an owner spams status for the full service lifetime.
        require(len(self.request_ids) <= 4096, "request count bound exhausted")
        self.validate_evidence(deadline)
        op = request.get("op")
        common = set(self.binding) | {"request_id", "op"}
        fields = {"status": set(), "close": set(),
                  "begin": {"event", "literal_cli_argv", "receipt_path", "companion_path"},
                  "finish": {"event", "exit_code", "errors"}}
        require(isinstance(op, str) and op in fields and set(request) == common | fields[op],
                "unknown operation or fields")
        if op == "status":
            return self.status()
        if op == "close":
            self.stop("closed_complete" if self.index == len(ORDER) else "closed_incomplete")
            return self.status()
        require(self.index < len(ORDER) and request["event"] == ORDER[self.index],
                "event out of fixed cohort order")
        kind = request["event"].split("/")[1]
        prefix = request["event"].replace("/", ".")
        if op == "begin":
            require(self.active is None, "overlapping or duplicate begin")
            require(self.deadline - time.monotonic() >= ADMISSION_SECONDS[kind],
                    "insufficient remaining lifetime for execution/cleanup/readiness ceiling")
            argv = request["literal_cli_argv"]
            require(isinstance(argv, list) and argv and all(isinstance(v, str) and v and "\0" not in v for v in argv),
                    "literal argv is incomplete")
            require(pathlib.Path(argv[0]).is_absolute() and sum(len(v.encode()) for v in argv) <= 65536,
                    "literal argv must be bounded with an absolute executable")
            pending = []
            for key in ("receipt_path", "companion_path"):
                path = inside(self.root, request[key], missing=True)
                require(path.parent != self.records and self.records not in path.parents,
                        "input may not alias collector-owned evidence")
                if kind == "readiness" and key == "receipt_path":
                    previous = self.last_execution_receipt
                    require(previous is not None
                            and previous["slot"] == request["event"].split("/")[0]
                            and previous["path"] == str(path)
                            and self.evidence.get(str(path)) == previous["identity"],
                            "readiness requires the unchanged immediately preceding same-slot execution receipt")
                else:
                    require(not path.exists() and str(path) not in self.used_paths and str(path) not in pending,
                            "receipt/companion must be a fresh absent unreserved path")
                pending.append(str(path))
            start = {"clock": "unix_ms", "elapsed_clock": "monotonic",
                     "monotonic_clock_id": self.domain, "boundary": BOUNDARIES[kind],
                     "literal_cli_argv": argv, "started_unix_ms": time.time_ns() // 1000000,
                     "monotonic_started_ns": time.monotonic_ns(),
                     "collection_scope": "external orchestration bracket; not exact process creation or inference time",
                     "clock_limitations": "Wall clock can adjust; monotonic comparability requires this same original collector process. No authentication or whole-host proof.",
                     "study_root": str(self.root), "event": request["event"],
                     "protocol_sha256": PROTOCOL_SHA256, "source_identity": self.source_identity}
            self.active = {"event": request["event"], "start": start, "pending_paths": pending}
            self.used_paths.update(pending)
            path = self.records / (prefix + ".start.json")
            publish(path, start)
            self.remember(path, deadline)
            return {**self.status(), "record_path": str(path), "record": start}
        require(self.active is not None, "finish without original begin")
        require(type(request["exit_code"]) is int and -(2**31) <= request["exit_code"] < 2**31,
                "exit_code must be the original signed integer outcome")
        require(isinstance(request["errors"], list) and len(request["errors"]) <= 64
                and all(isinstance(e, str) and 0 < len(e) <= 4096 for e in request["errors"]),
                "collection errors must be bounded strings")
        value = dict(self.active["start"])
        value.update(exit_code=request["exit_code"], errors=list(request["errors"]))
        keys = ("receipt_identity", "attempt_identity" if kind == "execution" else "readiness_identity")
        for key, path in zip(keys, self.active["pending_paths"]):
            try:
                inside(self.root, path)
                observed = identity(path, deadline)
                if kind == "readiness" and key == "receipt_identity":
                    require(self.last_execution_receipt is not None
                            and path == self.last_execution_receipt["path"]
                            and observed == self.last_execution_receipt["identity"],
                            "original same-slot execution receipt changed before readiness finish")
                else:
                    require(observed[1][3] >= value["started_unix_ms"] * 1_000_000
                            and observed[1][4] >= value["started_unix_ms"] * 1_000_000,
                            "receipt/companion predates the original bracket")
                self.evidence[path] = observed
                value[key] = observed[0]
            except (OSError, ValueError) as error:
                value[key] = None
                value["errors"].append(f"{key}: {error}")
        value["ended_unix_ms"] = time.time_ns() // 1000000
        value["monotonic_ended_ns"] = time.monotonic_ns()
        value["elapsed_us"] = (value["monotonic_ended_ns"] - value["monotonic_started_ns"]) // 1000
        value["collection_complete"] = (not value["errors"]
                                        and value["ended_unix_ms"] >= value["started_unix_ms"]
                                        and value["monotonic_ended_ns"] >= value["monotonic_started_ns"])
        path = self.records / (prefix + ".json")
        publish(path, value)
        self.remember(path, deadline)
        if not value["collection_complete"] or value["exit_code"] != 0:
            self.stop("collection_error", "incomplete bracket or nonzero original command outcome")
        else:
            if kind == "execution":
                receipt_path = self.active["pending_paths"][0]
                self.last_execution_receipt = {
                    "slot": request["event"].split("/")[0], "path": receipt_path,
                    "identity": self.evidence[receipt_path],
                }
            else:
                self.last_execution_receipt = None
            self.index += 1
            self.active = None
        return {**self.status(), "record_path": str(path), "record": value}

    def activate(self):
        self.ipc = pathlib.Path(tempfile.mkdtemp(prefix="h3c-", dir=self.ipc_parent))
        private_dir(self.ipc)
        ipc_info = self.ipc.stat()
        self.ipc_inode = (ipc_info.st_dev, ipc_info.st_ino)
        self.socket_path = self.ipc / "s"
        require(len(os.fsencode(self.socket_path)) < 104, "Unix socket path exceeds macOS bound")
        activation = {**self.binding, "original_pid": os.getpid(), "socket_path": str(self.socket_path),
                      "source_identity": self.source_identity, "created_monotonic_ns": self.created_ns,
                      "maximum_lifetime_seconds": self.lifetime_seconds,
                      "deadline_monotonic_ns": int(self.deadline * 1_000_000_000),
                      "outer_owner_settlement": "required; retain original child handle and wait/reap"}
        publish(self.activation_path, activation)
        self.activated = True
        self.remember(self.activation_path, min(self.deadline, time.monotonic() + REQUEST_SECONDS))
        self.listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.listener.bind(str(self.socket_path))
        os.chmod(self.socket_path, 0o600)
        self.socket_stamp = fingerprint(self.socket_path.lstat())
        self.listener.listen(1)

    def cleanup_ipc(self):
        if self.listener:
            self.listener.close()
        if self.socket_path and self.socket_stamp:
            try:
                if fingerprint(self.socket_path.lstat()) == self.socket_stamp:
                    self.socket_path.unlink()
            except OSError as error:
                self.errors.append("owned socket cleanup failed: " + str(error))
        if self.ipc and self.ipc_inode:
            try:
                info = self.ipc.lstat()
                if stat.S_ISDIR(info.st_mode) and (info.st_dev, info.st_ino) == self.ipc_inode:
                    self.ipc.rmdir()  # Never recursively remove or touch foreign contents.
            except OSError:
                pass

    def run(self):
        def interrupted(signum, frame):
            self.stop("owner_signal", f"received signal {signum}; no owner reaping assertion")
        previous = {sig: signal.signal(sig, interrupted) for sig in (signal.SIGTERM, signal.SIGINT)}
        try:
            self.activate()
            # One externally visible ready message, only after listen succeeds.
            print(json.dumps({"ready": True, **self.status(), "activation_path": str(self.activation_path)}), flush=True)
            while not self.stopping:
                if time.monotonic() >= self.deadline:
                    self.stop("expired", "finite collector lifetime expired")
                    break
                self.listener.settimeout(max(0.001, min(0.2, self.deadline - time.monotonic())))
                try:
                    connection, _ = self.listener.accept()
                except socket.timeout:
                    continue
                with connection:
                    deadline = min(self.deadline, time.monotonic() + REQUEST_SECONDS)
                    try:
                        request = receive(connection, deadline)
                        result = self.handle(request, deadline)
                        require(not self.stopping or request["op"] in ("finish", "close"),
                                "collector stopped during request; no admission")
                        send(connection, {"ok": True, "request_id": request["request_id"], "result": result}, deadline)
                        ack = receive(connection, deadline)
                        require(ack == {"ack": request["request_id"], "monotonic_clock_id": self.domain},
                                "response acknowledgement mismatch")
                        send(connection, {"acknowledged": request["request_id"], "monotonic_clock_id": self.domain}, deadline)
                    except (OSError, ValueError, TypeError, KeyError, RecursionError) as error:
                        self.stop("collection_error", error)
                        try:
                            send(connection, {"ok": False, "error": str(error)[:4096], **self.status()}, deadline)
                        except (OSError, ValueError):
                            pass
        except (OSError, ValueError, TypeError, KeyError, RecursionError) as error:
            self.stop("collector_failure", error)
        finally:
            self.cleanup_ipc()
            if self.activated:
                try:
                    publish(self.final_path, self.status())
                except (OSError, ValueError) as error:
                    self.errors.append("final state publication failed: " + str(error))
                    print(self.errors[-1], file=sys.stderr)
            for sig, handler in previous.items():
                signal.signal(sig, handler)
        return 0 if self.reason == "closed_complete" and not self.errors else 1


def client(root, source_sha256, domain, payload):
    deadline = time.monotonic() + REQUEST_SECONDS
    root = private_dir(root)
    source = inside(root, str(pathlib.Path(__file__).absolute()))
    require(identity(source, deadline)[0]["sha256"] == source_sha256, "client source SHA mismatch")
    protocol = inside(root, str(root / "predeclaration.json"))
    require(identity(protocol, deadline)[0]["sha256"] == PROTOCOL_SHA256, "client protocol SHA mismatch")
    activation_path = inside(root, str(root / "observation-clock" / "activation.json"))
    activation_id = identity(activation_path, deadline)
    require(activation_id[0]["bytes"] <= REQUEST_LIMIT, "activation byte bound exceeded")
    fd = os.open(activation_path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(fd, "rb") as source_file:
        require(stat.S_ISREG(os.fstat(source_file.fileno()).st_mode), "activation is not regular")
        data = source_file.read(REQUEST_LIMIT + 1)
    require(len(data) <= REQUEST_LIMIT, "activation grew past byte bound")
    activation = parse(data)
    require(identity(activation_path, deadline) == activation_id, "activation changed while reading")
    binding = {"study_root": str(root), "protocol_sha256": PROTOCOL_SHA256,
               "source_sha256": source_sha256, "monotonic_clock_id": domain}
    for key, value in binding.items():
        require(activation.get(key) == value, "original activation binding mismatch: " + key)
    socket_path = canonical(activation["socket_path"])
    private_dir(socket_path.parent)
    info = socket_path.lstat()
    require(stat.S_ISSOCK(info.st_mode) and stat.S_IMODE(info.st_mode) == 0o600
            and info.st_uid == os.getuid(), "IPC socket is not private and owned")
    require(isinstance(payload, dict) and not (set(payload) & (set(binding) | {"request_id"})),
            "payload may not override actor binding/request identity")
    request_id = str(uuid.uuid4())
    request = {**payload, **binding, "request_id": request_id}
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as connection:
        check_deadline(deadline)
        connection.settimeout(max(0.001, deadline - time.monotonic()))
        connection.connect(str(socket_path))
        send(connection, request, deadline)
        response = receive(connection, deadline)
        require(response.get("ok") is True, "actor rejected request: " + str(response.get("error")))
        require(response.get("request_id") == request_id, "response request identity mismatch")
        for key, value in binding.items():
            require(response["result"].get(key) == value, "response actor binding mismatch")
        send(connection, {"ack": request_id, "monotonic_clock_id": domain}, deadline)
        require(receive(connection, deadline) == {"acknowledged": request_id, "monotonic_clock_id": domain},
                "final acknowledgement missing/mismatched; stop, never retry")
    return response["result"]


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    commands = parser.add_subparsers(dest="command", required=True)
    serve = commands.add_parser("serve", help="Externally owned finite recorder; never executes commands")
    request = commands.add_parser("client", help="One bounded request; no retries")
    for command in (serve, request):
        command.add_argument("--root", required=True)
        command.add_argument("--source-sha256", required=True)
    serve.add_argument("--lifetime-seconds", required=True, type=int)
    serve.add_argument("--ipc-parent", default="/private/tmp" if sys.platform == "darwin" else "/tmp")
    request.add_argument("--domain", required=True)
    request.add_argument("--request-json", required=True)
    args = parser.parse_args()
    os.umask(0o077)
    try:
        if args.command == "serve":
            return Collector(args.root, args.source_sha256, args.lifetime_seconds, args.ipc_parent).run()
        data = args.request_json.encode()
        require(len(data) <= REQUEST_LIMIT, "request JSON exceeds byte bound")
        result = client(args.root, args.source_sha256, args.domain, parse(data))
        print(json.dumps(result, allow_nan=False), flush=True)
        return 0
    except (OSError, ValueError, TypeError, KeyError, RecursionError) as error:
        print("clock collection failed; stop, do not retry: " + str(error), file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
