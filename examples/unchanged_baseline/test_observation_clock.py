"""CPU-only CLI qualification; never executes a recorded command.

Default checkout regression run uses the co-located approved protocol fixture
and an isolated temporary root, removed only after all actor owners settle:
  python3 -m unittest discover -s examples/unchanged_baseline \
      -p test_observation_clock.py -v

For retained qualification evidence, optionally select a NEW proof directory:
  H3_CLOCK_PROTOCOL=/absolute/fresh-study/predeclaration.json \
  H3_CLOCK_SMOKE_ROOT=/private/tmp/h3-clock-cpu-proof-UNIQUE \
  python3 -m unittest discover -s examples/unchanged_baseline \
      -p test_observation_clock.py -v

The original approved protocol bytes are copied unchanged. Each test launches
and actually waits/reaps its own original finite actor via subprocess.Popen;
clients are distinct short-lived CLI processes. No production activation, model,
native command, observer, lease, host scan, or service action is performed.
An explicit proof directory retains synthetic records, logs and actual owner
settlement results. Their contents are NOT native transaction evidence.
"""

import hashlib
import importlib.util
import json
import os
import pathlib
import select
import socket
import struct
import subprocess
import sys
import tempfile
import time
import unittest
import uuid

SOURCE = pathlib.Path(__file__).with_name("observation_clock.py")
SPEC = importlib.util.spec_from_file_location("h3_clock_under_test", SOURCE)
CLOCK = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(CLOCK)


def write_private(path, data):
    if not isinstance(data, bytes):
        data = (json.dumps(data, indent=2) + "\n").encode()
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "wb") as output:
        output.write(data)


class OwnedActor:
    def __init__(self, root, protocol, lifetime=3000):
        root.mkdir(mode=0o700)
        self.root = root
        self.source = root / "observation_clock.py"
        write_private(self.source, SOURCE.read_bytes())
        self.sha = hashlib.sha256(self.source.read_bytes()).hexdigest()
        write_private(root / "predeclaration.json", protocol)
        self.command = [sys.executable, str(self.source), "serve", "--root", str(root),
                        "--source-sha256", self.sha, "--lifetime-seconds", str(lifetime),
                        "--ipc-parent", str(pathlib.Path("/tmp").resolve())]
        self.process = None
        self.log = None
        self.ready = None
        self.activation = None
        self.client_count = 0
        self.settlement = None

    def start(self):
        self.log = open(self.root / "actor.stderr", "xb")
        os.chmod(self.root / "actor.stderr", 0o600)
        self.process = subprocess.Popen(self.command, stdin=subprocess.DEVNULL,
                                        stdout=subprocess.PIPE, stderr=self.log)
        readable, _, _ = select.select([self.process.stdout], [], [], 5)
        if not readable:
            raise AssertionError("original actor did not become ready in five seconds")
        self.ready = json.loads(self.process.stdout.readline(131073))
        if self.ready.get("ready") is not True:
            raise AssertionError("actor readiness message missing")
        write_private(self.root / "owner-observed-ready.json", self.ready)
        self.activation = json.loads((self.root / "observation-clock" / "activation.json").read_bytes())
        return self

    def cli(self, payload, domain=None, expected=0):
        self.client_count += 1
        result = subprocess.run(
            [sys.executable, str(self.source), "client", "--root", str(self.root),
             "--source-sha256", self.sha, "--domain", domain or self.ready["monotonic_clock_id"],
             "--request-json", json.dumps(payload)],
            stdin=subprocess.DEVNULL, capture_output=True, timeout=7, check=False)
        write_private(self.root / f"client-{self.client_count}.stdout", result.stdout)
        write_private(self.root / f"client-{self.client_count}.stderr", result.stderr)
        if result.returncode != expected:
            raise AssertionError(f"client exit {result.returncode}, expected {expected}: {result.stderr!r}")
        return json.loads(result.stdout) if expected == 0 else result

    def request(self, payload, request_id=None, **overrides):
        return {**payload, "study_root": str(self.root), "protocol_sha256": CLOCK.PROTOCOL_SHA256,
                "source_sha256": self.sha, "monotonic_clock_id": self.ready["monotonic_clock_id"],
                "request_id": request_id or str(uuid.uuid4()), **overrides}

    def raw(self, request, acknowledge=True):
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as connection:
            connection.settimeout(5)
            connection.connect(self.activation["socket_path"])
            deadline = time.monotonic() + 5
            CLOCK.send(connection, request, deadline)
            response = CLOCK.receive(connection, deadline)
            if acknowledge and response.get("ok"):
                CLOCK.send(connection, {"ack": request["request_id"],
                                        "monotonic_clock_id": self.ready["monotonic_clock_id"]}, deadline)
                CLOCK.receive(connection, deadline)
            return response

    def begin(self, event="H0/execution", **overrides):
        prefix = event.replace("/", "-")
        return {"op": "begin", "event": event,
                "literal_cli_argv": ["/never-executed/immutable-guardian", "--synthetic-clock-only"],
                "receipt_path": str(self.root / (event.split("/")[0] + "-execution-receipt.json")),
                "companion_path": str(self.root / (prefix + "-companion.json")), **overrides}

    def publish_inputs(self, begin):
        keys = ("companion_path",) if begin["event"].endswith("/readiness") else ("receipt_path", "companion_path")
        for key in keys:
            write_private(pathlib.Path(begin[key]), {"synthetic_cpu_clock_fixture": True,
                                                    "not_native_receipt": True, "kind": key})

    def finish(self, event="H0/execution", **overrides):
        return {"op": "finish", "event": event, "exit_code": 0, "errors": [], **overrides}

    def wait(self, timeout=7):
        result = self.process.wait(timeout=timeout)
        self.record_settlement(result, [])
        return result

    def record_settlement(self, result, actions):
        if self.settlement is None:
            self.settlement = {"synthetic_cpu_clock_proof": True, "original_pid": self.process.pid,
                               "actual_outer_owner_wait_returncode": result,
                               "owner_cleanup_actions": actions,
                               "original_domain": self.ready["monotonic_clock_id"] if self.ready else None}
            write_private(self.root / "outer-owner-settlement.json", self.settlement)

    def settle(self):
        if self.process is not None:
            actions = []
            if self.process.poll() is None:
                self.process.terminate()
                actions.append("terminate_original_child")
            try:
                result = self.process.wait(timeout=7)
            except subprocess.TimeoutExpired:
                self.process.kill()
                actions.append("kill_original_child")
                result = self.process.wait(timeout=7)
            self.record_settlement(result, actions)
            self.process.stdout.close()
        if self.log:
            self.log.close()

    def final(self):
        return json.loads((self.root / "observation-clock" / "final.json").read_bytes())


class AdmissionBudgetTests(unittest.TestCase):
    def test_bounded_execution_composes_with_readiness_and_cleanup(self):
        # Start exactly at the admitted boundary; simulate ceilings rather than
        # sleeping or pretending unbounded caller scheduling is covered.
        remaining = CLOCK.ADMISSION_SECONDS["execution"]
        for seconds in (CLOCK.REQUEST_SECONDS, 1900, CLOCK.REQUEST_SECONDS,
                        CLOCK.REQUEST_SECONDS):
            # Execution begin response/ack, outer command, execution finish,
            # then readiness begin before its own admission check.
            remaining -= seconds
        self.assertEqual(remaining, CLOCK.ADMISSION_SECONDS["readiness"])
        self.assertLess(remaining - 1, CLOCK.ADMISSION_SECONDS["readiness"])
        for seconds in (CLOCK.REQUEST_SECONDS, 15, CLOCK.REQUEST_SECONDS):
            # Readiness begin response/ack, declared work ceiling, finish.
            remaining -= seconds
        self.assertEqual(remaining, 30)


class CollectorCliTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        protocol = os.environ.get("H3_CLOCK_PROTOCOL") or SOURCE.with_name("h3_only_predeclaration.json")
        proof = os.environ.get("H3_CLOCK_SMOKE_ROOT")
        cls.protocol = pathlib.Path(protocol).read_bytes()
        if hashlib.sha256(cls.protocol).hexdigest() != CLOCK.PROTOCOL_SHA256:
            raise RuntimeError("CPU proof requires exact unchanged approved protocol bytes")
        if proof:
            cls.proof = pathlib.Path(proof)
            if not cls.proof.is_absolute() or cls.proof.resolve() != cls.proof:
                raise RuntimeError("Synthetic proof path must be canonical and absolute")
        else:
            temporary = tempfile.TemporaryDirectory(
                prefix="h3-clock-tests-", dir=str(pathlib.Path(tempfile.gettempdir()).resolve()))
            # unittest runs every test's actor.settle cleanup before class cleanup.
            cls.addClassCleanup(temporary.cleanup)
            cls.proof = pathlib.Path(temporary.name).resolve() / "proof"
        cls.proof.mkdir(mode=0o700)  # No reuse or reconstruction of a previous proof.
        write_private(cls.proof / "proof-scope.json", {
            "synthetic_cpu_only": True, "native_evidence": False,
            "protocol_sha256": CLOCK.PROTOCOL_SHA256,
            "source_sha256": hashlib.sha256(SOURCE.read_bytes()).hexdigest()})

    def actor(self, suffix="", lifetime=3000):
        actor = OwnedActor(self.proof / (self._testMethodName + suffix), self.protocol, lifetime)
        self.addCleanup(actor.settle)
        return actor.start()

    def assert_terminal(self, actor):
        self.assertEqual(actor.wait(), 1)
        final = actor.final()
        self.assertTrue(final["stopping"])
        self.assertTrue(final["terminal_errors"])
        self.assertFalse(final["collection_complete"])
        self.assertFalse(pathlib.Path(actor.activation["socket_path"]).exists())
        return final

    def test_complete_sequence_survives_distinct_clients_and_owner_reaps(self):
        actor = self.actor()
        prior_end = 0
        execution_receipt = None
        for event in CLOCK.ORDER:
            begin = actor.begin(event)
            first = actor.cli(begin)  # subprocess.run actually reaped this client.
            start = first["record"]
            original_start = pathlib.Path(first["record_path"]).read_bytes()
            status = actor.cli({"op": "status"})  # A fresh client, not a replacement actor.
            self.assertEqual(status["original_pid"], actor.process.pid)
            self.assertEqual(status["monotonic_clock_id"], actor.ready["monotonic_clock_id"])
            self.assertNotIn("started_unix_ms", status)
            self.assertEqual(pathlib.Path(first["record_path"]).read_bytes(), original_start)
            actor.publish_inputs(begin)
            finish = actor.cli(actor.finish(event))["record"]
            self.assertTrue(finish["collection_complete"])
            self.assertEqual(finish["monotonic_clock_id"], start["monotonic_clock_id"])
            self.assertEqual(finish["monotonic_started_ns"], start["monotonic_started_ns"])
            self.assertEqual(finish["started_unix_ms"], start["started_unix_ms"])
            self.assertGreaterEqual(start["monotonic_started_ns"], prior_end)
            self.assertGreaterEqual(finish["monotonic_ended_ns"], start["monotonic_started_ns"])
            self.assertEqual(finish["elapsed_us"],
                             (finish["monotonic_ended_ns"] - start["monotonic_started_ns"]) // 1000)
            self.assertEqual(finish["clock"], "unix_ms")
            self.assertEqual(finish["elapsed_clock"], "monotonic")
            kind = event.split("/")[1]
            self.assertEqual(finish["boundary"], CLOCK.BOUNDARIES[kind])
            self.assertIn("attempt_identity" if kind == "execution" else "readiness_identity", finish)
            self.assertEqual(finish["receipt_identity"]["path"], begin["receipt_path"])
            if kind == "execution":
                execution_receipt = finish["receipt_identity"]
            else:
                self.assertEqual(finish["receipt_identity"], execution_receipt)
            prior_end = finish["monotonic_ended_ns"]
        self.assertTrue(actor.cli({"op": "close"})["collection_complete"])
        self.assertEqual(actor.wait(), 0)
        self.assertEqual(actor.final()["shutdown_reason"], "closed_complete")
        self.assertEqual(actor.settlement["actual_outer_owner_wait_returncode"], 0)
        self.assertFalse(pathlib.Path(actor.activation["socket_path"]).exists())
        for path in actor.root.rglob("*"):
            self.assertEqual(path.stat().st_mode & 0o777, 0o700 if path.is_dir() else 0o600)

    def test_overlap_duplicate_and_wrong_order_stop_original_actor(self):
        for name, second in (("duplicate", "H0/execution"), ("overlap", "H0/readiness")):
            with self.subTest(name=name):
                actor = self.actor("-" + name)
                original = actor.cli(actor.begin())
                data = pathlib.Path(original["record_path"]).read_bytes()
                actor.cli(actor.begin(second), expected=1)
                self.assert_terminal(actor)
                self.assertEqual(pathlib.Path(original["record_path"]).read_bytes(), data)
        actor = self.actor("-wrong-first")
        actor.cli(actor.begin("H1/execution"), expected=1)
        self.assert_terminal(actor)

    def test_finish_requires_original_begin_and_is_once_only(self):
        actor = self.actor("-missing")
        actor.cli(actor.finish(), expected=1)
        self.assert_terminal(actor)
        actor = self.actor("-duplicate")
        begin = actor.begin()
        actor.cli(begin)
        actor.publish_inputs(begin)
        first = actor.cli(actor.finish())
        data = pathlib.Path(first["record_path"]).read_bytes()
        actor.cli(actor.finish(), expected=1)
        self.assert_terminal(actor)
        self.assertEqual(pathlib.Path(first["record_path"]).read_bytes(), data)

    def test_root_protocol_source_and_domain_mismatch_are_terminal(self):
        for key, invalid in (("study_root", str(self.proof)), ("protocol_sha256", "0" * 64),
                             ("source_sha256", "0" * 64), ("monotonic_clock_id", "different-domain")):
            with self.subTest(key=key):
                actor = self.actor("-" + key)
                response = actor.raw(actor.request({"op": "status"}, **{key: invalid}))
                self.assertFalse(response["ok"])
                self.assert_terminal(actor)

    def test_request_replay_is_terminal(self):
        actor = self.actor()
        request = actor.request({"op": "status"})
        self.assertTrue(actor.raw(request)["ok"])
        self.assertFalse(actor.raw(request)["ok"])
        self.assert_terminal(actor)

    def test_existing_and_backdated_receipts_are_rejected(self):
        actor = self.actor("-existing")
        begin = actor.begin()
        actor.publish_inputs(begin)
        original = pathlib.Path(begin["receipt_path"]).read_bytes()
        actor.cli(begin, expected=1)
        self.assert_terminal(actor)
        self.assertEqual(pathlib.Path(begin["receipt_path"]).read_bytes(), original)
        actor = self.actor("-backdated")
        begin = actor.begin()
        actor.cli(begin)
        actor.publish_inputs(begin)
        os.utime(begin["receipt_path"], ns=(1_000_000_000, 1_000_000_000))
        result = actor.cli(actor.finish())
        self.assertFalse(result["record"]["collection_complete"])
        self.assertIn("predates", " ".join(result["record"]["errors"]))
        self.assert_terminal(actor)

    def test_readiness_rejects_wrong_slot_or_new_receipt(self):
        for invalid in ("wrong-slot", "new-receipt"):
            with self.subTest(invalid=invalid):
                actor = self.actor("-" + invalid)
                for event in ("H0/execution", "H0/readiness", "H1/execution"):
                    begin = actor.begin(event)
                    actor.cli(begin)
                    actor.publish_inputs(begin)
                    actor.cli(actor.finish(event))
                wrong_path = (actor.begin("H0/execution")["receipt_path"] if invalid == "wrong-slot"
                              else str(actor.root / "new-readiness-receipt.json"))
                actor.cli(actor.begin("H1/readiness", receipt_path=wrong_path), expected=1)
                self.assert_terminal(actor)
                self.assertFalse((actor.root / "observation-clock" / "H1.readiness.start.json").exists())

    def test_readiness_rejects_execution_receipt_changed_before_begin_or_finish(self):
        for boundary in ("begin", "finish"):
            with self.subTest(boundary=boundary):
                actor = self.actor("-" + boundary)
                execution = actor.begin()
                actor.cli(execution)
                actor.publish_inputs(execution)
                completed = actor.cli(actor.finish())
                original_record = pathlib.Path(completed["record_path"]).read_bytes()
                readiness = actor.begin("H0/readiness")
                if boundary == "finish":
                    actor.cli(readiness)
                    actor.publish_inputs(readiness)
                with open(execution["receipt_path"], "ab") as output:
                    output.write(b" ")
                actor.cli(readiness if boundary == "begin" else actor.finish("H0/readiness"), expected=1)
                self.assert_terminal(actor)
                self.assertEqual(pathlib.Path(completed["record_path"]).read_bytes(), original_record)
                self.assertFalse((actor.root / "observation-clock" / "H0.readiness.json").exists())

    def test_missing_receipt_preserves_incomplete_record(self):
        actor = self.actor()
        begin = actor.begin()
        started = actor.cli(begin)
        result = actor.cli(actor.finish())
        self.assertFalse(result["record"]["collection_complete"])
        self.assertIsNone(result["record"]["receipt_identity"])
        self.assertTrue(pathlib.Path(started["record_path"]).exists())
        self.assert_terminal(actor)

    def test_missing_mutated_and_replaced_original_records_stop_admission(self):
        for change in ("missing", "mutated", "replaced"):
            with self.subTest(change=change):
                actor = self.actor("-" + change)
                begin = actor.begin()
                actor.cli(begin)
                actor.publish_inputs(begin)
                finished = actor.cli(actor.finish())
                path = pathlib.Path(finished["record_path"])
                data = path.read_bytes()
                if change == "missing":
                    path.rename(path.with_suffix(".retained-original"))
                elif change == "mutated":
                    with open(path, "ab") as output:
                        output.write(b" ")
                else:
                    path.rename(path.with_suffix(".retained-original"))
                    write_private(path, data)
                actor.cli(actor.begin("H0/readiness"), expected=1)
                self.assert_terminal(actor)
                self.assertFalse((actor.root / "observation-clock" / "H0.readiness.start.json").exists())

    def test_mutated_consumed_receipt_is_not_silently_rehashed(self):
        actor = self.actor()
        begin = actor.begin()
        actor.cli(begin)
        actor.publish_inputs(begin)
        actor.cli(actor.finish())
        with open(begin["receipt_path"], "ab") as output:
            output.write(b" ")
        actor.cli({"op": "status"}, expected=1)
        self.assert_terminal(actor)

    def test_changed_source_protocol_activation_and_start_are_terminal(self):
        for name in ("source", "protocol", "activation", "start"):
            with self.subTest(name=name):
                actor = self.actor("-" + name)
                start = actor.cli(actor.begin())
                paths = {"source": actor.source, "protocol": actor.root / "predeclaration.json",
                         "activation": actor.root / "observation-clock" / "activation.json",
                         "start": pathlib.Path(start["record_path"])}
                with open(paths[name], "ab") as output:
                    output.write(b" ")
                # Raw IPC deliberately exercises actor-side checks even when
                # client-side source/protocol verification would already stop.
                self.assertFalse(actor.raw(actor.request({"op": "status"}))["ok"])
                self.assert_terminal(actor)

    def test_no_restart_after_original_activation(self):
        actor = self.actor()
        activation = (actor.root / "observation-clock" / "activation.json").read_bytes()
        concurrent = subprocess.run(actor.command, stdin=subprocess.DEVNULL, capture_output=True,
                                    timeout=7, check=False)
        write_private(actor.root / "concurrent-restart-rejection.stderr", concurrent.stderr)
        self.assertNotEqual(concurrent.returncode, 0)
        self.assertEqual(actor.cli({"op": "status"})["original_pid"], actor.process.pid)
        actor.cli({"op": "close"})
        self.assertEqual(actor.wait(), 1)
        result = subprocess.run(actor.command, stdin=subprocess.DEVNULL, capture_output=True,
                                timeout=7, check=False)
        write_private(actor.root / "restart-rejection.stderr", result.stderr)
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual((actor.root / "observation-clock" / "activation.json").read_bytes(), activation)

    def test_response_loss_stops_without_reissuing_or_reconstructing(self):
        actor = self.actor()
        result = actor.raw(actor.request(actor.begin()), acknowledge=False)
        self.assertTrue(result["ok"])
        final = self.assert_terminal(actor)
        self.assertEqual(final["active_event"], "H0/execution")
        self.assertTrue((actor.root / "observation-clock" / "H0.execution.start.json").exists())
        self.assertFalse((actor.root / "observation-clock" / "H0.execution.json").exists())

    def test_oversized_request_is_terminal(self):
        actor = self.actor()
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as connection:
            connection.settimeout(5)
            connection.connect(actor.activation["socket_path"])
            connection.sendall(struct.pack("!I", CLOCK.REQUEST_LIMIT + 1))
            result = CLOCK.receive(connection, time.monotonic() + 5)
            self.assertFalse(result["ok"])
        self.assert_terminal(actor)

    def test_read_deadline_is_finite(self):
        actor = self.actor()
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as connection:
            connection.connect(actor.activation["socket_path"])
            connection.sendall(b"\x00")  # Incomplete frame; never retry it.
            self.assert_terminal(actor)

    def test_execution_rejects_incomplete_exchange_reserve(self):
        actor = self.actor(lifetime=1950)
        actor.cli(actor.begin(), expected=1)
        final = self.assert_terminal(actor)
        self.assertEqual(final["completed_brackets"], 0)
        self.assertIsNone(final["active_event"])
        self.assertFalse((actor.root / "observation-clock" / "H0.execution.start.json").exists())

    def test_remaining_lifetime_admission_and_idle_expiry(self):
        actor = self.actor("-admission", lifetime=1944)
        actor.cli(actor.begin(), expected=1)
        self.assert_terminal(actor)
        actor = self.actor("-expiry", lifetime=2)
        status = actor.cli({"op": "status"})
        self.assertIsNone(status["active_event"])
        final = self.assert_terminal(actor)
        self.assertEqual(final["shutdown_reason"], "expired")
        self.assertEqual(list((actor.root / "observation-clock").glob("*.start.json")), [])

    def test_symlink_outside_root_and_oversized_metadata_are_rejected(self):
        actor = self.actor("-symlink")
        begin = actor.begin()
        actor.cli(begin)
        actor.publish_inputs({**begin, "receipt_path": str(actor.root / "symlink-target.json")})
        pathlib.Path(begin["receipt_path"]).symlink_to(actor.root / "symlink-target.json")
        actor.cli(actor.finish(), expected=1)
        self.assert_terminal(actor)
        actor = self.actor("-outside")
        actor.cli(actor.begin(receipt_path=str(self.proof / "foreign.json")), expected=1)
        self.assert_terminal(actor)
        actor = self.actor("-oversized")
        begin = actor.begin()
        actor.cli(begin)
        actor.publish_inputs(begin)
        with open(begin["receipt_path"], "ab") as output:
            output.truncate(CLOCK.LIMIT + 1)
        result = actor.cli(actor.finish())
        self.assertFalse(result["record"]["collection_complete"])
        self.assert_terminal(actor)

    def test_nonzero_outcome_closes_collection_without_altering_exit_code(self):
        actor = self.actor()
        begin = actor.begin()
        actor.cli(begin)
        actor.publish_inputs(begin)
        result = actor.cli(actor.finish(exit_code=7))
        self.assertEqual(result["record"]["exit_code"], 7)
        self.assertTrue(result["record"]["collection_complete"])
        self.assert_terminal(actor)


class ExternalOwnerTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        CollectorCliTests.setUpClass.__func__(cls)

    def test_owner_interrupt_settles_original_collector_without_success_or_restart(self):
        actor = OwnedActor(self.proof / "external-owner-interrupt", self.protocol)
        self.addCleanup(actor.settle)
        source = SOURCE.with_name("clock_owner.py").read_bytes()
        owner = actor.root / "clock_owner.py"
        write_private(owner, source)
        actor.command = [sys.executable, "-I", "-S", "-B", str(owner),
                         "--root", str(actor.root), "--source-sha256", actor.sha,
                         "--owner-sha256", hashlib.sha256(source).hexdigest(),
                         "--lifetime-seconds", "3000"]
        actor.start()
        created = json.loads((actor.root / "clock-owner" / "creation.json").read_bytes())
        self.assertEqual(created["owner_pid"], actor.process.pid)
        self.assertNotEqual(created["original_pid"], actor.process.pid)
        write_private(actor.root / "owner-interruption-request.json",
                      {"original_owner_pid": actor.process.pid, "signal": "SIGTERM"})
        actor.process.terminate()
        self.assertEqual(actor.wait(timeout=15), 1)
        outcome = json.loads((actor.root / "clock-owner" / "outcome.json").read_bytes())
        self.assertEqual(outcome["original_pid"], created["original_pid"])
        self.assertTrue(outcome["leader_reaped"])
        self.assertTrue(outcome["group_absent"])
        self.assertEqual(outcome["signals_sent"], ["SIGTERM"])
        self.assertNotEqual(outcome["exit_code"], 0)
        self.assertFalse(outcome["complete"])
        self.assertTrue(outcome["errors"])
        self.assertTrue((actor.root / "observation-clock" / "activation.json").is_file())
        self.assertFalse((actor.root / "observation-clock" / "H0.execution.start.json").exists())


if __name__ == "__main__":
    unittest.main()
