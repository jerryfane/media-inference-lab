"""Real harmless CPU children only; these tests are NOT native/model successes.

python3 -m unittest discover -s examples/unchanged_baseline \
    -p test_study_command_owner.py -v

The bracket tests run an isolated original clock actor and retain its actual
start record. The command owner itself never starts or queries that actor.
"""
import hashlib
import importlib.util
import json
import os
import pathlib
import signal
import shutil
import subprocess
import sys
import tempfile
import unittest

HERE = pathlib.Path(__file__).resolve().parent
OWNER = HERE / "study_command_owner.py"
SPEC = importlib.util.spec_from_file_location("clock_test_helpers", HERE / "test_observation_clock.py")
HELPERS = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(HELPERS)
write_private = HELPERS.write_private
CPU = "import json,os,sys; print(json.dumps({'cwd':os.getcwd(),'argv':sys.argv,'pid':os.getpid(),'pgid':os.getpgrp(),'cpu_fixture':True})); print('actual stderr',file=sys.stderr)"


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


class StudyCommandOwnerTests(unittest.TestCase):
    def setUp(self):
        self.base = pathlib.Path(tempfile.mkdtemp(prefix="study-command-cpu-")).resolve()
        self.addCleanup(self.retain_failed_evidence)
        self.invocations = 0
        self.root = self.base / "study"
        self.root.mkdir(mode=0o700)
        (self.root / "slots").mkdir(mode=0o700)
        self.binding = self.root / "launch.json"
        self.output = self.root / "slots" / "H0"

    def retain_failed_evidence(self):
        result = self._outcome.result
        failed = any(test is self or getattr(test, "test_case", None) is self
                     for test, _ in result.failures + result.errors)
        if failed:
            print(f"\nRetained failed CPU command evidence: {self.base}", file=sys.stderr)
        else:
            shutil.rmtree(self.base)

    def pin(self, argv=None, **values):
        binding = {"cwd": str(self.root), "literal_cli_argv": argv or [sys.executable, "-I", "-S", "-B", "-c", CPU, "space arg", "--literal"], **values}
        write_private(self.binding, binding)
        return binding

    def command(self, **overrides):
        values = {"launch-binding": str(self.binding), "launch-binding-sha256": digest(self.binding),
                  "output-dir": str(self.output), "timeout-seconds": "5", "mode": "cpu", **overrides}
        return [sys.executable, "-I", "-S", "-B", str(OWNER),
                *[part for key, value in values.items() for part in ("--" + key, str(value))]]

    def invoke(self, expected=0, **overrides):
        command = self.command(**overrides)
        process = subprocess.Popen(command, cwd=self.base, stdin=subprocess.DEVNULL,
                                   stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        actions = []
        timed_out = False
        try:
            stdout, stderr = process.communicate(timeout=20)
        except subprocess.TimeoutExpired:
            timed_out = True
            # Signal only the still-owned original wrapper. Its handler owns
            # command cleanup; never rediscover/signal its child by saved PID.
            process.terminate()
            actions.append("terminate_original_wrapper")
            try:
                stdout, stderr = process.communicate(timeout=12)
            except subprocess.TimeoutExpired:
                process.kill()
                actions.append("kill_original_wrapper")
                stdout, stderr = process.communicate(timeout=5)
        self.invocations += 1
        prefix = self.base / f"wrapper-{self.invocations}"
        write_private(prefix.with_suffix(".stdout"), stdout)
        write_private(prefix.with_suffix(".stderr"), stderr)
        write_private(prefix.with_suffix(".json"),
                      {"argv": command, "original_wrapper_pid": process.pid,
                       "exit_code": process.returncode, "leader_reaped": process.returncode is not None,
                       "timed_out": timed_out, "cleanup_actions": actions})
        self.assertFalse(timed_out, f"original wrapper timeout; evidence: {self.base}")
        self.assertEqual(process.returncode, expected, stderr.decode(errors="replace"))
        return subprocess.CompletedProcess(command, process.returncode, stdout, stderr)

    def outcome(self):
        return json.loads((self.output / "command-outcome.json").read_bytes())

    def test_pinned_argv_and_cwd_are_actual_not_evidence_directory(self):
        binding = self.pin()
        self.invoke()
        outcome = self.outcome()
        actual = json.loads((self.output / "stdout").read_bytes())
        self.assertEqual(actual["cwd"], str(self.root))
        self.assertNotEqual(actual["cwd"], str(self.output))
        self.assertEqual(actual["argv"], ["-c", "space arg", "--literal"])
        self.assertEqual(outcome["argv"], binding["literal_cli_argv"])
        self.assertEqual(outcome["cwd"], actual["cwd"])
        self.assertEqual(outcome["original_pid"], actual["pid"])
        self.assertEqual(outcome["original_pgid"], actual["pgid"])
        self.assertEqual((self.output / "stderr").read_bytes(), b"actual stderr\n")
        for name in ("stdout", "stderr"):
            path = self.output / name
            self.assertEqual(outcome[name]["sha256"], digest(path))
            self.assertEqual(outcome[name]["bytes"], path.stat().st_size)
        self.assertTrue(outcome["complete"])
        self.assertTrue(outcome["leader_reaped"])
        self.assertTrue(outcome["group_absent"])
        self.assertTrue(outcome["output_complete"])
        self.assertEqual(outcome["signals_sent"], [])
        self.assertFalse(outcome["original_study_bracket"])
        self.assertEqual(outcome["declared_scope"], "cpu")
        self.assertNotIn("native_model_service_observer_activity", outcome)

    def test_unreviewed_environment_rejects_before_child(self):
        marker = self.root / "forbidden-child"
        program = f"with open({str(marker)!r},'wb') as f: f.write(b'ran')"
        for index, environment in enumerate((
            {"LC_ALL": "C", "DYLD_INSERT_LIBRARIES": "/unreviewed.dylib"},
            {"LC_ALL": "C", "PATH": "/unreviewed"},
            {"HOME": str(self.root)},
            {"LC_ALL": "C", "HOME": "x" * 65536},
        )):
            with self.subTest(keys=list(environment)):
                self.binding = self.root / f"environment-{index}.json"
                self.pin([sys.executable, "-I", "-S", "-c", program], environment=environment)
                self.invoke(expected=1)
                self.assertFalse(marker.exists())
                self.assertFalse(self.output.exists())

    def test_outputs_are_create_only_and_second_invocation_does_not_spawn(self):
        count = self.root / "actual-child-count"
        self.pin([sys.executable, "-I", "-S", "-c", f"with open({str(count)!r},'ab') as f: f.write(b'child\\n')"])
        self.invoke()
        original = {path.name: path.read_bytes() for path in self.output.iterdir()}
        self.invoke(expected=1)
        self.assertEqual(count.read_bytes(), b"child\n")
        self.assertEqual(original, {path.name: path.read_bytes() for path in self.output.iterdir()})

    def test_hash_mismatch_rejects_before_spawn(self):
        self.pin()
        self.invoke(expected=1, **{"launch-binding-sha256": "0" * 64})
        self.assertFalse(self.output.exists())

    def test_nonprivate_binding_rejects_before_spawn(self):
        self.pin()
        self.binding.chmod(0o644)
        self.invoke(expected=1)
        self.assertFalse(self.output.exists())

    def test_symlink_cwd_rejects_before_spawn(self):
        alias = self.base / "alias"
        alias.symlink_to(self.root, target_is_directory=True)
        self.pin(cwd=str(alias))
        self.invoke(expected=1)
        self.assertFalse(self.output.exists())

    def test_cwd_override_is_not_an_executor_option(self):
        self.pin()
        self.invoke(expected=2, cwd=str(self.output))
        self.assertFalse(self.output.exists())

    def test_oversized_argv_rejects_before_spawn(self):
        self.pin([sys.executable, "-c", CPU, "x" * 65536])
        self.invoke(expected=1)
        self.assertFalse(self.output.exists())

    def test_nonzero_original_exit_is_preserved(self):
        self.pin([sys.executable, "-I", "-S", "-c", "import sys; print('real failure'); sys.exit(7)"])
        self.invoke(expected=1)
        outcome = self.outcome()
        self.assertEqual(outcome["exit_code"], 7)
        self.assertTrue(outcome["complete"])
        self.assertEqual((self.output / "stdout").read_bytes(), b"real failure\n")
        self.assertEqual(outcome["signals_sent"], [])

    def test_timeout_settles_original_group_without_signalling_unrelated_child(self):
        unrelated = subprocess.Popen([sys.executable, "-I", "-S", "-c", "import time; time.sleep(30)"],
                                     stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                                     stderr=subprocess.DEVNULL, start_new_session=True)
        def settle_unrelated():
            if unrelated.poll() is None:
                unrelated.terminate()
            unrelated.wait(timeout=5)
        self.addCleanup(settle_unrelated)
        program = "import json,os,signal,time; signal.signal(signal.SIGTERM,signal.SIG_IGN); print(json.dumps({'pid':os.getpid(),'pgid':os.getpgrp()}),flush=True); time.sleep(30)"
        self.pin([sys.executable, "-I", "-S", "-c", program])
        self.invoke(expected=1, **{"timeout-seconds": "1"})
        outcome = self.outcome()
        actual = json.loads((self.output / "stdout").read_bytes())
        self.assertFalse(outcome["complete"])
        self.assertTrue(outcome["leader_reaped"])
        self.assertTrue(outcome["group_absent"])
        self.assertTrue(outcome["output_complete"])
        self.assertEqual(outcome["exit_code"], -signal.SIGKILL)
        self.assertEqual([item["signal"] for item in outcome["signals_sent"]], ["SIGTERM", "SIGKILL"])
        self.assertTrue(all(item["pgid"] == actual["pgid"] for item in outcome["signals_sent"]))
        self.assertIsNone(unrelated.poll())
        self.assertLess(outcome["wall_seconds"], 15)

    def test_timeout_reaches_original_group_child_and_preserves_output(self):
        # The leader reaps its own CPU child on TERM; no orphan/zombie timing
        # assumptions or process lookup are needed to demonstrate group cleanup.
        program = """import json,os,signal,subprocess,sys,time
child = subprocess.Popen([sys.executable, '-I', '-S', '-c', 'import time; time.sleep(30)'])
def stop(signum, frame):
    result = child.wait(timeout=4)
    print(json.dumps({'child_exit':result}), flush=True)
    sys.exit(0)
signal.signal(signal.SIGTERM, stop)
print(json.dumps({'pid':os.getpid(),'child_pid':child.pid}), flush=True)
time.sleep(30)
"""
        self.pin([sys.executable, "-I", "-S", "-c", program])
        self.invoke(expected=1, **{"timeout-seconds": "1"})
        outcome = self.outcome()
        lines = [json.loads(line) for line in (self.output / "stdout").read_bytes().splitlines()]
        self.assertEqual(lines[-1]["child_exit"], -signal.SIGTERM)
        self.assertEqual(outcome["exit_code"], 0, json.dumps(outcome, sort_keys=True))
        self.assertTrue(outcome["leader_reaped"], json.dumps(outcome, sort_keys=True))
        self.assertTrue(outcome["group_absent"])
        self.assertTrue(outcome["output_complete"])
        self.assertFalse(outcome["complete"])

    def test_excess_output_is_bounded_and_incomplete(self):
        self.pin([sys.executable, "-I", "-S", "-c", "import os; os.write(1,b'x'*(1024*1024))"])
        self.invoke(expected=1)
        outcome = self.outcome()
        self.assertFalse(outcome["complete"])
        self.assertTrue(outcome["output_truncated"])
        self.assertFalse(outcome["output_complete"])
        self.assertEqual((self.output / "stdout").stat().st_size, 512 * 1024)
        self.assertTrue(outcome["leader_reaped"], json.dumps(outcome, sort_keys=True))
        self.assertTrue(outcome["group_absent"])

    def test_timeout_after_child_closes_output_still_reaps_original_group(self):
        program = "import os,signal,time; signal.signal(signal.SIGTERM,signal.SIG_IGN); os.close(1); os.close(2); time.sleep(30)"
        self.pin([sys.executable, "-I", "-S", "-c", program])
        self.invoke(expected=1, **{"timeout-seconds": "1"})
        outcome = self.outcome()
        self.assertEqual(outcome["exit_code"], -signal.SIGKILL, json.dumps(outcome, sort_keys=True))
        self.assertTrue(outcome["leader_reaped"], json.dumps(outcome, sort_keys=True))
        self.assertTrue(outcome["group_absent"], json.dumps(outcome, sort_keys=True))
        self.assertTrue(outcome["output_complete"])
        self.assertFalse(outcome["complete"])
        self.assertEqual(outcome["stdout"]["bytes"], 0)
        self.assertEqual(outcome["stderr"]["bytes"], 0)

    def bracket_fixture(self):
        actor = HELPERS.OwnedActor(self.base / "clock-study", (HERE / "h3_only_predeclaration.json").read_bytes())
        self.addCleanup(actor.settle)
        actor.start()
        self.root = actor.root
        self.binding = self.root / "launch.json"
        self.output = self.root / "cpu-command-evidence"
        argv = [sys.executable, "-I", "-S", "-B", "-c", CPU, "original-clock-cpu-fixture"]
        begin = actor.begin(literal_cli_argv=argv, companion_path=str(self.output / "command-outcome.json"))
        response = actor.cli(begin)
        start = pathlib.Path(response["record_path"])
        collector = {key: response["record"][key] for key in
                     ("study_root", "protocol_sha256", "source_identity", "monotonic_clock_id")}
        self.pin(argv, collector=collector, event="H0/execution")
        return actor, begin, start

    def test_original_real_clock_start_classifies_harmless_cpu_child_truthfully(self):
        actor, begin, start = self.bracket_fixture()
        self.invoke(mode="study", **{"bracket-start": str(start), "bracket-start-sha256": digest(start)})
        outcome = self.outcome()
        self.assertTrue(outcome["original_study_bracket"])
        self.assertEqual(outcome["original_bracket_reference"]["identity"]["sha256"], digest(start))
        self.assertEqual(outcome["activity_classification"], "original_bracket_execution")
        self.assertNotIn("native_model_service_observer_activity", outcome)
        actual = json.loads((self.output / "stdout").read_bytes())
        self.assertTrue(actual["cpu_fixture"])
        self.assertEqual(actual["cwd"], str(actor.root))
        write_private(pathlib.Path(begin["receipt_path"]), {"synthetic_cpu_fixture": True, "not_native_receipt": True})
        finish = actor.cli(actor.finish())
        self.assertTrue(finish["record"]["collection_complete"])
        self.assertEqual(finish["record"]["attempt_identity"]["sha256"], digest(self.output / "command-outcome.json"))

    def test_cpu_scope_cannot_claim_supplied_original_bracket(self):
        _, _, start = self.bracket_fixture()
        self.invoke(expected=1, **{"bracket-start": str(start), "bracket-start-sha256": digest(start)})
        self.assertFalse(self.output.exists())

    def test_study_requires_original_start_not_default_false(self):
        self.pin()
        self.invoke(expected=1, mode="study")
        self.assertFalse(self.output.exists())

    def test_mismatched_original_start_rejects_before_child(self):
        _, _, start = self.bracket_fixture()
        original = json.loads(self.binding.read_bytes())
        variants = [
            {**original, "literal_cli_argv": original["literal_cli_argv"] + ["different-command"]},
            {**original, "event": "H0/readiness"},
            {**original, "event": "H0/unknown"},
            {**original, "collector": {**original["collector"], "monotonic_clock_id": "other-domain"}},
            {**original, "collector": {**original["collector"], "study_root": str(self.base)}},
        ]
        for index, binding in enumerate(variants):
            with self.subTest(index=index):
                self.binding = self.root / f"different-{index}.json"
                write_private(self.binding, binding)
                self.invoke(expected=1, mode="study", **{"bracket-start": str(start), "bracket-start-sha256": digest(start)})
                self.assertFalse(self.output.exists())

    def test_changed_saved_collector_source_rejects_start(self):
        actor, _, start = self.bracket_fixture()
        with actor.source.open("ab") as source:
            source.write(b"\n# changed CPU fixture source\n")
        self.invoke(expected=1, mode="study", **{"bracket-start": str(start), "bracket-start-sha256": digest(start)})
        self.assertFalse(self.output.exists())

    def test_completed_original_start_is_not_reusable(self):
        actor, begin, start = self.bracket_fixture()
        self.invoke(mode="study", **{"bracket-start": str(start), "bracket-start-sha256": digest(start)})
        write_private(pathlib.Path(begin["receipt_path"]), {"synthetic_cpu_fixture": True, "not_native_receipt": True})
        actor.cli(actor.finish())
        self.output = self.root / "must-not-retry"
        self.invoke(expected=1, mode="study", **{"bracket-start": str(start), "bracket-start-sha256": digest(start)})
        self.assertFalse(self.output.exists())


if __name__ == "__main__":
    unittest.main()
