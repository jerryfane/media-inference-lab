#![cfg(target_os = "macos")]
use serde_json::Value;
use std::{
    fs,
    os::unix::fs::PermissionsExt,
    path::{Path, PathBuf},
    process::{Child, Command, Stdio},
    thread,
    time::{Duration, Instant},
};

fn private_root() -> tempfile::TempDir {
    let root = tempfile::tempdir().unwrap();
    fs::set_permissions(root.path(), fs::Permissions::from_mode(0o700)).unwrap();
    root
}
fn json(path: impl AsRef<Path>) -> Value {
    serde_json::from_slice(&fs::read(path).unwrap()).unwrap()
}
struct OwnedController {
    child: Child,
    stdout: PathBuf,
    receipt: Option<PathBuf>,
}
impl OwnedController {
    fn spawn(root: &Path, scenario: &str) -> Self {
        let stdout = root.join("controller.stdout");
        let child = Command::new(env!("CARGO_BIN_EXE_mil"))
            .args(["maintenance-cpu", "--root"])
            .arg(root)
            .args(["--scenario", scenario])
            .env_clear()
            .stdout(Stdio::from(fs::File::create(&stdout).unwrap()))
            .stderr(Stdio::from(
                fs::File::create(root.join("controller.stderr")).unwrap(),
            ))
            .spawn()
            .unwrap();
        Self {
            child,
            stdout,
            receipt: None,
        }
    }
    fn protocol(&mut self) -> Value {
        let deadline = Instant::now() + Duration::from_secs(10);
        loop {
            if let Some(value) = self.read_protocol() {
                self.receipt = Some(PathBuf::from(value["receipt"].as_str().unwrap()));
                return value;
            }
            assert!(
                Instant::now() < deadline,
                "CLI did not produce enrollment evidence"
            );
            assert!(
                self.child.try_wait().unwrap().is_none(),
                "controller exited before enrollment"
            );
            thread::sleep(Duration::from_millis(20));
        }
    }
    fn read_protocol(&self) -> Option<Value> {
        let text = fs::read_to_string(&self.stdout).ok()?;
        serde_json::from_str(text.lines().next()?).ok()
    }
    fn wait(&mut self) {
        let deadline = Instant::now() + Duration::from_secs(35);
        while self.child.try_wait().unwrap().is_none() {
            assert!(
                Instant::now() < deadline,
                "CPU controller exceeded its finite ceiling"
            );
            thread::sleep(Duration::from_millis(20));
        }
    }
}
impl Drop for OwnedController {
    fn drop(&mut self) {
        // Keep the root until the bounded CLI settles its own candidates and
        // the guardian recovers, including after a driver assertion unwinds.
        let deadline = Instant::now() + Duration::from_secs(35);
        while matches!(self.child.try_wait(), Ok(None)) && Instant::now() < deadline {
            thread::sleep(Duration::from_millis(20));
        }
        if matches!(self.child.try_wait(), Ok(None)) {
            let _ = self.child.kill();
        }
        let _ = self.child.wait();
        let receipt = self.receipt.clone().or_else(|| {
            self.read_protocol()?
                .get("receipt")?
                .as_str()
                .map(PathBuf::from)
        });
        if let Some(receipt) = receipt {
            let deadline = Instant::now() + Duration::from_secs(35);
            while Instant::now() < deadline {
                if let Ok(bytes) = fs::read(&receipt)
                    && let Ok(value) = serde_json::from_slice::<Value>(&bytes)
                    && let Some(pid) = value["guardian_pid"].as_u64()
                    && matches!(
                        media_inference_lab::process_scope::observe(pid as u32),
                        Ok(None)
                    )
                {
                    return;
                }
                thread::sleep(Duration::from_millis(20));
            }
            eprintln!(
                "owned guardian settlement unavailable; evidence root: {}",
                receipt.display()
            );
        }
    }
}

fn run(scenario: &str) -> (tempfile::TempDir, PathBuf, Value) {
    let root = private_root();
    let mut controller = OwnedController::spawn(root.path(), scenario);
    let protocol = controller.protocol();
    controller.wait();
    let receipt = PathBuf::from(protocol["receipt"].as_str().unwrap());
    let result = json(&receipt);
    assert_eq!(
        controller.child.try_wait().unwrap().unwrap().code(),
        Some(if result["success"] == true { 0 } else { 1 }),
        "CLI exit status must preserve the terminal transaction result"
    );
    (root, receipt, result)
}
fn service_outcomes(receipt: &Path) -> Value {
    json(receipt.parent().unwrap().join("service-outcomes.json"))
}
fn assert_uncontrolled_fixture(root: &Path) {
    let fixture = json(root.join("absence-fixture-settlement.json"));
    assert_eq!(fixture["uncontrolled_by_guardian"], true);
    assert_eq!(fixture["settlement"]["complete"], true);
    let pid = fixture["identity"]["pid"].as_u64().unwrap() as u32;
    assert!(
        media_inference_lab::process_scope::observe(pid)
            .unwrap()
            .is_none()
    );
}

#[test]
fn clean_absence_runs_owned_work_without_fabricating_service_lifecycle() {
    let (_root, receipt, result) = run("absence-clean");
    assert_eq!(result["success"], true);
    assert_eq!(result["creation_attempted"], true);
    assert_eq!(result["settlement"]["complete"], true);
    assert_eq!(result["service_accounting_complete"], true);
    let services = service_outcomes(&receipt);
    assert_eq!(services[0]["restored"], true);
    let absent = &services[1];
    assert_eq!(absent["absence"]["state"], "absent");
    assert_eq!(absent["absence"]["private_qualification"], "not_applicable");
    assert_eq!(absent["root"], Value::Null);
    assert_eq!(absent["gui"], Value::Null);
    assert_eq!(absent["inhibited"], false);
    assert_eq!(absent["restored"], false);
    assert_eq!(absent["launch_record"], Value::Null);
}

#[test]
fn untitled_non_listening_executable_candidate_denies_before_service_controls() {
    let (root, receipt, result) = run("absence-presence");
    assert_eq!(result["success"], false);
    assert_eq!(result["creation_attempted"], false);
    assert_eq!(
        result["service_enrollment_failure"]["absence"]["state"],
        "present"
    );
    assert_eq!(service_outcomes(&receipt), serde_json::json!([]));
    assert_uncontrolled_fixture(root.path());
}

#[test]
fn late_foreign_appearance_aborts_owned_work_but_does_not_block_studio_recovery() {
    let (root, receipt, result) = run("absence-late");
    assert_eq!(result["success"], false);
    assert_eq!(result["creation_attempted"], true);
    assert_eq!(result["settlement"]["complete"], true);
    assert_eq!(result["restored"], true);
    assert_eq!(result["recovery_failure"], Value::Null);
    assert!(result["final_absence_failure"].is_string());
    let services = service_outcomes(&receipt);
    assert_eq!(services[0]["restored"], true);
    assert_eq!(services[1]["absence"]["state"], "present");
    assert_eq!(services[1]["restored"], false);
    assert_eq!(services[1]["root"], Value::Null);
    assert_uncontrolled_fixture(root.path());
}

#[test]
fn ambiguous_or_unavailable_probes_never_admit_work_or_control_candidates() {
    for scenario in ["absence-ambiguous", "absence-probe-error", "absence-reused"] {
        let (root, receipt, result) = run(scenario);
        assert_eq!(result["success"], false, "{scenario}");
        assert_eq!(result["creation_attempted"], false, "{scenario}");
        assert_eq!(
            result["service_enrollment_failure"]["absence"]["state"], "unavailable",
            "{scenario}"
        );
        assert_eq!(service_outcomes(&receipt), serde_json::json!([]));
        if scenario != "absence-probe-error" {
            assert_uncontrolled_fixture(root.path());
        }
    }
}

#[test]
fn absent_scope_controller_loss_settles_experiment_and_restores_only_studio() {
    let root = private_root();
    let mut controller = OwnedController::spawn(root.path(), "absence-controller-loss");
    let protocol = controller.protocol();
    let receipt = PathBuf::from(protocol["receipt"].as_str().unwrap());
    let journal = receipt.parent().unwrap().join("guardian.jsonl");
    let deadline = Instant::now() + Duration::from_secs(15);
    loop {
        if fs::read_to_string(&journal)
            .unwrap_or_default()
            .lines()
            .any(|line| {
                serde_json::from_str::<Value>(line)
                    .ok()
                    .is_some_and(|value| value["phase"] == "experiment_created")
            })
        {
            break;
        }
        assert!(Instant::now() < deadline, "owned experiment did not start");
        thread::sleep(Duration::from_millis(20));
    }
    controller.child.kill().unwrap();
    controller.child.wait().unwrap();
    let result = loop {
        if let Ok(bytes) = fs::read(&receipt)
            && let Ok(value) = serde_json::from_slice::<Value>(&bytes)
        {
            break value;
        }
        assert!(
            Instant::now() < deadline,
            "guardian did not finish bounded recovery"
        );
        thread::sleep(Duration::from_millis(20));
    };
    assert_eq!(result["success"], false);
    assert_eq!(result["creation_attempted"], true);
    assert_eq!(result["settlement"]["complete"], true);
    assert_eq!(result["restored"], true);
    assert_eq!(result["service_accounting_complete"], true);
    let services = service_outcomes(&receipt);
    assert_eq!(services[0]["restored"], true);
    assert_eq!(services[1]["restored"], false);
    assert_eq!(services[1]["absence"]["state"], "absent");
}
