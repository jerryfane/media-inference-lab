#![cfg(unix)]

use media_inference_lab::guards::{
    GuardConfig, GuardDecision, GuardPolicy, GuardReport, GuardSample, GuardSnapshot, Lease,
    MAX_MONITOR_DURATION_MS, MAX_SAMPLES, MAX_SWAP_GROWTH_BYTES, Observation, evaluate_launch,
    evaluate_running, parse_memory_pressure, parse_swap_usage,
};
use parking_lot::Mutex;
use std::{
    fs,
    os::unix::{fs::symlink, process::CommandExt},
    path::{Path, PathBuf},
    process::{Child, Command, Stdio},
    thread,
    time::{Duration, Instant},
};

// Avoid cross-test fork/exec windows temporarily inheriting another case's lease FD.
static LEASE_CASE: Mutex<()> = Mutex::new(());
fn available<T>(value: T) -> Observation<T> {
    Observation::Available { value }
}
fn config() -> GuardConfig {
    GuardConfig {
        min_disk_free_bytes: 1000,
        max_disk_growth_bytes: 2000,
        sample_interval_ms: 100,
    }
}
fn snapshot() -> GuardSnapshot {
    GuardSnapshot {
        epoch_ms: 1,
        platform: "deterministic_cpu_fixture".into(),
        free_system_memory_percent: available(30.0),
        swap_used_bytes: available(1024),
        disk_free_bytes: available(10_000),
    }
}
fn report() -> GuardReport {
    let baseline = snapshot();
    GuardReport {
        schema_version: 3,
        config: config(),
        policy: GuardPolicy::default(),
        initial_decision: evaluate_launch(&config(), &baseline),
        baseline,
        samples: vec![],
    }
}
#[test]
fn fixed_memory_and_swap_threshold_boundaries() {
    let config = config();
    let baseline = snapshot();
    assert!(evaluate_launch(&config, &baseline).allowed);
    let mut sample = baseline.clone();
    sample.free_system_memory_percent = available(29.999);
    assert!(!evaluate_launch(&config, &sample).allowed);
    sample.free_system_memory_percent = available(15.0);
    assert!(evaluate_running(&config, &baseline, &sample).allowed);
    sample.free_system_memory_percent = available(14.999);
    assert!(!evaluate_running(&config, &baseline, &sample).allowed);
    sample.free_system_memory_percent = available(30.0);
    sample.swap_used_bytes = available(1024 + MAX_SWAP_GROWTH_BYTES);
    assert!(evaluate_running(&config, &baseline, &sample).allowed);
    sample.swap_used_bytes = available(1025 + MAX_SWAP_GROWTH_BYTES);
    assert!(!evaluate_running(&config, &baseline, &sample).allowed);
    sample.swap_used_bytes = available(0);
    assert!(evaluate_running(&config, &baseline, &sample).allowed);
}
#[test]
fn disk_and_every_missing_resource_observation_fail_closed() {
    let config = config();
    let baseline = snapshot();
    let mut sample = baseline.clone();
    sample.disk_free_bytes = available(config.min_disk_free_bytes - 1);
    assert!(!evaluate_launch(&config, &sample).allowed);
    sample.disk_free_bytes = available(config.min_disk_free_bytes);
    assert!(evaluate_launch(&config, &sample).allowed);
    sample.disk_free_bytes = available(8000);
    assert!(evaluate_running(&config, &baseline, &sample).allowed);
    sample.disk_free_bytes = available(7999);
    assert!(!evaluate_running(&config, &baseline, &sample).allowed);
    for field in [
        "free_system_memory_percent",
        "swap_used_bytes",
        "disk_free_bytes",
    ] {
        let mut json = serde_json::to_value(&baseline).unwrap();
        json[field] =
            serde_json::json!({"status":"unavailable", "reason":"collector fixture failure"});
        let sample = serde_json::from_value(json).unwrap();
        for decision in [
            evaluate_launch(&config, &sample),
            evaluate_running(&config, &baseline, &sample),
        ] {
            assert!(!decision.allowed);
            assert!(
                decision
                    .reasons
                    .iter()
                    .any(|reason| reason.contains("collector fixture failure"))
            );
        }
        assert!(!evaluate_running(&config, &sample, &baseline).allowed);
    }
    for invalid in [f64::NAN, f64::INFINITY, -0.01, 100.01] {
        let mut sample = baseline.clone();
        sample.free_system_memory_percent = available(invalid);
        assert!(!evaluate_launch(&config, &sample).allowed);
    }
}
#[test]
fn collectors_reject_malformed_or_ambiguous_numbers() {
    assert_eq!(
        parse_memory_pressure("System-wide memory free percentage: 30%\n").unwrap(),
        30.0
    );
    for text in [
        "",
        "free: 30%",
        "System-wide memory free percentage: NaN%",
        "System-wide memory free percentage: 101%",
        "System-wide memory free percentage: 30%\nSystem-wide memory free percentage: 30%",
    ] {
        assert!(parse_memory_pressure(text).is_err());
    }
    assert_eq!(
        parse_swap_usage(
            "vm.swapusage: total = 1024.00M used = 512.50M free = 511.50M (encrypted)"
        )
        .unwrap(),
        MAX_SWAP_GROWTH_BYTES + 524288
    );
    for text in [
        "",
        "vm.swapusage: used = -1M",
        "vm.swapusage: used = NaNM",
        "vm.swapusage: used = 1T",
        "vm.swapusage: used = 1é",
        "vm.swapusage: used = 1M used = 2M",
        "vm.swapusage: used = 18446744073709551615G",
    ] {
        assert!(parse_swap_usage(text).is_err());
    }
}
#[test]
fn guard_evidence_validation_rejects_forged_or_unbounded_decisions() {
    let good = report();
    good.validate().unwrap();
    let mut forged = good.clone();
    forged.baseline.free_system_memory_percent = available(29.0);
    assert!(forged.validate().is_err());
    let mut forged = good.clone();
    forged.policy.abort_free_percent_below = 1.0;
    assert!(forged.validate().is_err());
    let mut forged = good.clone();
    forged.config.sample_interval_ms = 10_000;
    assert!(forged.validate().is_err());
    let mut failing = snapshot();
    failing.free_system_memory_percent = available(14.0);
    let sample = GuardSample {
        elapsed_ms: 100,
        decision: evaluate_running(&config(), &good.baseline, &failing),
        snapshot: failing,
        stop_reason: None,
    };
    let mut stopped = good.clone();
    stopped.samples.push(sample.clone());
    stopped.validate().unwrap();
    stopped.samples.push(sample.clone());
    assert!(stopped.validate().is_err());
    let mut forged = good.clone();
    forged.samples.push(GuardSample {
        decision: GuardDecision {
            allowed: true,
            reasons: vec![],
        },
        ..sample.clone()
    });
    assert!(forged.validate().is_err());
    let mut overdue = good.clone();
    overdue.samples.push(GuardSample {
        elapsed_ms: MAX_MONITOR_DURATION_MS,
        ..sample.clone()
    });
    assert!(overdue.validate().is_err());
    let mut too_many = good;
    too_many.samples = vec![sample; MAX_SAMPLES + 1];
    assert!(too_many.validate().is_err());
    let mut json = serde_json::to_value(config()).unwrap();
    json["abort_free_percent_below"] = serde_json::json!(1);
    assert!(serde_json::from_value::<GuardConfig>(json).is_err());
}

struct OwnedChild(Child);
impl Drop for OwnedChild {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}
fn root() -> (tempfile::TempDir, PathBuf) {
    let temporary = tempfile::tempdir().unwrap();
    let root = fs::canonicalize(temporary.path()).unwrap();
    (temporary, root)
}
fn await_file(path: &Path, child: &mut Child) {
    let deadline = Instant::now() + Duration::from_secs(5);
    while !path.exists() {
        assert!(
            child.try_wait().unwrap().is_none(),
            "lease helper exited before ready"
        );
        assert!(
            Instant::now() < deadline,
            "lease helper did not become ready"
        );
        thread::sleep(Duration::from_millis(5));
    }
}
fn owner(root: &Path, inherit: bool) -> OwnedChild {
    OwnedChild(
        Command::new(std::env::current_exe().unwrap())
            .args(["--exact", "lease_subprocess_helper", "--nocapture"])
            .env("MIL_LEASE_TEST_ROOT", root)
            .env("MIL_LEASE_TEST_INHERIT", if inherit { "yes" } else { "no" })
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .unwrap(),
    )
}
#[test]
fn lease_subprocess_helper() {
    let Some(root) = std::env::var_os("MIL_LEASE_TEST_ROOT") else {
        return;
    };
    let root = PathBuf::from(root);
    let lease = Lease::acquire(&root.join("gpu.lock")).unwrap();
    let _inherited_child = if std::env::var("MIL_LEASE_TEST_INHERIT").unwrap() == "yes" {
        let fd = lease.raw_fd();
        let mut command = Command::new("/bin/sh");
        command.args(["-c", "n=0; while [ ! -e release ] && [ \"$n\" -lt 500 ]; do /bin/sleep 0.01; n=$((n + 1)); done"])
            .current_dir(&root).env_clear().stdin(Stdio::null()).stdout(Stdio::null()).stderr(Stdio::null());
        unsafe {
            command.pre_exec(move || {
                let flags = libc::fcntl(fd, libc::F_GETFD);
                if flags < 0 || libc::fcntl(fd, libc::F_SETFD, flags & !libc::FD_CLOEXEC) < 0 {
                    return Err(std::io::Error::last_os_error());
                }
                Ok(())
            });
        }
        Some(command.spawn().unwrap())
    } else {
        None
    };
    if _inherited_child.is_some() {
        drop(lease);
    }
    fs::write(root.join("ready"), b"owned").unwrap();
    thread::sleep(Duration::from_secs(30));
}
#[test]
fn lease_contention_close_recovery_and_link_rejection() {
    let _case = LEASE_CASE.lock();
    let (_temporary, root) = root();
    let path = root.join("gpu.lock");
    let lease = Lease::acquire(&path).unwrap();
    assert!(Lease::acquire(&path).is_err());
    assert_ne!(
        unsafe { libc::fcntl(lease.raw_fd(), libc::F_GETFD) } & libc::FD_CLOEXEC,
        0
    );
    drop(lease);
    let reacquired = Lease::acquire(&path).unwrap();
    drop(reacquired);
    assert!(path.exists(), "lease inode must remain persistent");
    symlink(&path, root.join("alias.lock")).unwrap();
    assert!(Lease::acquire(&root.join("alias.lock")).is_err());
    fs::hard_link(&path, root.join("hard.lock")).unwrap();
    assert!(Lease::acquire(&path).is_err());
}
#[test]
fn abnormal_owner_exit_recovers_without_touching_unrelated_process() {
    let _case = LEASE_CASE.lock();
    let (_temporary, root) = root();
    let mut sentinel = OwnedChild(Command::new("/bin/sleep").arg("30").spawn().unwrap());
    let mut owner = owner(&root, false);
    await_file(&root.join("ready"), &mut owner.0);
    assert!(Lease::acquire(&root.join("gpu.lock")).is_err());
    owner.0.kill().unwrap();
    owner.0.wait().unwrap();
    let _lease = Lease::acquire(&root.join("gpu.lock")).unwrap();
    assert!(sentinel.0.try_wait().unwrap().is_none());
}
#[test]
fn inherited_child_keeps_lease_after_supervisor_sigkill_until_natural_exit() {
    let _case = LEASE_CASE.lock();
    let (_temporary, root) = root();
    let mut owner = owner(&root, true);
    await_file(&root.join("ready"), &mut owner.0);
    assert!(
        Lease::acquire(&root.join("gpu.lock")).is_err(),
        "normal parent close must not unlock an inherited child lease"
    );
    owner.0.kill().unwrap();
    owner.0.wait().unwrap();
    assert!(
        Lease::acquire(&root.join("gpu.lock")).is_err(),
        "owned child must retain lock after supervisor death"
    );
    fs::write(root.join("release"), b"exit naturally").unwrap();
    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        if let Ok(lease) = Lease::acquire(&root.join("gpu.lock")) {
            drop(lease);
            break;
        }
        assert!(
            Instant::now() < deadline,
            "kernel did not recover inherited lease after child natural exit"
        );
        thread::sleep(Duration::from_millis(10));
    }
}
