#![cfg(target_os = "macos")]
use media_inference_lab::{
    maintenance::{self, Authorization, Budgets, Experiment, Transaction},
    native_guard::{self, ScopePurpose},
    process_scope::CommandSpec,
    service_lifecycle::{ServiceRole, ServiceSpec},
};
use std::{collections::BTreeMap, fs};

fn fixture(root: &std::path::Path) -> (Transaction, Authorization) {
    let executable = std::env::current_exe().unwrap();
    let command = CommandSpec {
        executable: executable.clone(),
        args: vec![
            "maintenance-participant".into(),
            "--mode".into(),
            "service".into(),
            "--duration-ms".into(),
            "1000".into(),
        ],
        cwd: root.to_owned(),
        environment: BTreeMap::new(),
    };
    let transaction = Transaction {
        schema_version: 1,
        transaction_id: "authorization-boundary".into(),
        purpose: ScopePurpose::Cpu,
        evidence_root: root.join("scope"),
        lease_path: root.join(".cpu-maintenance.lock"),
        guardian_sha256: maintenance::executable_digest(&executable).unwrap(),
        budgets: Budgets {
            arming_ms: 1000,
            studio_stop_ms: 1000,
            omlx_stop_ms: 1000,
            prelaunch_ms: 1000,
            experiment_ms: 1000,
            cleanup_ms: 1000,
            omlx_restore_ms: 1000,
            studio_restore_ms: 1000,
            recovery_ms: 1000,
            total_ms: 10_000,
        },
        services: vec![
            ServiceSpec::OwnedCpu {
                role: ServiceRole::Studio,
                command: command.clone(),
                restore_command: command.clone(),
                gui_command: None,
            },
            ServiceSpec::OwnedCpu {
                role: ServiceRole::Omlx,
                command: command.clone(),
                restore_command: command.clone(),
                gui_command: Some(command.clone()),
            },
        ],
        experiment: Experiment::Cpu { command },
        reviewed_permissions: None,
    };
    let now = native_guard::unix_ms().unwrap();
    let authorization = Authorization {
        schema_version: 1,
        transaction_sha256: maintenance::digest(&transaction).unwrap(),
        purpose: ScopePurpose::Cpu,
        owner_uid: unsafe { libc::geteuid() },
        not_before_unix_ms: now,
        expires_unix_ms: now + 60_000,
        review_reference: "unit: exact private CPU authorization".into(),
        service_interruption_approved: true,
        cold_restore_approved: true,
        interrupted_work_loss_approved: true,
    };
    (transaction, authorization)
}
#[test]
fn changed_work_or_permission_cannot_create_guardian_evidence_or_lease() {
    let temporary = tempfile::tempdir().unwrap();
    let root = fs::canonicalize(temporary.path()).unwrap();
    let (transaction, authorization) = fixture(&root);
    maintenance::validate_authorization(&transaction, &authorization).unwrap();
    let mut changed = transaction.clone();
    if let Experiment::Cpu { command } = &mut changed.experiment {
        command.args[4] = "2000".into();
    }
    assert!(maintenance::run_controller(changed, authorization.clone()).is_err());
    for denied in [
        Authorization {
            purpose: ScopePurpose::Native,
            ..authorization.clone()
        },
        Authorization {
            expires_unix_ms: authorization.not_before_unix_ms,
            ..authorization.clone()
        },
        Authorization {
            cold_restore_approved: false,
            ..authorization.clone()
        },
        Authorization {
            transaction_sha256: "0".repeat(64),
            ..authorization.clone()
        },
    ] {
        assert!(maintenance::run_controller(transaction.clone(), denied).is_err());
    }
    assert!(!transaction.evidence_root.exists());
    assert!(!transaction.lease_path.exists());
}
#[test]
fn cpu_scope_cannot_select_shared_gpu_lease_or_borrow_phase_time() {
    let temporary = tempfile::tempdir().unwrap();
    let root = fs::canonicalize(temporary.path()).unwrap();
    let (mut transaction, _) = fixture(&root);
    transaction.lease_path = root.join("gpu.lock");
    assert!(transaction.validate().is_err());
    transaction.lease_path = root.join(".cpu-maintenance.lock");
    transaction.budgets.cleanup_ms = 30_001;
    assert!(transaction.validate().is_err());
    transaction.budgets.cleanup_ms = 1000;
    transaction.budgets.total_ms = 8999;
    assert!(transaction.validate().is_err());
    assert!(!transaction.evidence_root.exists() && !transaction.lease_path.exists());
}
