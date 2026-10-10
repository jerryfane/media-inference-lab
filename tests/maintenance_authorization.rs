#![cfg(target_os = "macos")]
use media_inference_lab::{
    maintenance::{self, Authorization, Budgets, Experiment, Transaction},
    native_guard::{self, ScopePurpose},
    process_scope::CommandSpec,
    service_lifecycle::{AbsenceBinding, ServiceRole, ServiceSpec, UnmanagedAcknowledgement},
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

#[test]
fn absence_mode_requires_exact_grant_and_cannot_cross_purposes() {
    let temporary = tempfile::tempdir().unwrap();
    let root = fs::canonicalize(temporary.path()).unwrap();
    let (mut transaction, authorization) = fixture(&root);
    let Experiment::Cpu { command } = &transaction.experiment else { unreachable!() };
    let mut probe = command.clone();
    probe.args = ["maintenance-participant", "--mode", "absence-probe", "--duration-ms", "1"]
        .map(String::from).to_vec();
    transaction.services[1] = ServiceSpec::OmlxAbsent {
        binding: AbsenceBinding::Cpu { probe, executable_root: root.join("absence-bin") },
    };
    transaction.validate().unwrap();
    assert!(maintenance::run_controller(transaction.clone(), authorization.clone()).is_err());
    assert!(!transaction.evidence_root.exists());
    let absent = &transaction.services[1];
    assert!(absent.validate(ScopePurpose::Native).is_err());
    let native = ServiceSpec::OmlxAbsent { binding: AbsenceBinding::Native };
    assert!(native.validate(ScopePurpose::Cpu).is_err());
    native.validate(ScopePurpose::Native).unwrap();
    transaction.services[1] = native;
    assert!(transaction.validate().is_err());
    assert!(!transaction.lease_path.exists());
}

#[test]
fn absent_validation_never_opens_fixture_paths() {
    let temporary = tempfile::tempdir().unwrap();
    let root = fs::canonicalize(temporary.path()).unwrap();
    let (mut transaction, _) = fixture(&root);
    let Experiment::Cpu { command } = &transaction.experiment else { unreachable!() };
    let mut probe = command.clone();
    probe.executable = root.join("does-not-exist");
    probe.cwd = root.join("missing-directory");
    probe.args = ["maintenance-participant", "--mode", "absence-probe", "--duration-ms", "1"]
        .map(String::from).to_vec();
    transaction.services[1] = ServiceSpec::OmlxAbsent {
        binding: AbsenceBinding::Cpu { executable_root: probe.cwd.join("absence-bin"), probe },
    };
    transaction.validate().unwrap();
    assert!(!root.join("missing-directory").exists());
}

fn unmanaged(purpose: ScopePurpose) -> ServiceSpec {
    ServiceSpec::OmlxUnmanaged {
        purpose,
        acknowledgement: UnmanagedAcknowledgement::AcceptUnverifiedOmlx,
    }
}

#[test]
fn unmanaged_policy_requires_explicit_well_formed_acknowledgement_and_purpose() {
    let temporary = tempfile::tempdir().unwrap();
    let root = fs::canonicalize(temporary.path()).unwrap();
    let (mut transaction, _) = fixture(&root);
    transaction.services[1] = unmanaged(ScopePurpose::Cpu);
    let bound = serde_json::to_value(&transaction).unwrap();
    let decoded: Transaction = serde_json::from_value(bound.clone()).unwrap();
    decoded.validate().unwrap();
    for field in ["acknowledgement", "purpose"] {
        let mut omitted = bound.clone();
        omitted["services"][1].as_object_mut().unwrap().remove(field);
        assert!(serde_json::from_value::<Transaction>(omitted).is_err());
    }
    for malformed in [
        serde_json::Value::Null,
        serde_json::json!(true),
        serde_json::json!(""),
        serde_json::json!("accept_unverified"),
        serde_json::json!("absent"),
        serde_json::json!({"accept_unverified_omlx": true}),
    ] {
        let mut value = bound.clone();
        value["services"][1]["acknowledgement"] = malformed;
        assert!(serde_json::from_value::<Transaction>(value).is_err());
    }
    for purpose in [serde_json::Value::Null, serde_json::json!("unknown"), serde_json::json!(true)] {
        let mut value = bound.clone();
        value["services"][1]["purpose"] = purpose;
        assert!(serde_json::from_value::<Transaction>(value).is_err());
    }
    let mut missing_kind = bound;
    missing_kind["services"][1].as_object_mut().unwrap().remove("kind");
    assert!(serde_json::from_value::<Transaction>(missing_kind).is_err());
    assert!(!transaction.evidence_root.exists() && !transaction.lease_path.exists());
}

#[test]
fn unmanaged_policy_mutation_requires_new_exact_authorization_before_effects() {
    let temporary = tempfile::tempdir().unwrap();
    let root = fs::canonicalize(temporary.path()).unwrap();
    let (mut transaction, original_authorization) = fixture(&root);
    let original_service = transaction.services[1].clone();
    transaction.services[1] = unmanaged(ScopePurpose::Cpu);
    transaction.validate().unwrap();
    assert!(maintenance::run_controller(transaction.clone(), original_authorization.clone()).is_err());
    let authorization = Authorization {
        transaction_sha256: maintenance::digest(&transaction).unwrap(),
        ..original_authorization
    };
    maintenance::validate_authorization(&transaction, &authorization).unwrap();
    transaction.services[1] = original_service;
    assert!(maintenance::run_controller(transaction.clone(), authorization).is_err());
    assert!(!transaction.evidence_root.exists() && !transaction.lease_path.exists());
}

#[test]
fn unmanaged_cpu_policy_and_grant_cannot_authorize_native_purpose() {
    let temporary = tempfile::tempdir().unwrap();
    let root = fs::canonicalize(temporary.path()).unwrap();
    let (mut transaction, mut authorization) = fixture(&root);
    transaction.services[1] = unmanaged(ScopePurpose::Cpu);
    authorization.transaction_sha256 = maintenance::digest(&transaction).unwrap();
    maintenance::validate_authorization(&transaction, &authorization).unwrap();
    assert!(transaction.services[1].validate(ScopePurpose::Native).is_err());
    let native = unmanaged(ScopePurpose::Native);
    native.validate(ScopePurpose::Native).unwrap();
    assert!(native.validate(ScopePurpose::Cpu).is_err());
    transaction.services[1] = native;
    authorization.transaction_sha256 = maintenance::digest(&transaction).unwrap();
    assert!(maintenance::run_controller(transaction.clone(), authorization.clone()).is_err());
    transaction.services[1] = unmanaged(ScopePurpose::Cpu);
    authorization.transaction_sha256 = maintenance::digest(&transaction).unwrap();
    authorization.purpose = ScopePurpose::Native;
    assert!(maintenance::run_controller(transaction.clone(), authorization.clone()).is_err());
    transaction.purpose = ScopePurpose::Native;
    authorization.transaction_sha256 = maintenance::digest(&transaction).unwrap();
    assert!(maintenance::run_controller(transaction.clone(), authorization).is_err());
    assert!(!transaction.evidence_root.exists() && !transaction.lease_path.exists());
}

#[test]
fn unmanaged_policy_rejects_private_permissions_even_with_exact_grant() {
    use media_inference_lab::{
        process_scope::{ProcessIdentity, ProcessState},
        qualification_scope::ReviewedLaunchScope,
        restore_qualification::ReviewedPermissionInput,
    };
    let temporary = tempfile::tempdir().unwrap();
    let root = fs::canonicalize(temporary.path()).unwrap();
    let (mut transaction, mut authorization) = fixture(&root);
    transaction.services[1] = unmanaged(ScopePurpose::Cpu);
    authorization.transaction_sha256 = maintenance::digest(&transaction).unwrap();
    maintenance::validate_authorization(&transaction, &authorization).unwrap();
    transaction.reviewed_permissions = Some(ReviewedPermissionInput {
        review_reference: "synthetic-private-review".into(),
        plan_sha256: "0".repeat(64),
        old_identity: ProcessIdentity {
            pid: 200, ppid: 1, pgid: 200, sid: 200, uid: unsafe { libc::geteuid() },
            start_seconds: 1, start_subseconds: 2,
            executable: root.join("not-opened"), cwd: root.clone(), state: ProcessState::Running,
        },
        x2_launcher_private_comparison: true,
        existing_log_observation_review_reference: "synthetic-log-review".into(),
        x3: None,
        launch_scope: ReviewedLaunchScope {
            review_reference: "synthetic-scope".into(),
            source_review_reference: "synthetic-source".into(),
            allow_metadata_name_observation: true,
            restore_home: root.clone(), runtime_directory: root.join("not-opened"),
            manifest_prefix: "launch-".into(), manifest_suffix: ".json".into(), max_entries: 4096,
        },
        residuals_review_reference: "synthetic-residuals".into(),
    });
    authorization.transaction_sha256 = maintenance::digest(&transaction).unwrap();
    assert!(maintenance::run_controller(transaction.clone(), authorization).is_err());
    assert!(!root.join("not-opened").exists());
    assert!(!transaction.evidence_root.exists() && !transaction.lease_path.exists());
}
