//! Native MFLUX preparation and explicit launch. CPU checks never establish readiness.
use crate::{
    capture,
    guards::GuardConfig,
    maintenance::{self, Authorization, Experiment, Transaction},
    native_guard, preflight,
    schema::{CachePolicy, MediaSettings, Precision, ProcessPolicy, Quantization, Workload},
};
use anyhow::{Context, Result, ensure};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::{
    collections::BTreeMap,
    fs::{self, File, OpenOptions},
    io::{Read, Write},
    os::unix::fs::{MetadataExt, OpenOptionsExt},
    path::{Path, PathBuf},
    process::{Command, Stdio},
    time::{Duration, Instant},
};

const REPORT_LIMIT: usize = 8 * 1024 * 1024;
const CHECK_SANDBOX: &str = "(version 1)(allow default)(deny network*)(deny file-write*)";

pub struct NativeOptions {
    pub python: PathBuf,
    pub source_dir: PathBuf,
    pub model_dir: PathBuf,
    pub source_sha256: String,
    pub workload: PathBuf,
    pub root: PathBuf,
    pub output: PathBuf,
    pub timeout: Duration,
    pub check_timeout: Duration,
    pub max_output_bytes: u64,
    pub guard_config: Option<PathBuf>,
    pub maintenance_transaction: Option<PathBuf>,
    pub authorization: Option<PathBuf>,
    pub execute: bool,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FileIdentity {
    pub(crate) selected_path: PathBuf,
    canonical_path: PathBuf,
    sha256: String,
    bytes: u64,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Plan {
    schema_version: u32,
    kind: String,
    pub(crate) workload: Workload,
    workload_identity: String,
    pub(crate) python: FileIdentity,
    source_directory: PathBuf,
    expected_source_tree_sha256: String,
    model_directory: PathBuf,
    adapter: FileIdentity,
    preflight_helper: FileIdentity,
    pub(crate) output_root: PathBuf,
    pub(crate) timeout_ms: u64,
    pub(crate) max_output_bytes: u64,
    pub(crate) guard_config: Option<GuardConfig>,
    pub(crate) python_arguments: Vec<String>,
    environment: BTreeMap<String, String>,
    sandbox_executable: String,
    sandbox_profile: String,
    dynamic_supervisor_fields: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PreparedPlan {
    pub(crate) sha256: String,
    identity_method: String,
    pub(crate) command: Plan,
}

fn regular_json<T: for<'de> Deserialize<'de>>(path: &Path, limit: u64) -> Result<T> {
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(path)?;
    ensure!(
        file.metadata()?.is_file(),
        "JSON input must be a regular non-symlink file"
    );
    let mut bytes = Vec::new();
    file.take(limit + 1).read_to_end(&mut bytes)?;
    ensure!(
        bytes.len() as u64 <= limit,
        "JSON input exceeds {limit} bytes"
    );
    serde_json::from_slice(&bytes).context("invalid JSON contract")
}

fn file_identity(path: &Path, limit: u64) -> Result<FileIdentity> {
    ensure!(
        path.is_absolute(),
        "explicit absolute file path required: {}",
        path.display()
    );
    let canonical_path = fs::canonicalize(path)?;
    let mut file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(&canonical_path)?;
    let before = file.metadata()?;
    ensure!(
        before.is_file() && before.len() <= limit,
        "identity input is not a bounded regular file"
    );
    let mut hash = Sha256::new();
    let mut bytes = 0_u64;
    let mut buffer = [0_u8; 64 * 1024];
    loop {
        let count = file.read(&mut buffer)?;
        if count == 0 {
            break;
        }
        bytes += count as u64;
        ensure!(bytes <= limit, "identity input grew beyond byte bound");
        hash.update(&buffer[..count]);
    }
    let after = file.metadata()?;
    let current = fs::metadata(path)?;
    ensure!(
        bytes == before.len()
            && after.len() == before.len()
            && after.mtime() == before.mtime()
            && after.mtime_nsec() == before.mtime_nsec()
            && current.dev() == before.dev()
            && current.ino() == before.ino()
            && current.len() == after.len()
            && current.mtime() == after.mtime()
            && current.mtime_nsec() == after.mtime_nsec(),
        "identity input changed while hashing"
    );
    Ok(FileIdentity {
        selected_path: path.to_path_buf(),
        canonical_path,
        sha256: format!("{:x}", hash.finalize()),
        bytes,
    })
}

fn utf8(path: &Path) -> Result<String> {
    Ok(path
        .to_str()
        .context("native command paths must be UTF-8")?
        .to_owned())
}

fn validate_request(workload: &Workload, model: &Path) -> Result<()> {
    workload.validate()?;
    ensure!(
        workload.process_policy == ProcessPolicy::FreshProcess,
        "native runner requires fresh_process"
    );
    ensure!(
        workload.cache_policy == CachePolicy::Unspecified,
        "cold/warm cache state cannot be established; require unspecified"
    );
    ensure!(
        matches!(
            workload.model.name.as_str(),
            "Qwen/Qwen-Image-2.1" | "qwen-image-2.1"
        ),
        "native runner supports Qwen Image 2.1 only"
    );
    ensure!(
        workload.model.sha256.is_none(),
        "requested model payload hash is not supported by pre-load validation"
    );
    if let Some(revision) = &workload.model.revision {
        ensure!(
            model.file_name().and_then(|name| name.to_str()) == Some(revision.as_str()),
            "requested revision differs from local snapshot directory"
        );
    }
    let MediaSettings::Image { generation } = &workload.settings else {
        anyhow::bail!("native Qwen runner supports image requests only");
    };
    ensure!(
        generation.batch_size == 1
            && generation.references.is_empty()
            && generation.strength.is_none(),
        "native runner supports batch-one txt2img without references/strength"
    );
    ensure!(
        generation.scheduler == "linear",
        "native runner supports linear scheduler only"
    );
    ensure!(
        matches!(generation.precision, Precision::Auto | Precision::Bfloat16),
        "native model precision must be BF16"
    );
    ensure!(
        matches!(
            generation.compute_precision,
            None | Some(Precision::Float16)
        ),
        "unsupported native compute_precision"
    );
    ensure!(
        generation.quantization == Quantization::None,
        "initial native runner requires unquantized weights"
    );
    ensure!(
        generation.optimizations.use_kv_cache.is_none()
            && generation.optimizations.step_cache_threshold.is_none(),
        "use_kv_cache/step_cache_threshold are not supported native options"
    );
    if let Some(ratio) = generation.optimizations.step_cache_ratio {
        ensure!(
            ratio > 0.0 && ratio < 1.0,
            "native step_cache_ratio must be null or strictly between 0 and 1"
        );
    }
    ensure!(
        generation.seed <= u32::MAX as u64,
        "native seed must fit uint32"
    );
    ensure!(
        generation.resolution.width.is_multiple_of(16)
            && generation.resolution.height.is_multiple_of(16),
        "native dimensions must be multiples of 16; no rounding is allowed"
    );
    Ok(())
}

fn prepare(options: &NativeOptions) -> Result<PreparedPlan> {
    ensure!(
        options.timeout >= Duration::from_secs(1) && options.timeout <= Duration::from_secs(600),
        "native timeout must be 1..600 seconds"
    );
    ensure!(
        options.check_timeout >= Duration::from_secs(1)
            && options.check_timeout <= Duration::from_secs(120),
        "CPU check timeout must be 1..120 seconds"
    );
    ensure!(
        (1..=1024 * 1024 * 1024).contains(&options.max_output_bytes),
        "native output/log bound must be 1 byte..1 GiB"
    );
    ensure!(
        options.source_sha256.len() == 64
            && options
                .source_sha256
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)),
        "expected source tree SHA-256 must be 64 lowercase hexadecimal digits"
    );
    ensure!(
        options.python.is_absolute()
            && options.source_dir.is_absolute()
            && options.model_dir.is_absolute(),
        "Python/source/model selections must be explicit absolute paths"
    );
    let workload: Workload = regular_json(&options.workload, 1024 * 1024)?;
    validate_request(&workload, &options.model_dir)?;
    ensure!(
        options.model_dir.is_dir(),
        "local model directory is missing; runner never downloads"
    );
    ensure!(
        options.source_dir.is_dir(),
        "selected MFLUX source directory is missing"
    );
    let python = file_identity(&options.python, 64 * 1024 * 1024)?;
    let adapter = file_identity(
        &Path::new(env!("CARGO_MANIFEST_DIR")).join("adapters/mflux_native.py"),
        16 * 1024 * 1024,
    )?;
    let preflight_helper = file_identity(
        &Path::new(env!("CARGO_MANIFEST_DIR")).join("adapters/mflux_preflight.py"),
        16 * 1024 * 1024,
    )?;
    let guard_config = options
        .guard_config
        .as_ref()
        .map(|path| regular_json::<GuardConfig>(path, 64 * 1024))
        .transpose()?;
    if let Some(guard) = &guard_config {
        guard.validate()?;
    }
    let environment = native_guard::OFFLINE_ENVIRONMENT
        .into_iter()
        .map(|(key, value)| (key.to_owned(), value.to_owned()))
        .collect();
    let python_arguments = vec![
        "-I".into(),
        "-S".into(),
        "-B".into(),
        utf8(&adapter.selected_path)?,
        "--python".into(),
        utf8(&options.python)?,
        "--source-dir".into(),
        utf8(&options.source_dir)?,
        "--model-dir".into(),
        utf8(&options.model_dir)?,
        "--source-sha256".into(),
        options.source_sha256.clone(),
        "--timeout-seconds".into(),
        options.timeout.as_secs().to_string(),
        "--max-output-bytes".into(),
        options.max_output_bytes.to_string(),
    ];
    let command = Plan {
        schema_version: 2,
        kind: "native_qwen21_mflux_launch_plan".into(),
        workload_identity: workload.identity()?,
        workload,
        python,
        source_directory: options.source_dir.clone(),
        expected_source_tree_sha256: options.source_sha256.clone(),
        model_directory: options.model_dir.clone(),
        adapter,
        preflight_helper,
        output_root: std::path::absolute(&options.root)?,
        timeout_ms: options.timeout.as_millis() as u64,
        max_output_bytes: options.max_output_bytes,
        guard_config,
        python_arguments,
        environment,
        sandbox_executable: native_guard::SANDBOX_EXECUTABLE.into(),
        sandbox_profile: native_guard::SANDBOX_PROFILE.into(),
        dynamic_supervisor_fields: "Guardian supplies fresh private run paths, workload identity and its own PID. Native root is a session leader; OS sandbox denies fork/network/writes outside run. Close-only lease is retained across exec; no user environment/credentials inherited.".into(),
    };
    let sha256 = format!("{:x}", Sha256::digest(serde_json::to_vec(&command)?));
    Ok(PreparedPlan {
        sha256,
        identity_method: "SHA-256 of compact serde JSON of command in versioned Rust field order. Selected venv and resolved executable, workload, expected source, model, adapter/helper, arguments/environment, root/bounds and resource policy participate. Transaction authorization separately binds this plan, service identities, guardian binary and all phase deadlines.".into(),
        command,
    })
}

impl PreparedPlan {
    pub(crate) fn validate_enrolled(&self) -> Result<()> {
        let command = &self.command;
        ensure!(
            command.schema_version == 2 && command.kind == "native_qwen21_mflux_launch_plan",
            "unsupported native launch plan"
        );
        ensure!(
            self.sha256 == maintenance::digest(command)?,
            "native launch plan identity mismatch"
        );
        validate_request(&command.workload, &command.model_directory)?;
        ensure!(
            command.workload_identity == command.workload.identity()?,
            "native workload identity differs"
        );
        ensure!(
            command.sandbox_executable == native_guard::SANDBOX_EXECUTABLE
                && command.sandbox_profile == native_guard::SANDBOX_PROFILE,
            "native confinement differs"
        );
        ensure!(
            command.timeout_ms > 0
                && command.timeout_ms <= 600_000
                && command.max_output_bytes == 64 * 1024 * 1024,
            "native bounds differ"
        );
        ensure!(
            command.output_root.is_absolute()
                && command.source_directory.is_absolute()
                && command.model_directory.is_absolute(),
            "native paths must be explicit absolute selections"
        );
        ensure!(
            native_guard::valid_hash(&command.expected_source_tree_sha256),
            "native source identity invalid"
        );
        let repository = Path::new(env!("CARGO_MANIFEST_DIR"));
        ensure!(
            command.adapter.selected_path == repository.join("adapters/mflux_native.py")
                && command.preflight_helper.selected_path
                    == repository.join("adapters/mflux_preflight.py"),
            "native adapter/helper selection differs from reviewed implementation"
        );
        let args = &command.python_arguments;
        ensure!(
            args.len() == 16 && args[..3] == ["-I", "-S", "-B"],
            "native Python argument shape differs"
        );
        ensure!(
            args[3] == utf8(&command.adapter.selected_path)?
                && args[4] == "--python"
                && args[5] == utf8(&command.python.selected_path)?
                && args[6] == "--source-dir"
                && args[7] == utf8(&command.source_directory)?
                && args[8] == "--model-dir"
                && args[9] == utf8(&command.model_directory)?
                && args[10] == "--source-sha256"
                && args[11] == command.expected_source_tree_sha256
                && args[12] == "--timeout-seconds"
                && args[13].parse::<u64>()?.checked_mul(1000) == Some(command.timeout_ms)
                && args[14] == "--max-output-bytes"
                && args[15].parse::<u64>()? == command.max_output_bytes,
            "native argv does not match declared workload/runtime/bounds"
        );
        ensure!(
            command.environment.len() == native_guard::OFFLINE_ENVIRONMENT.len()
                && native_guard::OFFLINE_ENVIRONMENT
                    .iter()
                    .all(|(key, value)| command
                        .environment
                        .get(*key)
                        .is_some_and(|actual| actual == value)),
            "native environment differs from fixed offline policy"
        );
        let resources = command
            .guard_config
            .as_ref()
            .context("native resource policy absent")?;
        resources.validate()?;
        ensure!(
            resources.min_disk_free_bytes >= 10 * 1024 * 1024 * 1024
                && resources.max_disk_growth_bytes <= 256 * 1024 * 1024,
            "native disk policy weakened"
        );
        Ok(())
    }
    pub(crate) fn verify_files(&self) -> Result<()> {
        self.validate_enrolled()?;
        for expected in [
            &self.command.python,
            &self.command.adapter,
            &self.command.preflight_helper,
        ] {
            let actual = file_identity(&expected.selected_path, 64 * 1024 * 1024)?;
            ensure!(
                actual.canonical_path == expected.canonical_path
                    && actual.sha256 == expected.sha256
                    && actual.bytes == expected.bytes,
                "approved native file identity changed"
            );
        }
        Ok(())
    }
}

fn check(options: &NativeOptions, plan: &PreparedPlan, diagnostics: &mut Vec<u8>) -> Result<Value> {
    ensure!(
        cfg!(target_os = "macos"),
        "read-only native preparation requires the macOS sandbox"
    );
    let mut command = Command::new(native_guard::SANDBOX_EXECUTABLE);
    command
        .args(["-p", CHECK_SANDBOX])
        .arg(&plan.command.python.selected_path)
        .args(&plan.command.python_arguments)
        .arg("--check-only")
        .arg("--workload")
        .arg(fs::canonicalize(&options.workload)?)
        .env_clear()
        .envs(&plan.command.environment)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let report = preflight::execute_check(
        command,
        options.check_timeout,
        diagnostics,
        "cpu_native_adapter_check",
    )?;
    if report["ok"] == true {
        let checked: Workload = serde_json::from_value(report["requested"].clone())
            .context("check omitted requested workload")?;
        ensure!(
            checked.identity()? == plan.command.workload_identity,
            "workload changed between preparation and adapter check"
        );
        ensure!(
            report["environment"]["executable_identity"]["sha256"] == plan.command.python.sha256,
            "observed Python identity differs from prepared command"
        );
    }
    Ok(report)
}

struct ReportWriter {
    file: File,
    remaining: usize,
}
impl Write for ReportWriter {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        if bytes.len() > self.remaining {
            return Err(std::io::Error::other(
                "native preparation report exceeds 8 MiB",
            ));
        }
        let n = self.file.write(bytes)?;
        self.remaining -= n;
        Ok(n)
    }
    fn flush(&mut self) -> std::io::Result<()> {
        self.file.flush()
    }
}

#[derive(Clone, Copy)]
enum AttemptStage {
    Preparation,
    Controller,
    Evidence,
}

fn report_outcome(report: &mut Value, stage: AttemptStage, outcome: Result<bool>) -> bool {
    match outcome {
        Ok(passed) => passed,
        Err(error) => {
            let (status, stage) = match stage {
                AttemptStage::Preparation => ("preparation_failed", "preparation"),
                AttemptStage::Controller => ("execution_failed", "controller"),
                AttemptStage::Evidence => ("evidence_failed", "receipt_or_capture"),
            };
            report["status"] = json!(status);
            report["errors"] = json!([{"stage":stage, "message":format!("{error:#}")}]);
            // Errors cannot revoke already validated evidence, nor establish
            // non-execution after entering the controller.
            false
        }
    }
}

fn controller_report(
    report: &mut Value,
    stage: &mut AttemptStage,
    expected_receipt: &Path,
    controller: impl FnOnce() -> Result<PathBuf>,
) -> Result<bool> {
    *stage = AttemptStage::Controller;
    report["native_execution"] = Value::Null;
    report["maintenance_receipt"] = json!(expected_receipt);
    report["authorization_decision"] = json!({"allowed":true,"reasons":[]});
    let receipt_path = controller()?;
    *stage = AttemptStage::Evidence;
    report["maintenance_receipt"] = json!(receipt_path);
    let receipt: Value = maintenance::read_private(&receipt_path)?;
    report["capture_directory"] = receipt["capture_directory"].clone();
    if let Some(directory) = receipt["capture_directory"].as_str() {
        let record = capture::inspect(Path::new(directory))?;
        report["process_exit_observed"] = json!(record.exit.is_some());
        if record.is_success() {
            report["native_execution"] = json!(true);
        }
        report["status"] = json!(record.state);
    } else {
        ensure!(
            receipt["capture_directory"].is_null(),
            "receipt capture_directory must be a path or null"
        );
        // Missing, malformed, or true creation evidence cannot prove that
        // nothing ran. Only the retained receipt's exact boolean false can.
        let not_attempted = receipt["creation_attempted"].as_bool() == Some(false);
        if not_attempted {
            report["native_execution"] = json!(false);
        }
        report["status"] = json!(if not_attempted {
            "maintenance_failed_before_capture"
        } else {
            "maintenance_execution_unknown"
        });
    }
    Ok(receipt["success"] == true && report["native_execution"] == true)
}

/// A preparation check is not execution. Unapproved transactions deny before
/// Python, service observation/control, lease acquisition or capture creation.
pub fn run(options: NativeOptions) -> Result<bool> {
    let file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&options.output)
        .context("creating non-overwriting native attempt report")?;
    let started = Instant::now();
    let mut diagnostics = Vec::new();
    let mut report = json!({
        "schema_version":2, "kind":"native_mflux_attempt", "mode":if options.execute {"execute"} else {"check_only"},
        "ok":false, "status":"not_launched", "native_execution":false, "prepared_plan":null,
        "check":null, "authorization_decision":{"allowed":false,"reasons":["exact transaction authorization not established"]}, "capture_directory":null, "maintenance_receipt":null, "errors":[],
        "limitations":[
            "CPU validation is not native import, ABI, model allocation, inference or benchmark proof.",
            "Named scope is enrolled Studio/oMLX plus guardian-owned experiment, not aggregate live queue or whole-host GPU authority.",
            "Only exact transaction authorization plus actual service/resource observations permit creation; persisted readings and references cannot grant authority.",
            "The existing venv is invoked by its selected path; resolved base interpreter identity is recorded separately, never substituted.",
            "No automatic retries, installs, network/model downloads, weight copies, live changes or uploads. Partial failures are retained. Filesystem syscalls have no forced deadline."
        ]
    });
    let mut stage = AttemptStage::Preparation;
    let outcome = (|| -> Result<bool> {
        // This validation is deliberately before preparation: even Python file
        // identity/guard-config reads cannot accidentally trigger the denied path.
        let approved = if options.execute {
            let transaction: Transaction = maintenance::read_private(
                options
                    .maintenance_transaction
                    .as_deref()
                    .context("native activation denied: maintenance transaction absent")?,
            )?;
            let authorization: Authorization = maintenance::read_private(
                options
                    .authorization
                    .as_deref()
                    .context("native activation denied: exact authorization absent")?,
            )?;
            maintenance::validate_authorization(&transaction, &authorization)?;
            Some((transaction, authorization))
        } else {
            None
        };
        let plan = prepare(&options)?;
        report["prepared_plan"] = serde_json::to_value(&plan)?;
        if let Some((transaction, authorization)) = approved {
            match &transaction.experiment {
                Experiment::Native { plan: enrolled } => ensure!(
                    enrolled.sha256 == plan.sha256
                        && serde_json::to_value(enrolled)? == serde_json::to_value(&plan)?,
                    "approved native plan differs from exact CLI preparation"
                ),
                _ => anyhow::bail!("CPU authorization cannot execute a native workload"),
            }
            let expected_receipt = transaction.evidence_root.join("receipt.json");
            controller_report(&mut report, &mut stage, &expected_receipt, || {
                maintenance::run_controller(transaction, authorization)
            })
        } else {
            let checked = check(&options, &plan, &mut diagnostics)?;
            let passed = checked["ok"] == true;
            report["check"] = checked;
            report["status"] = json!(if passed {
                "checked_not_executed"
            } else {
                "validation_failed"
            });
            Ok(passed)
        }
    })();
    let passed = report_outcome(&mut report, stage, outcome);
    report["ok"] = json!(passed);
    report["diagnostics"] = json!(String::from_utf8_lossy(&diagnostics));
    report["elapsed_ms"] = json!(started.elapsed().as_millis().min(u64::MAX as u128) as u64);
    let mut writer = ReportWriter {
        file,
        remaining: REPORT_LIMIT,
    };
    serde_json::to_writer_pretty(&mut writer, &report)?;
    writer.write_all(b"\n")?;
    writer.flush()?;
    writer.file.sync_all()?;
    Ok(passed)
}

#[cfg(test)]
mod tests {
    use super::*;

    // Reuse persisted CPU evidence solely to exercise report classification.
    // These fixtures are neither native inference nor authorization proof.
    mod capture_fixture {
        use crate as media_inference_lab;
        include!("../tests/support/capture_fixture.rs");
    }

    fn reported(path: &Path, controller: impl FnOnce() -> Result<PathBuf>) -> Value {
        let mut report = json!({"native_execution":false, "errors":[]});
        let mut stage = AttemptStage::Preparation;
        let outcome = controller_report(&mut report, &mut stage, path, controller);
        let passed = report_outcome(&mut report, stage, outcome);
        report["ok"] = json!(passed);
        report
    }

    fn receipt(path: &Path, value: &Value) {
        let file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(path)
            .unwrap();
        serde_json::to_writer(file, value).unwrap();
    }

    fn capture_record() -> Value {
        let workload: Workload =
            serde_json::from_str(include_str!("../examples/image-workload.json")).unwrap();
        capture_fixture::record(&workload, 0, 1.0)
    }

    #[test]
    fn controller_error_keeps_execution_unknown_and_receipt_path() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("receipt.json");
        let report = reported(&path, || anyhow::bail!("controller failed after entry"));
        assert_eq!(report["native_execution"], Value::Null);
        assert_eq!(report["status"], "execution_failed");
        assert_eq!(report["errors"][0]["stage"], "controller");
        assert_eq!(report["maintenance_receipt"], json!(path));
        assert_eq!(report["ok"], false);
    }

    #[test]
    fn unreadable_and_malformed_receipts_keep_execution_unknown() {
        let directory = tempfile::tempdir().unwrap();
        let missing = directory.path().join("missing.json");
        let malformed = directory.path().join("malformed.json");
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&malformed)
            .unwrap();
        file.write_all(b"{").unwrap();
        for path in [missing, malformed] {
            let report = reported(&path, || Ok(path.clone()));
            assert_eq!(report["native_execution"], Value::Null);
            assert_eq!(report["status"], "evidence_failed");
            assert_eq!(report["errors"][0]["stage"], "receipt_or_capture");
            assert_eq!(report["maintenance_receipt"], json!(path));
            assert_eq!(report["ok"], false);
        }
    }

    #[test]
    fn no_capture_requires_exact_false_creation_evidence() {
        for creation in [
            None,
            Some(Value::Null),
            Some(json!("false")),
            Some(json!(0)),
            Some(json!(true)),
            Some(json!(false)),
        ] {
            let directory = tempfile::tempdir().unwrap();
            let path = directory.path().join("receipt.json");
            // Even a claimed success cannot replace validated capture evidence.
            let mut value = json!({"capture_directory":null, "success":true});
            if let Some(creation) = &creation {
                value["creation_attempted"] = creation.clone();
            }
            receipt(&path, &value);
            let report = reported(&path, || Ok(path.clone()));
            let not_attempted = creation == Some(json!(false));
            assert_eq!(
                report["native_execution"],
                if not_attempted { json!(false) } else { Value::Null },
                "{value}"
            );
            assert_eq!(
                report["status"],
                if not_attempted {
                    "maintenance_failed_before_capture"
                } else {
                    "maintenance_execution_unknown"
                }
            );
            assert_eq!(report["ok"], false);
        }
    }

    #[test]
    fn capture_read_errors_do_not_turn_false_creation_into_nonexecution() {
        let directory = tempfile::tempdir().unwrap();
        for (index, capture) in [json!(directory.path().join("missing-capture")), json!(42)]
            .into_iter()
            .enumerate()
        {
            let path = directory.path().join(format!("receipt-{index}.json"));
            receipt(&path, &json!({
                "creation_attempted":false, "capture_directory":capture, "success":false
            }));
            let report = reported(&path, || Ok(path.clone()));
            assert_eq!(report["native_execution"], Value::Null);
            assert_eq!(report["status"], "evidence_failed");
            assert_eq!(report["capture_directory"], capture);
            assert_eq!(report["ok"], false);
        }
    }

    #[test]
    fn retained_failed_capture_keeps_execution_unknown() {
        let directory = tempfile::tempdir().unwrap();
        let capture = fs::canonicalize(directory.path()).unwrap().join("cpu-report-fixture");
        let mut record = capture_record();
        record["state"] = json!("failed");
        record["failure"] = json!("CPU report fixture failure");
        record["adapter_result"] = Value::Null;
        capture_fixture::persist(&capture, &record);
        let path = directory.path().join("receipt.json");
        receipt(&path, &json!({
            "creation_attempted":true, "capture_directory":capture, "success":false
        }));
        let report = reported(&path, || Ok(path.clone()));
        assert_eq!(report["native_execution"], Value::Null);
        assert_eq!(report["status"], "failed");
        assert_eq!(report["process_exit_observed"], true);
        assert_eq!(report["ok"], false);
    }

    #[test]
    fn completed_capture_requires_validation_and_survives_later_report_error() {
        let directory = tempfile::tempdir().unwrap();
        let capture = fs::canonicalize(directory.path()).unwrap().join("cpu-report-fixture");
        capture_fixture::persist(&capture, &capture_record());
        let path = directory.path().join("receipt.json");
        receipt(&path, &json!({
            "creation_attempted":true, "capture_directory":capture, "success":true
        }));
        let mut report = reported(&path, || Ok(path.clone()));
        assert_eq!(report["native_execution"], true);
        assert_eq!(report["status"], "completed");
        assert_eq!(report["ok"], true);
        assert!(!report_outcome(
            &mut report,
            AttemptStage::Evidence,
            Err(anyhow::anyhow!("later unrelated report failure"))
        ));
        assert_eq!(report["native_execution"], true);
        assert_eq!(report["status"], "evidence_failed");

        // A completed manifest alone is not successful evidence: inspection
        // must also validate the retained artifact against the result.
        fs::write(capture.join("artifacts/schema-output.txt"), b"tampered").unwrap();
        let report = reported(&path, || Ok(path.clone()));
        assert_eq!(report["native_execution"], Value::Null);
        assert_eq!(report["status"], "evidence_failed");
        assert_eq!(report["ok"], false);
    }
}
