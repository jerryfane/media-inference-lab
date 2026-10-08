//! Native MFLUX preparation and explicit launch. CPU checks never establish readiness.
use crate::{
    capture::{self, CaptureOptions},
    guards::{GuardConfig, Lease},
    native_guard::{self, NativeGuardConfig},
    preflight,
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
    sync::{Arc, atomic::AtomicBool},
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
    pub manager_grant_reference: Option<String>,
    pub execute: bool,
}

#[derive(Serialize)]
struct FileIdentity {
    selected_path: PathBuf,
    canonical_path: PathBuf,
    sha256: String,
    bytes: u64,
}

#[derive(Serialize)]
struct Plan {
    schema_version: u32,
    kind: &'static str,
    workload: Workload,
    workload_identity: String,
    python: FileIdentity,
    source_directory: PathBuf,
    expected_source_tree_sha256: String,
    model_directory: PathBuf,
    adapter: FileIdentity,
    preflight_helper: FileIdentity,
    output_root: PathBuf,
    timeout_ms: u64,
    max_output_bytes: u64,
    guard_config: Option<GuardConfig>,
    python_arguments: Vec<String>,
    environment: BTreeMap<String, String>,
    sandbox_executable: &'static str,
    sandbox_profile: &'static str,
    dynamic_supervisor_fields: &'static str,
}

#[derive(Serialize)]
struct PreparedPlan {
    sha256: String,
    identity_method: &'static str,
    command: Plan,
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
        schema_version: 1,
        kind: "native_qwen21_mflux_launch_plan",
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
        sandbox_executable: native_guard::SANDBOX_EXECUTABLE,
        sandbox_profile: native_guard::SANDBOX_PROFILE,
        dynamic_supervisor_fields: "Fresh private run directory, requested/result paths, workload identity, native guarded marker and supervisor PID are supplied internally. HOME/TMPDIR/HF_HOME/XDG_CACHE_HOME point into that run. Capture uses one new process group and the persistent close-only project lease. No user environment or credential inheritance.",
    };
    let sha256 = format!("{:x}", Sha256::digest(serde_json::to_vec(&command)?));
    Ok(PreparedPlan {
        sha256,
        identity_method: "SHA-256 of compact serde JSON of command in this versioned Rust field order; all typed workload/settings, selected venv invocation and observed executable hash, expected source identity, model path, adapter/helper hashes, arguments/environment, output root/bounds and resource guard config participate. Dynamic run paths, observation times, report destination and external grant reference are excluded. Source/payload/import identity is not established by this plan.",
        command,
    })
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

/// Every returned report is preparation/denial evidence, not proof of native import.
/// Production native readiness is unavailable; external coordination must be separately implemented.
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
        "schema_version":1, "kind":"native_mflux_attempt", "mode":if options.execute {"execute"} else {"check_only"},
        "ok":false, "status":"not_launched", "native_execution":false, "prepared_plan":null,
        "manager_grant_reference":options.manager_grant_reference,
        "check":null, "readiness":null, "decision":null, "capture_directory":null, "errors":[],
        "limitations":[
            "CPU validation is not native import, ABI, model allocation, inference or benchmark proof.",
            "Authoritative aggregate live queue and unrelated-GPU readiness integrations are currently absent. Worker absence, health, per-ID lookup, files/logs and historical observations cannot substitute.",
            "A recorded manager reference is not authentication, a readiness observation, a reservation or an override. A fresh explicit exact-command grant remains required after readiness integration is separately authorized.",
            "The existing venv is invoked by its selected path; resolved base interpreter identity is recorded separately, never substituted.",
            "No automatic retries, installs, network/model downloads, weight copies, live changes or uploads. Partial failures are retained. Filesystem syscalls have no forced deadline."
        ]
    });
    let outcome = (|| -> Result<bool> {
        let plan = prepare(&options)?;
        let gate = NativeGuardConfig {
            invocation_sha256: plan.sha256.clone(),
            manager_grant_reference: options.manager_grant_reference.clone(),
        };
        gate.validate()?;
        let readiness = native_guard::readiness();
        let decision = native_guard::evaluate(&gate, &readiness);
        report["readiness"] = serde_json::to_value(&readiness)?;
        report["decision"] = serde_json::to_value(&decision)?;
        report["prepared_plan"] = serde_json::to_value(&plan)?;
        if options.execute && !decision.allowed {
            report["errors"] =
                json!([{"stage":"native_readiness", "message":decision.reasons.join("; ")}]);
            // No guard-check, shared lease, Python subprocess or native import on this path.
            return Ok(false);
        }
        let checked = check(&options, &plan, &mut diagnostics)?;
        let passed = checked["ok"] == true;
        report["check"] = checked;
        if !passed {
            report["status"] = json!("validation_failed");
            return Ok(false);
        }
        if !options.execute {
            report["status"] = json!("checked_not_executed");
            return Ok(true);
        }
        let guard = plan
            .command
            .guard_config
            .context("native execution requires explicit resource guard configuration")?;
        let home = PathBuf::from(
            std::env::var_os("HOME").context("HOME is required for the project lease")?,
        );
        ensure!(home.is_absolute(), "HOME must be absolute");
        let lease_root = home.join(".local/share/media-inference-lab");
        // Native readiness must be genuinely implemented before this branch can be reached.
        // Do not create a new reservation or a readiness substitute here.
        let lease = Lease::acquire(&lease_root.join("gpu.lock"))?;
        let cancelled = Arc::new(AtomicBool::new(false));
        let mut signals = Vec::new();
        for signal in [signal_hook::consts::SIGINT, signal_hook::consts::SIGTERM] {
            signals.push(signal_hook::flag::register(signal, Arc::clone(&cancelled))?);
        }
        let result = capture::capture_native_guarded(
            plan.command.workload,
            CaptureOptions {
                root: plan.command.output_root,
                executable: plan.command.python.selected_path,
                args: plan.command.python_arguments,
                env: BTreeMap::new(),
                timeout: options.timeout,
                max_output_bytes: options.max_output_bytes,
            },
            cancelled,
            guard,
            lease,
            gate,
        );
        for signal in signals {
            signal_hook::low_level::unregister(signal);
        }
        let directory = result?;
        let record = capture::inspect(&directory)?;
        report["capture_directory"] = json!(directory);
        report["process_exit_observed"] = json!(record.exit.is_some());
        // A failing child can have imported/allocated/generated before failure.
        // An exit status alone never establishes whether native execution occurred.
        report["native_execution"] = if record.is_success() {
            json!(true)
        } else {
            Value::Null
        };
        report["status"] = json!(record.state);
        Ok(record.is_success())
    })();
    let passed = match outcome {
        Ok(passed) => passed,
        Err(error) => {
            report["status"] = json!("preparation_failed");
            report["errors"] =
                json!([{"stage":"preparation_or_launch", "message":format!("{error:#}")}]);
            false
        }
    };
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
