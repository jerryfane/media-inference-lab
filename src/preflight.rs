//! CPU-only, read-only MFLUX metadata inspection; never an inference launch.
use crate::capture::unix::OwnedChild;
use anyhow::{Context, Result, bail, ensure};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::fs::{self, OpenOptions};
use std::io::{Read, Write};
use std::os::fd::AsRawFd;
use std::os::unix::fs::OpenOptionsExt;
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

const OUTPUT_LIMIT: usize = 4 * 1024 * 1024;
const DIAGNOSTIC_LIMIT: usize = 64 * 1024;
const WORKLOAD_LIMIT: u64 = 1024 * 1024;

pub struct PreflightOptions {
    pub python: PathBuf,
    pub model_dir: PathBuf,
    pub workload: PathBuf,
    pub output: PathBuf,
    pub timeout: Duration,
}

fn nonblocking(pipe: &impl AsRawFd) -> Result<()> {
    let fd = pipe.as_raw_fd();
    let flags = unsafe { libc::fcntl(fd, libc::F_GETFL) };
    ensure!(flags >= 0, "reading adapter pipe flags failed");
    ensure!(
        unsafe { libc::fcntl(fd, libc::F_SETFL, flags | libc::O_NONBLOCK) } >= 0,
        "setting nonblocking adapter pipe failed"
    );
    Ok(())
}

fn drain(pipe: &mut impl Read, bytes: &mut Vec<u8>, limit: usize) -> Result<bool> {
    let mut buffer = [0; 8192];
    loop {
        match pipe.read(&mut buffer) {
            Ok(0) => return Ok(true),
            Ok(count) => {
                ensure!(
                    count <= limit.saturating_sub(bytes.len()),
                    "adapter output exceeded {limit} byte bound"
                );
                bytes.extend_from_slice(&buffer[..count]);
            }
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => return Ok(false),
            Err(error) if error.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(error) => return Err(error.into()),
        }
    }
}

fn execute(options: &PreflightOptions, script: &Path, diagnostics: &mut Vec<u8>) -> Result<Value> {
    ensure!(
        options.timeout >= Duration::from_secs(1) && options.timeout <= Duration::from_secs(120),
        "preflight timeout must be between 1 and 120 seconds"
    );
    ensure!(
        options.python.is_absolute(),
        "select an absolute virtual-environment Python path"
    );
    let workload = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NONBLOCK)
        .open(&options.workload)
        .context("opening workload")?;
    ensure!(
        workload.metadata()?.is_file(),
        "workload must be a regular file"
    );
    let mut input = Vec::new();
    workload.take(WORKLOAD_LIMIT + 1).read_to_end(&mut input)?;
    ensure!(
        input.len() as u64 <= WORKLOAD_LIMIT,
        "workload exceeds 1 MiB bound"
    );
    let parsed: crate::schema::Workload =
        serde_json::from_slice(&input).context("invalid workload contract")?;
    parsed.validate().context("invalid workload settings")?;
    let workload = fs::canonicalize(&options.workload)?;
    let model = std::path::absolute(&options.model_dir)?;
    let mut command = Command::new(&options.python);
    command
        .args(["-I", "-S", "-B"])
        .arg(script)
        .arg("--python")
        .arg(&options.python)
        .arg("--model-dir")
        .arg(model)
        .arg("--workload")
        .arg(workload)
        .env_clear()
        .env("HF_HUB_OFFLINE", "1")
        .env("HF_HUB_DISABLE_IMPLICIT_TOKEN", "1")
        .env("TRANSFORMERS_OFFLINE", "1")
        .env("LC_ALL", "C")
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    execute_check(
        command,
        options.timeout,
        diagnostics,
        "cpu_static_preflight",
    )
}

/// Persist a non-overwriting report, including request/dependency/model/launcher failures.
/// `true` means static checks passed, not native import compatibility or GPU authorization.
pub fn run(options: PreflightOptions) -> Result<bool> {
    let mut output = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&options.output)
        .with_context(|| {
            format!(
                "creating non-overwriting preflight report {}",
                options.output.display()
            )
        })?;
    let script = Path::new(env!("CARGO_MANIFEST_DIR")).join("adapters/mflux_preflight.py");
    let mut diagnostics = Vec::new();
    let started = Instant::now();
    let script_bytes = fs::read(&script);
    let script_hash = script_bytes
        .as_ref()
        .ok()
        .map(|bytes| format!("{:x}", Sha256::digest(bytes)));
    let result = match script_bytes {
        Ok(_) => execute(&options, &script, &mut diagnostics),
        Err(error) => Err(anyhow::Error::new(error).context("reading bundled preflight adapter")),
    };
    let mut report = result.unwrap_or_else(|error| json!({
        "schema_version": 1, "mode": "cpu_static_preflight", "ok": false,
        "errors": [{"stage": "launcher", "message": format!("{error:#}")}],
        "environment": null, "source": null, "model": null, "requested": null, "resolved": null,
        "limitations": ["No inference was performed. Static preflight is not GPU authorization.",
            "Adapter observations are unavailable because launcher/request validation failed."]
    }));
    report["launcher"] = json!({
        "adapter_path": script, "adapter_sha256": script_hash,
        "python": options.python, "python_flags": ["-I", "-S", "-B"],
        "environment_cleared": true, "stdin": "null", "shell": false,
        "timeout_ms": options.timeout.as_millis(), "elapsed_ms": started.elapsed().as_millis(),
        "stdout_limit_bytes": OUTPUT_LIMIT, "stderr_limit_bytes": DIAGNOSTIC_LIMIT,
        "diagnostics": String::from_utf8_lossy(&diagnostics), "gpu_authorization": false
    });
    let ok = report["ok"] == true;
    serde_json::to_writer_pretty(&mut output, &report).context("writing preflight report")?;
    output.write_all(b"\n")?;
    output.sync_all()?;
    Ok(ok)
}

/// Bounded stdlib-only check runner shared by static and native-adapter preparation.
pub(crate) fn execute_check(
    mut command: Command,
    timeout: Duration,
    diagnostics: &mut Vec<u8>,
    mode: &str,
) -> Result<Value> {
    ensure!(
        timeout >= Duration::from_secs(1) && timeout <= Duration::from_secs(120),
        "CPU check timeout must be between 1 and 120 seconds"
    );
    unsafe {
        command.pre_exec(|| {
            if libc::setpgid(0, 0) != 0 {
                return Err(std::io::Error::last_os_error());
            }
            Ok(())
        });
    }
    let mut child = OwnedChild::new(command.spawn().context("launching selected Python")?);
    let mut stdout = child
        .child
        .stdout
        .take()
        .context("missing adapter stdout")?;
    let mut stderr = child
        .child
        .stderr
        .take()
        .context("missing adapter stderr")?;
    nonblocking(&stdout)?;
    nonblocking(&stderr)?;
    let deadline = Instant::now() + timeout;
    let mut bytes = Vec::new();
    let mut exit_status = None;
    let status = loop {
        ensure!(Instant::now() < deadline, "CPU preflight exceeded timeout");
        let out_done = drain(&mut stdout, &mut bytes, OUTPUT_LIMIT)?;
        let err_done = drain(&mut stderr, diagnostics, DIAGNOSTIC_LIMIT)?;
        if exit_status.is_none() && child.exited()? {
            exit_status = Some(child.cleanup()?);
        }
        if let Some(status) = exit_status
            && out_done
            && err_done
        {
            break status;
        }
        std::thread::sleep(Duration::from_millis(10));
    };
    let report: Value = serde_json::from_slice(&bytes).context("adapter emitted malformed JSON")?;
    ensure!(
        report.is_object() && report["schema_version"] == 1 && report["mode"] == mode,
        "adapter returned an unsupported report schema"
    );
    let ok = report["ok"]
        .as_bool()
        .context("adapter omitted boolean static-check outcome")?;
    ensure!(
        report["errors"].is_array() && report["limitations"].is_array(),
        "adapter omitted report evidence fields"
    );
    ensure!(
        (ok && status.success()) || (!ok && status.code() == Some(2)),
        "adapter status disagrees with report: {status}"
    );
    if ok && !report["errors"].as_array().unwrap().is_empty() {
        bail!("adapter reported success alongside errors");
    }
    Ok(report)
}
