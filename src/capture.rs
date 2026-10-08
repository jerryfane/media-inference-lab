use crate::schema::{AdapterResult, ProcessPolicy, Workload};
use anyhow::{Context, Result, bail, ensure};
use serde::{Deserialize, Serialize, de::DeserializeOwned};
use sha2::{Digest, Sha256};
use std::{
    collections::BTreeMap,
    fs::{self, File, OpenOptions},
    io::{Read, Write},
    path::{Component, Path, PathBuf},
    sync::{
        Arc,
        atomic::{AtomicBool, AtomicU64, Ordering},
    },
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

const RECORD_VERSION: u32 = 1;
const JSON_LIMIT: u64 = 16 * 1024 * 1024;
const POLL: Duration = Duration::from_millis(10);
const TERM_GRACE: Duration = Duration::from_millis(100);
const KILL_GRACE: Duration = Duration::from_secs(1);
const INSPECTION_LIMIT: Duration = Duration::from_secs(30);
const REDACTED: &str = "[redacted]";
static SEQUENCE: AtomicU64 = AtomicU64::new(0);

pub struct CaptureOptions {
    pub root: PathBuf,
    pub executable: PathBuf,
    pub args: Vec<String>,
    pub env: BTreeMap<String, String>,
    pub timeout: Duration,
    pub max_output_bytes: u64,
}

#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum CaptureState {
    Running,
    Completed,
    Failed,
    TimedOut,
    Cancelled,
    Incomplete,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct HostIdentity {
    pub os: String,
    pub architecture: String,
    pub kernel_release: String,
    pub logical_cpus: Option<usize>,
    pub observation_method: String,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Invocation {
    pub executable: String,
    pub executable_sha256: Option<String>,
    pub executable_hash_unavailable: Option<String>,
    pub args: Vec<String>,
    pub environment: BTreeMap<String, String>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CaptureLimits {
    pub timeout_ms: u64,
    pub max_output_bytes: u64,
    pub platform_limits: Vec<String>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ChildExit {
    pub code: Option<i32>,
    pub signal: Option<i32>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Cleanup {
    pub process_group: Option<u32>,
    pub group_signalled: bool,
    /// No live group remained: absent, or Darwin reported only our unreaped zombie leader.
    pub group_quiescent: bool,
    pub leader_reaped: bool,
}

#[derive(Clone, Debug, Deserialize, Serialize, Default)]
#[serde(deny_unknown_fields)]
pub struct LogEvidence {
    pub stdout_bytes: u64,
    pub stderr_bytes: u64,
    pub truncated: bool,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CaptureRecord {
    pub record_version: u32,
    pub sample_index: u32,
    pub state: CaptureState,
    pub request: Workload,
    pub workload_identity: String,
    pub host: HostIdentity,
    pub invocation: Invocation,
    pub limits: CaptureLimits,
    pub started_unix_ms: u64,
    pub ended_unix_ms: Option<u64>,
    /// Monotonic spawn-to-leader-exit/stop-decision boundary, not native inference time.
    pub host_elapsed_ms: Option<u64>,
    /// Null means this stage was not entered; zero is an observed sub-ms duration.
    pub artifact_inspection_ms: Option<u64>,
    /// Null means no child was spawned and group cleanup was not attempted.
    pub cleanup_elapsed_ms: Option<u64>,
    pub exit: Option<ChildExit>,
    pub cleanup: Option<Cleanup>,
    pub logs: LogEvidence,
    pub failure: Option<String>,
    pub adapter_result: Option<AdapterResult>,
}

impl CaptureRecord {
    pub fn is_success(&self) -> bool {
        self.state == CaptureState::Completed
    }

    pub fn validate(&self) -> Result<()> {
        ensure!(
            self.record_version == RECORD_VERSION,
            "unsupported capture record version"
        );
        ensure!(
            self.sample_index == 0,
            "this capture version supports only sample index 0"
        );
        self.request.validate()?;
        ensure!(
            self.request.process_policy == ProcessPolicy::FreshProcess,
            "capture requires fresh_process policy"
        );
        ensure!(
            self.workload_identity == self.request.identity()?,
            "capture workload identity mismatch"
        );
        ensure!(
            self.limits.timeout_ms > 0 && self.limits.max_output_bytes > 0,
            "invalid capture limits"
        );
        ensure!(
            !self.host.os.is_empty()
                && !self.host.architecture.is_empty()
                && !self.host.kernel_release.is_empty()
                && !self.host.observation_method.is_empty(),
            "missing host provenance"
        );
        ensure!(
            self.host.logical_cpus != Some(0),
            "invalid logical CPU count"
        );
        ensure!(
            Path::new(&self.invocation.executable).is_absolute(),
            "executable must be absolute"
        );
        ensure!(
            self.invocation.args.iter().all(|v| v == REDACTED)
                && self.invocation.environment.values().all(|v| v == REDACTED),
            "unredacted invocation values"
        );
        for key in [
            "MIL_RUN_DIR",
            "MIL_REQUEST_PATH",
            "MIL_RESULT_PATH",
            "MIL_WORKLOAD_IDENTITY",
        ] {
            ensure!(
                self.invocation.environment.contains_key(key),
                "missing adapter environment provenance"
            );
        }
        match (
            &self.invocation.executable_sha256,
            &self.invocation.executable_hash_unavailable,
        ) {
            (Some(hash), None) => ensure!(valid_hash(hash), "invalid executable SHA256"),
            (None, Some(reason)) => {
                ensure!(!reason.trim().is_empty(), "missing executable hash reason")
            }
            _ => bail!("executable hash availability is contradictory"),
        }
        ensure!(
            self.logs
                .stdout_bytes
                .checked_add(self.logs.stderr_bytes)
                .is_some_and(|n| n <= self.limits.max_output_bytes),
            "recorded logs exceed output limit"
        );
        if let Some(exit) = &self.exit {
            ensure!(
                exit.code.is_some() != exit.signal.is_some(),
                "exit must contain exactly one of code/signal"
            );
            ensure!(
                exit.code.is_none_or(|n| (0..=255).contains(&n))
                    && exit.signal.is_none_or(|n| n > 0),
                "invalid exit status"
            );
        }
        if self.state == CaptureState::Running {
            ensure!(
                self.ended_unix_ms.is_none()
                    && self.host_elapsed_ms.is_none()
                    && self.artifact_inspection_ms.is_none()
                    && self.cleanup_elapsed_ms.is_none()
                    && self.exit.is_none()
                    && self.cleanup.is_none()
                    && self.failure.is_none()
                    && self.adapter_result.is_none(),
                "running record contains terminal evidence"
            );
            return Ok(());
        }
        ensure!(
            self.ended_unix_ms.is_some()
                && self.host_elapsed_ms.is_some()
                && self.cleanup.is_some(),
            "terminal record lacks host boundaries or cleanup evidence"
        );
        let cleanup = self.cleanup.as_ref().expect("checked cleanup");
        ensure!(
            cleanup.process_group.is_some()
                || (!cleanup.group_signalled
                    && !cleanup.group_quiescent
                    && !cleanup.leader_reaped
                    && self.exit.is_none()),
            "cleanup claims an unowned process"
        );
        ensure!(
            cleanup
                .process_group
                .is_none_or(|pid| pid > 1 && pid <= i32::MAX as u32),
            "invalid owned process group"
        );
        ensure!(
            self.cleanup_elapsed_ms.is_some() == cleanup.process_group.is_some(),
            "cleanup timing must describe an attempted owned-group cleanup"
        );
        ensure!(
            self.artifact_inspection_ms.is_none()
                || self.exit.as_ref().is_some_and(|e| e.code == Some(0)),
            "artifact inspection requires a zero child exit"
        );
        ensure!(
            cleanup.leader_reaped == self.exit.is_some(),
            "exit and reaping evidence disagree"
        );
        if self.is_success() {
            ensure!(
                self.failure.is_none() && !self.logs.truncated,
                "successful record contains failure/truncation"
            );
            ensure!(
                self.exit.as_ref().is_some_and(|e| e.code == Some(0)),
                "success requires a zero child exit"
            );
            ensure!(
                (cleanup.group_signalled || cleanup.group_quiescent) && cleanup.leader_reaped,
                "success requires owned-group cleanup"
            );
            ensure!(
                self.artifact_inspection_ms.is_some(),
                "success lacks artifact inspection boundary"
            );
            self.adapter_result
                .as_ref()
                .context("success lacks adapter result")?
                .validate(&self.request)?;
        } else {
            ensure!(
                self.failure.as_ref().is_some_and(|s| !s.trim().is_empty()),
                "non-success requires an explanation"
            );
            ensure!(
                self.adapter_result.is_none(),
                "non-success cannot contain a successful adapter result"
            );
            if self.state == CaptureState::TimedOut {
                ensure!(
                    cleanup.process_group.is_some()
                        && self
                            .host_elapsed_ms
                            .is_some_and(|n| n >= self.limits.timeout_ms),
                    "timeout lacks an owned child or expired host deadline"
                );
            }
            if self.state == CaptureState::Incomplete {
                ensure!(
                    self.exit.as_ref().is_some_and(|e| e.code == Some(0))
                        && self.artifact_inspection_ms.is_some(),
                    "missing-result incomplete state requires zero child exit and inspection"
                );
            }
        }
        Ok(())
    }
}

fn valid_hash(value: &str) -> bool {
    value.len() == 64 && value.bytes().all(|b| b.is_ascii_hexdigit())
}

fn millis(duration: Duration) -> u64 {
    u64::try_from(duration.as_millis()).unwrap_or(u64::MAX)
}

fn now_ms() -> Result<u64> {
    Ok(millis(
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .context("wall clock predates Unix epoch")?,
    ))
}

fn safe_directory(path: &Path) -> Result<()> {
    let mut current = PathBuf::new();
    for component in path.components() {
        ensure!(
            !matches!(component, Component::ParentDir),
            "parent components are not allowed in evidence directory paths"
        );
        current.push(component);
        match fs::symlink_metadata(&current) {
            Ok(metadata) => ensure!(
                metadata.is_dir() && !metadata.file_type().is_symlink(),
                "evidence directory component is not a real directory: {}",
                current.display()
            ),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => return Err(error.into()),
        }
    }
    Ok(())
}

fn absolute(path: &Path) -> Result<PathBuf> {
    Ok(if path.is_absolute() {
        path.to_path_buf()
    } else {
        std::env::current_dir()?.join(path)
    })
}

fn unique_run(root: &Path) -> Result<PathBuf> {
    let root = absolute(root)?;
    safe_directory(&root)?;
    fs::create_dir_all(&root)?;
    let root = fs::canonicalize(root)?;
    for _ in 0..100 {
        let path = root.join(format!(
            "run-{}-{}-{}",
            now_ms()?,
            std::process::id(),
            SEQUENCE.fetch_add(1, Ordering::Relaxed)
        ));
        match fs::create_dir(&path) {
            Ok(()) => {
                File::open(&root)?.sync_all()?;
                return Ok(path);
            }
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => continue,
            Err(error) => return Err(error.into()),
        }
    }
    bail!("could not allocate a unique run directory")
}

struct BoundedWriter<'a> {
    file: &'a mut File,
    remaining: u64,
}

impl Write for BoundedWriter<'_> {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        if bytes.len() as u64 > self.remaining {
            return Err(std::io::Error::other("capture JSON exceeds 16 MiB"));
        }
        let written = self.file.write(bytes)?;
        self.remaining -= written as u64;
        Ok(written)
    }

    fn flush(&mut self) -> std::io::Result<()> {
        self.file.flush()
    }
}

fn atomic_json<T: Serialize>(directory: &Path, name: &str, value: &T) -> Result<()> {
    let temporary = directory.join(format!(
        ".mil-{}-{}.tmp",
        std::process::id(),
        SEQUENCE.fetch_add(1, Ordering::Relaxed)
    ));
    let result = (|| {
        let mut file = OpenOptions::new()
            .create_new(true)
            .write(true)
            .open(&temporary)?;
        let mut writer = BoundedWriter {
            file: &mut file,
            remaining: JSON_LIMIT,
        };
        serde_json::to_writer_pretty(&mut writer, value)?;
        writer.write_all(b"\n")?;
        file.sync_all()?;
        fs::rename(&temporary, directory.join(name))?;
        File::open(directory)?.sync_all()?;
        Ok(())
    })();
    if result.is_err() {
        let _ = fs::remove_file(temporary);
    }
    result
}

fn regular_file(path: &Path) -> Result<File> {
    let metadata = fs::symlink_metadata(path)?;
    ensure!(
        metadata.is_file() && !metadata.file_type().is_symlink(),
        "not a regular non-symlink file: {}",
        path.display()
    );
    let mut options = OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK);
    }
    let file = options.open(path)?;
    ensure!(
        file.metadata()?.is_file(),
        "not a regular file: {}",
        path.display()
    );
    Ok(file)
}

fn load_json<T: DeserializeOwned>(path: &Path, limit: u64) -> Result<T> {
    let file = regular_file(path)?;
    ensure!(
        file.metadata()?.len() <= limit,
        "JSON exceeds byte limit: {}",
        path.display()
    );
    let mut bytes = Vec::new();
    file.take(limit.saturating_add(1)).read_to_end(&mut bytes)?;
    ensure!(bytes.len() as u64 <= limit, "JSON exceeds byte limit");
    serde_json::from_slice(&bytes).with_context(|| format!("invalid JSON in {}", path.display()))
}

fn hash_file(
    path: &Path,
    max_bytes: u64,
    deadline: Instant,
    cancelled: Option<&AtomicBool>,
) -> Result<(String, u64)> {
    let mut file = regular_file(path)?;
    ensure!(
        file.metadata()?.len() <= max_bytes,
        "file exceeds byte limit: {}",
        path.display()
    );
    let mut hasher = Sha256::new();
    let mut buffer = [0_u8; 64 * 1024];
    let mut bytes = 0_u64;
    loop {
        ensure!(
            Instant::now() < deadline,
            "artifact inspection deadline exceeded"
        );
        ensure!(
            !cancelled.is_some_and(|flag| flag.load(Ordering::Relaxed)),
            "cancelled during artifact inspection"
        );
        let count = file.read(&mut buffer)?;
        if count == 0 {
            break;
        }
        bytes = bytes
            .checked_add(count as u64)
            .context("file size overflow")?;
        ensure!(bytes <= max_bytes, "file exceeds byte limit");
        hasher.update(&buffer[..count]);
    }
    Ok((format!("{:x}", hasher.finalize()), bytes))
}

fn output_bytes(directory: &Path, limit: u64) -> Result<u64> {
    let mut stack = vec![(directory.to_path_buf(), 0_u32)];
    let mut entries = 0_u32;
    let mut bytes = 0_u64;
    while let Some((path, depth)) = stack.pop() {
        ensure!(depth <= 16, "adapter output directory nesting exceeds 16");
        for entry in fs::read_dir(path)? {
            let entry = entry?;
            entries += 1;
            ensure!(
                entries <= 4096,
                "adapter output exceeds 4096 directory entries"
            );
            let metadata = fs::symlink_metadata(entry.path())?;
            ensure!(
                !metadata.file_type().is_symlink(),
                "symlinks are not allowed in adapter output"
            );
            if depth == 0
                && matches!(
                    entry.file_name().to_str(),
                    Some("manifest.json" | "requested.json")
                )
            {
                ensure!(
                    metadata.is_file() && metadata.len() <= JSON_LIMIT,
                    "invalid control evidence file"
                );
                continue;
            }
            if metadata.is_dir() {
                stack.push((entry.path(), depth + 1));
            } else {
                ensure!(
                    metadata.is_file(),
                    "adapter output contains a non-regular file"
                );
                bytes = bytes
                    .checked_add(metadata.len())
                    .context("output size overflow")?;
                ensure!(
                    bytes <= limit,
                    "adapter output exceeds configured byte limit"
                );
            }
        }
    }
    Ok(bytes)
}

fn verify_artifacts(
    directory: &Path,
    result: &AdapterResult,
    limit: u64,
    deadline: Instant,
    cancelled: Option<&AtomicBool>,
) -> Result<()> {
    let mut total = 0_u64;
    for artifact in &result.artifacts {
        let path = directory.join(&artifact.path);
        safe_directory(path.parent().context("artifact has no parent")?)?;
        let remaining = limit
            .checked_sub(total)
            .context("artifact bytes exceed capture limit")?;
        let (hash, bytes) = hash_file(&path, remaining, deadline, cancelled)?;
        ensure!(
            bytes == artifact.bytes,
            "artifact byte count mismatch: {}",
            artifact.path
        );
        ensure!(
            hash.eq_ignore_ascii_case(&artifact.sha256),
            "artifact SHA256 mismatch: {}",
            artifact.path
        );
        total += bytes;
    }
    Ok(())
}

/// Read-only inspection. A durable `running` record is unresolved, not a claim that
/// its owner is alive or dead; inspection never signals, recovers, or rewrites it.
pub fn inspect(run_dir: &Path) -> Result<CaptureRecord> {
    let directory = absolute(run_dir)?;
    safe_directory(&directory)?;
    let record: CaptureRecord = load_json(&directory.join("manifest.json"), JSON_LIMIT)?;
    record.validate()?;
    let requested: Workload = load_json(&directory.join("requested.json"), JSON_LIMIT)?;
    ensure!(
        requested == record.request && requested.identity()? == record.workload_identity,
        "requested.json disagrees with capture manifest"
    );
    if record.state == CaptureState::Incomplete {
        ensure!(
            matches!(fs::symlink_metadata(directory.join("result.json")), Err(error) if error.kind() == std::io::ErrorKind::NotFound),
            "missing-result record has a result path"
        );
    }
    if record.is_success() {
        let result: AdapterResult = load_json(
            &directory.join("result.json"),
            JSON_LIMIT.min(record.limits.max_output_bytes),
        )?;
        result.validate(&record.request)?;
        ensure!(
            serde_json::to_value(&result)?
                == serde_json::to_value(record.adapter_result.as_ref().context("missing result")?)?,
            "result.json disagrees with capture manifest"
        );
        output_bytes(&directory, record.limits.max_output_bytes)?;
        verify_artifacts(
            &directory,
            &result,
            record.limits.max_output_bytes,
            Instant::now() + INSPECTION_LIMIT,
            None,
        )?;
        ensure!(
            regular_file(&directory.join("stdout.log"))?
                .metadata()?
                .len()
                == record.logs.stdout_bytes
                && regular_file(&directory.join("stderr.log"))?
                    .metadata()?
                    .len()
                    == record.logs.stderr_bytes,
            "log size disagrees with manifest"
        );
    }
    Ok(record)
}

pub fn capture(
    request: Workload,
    options: CaptureOptions,
    cancelled: Arc<AtomicBool>,
) -> Result<PathBuf> {
    request.validate()?;
    ensure!(
        request.process_policy == ProcessPolicy::FreshProcess,
        "only fresh_process capture is supported; in_process is not silently substituted"
    );
    ensure!(
        millis(options.timeout) > 0 && options.timeout <= Duration::from_secs(86400),
        "timeout must be between 1 ms and 24 hours"
    );
    ensure!(
        options.max_output_bytes > 0,
        "max_output_bytes must be positive"
    );
    ensure!(
        options.executable.is_absolute() || options.executable.components().count() > 1,
        "an explicit executable path is required, not PATH lookup"
    );
    ensure!(
        !options.args.iter().any(|arg| arg.contains('\0')),
        "argument contains NUL"
    );
    for (key, value) in &options.env {
        ensure!(
            !key.is_empty()
                && !key.contains(['=', '\0'])
                && !key.starts_with("MIL_")
                && !value.contains('\0'),
            "invalid or reserved explicit environment entry"
        );
    }
    #[cfg(any(target_os = "macos", target_os = "linux"))]
    {
        unix::capture(request, options, cancelled)
    }
    #[cfg(not(any(target_os = "macos", target_os = "linux")))]
    {
        let _ = (request, options, cancelled);
        bail!("process ownership supervision is supported only on macOS and Linux")
    }
}

#[cfg(any(target_os = "macos", target_os = "linux"))]
mod unix {
    use super::*;
    use std::{
        os::{
            fd::AsRawFd,
            unix::process::{CommandExt, ExitStatusExt},
        },
        process::{Child, Command, ExitStatus, Stdio},
        thread,
    };

    // Never reap the group leader until all group signals have been sent. Its
    // unreaped PID pins the group ID, so cleanup cannot signal a reused PID/PGID.
    // Embedders must not install SIGCHLD auto-reaping or reap this module's child.
    struct OwnedChild {
        child: Child,
        anchored: bool,
        group_signalled: bool,
        group_quiescent: bool,
    }

    #[cfg(target_os = "macos")]
    fn only_zombie_leader(group: u32) -> Result<bool> {
        // XNU killpg1 skips zombies and returns EPERM if it signals no member.
        // Do not suppress permission failures on live descendants. The caller
        // has observed its unreaped leader's exit; require it to be the ONLY
        // listed member. Unknown membership fails closed.
        const PROC_PGRP_ONLY: u32 = 2; // public sys/proc_info.h
        let mut members = [0_i32; 1024];
        let bytes = unsafe {
            libc::proc_listpids(
                PROC_PGRP_ONLY,
                group,
                members.as_mut_ptr().cast(),
                std::mem::size_of_val(&members) as i32,
            )
        };
        ensure!(
            bytes > 0,
            "cannot observe Darwin process-group membership: {}",
            std::io::Error::last_os_error()
        );
        ensure!(
            (bytes as usize) < std::mem::size_of_val(&members)
                && (bytes as usize).is_multiple_of(std::mem::size_of::<i32>()),
            "Darwin process-group membership is truncated or malformed"
        );
        Ok(bytes as usize == std::mem::size_of::<i32>() && members[0] == group as i32)
    }

    impl OwnedChild {
        fn exited(&mut self) -> Result<bool> {
            let mut info: libc::siginfo_t = unsafe { std::mem::zeroed() };
            loop {
                let result = unsafe {
                    libc::waitid(
                        libc::P_PID,
                        self.child.id(),
                        &mut info,
                        libc::WEXITED | libc::WNOHANG | libc::WNOWAIT,
                    )
                };
                if result == 0 {
                    return Ok(unsafe { info.si_pid() } != 0);
                }
                let error = std::io::Error::last_os_error();
                if error.kind() == std::io::ErrorKind::Interrupted {
                    continue;
                }
                if error.raw_os_error() == Some(libc::ECHILD) {
                    self.anchored = false;
                }
                return Err(error).context("observing owned child without reaping");
            }
        }

        fn signal(&mut self, signal: i32) -> Result<()> {
            // Confirm ownership immediately before each signal, including after
            // an unexpected externally installed SIGCHLD handler.
            let leader_exited = self.exited()?;
            ensure!(
                self.anchored,
                "lost child ownership; refusing process-group signal"
            );
            let result = unsafe { libc::kill(-(self.child.id() as i32), signal) };
            if result == 0 {
                self.group_signalled = true;
            }
            if result != 0 {
                let error = std::io::Error::last_os_error();
                if error.raw_os_error() == Some(libc::ESRCH) && leader_exited {
                    self.group_quiescent = true;
                    return Ok(());
                }
                #[cfg(target_os = "macos")]
                if error.raw_os_error() == Some(libc::EPERM)
                    && leader_exited
                    && only_zombie_leader(self.child.id())?
                {
                    self.group_quiescent = true;
                    return Ok(());
                }
                return Err(error.into());
            }
            Ok(())
        }

        fn cleanup(&mut self) -> Result<ExitStatus> {
            self.signal(libc::SIGTERM)?;
            thread::sleep(TERM_GRACE);
            self.signal(libc::SIGKILL)?;
            let deadline = Instant::now() + KILL_GRACE;
            loop {
                if self.exited()? {
                    let status = self.child.wait()?;
                    self.anchored = false;
                    return Ok(status);
                }
                ensure!(
                    Instant::now() < deadline,
                    "owned leader did not exit within SIGKILL cleanup bound"
                );
                thread::sleep(POLL);
            }
        }
    }

    impl Drop for OwnedChild {
        fn drop(&mut self) {
            if !self.anchored {
                return;
            }
            if self.signal(libc::SIGKILL).is_err() {
                return;
            }
            let deadline = Instant::now() + KILL_GRACE;
            while Instant::now() < deadline {
                match self.exited() {
                    Ok(true) => {
                        let _ = self.child.wait();
                        self.anchored = false;
                        break;
                    }
                    Ok(false) => thread::sleep(POLL),
                    Err(_) => break,
                }
            }
        }
    }

    fn nonblocking<T: AsRawFd>(pipe: &T) -> Result<()> {
        let flags = unsafe { libc::fcntl(pipe.as_raw_fd(), libc::F_GETFL) };
        ensure!(
            flags >= 0,
            "reading pipe flags: {}",
            std::io::Error::last_os_error()
        );
        ensure!(
            unsafe { libc::fcntl(pipe.as_raw_fd(), libc::F_SETFL, flags | libc::O_NONBLOCK) } >= 0,
            "setting nonblocking pipe: {}",
            std::io::Error::last_os_error()
        );
        Ok(())
    }

    fn drain(
        pipe: &mut impl Read,
        log: &mut File,
        remaining: &mut u64,
        count: &mut u64,
    ) -> Result<(bool, bool)> {
        let mut buffer = [0_u8; 8192];
        for _ in 0..8 {
            match pipe.read(&mut buffer) {
                Ok(0) => return Ok((false, true)),
                Ok(bytes) => {
                    let retained = (bytes as u64).min(*remaining) as usize;
                    log.write_all(&buffer[..retained])?;
                    *remaining -= retained as u64;
                    *count += retained as u64;
                    if retained < bytes {
                        return Ok((true, false));
                    }
                }
                Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                    return Ok((false, true));
                }
                Err(error) if error.kind() == std::io::ErrorKind::Interrupted => continue,
                Err(error) => return Err(error.into()),
            }
        }
        Ok((false, false))
    }

    fn final_drain(
        pipe: &mut impl Read,
        log: &mut File,
        remaining: &mut u64,
        count: &mut u64,
    ) -> Result<bool> {
        let deadline = Instant::now() + Duration::from_millis(100);
        loop {
            let (overflow, drained) = drain(pipe, log, remaining, count)?;
            if overflow || drained {
                return Ok(overflow);
            }
            if Instant::now() >= deadline {
                return Ok(true);
            }
        }
    }

    fn host_identity() -> Result<HostIdentity> {
        let mut info: libc::utsname = unsafe { std::mem::zeroed() };
        ensure!(
            unsafe { libc::uname(&mut info) } == 0,
            "observing host uname failed"
        );
        let text = |field: &[libc::c_char]| {
            unsafe { std::ffi::CStr::from_ptr(field.as_ptr()) }
                .to_string_lossy()
                .into_owned()
        };
        Ok(HostIdentity {
            os: text(&info.sysname), architecture: text(&info.machine), kernel_release: text(&info.release),
            logical_cpus: thread::available_parallelism().ok().map(usize::from),
            observation_method: "POSIX uname OS/kernel/machine; std::thread::available_parallelism CPU availability; no GPU or memory readings".into(),
        })
    }

    pub(super) fn capture(
        request: Workload,
        options: CaptureOptions,
        cancelled: Arc<AtomicBool>,
    ) -> Result<PathBuf> {
        let executable = absolute(&options.executable)?;
        let executable_hash = hash_file(
            &executable,
            512 * 1024 * 1024,
            Instant::now() + Duration::from_secs(2),
            None,
        );
        let directory = unique_run(&options.root)?;
        let mut environment: BTreeMap<_, _> = options
            .env
            .keys()
            .map(|key| (key.clone(), REDACTED.into()))
            .collect();
        for key in [
            "MIL_REQUEST_PATH",
            "MIL_RESULT_PATH",
            "MIL_RUN_DIR",
            "MIL_WORKLOAD_IDENTITY",
        ] {
            environment.insert(key.into(), REDACTED.into());
        }
        let (executable_sha256, executable_hash_unavailable) = match executable_hash {
            Ok((hash, _)) => (Some(hash), None),
            Err(error) => (None, Some(format!("{error:#}"))),
        };
        let mut record = CaptureRecord {
            record_version: RECORD_VERSION, sample_index: 0, state: CaptureState::Running,
            workload_identity: request.identity()?, request,
            host: host_identity()?,
            invocation: Invocation { executable: executable.to_string_lossy().into(), executable_sha256, executable_hash_unavailable, args: options.args.iter().map(|_| REDACTED.into()).collect(), environment },
            limits: CaptureLimits {
                timeout_ms: millis(options.timeout), max_output_bytes: options.max_output_bytes,
                platform_limits: vec![
                    "macOS/Linux owned process group; trusted children must not escape via setsid/setpgid; not a sandbox".into(),
                    "no external SIGCHLD auto-reaping or competing child reaper is supported".into(),
                    "nonblocking bounded logs; output sizes polled, not a filesystem quota; no OS bound on stalled filesystem I/O".into(),
                    "TERM grace 100 ms, KILL observation 1 s; process-group signal delivery does not prove every descendant exited".into(),
                    "artifact inspection has a 30 s cooperative deadline and streaming byte bounds; no native/GPU timing inferred".into(),
                    "one fresh-process sample, no retries; running records have unknown owner liveness".into(),
                ],
            },
            started_unix_ms: now_ms()?, ended_unix_ms: None, host_elapsed_ms: None, artifact_inspection_ms: None, cleanup_elapsed_ms: None,
            exit: None, cleanup: None, logs: LogEvidence::default(), failure: None, adapter_result: None,
        };
        atomic_json(&directory, "requested.json", &record.request)?;
        atomic_json(&directory, "manifest.json", &record)?;
        let mut stdout_log = OpenOptions::new()
            .create_new(true)
            .write(true)
            .open(directory.join("stdout.log"))?;
        let mut stderr_log = OpenOptions::new()
            .create_new(true)
            .write(true)
            .open(directory.join("stderr.log"))?;
        let execution_start = Instant::now();
        let mut command = Command::new(&executable);
        command
            .args(&options.args)
            .env_clear()
            .envs(&options.env)
            .env("MIL_REQUEST_PATH", directory.join("requested.json"))
            .env("MIL_RESULT_PATH", directory.join("result.json"))
            .env("MIL_WORKLOAD_IDENTITY", &record.workload_identity)
            .env("MIL_RUN_DIR", &directory)
            .current_dir(&directory)
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        unsafe {
            command.pre_exec(|| {
                if libc::setpgid(0, 0) != 0 {
                    return Err(std::io::Error::last_os_error());
                }
                Ok(())
            });
        }
        let spawned = if cancelled.load(Ordering::Relaxed) {
            None
        } else {
            Some(command.spawn())
        };
        match spawned {
            None => {
                record.state = CaptureState::Cancelled;
                record.failure = Some("cancelled before spawn".into());
                record.cleanup = Some(Cleanup {
                    process_group: None,
                    group_signalled: false,
                    group_quiescent: false,
                    leader_reaped: false,
                });
            }
            Some(Err(error)) => {
                record.state = CaptureState::Failed;
                record.failure = Some(format!("could not spawn explicit executable: {error}"));
                record.cleanup = Some(Cleanup {
                    process_group: None,
                    group_signalled: false,
                    group_quiescent: false,
                    leader_reaped: false,
                });
            }
            Some(Ok(child)) => {
                let mut owned = OwnedChild {
                    child,
                    anchored: true,
                    group_signalled: false,
                    group_quiescent: false,
                };
                let group = owned.child.id();
                let mut stdout = owned
                    .child
                    .stdout
                    .take()
                    .context("missing child stdout pipe")?;
                let mut stderr = owned
                    .child
                    .stderr
                    .take()
                    .context("missing child stderr pipe")?;
                let mut remaining = options.max_output_bytes;
                let mut last_size_check = Instant::now();
                let execution = (|| -> Result<()> {
                    nonblocking(&stdout)?;
                    nonblocking(&stderr)?;
                    loop {
                        if cancelled.load(Ordering::Relaxed) {
                            record.state = CaptureState::Cancelled;
                            record.failure = Some("cancelled by caller".into());
                            break;
                        }
                        if execution_start.elapsed() >= options.timeout {
                            record.state = CaptureState::TimedOut;
                            record.failure = Some("host execution deadline exceeded".into());
                            break;
                        }
                        let (stdout_overflow, _) = drain(
                            &mut stdout,
                            &mut stdout_log,
                            &mut remaining,
                            &mut record.logs.stdout_bytes,
                        )?;
                        let (stderr_overflow, _) = drain(
                            &mut stderr,
                            &mut stderr_log,
                            &mut remaining,
                            &mut record.logs.stderr_bytes,
                        )?;
                        if stdout_overflow || stderr_overflow {
                            record.logs.truncated = true;
                            bail!("combined stdout/stderr exceeded byte limit");
                        }
                        if owned.exited()? {
                            break;
                        }
                        if last_size_check.elapsed() >= Duration::from_millis(50) {
                            output_bytes(&directory, options.max_output_bytes)?;
                            last_size_check = Instant::now();
                        }
                        thread::sleep(POLL);
                    }
                    Ok(())
                })();
                record.host_elapsed_ms = Some(millis(execution_start.elapsed()));
                if let Err(error) = execution {
                    record.state = CaptureState::Failed;
                    record.failure = Some(format!("capture monitoring failed: {error:#}"));
                }
                let cleanup_start = Instant::now();
                let cleanup = owned.cleanup();
                record.cleanup_elapsed_ms = Some(millis(cleanup_start.elapsed()));
                record.cleanup = Some(Cleanup {
                    process_group: Some(group),
                    group_signalled: owned.group_signalled,
                    group_quiescent: owned.group_quiescent,
                    leader_reaped: cleanup.is_ok(),
                });
                match cleanup {
                    Ok(status) => {
                        record.exit = Some(ChildExit {
                            code: status.code(),
                            signal: status.signal(),
                        })
                    }
                    Err(error) => {
                        record.state = CaptureState::Failed;
                        record.failure = Some(format!("owned-group cleanup failed: {error:#}"));
                    }
                }
                // Nonblocking drains have a separate 100 ms bound per pipe: an
                // escaped descendant can never make us wait indefinitely for EOF.
                let final_logs = (|| -> Result<bool> {
                    nonblocking(&stdout)?;
                    nonblocking(&stderr)?;
                    let out = final_drain(
                        &mut stdout,
                        &mut stdout_log,
                        &mut remaining,
                        &mut record.logs.stdout_bytes,
                    )?;
                    let err = final_drain(
                        &mut stderr,
                        &mut stderr_log,
                        &mut remaining,
                        &mut record.logs.stderr_bytes,
                    )?;
                    Ok(out || err)
                })();
                match final_logs {
                    Ok(true) => {
                        record.logs.truncated = true;
                        if record.state == CaptureState::Running {
                            record.state = CaptureState::Failed;
                            record.failure =
                                Some("logs exceeded byte limit or final drain deadline".into());
                        }
                    }
                    Ok(false) => {}
                    Err(error) => {
                        record.state = CaptureState::Failed;
                        record.failure = Some(format!("retaining final logs failed: {error}"));
                    }
                }
                drop(stdout);
                drop(stderr);
            }
        }
        record
            .host_elapsed_ms
            .get_or_insert_with(|| millis(execution_start.elapsed()));
        stdout_log.sync_all()?;
        stderr_log.sync_all()?;
        if record.state == CaptureState::Running {
            if !record
                .exit
                .as_ref()
                .is_some_and(|exit| exit.code == Some(0))
            {
                record.state = CaptureState::Failed;
                record.failure = Some(
                    "child exited unsuccessfully; adapter evidence cannot override exit status"
                        .into(),
                );
            } else {
                let inspection_start = Instant::now();
                let result_path = directory.join("result.json");
                if matches!(fs::symlink_metadata(&result_path), Err(error) if error.kind() == std::io::ErrorKind::NotFound)
                {
                    record.state = CaptureState::Incomplete;
                    record.failure = Some("child exited without result.json".into());
                } else {
                    let validation = (|| -> Result<AdapterResult> {
                        output_bytes(&directory, options.max_output_bytes)?;
                        let requested: Workload =
                            load_json(&directory.join("requested.json"), JSON_LIMIT)?;
                        ensure!(
                            requested == record.request
                                && requested.identity()? == record.workload_identity,
                            "adapter changed requested.json"
                        );
                        let result: AdapterResult =
                            load_json(&result_path, JSON_LIMIT.min(options.max_output_bytes))?;
                        result.validate(&record.request)?;
                        verify_artifacts(
                            &directory,
                            &result,
                            options.max_output_bytes,
                            inspection_start + INSPECTION_LIMIT,
                            Some(&cancelled),
                        )?;
                        Ok(result)
                    })();
                    match validation {
                        Ok(result) => {
                            record.state = CaptureState::Completed;
                            record.adapter_result = Some(result);
                        }
                        Err(error) => {
                            record.state = if cancelled.load(Ordering::Relaxed) {
                                CaptureState::Cancelled
                            } else {
                                CaptureState::Failed
                            };
                            record.failure = Some(format!("adapter evidence rejected: {error:#}"));
                        }
                    }
                }
                record.artifact_inspection_ms = Some(millis(inspection_start.elapsed()));
            }
        }
        record.ended_unix_ms = Some(now_ms()?);
        record.validate()?;
        atomic_json(&directory, "manifest.json", &record)?;
        Ok(directory)
    }
}
