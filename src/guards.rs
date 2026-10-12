//! Resource safety only. Service inhibition and authorization belong to the guardian.
use anyhow::{Context, Result, bail, ensure};
use serde::{Deserialize, Serialize};
use std::{
    fs::{self, File, OpenOptions},
    os::unix::{
        fs::{MetadataExt, OpenOptionsExt},
        io::AsRawFd,
    },
    path::{Path, PathBuf},
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

pub const LAUNCH_FREE_PERCENT: f64 = 30.0;
pub const ABORT_FREE_PERCENT: f64 = 15.0;
pub const MAX_SWAP_GROWTH_BYTES: u64 = 512 * 1024 * 1024;
pub const MAX_MONITOR_DURATION_MS: u64 = 600_000;
pub const MAX_SAMPLES: usize = 6002;

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GuardConfig {
    pub min_disk_free_bytes: u64,
    pub max_disk_growth_bytes: u64,
    pub sample_interval_ms: u64,
}
impl GuardConfig {
    pub fn validate(&self) -> Result<()> {
        ensure!(
            self.min_disk_free_bytes > 0 && self.max_disk_growth_bytes > 0,
            "explicit positive disk limits are required"
        );
        ensure!(
            (100..=1000).contains(&self.sample_interval_ms),
            "sample interval must be 100..=1000 ms"
        );
        Ok(())
    }
}

/// Close-only lifetime: explicitly unlocking here would release an inherited child's lock.
pub struct Lease {
    file: File,
    path: PathBuf,
}
impl Lease {
    pub fn acquire(path: &Path) -> Result<Self> {
        let parent = path.parent().context("lease path has no parent")?;
        ensure!(
            parent.is_absolute() && fs::canonicalize(parent)? == parent,
            "lease parent must be an existing canonical absolute directory"
        );
        ensure!(path.file_name().is_some(), "lease needs a filename");
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK)
            .open(path)
            .context("opening persistent lease file")?;
        let metadata = file.metadata()?;
        ensure!(
            metadata.is_file() && metadata.nlink() == 1,
            "lease must be a regular file without hard links"
        );
        ensure!(
            metadata.uid() == unsafe { libc::geteuid() } && metadata.mode() & 0o077 == 0,
            "lease must be private to its owner"
        );
        if unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } != 0 {
            return Err(std::io::Error::last_os_error())
                .context("cooperating lease unavailable (another owner may be active)");
        }
        let current = fs::symlink_metadata(path)?;
        ensure!(
            current.is_file() && current.dev() == metadata.dev() && current.ino() == metadata.ino(),
            "lease path changed during acquisition"
        );
        Ok(Self {
            file,
            path: path.to_path_buf(),
        })
    }
    pub fn raw_fd(&self) -> i32 {
        self.file.as_raw_fd()
    }
    pub fn path(&self) -> &Path {
        &self.path
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(tag = "status", rename_all = "snake_case", deny_unknown_fields)]
pub enum Observation<T> {
    Available { value: T },
    Unavailable { reason: String },
}
impl<T> Observation<T> {
    #[cfg(target_os = "macos")]
    fn from_result(result: Result<T>) -> Self {
        match result {
            Ok(value) => Self::Available { value },
            Err(error) => Self::Unavailable {
                reason: format!("{error:#}"),
            },
        }
    }
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct GuardSnapshot {
    pub epoch_ms: u64,
    pub platform: String,
    pub free_system_memory_percent: Observation<f64>,
    pub swap_used_bytes: Observation<u64>,
    pub disk_free_bytes: Observation<u64>,
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct GuardPolicy {
    pub launch_free_percent_min: f64,
    pub abort_free_percent_below: f64,
    pub abort_swap_growth_above_bytes: u64,
    pub max_duration_ms: u64,
    pub max_samples: usize,
    pub memory_method: String,
    pub swap_method: String,
    pub disk_method: String,
    pub limitations: Vec<String>,
    pub gpu_authorization: bool,
}
impl Default for GuardPolicy {
    fn default() -> Self {
        Self {
            launch_free_percent_min: LAUNCH_FREE_PERCENT,
            abort_free_percent_below: ABORT_FREE_PERCENT,
            abort_swap_growth_above_bytes: MAX_SWAP_GROWTH_BYTES,
            max_duration_ms: MAX_MONITOR_DURATION_MS,
            max_samples: MAX_SAMPLES,
            memory_method: "/usr/bin/memory_pressure -Q; system-wide free percentage indication, not RSS or GPU memory".into(),
            swap_method: "/usr/sbin/sysctl vm.swapusage; used bytes, growth from launch baseline".into(),
            disk_method: "statvfs(output directory): unprivileged available bytes; growth is filesystem-wide decrease from baseline".into(),
            limitations: vec![
                "Resource observations do not establish service idleness, named-scope exclusion, or whole-host GPU ownership.".into(),
                "Polling can miss short-lived jobs and overshoot memory/disk limits; disk decrease includes unrelated writers and is not a filesystem quota.".into(),
                "Collectors are read-only macOS commands with a 2-second bound each and bounded output; sequential observations are not atomic. Filesystem syscalls may stall.".into(),
                "Lease serializes cooperating project processes only; its persistent owner-private inode must never be unlinked or replaced. Inherited lock protects only descendants retaining the descriptor.".into(),
            ],
            gpu_authorization: false,
        }
    }
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct GuardDecision {
    pub allowed: bool,
    pub reasons: Vec<String>,
}
impl GuardDecision {
    fn result(&self) -> Result<()> {
        ensure!(self.allowed, "guard denied: {}", self.reasons.join("; "));
        Ok(())
    }
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum StopReason {
    DurationLimit,
    SampleLimit,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GuardSample {
    pub elapsed_ms: u64,
    pub snapshot: GuardSnapshot,
    pub stop_reason: Option<StopReason>,
    pub decision: GuardDecision,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GuardReport {
    pub schema_version: u32,
    pub config: GuardConfig,
    pub policy: GuardPolicy,
    pub baseline: GuardSnapshot,
    pub initial_decision: GuardDecision,
    pub samples: Vec<GuardSample>,
}
impl GuardReport {
    pub fn validate(&self) -> Result<()> {
        ensure!(
            self.schema_version == 3,
            "unsupported resource guard report version"
        );
        self.config.validate()?;
        ensure!(
            self.policy == GuardPolicy::default(),
            "guard policy does not match fixed safety policy"
        );
        ensure!(
            self.samples.len() <= MAX_SAMPLES,
            "guard history exceeds bound"
        );
        let initial = evaluate_launch(&self.config, &self.baseline);
        ensure!(
            self.initial_decision == initial,
            "initial guard decision contradicts observations"
        );
        ensure!(
            self.initial_decision.allowed || self.samples.is_empty(),
            "sampling continued after initial denial"
        );
        let mut previous_ms = 0;
        for (index, sample) in self.samples.iter().enumerate() {
            ensure!(
                sample.elapsed_ms >= previous_ms,
                "guard elapsed time regressed"
            );
            previous_ms = sample.elapsed_ms;
            let expected_stop = if sample.elapsed_ms >= MAX_MONITOR_DURATION_MS {
                Some(StopReason::DurationLimit)
            } else if index + 1 == MAX_SAMPLES {
                Some(StopReason::SampleLimit)
            } else {
                None
            };
            ensure!(
                sample.stop_reason == expected_stop,
                "invalid guard stopping bound"
            );
            let mut expected = evaluate_running(&self.config, &self.baseline, &sample.snapshot);
            apply_stop(&mut expected, sample.stop_reason.as_ref());
            ensure!(
                sample.decision == expected,
                "guard decision contradicts observations"
            );
            ensure!(
                sample.decision.allowed || index + 1 == self.samples.len(),
                "sampling continued after denial"
            );
        }
        Ok(())
    }
}

fn required<'a, T>(
    reading: &'a Observation<T>,
    name: &str,
    reasons: &mut Vec<String>,
) -> Option<&'a T> {
    match reading {
        Observation::Available { value } => Some(value),
        Observation::Unavailable { reason } => {
            reasons.push(format!("{name} unavailable: {reason}"));
            None
        }
    }
}
fn evaluate(
    config: &GuardConfig,
    baseline: Option<&GuardSnapshot>,
    sample: &GuardSnapshot,
) -> GuardDecision {
    let mut reasons = Vec::new();
    if let Err(error) = config.validate() {
        reasons.push(error.to_string());
    }
    if let Some(free) = required(
        &sample.free_system_memory_percent,
        "free-system-memory",
        &mut reasons,
    ) {
        let minimum = if baseline.is_some() {
            ABORT_FREE_PERCENT
        } else {
            LAUNCH_FREE_PERCENT
        };
        if !free.is_finite() || !(0.0..=100.0).contains(free) {
            reasons.push("free-system-memory percentage is invalid".into());
        } else if *free < minimum {
            reasons.push(format!("free-system-memory {free}% below {minimum}%"));
        }
    }
    let swap = required(&sample.swap_used_bytes, "swap", &mut reasons);
    let disk = required(&sample.disk_free_bytes, "disk", &mut reasons);
    if let Some(free) = disk
        && *free < config.min_disk_free_bytes
    {
        reasons.push("disk free bytes below configured minimum".into());
    }
    if let Some(base) = baseline {
        if let Some(before) = required(&base.swap_used_bytes, "baseline swap", &mut reasons)
            && swap.is_some_and(|now| now.saturating_sub(*before) > MAX_SWAP_GROWTH_BYTES)
        {
            reasons.push("swap growth exceeds 512 MiB".into());
        }
        if let Some(before) = required(&base.disk_free_bytes, "baseline disk", &mut reasons)
            && disk.is_some_and(|now| before.saturating_sub(*now) > config.max_disk_growth_bytes)
        {
            reasons.push("filesystem disk consumption exceeds configured growth limit".into());
        }
    }
    GuardDecision {
        allowed: reasons.is_empty(),
        reasons,
    }
}
pub fn evaluate_launch(config: &GuardConfig, sample: &GuardSnapshot) -> GuardDecision {
    evaluate(config, None, sample)
}
pub fn evaluate_running(
    config: &GuardConfig,
    baseline: &GuardSnapshot,
    sample: &GuardSnapshot,
) -> GuardDecision {
    let mut decision = evaluate(config, Some(baseline), sample);
    let initial = evaluate_launch(config, baseline);
    if !initial.allowed {
        decision.allowed = false;
        decision.reasons.extend(
            initial
                .reasons
                .into_iter()
                .map(|reason| format!("invalid launch baseline: {reason}")),
        );
    }
    decision
}
fn apply_stop(decision: &mut GuardDecision, stop: Option<&StopReason>) {
    if let Some(stop) = stop {
        decision.allowed = false;
        decision.reasons.push(
            match stop {
                StopReason::DurationLimit => "guard monitoring reached 600-second duration limit",
                StopReason::SampleLimit => "guard monitoring history capacity reached",
            }
            .into(),
        );
    }
}

pub struct GuardMonitor {
    report: GuardReport,
    output_dir: PathBuf,
    started: Instant,
    last_observation: Instant,
}
impl GuardMonitor {
    pub fn start(config: GuardConfig, output_dir: &Path) -> Result<Self> {
        config.validate()?;
        let started = Instant::now();
        let baseline = collect(&config, output_dir);
        let initial_decision = evaluate_launch(&config, &baseline);
        Ok(Self {
            report: GuardReport {
                schema_version: 3,
                config,
                policy: GuardPolicy::default(),
                baseline,
                initial_decision,
                samples: Vec::new(),
            },
            output_dir: output_dir.to_owned(),
            started,
            last_observation: Instant::now(),
        })
    }
    pub fn report(&self) -> &GuardReport {
        &self.report
    }
    pub fn sample_count(&self) -> usize {
        1 + self.report.samples.len()
    }
    pub fn initial_decision(&self) -> Result<()> {
        self.report.initial_decision.result()
    }
    pub fn check(&mut self) -> Result<()> {
        self.initial_decision()?;
        if let Some(last) = self.report.samples.last() {
            last.decision.result()?;
        }
        if self.last_observation.elapsed()
            < Duration::from_millis(self.report.config.sample_interval_ms)
            && self.started.elapsed() < Duration::from_millis(MAX_MONITOR_DURATION_MS)
        {
            return Ok(());
        }
        let snapshot = collect(&self.report.config, &self.output_dir);
        let elapsed_ms = self.started.elapsed().as_millis().min(u64::MAX as u128) as u64;
        let stop_reason = if elapsed_ms >= MAX_MONITOR_DURATION_MS {
            Some(StopReason::DurationLimit)
        } else if self.report.samples.len() + 1 == MAX_SAMPLES {
            Some(StopReason::SampleLimit)
        } else {
            None
        };
        let mut decision = evaluate_running(&self.report.config, &self.report.baseline, &snapshot);
        apply_stop(&mut decision, stop_reason.as_ref());
        self.report.samples.push(GuardSample {
            elapsed_ms,
            snapshot,
            stop_reason,
            decision,
        });
        self.last_observation = Instant::now();
        self.report.samples.last().unwrap().decision.result()
    }
    pub fn finish(self) -> GuardReport {
        self.report
    }
}

/// Checked parsing is public for deterministic platform-independent regression tests.
pub fn parse_memory_pressure(text: &str) -> Result<f64> {
    let values: Vec<_> = text
        .lines()
        .filter_map(|line| {
            line.trim()
                .strip_prefix("System-wide memory free percentage:")
        })
        .collect();
    ensure!(
        values.len() == 1,
        "memory_pressure lacks a unique free percentage"
    );
    let value: f64 = values[0]
        .trim()
        .strip_suffix('%')
        .context("memory percentage lacks units")?
        .parse()
        .context("invalid memory percentage")?;
    ensure!(
        value.is_finite() && (0.0..=100.0).contains(&value),
        "invalid memory percentage range"
    );
    Ok(value)
}
pub fn parse_swap_usage(text: &str) -> Result<u64> {
    let body = text
        .trim()
        .strip_prefix("vm.swapusage:")
        .context("unexpected sysctl swap source")?;
    let words: Vec<_> = body.split_whitespace().collect();
    let positions: Vec<_> = words
        .iter()
        .enumerate()
        .filter(|(_, word)| **word == "used")
        .map(|(index, _)| index)
        .collect();
    ensure!(positions.len() == 1, "swap output lacks unique used value");
    let index = positions[0];
    ensure!(
        words.get(index + 1) == Some(&"="),
        "invalid swap used separator"
    );
    let value = *words.get(index + 2).context("missing swap used amount")?;
    ensure!(value.is_ascii(), "invalid swap amount encoding");
    let (number, unit) = value.split_at(value.len().checked_sub(1).context("empty swap value")?);
    let multiplier: u64 = match unit {
        "K" => 1024,
        "M" => 1024 * 1024,
        "G" => 1024 * 1024 * 1024,
        "B" => 1,
        _ => bail!("unsupported swap units"),
    };
    let (whole, fraction) = number.split_once('.').unwrap_or((number, ""));
    ensure!(
        !whole.is_empty()
            && whole.bytes().all(|b| b.is_ascii_digit())
            && fraction.bytes().all(|b| b.is_ascii_digit())
            && fraction.len() <= 9,
        "invalid swap amount"
    );
    let whole: u64 = whole.parse()?;
    let fraction_value: u64 = if fraction.is_empty() {
        0
    } else {
        fraction.parse()?
    };
    whole
        .checked_mul(multiplier)
        .and_then(|bytes| {
            bytes.checked_add(fraction_value * multiplier / 10u64.pow(fraction.len() as u32))
        })
        .context("swap amount overflow")
}

fn collect(_config: &GuardConfig, output_dir: &Path) -> GuardSnapshot {
    let epoch_ms = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis()
        .min(u64::MAX as u128) as u64;
    #[cfg(target_os = "macos")]
    {
        GuardSnapshot {
            epoch_ms,
            platform: "macos".into(),
            free_system_memory_percent: Observation::from_result(
                collector("/usr/bin/memory_pressure", &["-Q"])
                    .and_then(|text| parse_memory_pressure(&text)),
            ),
            swap_used_bytes: Observation::from_result(
                collector("/usr/sbin/sysctl", &["vm.swapusage"])
                    .and_then(|text| parse_swap_usage(&text)),
            ),
            disk_free_bytes: Observation::from_result(disk_free(output_dir)),
        }
    }
    #[cfg(not(target_os = "macos"))]
    {
        let _ = output_dir;
        let reason = "required native collectors are implemented only for macOS";
        GuardSnapshot {
            epoch_ms,
            platform: std::env::consts::OS.into(),
            free_system_memory_percent: Observation::Unavailable {
                reason: reason.into(),
            },
            swap_used_bytes: Observation::Unavailable {
                reason: reason.into(),
            },
            disk_free_bytes: Observation::Unavailable {
                reason: reason.into(),
            },
        }
    }
}
#[cfg(target_os = "macos")]
fn disk_free(path: &Path) -> Result<u64> {
    use std::{ffi::CString, os::unix::ffi::OsStrExt};
    let path = CString::new(path.as_os_str().as_bytes())?;
    let mut stat = std::mem::MaybeUninit::<libc::statvfs>::uninit();
    ensure!(
        unsafe { libc::statvfs(path.as_ptr(), stat.as_mut_ptr()) } == 0,
        "disk statvfs unavailable: {}",
        std::io::Error::last_os_error()
    );
    let stat = unsafe { stat.assume_init() };
    u64::from(stat.f_bavail)
        .checked_mul(stat.f_frsize)
        .context("disk free byte count overflow")
}

#[cfg(target_os = "macos")]
fn collector(program: &str, args: &[&str]) -> Result<String> {
    use std::{
        io::Read,
        process::{Command, Stdio},
        thread,
    };
    let mut child = Command::new(program)
        .args(args)
        .env_clear()
        .env("LC_ALL", "C")
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .context("spawning read-only guard collector")?;
    // Every path after spawn kills/reaps only this collector, never a discovered PID.
    let result = (|| -> Result<String> {
        let mut stdout = child.stdout.take().context("missing collector stdout")?;
        let mut stderr = child.stderr.take().context("missing collector stderr")?;
        for fd in [stdout.as_raw_fd(), stderr.as_raw_fd()] {
            nonblocking(fd)?;
        }
        let deadline = Instant::now() + Duration::from_secs(2);
        let mut output = Vec::new();
        let mut stderr_bytes = 0usize;
        let mut buffer = [0u8; 8192];
        loop {
            ensure!(
                Instant::now() < deadline,
                "guard collector timed out after 2 seconds"
            );
            let mut stdout_eof = false;
            let mut stderr_eof = false;
            match stdout.read(&mut buffer) {
                Ok(0) => stdout_eof = true,
                Ok(count) => {
                    ensure!(
                        output.len() + count <= 1024 * 1024,
                        "guard collector stdout exceeded 1 MiB"
                    );
                    output.extend_from_slice(&buffer[..count]);
                }
                Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {}
                Err(error) if error.kind() == std::io::ErrorKind::Interrupted => {}
                Err(error) => return Err(error.into()),
            }
            match stderr.read(&mut buffer) {
                Ok(0) => stderr_eof = true,
                Ok(count) => {
                    stderr_bytes += count;
                    ensure!(
                        stderr_bytes <= 16 * 1024,
                        "guard collector stderr exceeded 16 KiB"
                    );
                }
                Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {}
                Err(error) if error.kind() == std::io::ErrorKind::Interrupted => {}
                Err(error) => return Err(error.into()),
            }
            if let Some(status) = child.try_wait()? {
                ensure!(
                    status.success(),
                    "guard collector exited unsuccessfully ({status})"
                );
                if stdout_eof && stderr_eof {
                    return String::from_utf8(output)
                        .context("guard collector output is not UTF-8");
                }
            }
            thread::sleep(Duration::from_millis(2));
        }
    })();
    if result.is_err() {
        let _ = child.kill();
    }
    let reaped = child.wait().context("reaping guard collector");
    match result {
        Ok(text) => {
            reaped?;
            Ok(text)
        }
        Err(error) => {
            let _ = reaped;
            Err(error)
        }
    }
}
#[cfg(target_os = "macos")]
fn nonblocking(fd: std::os::unix::io::RawFd) -> Result<()> {
    let flags = unsafe { libc::fcntl(fd, libc::F_GETFL) };
    ensure!(
        flags >= 0 && unsafe { libc::fcntl(fd, libc::F_SETFL, flags | libc::O_NONBLOCK) } >= 0,
        "setting collector pipe nonblocking failed"
    );
    Ok(())
}
