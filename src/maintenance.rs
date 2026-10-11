//! One independent guardian owns the transaction, experiment and ordered recovery.
use crate::{
    capture::{self, CaptureOptions, NativeCaptureControl},
    guards::Lease,
    native_guard::{self, GuardianClock, NativeBinding, ScopeAuthority, ScopePurpose},
    process_scope::{self, CommandSpec, OwnedProcess, ProcessIdentity, Settlement},
    restore_qualification::{AuthorizedPermissions, ReviewedPermissionInput},
    service_lifecycle::{
        RecoveryBudget, RecoveryControl, ServiceEnrollmentFailure, ServiceHandle, ServiceRole,
        ServiceSpec, AbsenceBinding,
    },
};
use anyhow::{Context, Result, bail, ensure};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    cell::RefCell,
    collections::BTreeMap,
    fs::{self, File, OpenOptions},
    io::{Read, Write},
    os::{
        fd::{AsRawFd, FromRawFd},
        unix::{
            fs::{DirBuilderExt, MetadataExt, OpenOptionsExt},
            net::UnixStream,
            process::CommandExt,
        },
    },
    path::{Path, PathBuf},
    process::{Command, Stdio},
    rc::Rc,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    thread,
    time::{Duration, Instant, SystemTime},
};

const JSON_BOUND: u64 = 16 * 1024 * 1024;
const OUTPUT_BOUND: u64 = 64 * 1024 * 1024;
const POLL: Duration = Duration::from_millis(20);

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Budgets {
    pub arming_ms: u64,
    pub studio_stop_ms: u64,
    pub omlx_stop_ms: u64,
    pub prelaunch_ms: u64,
    pub experiment_ms: u64,
    pub cleanup_ms: u64,
    pub omlx_restore_ms: u64,
    pub studio_restore_ms: u64,
    pub recovery_ms: u64,
    pub total_ms: u64,
}
impl Budgets {
    fn assigned_ms(&self) -> u64 {
        self.arming_ms
            + self.studio_stop_ms
            + self.omlx_stop_ms
            + self.prelaunch_ms
            + self.experiment_ms
            + self.cleanup_ms
            + self.omlx_restore_ms
            + self.studio_restore_ms
            + self.recovery_ms
    }
    fn validate(&self) -> Result<()> {
        let values = [
            (self.arming_ms, 60_000),
            (self.studio_stop_ms, 120_000),
            (self.omlx_stop_ms, 120_000),
            (self.prelaunch_ms, 90_000),
            (self.experiment_ms, 600_000),
            (self.cleanup_ms, 30_000),
            (self.omlx_restore_ms, 120_000),
            (self.studio_restore_ms, 120_000),
            (self.recovery_ms, 120_000),
        ];
        ensure!(
            values.iter().all(|(value, max)| *value > 0 && value <= max),
            "phase budget exceeds fixed policy"
        );
        ensure!(
            self.total_ms > 0 && self.total_ms <= 1_800_000,
            "invalid total ceiling"
        );
        ensure!(
            values.iter().map(|(value, _)| value).sum::<u64>() <= self.total_ms,
            "phase budgets exceed ceiling; borrowing is forbidden"
        );
        Ok(())
    }
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum Experiment {
    Cpu {
        command: CommandSpec,
    },
    Native {
        plan: Box<crate::native::PreparedPlan>,
    },
    NativeH3 {
        plan: Box<crate::h3_native::PreparedPlan>,
    },
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Transaction {
    pub schema_version: u32,
    pub transaction_id: String,
    pub purpose: ScopePurpose,
    pub evidence_root: PathBuf,
    pub lease_path: PathBuf,
    pub guardian_sha256: String,
    pub budgets: Budgets,
    pub services: Vec<ServiceSpec>,
    pub experiment: Experiment,
    pub reviewed_permissions: Option<ReviewedPermissionInput>,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Authorization {
    pub schema_version: u32,
    pub transaction_sha256: String,
    pub purpose: ScopePurpose,
    pub owner_uid: u32,
    pub not_before_unix_ms: u64,
    pub expires_unix_ms: u64,
    pub review_reference: String,
    pub service_interruption_approved: bool,
    pub cold_restore_approved: bool,
    pub interrupted_work_loss_approved: bool,
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Envelope {
    transaction: Transaction,
    authorization: Authorization,
    controller: ProcessIdentity,
}

pub fn digest<T: Serialize>(value: &T) -> Result<String> {
    Ok(format!("{:x}", Sha256::digest(serde_json::to_vec(value)?)))
}
pub fn executable_digest(path: &Path) -> Result<String> {
    let mut file = File::open(path)?;
    let before = file.metadata()?;
    ensure!(
        before.is_file() && before.len() <= 512 * 1024 * 1024,
        "executable identity outside bound"
    );
    let mut hash = Sha256::new();
    let mut buffer = [0u8; 65536];
    let mut bytes = 0u64;
    loop {
        let n = file.read(&mut buffer)?;
        if n == 0 {
            break;
        }
        bytes += n as u64;
        ensure!(bytes <= 512 * 1024 * 1024, "executable grew beyond bound");
        hash.update(&buffer[..n]);
    }
    let after = file.metadata()?;
    ensure!(
        bytes == before.len()
            && before.dev() == after.dev()
            && before.ino() == after.ino()
            && before.mtime() == after.mtime()
            && before.mtime_nsec() == after.mtime_nsec()
            && before.ctime() == after.ctime()
            && before.ctime_nsec() == after.ctime_nsec(),
        "executable changed while hashing"
    );
    Ok(format!("{:x}", hash.finalize()))
}
pub fn read_private<T: for<'de> Deserialize<'de>>(path: &Path) -> Result<T> {
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK)
        .open(path)?;
    let metadata = file.metadata()?;
    ensure!(
        metadata.is_file()
            && metadata.nlink() == 1
            && metadata.uid() == unsafe { libc::geteuid() }
            && metadata.mode() & 0o077 == 0
            && metadata.len() <= JSON_BOUND,
        "transaction/authorization must be bounded owner-private regular files"
    );
    let mut bytes = Vec::new();
    file.take(JSON_BOUND + 1).read_to_end(&mut bytes)?;
    ensure!(bytes.len() as u64 <= JSON_BOUND, "JSON exceeds bound");
    Ok(serde_json::from_slice(&bytes)?)
}
fn private_json(path: &Path, value: &impl Serialize) -> Result<()> {
    let bytes = serde_json::to_vec_pretty(value)?;
    ensure!(bytes.len() as u64 <= JSON_BOUND, "evidence exceeds bound");
    let temporary = path.with_extension("json.partial");
    let mut file = OpenOptions::new()
        .create_new(true)
        .write(true)
        .mode(0o600)
        .open(&temporary)?;
    file.write_all(&bytes)?;
    file.sync_all()?;
    // Publish complete bytes without replacing any prior evidence/consumption record.
    fs::hard_link(&temporary, path)?;
    fs::remove_file(&temporary)?;
    Ok(())
}
impl Transaction {
    pub fn validate(&self) -> Result<()> {
        ensure!(
            self.schema_version == 1
                && !self.transaction_id.is_empty()
                && self.transaction_id.len() <= 128
                && self
                    .transaction_id
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b == b'-'),
            "invalid transaction identity"
        );
        self.budgets.validate()?;
        ensure!(
            native_guard::valid_hash(&self.guardian_sha256),
            "invalid guardian executable identity"
        );
        ensure!(
            self.evidence_root.is_absolute() && self.lease_path.is_absolute(),
            "scope paths must be absolute"
        );
        ensure!(
            self.services.len() == 2
                && self.services[0].role() == ServiceRole::Studio
                && self.services[1].role() == ServiceRole::Omlx,
            "exact Studio/oMLX named scope required"
        );
        for service in &self.services {
            service.validate(self.purpose)?;
        }
        if matches!(self.services[1], ServiceSpec::OmlxUnmanaged { .. }) {
            ensure!(
                self.reviewed_permissions.is_none(),
                "unmanaged oMLX excludes private running-service permissions"
            );
        }
        match (&self.experiment, self.purpose) {
            (Experiment::Cpu { command }, ScopePurpose::Cpu) => {
                command.validate()?;
                ensure!(
                    self.reviewed_permissions.is_none(),
                    "CPU scope cannot carry live credential permissions"
                );
                ensure!(
                    self.lease_path.parent() == self.evidence_root.parent()
                        && self
                            .lease_path
                            .file_name()
                            .is_some_and(|name| name == ".cpu-maintenance.lock"),
                    "CPU transaction must use its own temporary-root lease"
                );
                for service in &self.services {
                    if let ServiceSpec::OwnedCpu {
                        command,
                        restore_command,
                        gui_command,
                        ..
                    } = service
                    {
                        validate_cpu_command(command)?;
                        validate_cpu_command(restore_command)?;
                        if let Some(gui) = gui_command {
                            validate_cpu_command(gui)?;
                        }
                    } else if let ServiceSpec::OmlxAbsent { binding: AbsenceBinding::Cpu { probe, .. } } = service {
                        validate_cpu_command(probe)?;
                        ensure!(
                            probe.args == ["maintenance-participant", "--mode", "absence-probe", "--duration-ms", "1"],
                            "CPU absence requires the bounded metadata fixture probe"
                        );
                    } else if !matches!(service, ServiceSpec::OmlxUnmanaged { purpose: ScopePurpose::Cpu, .. }) {
                        bail!("CPU transaction contains a live service");
                    }
                }
                validate_cpu_command(command)?;
            }
            (
                Experiment::Native { .. } | Experiment::NativeH3 { .. },
                ScopePurpose::Native,
            ) => {
                let timeout_ms = match &self.experiment {
                    Experiment::Native { plan } => {
                        plan.validate_enrolled()?;
                        plan.command.timeout_ms
                    }
                    Experiment::NativeH3 { plan } => {
                        plan.validate_enrolled()?;
                        plan.command.timeout_ms
                    }
                    Experiment::Cpu { .. } => unreachable!(),
                };
                ensure!(
                    self.budgets.experiment_ms == timeout_ms,
                    "native phase and invocation deadlines differ"
                );
                if let ServiceSpec::Omlx { qualification, .. } = &self.services[1] {
                    let reviewed = self.reviewed_permissions.as_ref().context(
                        "native activation denied before effects: explicit reviewed X2/X3 permission absent"
                    )?;
                    qualification.validate_reviewed_permissions(Some(reviewed))?;
                } else {
                    ensure!(
                        matches!(self.services[1],
                            ServiceSpec::OmlxAbsent { binding: AbsenceBinding::Native }
                            | ServiceSpec::OmlxUnmanaged { purpose: ScopePurpose::Native, .. }),
                        "native transaction requires explicit running, absent or acknowledged unmanaged oMLX scope"
                    );
                    ensure!(
                        self.reviewed_permissions.is_none(),
                        "absent or unmanaged oMLX cannot carry private running-service permissions"
                    );
                }
            }
            _ => bail!("experiment purpose mismatch"),
        }
        Ok(())
    }
}
fn validate_cpu_command(command: &CommandSpec) -> Result<()> {
    command.validate()?;
    ensure!(
        command.args.first().is_some_and(|arg| arg == "maintenance-participant")
            && command.environment.is_empty(),
        "CPU scope only permits this executable's finite CPU participant, with empty environment"
    );
    Ok(())
}
pub fn validate_authorization(
    transaction: &Transaction,
    authorization: &Authorization,
) -> Result<()> {
    transaction.validate()?;
    ensure!(
        authorization.schema_version == 1
            && authorization.transaction_sha256 == digest(transaction)?
            && authorization.purpose == transaction.purpose
            && authorization.owner_uid == unsafe { libc::geteuid() },
        "authorization transaction/purpose/owner mismatch"
    );
    ensure!(
        !authorization.review_reference.trim().is_empty()
            && authorization.review_reference.len() <= 2048,
        "explicit authorization review reference required"
    );
    ensure!(
        authorization.service_interruption_approved
            && authorization.cold_restore_approved
            && authorization.interrupted_work_loss_approved,
        "maintenance effects not authorized"
    );
    let now = native_guard::unix_ms()?;
    ensure!(
        authorization.not_before_unix_ms <= now
            && now < authorization.expires_unix_ms
            && authorization.expires_unix_ms - authorization.not_before_unix_ms <= 1_800_000,
        "authorization outside exact validity interval"
    );
    ensure!(
        authorization.expires_unix_ms - now >= transaction.budgets.assigned_ms(),
        "authorization cannot cover assigned phase budgets"
    );
    ensure!(
        executable_digest(&std::env::current_exe()?)? == transaction.guardian_sha256,
        "guardian binary differs from approved transaction"
    );
    Ok(())
}

/// Validate all no-effect gates before creating a guardian, lease, service or capture.
fn guardian_environment(transaction: &Transaction) -> Result<BTreeMap<String, String>> {
    let mut environment = BTreeMap::new();
    if transaction.purpose == ScopePurpose::Cpu {
        let executable = std::env::current_exe()?;
        let check = |command: &CommandSpec| -> Result<()> {
            ensure!(command.executable == executable, "CPU participant executable differs from guardian");
            Ok(())
        };
        for service in &transaction.services {
            match service {
                ServiceSpec::OwnedCpu { command, restore_command, gui_command, .. } => {
                    check(command)?;
                    check(restore_command)?;
                    if let Some(gui) = gui_command { check(gui)?; }
                }
                ServiceSpec::OmlxAbsent { binding: AbsenceBinding::Cpu { probe, .. } } => check(probe)?,
                ServiceSpec::OmlxUnmanaged { purpose: ScopePurpose::Cpu, .. } => {}
                _ => bail!("CPU service binding mismatch"),
            }
        }
        if let Experiment::Cpu { command } = &transaction.experiment { check(command)?; }
    }
    if transaction.purpose == ScopePurpose::Native {
        // Only after exact authorization. Read these four names from OUR process,
        // never another process's environment or an inherited arbitrary map.
        for key in ["HOME", "USER", "LOGNAME", "TMPDIR"] {
            let value = std::env::var(key).map_err(|_| {
                anyhow::anyhow!("PF3 allowlisted guardian variable {key} unavailable")
            })?;
            environment.insert(key.into(), value);
        }
        environment.insert("PATH".into(), "/usr/bin:/bin:/usr/sbin:/sbin".into());
        if let ServiceSpec::Omlx { launcher, .. } = &transaction.services[1] {
            ensure!(
                environment == launcher.environment,
                "PF3 constructed environment differs from exact reviewed launch plan"
            );
        }
    }
    Ok(environment)
}

struct ControllerSignals([Option<signal_hook::SigId>; 2]);
impl Drop for ControllerSignals {
    fn drop(&mut self) {
        for registration in &mut self.0 {
            if let Some(id) = registration.take() {
                signal_hook::low_level::unregister(id);
            }
        }
    }
}

pub fn run_controller(transaction: Transaction, authorization: Authorization) -> Result<PathBuf> {
    validate_authorization(&transaction, &authorization)?;
    let environment = guardian_environment(&transaction)?;
    let parent = transaction
        .evidence_root
        .parent()
        .context("missing scope parent")?;
    let metadata = fs::symlink_metadata(parent)?;
    ensure!(
        metadata.is_dir()
            && metadata.uid() == unsafe { libc::geteuid() }
            && metadata.mode() & 0o077 == 0
            && fs::canonicalize(parent)? == parent,
        "scope parent must be existing canonical owner-private directory"
    );
    fs::DirBuilder::new()
        .mode(0o700)
        .create(&transaction.evidence_root)?;
    let receipt = transaction.evidence_root.join("receipt.json");
    private_json(
        &transaction.evidence_root.join("transaction.json"),
        &transaction,
    )?;
    private_json(
        &transaction.evidence_root.join("authorization.json"),
        &authorization,
    )?;
    let controller =
        process_scope::observe(std::process::id())?.context("controller identity unavailable")?;
    let envelope = Envelope {
        transaction,
        authorization,
        controller,
    };
    let bytes = serde_json::to_vec(&envelope)?;
    ensure!(
        bytes.len() as u64 <= JSON_BOUND,
        "guardian envelope too large"
    );
    let (mut controller_link, guardian_link) = UnixStream::pair()?;
    let fd = guardian_link.as_raw_fd();
    let log = OpenOptions::new()
        .create_new(true)
        .write(true)
        .mode(0o600)
        .open(envelope.transaction.evidence_root.join("guardian.log"))?;
    let mut command = Command::new(std::env::current_exe()?);
    command
        .args(["maintenance-guardian", "--control-fd", &fd.to_string()])
        .env_clear()
        .envs(environment)
        .stdin(Stdio::null())
        .stdout(log.try_clone()?)
        .stderr(log);
    unsafe {
        command.pre_exec(move || {
            if libc::setsid() < 0 || libc::fcntl(fd, libc::F_SETFD, 0) < 0 {
                return Err(std::io::Error::last_os_error());
            }
            Ok(())
        });
    }
    let mut guardian = command.spawn().context("creating independent guardian")?;
    drop(guardian_link);
    controller_link.set_write_timeout(Some(Duration::from_secs(2)))?;
    controller_link.write_all(&(bytes.len() as u32).to_be_bytes())?;
    controller_link.write_all(&bytes)?;
    controller_link.set_nonblocking(true)?;
    println!(
        "{}",
        serde_json::json!({"guardian_pid":guardian.id(),"controller_pid":std::process::id(),"receipt":receipt})
    );
    std::io::stdout().flush()?;
    let cancelled = Arc::new(AtomicBool::new(false));
    let mut signals = ControllerSignals([None, None]);
    for (index, signal) in [signal_hook::consts::SIGINT, signal_hook::consts::SIGTERM]
        .into_iter()
        .enumerate()
    {
        signals.0[index] = Some(signal_hook::flag::register(signal, cancelled.clone())?);
    }
    let status = loop {
        if let Some(status) = guardian.try_wait()? {
            break status;
        }
        let byte = if cancelled.load(Ordering::Relaxed) {
            b'C'
        } else {
            b'H'
        };
        match controller_link.write(&[byte]) {
            Ok(_) => {}
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {}
            Err(_) => {
                break guardian.wait()?;
            }
        }
        thread::sleep(Duration::from_millis(100));
    };
    ensure!(
        receipt.exists(),
        "guardian exited without terminal evidence; no recovery inference permitted"
    );
    ensure!(
        status.success(),
        "guardian terminal infrastructure failed ({status}); retained receipt is not successful completion authority"
    );
    Ok(receipt)
}

struct Runtime {
    clock: GuardianClock,
    wall_ceiling: SystemTime,
    link: UnixStream,
    controller: ProcessIdentity,
    last_heartbeat: Instant,
    last_scope_observation: Option<Instant>,
    lost: Option<String>,
    services: Vec<ServiceHandle>,
    service_recovery: Rc<RefCell<RecoveryBudget>>,
    authority: ScopeAuthority,
    journal: File,
    journal_bytes: u64,
}
impl Runtime {
    fn event(&mut self, phase: &str, value: impl Serialize) -> Result<()> {
        let mut bytes = serde_json::to_vec(
            &serde_json::json!({"guardian_elapsed_ms":self.clock.elapsed_ms(),"phase":phase,"evidence":value}),
        )?;
        bytes.push(b'\n');
        ensure!(
            self.journal_bytes + bytes.len() as u64 <= OUTPUT_BOUND,
            "guardian journal bound reached"
        );
        self.journal.write_all(&bytes)?;
        self.journal_bytes += bytes.len() as u64;
        self.journal.flush()?;
        Ok(())
    }
    fn recovery_tick(&mut self) -> Result<()> {
        self.clock.recovery_check()?;
        ensure!(
            Instant::now() < self.clock.hard_deadline() && SystemTime::now() < self.wall_ceiling,
            "automation ceiling expired; manual recovery required"
        );
        Ok(())
    }
    fn tick(&mut self) -> Result<()> {
        self.recovery_tick()?;
        self.clock.check()?;
        if let Some(reason) = &self.lost {
            bail!("controller authority revoked: {reason}");
        }
        let mut bytes = [0u8; 128];
        loop {
            match self.link.read(&mut bytes) {
                Ok(0) => {
                    self.lost = Some("controller EOF".into());
                    break;
                }
                Ok(n) => {
                    ensure!(
                        bytes[..n].iter().all(|byte| *byte == b'H' || *byte == b'C'),
                        "invalid controller protocol"
                    );
                    if bytes[..n].contains(&b'C') {
                        self.lost = Some("controller cancelled".into());
                        break;
                    }
                    self.last_heartbeat = Instant::now();
                }
                Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => break,
                Err(error) if error.kind() == std::io::ErrorKind::Interrupted => continue,
                Err(error) => {
                    self.lost = Some(format!("controller channel lost: {error}"));
                    break;
                }
            }
        }
        if self.last_heartbeat.elapsed() > native_guard::MAX_AUTHORITY_GAP {
            self.lost = Some("controller heartbeat expired".into());
        }
        if let Some(reason) = &self.lost {
            bail!("controller authority revoked: {reason}");
        }
        let current =
            process_scope::observe(self.controller.pid)?.context("controller vanished")?;
        ensure!(
            self.controller.same_process(&current),
            "controller identity changed"
        );
        Ok(())
    }
    fn active_tick(&mut self) -> Result<()> {
        self.tick()?;
        if self
            .last_scope_observation
            .is_some_and(|at| at.elapsed() < Duration::from_millis(100))
        {
            return Ok(());
        }
        let reading = self.authority.collect(
            &mut self.services,
            &mut self.clock,
            self.wall_ceiling,
            Rc::clone(&self.service_recovery),
        );
        let result = if reading.decision.allowed {
            Ok(())
        } else {
            Err(anyhow::anyhow!(
                "named scope revoked: {}",
                reading.decision.reasons.join("; ")
            ))
        };
        self.event("scope_observation", reading)?;
        if result.is_ok() {
            self.last_scope_observation = Some(Instant::now());
        }
        result
    }
}

/// Hidden process entrypoint. A private IPC envelope is necessary, not sufficient:
/// exact authorization and current identities are revalidated here before effects.
pub fn guardian_main(control_fd: i32) -> Result<()> {
    ensure!(control_fd > 2, "guardian requires private control socket");
    let flags = unsafe { libc::fcntl(control_fd, libc::F_GETFD) };
    ensure!(
        flags >= 0
            && unsafe { libc::fcntl(control_fd, libc::F_SETFD, flags | libc::FD_CLOEXEC) } == 0,
        "protecting guardian control descriptor failed"
    );
    let mut socket_type = 0_i32;
    let mut socket_type_size = std::mem::size_of::<i32>() as libc::socklen_t;
    ensure!(
        unsafe {
            libc::getsockopt(
                control_fd,
                libc::SOL_SOCKET,
                libc::SO_TYPE,
                (&mut socket_type as *mut i32).cast(),
                &mut socket_type_size,
            )
        } == 0
            && socket_type == libc::SOCK_STREAM,
        "guardian control must be a stream socket"
    );
    let mut link = unsafe { UnixStream::from_raw_fd(control_fd) };
    link.set_read_timeout(Some(Duration::from_secs(2)))?;
    let mut size = [0u8; 4];
    link.read_exact(&mut size)?;
    let size = u32::from_be_bytes(size) as usize;
    ensure!(
        size > 0 && size as u64 <= JSON_BOUND,
        "invalid envelope size"
    );
    let mut bytes = vec![0; size];
    link.read_exact(&mut bytes)?;
    let envelope: Envelope = serde_json::from_slice(&bytes)?;
    validate_authorization(&envelope.transaction, &envelope.authorization)?;
    guardian_environment(&envelope.transaction)?;
    ensure!(
        unsafe { libc::getppid() } as u32 == envelope.controller.pid,
        "guardian controller parent differs"
    );
    process_scope::verify_identity(&envelope.controller)?;
    link.set_read_timeout(None)?;
    link.set_nonblocking(true)?;
    let transaction = envelope.transaction;
    let identity = digest(&transaction)?;
    private_json(
        &transaction
            .evidence_root
            .join("authorization-consumed.json"),
        &serde_json::json!({"transaction_sha256":identity,"guardian_pid":std::process::id()}),
    )?;
    let journal = OpenOptions::new()
        .create_new(true)
        .write(true)
        .mode(0o600)
        .open(transaction.evidence_root.join("guardian.jsonl"))?;
    let remaining = envelope
        .authorization
        .expires_unix_ms
        .checked_sub(native_guard::unix_ms()?)
        .context("authorization expired while arming")?
        .min(transaction.budgets.total_ms);
    let wall_ceiling = (std::time::UNIX_EPOCH
        + Duration::from_millis(envelope.authorization.expires_unix_ms))
    .min(SystemTime::now() + Duration::from_millis(transaction.budgets.total_ms));
    let clock = GuardianClock::new(Duration::from_millis(remaining))?;
    let service_recovery = Rc::new(RefCell::new(RecoveryBudget::new(
        Duration::from_millis(transaction.budgets.recovery_ms),
        clock.hard_deadline(),
    )));
    let runtime = RefCell::new(Runtime {
        clock,
        wall_ceiling,
        link,
        controller: envelope.controller,
        last_heartbeat: Instant::now(),
        last_scope_observation: None,
        lost: None,
        services: Vec::new(),
        service_recovery: Rc::clone(&service_recovery),
        authority: ScopeAuthority::new(identity.clone())?,
        journal,
        journal_bytes: 0,
    });
    let mut recovery_tick = || runtime.borrow_mut().recovery_tick();
    let mut recovery = RecoveryControl::new(Rc::clone(&service_recovery), &mut recovery_tick);
    let mut settlement: Option<Settlement> = None;
    let mut capture_directory = None;
    let mut creation_attempted = false;
    let mut native_helper_accounting_complete = true;
    let mut native_helper_dispositions = Vec::new();
    let mut restored = false;
    let mut recovery_failure = None;
    let mut lease = None;
    let outcome = (|| -> Result<()> {
        runtime.borrow_mut().tick()?;
        let permissions = transaction
            .reviewed_permissions
            .as_ref()
            .map(|reviewed| {
                AuthorizedPermissions::from_transaction_authorization(reviewed, &identity)
            })
            .transpose()?;
        lease = Some(Lease::acquire(&transaction.lease_path)?);
        let arming = runtime
            .borrow()
            .clock
            .phase_deadline(Duration::from_millis(transaction.budgets.arming_ms));
        // oMLX's complete pre-stop fidelity gate runs before any service is stopped.
        let omlx = ServiceHandle::enroll(
            &transaction.services[1],
            transaction.purpose,
            permissions.as_ref(),
            arming,
            &mut || runtime.borrow_mut().tick(),
            &mut recovery,
        )?;
        runtime.borrow_mut().services.push(omlx);
        if runtime.borrow().services[0].is_no_control_scope() {
            let observation = runtime.borrow().services[0].last_observation();
            let label = if observation.unmanaged.is_some() {
                "omlx_unmanaged_admission"
            } else {
                "omlx_absence_admission"
            };
            runtime.borrow_mut().event(label, observation)?;
        }
        let studio = ServiceHandle::enroll(
            &transaction.services[0],
            transaction.purpose,
            permissions.as_ref(),
            arming,
            &mut || runtime.borrow_mut().tick(),
            &mut recovery,
        )?;
        runtime.borrow_mut().services.insert(0, studio);
        for (index, budget, label) in [
            (0, transaction.budgets.studio_stop_ms, "studio_stop"),
            (1, transaction.budgets.omlx_stop_ms, "omlx_stop"),
        ] {
            let deadline = runtime
                .borrow()
                .clock
                .phase_deadline(Duration::from_millis(budget));
            let mut services = std::mem::take(&mut runtime.borrow_mut().services);
            let result = (|| {
                for service in &mut services {
                    service
                        .check_named_scope_absence(deadline, &mut || runtime.borrow_mut().tick())?;
                    service.observe_absent_scope(deadline, &mut || runtime.borrow_mut().tick(), &mut recovery)?;
                }
                if services[index].is_no_control_scope() {
                    Ok(services[index].last_observation())
                } else {
                    services[index].stop(deadline, &mut || runtime.borrow_mut().tick(), &mut recovery)
                }
            })();
            runtime.borrow_mut().services = services;
            let observation = result?;
            let label = if observation.unmanaged.is_some() {
                "omlx_unmanaged_prelaunch_no_control"
            } else if observation.absence.is_some() {
                "omlx_absence_prelaunch"
            } else { label };
            runtime.borrow_mut().event(label, observation)?;
        }
        let prelaunch = runtime
            .borrow()
            .clock
            .phase_deadline(Duration::from_millis(transaction.budgets.prelaunch_ms));
        runtime.borrow_mut().active_tick()?;
        ensure!(Instant::now() < prelaunch, "prelaunch deadline expired");
        match &transaction.experiment {
            Experiment::Cpu { command } => {
                let deadline = runtime
                    .borrow()
                    .clock
                    .phase_deadline(Duration::from_millis(transaction.budgets.experiment_ms));
                let mut out = OpenOptions::new()
                    .create_new(true)
                    .write(true)
                    .mode(0o600)
                    .open(transaction.evidence_root.join("experiment.stdout"))?;
                let mut err = OpenOptions::new()
                    .create_new(true)
                    .write(true)
                    .mode(0o600)
                    .open(transaction.evidence_root.join("experiment.stderr"))?;
                runtime.borrow_mut().active_tick()?;
                ensure!(
                    Instant::now() < prelaunch,
                    "CPU setup exceeded prelaunch slot"
                );
                let spawned = OwnedProcess::spawn_with_lease(
                    command,
                    deadline.min(prelaunch),
                    &mut || runtime.borrow_mut().active_tick(),
                    lease.as_ref().context("CPU lease lost")?.raw_fd(),
                );
                let attempt = spawned?;
                creation_attempted = true;
                let mut child = attempt.process;
                let mut stdout = child.stdout.take();
                let mut stderr = child.stderr.take();
                let mut remaining = OUTPUT_BOUND;
                let execution = (|| -> Result<()> {
                    runtime.borrow_mut().event("experiment_creation_attempt",
                        serde_json::json!({"pid":child.pid(),"failure":attempt.failure,"identity":child.identity().ok()}))?;
                    if let Some(failure) = attempt.failure {
                        bail!("owned experiment launch failed: {failure}");
                    }
                    let stdout = stdout.as_mut().context("CPU stdout absent")?;
                    let stderr = stderr.as_mut().context("CPU stderr absent")?;
                    runtime
                        .borrow_mut()
                        .event("experiment_created", child.identity()?)?;
                    loop {
                        runtime.borrow_mut().active_tick()?;
                        ensure!(
                            Instant::now() < deadline,
                            "experiment phase deadline expired"
                        );
                        drain(stdout, &mut out, &mut remaining)?;
                        drain(stderr, &mut err, &mut remaining)?;
                        child.check_membership()?;
                        if child.exited_unreaped()? {
                            break;
                        }
                        thread::sleep(POLL);
                    }
                    Ok(())
                })();
                let cleanup = runtime
                    .borrow()
                    .clock
                    .phase_deadline(Duration::from_millis(transaction.budgets.cleanup_ms));
                settlement =
                    Some(child.settle(cleanup, Duration::from_millis(100), &mut || {
                        runtime.borrow_mut().recovery_tick()
                    })?);
                if let Some(stdout) = stdout.as_mut() {
                    drain(stdout, &mut out, &mut remaining)?;
                }
                if let Some(stderr) = stderr.as_mut() {
                    drain(stderr, &mut err, &mut remaining)?;
                }
                runtime
                    .borrow_mut()
                    .event("experiment_settlement", &settlement)?;
                execution?;
                let status = settlement.as_ref().context("settlement absent")?;
                ensure!(
                    status.complete && status.exit_code == Some(0),
                    "CPU experiment failed or ownership incomplete"
                );
            }
            experiment @ (Experiment::Native { .. } | Experiment::NativeH3 { .. }) => {
                let invocation_sha256 = match experiment {
                    Experiment::Native { plan } => {
                        plan.verify_files()?;
                        plan.sha256.clone()
                    }
                    Experiment::NativeH3 { plan } => {
                        plan.verify_files()?;
                        plan.sha256.clone()
                    }
                    Experiment::Cpu { .. } => unreachable!(),
                };
                runtime.borrow_mut().last_scope_observation = None;
                runtime.borrow_mut().active_tick()?;
                ensure!(
                    Instant::now() < prelaunch,
                    "native preparation exceeded prelaunch slot"
                );
                let mut tick = || runtime.borrow_mut().active_tick();
                let mut recovery_tick = || runtime.borrow_mut().recovery_tick();
                let mut control = NativeCaptureControl {
                    binding: NativeBinding {
                        invocation_sha256,
                        transaction_sha256: identity.clone(),
                        guardian_pid: std::process::id(),
                        omlx_unmanaged: match &transaction.services[1] {
                            ServiceSpec::OmlxUnmanaged { acknowledgement, .. } => Some(*acknowledgement),
                            _ => None,
                        },
                    },
                    tick: &mut tick,
                    recovery_tick: &mut recovery_tick,
                    cleanup_budget: Duration::from_millis(transaction.budgets.cleanup_ms),
                    automation_deadline: runtime.borrow().clock.hard_deadline(),
                    prelaunch_deadline: prelaunch,
                    creation_attempted: false,
                    directory: None,
                    settlement: None,
                    helper_accounting_complete: true,
                    helper_dispositions: Vec::new(),
                };
                let result = match experiment {
                    Experiment::Native { plan } => {
                        let command = &plan.command;
                        capture::capture_native_guarded(
                            command.workload.clone(),
                            CaptureOptions {
                                root: command.output_root.clone(),
                                executable: command.python.selected_path.clone(),
                                args: command.python_arguments.clone(),
                                env: BTreeMap::new(),
                                timeout: Duration::from_millis(transaction.budgets.experiment_ms),
                                max_output_bytes: command.max_output_bytes,
                            },
                            Arc::new(AtomicBool::new(false)),
                            command.guard_config.clone().context("resource policy absent")?,
                            lease.as_ref().context("native lease lost")?,
                            &mut control,
                        )
                    }
                    Experiment::NativeH3 { plan } => crate::h3_capture::run(
                        plan,
                        lease.as_ref().context("native lease lost")?,
                        &mut control,
                    ),
                    Experiment::Cpu { .. } => unreachable!(),
                };
                creation_attempted = control.creation_attempted;
                settlement = control.settlement.take();
                capture_directory = control.directory.take();
                native_helper_accounting_complete = control.helper_accounting_complete;
                native_helper_dispositions = std::mem::take(&mut control.helper_dispositions);
                let directory = result?;
                let record = capture::inspect(&directory)?;
                capture_directory = Some(directory);
                ensure!(
                    record.is_success(),
                    "native capture failed: {:?}",
                    record.failure
                );
            }
        }
        Ok(())
    })();
    // Observation-helper failures return promptly so capture can stop its
    // experiment first. Continue their retained ownership within the SAME
    // recovery slot before considering any conflicting service restoration.
    if let Err(error) = recovery.finish_pending() {
        recovery_failure = Some(format!(
            "deferred service helper cleanup incomplete: {error:#}"
        ));
    }
    let enrollment_failure = outcome
        .as_ref()
        .err()
        .and_then(|error| error.downcast_ref::<ServiceEnrollmentFailure>())
        .map(|failure| failure.observation.clone());
    // Authority loss is sticky for the experiment. Recovery is a separately
    // authorized action; it cannot erase failure or run before proven settlement.
    let safe_to_restore = recovery.complete()
        && native_helper_accounting_complete
        && (!creation_attempted || settlement.as_ref().is_some_and(|value| value.complete));
    if safe_to_restore && runtime.borrow().services.len() == 2 {
        let result = (|| -> Result<()> {
            for (index, budget, label) in [
                (1, transaction.budgets.omlx_restore_ms, "omlx_restore"),
                (0, transaction.budgets.studio_restore_ms, "studio_restore"),
            ] {
                let deadline = runtime
                    .borrow()
                    .clock
                    .phase_deadline(Duration::from_millis(budget));
                let mut services = std::mem::take(&mut runtime.borrow_mut().services);
                let result = (|| {
                    // Absence failures revoke experiment authority, never the
                    // separately authorized recovery of our interrupted Studio.
                    if services[index].is_no_control_scope() {
                        return Ok(services[index].last_observation());
                    }
                    for service in &mut services {
                        if !service.is_no_control_scope() {
                            service.check_named_scope_absence(deadline, &mut || {
                                runtime.borrow_mut().recovery_tick()
                            })?;
                        }
                    }
                    services[index].restore(
                        deadline,
                        &mut || runtime.borrow_mut().recovery_tick(),
                        &mut recovery,
                    )
                })();
                runtime.borrow_mut().services = services;
                let observation = result?;
                ensure!(
                    observation.absence.is_some() || observation.unmanaged.is_some()
                        || (observation.restored && observation.failure.is_none()),
                    "restore unqualified; no next callback"
                );
                let label = if observation.unmanaged.is_some() {
                    "omlx_unmanaged_recovery_no_control"
                } else if observation.absence.is_some() {
                    "omlx_absence_recovery_no_control"
                } else { label };
                runtime.borrow_mut().event(label, observation)?;
            }
            Ok(())
        })();
        match result {
            Ok(()) => restored = true,
            Err(error) => recovery_failure = Some(format!("{error:#}")),
        }
    } else if creation_attempted || !recovery.complete() || !native_helper_accounting_complete {
        recovery_failure =
            Some("experiment/helper settlement unproved: all restoration withheld".into());
    }
    // Disposal of this transaction's CPU fixtures is not production recovery.
    if transaction.purpose == ScopePurpose::Cpu {
        let mut services = std::mem::take(&mut runtime.borrow_mut().services);
        for service in services.iter_mut().rev() {
            if let Err(error) = service.finish_owned_cpu(&mut recovery) {
                recovery_failure
                    .get_or_insert_with(|| format!("owned CPU fixture disposal failed: {error:#}"));
            }
        }
        runtime.borrow_mut().services = services;
    }
    // Final evidence remains independent of recovery and accounting. In
    // particular an appearing foreign service is never stopped or "restored".
    let mut final_absence_failure = None;
    {
        let deadline = runtime.borrow().clock.phase_deadline(Duration::from_millis(500));
        let mut services = std::mem::take(&mut runtime.borrow_mut().services);
        for service in &mut services {
            if let Err(error) = service.observe_absent_scope(
                deadline, &mut || runtime.borrow_mut().recovery_tick(), &mut recovery,
            ) {
                final_absence_failure = Some(format!("{error:#}"));
            }
        }
        runtime.borrow_mut().services = services;
    }
    if !recovery.complete() {
        recovery_failure.get_or_insert_with(|| {
            "service helper accounting remains incomplete; no retry or budget extension".into()
        });
    }
    let success = outcome.is_ok() && restored && recovery_failure.is_none() && final_absence_failure.is_none();
    let service_outcomes: Vec<_> = runtime
        .borrow()
        .services
        .iter()
        .map(ServiceHandle::last_observation)
        .collect();
    private_json(
        &transaction.evidence_root.join("service-outcomes.json"),
        &service_outcomes,
    )?;
    let receipt = serde_json::json!({
        "schema_version":1,
        "kind":if transaction.purpose==ScopePurpose::Cpu{"cpu_maintenance_transaction"}else{"native_maintenance_transaction"},
        "transaction_sha256":identity,"transaction_id":transaction.transaction_id,
        "guardian_pid":std::process::id(),"controller_identity":runtime.borrow().controller,
        "success":success,"experiment_failure":outcome.err().map(|error|format!("{error:#}")),
        "creation_attempted":creation_attempted,"settlement":settlement,"restored":restored,
        "recovery_failure":recovery_failure,"capture_directory":capture_directory,
        "final_absence_failure":final_absence_failure,
        "omlx_unmanaged":service_outcomes.iter()
            .find(|observation| observation.role == ServiceRole::Omlx)
            .and_then(|observation| observation.unmanaged.as_ref()),
        "service_enrollment_failure":enrollment_failure,
        "service_process_dispositions":recovery.observations(),
        "service_accounting_complete":recovery.complete(),
        "native_helper_accounting_complete":native_helper_accounting_complete,
        "native_helper_dispositions":native_helper_dispositions,
        "elapsed_ms":runtime.borrow().clock.elapsed_ms(),"lease_path":transaction.lease_path,
        "scope":if matches!(transaction.services[1], ServiceSpec::OmlxUnmanaged { .. }) {
            "Studio lifecycle and direct guardian experiment only; oMLX unverified and excluded from control; not an isolated or verified-exclusive GPU baseline"
        } else {
            "Only enrolled Studio/oMLX and direct guardian experiment; no whole-host or arbitrary-descendant guarantee"
        },
        "automation_ceiling_note":"Bounds automation, not a failed outage; GUI may remain paused for manual recovery"
    });
    private_json(&transaction.evidence_root.join("receipt.json"), &receipt)?;
    runtime.borrow_mut().journal.sync_all()?;
    drop(lease);
    Ok(())
}
fn drain(input: &mut File, output: &mut File, remaining: &mut u64) -> Result<()> {
    let mut bytes = [0u8; 8192];
    loop {
        match input.read(&mut bytes) {
            Ok(0) => return Ok(()),
            Ok(n) => {
                ensure!((n as u64) <= *remaining, "CPU output exceeded 64 MiB");
                output.write_all(&bytes[..n])?;
                *remaining -= n as u64;
            }
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => return Ok(()),
            Err(error) if error.kind() == std::io::ErrorKind::Interrupted => {}
            Err(error) => return Err(error.into()),
        }
    }
}

/// A real finite CPU participant. It never imports native runtimes or emits media
/// inference evidence. Fork cases deliberately exercise the observation limit.
pub fn participant(mode: &str, duration_ms: u64) -> Result<bool> {
    ensure!(
        (1..=30_000).contains(&duration_ms),
        "participant duration outside finite CPU limit"
    );
    match mode {
        "absence-probe" => {
            let path = std::env::current_dir()?.join("absence-candidates.json");
            match fs::symlink_metadata(&path) {
                Ok(metadata) => ensure!(metadata.len() <= 65_536, "CPU candidate input exceeds bound"),
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(false),
                Err(error) => return Err(error).context("CPU candidate probe unavailable"),
            }
            let candidates: Vec<ProcessIdentity> = read_private(&path)?;
            ensure!(candidates.len() <= 16, "CPU candidate bound exceeded");
            let prefix = std::env::current_dir()?.join("absence-bin");
            let mut seen = std::collections::BTreeSet::new();
            let mut present = Vec::new();
            for expected in candidates {
                ensure!(seen.insert(expected.pid), "ambiguous CPU candidate identity");
                if let Some(current) = process_scope::observe(expected.pid)? {
                    ensure!(current.same_process(&expected), "CPU candidate PID reused");
                    ensure!(process_scope::executable_matches_prefix(expected.pid, &prefix)?, "CPU candidate executable binding differs");
                    present.push(current.pid);
                }
            }
            for pid in &present { println!("{pid}"); }
            return Ok(!present.is_empty());
        }
        "absence-appear" => {
            private_json(&std::env::current_dir()?.join("absence-ready.json"), &true)?;
            thread::sleep(Duration::from_millis(duration_ms));
        }
        "service" | "hold" => thread::sleep(Duration::from_millis(duration_ms)),
        "fail" => return Ok(false),
        "ignore-term" => {
            unsafe {
                libc::signal(libc::SIGTERM, libc::SIG_IGN);
            }
            thread::sleep(Duration::from_millis(duration_ms));
        }
        "retained" | "escaped" => {
            let escaped = mode == "escaped";
            let pid = unsafe { libc::fork() };
            ensure!(pid >= 0, "CPU participant fork failed");
            if pid == 0 {
                unsafe {
                    if escaped && libc::setsid() < 0 {
                        libc::_exit(91);
                    }
                    if escaped {
                        let evidence = b"{\"cpu_child_event\":\"setsid_succeeded\"}\n";
                        libc::write(1, evidence.as_ptr().cast(), evidence.len());
                    }
                    libc::usleep((duration_ms.min(5000) * 1000) as u32);
                    libc::_exit(0);
                }
            }
            // Keep the root anchored long enough for the enrolled kernel event.
            thread::sleep(Duration::from_millis(duration_ms));
        }
        "compute" => {
            let start = Instant::now();
            let mut accumulator = 0x9e3779b97f4a7c15u64;
            let mut iterations = 0u64;
            while start.elapsed() < Duration::from_millis(duration_ms) {
                for _ in 0..4096 {
                    accumulator = std::hint::black_box(
                        accumulator
                            .rotate_left(7)
                            .wrapping_mul(6364136223846793005)
                            .wrapping_add(1),
                    );
                    iterations += 1;
                }
            }
            println!(
                "{}",
                serde_json::json!({"kind":"integer_cpu_work","iterations":iterations,"checksum":format!("{accumulator:016x}"),"participant_elapsed_ms":start.elapsed().as_millis(),"native_inference":false})
            );
        }
        _ => bail!("unknown finite CPU participant mode"),
    }
    Ok(true)
}

pub fn run_cpu(root: &Path, scenario: &str) -> Result<PathBuf> {
    ensure!(
        matches!(
            scenario,
            "normal"
                | "controller-loss"
                | "retained"
                | "escaped"
                | "deadline"
                | "cleanup-deadline"
                | "restore-failure"
                | "stale"
                | "arming-deadline"
                | "restore-launch-deadline"
                | "absence-clean"
                | "absence-presence"
                | "absence-late"
                | "absence-ambiguous"
                | "absence-probe-error"
                | "absence-reused"
                | "absence-controller-loss"
                | "unmanaged-normal"
                | "unmanaged-failure"
                | "unmanaged-controller-loss"
        ),
        "unknown CPU lifecycle scenario"
    );
    let root = fs::canonicalize(root)?;
    let metadata = fs::symlink_metadata(&root)?;
    ensure!(
        metadata.is_dir()
            && metadata.uid() == unsafe { libc::geteuid() }
            && metadata.mode() & 0o077 == 0,
        "CPU root must be owner-private"
    );
    let executable = std::env::current_exe()?;
    let command = |mode: &str, duration: u64| CommandSpec {
        executable: executable.clone(),
        args: vec![
            "maintenance-participant".into(),
            "--mode".into(),
            mode.into(),
            "--duration-ms".into(),
            duration.to_string(),
        ],
        cwd: root.clone(),
        environment: BTreeMap::new(),
    };
    let id = format!("cpu-{}-{}", native_guard::unix_ms()?, std::process::id());
    let (mode, duration, experiment_ms, cleanup_ms) = match scenario {
        "controller-loss" | "stale" | "absence-controller-loss" | "unmanaged-controller-loss" => ("hold", 5000, 6000, 2000),
        "absence-late" => ("absence-appear", 5000, 6000, 2000),
        "retained" => ("retained", 1500, 3000, 2000),
        "escaped" => ("escaped", 1500, 3000, 2000),
        "deadline" => ("hold", 2000, 100, 2000),
        "cleanup-deadline" => ("ignore-term", 2000, 200, 1),
        "unmanaged-failure" => ("fail", 1, 3000, 2000),
        _ => ("compute", 200, 3000, 2000),
    };
    let service = command("service", 30_000);
    let mut transaction = Transaction {
        schema_version: 1,
        transaction_id: id.clone(),
        purpose: ScopePurpose::Cpu,
        evidence_root: root.join(id),
        lease_path: root.join(".cpu-maintenance.lock"),
        guardian_sha256: executable_digest(&executable)?,
        budgets: Budgets {
            arming_ms: if scenario == "arming-deadline" {
                50
            } else {
                3000
            },
            studio_stop_ms: 2000,
            omlx_stop_ms: 2000,
            prelaunch_ms: 1000,
            experiment_ms,
            cleanup_ms,
            omlx_restore_ms: if scenario == "restore-launch-deadline" {
                50
            } else {
                3000
            },
            studio_restore_ms: 2000,
            recovery_ms: 3000,
            total_ms: 30_000,
        },
        services: vec![
            ServiceSpec::OwnedCpu {
                role: ServiceRole::Studio,
                command: service.clone(),
                restore_command: service.clone(),
                gui_command: None,
            },
            ServiceSpec::OwnedCpu {
                role: ServiceRole::Omlx,
                command: service.clone(),
                restore_command: if scenario == "restore-failure" {
                    command("fail", 1)
                } else {
                    service.clone()
                },
                gui_command: Some(service),
            },
        ],
        experiment: Experiment::Cpu {
            command: command(mode, duration),
        },
        reviewed_permissions: None,
    };
    let absent = scenario.starts_with("absence-");
    if absent {
        transaction.services[1] = ServiceSpec::OmlxAbsent {
            binding: AbsenceBinding::Cpu {
                probe: command("absence-probe", 1),
                executable_root: root.join("absence-bin"),
            },
        };
    }
    if scenario.starts_with("unmanaged-") {
        transaction.services[1] = ServiceSpec::OmlxUnmanaged {
            purpose: ScopePurpose::Cpu,
            acknowledgement: crate::service_lifecycle::UnmanagedAcknowledgement::AcceptUnverifiedOmlx,
        };
    }
    let now = native_guard::unix_ms()?;
    let authorization = Authorization {
        schema_version: 1,
        transaction_sha256: digest(&transaction)?,
        purpose: ScopePurpose::Cpu,
        owner_uid: unsafe { libc::geteuid() },
        not_before_unix_ms: now,
        expires_unix_ms: now + 35_000,
        review_reference:
            "explicit CLI CPU-only transaction; no live service or native permissions".into(),
        service_interruption_approved: true,
        cold_restore_approved: true,
        interrupted_work_loss_approved: true,
    };
    let stop = Arc::new(AtomicBool::new(false));
    let fixture = if matches!(scenario, "absence-presence" | "absence-late" | "absence-ambiguous" | "absence-reused") {
        Some(cpu_absence_actor(&root, scenario, Arc::clone(&stop))?)
    } else {
        if scenario == "absence-probe-error" {
            private_json(&root.join("absence-candidates.json"), &serde_json::json!({"invalid":"candidate list"}))?;
        }
        None
    };
    // Controller-loss deliberately has no controller-owned foreign actor. Its
    // independent smoke/test harness must own and settle that fixture instead.
    let unmanaged_fixture = if matches!(scenario, "unmanaged-normal" | "unmanaged-failure") {
        Some(CpuUnmanagedActor::spawn(&root, &command("service", 30_000))?)
    } else {
        None
    };
    let result = run_controller(transaction, authorization);
    stop.store(true, Ordering::Relaxed);
    if let Some(fixture) = fixture {
        fixture.finish()?;
    }
    if let Some(fixture) = unmanaged_fixture {
        fixture.finish()?;
    }
    result
}

/// Never serialized into the transaction or handed to the guardian. The CLI
/// harness retains ownership before any fallible identity/evidence work.
struct CpuUnmanagedActor {
    actor: OwnedProcess,
    root: PathBuf,
    before: Option<ProcessIdentity>,
    finished: bool,
}
impl CpuUnmanagedActor {
    fn spawn(root: &Path, command: &CommandSpec) -> Result<Self> {
        let attempt = OwnedProcess::spawn_with_deadline(
            command, Instant::now() + Duration::from_secs(3), &mut || Ok(()),
        )?;
        let mut fixture = Self {
            actor: attempt.process, root: root.to_owned(), before: None, finished: false,
        };
        if let Some(failure) = attempt.failure {
            bail!(failure);
        }
        let before = fixture.actor.identity()?;
        ensure!(before.state == process_scope::ProcessState::Running, "foreign fixture not running");
        fixture.before = Some(before);
        private_json(&root.join("unmanaged-fixture-before.json"), &fixture.before)?;
        Ok(fixture)
    }

    fn finish(mut self) -> Result<()> {
        self.settle(false)
    }

    fn settle(&mut self, unwinding: bool) -> Result<()> {
        let after = (|| -> Result<ProcessIdentity> {
            let before = self.before.as_ref().context("foreign fixture enrollment incomplete")?;
            let after = process_scope::verify_identity(before)?;
            ensure!(
                after == *before && after.state == process_scope::ProcessState::Running,
                "guardian interfered with non-owned fixture"
            );
            Ok(after)
        })();
        let settlement = self.actor.settle(
            Instant::now() + Duration::from_secs(2),
            Duration::from_millis(100), &mut || Ok(()),
        );
        // Settlement is single-shot even if persistence subsequently fails.
        self.finished = true;
        private_json(&self.root.join("unmanaged-fixture-settlement.json"), &serde_json::json!({
            "created":true, "pid":self.actor.pid(), "owner":"cpu_cli_harness",
            "before":self.before, "after":after.as_ref().ok(),
            "uncontrolled_by_guardian":after.is_ok(), "unwinding":unwinding,
            "settlement":settlement.as_ref().ok(),
            "failure":after.as_ref().err().map(|error|format!("{error:#}")),
            "settlement_failure":settlement.as_ref().err().map(|error|format!("{error:#}")),
        }))?;
        after?;
        ensure!(settlement?.complete, "foreign fixture settlement incomplete");
        Ok(())
    }
}
impl Drop for CpuUnmanagedActor {
    fn drop(&mut self) {
        if !self.finished {
            let _ = self.settle(true);
        }
    }
}

struct CpuAbsenceActor {
    stop: Arc<AtomicBool>,
    worker: Option<thread::JoinHandle<Result<serde_json::Value>>>,
}
impl CpuAbsenceActor {
    fn finish(mut self) -> Result<serde_json::Value> {
        self.stop.store(true, Ordering::Relaxed);
        self.worker.take().unwrap().join()
            .map_err(|_| anyhow::anyhow!("CPU fixture owner panicked"))?
    }
}
impl Drop for CpuAbsenceActor {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Relaxed);
        if let Some(worker) = self.worker.take() {
            let _ = worker.join();
        }
    }
}

/// This fixture actor belongs to the CLI driver, NOT the guardian transaction.
/// It has no oMLX title/listener and is detected solely by its private executable
/// binding. Only this owner settles it, after checking guardian non-interference.
fn cpu_absence_actor(
    root: &Path,
    scenario: &str,
    stop: Arc<AtomicBool>,
) -> Result<CpuAbsenceActor> {
    let directory = root.join("absence-bin");
    fs::DirBuilder::new().mode(0o700).create(&directory)?;
    let executable = directory.join("startup-actor");
    fs::copy("/bin/sleep", &executable)?;
    // macOS can kill an Apple platform binary copied outside its trusted path.
    // Ad-hoc sign only our private copy; never alter the system executable.
    let signing_deadline = Instant::now() + Duration::from_secs(2);
    let attempt = OwnedProcess::spawn_with_deadline(&CommandSpec {
        executable: "/usr/bin/codesign".into(),
        args: vec!["--force".into(), "--sign".into(), "-".into(), executable.to_string_lossy().into_owned()],
        cwd: root.to_owned(),
        environment: BTreeMap::new(),
    }, signing_deadline, &mut || Ok(()))?;
    let mut signer = attempt.process;
    let signing = (|| -> Result<()> {
        if let Some(failure) = attempt.failure { bail!(failure); }
        while !signer.exited_unreaped()? {
            ensure!(Instant::now() < signing_deadline, "CPU fixture signing timed out");
            thread::sleep(POLL);
        }
        Ok(())
    })();
    let signing_settlement = signer.settle(
        Instant::now() + Duration::from_secs(2), Duration::from_millis(100), &mut || Ok(()),
    )?;
    private_json(&root.join("absence-fixture-preparation.json"), &serde_json::json!({
        "kind":"ad_hoc_sign_owned_sleep_copy", "pid":signer.pid(),
        "executable":executable, "failure":signing.as_ref().err().map(|error|format!("{error:#}")),
        "settlement":signing_settlement,
    }))?;
    signing?;
    ensure!(
        signing_settlement.complete && signing_settlement.exit_code == Some(0),
        "CPU fixture signing failed"
    );
    let root = root.to_owned();
    let scenario = scenario.to_owned();
    let (ready, waiting) = std::sync::mpsc::sync_channel(1);
    let worker_stop = Arc::clone(&stop);
    let worker = thread::spawn(move || -> Result<serde_json::Value> {
        let deadline = Instant::now() + Duration::from_secs(30);
        let late = scenario == "absence-late";
        if late {
            ready.send(()).map_err(|_| anyhow::anyhow!("CPU fixture receiver lost"))?;
            while !root.join("absence-ready.json").try_exists()? {
                if worker_stop.load(Ordering::Relaxed) {
                    let observation = serde_json::json!({"created":false});
                    private_json(&root.join("absence-fixture-settlement.json"), &observation)?;
                    return Ok(observation);
                }
                ensure!(Instant::now() < deadline, "CPU appearance fixture timed out");
                thread::sleep(POLL);
            }
        }
        let command = CommandSpec {
            executable, args: vec!["25".into()], cwd: root.clone(), environment: BTreeMap::new(),
        };
        let attempt = OwnedProcess::spawn_with_deadline(&command, deadline, &mut || Ok(()))?;
        let mut actor = attempt.process;
        let execution = (|| -> Result<ProcessIdentity> {
            if let Some(failure) = attempt.failure { bail!(failure); }
            let identity = actor.identity()?;
            let mut enrolled = identity.clone();
            if scenario == "absence-reused" { enrolled.start_seconds = enrolled.start_seconds.saturating_sub(1); }
            let candidates = if scenario == "absence-ambiguous" {
                vec![enrolled.clone(), enrolled]
            } else { vec![enrolled] };
            private_json(&root.join("absence-candidates.json"), &candidates)?;
            if !late { ready.send(()).map_err(|_| anyhow::anyhow!("CPU fixture receiver lost"))?; }
            while !worker_stop.load(Ordering::Relaxed) {
                ensure!(Instant::now() < deadline, "CPU fixture owner timed out");
                thread::sleep(POLL);
            }
            let current = process_scope::verify_identity(&identity)?;
            ensure!(current.state == process_scope::ProcessState::Running, "guardian interfered with non-owned fixture");
            Ok(identity)
        })();
        let settlement = actor.settle(Instant::now() + Duration::from_secs(2), Duration::from_millis(100), &mut || Ok(()))?;
        let observation = serde_json::json!({
            "created":true, "pid":actor.pid(), "identity":execution.as_ref().ok(),
            "uncontrolled_by_guardian":execution.is_ok(), "settlement":settlement,
            "failure":execution.as_ref().err().map(|error|format!("{error:#}")),
        });
        private_json(&root.join("absence-fixture-settlement.json"), &observation)?;
        execution?;
        ensure!(settlement.complete, "CPU fixture settlement incomplete");
        Ok(observation)
    });
    let fixture = CpuAbsenceActor { stop: Arc::clone(&stop), worker: Some(worker) };
    if waiting.recv_timeout(Duration::from_secs(3)).is_err() {
        stop.store(true, Ordering::Relaxed);
        let detail = fixture.finish();
        bail!("CPU fixture enrollment failed: {detail:?}");
    }
    Ok(fixture)
}
