//! Direct guardian child ownership, not a PID-forwarding wrapper.
//!
//! Darwin's EVFILT_PROC is installed while the child is behind an exec barrier.
//! NOTE_FORK has no child PID; NOTE_TRACK/NOTE_CHILD have been unsupported since
//! macOS 10.5 (SDK sys/event.h). Consequently ANY observed fork, observation
//! failure, or escaped known member permanently disqualifies this scope. Cleaning
//! its pinned group does not prove absence of arbitrary escaped descendants.
//! Native callers additionally need a fork-denying sandbox. Linux is deliberately
//! unsupported: polling /proc cannot supply the same pre-exec fork observation.
//!
//! External identity reads/signals are bounded snapshots, NOT atomic pid handles.
//! A birth check immediately before kill still has a check-to-signal race. Group
//! signals require a session/group leader and never widen to another group.
//! No SIGCHLD auto-reaper or competing waitpid owner is supported. There is no
//! Drop cleanup: the guardian must retain this object and explicitly settle it.
//! Pipes have bounded kernel storage; callers must drain/cap captured bytes.
//! Kernel/filesystem syscalls themselves have no hard wall-clock cancellation.

use std::collections::BTreeMap;
use std::fs::File;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use anyhow::{Context, Result, bail, ensure};
use serde::{Deserialize, Serialize};

const MAX_PATH_BYTES: usize = 4095;
const MAX_ITEMS: usize = 256;
const MAX_STRING_BYTES: usize = 16 * 1024;
const MAX_COMMAND_BYTES: usize = 128 * 1024;

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CommandSpec {
    pub executable: PathBuf,
    pub args: Vec<String>,
    pub cwd: PathBuf,
    pub environment: BTreeMap<String, String>,
}

impl CommandSpec {
    /// Pure validation: no PATH lookup, canonicalization, or inherited env read.
    /// In particular a selected virtualenv executable is not resolved away.
    pub fn validate(&self) -> Result<()> {
        validate_path(&self.executable)?;
        validate_path(&self.cwd)?;
        ensure!(self.args.len() <= MAX_ITEMS, "too many command arguments");
        ensure!(
            self.environment.len() <= MAX_ITEMS,
            "too many environment entries"
        );
        let mut total = self.executable.as_os_str().len() + self.cwd.as_os_str().len() + 2;
        for arg in &self.args {
            validate_string(arg)?;
            total += arg.len() + 1;
        }
        for (name, value) in &self.environment {
            ensure!(
                !name.is_empty() && !name.contains('='),
                "invalid environment name"
            );
            validate_string(name)?;
            validate_string(value)?;
            total += name.len() + value.len() + 2;
        }
        ensure!(total <= MAX_COMMAND_BYTES, "command exceeds byte bound");
        Ok(())
    }
}

fn validate_path(path: &Path) -> Result<()> {
    ensure!(path.is_absolute(), "command paths must be absolute");
    ensure!(
        path.as_os_str().len() <= MAX_PATH_BYTES,
        "command path exceeds byte bound"
    );
    ensure!(
        !path.as_os_str().as_encoded_bytes().contains(&0),
        "NUL in command path"
    );
    Ok(())
}

fn validate_string(value: &str) -> Result<()> {
    ensure!(
        value.len() <= MAX_STRING_BYTES && !value.contains('\0'),
        "invalid or oversized command string"
    );
    Ok(())
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProcessState {
    Running,
    Stopped,
    Zombie,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProcessIdentity {
    pub pid: u32,
    pub ppid: u32,
    pub pgid: u32,
    pub sid: i32,
    pub uid: u32,
    pub start_seconds: u64,
    pub start_subseconds: u64,
    pub executable: PathBuf,
    pub cwd: PathBuf,
    pub state: ProcessState,
}

impl ProcessIdentity {
    pub fn same_process(&self, other: &Self) -> bool {
        self.pid == other.pid
            && self.pgid == other.pgid
            && self.sid == other.sid
            && self.uid == other.uid
            && self.start_seconds == other.start_seconds
            && self.start_subseconds == other.start_subseconds
            && self.executable == other.executable
            && self.cwd == other.cwd
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Settlement {
    /// Includes observation qualification, not merely successful signal delivery.
    pub complete: bool,
    pub leader_reaped: bool,
    pub group_absent: bool,
    pub group_signalled: bool,
    pub exit_code: Option<i32>,
    pub exit_signal: Option<i32>,
    pub failure: Option<String>,
}

/// A failed spawn may still have an unreaped child. Never restore services unless
/// this evidence is complete; an incomplete error requires guardian escalation.
#[derive(Debug)]
pub struct SpawnFailure {
    pub pid: u32,
    pub cause: String,
    pub settlement: Settlement,
    pub cleanup_elapsed_ms: u64,
}

impl std::fmt::Display for SpawnFailure {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "spawn of owned pid {} failed: {}; cleanup complete={}, reaped={}, group_absent={}, failure={:?}",
            self.pid,
            self.cause,
            self.settlement.complete,
            self.settlement.leader_reaped,
            self.settlement.group_absent,
            self.settlement.failure
        )
    }
}

impl std::error::Error for SpawnFailure {}

pub fn verify_identity(expected: &ProcessIdentity) -> Result<ProcessIdentity> {
    let actual = observe(expected.pid)?.context("bound process no longer exists")?;
    ensure!(
        expected.same_process(&actual),
        "bound process identity changed"
    );
    Ok(actual)
}

/// Fresh identity and bounded membership checks reduce, but do not eliminate,
/// external PID reuse, exec, cwd, and group-membership races before kill(2).
pub fn signal_bound(expected: &ProcessIdentity, signal: i32, group: bool) -> Result<()> {
    validate_signal(signal)?;
    let first = verify_identity(expected)?;
    ensure!(
        first.state != ProcessState::Zombie,
        "cannot signal bound zombie"
    );
    if group {
        ensure!(
            first.pid == first.pgid && first.sid == first.pid as i32,
            "external group requires its session-root identity"
        );
        let members = group_members(first.pgid)?;
        ensure!(!members.is_empty(), "bound process group disappeared");
        ensure!(
            members.iter().any(|p| p.same_process(&first)),
            "bound leader missing from group"
        );
        ensure!(
            members
                .iter()
                .all(|p| p.sid == first.sid && p.uid == first.uid),
            "external group includes unbound session or UID"
        );
    }
    let fresh = verify_identity(expected)?;
    ensure!(
        fresh.state != ProcessState::Zombie,
        "bound process exited before signal"
    );
    platform_signal(
        if group {
            -(fresh.pgid as i32)
        } else {
            fresh.pid as i32
        },
        signal,
    )
}

fn validate_pid(pid: u32) -> Result<()> {
    ensure!(
        pid > 1 && pid <= i32::MAX as u32,
        "invalid targeted process identity"
    );
    Ok(())
}

fn validate_signal(signal: i32) -> Result<()> {
    ensure!(
        matches!(
            signal,
            libc::SIGTERM | libc::SIGKILL | libc::SIGSTOP | libc::SIGCONT
        ),
        "unsupported process-control signal"
    );
    Ok(())
}

#[cfg(unix)]
fn platform_signal(pid: i32, signal: i32) -> Result<()> {
    if unsafe { libc::kill(pid, signal) } != 0 {
        return Err(std::io::Error::last_os_error()).context("signalling bound process");
    }
    Ok(())
}

#[cfg(not(unix))]
fn platform_signal(_pid: i32, _signal: i32) -> Result<()> {
    bail!("process scope requires Darwin")
}

#[cfg(target_os = "macos")]
pub use darwin::{OwnedProcess, bound_absent, group_members, observe};

#[cfg(target_os = "macos")]
mod darwin {
    use super::*;
    use std::ffi::{CString, OsString};
    use std::io::{self, Read};
    use std::mem::{size_of, size_of_val};
    use std::os::fd::{AsRawFd, FromRawFd, RawFd};
    use std::os::unix::ffi::{OsStrExt, OsStringExt};
    use std::ptr;
    use std::thread;

    const MAX_MEMBERS: usize = 4096;
    const MAX_FDS: usize = 8192;
    const POLL_INTERVAL: Duration = Duration::from_millis(5);

    #[derive(Clone, Copy, Debug)]
    struct Basic {
        pid: u32,
        ppid: u32,
        pgid: u32,
        uid: u32,
        seconds: u64,
        subseconds: u64,
        state: ProcessState,
    }

    impl Basic {
        fn same_birth(self, other: Self) -> bool {
            self.pid == other.pid
                && self.seconds == other.seconds
                && self.subseconds == other.subseconds
        }
    }

    fn basic(pid: u32) -> Result<Option<Basic>> {
        validate_pid(pid)?;
        let mut info: libc::proc_bsdinfo = unsafe { std::mem::zeroed() };
        let bytes = unsafe {
            libc::proc_pidinfo(
                pid as i32,
                libc::PROC_PIDTBSDINFO,
                1,
                (&mut info as *mut libc::proc_bsdinfo).cast(),
                size_of_val(&info) as i32,
            )
        };
        if bytes == 0 {
            let error = io::Error::last_os_error();
            if error.raw_os_error() == Some(libc::ESRCH) {
                return Ok(None);
            }
            return Err(error).context("reading targeted Darwin process identity");
        }
        ensure!(
            bytes as usize == size_of_val(&info) && info.pbi_pid == pid,
            "short or mismatched Darwin process identity"
        );
        let state = match info.pbi_status {
            1..=3 => ProcessState::Running,
            4 => ProcessState::Stopped,
            5 => ProcessState::Zombie,
            value => bail!("unknown Darwin process state {value}"),
        };
        Ok(Some(Basic {
            pid,
            ppid: info.pbi_ppid,
            pgid: info.pbi_pgid,
            uid: info.pbi_uid,
            seconds: info.pbi_start_tvsec,
            subseconds: info.pbi_start_tvusec,
            state,
        }))
    }

    fn session(pid: u32) -> Result<i32> {
        let sid = unsafe { libc::getsid(pid as i32) };
        ensure!(
            sid >= 0,
            "reading targeted process session: {}",
            io::Error::last_os_error()
        );
        Ok(sid)
    }

    fn validate_binding(expected: &ProcessIdentity, actual: Basic) -> Result<()> {
        ensure!(
            actual.pid == expected.pid
                && actual.uid == expected.uid
                && actual.pgid == expected.pgid
                && actual.seconds == expected.start_seconds
                && actual.subseconds == expected.start_subseconds,
            "bound process birth, UID, or group changed"
        );
        Ok(())
    }

    /// Targeted absence observation, NOT a fresh executable/cwd attestation.
    /// BSD birth/UID/group metadata remains available for unreaped zombies;
    /// requiring getsid/vnodes here would race ordinary live-to-zombie exit.
    /// A matching live process or zombie is not absent. Absence requires both
    /// the PID and enrolled PGID to disappear. PID reuse is an error, not exit.
    /// Like all external observations this is a bounded, non-atomic snapshot;
    /// it cannot establish absence of descendants that escaped the group.
    pub fn bound_absent(expected: &ProcessIdentity) -> Result<bool> {
        validate_pid(expected.pid)?;
        validate_pid(expected.pgid)?;
        if let Some(actual) = basic(expected.pid)? {
            validate_binding(expected, actual)?;
            return Ok(false);
        }
        let mut ids = [0_i32; MAX_MEMBERS];
        let count = group_ids(expected.pgid, &mut ids)?;
        for pid in &ids[..count] {
            let member = basic(*pid as u32)?
                .context("group member disappeared during absence observation")?;
            ensure!(
                member.pgid == expected.pgid && member.uid == expected.uid,
                "bound group changed during absence observation"
            );
        }
        // Detect reuse/reappearance between the PID and PGID snapshots.
        if let Some(actual) = basic(expected.pid)? {
            validate_binding(expected, actual)?;
            return Ok(false);
        }
        Ok(count == 0)
    }

    fn kernel_path(bytes: &[u8]) -> Result<PathBuf> {
        let length = bytes
            .iter()
            .position(|b| *b == 0)
            .context("truncated kernel process path")?;
        ensure!(
            length > 0 && length < MAX_PATH_BYTES,
            "unavailable or oversized kernel process path"
        );
        let path = PathBuf::from(OsString::from_vec(bytes[..length].to_vec()));
        ensure!(path.is_absolute(), "kernel process path is not absolute");
        Ok(path)
    }

    /// Zombies may no longer expose vnode/cwd information; that is an error,
    /// not a fabricated executable path. Settlement uses birth/group metadata
    /// independently and can therefore settle a short-lived unreaped child.
    pub fn observe(pid: u32) -> Result<Option<ProcessIdentity>> {
        let Some(before) = basic(pid)? else {
            return Ok(None);
        };
        ensure!(
            before.state != ProcessState::Zombie,
            "full zombie executable/cwd/session identity unavailable"
        );
        let before_sid = session(pid)?;
        let mut executable = [0_u8; 4096];
        let bytes = unsafe {
            libc::proc_pidpath(
                pid as i32,
                executable.as_mut_ptr().cast(),
                executable.len() as u32,
            )
        };
        ensure!(
            bytes > 0 && (bytes as usize) < executable.len(),
            "process executable unavailable or truncated: {}",
            io::Error::last_os_error()
        );
        let executable = kernel_path(&executable)?;
        let mut paths: libc::proc_vnodepathinfo = unsafe { std::mem::zeroed() };
        let bytes = unsafe {
            libc::proc_pidinfo(
                pid as i32,
                libc::PROC_PIDVNODEPATHINFO,
                0,
                (&mut paths as *mut libc::proc_vnodepathinfo).cast(),
                size_of_val(&paths) as i32,
            )
        };
        ensure!(
            bytes as usize == size_of_val(&paths),
            "process cwd unavailable or truncated: {}",
            io::Error::last_os_error()
        );
        let cwd_bytes = unsafe {
            std::slice::from_raw_parts(
                paths.pvi_cdir.vip_path.as_ptr().cast::<u8>(),
                size_of_val(&paths.pvi_cdir.vip_path),
            )
        };
        let cwd = kernel_path(cwd_bytes)?;
        let after = basic(pid)?.context("process disappeared during identity read")?;
        let after_sid = session(pid)?;
        ensure!(
            before.same_birth(after)
                && before.uid == after.uid
                && before.pgid == after.pgid
                && before_sid == after_sid
                && after.state != ProcessState::Zombie,
            "process changed during identity read"
        );
        Ok(Some(ProcessIdentity {
            pid,
            ppid: after.ppid,
            pgid: after.pgid,
            sid: after_sid,
            uid: after.uid,
            start_seconds: after.seconds,
            start_subseconds: after.subseconds,
            executable,
            cwd,
            state: after.state,
        }))
    }

    fn group_ids(pgid: u32, ids: &mut [i32; MAX_MEMBERS]) -> Result<usize> {
        validate_pid(pgid)?;
        // libproc maps errors to zero; clear errno to distinguish an empty group.
        unsafe { *libc::__error() = 0 };
        let bytes = unsafe {
            libc::proc_listpids(2, pgid, ids.as_mut_ptr().cast(), size_of_val(ids) as i32)
        };
        let errno = io::Error::last_os_error().raw_os_error().unwrap_or(0);
        ensure!(
            bytes >= 0 && (bytes != 0 || errno == 0 || errno == libc::ESRCH),
            "Darwin group enumeration unavailable: errno {errno}"
        );
        ensure!(
            (bytes as usize) < size_of_val(ids)
                && (bytes as usize).is_multiple_of(size_of::<i32>()),
            "Darwin group enumeration truncated or malformed"
        );
        let count = bytes as usize / size_of::<i32>();
        let members = &mut ids[..count];
        ensure!(
            members.iter().all(|pid| *pid > 1),
            "invalid Darwin group member"
        );
        members.sort_unstable();
        ensure!(
            members.windows(2).all(|pair| pair[0] != pair[1]),
            "duplicate Darwin group member"
        );
        Ok(count)
    }

    fn group_pids(pgid: u32) -> Result<Vec<u32>> {
        let mut ids = [0_i32; MAX_MEMBERS];
        let count = group_ids(pgid, &mut ids)?;
        Ok(ids[..count].iter().map(|pid| *pid as u32).collect())
    }

    struct GroupSnapshot {
        count: usize,
        all_zombies: bool,
    }

    pub fn group_members(pgid: u32) -> Result<Vec<ProcessIdentity>> {
        let ids = group_pids(pgid)?;
        let mut members = Vec::with_capacity(ids.len());
        for pid in &ids {
            let process = observe(*pid)?.context("group member disappeared during observation")?;
            ensure!(
                process.pgid == pgid,
                "group member escaped during observation"
            );
            members.push(process);
        }
        ensure!(
            ids == group_pids(pgid)?,
            "group changed during bounded observation"
        );
        Ok(members)
    }

    fn cloexec(fd: RawFd) -> Result<()> {
        if unsafe { libc::fcntl(fd, libc::F_SETFD, libc::FD_CLOEXEC) } < 0 {
            return Err(io::Error::last_os_error())
                .context("marking process descriptor close-on-exec");
        }
        Ok(())
    }

    fn nonblocking(file: &File) -> Result<()> {
        let fd = file.as_raw_fd();
        let flags = unsafe { libc::fcntl(fd, libc::F_GETFL) };
        if flags < 0 || unsafe { libc::fcntl(fd, libc::F_SETFL, flags | libc::O_NONBLOCK) } < 0 {
            return Err(io::Error::last_os_error()).context("making process pipe nonblocking");
        }
        Ok(())
    }

    fn owned_fd(fd: RawFd) -> Result<File> {
        ensure!(
            fd >= 0,
            "allocating process descriptor: {}",
            io::Error::last_os_error()
        );
        let original = unsafe { File::from_raw_fd(fd) };
        if fd < 3 {
            let duplicate = unsafe { libc::fcntl(fd, libc::F_DUPFD_CLOEXEC, 3) };
            ensure!(
                duplicate >= 0,
                "promoting process descriptor: {}",
                io::Error::last_os_error()
            );
            return Ok(unsafe { File::from_raw_fd(duplicate) });
        }
        cloexec(fd)?;
        Ok(original)
    }

    fn pipe() -> Result<(File, File)> {
        let mut fds = [-1; 2];
        ensure!(
            unsafe { libc::pipe(fds.as_mut_ptr()) } == 0,
            "creating process pipe: {}",
            io::Error::last_os_error()
        );
        // Own both before any fallible conversion, including closed-stdio cases.
        let left = unsafe { File::from_raw_fd(fds[0]) };
        let right = unsafe { File::from_raw_fd(fds[1]) };
        use std::os::fd::IntoRawFd;
        let left = owned_fd(left.into_raw_fd())?;
        let right = owned_fd(right.into_raw_fd())?;
        Ok((left, right))
    }

    struct Prepared {
        executable: CString,
        cwd: CString,
        _args: Vec<CString>,
        argv: Vec<*const libc::c_char>,
        _environment: Vec<CString>,
        envp: Vec<*const libc::c_char>,
        fds: Vec<libc::proc_fdinfo>,
    }

    impl Prepared {
        fn new(spec: &CommandSpec) -> Result<Self> {
            spec.validate()?;
            let executable = CString::new(spec.executable.as_os_str().as_bytes())?;
            let cwd = CString::new(spec.cwd.as_os_str().as_bytes())?;
            let mut args = Vec::with_capacity(spec.args.len() + 1);
            args.push(executable.clone());
            for arg in &spec.args {
                args.push(CString::new(arg.as_bytes())?);
            }
            let mut argv: Vec<_> = args.iter().map(|s| s.as_ptr()).collect();
            argv.push(ptr::null());
            let mut environment = Vec::with_capacity(spec.environment.len());
            for (key, value) in &spec.environment {
                environment.push(CString::new(format!("{key}={value}"))?);
            }
            let mut envp: Vec<_> = environment.iter().map(|s| s.as_ptr()).collect();
            envp.push(ptr::null());
            let fds = (0..MAX_FDS)
                .map(|_| libc::proc_fdinfo {
                    proc_fd: 0,
                    proc_fdtype: 0,
                })
                .collect();
            Ok(Self {
                executable,
                cwd,
                _args: args,
                argv,
                _environment: environment,
                envp,
                fds,
            })
        }
    }

    // Post-fork path: no Rust allocation, formatting, destructors, locks, or
    // environment access. Apple's libproc.c implementation of proc_pidinfo is
    // only __proc_info + errno translation, without allocator/stdio locks:
    // https://github.com/apple-oss-distributions/xnu/blob/main/libsyscall/wrappers/libproc/libproc.c
    unsafe fn child_error(status: RawFd, error: i32) -> ! {
        let bytes = error.to_ne_bytes();
        unsafe {
            libc::write(status, bytes.as_ptr().cast(), bytes.len());
            libc::_exit(127)
        }
    }

    unsafe fn child_exec(
        prepared: &mut Prepared,
        stdin: RawFd,
        stdout: RawFd,
        stderr: RawFd,
        barrier: RawFd,
        status: RawFd,
        lease: Option<RawFd>,
    ) -> ! {
        unsafe {
            libc::umask(0o077);
            let mut mask: libc::sigset_t = std::mem::zeroed();
            libc::sigemptyset(&mut mask);
            if libc::sigprocmask(libc::SIG_SETMASK, &mask, ptr::null_mut()) != 0 {
                child_error(status, *libc::__error());
            }
            // Reset inherited handlers before any child pipe write (SIGPIPE).
            for signal in 1..32 {
                if signal != libc::SIGKILL && signal != libc::SIGSTOP {
                    let mut action: libc::sigaction = std::mem::zeroed();
                    action.sa_sigaction = libc::SIG_DFL;
                    libc::sigemptyset(&mut action.sa_mask);
                    if libc::sigaction(signal, &action, ptr::null_mut()) != 0 {
                        child_error(status, *libc::__error());
                    }
                }
            }
            if libc::setsid() < 0 || libc::chdir(prepared.cwd.as_ptr()) != 0 {
                child_error(status, *libc::__error());
            }
            if libc::dup2(stdin, 0) < 0 || libc::dup2(stdout, 1) < 0 || libc::dup2(stderr, 2) < 0 {
                child_error(status, *libc::__error());
            }
            // Snapshot the SINGLE-THREADED CHILD's inherited descriptor table,
            // not the parent's racy/high-watermark approximation. Reject full
            // buffers, including exact-capacity results; no descriptor leak.
            let capacity = prepared.fds.len() * size_of::<libc::proc_fdinfo>();
            let bytes = libc::proc_pidinfo(
                libc::getpid(),
                libc::PROC_PIDLISTFDS,
                0,
                prepared.fds.as_mut_ptr().cast(),
                capacity as i32,
            );
            if bytes <= 0
                || bytes as usize >= capacity
                || !(bytes as usize).is_multiple_of(size_of::<libc::proc_fdinfo>())
            {
                child_error(status, libc::EOVERFLOW);
            }
            let mut index = 0;
            while index < bytes as usize / size_of::<libc::proc_fdinfo>() {
                let fd = (*prepared.fds.as_ptr().add(index)).proc_fd;
                if fd > 2 && fd != barrier && fd != status && Some(fd) != lease {
                    libc::close(fd);
                }
                index += 1;
            }
            if let Some(fd) = lease
                && libc::fcntl(fd, libc::F_SETFD, 0) < 0
            {
                child_error(status, *libc::__error());
            }
            let ready = 0_i32.to_ne_bytes();
            if libc::write(status, ready.as_ptr().cast(), ready.len()) != ready.len() as isize {
                libc::_exit(127);
            }
            let mut release = 0_u8;
            loop {
                let count = libc::read(barrier, (&mut release as *mut u8).cast(), 1);
                if count == 1 {
                    break;
                }
                if count < 0 && *libc::__error() == libc::EINTR {
                    continue;
                }
                libc::_exit(127);
            }
            libc::close(barrier);
            if release != 1 {
                libc::_exit(127);
            }
            libc::execve(
                prepared.executable.as_ptr(),
                prepared.argv.as_ptr(),
                prepared.envp.as_ptr(),
            );
            child_error(status, *libc::__error());
        }
    }

    #[must_use = "owned children must be explicitly settled before restoration"]
    pub struct OwnedProcess {
        pid: u32,
        anchor: Option<Basic>,
        session_ready: bool,
        events: File,
        saw_exec: bool,
        reaped: bool,
        group_signalled: bool,
        known: BTreeMap<u32, Basic>,
        failure: Option<String>,
        settlement: Option<Settlement>,
        pub stdout: Option<File>,
        pub stderr: Option<File>,
    }

    impl OwnedProcess {
        pub fn spawn_with_deadline(
            spec: &CommandSpec,
            deadline: Instant,
            tick: &mut dyn FnMut() -> Result<()>,
        ) -> Result<Self> {
            Self::spawn_inner(spec, deadline, tick, None)
        }

        /// Inherit ONLY the caller's explicitly owned project lease. The child
        /// copy clears CLOEXEC; no lease-path/env marker or arbitrary fd list.
        pub fn spawn_with_lease(
            spec: &CommandSpec,
            deadline: Instant,
            tick: &mut dyn FnMut() -> Result<()>,
            lease_fd: i32,
        ) -> Result<Self> {
            ensure!(
                lease_fd >= 3 && unsafe { libc::fcntl(lease_fd, libc::F_GETFD) } >= 0,
                "invalid owned project lease descriptor"
            );
            Self::spawn_inner(spec, deadline, tick, Some(lease_fd))
        }

        fn spawn_inner(
            spec: &CommandSpec,
            deadline: Instant,
            tick: &mut dyn FnMut() -> Result<()>,
            lease: Option<RawFd>,
        ) -> Result<Self> {
            let mut prepared = Prepared::new(spec)?;
            checkpoint(deadline, tick)?;
            // Resolve/validate libproc before fork as well as in the child.
            basic(unsafe { libc::getpid() } as u32)?.context("guardian identity unavailable")?;
            let stdin = owned_fd(unsafe {
                libc::open(c"/dev/null".as_ptr(), libc::O_RDONLY | libc::O_CLOEXEC)
            })?;
            let (stdout_read, stdout_write) = pipe()?;
            let (stderr_read, stderr_write) = pipe()?;
            let (barrier_read, barrier_write) = pipe()?;
            let (mut status_read, status_write) = pipe()?;
            nonblocking(&stdout_read)?;
            nonblocking(&stderr_read)?;
            nonblocking(&status_read)?;
            let events = owned_fd(unsafe { libc::kqueue() })?;
            checkpoint(deadline, tick)?;
            let pid = unsafe { libc::fork() };
            ensure!(
                pid >= 0,
                "forking guardian child: {}",
                io::Error::last_os_error()
            );
            if pid == 0 {
                unsafe {
                    child_exec(
                        &mut prepared,
                        stdin.as_raw_fd(),
                        stdout_write.as_raw_fd(),
                        stderr_write.as_raw_fd(),
                        barrier_read.as_raw_fd(),
                        status_write.as_raw_fd(),
                        lease,
                    )
                }
            }
            drop(stdin);
            drop(stdout_write);
            drop(stderr_write);
            drop(barrier_read);
            drop(status_write);
            let mut owned = Self {
                pid: pid as u32,
                anchor: None,
                session_ready: false,
                events,
                saw_exec: false,
                reaped: false,
                group_signalled: false,
                known: BTreeMap::new(),
                failure: None,
                settlement: None,
                stdout: Some(stdout_read),
                stderr: Some(stderr_read),
            };
            let result = (|| -> Result<()> {
                let change = libc::kevent {
                    ident: pid as usize,
                    filter: libc::EVFILT_PROC,
                    flags: libc::EV_ADD | libc::EV_ENABLE | libc::EV_CLEAR,
                    fflags: libc::NOTE_FORK | libc::NOTE_EXEC | libc::NOTE_EXIT,
                    data: 0,
                    udata: ptr::null_mut(),
                };
                ensure!(
                    unsafe {
                        libc::kevent(
                            owned.events.as_raw_fd(),
                            &change,
                            1,
                            ptr::null_mut(),
                            0,
                            ptr::null(),
                        )
                    } == 0,
                    "enrolling pre-exec process observation: {}",
                    io::Error::last_os_error()
                );
                let ready = read_status(&mut status_read, deadline, tick)?
                    .context("child exited before enrollment barrier")?;
                ensure!(
                    ready == 0,
                    "child setup failed: {}",
                    io::Error::from_raw_os_error(ready)
                );
                let anchor = basic(owned.pid)?.context("child vanished behind barrier")?;
                ensure!(
                    anchor.ppid == unsafe { libc::getpid() } as u32
                        && anchor.pgid == owned.pid
                        && session(owned.pid)? == owned.pid as i32,
                    "child did not establish guardian-owned session"
                );
                owned.anchor = Some(anchor);
                owned.session_ready = true;
                checkpoint(deadline, tick)?;
                // F_SETNOSIGPIPE handles a child dying after ready without
                // changing guardian-wide signal disposition.
                release_barrier(barrier_write.as_raw_fd())?;
                let status = read_status(&mut status_read, deadline, tick)?;
                if let Some(error) = status {
                    bail!("execve failed: {}", io::Error::from_raw_os_error(error));
                }
                loop {
                    checkpoint(deadline, tick)?;
                    owned.poll_events()?;
                    if owned.saw_exec {
                        break;
                    }
                    if owned.exited_unreaped()? {
                        owned.poll_events()?;
                        ensure!(owned.saw_exec, "child status closed without observed exec");
                        break;
                    }
                    thread::sleep(
                        POLL_INTERVAL.min(deadline.saturating_duration_since(Instant::now())),
                    );
                }
                Ok(())
            })();
            drop(barrier_write);
            if let Err(error) = result {
                let cause = format!("{error:#}");
                // No command-side retry. Cleanup remains bounded by the same
                // guardian deadline and reports an unreaped child explicitly.
                let cleanup_started = Instant::now();
                let settlement = owned.settle(deadline, Duration::ZERO, tick)?;
                return Err(SpawnFailure {
                    pid: owned.pid,
                    cause,
                    settlement,
                    cleanup_elapsed_ms: cleanup_started.elapsed().as_millis().min(u64::MAX as u128)
                        as u64,
                }
                .into());
            }
            Ok(owned)
        }

        pub fn pid(&self) -> u32 {
            self.pid
        }

        pub fn identity(&self) -> Result<ProcessIdentity> {
            ensure!(!self.reaped, "owned leader already reaped");
            let actual = observe(self.pid)?.context("owned leader disappeared")?;
            let anchor = self.anchor.context("owned leader not enrolled")?;
            ensure!(
                actual.start_seconds == anchor.seconds
                    && actual.start_subseconds == anchor.subseconds
                    && actual.uid == anchor.uid
                    && actual.ppid == anchor.ppid
                    && actual.pgid == self.pid
                    && actual.sid == self.pid as i32,
                "owned leader identity escaped or changed"
            );
            Ok(actual)
        }

        fn fail(&mut self, message: impl AsRef<str>) {
            let message = message.as_ref();
            match &mut self.failure {
                None => self.failure = Some(message.to_owned()),
                Some(failure) if !failure.contains(message) && failure.len() < 8192 => {
                    failure.push_str("; ");
                    failure.push_str(message);
                }
                Some(_) => {}
            }
        }

        fn poll_events(&mut self) -> Result<()> {
            let mut events: [libc::kevent; 8] = unsafe { std::mem::zeroed() };
            let timeout = libc::timespec {
                tv_sec: 0,
                tv_nsec: 0,
            };
            let count = unsafe {
                libc::kevent(
                    self.events.as_raw_fd(),
                    ptr::null(),
                    0,
                    events.as_mut_ptr(),
                    events.len() as i32,
                    &timeout,
                )
            };
            ensure!(
                count >= 0 && (count as usize) < events.len(),
                "kernel process observation failed or saturated: {}",
                io::Error::last_os_error()
            );
            for event in &events[..count as usize] {
                ensure!(
                    event.ident == self.pid as usize
                        && event.filter == libc::EVFILT_PROC
                        && event.flags & libc::EV_ERROR == 0,
                    "unexpected kernel process event"
                );
                if event.fflags & libc::NOTE_FORK != 0 {
                    self.fail("fork observed; Darwin cannot atomically enroll arbitrary descendants; escaped-descendant absence remains unqualified even after known-group cleanup");
                }
                if event.fflags & libc::NOTE_EXEC != 0 {
                    self.saw_exec = true;
                }
            }
            Ok(())
        }

        pub fn exited_unreaped(&mut self) -> Result<bool> {
            ensure!(!self.reaped, "owned leader already reaped");
            let mut info: libc::siginfo_t = unsafe { std::mem::zeroed() };
            let result = unsafe {
                libc::waitid(
                    libc::P_PID,
                    self.pid,
                    &mut info,
                    libc::WEXITED | libc::WNOHANG | libc::WNOWAIT,
                )
            };
            if result != 0 {
                let error = io::Error::last_os_error();
                self.fail(format!("unreaped child ownership unavailable: {error}"));
                return Err(error).context("observing child without reaping");
            }
            Ok(unsafe { info.si_pid() } != 0)
        }

        fn snapshot(&mut self) -> Result<GroupSnapshot> {
            let anchor = self.anchor.context("owned session not enrolled")?;
            let root = basic(self.pid)?.context("unreaped session root disappeared")?;
            ensure!(
                root.same_birth(anchor)
                    && root.ppid == anchor.ppid
                    && root.uid == anchor.uid
                    && root.pgid == self.pid,
                "lost pinned session/group identity"
            );
            let mut ids = [0_i32; MAX_MEMBERS];
            let count = group_ids(self.pid, &mut ids)?;
            let mut all_zombies = true;
            let mut found_leader = false;
            for id in &ids[..count] {
                let pid = *id as u32;
                let member = if pid == self.pid {
                    root
                } else {
                    basic(pid)?.context("member disappeared during group observation")?
                };
                // This root's session was pinned behind the exec barrier.
                // Equal kernel PGID therefore implies the same session. Use
                // birth/group metadata only: getsid races normal process exit.
                ensure!(
                    member.pgid == self.pid && member.uid == anchor.uid,
                    "known group member changed session or UID"
                );
                if pid != self.pid {
                    self.fail("descendant observed; complete fork/escape enrollment cannot be established");
                    if let Some(old) = self.known.get(&pid) {
                        ensure!(old.same_birth(member), "known descendant PID reused");
                    }
                    ensure!(
                        self.known.len() < MAX_MEMBERS || self.known.contains_key(&pid),
                        "known descendant tracking saturated"
                    );
                    self.known.insert(pid, member);
                }
                all_zombies &= member.state == ProcessState::Zombie;
                found_leader |= member.pid == self.pid;
            }
            ensure!(found_leader, "unreaped leader missing from pinned group");
            Ok(GroupSnapshot { count, all_zombies })
        }

        pub fn check_membership(&mut self) -> Result<()> {
            let result = (|| -> Result<()> {
                self.exited_unreaped()?;
                self.poll_events()?;
                self.snapshot()?;
                for (pid, known) in &self.known {
                    if let Some(now) = basic(*pid)? {
                        ensure!(
                            known.same_birth(now) && now.pgid == self.pid && now.uid == known.uid,
                            "known descendant escaped or PID reused"
                        );
                    }
                }
                Ok(())
            })();
            if let Err(error) = result {
                self.fail(format!("membership observation failed: {error:#}"));
            }
            if let Some(failure) = &self.failure {
                bail!("{failure}");
            }
            Ok(())
        }

        /// Signals only the unreaped root's pinned group, never escaped PIDs.
        /// Sticky uncertainty does not prevent safe cleanup of that known group.
        pub fn signal(&mut self, signal: i32) -> Result<()> {
            self.signal_checked(signal, &mut || Ok(()))
        }

        fn signal_checked(
            &mut self,
            signal: i32,
            before_effect: &mut dyn FnMut() -> Result<()>,
        ) -> Result<()> {
            validate_signal(signal)?;
            let exited = self.exited_unreaped()?;
            let result = (|| -> Result<()> {
                if let Err(error) = self.poll_events() {
                    self.fail(format!(
                        "kernel observation failed before signal: {error:#}"
                    ));
                }
                if !self.session_ready {
                    // Fixed pre-exec code cannot fork or run user commands.
                    if exited {
                        return Ok(());
                    }
                    before_effect()?;
                    return platform_signal(self.pid as i32, signal);
                }
                let members = self.snapshot()?;
                if members.all_zombies {
                    return Ok(());
                }
                // waitid immediately before kill retains the PID/group anchor.
                self.exited_unreaped()?;
                before_effect()?;
                match platform_signal(-(self.pid as i32), signal) {
                    Ok(()) => {
                        self.group_signalled = true;
                        Ok(())
                    }
                    Err(error) => {
                        let errno = error
                            .downcast_ref::<io::Error>()
                            .and_then(io::Error::raw_os_error);
                        // XNU killpg ignores zombies. Never suppress EPERM for
                        // a live or unknown member; reobserve the pinned group.
                        if matches!(errno, Some(libc::ESRCH) | Some(libc::EPERM))
                            && self.snapshot()?.all_zombies
                        {
                            Ok(())
                        } else {
                            Err(error)
                        }
                    }
                }
            })();
            if let Err(error) = &result {
                self.fail(format!("owned signal failed: {error:#}"));
            }
            result
        }

        /// Single settlement attempt. A later call returns exactly its original
        /// evidence; it cannot convert failed cleanup into restoration authority.
        pub fn settle(
            &mut self,
            deadline: Instant,
            term_grace: Duration,
            tick: &mut dyn FnMut() -> Result<()>,
        ) -> Result<Settlement> {
            if let Some(result) = &self.settlement {
                return Ok(result.clone());
            }
            let mut control_allowed = match checkpoint(deadline, tick) {
                Ok(()) => true,
                Err(error) => {
                    self.fail(format!("settlement control denied: {error:#}"));
                    false
                }
            };
            if let Err(error) = self.poll_events() {
                self.fail(format!("kernel observation failed: {error:#}"));
            }
            if control_allowed
                && let Err(error) =
                    self.signal_checked(libc::SIGTERM, &mut || checkpoint(deadline, tick))
            {
                self.fail(format!("TERM failed or control expired: {error:#}"));
                control_allowed = false;
            }
            let term_end = Instant::now()
                .checked_add(term_grace)
                .unwrap_or(deadline)
                .min(deadline);
            let mut killed = false;
            let mut reaped_status = None;
            let mut group_absent = false;
            loop {
                if control_allowed && let Err(error) = checkpoint(deadline, tick) {
                    self.fail(format!("settlement control denied: {error:#}"));
                    control_allowed = false;
                }
                if let Err(error) = self.poll_events() {
                    self.fail(format!("kernel observation failed: {error:#}"));
                }
                let exited = match self.exited_unreaped() {
                    Ok(value) => value,
                    Err(error) => {
                        self.fail(format!("lost unreaped ownership: {error:#}"));
                        break;
                    }
                };
                let quiescent = if self.session_ready {
                    match self.snapshot() {
                        Ok(members) => members.count == 1 && exited,
                        Err(error) => {
                            self.fail(format!("group settlement observation failed: {error:#}"));
                            false
                        }
                    }
                } else {
                    exited
                };
                if quiescent {
                    // Observe any last coalesced fork note BEFORE dropping the
                    // unreaped anchor. No signal may be sent after this point.
                    if let Err(error) = self.poll_events() {
                        self.fail(format!("final kernel observation failed: {error:#}"));
                    }
                    let mut status = 0;
                    let result =
                        unsafe { libc::waitpid(self.pid as i32, &mut status, libc::WNOHANG) };
                    if result == self.pid as i32 {
                        self.reaped = true;
                        reaped_status = Some(status);
                        let mut ids = [0_i32; MAX_MEMBERS];
                        match group_ids(self.pid, &mut ids) {
                            Ok(count) => group_absent = count == 0,
                            Err(error) => {
                                self.fail(format!("post-reap group absence unavailable: {error:#}"))
                            }
                        }
                        if !group_absent {
                            self.fail("group not absent after leader reap; no post-reap signals permitted");
                        }
                    } else {
                        self.fail(format!(
                            "leader reap failed or changed: {}",
                            io::Error::last_os_error()
                        ));
                    }
                    break;
                }
                // After denial/expiry only the immediately available quiescent
                // reap above is allowed. No further signals, polling, or grace.
                if !control_allowed {
                    break;
                }
                let now = Instant::now();
                if now >= deadline {
                    self.fail("guardian settlement deadline reached; known group or unreaped leader remains");
                    break;
                }
                if !killed && now >= term_end {
                    if let Err(error) =
                        self.signal_checked(libc::SIGKILL, &mut || checkpoint(deadline, tick))
                    {
                        self.fail(format!("KILL failed or control expired: {error:#}"));
                        break;
                    }
                    killed = true;
                }
                thread::sleep(
                    POLL_INTERVAL.min(deadline.saturating_duration_since(Instant::now())),
                );
            }
            let exit_code = reaped_status
                .filter(|s| libc::WIFEXITED(*s))
                .map(|status| libc::WEXITSTATUS(status));
            let exit_signal = reaped_status
                .filter(|s| libc::WIFSIGNALED(*s))
                .map(|status| libc::WTERMSIG(status));
            let result = Settlement {
                complete: self.reaped && group_absent && self.failure.is_none(),
                leader_reaped: self.reaped,
                group_absent,
                group_signalled: self.group_signalled,
                exit_code,
                exit_signal,
                failure: self.failure.clone(),
            };
            self.settlement = Some(result.clone());
            Ok(result)
        }
    }

    fn checkpoint(deadline: Instant, tick: &mut dyn FnMut() -> Result<()>) -> Result<()> {
        tick()?;
        ensure!(
            Instant::now() < deadline,
            "guardian process deadline reached"
        );
        Ok(())
    }

    fn read_status(
        file: &mut File,
        deadline: Instant,
        tick: &mut dyn FnMut() -> Result<()>,
    ) -> Result<Option<i32>> {
        let mut bytes = [0_u8; 4];
        let mut used = 0;
        loop {
            checkpoint(deadline, tick)?;
            match file.read(&mut bytes[used..]) {
                Ok(0) => {
                    ensure!(used == 0, "truncated child exec status");
                    return Ok(None);
                }
                Ok(count) => {
                    used += count;
                    if used == bytes.len() {
                        return Ok(Some(i32::from_ne_bytes(bytes)));
                    }
                }
                Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => thread::sleep(
                    POLL_INTERVAL.min(deadline.saturating_duration_since(Instant::now())),
                ),
                Err(error) => return Err(error).context("reading child exec status"),
            }
        }
    }

    fn release_barrier(fd: RawFd) -> Result<()> {
        // Darwin supports F_SETNOSIGPIPE on pipes, avoiding signal-mask changes
        // in a potentially multi-threaded caller. This is per file description.
        const F_SETNOSIGPIPE: i32 = 73; // Darwin SDK sys/fcntl.h; absent in libc.
        ensure!(
            unsafe { libc::fcntl(fd, F_SETNOSIGPIPE, 1) } == 0,
            "protecting enrollment barrier from SIGPIPE: {}",
            io::Error::last_os_error()
        );
        let byte = 1_u8;
        ensure!(
            unsafe { libc::write(fd, (&byte as *const u8).cast(), 1) } == 1,
            "releasing enrollment barrier: {}",
            io::Error::last_os_error()
        );
        Ok(())
    }

    #[cfg(test)]
    mod metadata_tests {
        use super::*;

        #[test]
        fn absence_binding_rejects_reuse_and_escape_but_accepts_zombie_transition() {
            let expected = ProcessIdentity {
                pid: 500,
                ppid: 42,
                pgid: 500,
                sid: 500,
                uid: 501,
                start_seconds: 100,
                start_subseconds: 9,
                executable: "/bin/sleep".into(),
                cwd: "/".into(),
                state: ProcessState::Running,
            };
            let bound = Basic {
                pid: 500,
                ppid: 42,
                pgid: 500,
                uid: 501,
                seconds: 100,
                subseconds: 9,
                state: ProcessState::Running,
            };
            let zombie = Basic {
                state: ProcessState::Zombie,
                ppid: 1,
                ..bound
            };
            assert!(validate_binding(&expected, zombie).is_ok());
            for changed in [
                Basic { pid: 501, ..bound },
                Basic { pgid: 501, ..bound },
                Basic { uid: 502, ..bound },
                Basic {
                    seconds: 101,
                    ..bound
                },
                Basic {
                    subseconds: 10,
                    ..bound
                },
            ] {
                assert!(validate_binding(&expected, changed).is_err(), "{changed:?}");
            }
        }
    }
}

#[cfg(not(target_os = "macos"))]
pub fn observe(_pid: u32) -> Result<Option<ProcessIdentity>> {
    bail!("targeted process observation requires Darwin libproc")
}

#[cfg(not(target_os = "macos"))]
pub fn group_members(_pgid: u32) -> Result<Vec<ProcessIdentity>> {
    bail!("bounded targeted group observation requires Darwin libproc")
}

#[cfg(not(target_os = "macos"))]
pub fn bound_absent(_expected: &ProcessIdentity) -> Result<bool> {
    bail!("targeted bound-process absence observation requires Darwin libproc")
}

#[cfg(not(target_os = "macos"))]
pub struct OwnedProcess {
    pub stdout: Option<File>,
    pub stderr: Option<File>,
}

#[cfg(not(target_os = "macos"))]
impl OwnedProcess {
    pub fn spawn_with_deadline(
        _spec: &CommandSpec,
        _deadline: Instant,
        _tick: &mut dyn FnMut() -> Result<()>,
    ) -> Result<Self> {
        bail!(
            "owned process scope requires Darwin pre-exec kernel fork observation; no polling fallback"
        )
    }
    pub fn spawn_with_lease(
        spec: &CommandSpec,
        deadline: Instant,
        tick: &mut dyn FnMut() -> Result<()>,
        _lease_fd: i32,
    ) -> Result<Self> {
        Self::spawn_with_deadline(spec, deadline, tick)
    }
    pub fn pid(&self) -> u32 {
        unreachable!("no supported constructor on this platform")
    }
    pub fn identity(&self) -> Result<ProcessIdentity> {
        bail!("owned process scope requires Darwin")
    }
    pub fn exited_unreaped(&mut self) -> Result<bool> {
        bail!("owned process scope requires Darwin")
    }
    pub fn check_membership(&mut self) -> Result<()> {
        bail!("owned process scope requires Darwin")
    }
    pub fn signal(&mut self, _signal: i32) -> Result<()> {
        bail!("owned process scope requires Darwin")
    }
    pub fn settle(
        &mut self,
        _deadline: Instant,
        _grace: Duration,
        _tick: &mut dyn FnMut() -> Result<()>,
    ) -> Result<Settlement> {
        bail!("owned process scope requires Darwin")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn command() -> CommandSpec {
        CommandSpec {
            executable: "/private/selected-venv/bin/python".into(),
            args: vec!["-c".into(), "pass".into()],
            cwd: "/private/work".into(),
            environment: BTreeMap::new(),
        }
    }

    #[test]
    fn command_rejects_ambiguous_or_unbounded_exec_input() {
        let mut spec = command();
        spec.executable = "python".into();
        assert!(spec.validate().is_err());
        spec = command();
        spec.cwd = "relative".into();
        assert!(spec.validate().is_err());
        spec = command();
        spec.args = vec!["x".repeat(MAX_STRING_BYTES + 1)];
        assert!(spec.validate().is_err());
        spec = command();
        spec.environment.insert("A=B".into(), "value".into());
        assert!(spec.validate().is_err());
        spec = command();
        spec.environment.insert("A".into(), "x\0y".into());
        assert!(spec.validate().is_err());
    }

    #[test]
    fn identity_distinguishes_reuse_escape_and_exec_but_not_stop_or_reparent() {
        let identity = ProcessIdentity {
            pid: 500,
            ppid: 42,
            pgid: 500,
            sid: 500,
            uid: 501,
            start_seconds: 100,
            start_subseconds: 9,
            executable: "/bin/sleep".into(),
            cwd: "/".into(),
            state: ProcessState::Running,
        };
        let mut changed = identity.clone();
        changed.state = ProcessState::Stopped;
        changed.ppid = 1;
        assert!(identity.same_process(&changed));
        changed.start_subseconds += 1;
        assert!(!identity.same_process(&changed));
        changed = identity.clone();
        changed.pgid += 1;
        assert!(!identity.same_process(&changed));
        changed = identity.clone();
        changed.executable = "/bin/sh".into();
        assert!(!identity.same_process(&changed));
        changed = identity.clone();
        changed.cwd = "/private".into();
        assert!(!identity.same_process(&changed));
    }

    #[cfg(target_os = "macos")]
    fn run_isolated(spec: &CommandSpec) -> (Settlement, String, String) {
        use std::io::Read;
        let deadline = Instant::now() + Duration::from_secs(5);
        let mut tick = || Ok(());
        let mut process = OwnedProcess::spawn_with_deadline(spec, deadline, &mut tick).unwrap();
        let observed_exit = loop {
            match process.exited_unreaped() {
                Ok(true) => break Ok(()),
                Err(error) => break Err(error),
                Ok(false) if Instant::now() >= deadline => {
                    break Err(anyhow::anyhow!("isolated fixture deadline"));
                }
                Ok(false) => std::thread::sleep(Duration::from_millis(2)),
            }
        };
        let settlement = process.settle(deadline, Duration::ZERO, &mut tick).unwrap();
        observed_exit.unwrap();
        let mut stdout = String::new();
        let mut stderr = String::new();
        process
            .stdout
            .take()
            .unwrap()
            .read_to_string(&mut stdout)
            .unwrap();
        process
            .stderr
            .take()
            .unwrap()
            .read_to_string(&mut stderr)
            .unwrap();
        (settlement, stdout, stderr)
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn short_lived_exec_preserves_clean_environment_and_unreaped_exit() {
        let spec = CommandSpec {
            executable: "/usr/bin/env".into(),
            args: vec![],
            cwd: "/".into(),
            environment: BTreeMap::from([("SCOPE_VALUE".into(), "isolated".into())]),
        };
        let (settlement, stdout, stderr) = run_isolated(&spec);
        assert!(settlement.complete, "{settlement:?}");
        assert!(settlement.leader_reaped && settlement.group_absent);
        assert_eq!(settlement.exit_code, Some(0));
        assert_eq!(stdout, "SCOPE_VALUE=isolated\n");
        assert_eq!(stderr, "");
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn reaped_fork_still_disqualifies_otherwise_complete_known_group_cleanup() {
        let spec = CommandSpec {
            executable: "/bin/sh".into(),
            args: vec![
                "-c".into(),
                "(exit 0); printf output; printf error >&2; exit 0".into(),
            ],
            cwd: "/".into(),
            environment: BTreeMap::new(),
        };
        let (settlement, stdout, stderr) = run_isolated(&spec);
        assert!(!settlement.complete, "{settlement:?}");
        assert!(settlement.leader_reaped && settlement.group_absent);
        assert!(settlement.failure.is_some());
        assert_eq!(settlement.exit_code, Some(0));
        assert_eq!(stdout, "output");
        assert_eq!(stderr, "error");
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn live_term_transition_settles_without_requiring_dying_process_session() {
        let spec = CommandSpec {
            executable: "/bin/sleep".into(),
            args: vec!["30".into()],
            cwd: "/".into(),
            environment: BTreeMap::new(),
        };
        let deadline = Instant::now() + Duration::from_secs(5);
        let mut tick = || Ok(());
        let mut process = OwnedProcess::spawn_with_deadline(&spec, deadline, &mut tick).unwrap();
        let settlement = process
            .settle(deadline, Duration::from_millis(100), &mut tick)
            .unwrap();
        assert!(settlement.complete, "{settlement:?}");
        assert!(settlement.leader_reaped && settlement.group_absent);
        assert_eq!(settlement.exit_signal, Some(libc::SIGTERM));
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn bound_absence_waits_for_zombie_reap_and_rejects_mismatched_birth() {
        let spec = CommandSpec {
            executable: "/bin/sleep".into(),
            args: vec!["30".into()],
            cwd: "/".into(),
            environment: BTreeMap::new(),
        };
        let deadline = Instant::now() + Duration::from_secs(5);
        let mut tick = || Ok(());
        let mut process = OwnedProcess::spawn_with_deadline(&spec, deadline, &mut tick).unwrap();
        let observations = (|| -> Result<_> {
            let identity = process.identity()?;
            let live_absent = bound_absent(&identity)?;
            let mut reused = identity.clone();
            reused.start_subseconds += 1;
            let reuse_rejected = bound_absent(&reused).is_err();
            process.signal(libc::SIGTERM)?;
            while !process.exited_unreaped()? {
                ensure!(
                    Instant::now() < deadline,
                    "isolated zombie observation deadline"
                );
                std::thread::sleep(Duration::from_millis(2));
            }
            let zombie_absent = bound_absent(&identity)?;
            Ok((identity, live_absent, reuse_rejected, zombie_absent))
        })();
        // Cleanup precedes assertions, including failed observation assertions.
        let settlement = process.settle(deadline, Duration::ZERO, &mut tick).unwrap();
        let (identity, live_absent, reuse_rejected, zombie_absent) = observations.unwrap();
        assert!(settlement.complete, "{settlement:?}");
        assert!(!live_absent && !zombie_absent);
        assert!(reuse_rejected);
        assert!(bound_absent(&identity).unwrap());
        assert_eq!(settlement.exit_signal, Some(libc::SIGTERM));
    }
}
