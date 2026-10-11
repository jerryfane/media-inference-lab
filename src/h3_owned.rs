//! Guardian-owned codec IPC qualification. No native launch authority is minted here.
//!
//! H3's bridge never spawns: every actor uses the existing fork-denying sandbox
//! and OwnedProcess. Protocol tokens are not PIDs. Settlement failures stay final.
use crate::{
    native_guard::{GuardianClock, SANDBOX_EXECUTABLE, SANDBOX_PROFILE},
    process_scope::{CommandSpec, InheritedFd, OwnedProcess, ProcessEnrollment, Settlement},
};
use anyhow::{Context, Result, bail, ensure};
use serde::Serialize;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::{
    collections::BTreeMap,
    fs::{DirBuilder, File, OpenOptions},
    io::{self, Read, Write},
    os::{
        fd::{AsRawFd, FromRawFd, IntoRawFd},
        unix::{
            fs::{DirBuilderExt, OpenOptionsExt},
            net::UnixStream,
        },
    },
    path::Path,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    time::{Duration, Instant},
};

const MAGIC: u32 = 0x3142_484d;
const HEADER: usize = 24;
const PAYLOAD_LIMIT: usize = 16384;
const BROKER_FD: i32 = 198;
const LOG_LIMIT: u64 = 65536;
const VIDEO_BYTES: usize = 8 * 64 * 32 * 3;
const AUDIO_BYTES: usize = 10666 * 2 * 4;
const SCENARIOS: &[&str] = &[
    "success",
    "codec-failure",
    "cancel",
    "guard-denial",
    "root-failure",
    "unknown-tool",
    "direct-fork",
    "helper-fork",
];

fn private_file(path: &Path) -> Result<File> {
    Ok(OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW)
        .open(path)?)
}
fn write_json(path: &Path, value: &impl Serialize) -> Result<()> {
    let mut file = private_file(path)?;
    serde_json::to_writer_pretty(&mut file, value)?;
    file.write_all(b"\n")?;
    file.sync_all()?;
    Ok(())
}
fn file_hash(path: &Path) -> Result<String> {
    let mut input = File::open(path)?;
    ensure!(
        input.metadata()?.is_file() && input.metadata()?.len() <= 256 * 1024 * 1024,
        "invalid fingerprint input"
    );
    let mut hash = Sha256::new();
    let mut buffer = [0; 32768];
    let mut total = 0;
    loop {
        let n = input.read(&mut buffer)?;
        if n == 0 {
            break;
        }
        total += n;
        ensure!(
            total <= 256 * 1024 * 1024,
            "fingerprint byte limit exceeded"
        );
        hash.update(&buffer[..n]);
    }
    Ok(format!("{:x}", hash.finalize()))
}
fn digest(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}
fn pipe_file(file: &File) -> Result<()> {
    let mut stat = std::mem::MaybeUninit::<libc::stat>::uninit();
    ensure!(
        unsafe { libc::fstat(file.as_raw_fd(), stat.as_mut_ptr()) } == 0,
        "cannot identify transferred descriptor"
    );
    ensure!(
        unsafe { stat.assume_init() }.st_mode & libc::S_IFMT == libc::S_IFIFO,
        "codec descriptors must be pipes"
    );
    Ok(())
}
fn nonblocking(fd: i32) -> Result<()> {
    let flags = unsafe { libc::fcntl(fd, libc::F_GETFL) };
    ensure!(
        flags >= 0 && unsafe { libc::fcntl(fd, libc::F_SETFL, flags | libc::O_NONBLOCK) } == 0,
        "cannot set pipe nonblocking"
    );
    Ok(())
}

#[derive(Debug)]
enum Request {
    Spawn {
        id: u32,
        tool: u32,
        targets: Vec<i32>,
        argv: Vec<String>,
    },
    Wait {
        id: u32,
        token: u32,
    },
}
impl Request {
    fn id(&self) -> u32 {
        match self {
            Self::Spawn { id, .. } | Self::Wait { id, .. } => *id,
        }
    }
}
fn word(bytes: &[u8], offset: usize) -> Result<u32> {
    Ok(u32::from_le_bytes(
        bytes
            .get(offset..offset + 4)
            .context("truncated IPC integer")?
            .try_into()?,
    ))
}
fn decode_request(bytes: &[u8], descriptors: usize) -> Result<Request> {
    ensure!(
        bytes.len() >= HEADER && word(bytes, 0)? == MAGIC && word(bytes, 20)? == 0,
        "invalid IPC header"
    );
    let length = word(bytes, 12)? as usize;
    ensure!(
        length <= PAYLOAD_LIMIT && bytes.len() == HEADER + length,
        "invalid IPC payload length"
    );
    ensure!(
        descriptors <= 4 && word(bytes, 16)? as usize == descriptors,
        "IPC descriptor count mismatch"
    );
    let id = word(bytes, 8)?;
    ensure!(id > 0, "invalid request identity");
    let body = &bytes[HEADER..];
    match word(bytes, 4)? {
        1 => {
            let tool = word(body, 0)?;
            ensure!(matches!(tool, 1 | 2), "unregistered codec role");
            let argc = word(body, 4)? as usize;
            ensure!((1..=128).contains(&argc), "invalid IPC argument count");
            let mut targets = Vec::with_capacity(descriptors);
            for index in 0..descriptors {
                let target = word(body, 8 + index * 4)?;
                ensure!(
                    target <= 1023
                        && target != BROKER_FD as u32
                        && !targets.contains(&(target as i32)),
                    "invalid or duplicate codec target"
                );
                targets.push(target as i32);
            }
            let mut cursor = 8 + descriptors * 4;
            let mut argv = Vec::with_capacity(argc);
            for _ in 0..argc {
                let size = word(body, cursor)? as usize;
                cursor += 4;
                let argument = body
                    .get(cursor..cursor.checked_add(size).context("argument size overflow")?)
                    .context("truncated IPC argument")?;
                ensure!(!argument.contains(&0), "NUL in IPC argument");
                argv.push(std::str::from_utf8(argument)?.to_owned());
                cursor += size;
            }
            ensure!(cursor == body.len(), "trailing IPC data");
            ensure!(
                argv[0] == if tool == 1 { "ffmpeg" } else { "ffprobe" },
                "codec argv identity mismatch"
            );
            Ok(Request::Spawn {
                id,
                tool,
                targets,
                argv,
            })
        }
        2 => {
            ensure!(descriptors == 0 && body.len() == 4, "invalid wait request");
            Ok(Request::Wait {
                id,
                token: word(body, 0)?,
            })
        }
        _ => bail!("unsupported IPC operation"),
    }
}

// SCM_RIGHTS is received even when payload framing subsequently fails. Own every
// delivered descriptor before inspecting framing/truncation; dropping the reader
// closes it on every error/EOF path. No descriptor number supplied in payload is used.
struct Reader {
    bytes: [u8; HEADER + PAYLOAD_LIMIT],
    used: usize,
    files: Vec<File>,
    eof: bool,
}
impl Reader {
    fn new() -> Self {
        Self {
            bytes: [0; HEADER + PAYLOAD_LIMIT],
            used: 0,
            files: Vec::with_capacity(4),
            eof: false,
        }
    }
    fn receive(&mut self, socket: &UnixStream) -> Result<Option<Request>> {
        let target = if self.used < HEADER {
            HEADER
        } else {
            let size = word(&self.bytes, 12)? as usize;
            ensure!(size <= PAYLOAD_LIMIT, "IPC frame exceeds byte bound");
            HEADER + size
        };
        if self.used == target && self.used >= HEADER {
            return decode_request(&self.bytes[..self.used], self.files.len()).map(Some);
        }
        #[repr(C, align(8))]
        struct Ancillary([u8; 128]);
        let mut ancillary = Ancillary([0; 128]);
        let mut iov = libc::iovec {
            iov_base: self.bytes[self.used..target].as_mut_ptr().cast(),
            iov_len: target - self.used,
        };
        let mut message: libc::msghdr = unsafe { std::mem::zeroed() };
        message.msg_iov = &mut iov;
        message.msg_iovlen = 1;
        message.msg_control = ancillary.0.as_mut_ptr().cast();
        message.msg_controllen = ancillary.0.len() as _;
        let n = unsafe { libc::recvmsg(socket.as_raw_fd(), &mut message, 0) };
        if n < 0 {
            let error = io::Error::last_os_error();
            if matches!(
                error.kind(),
                io::ErrorKind::WouldBlock | io::ErrorKind::Interrupted
            ) {
                return Ok(None);
            }
            return Err(error.into());
        }
        let before = self.files.len();
        let mut unexpected = false;
        unsafe {
            let mut cmsg = libc::CMSG_FIRSTHDR(&message);
            while !cmsg.is_null() {
                let size = (*cmsg).cmsg_len as usize;
                let base = libc::CMSG_LEN(0) as usize;
                ensure!(size >= base, "invalid ancillary length");
                if (*cmsg).cmsg_level == libc::SOL_SOCKET && (*cmsg).cmsg_type == libc::SCM_RIGHTS {
                    let count = (size - base) / std::mem::size_of::<i32>();
                    for index in 0..count {
                        let fd = std::ptr::read_unaligned(
                            libc::CMSG_DATA(cmsg).cast::<i32>().add(index),
                        );
                        if fd >= 0 {
                            let file = File::from_raw_fd(fd);
                            let flags = libc::fcntl(fd, libc::F_GETFD);
                            if flags < 0
                                || libc::fcntl(fd, libc::F_SETFD, flags | libc::FD_CLOEXEC) < 0
                            {
                                unexpected = true;
                            }
                            self.files.push(file);
                        } else {
                            unexpected = true;
                        }
                    }
                    unexpected |= !(size - base).is_multiple_of(std::mem::size_of::<i32>());
                } else {
                    unexpected = true;
                }
                cmsg = libc::CMSG_NXTHDR(&message, cmsg);
            }
        }
        ensure!(
            !unexpected && message.msg_flags & (libc::MSG_CTRUNC | libc::MSG_TRUNC) == 0,
            "invalid or truncated ancillary data"
        );
        ensure!(
            self.files.len() <= 4 && (self.used == 0 || before == self.files.len()),
            "unexpected transferred descriptors"
        );
        if n == 0 {
            self.eof = true;
            ensure!(
                self.used == 0 && self.files.is_empty(),
                "truncated IPC frame at EOF"
            );
            return Ok(None);
        }
        self.used += n as usize;
        Ok(None)
    }
    fn clear(&mut self) {
        self.used = 0;
        self.files.clear();
    }
}
struct Reply {
    bytes: [u8; HEADER],
    sent: usize,
}
impl Reply {
    fn new(op: u32, id: u32, errno: i32, value: u32) -> Self {
        let mut bytes = [0; HEADER];
        for (chunk, value) in bytes.as_chunks_mut::<4>().0.iter_mut().zip([
            MAGIC,
            op | 0x8000_0000,
            id,
            errno as u32,
            value,
            0,
        ]) {
            chunk.copy_from_slice(&value.to_le_bytes());
        }
        Self { bytes, sent: 0 }
    }
    fn flush(&mut self, socket: &mut UnixStream) -> Result<bool> {
        match socket.write(&self.bytes[self.sent..]) {
            Ok(0) => bail!("broker reply stream closed"),
            Ok(n) => self.sent += n,
            Err(error)
                if matches!(
                    error.kind(),
                    io::ErrorKind::WouldBlock | io::ErrorKind::Interrupted
                ) => {}
            Err(error) => return Err(error.into()),
        }
        Ok(self.sent == HEADER)
    }
}

#[derive(Serialize)]
struct ActorRecord {
    role: &'static str,
    token: Option<u32>,
    pid: u32,
    enrollment: Option<ProcessEnrollment>,
    command: CommandSpec,
    spawn_failure: Option<String>,
    settlement: Option<Settlement>,
    settlement_error: Option<String>,
}
struct Actor {
    process: OwnedProcess,
    record: ActorRecord,
}
impl Actor {
    fn create(
        spec: CommandSpec,
        role: &'static str,
        token: Option<u32>,
        mappings: &[InheritedFd<'_>],
        control: &mut Control,
        journal: &mut File,
    ) -> Result<Self> {
        event(
            journal,
            &json!({"event":"spawn_intent","role":role,"token":token,"command":spec}),
        )?;
        let attempt = OwnedProcess::spawn_with_io(
            &spec,
            control.work_deadline,
            &mut || control.active(),
            mappings,
            None,
        )?;
        let record = ActorRecord {
            role,
            token,
            pid: attempt.process.pid(),
            enrollment: attempt.process.enrollment(),
            command: spec,
            spawn_failure: attempt.failure,
            settlement: None,
            settlement_error: None,
        };
        // Return custody even if recording fails. Never let an I/O error drop a
        // just-created child before the caller can apply independent cleanup.
        let mut actor = Self {
            process: attempt.process,
            record,
        };
        if let Err(error) = event(
            journal,
            &json!({"event":"spawn_observed","actor":actor.record}),
        ) {
            actor
                .record
                .spawn_failure
                .get_or_insert_with(|| format!("spawn evidence failed: {error:#}"));
        }
        Ok(actor)
    }
    fn settle(&mut self, control: &mut Control, journal: &mut File) {
        if self.record.settlement.is_some() || self.record.settlement_error.is_some() {
            return;
        }
        let deadline = control.clock.phase_deadline(Duration::from_secs(2));
        match self
            .process
            .settle(deadline, Duration::from_millis(200), &mut || {
                control.clock.recovery_check()
            }) {
            Ok(settlement) => self.record.settlement = Some(settlement),
            Err(error) => self.record.settlement_error = Some(format!("{error:#}")),
        }
        // The original result is final even if the journal disk is exhausted.
        if let Err(error) = event(
            journal,
            &json!({"event":"original_settlement","actor":self.record}),
        ) {
            control
                .evidence_error
                .get_or_insert_with(|| format!("{error:#}"));
        }
    }
    fn complete(&self) -> bool {
        self.record.settlement.as_ref().is_some_and(|s| s.complete)
    }
}
fn event(file: &mut File, value: &Value) -> Result<()> {
    ensure!(
        file.metadata()?.len() < 1024 * 1024,
        "broker journal bound exceeded"
    );
    serde_json::to_writer(&mut *file, value)?;
    file.write_all(b"\n")?;
    file.sync_data()?;
    Ok(())
}
struct Control {
    clock: GuardianClock,
    work_deadline: Instant,
    cancelled: Arc<AtomicBool>,
    scenario: String,
    media_started: Option<Instant>,
    stop: Option<&'static str>,
    evidence_error: Option<String>,
}
impl Control {
    fn active(&mut self) -> Result<()> {
        self.clock.check()?;
        ensure!(
            Instant::now() < self.work_deadline,
            "CPU broker work deadline expired"
        );
        let trigger = self
            .media_started
            .is_some_and(|at| at.elapsed() >= Duration::from_millis(200));
        if self.cancelled.load(Ordering::SeqCst) || (trigger && self.scenario == "cancel") {
            self.stop = Some("cancelled");
            bail!("CPU qualification cancellation; admission revoked");
        }
        if trigger && self.scenario == "guard-denial" {
            self.stop = Some("guard_denied");
            bail!("purpose-built CPU guard denial; admission revoked");
        }
        ensure!(self.stop.is_none(), "broker admission already revoked");
        Ok(())
    }
}
struct Logs {
    stdout: File,
    stderr: File,
    out_bytes: u64,
    err_bytes: u64,
}
impl Logs {
    fn new(dir: &Path) -> Result<Self> {
        Ok(Self {
            stdout: private_file(&dir.join("stdout.log"))?,
            stderr: private_file(&dir.join("stderr.log"))?,
            out_bytes: 0,
            err_bytes: 0,
        })
    }
    fn drain(&mut self, root: &mut Actor) -> Result<()> {
        for (source, target, count) in [
            (
                &mut root.process.stdout,
                &mut self.stdout,
                &mut self.out_bytes,
            ),
            (
                &mut root.process.stderr,
                &mut self.stderr,
                &mut self.err_bytes,
            ),
        ] {
            if let Some(source) = source {
                let mut buffer = [0; 8192];
                for _ in 0..8 {
                    match source.read(&mut buffer) {
                        Ok(0) => break,
                        Ok(n) => {
                            ensure!(
                                *count + n as u64 <= LOG_LIMIT,
                                "actor log byte limit exceeded"
                            );
                            target.write_all(&buffer[..n])?;
                            *count += n as u64;
                        }
                        Err(error) if error.kind() == io::ErrorKind::WouldBlock => break,
                        Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
                        Err(error) => return Err(error.into()),
                    }
                }
            }
        }
        Ok(())
    }
}
fn sandbox_command(
    binary: &Path,
    dir: &Path,
    args: impl IntoIterator<Item = String>,
    broker: bool,
) -> CommandSpec {
    let mut command = vec![
        "-D".into(),
        format!("MIL_RUN={}", dir.display()),
        "-p".into(),
        SANDBOX_PROFILE.into(),
        binary.to_string_lossy().into_owned(),
    ];
    command.extend(args);
    let mut environment = BTreeMap::from([("LC_ALL".into(), "C".into())]);
    if broker {
        environment.extend([
            ("MIL_H3_BROKER_FD".into(), BROKER_FD.to_string()),
            ("MIL_H3_BROKER_TIMEOUT_MS".into(), "10000".into()),
            ("H3_FFMPEG".into(), "ffmpeg".into()),
            ("H3_FFPROBE".into(), "ffprobe".into()),
        ]);
    }
    CommandSpec {
        executable: SANDBOX_EXECUTABLE.into(),
        args: command,
        cwd: dir.to_owned(),
        environment,
    }
}
fn wait_status(settlement: &Settlement) -> Result<u32> {
    ensure!(
        settlement.complete,
        "unqualified helper settlement cannot produce wait success"
    );
    match (settlement.exit_code, settlement.exit_signal) {
        (Some(code), None) if (0..=255).contains(&code) => Ok((code as u32) << 8),
        (None, Some(signal)) if (1..=127).contains(&signal) => Ok(signal as u32),
        _ => bail!("helper exit status unavailable or invalid"),
    }
}

/// Runs only the project CPU C fixture and fixed Rust media helpers. This does
/// not read native plans, accept executable paths, acquire GPU leases, or enter
/// the service/maintenance authority path. A non-success actor stays non-success
/// even when its negative-case qualification expectations pass.
pub fn qualify(output_dir: &Path, scenario: &str) -> Result<bool> {
    ensure!(
        cfg!(target_os = "macos"),
        "owned H3 qualification requires Darwin"
    );
    ensure!(SCENARIOS.contains(&scenario), "unsupported CPU scenario");
    let dir = std::path::absolute(output_dir)?;
    let parent = dir
        .parent()
        .context("output has no parent")?
        .canonicalize()?;
    let dir = parent.join(dir.file_name().context("output has no name")?);
    DirBuilder::new()
        .mode(0o700)
        .create(&dir)
        .context("qualification requires a new output directory")?;
    let binary = std::env::current_exe()?.canonicalize()?;
    let binary_sha = file_hash(&binary)?;
    let sandbox_sha = file_hash(Path::new(SANDBOX_EXECUTABLE))?;
    let mut journal = private_file(&dir.join("events.jsonl"))?;
    let mut logs = Logs::new(&dir)?;
    let cancelled = Arc::new(AtomicBool::new(false));
    let sigint = signal_hook::flag::register(libc::SIGINT, cancelled.clone())?;
    let sigterm = match signal_hook::flag::register(libc::SIGTERM, cancelled.clone()) {
        Ok(id) => id,
        Err(error) => {
            signal_hook::low_level::unregister(sigint);
            return Err(error.into());
        }
    };
    struct Signals(signal_hook::SigId, signal_hook::SigId);
    impl Drop for Signals {
        fn drop(&mut self) {
            signal_hook::low_level::unregister(self.0);
            signal_hook::low_level::unregister(self.1);
        }
    }
    let _signals = Signals(sigint, sigterm);
    let mut control = Control {
        clock: GuardianClock::new(Duration::from_secs(14))?,
        work_deadline: Instant::now() + Duration::from_secs(8),
        cancelled,
        scenario: scenario.into(),
        media_started: None,
        stop: None,
        evidence_error: None,
    };
    let (mut socket, client) = UnixStream::pair()?;
    socket.set_nonblocking(true)?;
    #[cfg(target_os = "macos")]
    {
        let one = 1_i32;
        ensure!(
            unsafe {
                libc::setsockopt(
                    socket.as_raw_fd(),
                    libc::SOL_SOCKET,
                    libc::SO_NOSIGPIPE,
                    (&one as *const i32).cast(),
                    std::mem::size_of_val(&one) as _,
                )
            } == 0,
            "broker no-SIGPIPE configuration failed"
        );
    }
    let client = unsafe { File::from_raw_fd(client.into_raw_fd()) };
    let spec = sandbox_command(
        &binary,
        &dir,
        [
            "h3-cpu-fixture".into(),
            "--scenario".into(),
            scenario.into(),
            "--output-dir".into(),
            dir.to_string_lossy().into_owned(),
        ],
        true,
    );
    let mut root = match Actor::create(
        spec,
        "root",
        None,
        &[InheritedFd {
            file: &client,
            target: BROKER_FD,
        }],
        &mut control,
        &mut journal,
    ) {
        Ok(actor) => actor,
        Err(error) => {
            write_json(
                &dir.join("report.json"),
                &json!({"schema":"mil.h3-owned-cpu.v1","scenario":scenario,"outcome":"spawn_failed","failure":format!("{error:#}"),"native_execution_attested":false,"capture_eligible":false,"creation_attempted":true,"child_created":false}),
            )?;
            return Ok(false);
        }
    };
    drop(client);
    let mut helpers: Vec<Actor> = Vec::with_capacity(2);
    let mut active: Option<usize> = None;
    let mut waiting: Option<u32> = None;
    let mut reply: Option<Reply> = None;
    let mut reader = Reader::new();
    let mut next_request = 1_u32;
    let execution = (|| -> Result<()> {
        ensure!(
            root.record.spawn_failure.is_none(),
            "root spawn failed: {:?}",
            root.record.spawn_failure
        );
        loop {
            control.active()?;
            logs.drain(&mut root)?;
            root.process.check_membership()?;
            if let Some(index) = active {
                helpers[index].process.check_membership()?;
            }
            if let (Some(index), Some(id)) = (active, waiting)
                && helpers[index].process.exited_unreaped()?
            {
                helpers[index].settle(&mut control, &mut journal);
                let status = wait_status(
                    helpers[index]
                        .record
                        .settlement
                        .as_ref()
                        .context("helper settlement unavailable")?,
                )?;
                reply = Some(Reply::new(2, id, 0, status));
                waiting = None;
                active = None;
            }
            if let Some(pending) = &mut reply {
                if pending.flush(&mut socket)? {
                    reply = None;
                }
            } else if waiting.is_none()
                && !reader.eof
                && let Some(request) = reader.receive(&socket)?
            {
                ensure!(
                    request.id() == next_request && next_request <= 32,
                    "replayed, out-of-order, or excessive IPC request"
                );
                next_request += 1;
                match request {
                    Request::Spawn {
                        id,
                        tool,
                        targets,
                        argv,
                    } => {
                        ensure!(
                            active.is_none() && helpers.len() < 16,
                            "overlapping or excessive codec creation"
                        );
                        for file in &reader.files {
                            pipe_file(file)?;
                        }
                        ensure!(
                            targets.contains(&1) && targets.contains(&2),
                            "codec output must use explicit bounded root pipes"
                        );
                        if tool == 2 {
                            ensure!(
                                argv == ["ffprobe", "--mil-cpu-probe"],
                                "probe role cannot select another fixture operation"
                            );
                        } else {
                            ensure!(
                                argv.len() == 7
                                    && argv[1] == "--mil-cpu-mode"
                                    && argv[2] == scenario
                                    && argv[3] == "--audio-fd"
                                    && argv[5] == "--output-dir"
                                    && Path::new(&argv[6]) == dir,
                                "codec fixture request differs from guardian selection"
                            );
                            let audio_target: i32 = argv[4].parse()?;
                            ensure!(
                                audio_target > 2
                                    && targets.contains(&0)
                                    && targets.contains(&audio_target),
                                "codec media pipes missing"
                            );
                        }
                        let mappings: Vec<_> = reader
                            .files
                            .iter()
                            .zip(targets)
                            .map(|(file, target)| InheritedFd { file, target })
                            .collect();
                        let mut args = vec!["h3-cpu-codec".into(), "--".into()];
                        args.extend(argv.into_iter().skip(1));
                        let spec = sandbox_command(&binary, &dir, args, false);
                        let token = helpers.len() as u32 + 1;
                        let actor = Actor::create(
                            spec,
                            if tool == 1 {
                                "ffmpeg_cpu_fixture"
                            } else {
                                "ffprobe_cpu_fixture"
                            },
                            Some(token),
                            &mappings,
                            &mut control,
                            &mut journal,
                        )?;
                        helpers.push(actor);
                        active = Some(helpers.len() - 1);
                        ensure!(
                            helpers
                                .last()
                                .is_some_and(|actor| actor.record.spawn_failure.is_none()),
                            "helper enrollment/exec failed"
                        );
                        if tool == 1 {
                            control.media_started = Some(Instant::now());
                        }
                        reply = Some(Reply::new(1, id, 0, token));
                    }
                    Request::Wait { id, token } => {
                        let index = active.context("wait has no owned helper")?;
                        ensure!(
                            helpers[index].record.token == Some(token),
                            "wait token mismatch"
                        );
                        waiting = Some(id);
                    }
                }
                reader.clear();
            }
            if root.process.exited_unreaped()? {
                ensure!(
                    active.is_none() && waiting.is_none() && reply.is_none(),
                    "root exited with outstanding codec protocol"
                );
                break;
            }
            std::thread::sleep(Duration::from_millis(2));
        }
        Ok(())
    })();
    // Close admission before cleanup. No IPC reply can manufacture a settlement.
    control.stop.get_or_insert("finished");
    drop(reader);
    drop(socket);
    for helper in helpers.iter_mut().rev() {
        helper.settle(&mut control, &mut journal);
    }
    root.settle(&mut control, &mut journal);
    if let Err(error) = logs.drain(&mut root) {
        control
            .evidence_error
            .get_or_insert_with(|| format!("{error:#}"));
    }
    logs.stdout.sync_all()?;
    logs.stderr.sync_all()?;
    let complete = root.complete() && helpers.iter().all(Actor::complete);
    let root_code = root.record.settlement.as_ref().and_then(|s| s.exit_code);
    let failure = execution.err().map(|error| format!("{error:#}"));
    let mut outcome = if !complete {
        "settlement_failed"
    } else if control.stop == Some("cancelled") {
        "cancelled"
    } else if control.stop == Some("guard_denied") {
        "guard_denied"
    } else if failure.is_some() || control.evidence_error.is_some() {
        "failed"
    } else if root_code == Some(0) {
        "completed"
    } else {
        "failed"
    };
    let media = if outcome == "completed" {
        Some(verify_media(&dir))
    } else {
        None
    };
    let media_verified = media.as_ref().is_some_and(|result| result.is_ok());
    if outcome == "completed" && !media_verified {
        outcome = "media_failed";
    }
    let stdout = std::fs::read_to_string(dir.join("stdout.log"))?;
    let qualification_passed = complete
        && control.evidence_error.is_none()
        && match scenario {
            "success" => {
                outcome == "completed"
                    && media_verified
                    && helpers.len() == 2
                    && helpers.iter().all(|h| {
                        h.record
                            .settlement
                            .as_ref()
                            .is_some_and(|s| s.exit_code == Some(0))
                    })
            }
            "codec-failure" => {
                failure.is_none()
                    && root_code.is_some_and(|code| code != 0)
                    && helpers.last().is_some_and(|h| {
                        h.record
                            .settlement
                            .as_ref()
                            .is_some_and(|s| s.exit_code == Some(7))
                    })
            }
            "root-failure" => {
                failure.is_none()
                    && root_code.is_some_and(|code| code != 0)
                    && helpers.len() == 2
                    && helpers.iter().all(|h| {
                        h.record
                            .settlement
                            .as_ref()
                            .is_some_and(|s| s.exit_code == Some(0))
                    })
            }
            "cancel" => outcome == "cancelled" && helpers.len() == 2,
            "guard-denial" => outcome == "guard_denied" && helpers.len() == 2,
            "unknown-tool" => {
                failure.is_none()
                    && root_code == Some(77)
                    && helpers.is_empty()
                    && stdout
                        .lines()
                        .any(|line| line == "MIL_CPU_UNKNOWN_TOOL_DENIED errno=2")
            }
            "direct-fork" => {
                failure.is_none()
                    && root_code == Some(77)
                    && helpers.is_empty()
                    && stdout
                        .lines()
                        .any(|line| line == "MIL_CPU_DIRECT_FORK_DENIED errno=1")
            }
            "helper-fork" => {
                failure.is_none()
                    && root_code == Some(13)
                    && helpers.len() == 2
                    && stdout
                        .lines()
                        .any(|line| line == "MIL_CPU_HELPER_FORK_DENIED errno=1")
            }
            _ => false,
        };
    let media_error = media
        .and_then(|result| result.err())
        .map(|error| format!("{error:#}"));
    let report = json!({
        "schema":"mil.h3-owned-cpu.v1", "scenario":scenario, "outcome":outcome,
        "qualification_passed":qualification_passed, "failure":failure, "evidence_error":control.evidence_error,
        "settlement_complete":complete, "media_verified":media_verified, "media_error":media_error,
        "native_execution_attested":false, "capture_eligible":false, "restoration_authority":false,
        "platform":{"os":std::env::consts::OS,"arch":std::env::consts::ARCH,"ownership_method":"Darwin pre-exec EVFILT_PROC enrollment, libproc birth/group snapshots, guardian waitid/waitpid; CPU evidence only"},
        "provenance":{"kind":"purpose_built_cpu_process_and_raw_media_fixture","native_h3_invoked":false,"real_ffmpeg_invoked":false,"models_loaded":false,"gpu_lease_acquired":false,"live_services_probed_or_controlled":false,"guard":"guardian monotonic/wall-clock deadlines, owned-process membership, bounded IPC/logs; guard-denial is a CPU fixture, not a system-memory or live-workload observation","binary":binary,"binary_sha256":binary_sha,"sandbox_executable":SANDBOX_EXECUTABLE,"sandbox_sha256":sandbox_sha,"sandbox_profile":SANDBOX_PROFILE,"broker_protocol":1},
        "elapsed_ms":control.clock.elapsed_ms(), "root":root.record, "helpers":helpers.iter().map(|h| &h.record).collect::<Vec<_>>(),
        "logs":{"stdout":{"bytes":logs.out_bytes,"sha256":file_hash(&dir.join("stdout.log"))?},"stderr":{"bytes":logs.err_bytes,"sha256":file_hash(&dir.join("stderr.log"))?}},
        "limits":{"work_seconds":8,"guardian_seconds":14,"settlement_seconds_per_actor":2,"helper_seconds":3,"max_helpers":16,"max_requests":32,"max_payload_bytes":PAYLOAD_LIMIT,"max_log_bytes_per_stream":LOG_LIMIT},
    });
    write_json(&dir.join("report.json"), &report)?;
    Ok(outcome == "completed" && qualification_passed)
}

#[cfg(target_os = "macos")]
unsafe extern "C" {
    fn mil_h3_cpu_fixture(
        scenario: *const libc::c_char,
        output_dir: *const libc::c_char,
    ) -> libc::c_int;
}
pub fn cpu_fixture(scenario: &str, output_dir: &Path) -> Result<i32> {
    ensure!(
        SCENARIOS.contains(&scenario),
        "unsupported CPU fixture scenario"
    );
    #[cfg(target_os = "macos")]
    {
        let scenario = std::ffi::CString::new(scenario)?;
        let output = std::ffi::CString::new(output_dir.as_os_str().as_encoded_bytes())?;
        Ok(unsafe { mil_h3_cpu_fixture(scenario.as_ptr(), output.as_ptr()) })
    }
    #[cfg(not(target_os = "macos"))]
    {
        let _ = output_dir;
        bail!("CPU bridge requires Darwin")
    }
}

/// Private CLI actor, not an encoder substitute. It consumes real dual pipes,
/// writes a genuine raw-sample PNG/PCM, and exits on a finite three-second bound.
pub fn cpu_codec(args: &[String]) -> Result<i32> {
    ensure!(
        unsafe { libc::fcntl(BROKER_FD, libc::F_GETFD) } == -1
            && io::Error::last_os_error().raw_os_error() == Some(libc::EBADF),
        "codec inherited broker authority"
    );
    if args == ["--mil-cpu-probe"] {
        println!("64x32");
        return Ok(0);
    }
    ensure!(
        args.len() == 6
            && args[0] == "--mil-cpu-mode"
            && args[2] == "--audio-fd"
            && args[4] == "--output-dir",
        "invalid CPU codec arguments"
    );
    let scenario = &args[1];
    ensure!(
        SCENARIOS.contains(&scenario.as_str()),
        "invalid CPU codec mode"
    );
    let audio_fd: i32 = args[3].parse()?;
    ensure!(
        (3..=1023).contains(&audio_fd) && audio_fd != BROKER_FD,
        "invalid audio descriptor"
    );
    let mut video = unsafe { File::from_raw_fd(libc::STDIN_FILENO) };
    let mut audio = unsafe { File::from_raw_fd(audio_fd) };
    pipe_file(&video)?;
    pipe_file(&audio)?;
    nonblocking(video.as_raw_fd())?;
    nonblocking(audio.as_raw_fd())?;
    let started = Instant::now();
    let mut rgb = Vec::with_capacity(VIDEO_BYTES);
    let mut pcm = Vec::with_capacity(AUDIO_BYTES);
    let mut eof = [false; 2];
    while !eof.iter().all(|closed| *closed) {
        ensure!(
            started.elapsed() < Duration::from_secs(2),
            "CPU pipe consumption deadline expired"
        );
        for (index, file, data, limit) in [
            (0, &mut video, &mut rgb, VIDEO_BYTES),
            (1, &mut audio, &mut pcm, AUDIO_BYTES),
        ] {
            if eof[index] {
                continue;
            }
            let mut buffer = [0; 8192];
            match file.read(&mut buffer) {
                Ok(0) => eof[index] = true,
                Ok(n) => {
                    ensure!(
                        data.len() + n <= limit,
                        "CPU fixture media byte limit exceeded"
                    );
                    data.extend_from_slice(&buffer[..n]);
                }
                Err(error)
                    if matches!(
                        error.kind(),
                        io::ErrorKind::WouldBlock | io::ErrorKind::Interrupted
                    ) => {}
                Err(error) => return Err(error.into()),
            }
        }
        std::thread::sleep(Duration::from_millis(1));
    }
    ensure!(
        rgb.len() == VIDEO_BYTES && pcm.len() == AUDIO_BYTES,
        "CPU fixture streams truncated"
    );
    println!(
        "MIL_CPU_STREAMS_CONSUMED video_bytes={} audio_bytes={}",
        rgb.len(),
        pcm.len()
    );
    if scenario == "helper-fork" {
        let child = unsafe { libc::fork() };
        if child == 0 {
            unsafe { libc::_exit(97) };
        }
        if child < 0 {
            println!(
                "MIL_CPU_HELPER_FORK_DENIED errno={}",
                io::Error::last_os_error().raw_os_error().unwrap_or(0)
            );
            return Ok(13);
        }
        eprintln!("unexpected CPU helper fork succeeded; scope must remain unqualified");
        return Ok(98);
    }
    if scenario == "codec-failure" {
        return Ok(7);
    }
    if matches!(scenario.as_str(), "cancel" | "guard-denial") {
        while started.elapsed() < Duration::from_secs(3) {
            std::thread::sleep(Duration::from_millis(10));
        }
        return Ok(75);
    }
    let dir = Path::new(&args[5]);
    let mut encoder = png::Encoder::new(private_file(&dir.join("first-frame.png"))?, 64, 32);
    encoder.set_color(png::ColorType::Rgb);
    encoder.set_depth(png::BitDepth::Eight);
    let mut writer = encoder.write_header()?;
    writer.write_image_data(&rgb[..64 * 32 * 3])?;
    writer.finish()?;
    let mut pcm_file = private_file(&dir.join("audio.f32le"))?;
    pcm_file.write_all(&pcm)?;
    pcm_file.sync_all()?;
    write_json(
        &dir.join("streams.json"),
        &json!({"kind":"cpu_raw_media_fixture_not_inference_or_ffmpeg","video_bytes":rgb.len(),"video_frames":8,"width":64,"height":32,"video_sha256":digest(&rgb),"audio_bytes":pcm.len(),"audio_sample_frames":10666,"audio_channels":2,"audio_format":"f32le","audio_sha256":digest(&pcm),"first_frame_png_sha256":file_hash(&dir.join("first-frame.png"))?}),
    )?;
    Ok(0)
}
fn verify_media(dir: &Path) -> Result<()> {
    let rgb: Vec<u8> = (0..VIDEO_BYTES)
        .map(|i| (i.wrapping_mul(17).wrapping_add(3)) as u8)
        .collect();
    let mut pcm = Vec::with_capacity(AUDIO_BYTES);
    for i in 0..AUDIO_BYTES / 4 {
        pcm.extend_from_slice(&((i % 101) as f32 / 101.0_f32).to_le_bytes());
    }
    let streams: Value = serde_json::from_reader(File::open(dir.join("streams.json"))?)?;
    ensure!(
        streams["video_sha256"] == digest(&rgb)
            && streams["video_bytes"] == VIDEO_BYTES
            && streams["audio_sha256"] == digest(&pcm)
            && streams["audio_bytes"] == AUDIO_BYTES,
        "fixture stream content mismatch"
    );
    ensure!(
        file_hash(&dir.join("audio.f32le"))? == digest(&pcm),
        "saved PCM mismatch"
    );
    let image = crate::png_image::decode(&dir.join("first-frame.png"))?;
    ensure!(
        image.samples() == &rgb[..64 * 32 * 3],
        "saved first-frame pixels mismatch"
    );
    ensure!(
        streams["first_frame_png_sha256"] == file_hash(&dir.join("first-frame.png"))?,
        "saved PNG provenance mismatch"
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    fn frame(op: u32, count: u32, body: &[u8]) -> Vec<u8> {
        let mut bytes = Vec::new();
        for n in [MAGIC, op, 1, body.len() as u32, count, 0] {
            bytes.extend_from_slice(&n.to_le_bytes());
        }
        bytes.extend_from_slice(body);
        bytes
    }
    #[test]
    fn forged_waits_and_descriptor_counts_are_rejected() {
        assert!(decode_request(&frame(2, 0, &7_u32.to_le_bytes()), 1).is_err());
        assert!(decode_request(&frame(2, 1, &7_u32.to_le_bytes()), 1).is_err());
        assert!(decode_request(&frame(2, 0, &[0; 8]), 0).is_err());
        assert!(matches!(
            decode_request(&frame(2, 0, &7_u32.to_le_bytes()), 0).unwrap(),
            Request::Wait { token: 7, .. }
        ));
    }
    #[test]
    fn failed_settlement_cannot_become_native_wait_success() {
        let mut s = Settlement {
            complete: false,
            leader_reaped: true,
            group_absent: true,
            group_signalled: false,
            exit_code: Some(0),
            exit_signal: None,
            failure: Some("retained failure".into()),
        };
        assert!(wait_status(&s).is_err());
        s.complete = true;
        s.failure = None;
        s.exit_code = None;
        assert!(wait_status(&s).is_err());
        s.exit_signal = Some(15);
        let status = wait_status(&s).unwrap() as i32;
        assert!(libc::WIFSIGNALED(status));
        assert_eq!(libc::WTERMSIG(status), 15);
        s.exit_signal = None;
        s.exit_code = Some(7);
        let status = wait_status(&s).unwrap() as i32;
        assert!(libc::WIFEXITED(status));
        assert_eq!(libc::WEXITSTATUS(status), 7);
    }
    #[test]
    fn fragmented_frame_requires_every_byte_before_acceptance() {
        let (socket, mut peer) = UnixStream::pair().unwrap();
        socket.set_nonblocking(true).unwrap();
        let bytes = frame(2, 0, &9_u32.to_le_bytes());
        let mut reader = Reader::new();
        peer.write_all(&bytes[..3]).unwrap();
        assert!(reader.receive(&socket).unwrap().is_none());
        assert!(reader.receive(&socket).unwrap().is_none());
        peer.write_all(&bytes[3..]).unwrap();
        assert!(reader.receive(&socket).unwrap().is_none());
        assert!(reader.receive(&socket).unwrap().is_none());
        assert!(matches!(
            reader.receive(&socket).unwrap(),
            Some(Request::Wait { token: 9, .. })
        ));
    }

    #[test]
    fn rejected_frame_closes_received_rights_without_closing_sender_source() {
        let (socket, peer) = UnixStream::pair().unwrap();
        socket.set_nonblocking(true).unwrap();
        let mut pair = [-1; 2];
        assert_eq!(unsafe { libc::pipe(pair.as_mut_ptr()) }, 0);
        let mut read_end = unsafe { File::from_raw_fd(pair[0]) };
        let write_end = unsafe { File::from_raw_fd(pair[1]) };
        nonblocking(read_end.as_raw_fd()).unwrap();
        let bytes = frame(2, 1, &9_u32.to_le_bytes());
        #[repr(C, align(8))]
        struct Ancillary([u8; 128]);
        let mut control = Ancillary([0; 128]);
        let mut iov = libc::iovec {
            iov_base: bytes.as_ptr().cast_mut().cast(),
            iov_len: bytes.len(),
        };
        let mut message: libc::msghdr = unsafe { std::mem::zeroed() };
        message.msg_iov = &mut iov;
        message.msg_iovlen = 1;
        message.msg_control = control.0.as_mut_ptr().cast();
        unsafe {
            message.msg_controllen = libc::CMSG_SPACE(std::mem::size_of::<i32>() as _) as _;
            let cmsg = libc::CMSG_FIRSTHDR(&message);
            (*cmsg).cmsg_level = libc::SOL_SOCKET;
            (*cmsg).cmsg_type = libc::SCM_RIGHTS;
            (*cmsg).cmsg_len = libc::CMSG_LEN(std::mem::size_of::<i32>() as _) as _;
            std::ptr::write_unaligned(libc::CMSG_DATA(cmsg).cast::<i32>(), write_end.as_raw_fd());
            assert_eq!(
                libc::sendmsg(peer.as_raw_fd(), &message, 0),
                bytes.len() as isize
            );
        }
        let mut reader = Reader::new();
        assert!(reader.receive(&socket).unwrap().is_none());
        assert!(reader.receive(&socket).unwrap().is_none());
        assert!(reader.receive(&socket).is_err()); // Wait may not carry descriptors.
        drop(reader);
        assert!(unsafe { libc::fcntl(write_end.as_raw_fd(), libc::F_GETFD) } >= 0);
        drop(write_end);
        assert_eq!(read_end.read(&mut [0]).unwrap(), 0); // No leaked received writer.
    }
}
