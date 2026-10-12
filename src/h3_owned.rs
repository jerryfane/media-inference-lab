//! Guardian-owned codec IPC. CPU qualification never mints native authority.
//!
//! H3's bridge never spawns: every actor uses the existing fork-denying sandbox
//! and OwnedProcess. Protocol tokens are not PIDs. Settlement failures stay final.
use crate::{
    capture::NativeCaptureControl,
    guards::Lease,
    h3_native::PreparedPlan,
    native_guard::{GuardianClock, OFFLINE_ENVIRONMENT, SANDBOX_EXECUTABLE, SANDBOX_PROFILE},
    process_scope::{CommandSpec, InheritedFd, OwnedProcess, ProcessEnrollment, Settlement},
};
use anyhow::{Context, Result, bail, ensure};
use serde::{Deserialize, Serialize};
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
    path::{Path, PathBuf},
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
    let mut input = OpenOptions::new().read(true)
        .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW | libc::O_NONBLOCK).open(path)?;
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

#[derive(Debug, Serialize)]
pub(crate) struct ActorRecord {
    pub role: &'static str,
    pub token: Option<u32>,
    pub pid: u32,
    pub enrollment: Option<ProcessEnrollment>,
    pub command: CommandSpec,
    pub spawn_failure: Option<String>,
    pub settlement: Option<Settlement>,
    pub inherited_lease_fd: Option<i32>,
    pub requested_targets: Vec<i32>,
    pub settlement_error: Option<String>,
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
        control: &mut Control<'_>,
        journal: &mut File,
    ) -> Result<Self> {
        event(
            journal,
            &json!({"event":"spawn_intent","role":role,"token":token,"command":spec}),
        )?;
        control.active()?;
        *control.creation_attempted = true;
        // Only a conflicting lease is duplicated. F_DUPFD_CLOEXEC chooses a free
        // descriptor above EVERY actual destination; it never overwrites a live
        // descriptor and retains the same lock/open-file-description. Keep this
        // parent copy through fork/enrollment; OwnedProcess clears CLOEXEC only
        // in the direct child, whose original conflicting fd becomes the pipe.
        let remapped_lease = remap_lease(control.lease_fd, mappings)?;
        let lease_fd = remapped_lease.as_ref().map(AsRawFd::as_raw_fd).or(control.lease_fd);
        let attempt = OwnedProcess::spawn_with_io(
            &spec,
            control.prelaunch_deadline.map_or(control.work_deadline, |at| at.min(control.work_deadline)),
            &mut || control.active(),
            mappings,
            lease_fd,
        )?;
        let record = ActorRecord {
            role,
            token,
            pid: attempt.process.pid(),
            enrollment: attempt.process.enrollment(),
            command: spec,
            spawn_failure: attempt.failure,
            settlement: None,
            inherited_lease_fd: lease_fd,
            requested_targets: mappings.iter().map(|mapping| mapping.target).collect(),
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
    fn settle(&mut self, control: &mut Control<'_>, journal: &mut File) {
        if self.record.settlement.is_some() || self.record.settlement_error.is_some() {
            return;
        }
        let deadline = control.cleanup_deadline.unwrap_or_else(||
            (Instant::now() + control.cleanup_budget).min(control.automation_deadline));
        match self
            .process
            .settle(deadline, Duration::from_millis(200), &mut || {
                control.recovery()
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
fn remap_lease(lease: Option<i32>, mappings: &[InheritedFd<'_>]) -> Result<Option<File>> {
    let Some(fd) = lease.filter(|fd| mappings.iter().any(|mapping| mapping.target == *fd)) else {
        return Ok(None);
    };
    let minimum = mappings.iter().map(|mapping| mapping.target).max().unwrap_or(2)
        .checked_add(1).context("descriptor target overflow")?.max(3);
    let duplicate = unsafe { libc::fcntl(fd, libc::F_DUPFD_CLOEXEC, minimum) };
    ensure!(duplicate >= minimum, "cannot preserve conflicting lease: {}", io::Error::last_os_error());
    Ok(Some(unsafe { File::from_raw_fd(duplicate) }))
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
/// Identities come from a reviewed build/tool receipt, never from the IPC client.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct PinnedExecutable {
    pub path: PathBuf,
    pub sha256: String,
}
impl PinnedExecutable {
    pub(crate) fn verify(&self) -> Result<()> {
        ensure!(self.path.is_absolute() && self.path.to_str().is_some() && self.path.canonicalize()? == self.path,
            "executable must have a canonical absolute identity");
        ensure!(file_hash(&self.path)? == self.sha256, "pinned executable changed: {}", self.path.display());
        Ok(())
    }
}

/// Selected h3_ffmpeg.c recipes plus two fixed CPU audio verification recipes.
/// Repeated calls require repeated enrolled entries; each entry is consumed once.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(tag = "operation", rename_all = "snake_case", deny_unknown_fields)]
pub(crate) enum CodecOperation {
    Probe { path: PathBuf },
    ProbeAudio { path: PathBuf },
    ReadNativeAudio { path: PathBuf },
    ReadImage { path: PathBuf, width: u32, height: u32, crop: bool },
    ReadVideo { path: PathBuf, width: u32, height: u32, max_frames: u32 },
    ReadAudio { path: PathBuf, max_samples: u32, truncate_at_limit: bool },
    WriteVideo { path: PathBuf, width: u32, height: u32, fps: u32 },
    WriteAv { path: PathBuf, width: u32, height: u32, fps: u32, channels: u32, sample_rate: u32 },
}
impl CodecOperation {
    fn path(&self) -> &Path {
        match self {
            Self::Probe { path } | Self::ProbeAudio { path } | Self::ReadNativeAudio { path }
            | Self::ReadImage { path, .. } | Self::ReadVideo { path, .. }
            | Self::ReadAudio { path, .. } | Self::WriteVideo { path, .. } | Self::WriteAv { path, .. } => path,
        }
    }
    fn writes(&self) -> bool {
        matches!(self, Self::WriteVideo { .. } | Self::WriteAv { .. })
    }
    fn tool(&self) -> u32 {
        if matches!(self, Self::Probe { .. } | Self::ProbeAudio { .. }) { 2 } else { 1 }
    }
    fn validate(&self, dir: &Path, generated: bool) -> Result<()> {
        let path = self.path();
        let parent = path.parent().context("codec path lacks parent")?;
        ensure!(path.is_absolute() && path.to_str().is_some() && path.file_name().is_some()
            && parent.canonicalize()? == parent, "codec path must be canonical and local");
        if self.writes() {
            ensure!(parent.starts_with(dir)
                && matches!(std::fs::symlink_metadata(path), Err(error) if error.kind() == io::ErrorKind::NotFound),
                "codec output must be a new run-owned file");
        } else if !generated {
            ensure!(path.canonicalize()? == path && path.is_file(), "codec input is not a selected regular file");
        }
        let positive = |value: u32| -> Result<()> {
            ensure!(value > 0 && value <= i32::MAX as u32, "codec dimension/count outside C API range");
            Ok(())
        };
        match self {
            Self::Probe { .. } | Self::ProbeAudio { .. } | Self::ReadNativeAudio { .. } => {}
            Self::ReadImage { width, height, .. } => { positive(*width)?; positive(*height)?; }
            Self::ReadVideo { width, height, max_frames, .. } => {
                positive(*width)?; positive(*height)?; positive(*max_frames)?;
            }
            Self::ReadAudio { max_samples, .. } => positive(*max_samples)?,
            Self::WriteVideo { width, height, fps, .. } | Self::WriteAv { width, height, fps, .. } => {
                positive(*width)?; positive(*height)?; positive(*fps)?;
                ensure!(*width >= 2 && *height >= 2 && width % 2 == 0 && height % 2 == 0, "encoder requires even dimensions");
                if let Self::WriteAv { channels, sample_rate, .. } = self {
                    positive(*channels)?; positive(*sample_rate)?;
                }
            }
        }
        Ok(())
    }
    fn argv(&self, audio_target: i32) -> Vec<String> {
        let path = self.path().to_string_lossy().into_owned();
        let strings = |values: &[&str]| values.iter().map(|s| (*s).to_owned()).collect::<Vec<_>>();
        match self {
            Self::Probe { .. } => strings(&["ffprobe", "-v", "error", "-select_streams", "v:0",
                "-show_entries", "stream=width,height", "-of", "csv=p=0:s=x", &path]),
            Self::ProbeAudio { .. } => strings(&["ffprobe", "-v", "error", "-select_streams", "a:0",
                "-show_entries", "stream=sample_rate,channels", "-of", "default=noprint_wrappers=1", &path]),
            Self::ReadNativeAudio { .. } => strings(&["ffmpeg", "-nostdin", "-v", "error", "-i", &path,
                "-map", "0:a:0", "-f", "f32le", "-acodec", "pcm_f32le", "-"]),
            Self::ReadImage { width, height, crop, .. } => {
                let filter = if *crop {
                    format!("scale={width}:{height}:force_original_aspect_ratio=increase:flags=lanczos,crop={width}:{height}")
                } else { format!("scale={width}:{height}:flags=lanczos") };
                strings(&["ffmpeg", "-v", "error", "-i", &path, "-frames:v", "1", "-vf", &filter,
                    "-f", "rawvideo", "-pix_fmt", "rgb24", "pipe:1"])
            }
            Self::ReadVideo { width, height, max_frames, .. } => {
                let filter = format!("fps=24,scale={width}:{height}:flags=lanczos,setsar=1");
                strings(&["ffmpeg", "-v", "error", "-i", &path, "-map", "0:v:0", "-an", "-vf",
                    &filter, "-frames:v", &max_frames.to_string(), "-f", "rawvideo", "-pix_fmt", "rgb24", "pipe:1"])
            }
            Self::ReadAudio { max_samples, truncate_at_limit, .. } => {
                let mut seconds = *max_samples as f64 / 32000.0;
                if !truncate_at_limit { seconds += 1.0 / 32000.0; }
                strings(&["ffmpeg", "-v", "error", "-i", &path, "-map", "0:a:0", "-vn", "-ac", "2",
                    "-ar", "32000", "-t", &format!("{seconds:.9}"), "-f", "f32le", "pipe:1"])
            }
            Self::WriteVideo { width, height, fps, .. } | Self::WriteAv { width, height, fps, .. } => {
                let mut args = strings(&["ffmpeg", "-y", "-loglevel", "error", "-f", "rawvideo",
                    "-pixel_format", "rgb24", "-video_size", &format!("{width}x{height}"), "-framerate",
                    &fps.to_string(), "-i", "pipe:0"]);
                if let Self::WriteAv { channels, sample_rate, .. } = self {
                    args.extend(strings(&["-f", "f32le", "-ar", &sample_rate.to_string(), "-ac",
                        &channels.to_string(), "-i", &format!("pipe:{audio_target}"), "-map", "0:v:0", "-map", "1:a:0"]));
                } else { args.push("-an".into()); }
                args.extend(strings(&["-c:v", "libx264", "-preset", "fast", "-crf", "18", "-pix_fmt", "yuv420p"]));
                if matches!(self, Self::WriteAv { .. }) {
                    args.extend(strings(&["-c:a", "aac", "-b:a", "192k"]));
                }
                args.extend(strings(&["-movflags", "+faststart", &path]));
                args
            }
        }
    }
    fn audio_target(&self, targets: &[i32]) -> Result<i32> {
        let expected = if matches!(self, Self::WriteAv { .. }) { 4 } else if self.writes() { 3 } else { 2 };
        ensure!(targets.len() == expected && targets.contains(&1) && targets.contains(&2),
            "codec descriptor set differs from selected recipe");
        if self.writes() { ensure!(targets.contains(&0), "video input descriptor missing"); }
        if matches!(self, Self::WriteAv { .. }) {
            let target = *targets.iter().find(|&&fd| fd > 2).context("audio input descriptor missing")?;
            ensure!(target <= 1023, "invalid audio target");
            Ok(target)
        } else { Ok(-1) }
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct RealCodecPlan {
    pub ffmpeg: PinnedExecutable,
    pub ffprobe: PinnedExecutable,
    pub operations: Vec<CodecOperation>,
}
impl RealCodecPlan {
    fn validate(&self, dir: &Path) -> Result<()> {
        self.ffmpeg.verify()?;
        self.ffprobe.verify()?;
        ensure!(self.ffmpeg.path != self.ffprobe.path, "codec roles must have distinct executable identities");
        ensure!(!self.operations.is_empty() && self.operations.len() < (u32::MAX / 2) as usize,
            "codec operation budget is empty or exceeds protocol");
        for op in &self.operations {
            let generated = self.operations.iter().any(|candidate| candidate.writes() && candidate.path() == op.path());
            op.validate(dir, generated)?;
        }
        Ok(())
    }
}

enum Admission<'a> {
    Cpu { binary: &'a Path, scenario: &'a str },
    Real { plan: &'a RealCodecPlan, used: Vec<bool>, cancel_after: Option<usize> },
}
impl Admission<'_> {
    fn max_helpers(&self) -> usize {
        match self { Self::Cpu { .. } => 16, Self::Real { plan, .. } => plan.operations.len() }
    }
    fn command(&mut self, tool: u32, targets: &[i32], argv: &[String], dir: &Path) -> Result<CommandSpec> {
        match self {
            Self::Cpu { binary, scenario } => {
                if tool == 2 {
                    ensure!(argv == ["ffprobe", "--mil-cpu-probe"], "probe role cannot select another fixture operation");
                } else {
                    ensure!(argv.len() == 7 && argv[1] == "--mil-cpu-mode" && argv[2] == *scenario
                        && argv[3] == "--audio-fd" && argv[5] == "--output-dir" && Path::new(&argv[6]) == dir,
                        "codec fixture request differs from guardian selection");
                    let audio_target: i32 = argv[4].parse()?;
                    ensure!(audio_target > 2 && targets.contains(&0) && targets.contains(&audio_target),
                        "codec media pipes missing");
                }
                let mut args = vec!["h3-cpu-codec".into(), "--".into()];
                args.extend(argv.iter().skip(1).cloned());
                Ok(sandbox_command(binary, dir, args, false))
            }
            Self::Real { plan, used, .. } => {
                for (index, operation) in plan.operations.iter().enumerate() {
                    if used[index] || tool != operation.tool() { continue; }
                    let Ok(audio_target) = operation.audio_target(targets) else { continue; };
                    if argv != operation.argv(audio_target) { continue; }
                    operation.validate(dir, false)?;
                    let executable = if tool == 1 { &plan.ffmpeg } else { &plan.ffprobe };
                    executable.verify()?;
                    used[index] = true;
                    return Ok(sandbox_command(&executable.path, dir, argv.iter().skip(1).cloned(), false));
                }
                bail!("codec request is not an unused enrolled operation")
            }
        }
    }
    fn media_started(&self, helpers: usize) -> bool {
        match self {
            Self::Cpu { .. } => true,
            Self::Real { cancel_after, .. } => cancel_after.is_some_and(|count| helpers == count),
        }
    }
    fn role(&self, tool: u32) -> &'static str {
        match (self, tool) {
            (Self::Cpu { .. }, 1) => "ffmpeg_cpu_fixture",
            (Self::Cpu { .. }, _) => "ffprobe_cpu_fixture",
            (_, 1) => "ffmpeg",
            _ => "ffprobe",
        }
    }
}

#[derive(Debug, Serialize)]
pub(crate) struct BrokerLog {
    pub path: PathBuf,
    pub bytes: u64,
    pub sha256: Option<String>,
    pub truncated: bool,
}
#[derive(Debug, Serialize)]
pub(crate) struct BrokerResult {
    pub root: Option<ActorRecord>,
    pub helpers: Vec<ActorRecord>,
    pub complete: bool,
    pub creation_attempted: bool,
    pub failure: Option<String>,
    pub evidence_error: Option<String>,
    pub host_elapsed_ms: u64,
    pub cleanup_elapsed_ms: u64,
    pub stdout: BrokerLog,
    pub stderr: BrokerLog,
    pub root_identity: Option<PinnedExecutable>,
    pub codec_binding: Option<RealCodecPlan>,
    pub sandbox_sha256: Option<String>,
}

pub(crate) struct NativeBrokerInput {
    pub root: CommandSpec,
    pub root_identity: PinnedExecutable,
    pub codecs: RealCodecPlan,
    pub run_directory: PathBuf,
    pub execution_deadline: Instant,
    pub max_log_bytes: u64,
}

struct Control<'a> {
    clock: Option<GuardianClock>,
    active_tick: Option<&'a mut dyn FnMut() -> Result<()>>,
    recovery_tick: Option<&'a mut dyn FnMut() -> Result<()>>,
    work_deadline: Instant,
    automation_deadline: Instant,
    cleanup_budget: Duration,
    cleanup_deadline: Option<Instant>,
    prelaunch_deadline: Option<Instant>,
    log_limit: u64,
    lease_fd: Option<i32>,
    creation_attempted: &'a mut bool,
    cancelled: Option<Arc<AtomicBool>>,
    scenario: String,
    media_started: Option<Instant>,
    stop: Option<&'static str>,
    evidence_error: Option<String>,
}
impl Control<'_> {
    fn recovery(&mut self) -> Result<()> {
        ensure!(Instant::now() < self.automation_deadline, "broker recovery deadline expired");
        if let Some(clock) = &mut self.clock {
            clock.recovery_check()?;
        }
        if let Some(tick) = &mut self.recovery_tick {
            tick()?;
        }
        ensure!(Instant::now() < self.automation_deadline, "broker recovery observation exceeded deadline");
        Ok(())
    }
    fn active(&mut self) -> Result<()> {
        ensure!(self.stop.is_none(), "broker admission already revoked");
        let deadline = self.prelaunch_deadline.map_or(self.work_deadline, |at| at.min(self.work_deadline));
        if let Some(clock) = &mut self.clock {
            clock.check()?;
        }
        ensure!(Instant::now() < deadline, "broker work/prelaunch deadline expired");
        if let Some(tick) = &mut self.active_tick {
            tick()?;
        }
        ensure!(Instant::now() < deadline, "broker authority observation exceeded deadline");
        let trigger = self
            .media_started
            .is_some_and(|at| at.elapsed() >= Duration::from_millis(200));
        if self.cancelled.as_ref().is_some_and(|flag| flag.load(Ordering::SeqCst))
            || (trigger && self.scenario == "cancel")
        {
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
    out_truncated: bool,
    err_truncated: bool,
}
impl Logs {
    fn new(dir: &Path) -> Result<Self> {
        Ok(Self {
            stdout: private_file(&dir.join("stdout.log"))?,
            stderr: private_file(&dir.join("stderr.log"))?,
            out_bytes: 0,
            err_bytes: 0,
            out_truncated: false,
            err_truncated: false,
        })
    }
    fn drain(&mut self, root: &mut Actor, limit: u64) -> Result<()> {
        for (source, target, count, truncated) in [
            (
                &mut root.process.stdout,
                &mut self.stdout,
                &mut self.out_bytes,
                &mut self.out_truncated,
            ),
            (
                &mut root.process.stderr,
                &mut self.stderr,
                &mut self.err_bytes,
                &mut self.err_truncated,
            ),
        ] {
            if let Some(source) = source {
                let mut buffer = [0; 8192];
                for _ in 0..8 {
                    match source.read(&mut buffer) {
                        Ok(0) => break,
                        Ok(n) => {
                            let retained = n.min(limit.saturating_sub(*count) as usize);
                            target.write_all(&buffer[..retained])?;
                            *count += retained as u64;
                            *truncated |= retained != n;
                            ensure!(!*truncated, "actor log byte limit exceeded");
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
pub(crate) fn sandbox_command(
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

fn bounded_error(error: &anyhow::Error) -> String {
    let mut text = format!("{error:#}");
    if text.len() > 8192 {
        let mut end = 8192;
        while !text.is_char_boundary(end) { end -= 1; }
        text.truncate(end);
    }
    text
}
struct Executed {
    root: Actor,
    helpers: Vec<Actor>,
    logs: Logs,
    failure: Option<String>,
    host_elapsed_ms: u64,
    cleanup_elapsed_ms: u64,
}

/// Shared transport and custody loop. Once Actor::create returns an owned actor,
/// every fallible operation runs inside `execution` until all original settlements
/// have been retained. Active authority never substitutes for recovery authority.
fn execute(
    spec: CommandSpec,
    dir: &Path,
    mut admission: Admission<'_>,
    control: &mut Control<'_>,
    journal: &mut File,
    mut logs: Logs,
) -> Result<Executed> {
    let (mut socket, client) = UnixStream::pair()?;
    socket.set_nonblocking(true)?;
    #[cfg(target_os = "macos")]
    {
        let one = 1_i32;
        ensure!(unsafe { libc::setsockopt(socket.as_raw_fd(), libc::SOL_SOCKET, libc::SO_NOSIGPIPE,
            (&one as *const i32).cast(), std::mem::size_of_val(&one) as _) } == 0,
            "broker no-SIGPIPE configuration failed");
    }
    let client = unsafe { File::from_raw_fd(client.into_raw_fd()) };
    let started = Instant::now();
    let mut root = Actor::create(spec, "root", None,
        &[InheritedFd { file: &client, target: BROKER_FD }], control, journal)?;
    drop(client);
    control.prelaunch_deadline = None;
    let mut helpers: Vec<Actor> = Vec::new();
    let mut active: Option<usize> = None;
    let mut waiting: Option<u32> = None;
    let mut reply: Option<Reply> = None;
    let mut reader = Reader::new();
    let mut next_request = 1_u32;
    let execution = (|| -> Result<()> {
        ensure!(root.record.spawn_failure.is_none(), "root spawn failed: {:?}", root.record.spawn_failure);
        loop {
            control.active()?;
            logs.drain(&mut root, control.log_limit)?;
            root.process.check_membership()?;
            if let Some(index) = active { helpers[index].process.check_membership()?; }
            if let (Some(index), Some(id)) = (active, waiting)
                && helpers[index].process.exited_unreaped()?
            {
                helpers[index].settle(control, journal);
                let status = wait_status(helpers[index].record.settlement.as_ref()
                    .context("helper settlement unavailable")?)?;
                reply = Some(Reply::new(2, id, 0, status));
                waiting = None;
                active = None;
                if matches!(admission, Admission::Real { .. }) && admission.media_started(helpers.len()) {
                    control.media_started = Some(Instant::now());
                }
            }
            if let Some(pending) = &mut reply {
                control.active()?;
                if pending.flush(&mut socket)? { reply = None; }
            } else if waiting.is_none() && !reader.eof
                && let Some(request) = reader.receive(&socket)?
            {
                ensure!(request.id() == next_request && (next_request as usize) <= admission.max_helpers() * 2,
                    "replayed, out-of-order, or excessive IPC request");
                next_request += 1;
                match request {
                    Request::Spawn { id, tool, targets, argv } => {
                        ensure!(active.is_none() && helpers.len() < admission.max_helpers(),
                            "overlapping or excessive codec creation");
                        for (file, target) in reader.files.iter().zip(&targets) {
                            pipe_file(file)?;
                            let flags = unsafe { libc::fcntl(file.as_raw_fd(), libc::F_GETFL) };
                            let access = if *target == 1 || *target == 2 { libc::O_WRONLY } else { libc::O_RDONLY };
                            ensure!(flags >= 0 && flags & libc::O_ACCMODE == access,
                                "codec pipe direction differs from descriptor role");
                        }
                        ensure!(targets.contains(&1) && targets.contains(&2),
                            "codec output must use explicit bounded root pipes");
                        control.active()?;
                        let spec = admission.command(tool, &targets, &argv, dir)?;
                        let mappings: Vec<_> = reader.files.iter().zip(targets)
                            .map(|(file, target)| InheritedFd { file, target }).collect();
                        let token = helpers.len() as u32 + 1;
                        let actor = Actor::create(spec, admission.role(tool), Some(token),
                            &mappings, control, journal)?;
                        helpers.push(actor);
                        // Duplicates must close on enrollment, including enrollment failure,
                        // before any protocol response or wait can retain a pipe writer.
                        drop(mappings);
                        reader.files.clear();
                        active = Some(helpers.len() - 1);
                        ensure!(helpers.last().is_some_and(|actor| actor.record.spawn_failure.is_none()),
                            "helper enrollment/exec failed");
                        if tool == 1 && matches!(admission, Admission::Cpu { .. }) {
                            control.media_started = Some(Instant::now());
                        }
                        reply = Some(Reply::new(1, id, 0, token));
                    }
                    Request::Wait { id, token } => {
                        let index = active.context("wait has no owned helper")?;
                        ensure!(helpers[index].record.token == Some(token), "wait token mismatch");
                        waiting = Some(id);
                    }
                }
                reader.clear();
            }
            if root.process.exited_unreaped()? {
                ensure!(active.is_none() && waiting.is_none() && reply.is_none(),
                    "root exited with outstanding codec protocol");
                break;
            }
            std::thread::sleep(Duration::from_millis(2));
        }
        Ok(())
    })();
    let host_elapsed_ms = started.elapsed().as_millis() as u64;
    control.stop.get_or_insert("finished");
    drop(reader);
    drop(socket);
    let cleanup_started = Instant::now();
    if control.clock.is_none() {
        control.cleanup_deadline = Some((cleanup_started + control.cleanup_budget).min(control.automation_deadline));
    }
    for helper in helpers.iter_mut().rev() { helper.settle(control, journal); }
    root.settle(control, journal);
    let cleanup_elapsed_ms = cleanup_started.elapsed().as_millis() as u64;
    for result in [logs.drain(&mut root, control.log_limit), logs.stdout.sync_all().map_err(Into::into),
        logs.stderr.sync_all().map_err(Into::into)] {
        if let Err(error) = result { control.evidence_error.get_or_insert_with(|| bounded_error(&error)); }
    }
    Ok(Executed { root, helpers, logs, failure: execution.err().map(|error| bounded_error(&error)),
        host_elapsed_ms, cleanup_elapsed_ms })
}

fn log_record(dir: &Path, name: &str, bytes: u64, truncated: bool, evidence: &mut Option<String>) -> BrokerLog {
    let path = dir.join(name);
    let sha256 = match file_hash(&path) {
        Ok(hash) => Some(hash),
        Err(error) => { evidence.get_or_insert_with(|| bounded_error(&error)); None }
    };
    BrokerLog { path, bytes, sha256, truncated }
}
fn broker_result(executed: Result<Executed>, dir: &Path, control: &mut Control<'_>) -> BrokerResult {
    let (root, helpers, complete, failure, host_elapsed_ms, cleanup_elapsed_ms, counts) = match executed {
        Ok(run) => {
            let complete = run.root.complete() && run.helpers.iter().all(Actor::complete);
            let counts = (run.logs.out_bytes, run.logs.err_bytes, run.logs.out_truncated, run.logs.err_truncated);
            (Some(run.root.record), run.helpers.into_iter().map(|actor| actor.record).collect(),
                complete, run.failure, run.host_elapsed_ms, run.cleanup_elapsed_ms, counts)
        }
        Err(error) => (None, Vec::new(), false, Some(bounded_error(&error)), 0, 0, (0, 0, false, false)),
    };
    let stdout = log_record(dir, "stdout.log", counts.0, counts.2, &mut control.evidence_error);
    let stderr = log_record(dir, "stderr.log", counts.1, counts.3, &mut control.evidence_error);
    BrokerResult { root, helpers, complete, failure, evidence_error: control.evidence_error.take(),
        creation_attempted: *control.creation_attempted, host_elapsed_ms, cleanup_elapsed_ms, stdout, stderr,
        root_identity: None, codec_binding: None, sandbox_sha256: None }
}

/// Rebuilt from the strict enrolled plan, not from the command being admitted.
/// The only dynamic values are this private directory and the guardian binding.
pub(crate) fn native_environment(
    plan: &PreparedPlan, dir: &Path, guardian_pid: u32,
) -> Result<BTreeMap<String, String>> {
    plan.validate_enrolled()?;
    let selected = &plan.command.preparation;
    let mut environment = selected.environment.clone();
    environment.extend([
        ("LC_ALL".into(), "C".into()),
        ("MIL_H3_BROKER_FD".into(), BROKER_FD.to_string()),
        ("MIL_H3_BROKER_TIMEOUT_MS".into(), plan.command.timeout_ms.clamp(1, 600000).to_string()),
        ("H3_FFMPEG".into(), "ffmpeg".into()),
        ("H3_FFPROBE".into(), "ffprobe".into()),
        ("MIL_REQUEST_PATH".into(), dir.join("requested.json").to_string_lossy().into_owned()),
        ("MIL_RESULT_PATH".into(), dir.join("result.json").to_string_lossy().into_owned()),
        ("MIL_RUN_DIR".into(), dir.to_string_lossy().into_owned()),
        ("MIL_WORKLOAD_IDENTITY".into(), selected.workload_identity.clone()),
        ("MIL_NATIVE_GUARDED".into(), "1".into()),
        ("MIL_SUPERVISOR_PID".into(), guardian_pid.to_string()),
    ]);
    for (key, subdir) in [("HOME", "home"), ("TMPDIR", "tmp"), ("XDG_CACHE_HOME", "cache"), ("HF_HOME", "huggingface")] {
        environment.insert(key.into(), dir.join(subdir).to_string_lossy().into_owned());
    }
    for (key, value) in OFFLINE_ENVIRONMENT { environment.insert(key.into(), value.into()); }
    Ok(environment)
}

pub(crate) fn validate_native_environment(
    plan: &PreparedPlan, dir: &Path, guardian_pid: u32, actual: &BTreeMap<String, String>,
) -> Result<()> {
    ensure!(*actual == native_environment(plan, dir, guardian_pid)?,
        "native root environment differs from complete enrollment");
    Ok(())
}

/// Only the enrolled transaction/capture path can call this boundary. A JSON plan
/// or a real-codec fixture receipt is not a NativeCaptureControl or a held Lease.
pub(crate) fn run_native(
    input: NativeBrokerInput,
    plan: &PreparedPlan,
    native: &mut NativeCaptureControl<'_>,
    lease: &Lease,
) -> Result<BrokerResult> {
    ensure!(cfg!(target_os = "macos"), "native owned codecs require Darwin");
    let dir = &input.run_directory;
    ensure!(dir.is_absolute() && dir.canonicalize()? == *dir, "native run directory must be canonical");
    ensure!(native.directory.as_ref().is_none_or(|selected| selected == dir),
        "native broker directory differs from capture enrollment");
    ensure!(!native.cleanup_budget.is_zero() && input.max_log_bytes > 0, "native broker budgets are empty");
    let work_ceiling = native.automation_deadline.checked_sub(native.cleanup_budget)
        .context("native cleanup reserve exceeds deadline")?;
    ensure!(input.execution_deadline <= work_ceiling && Instant::now() < input.execution_deadline
        && Instant::now() < native.prelaunch_deadline, "native execution budget lacks enrolled cleanup reserve");
    (native.tick)()?;
    input.root_identity.verify()?;
    input.codecs.validate(dir)?;
    let expected_prefix = sandbox_command(&input.root_identity.path, dir, std::iter::empty(), false);
    ensure!(input.root.executable == expected_prefix.executable
        && input.root.args.starts_with(&expected_prefix.args) && input.root.cwd == *dir,
        "native root lacks the exact existing sandbox/cwd/executable binding");
    validate_native_environment(plan, dir, native.binding.guardian_pid, &input.root.environment)?;
    ensure!(lease.raw_fd() > 2, "invalid native lease descriptor");
    native.directory = Some(dir.clone());
    let mut journal = private_file(&dir.join("events.jsonl"))?;
    let sandbox_sha256 = file_hash(Path::new(SANDBOX_EXECUTABLE))?;
    event(&mut journal, &json!({"event":"native_codec_binding","root_identity":input.root_identity,
        "codecs":input.codecs,"root":input.root,"sandbox_sha256":sandbox_sha256}))?;
    let logs = Logs::new(dir)?;
    let mut control = Control {
        clock: None, active_tick: Some(&mut *native.tick), recovery_tick: Some(&mut *native.recovery_tick),
        work_deadline: input.execution_deadline, automation_deadline: native.automation_deadline,
        cleanup_budget: native.cleanup_budget, cleanup_deadline: None,
        prelaunch_deadline: Some(native.prelaunch_deadline), log_limit: input.max_log_bytes,
        lease_fd: Some(lease.raw_fd()), creation_attempted: &mut native.creation_attempted,
        cancelled: None, scenario: String::new(), media_started: None, stop: None, evidence_error: None,
    };
    let admission = Admission::Real { used: vec![false; input.codecs.operations.len()],
        plan: &input.codecs, cancel_after: None };
    let executed = execute(input.root, dir, admission, &mut control, &mut journal, logs);
    // No assignment to native.settlement: helper completeness is a distinct scope.
    let mut result = broker_result(executed, dir, &mut control);
    result.root_identity = Some(input.root_identity);
    result.codec_binding = Some(input.codecs);
    result.sandbox_sha256 = Some(sandbox_sha256);
    Ok(result)
}

// This lock exists only inside a new CPU qualification directory; never the
// project GPU/service lease. Reserve the exact regression fd without dup2 or
// closing anything owned by the caller/runtime.
fn cpu_collision_lease(dir: &Path, scenario: &str) -> Result<Option<File>> {
    let target = match scenario {
        "descriptor-collision" => 7,
        "broker-collision" => BROKER_FD,
        _ => return Ok(None),
    };
    let file = private_file(&dir.join("cpu-only.lease"))?;
    ensure!(unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } == 0,
        "cannot lock private CPU collision lease");
    let held = if file.as_raw_fd() == target { file } else {
        let fd = unsafe { libc::fcntl(file.as_raw_fd(), libc::F_DUPFD_CLOEXEC, target) };
        ensure!(fd >= 0, "cannot duplicate private CPU collision lease");
        let duplicate = unsafe { File::from_raw_fd(fd) };
        ensure!(fd == target, "CPU collision descriptor {target} is already occupied; no descriptor overwritten");
        duplicate
    };
    Ok(Some(held))
}

fn cpu_lease_still_held(dir: &Path, lease: &File) -> Result<bool> {
    let contender = OpenOptions::new().write(true)
        .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW).open(dir.join("cpu-only.lease"))?;
    let flags = unsafe { libc::fcntl(lease.as_raw_fd(), libc::F_GETFD) };
    let locked = unsafe { libc::flock(contender.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) };
    Ok(flags >= 0 && flags & libc::FD_CLOEXEC != 0 && locked == -1
        && io::Error::last_os_error().raw_os_error() == Some(libc::EWOULDBLOCK))
}

/// Explicitly CPU-only real-codec plumbing qualification of the project-built C
/// fixture. This entry neither reads a native plan nor acquires a GPU lease.
pub fn qualify_real_codecs(
    output_dir: &Path,
    scenario: &str,
    fixture: &Path,
    ffmpeg: &Path,
    ffprobe: &Path,
) -> Result<bool> {
    ensure!(cfg!(target_os = "macos"), "real-codec CPU qualification requires Darwin");
    ensure!(["success", "codec-failure", "cancel", "root-failure", "descriptor-collision", "broker-collision"].contains(&scenario),
        "unsupported real-codec CPU scenario");
    let pin = |path: &Path| -> Result<PinnedExecutable> {
        ensure!(path.is_absolute(), "explicit absolute CPU fixture/codec selection required");
        let path = path.canonicalize()?;
        let sha256 = file_hash(&path)?;
        Ok(PinnedExecutable { path, sha256 })
    };
    let fixture = pin(fixture)?;
    let ffmpeg = pin(ffmpeg)?;
    let ffprobe = pin(ffprobe)?;
    fixture.verify()?;
    ffmpeg.verify()?;
    ffprobe.verify()?;
    ensure!(fixture.path != ffmpeg.path && fixture.path != ffprobe.path && ffmpeg.path != ffprobe.path,
        "CPU fixture and codec executable identities must be distinct");
    let absolute = std::path::absolute(output_dir)?;
    let dir = absolute.parent().context("output has no parent")?.canonicalize()?
        .join(absolute.file_name().context("output has no filename")?);
    DirBuilder::new().mode(0o700).create(&dir).context("qualification requires a new output directory")?;
    let cpu_lease = cpu_collision_lease(&dir, scenario)?;
    let media = dir.join("fixture.mp4");
    let mut operations = vec![
        CodecOperation::WriteAv { path: media.clone(), width: 64, height: 32, fps: 12, channels: 2, sample_rate: 32000 },
        CodecOperation::Probe { path: media.clone() },
        CodecOperation::ReadImage { path: media.clone(), width: 64, height: 32, crop: false },
        CodecOperation::ReadVideo { path: media.clone(), width: 64, height: 32, max_frames: 5 },
        CodecOperation::ProbeAudio { path: media.clone() },
        CodecOperation::ReadNativeAudio { path: media.clone() },
        CodecOperation::ReadAudio { path: media, max_samples: 64000, truncate_at_limit: true },
    ];
    if scenario == "codec-failure" {
        operations.push(CodecOperation::ReadImage { path: dir.join("invalid-media.bin"), width: 64, height: 32, crop: false });
    }
    // These exact private files are created by the CPU fixture; native admission
    // instead validates every selected conditioning input before creation.
    for op in &operations { op.validate(&dir, true)?; }
    let plan = RealCodecPlan { ffmpeg, ffprobe, operations };
    let root_command = sandbox_command(&fixture.path, &dir,
        ["--scenario".into(), scenario.into(), "--output-dir".into(), dir.to_string_lossy().into_owned()], true);
    let mut journal = private_file(&dir.join("events.jsonl"))?;
    event(&mut journal, &json!({"event":"cpu_real_codec_binding","fixture":fixture,"codecs":plan,
        "root":root_command,"native_authority":false}))?;
    let logs = Logs::new(&dir)?;
    let cancelled = Arc::new(AtomicBool::new(false));
    let sigint = signal_hook::flag::register(libc::SIGINT, cancelled.clone())?;
    let sigterm = match signal_hook::flag::register(libc::SIGTERM, cancelled.clone()) {
        Ok(id) => id,
        Err(error) => { signal_hook::low_level::unregister(sigint); return Err(error.into()); }
    };
    struct Signals(signal_hook::SigId, signal_hook::SigId);
    impl Drop for Signals {
        fn drop(&mut self) {
            signal_hook::low_level::unregister(self.0);
            signal_hook::low_level::unregister(self.1);
        }
    }
    let _signals = Signals(sigint, sigterm);
    let mut creation_attempted = false;
    let mut control = Control {
        clock: Some(GuardianClock::new(Duration::from_secs(18))?),
        active_tick: None, recovery_tick: None,
        work_deadline: Instant::now() + Duration::from_secs(12),
        automation_deadline: Instant::now() + Duration::from_secs(18),
        cleanup_budget: Duration::from_secs(2), cleanup_deadline: None, prelaunch_deadline: None,
        log_limit: LOG_LIMIT, lease_fd: cpu_lease.as_ref().map(AsRawFd::as_raw_fd), creation_attempted: &mut creation_attempted,
        cancelled: Some(cancelled), scenario: scenario.into(), media_started: None, stop: None, evidence_error: None,
    };
    let admission = Admission::Real { plan: &plan, used: vec![false; plan.operations.len()],
        cancel_after: (scenario == "cancel").then_some(7) };
    let executed = execute(root_command, &dir, admission, &mut control, &mut journal, logs);
    let cancelled = control.stop == Some("cancelled");
    let result = broker_result(executed, &dir, &mut control);
    let stdout = std::fs::read_to_string(&result.stdout.path);
    let readback_verified = stdout.as_ref().is_ok_and(|text| text.lines().any(|line| {
        serde_json::from_str::<Value>(line).ok().is_some_and(|value|
            value["schema"] == "mil.h3-real-codec-fixture.v1" && value["event"] == "codec-validated"
                && value["native_generation"] == false)
    }));
    let code = result.root.as_ref().and_then(|root| root.settlement.as_ref()).and_then(|s| s.exit_code);
    let first_seven_ok = result.helpers.len() >= 7 && result.helpers[..7].iter().all(|actor|
        actor.settlement.as_ref().is_some_and(|settlement| settlement.exit_code == Some(0)));
    let collision_verified = if let Some(lease) = &cpu_lease {
        let target = lease.as_raw_fd();
        cpu_lease_still_held(&dir, lease)?
            && result.root.as_ref().is_some_and(|root| root.requested_targets == [BROKER_FD]
                && root.inherited_lease_fd.is_some_and(|fd| fd != BROKER_FD))
            && result.helpers.first().is_some_and(|helper| helper.requested_targets == [0, 1, 2, target]
                && helper.inherited_lease_fd.is_some_and(|fd| fd > target))
            && result.helpers.iter().all(|helper| helper.inherited_lease_fd.is_some_and(|fd|
                !helper.requested_targets.contains(&fd)))
    } else { true };
    let passed = result.complete && result.evidence_error.is_none() && readback_verified && first_seven_ok
        && collision_verified && match scenario {
            "success" | "descriptor-collision" | "broker-collision" =>
                result.failure.is_none() && code == Some(0) && result.helpers.len() == 7,
            "root-failure" => result.failure.is_none() && code == Some(9) && result.helpers.len() == 7,
            "codec-failure" => result.failure.is_none() && code == Some(7) && result.helpers.len() == 8
                && result.helpers[7].settlement.as_ref().is_some_and(|s| s.exit_code.is_some_and(|code| code != 0)),
            "cancel" => cancelled && result.helpers.len() == 7
                && stdout.as_ref().is_ok_and(|text| text.lines().any(|line| line == "MIL_H3_REAL_CODEC_READY")),
            _ => false,
        };
    write_json(&dir.join("report.json"), &json!({
        "schema":"mil.h3-owned-real-codec-cpu.v1","scenario":scenario,
        "evidence_scope":"project-built CPU fixture using selected native codec callsites; not native H3 generation",
        "qualification_passed":passed,"readback_verified":readback_verified,
        "native_execution_attested":false,"capture_eligible":false,"restoration_authority":false,
        "models_loaded":false,"gpu_lease_acquired":false,"live_services_probed_or_controlled":false,
        "cpu_private_lease_fd":cpu_lease.as_ref().map(AsRawFd::as_raw_fd),
        "descriptor_collision_verified":cpu_lease.as_ref().map(|_| collision_verified),
        "fixture":fixture,"codec_plan":plan,"broker":result,"sandbox_profile":SANDBOX_PROFILE,
        "sandbox_sha256":file_hash(Path::new(SANDBOX_EXECUTABLE))?,
        "stdout_read_failure":stdout.err().map(|error| error.to_string()),
        "limits":{"work_seconds":12,"guardian_seconds":18,"settlement_seconds_per_actor":2,
            "max_helpers":plan.operations.len(),"max_payload_bytes":PAYLOAD_LIMIT,"max_log_bytes_per_stream":LOG_LIMIT}
    }))?;
    Ok(passed)
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
    let logs = Logs::new(&dir)?;
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
    let mut creation_attempted = false;
    let mut control = Control {
        clock: Some(GuardianClock::new(Duration::from_secs(14))?),
        active_tick: None,
        recovery_tick: None,
        work_deadline: Instant::now() + Duration::from_secs(8),
        automation_deadline: Instant::now() + Duration::from_secs(14),
        cleanup_budget: Duration::from_secs(2),
        cleanup_deadline: None,
        prelaunch_deadline: None,
        log_limit: LOG_LIMIT,
        lease_fd: None,
        creation_attempted: &mut creation_attempted,
        cancelled: Some(cancelled),
        scenario: scenario.into(),
        media_started: None,
        stop: None,
        evidence_error: None,
    };
    let spec = sandbox_command(
        &binary, &dir,
        ["h3-cpu-fixture".into(), "--scenario".into(), scenario.into(),
            "--output-dir".into(), dir.to_string_lossy().into_owned()],
        true,
    );
    let Executed { root, helpers, logs, failure, .. } = match execute(
        spec, &dir, Admission::Cpu { binary: &binary, scenario },
        &mut control, &mut journal, logs,
    ) {
        Ok(executed) => executed,
        Err(error) => {
            write_json(&dir.join("report.json"), &json!({
                "schema":"mil.h3-owned-cpu.v1","scenario":scenario,"outcome":"spawn_failed",
                "failure":bounded_error(&error),"native_execution_attested":false,
                "capture_eligible":false,"creation_attempted":*control.creation_attempted,"child_created":false
            }))?;
            return Ok(false);
        }
    };
    let complete = root.complete() && helpers.iter().all(Actor::complete);
    let root_code = root.record.settlement.as_ref().and_then(|s| s.exit_code);
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
        "elapsed_ms":control.clock.as_ref().map(GuardianClock::elapsed_ms), "root":root.record, "helpers":helpers.iter().map(|h| &h.record).collect::<Vec<_>>(),
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
    #[test]
    fn real_codec_admission_rejects_unselected_paths_options_and_fd_shapes() {
        let temp = tempfile::tempdir().unwrap();
        let dir = temp.path().canonicalize().unwrap();
        let tool = dir.join("pinned-tool");
        std::fs::write(&tool, b"identity-only admission test; never executed").unwrap();
        let pin = PinnedExecutable { path: tool.clone(), sha256: file_hash(&tool).unwrap() };
        let op = CodecOperation::WriteAv { path: dir.join("clip.mp4"), width: 64, height: 32,
            fps: 12, channels: 2, sample_rate: 16000 };
        assert!(op.audio_target(&[0, 1, 2]).is_err());
        assert!(op.audio_target(&[0, 1, 2, 12, 13]).is_err());
        let target = op.audio_target(&[0, 1, 2, 12]).unwrap();
        let plan = RealCodecPlan {
            ffmpeg: pin,
            ffprobe: PinnedExecutable { path: dir.join("unused-probe"), sha256: String::new() },
            operations: vec![op],
        };
        let mut admission = Admission::Real { plan: &plan, used: vec![false], cancel_after: None };
        let mut injected = plan.operations[0].argv(target);
        *injected.last_mut().unwrap() = "https://unselected.invalid/upload".into();
        assert!(admission.command(1, &[0, 1, 2, 12], &injected, &dir).is_err());
        let mut changed_codec = plan.operations[0].argv(target);
        let codec = changed_codec.iter().position(|arg| arg == "libx264").unwrap();
        changed_codec[codec] = "h264_videotoolbox".into();
        assert!(admission.command(1, &[0, 1, 2, 12], &changed_codec, &dir).is_err());
        assert!(admission.command(2, &[0, 1, 2, 12], &plan.operations[0].argv(target), &dir).is_err());
        std::fs::write(&tool, b"drifted executable").unwrap();
        let enrolled = plan.operations[0].argv(target);
        assert!(admission.command(1, &[0, 1, 2, 12], &enrolled, &dir).is_err());
        std::fs::write(&tool, b"identity-only admission test; never executed").unwrap();
        std::os::unix::fs::symlink(dir.join("absent-target"), dir.join("clip.mp4")).unwrap();
        assert!(admission.command(1, &[0, 1, 2, 12], &enrolled, &dir).is_err());
        std::fs::remove_file(dir.join("clip.mp4")).unwrap();
        assert!(admission.command(1, &[0, 1, 2, 12], &enrolled, &dir).is_ok());
        assert!(admission.command(1, &[0, 1, 2, 12], &enrolled, &dir).is_err());
    }

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
