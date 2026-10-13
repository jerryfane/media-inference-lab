use super::media_io::{self as io, Budget};
use anyhow::{Context, Result, bail, ensure};
use media_inference_lab::process_scope::{CommandSpec, OwnedProcess};
use serde_json::{Value, json};
use std::{collections::BTreeMap, fs::File, io::Read, os::fd::AsRawFd, path::Path, time::{Duration, Instant}};

const DIAGNOSTIC_LIMIT: usize = 65536;
fn nonblocking(file: &File) -> Result<()> {
    let flags = unsafe { libc::fcntl(file.as_raw_fd(), libc::F_GETFL) };
    ensure!(flags >= 0, "reading helper pipe flags: {}", std::io::Error::last_os_error());
    ensure!(unsafe { libc::fcntl(file.as_raw_fd(), libc::F_SETFL, flags | libc::O_NONBLOCK) } >= 0,
        "setting helper pipe flags: {}", std::io::Error::last_os_error());
    Ok(())
}
fn drain(pipe: &mut File, consume: &mut impl FnMut(&[u8]) -> Result<()>) -> Result<bool> {
    let mut buffer = [0; 65536];
    for _ in 0..16 {
        match pipe.read(&mut buffer) {
            Ok(0) => return Ok(true),
            Ok(n) => consume(&buffer[..n])?,
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => return Ok(false),
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(e) => return Err(e.into()),
        }
    }
    Ok(false)
}

// Decoder interpretation is identical to video_inspection::decoder and its two
// output argument lists. Only owned creation/settlement and byte retention differ.
pub(super) fn command(ffmpeg: &Path, source: &Path, output: &Path, audio: bool) -> Result<CommandSpec> {
    let mut args: Vec<String> = ["-nostdin", "-hide_banner", "-v", "error", "-xerror", "-err_detect", "explode",
        "-threads", "1", "-filter_threads", "1", "-filter_complex_threads", "1", "-hwaccel", "none", "-noautorotate",
        "-protocol_whitelist", "file", "-f", "mov", "-enable_drefs", "0", "-use_absolute_path", "0", "-i"]
        .into_iter().map(str::to_owned).collect();
    args.push(source.to_str().context("non-UTF8 source")?.into());
    let suffix: &[&str] = if audio {
        &["-map", "0:a:0", "-vn", "-sn", "-dn", "-c:a", "pcm_f32le", "-threads:a", "1", "-f", "f32le", "pipe:1"]
    } else {
        &["-map", "0:v:0", "-an", "-sn", "-dn", "-fps_mode", "passthrough", "-c:v", "rawvideo", "-pix_fmt", "rgb24", "-threads:v", "1", "-f", "rawvideo", "pipe:1"]
    };
    args.extend(suffix.iter().map(|s| (*s).to_owned()));
    // The original guarded inspection denies forks/network and confines writes.
    // No lease, service authority or historical PID is borrowed for offline work.
    let mut sandbox_args = vec!["-D".into(), format!("MIL_RUN={}", output.display()), "-p".into(),
        "(version 1)(allow default)(deny network*)(deny process-fork)(deny file-write* (require-not (subpath (param \"MIL_RUN\"))))".into(),
        ffmpeg.to_str().context("non-UTF8 decoder")?.into()];
    sandbox_args.extend(args);
    Ok(CommandSpec { executable: "/usr/bin/sandbox-exec".into(), args: sandbox_args, cwd: output.to_owned(),
        environment: BTreeMap::from([("LC_ALL".into(), "C".into())]) })
}

pub(super) struct Helpers {
    pub deadline: Instant,
    pub cleanup_remaining: Duration,
    pub records: Vec<Value>,
}
impl Helpers {
    pub fn run(&mut self, ffmpeg: &Path, source: &Path, output: &Path, audio: bool,
        budget: &mut Budget, mut consume: impl FnMut(&[u8], &mut Budget) -> Result<()>) -> Result<()> {
        let label = if audio { "audio-decode" } else { "video-decode" };
        let spec = command(ffmpeg, source, output, audio)?;
        let started = Instant::now();
        // Reserve the entire unspent shared cleanup allowance before creation.
        let execution_end = (started + Duration::from_secs(120)).min(
            self.deadline.checked_sub(self.cleanup_remaining).context("missing cleanup reserve")?);
        io::check(execution_end)?;
        let attempt = match OwnedProcess::spawn_with_deadline(&spec, execution_end, &mut || io::check(execution_end)) {
            Ok(attempt) => attempt,
            Err(e) => {
                self.records.push(json!({"label":label,"command":spec,"created":false,"spawn_error":format!("{e:#}")}));
                return Err(e);
            }
        };
        let mut process = attempt.process;
        let mut record = json!({"label":label,"command":spec,"created":true,"pid":process.pid(),
            "enrollment":process.enrollment(),"spawn_failure":attempt.failure,"identity":null,"identity_error":null,
            "settlement":null,"settlement_error":null});
        // Enrollment is always retained, even when the short-lived process exits
        // before an executable-bearing identity observation can be obtained.
        match process.identity() {
            Ok(identity) => record["identity"] = json!(identity),
            Err(e) => record["identity_error"] = json!(format!("{e:#}")),
        }
        let mut stdout = process.stdout.take();
        let mut stderr = process.stderr.take();
        let mut diagnostics = Vec::new();
        let mut stdout_bytes = 0u64;
        let mut stderr_bytes = 0u64;
        let mut truncated = false;
        let mut stderr_ready = false;
        let mut collect = |chunk: &[u8]| -> Result<()> {
            stderr_bytes += chunk.len() as u64;
            let remaining = DIAGNOSTIC_LIMIT.saturating_sub(diagnostics.len());
            diagnostics.extend_from_slice(&chunk[..remaining.min(chunk.len())]);
            truncated |= chunk.len() > remaining;
            ensure!(!truncated, "helper diagnostics exceed 64 KiB");
            Ok(())
        };
        let execution = (|| -> Result<()> {
            ensure!(record["spawn_failure"].is_null(), "helper enrollment/exec failed");
            let out = stdout.as_mut().context("missing helper stdout")?;
            let err = stderr.as_mut().context("missing helper stderr")?;
            nonblocking(err)?;
            stderr_ready = true;
            nonblocking(out)?;
            loop {
                io::check(execution_end)?;
                process.check_membership()?;
                let err_done = drain(err, &mut collect)?;
                let out_done = drain(out, &mut |chunk| {
                    io::check(execution_end)?;
                    stdout_bytes += chunk.len() as u64;
                    consume(chunk, budget)
                })?;
                if process.exited_unreaped()? && out_done && err_done { break; }
                std::thread::sleep(Duration::from_millis(1));
            }
            Ok(())
        })();
        record["host_elapsed_seconds"] = json!(started.elapsed().as_secs_f64());
        let cleanup_start = Instant::now();
        let cleanup_end = (cleanup_start + self.cleanup_remaining).min(self.deadline);
        let settlement = process.settle(cleanup_end, Duration::from_millis(200), &mut || io::check(cleanup_end));
        self.cleanup_remaining = self.cleanup_remaining.saturating_sub(cleanup_start.elapsed());
        record["cleanup_elapsed_seconds"] = json!(cleanup_start.elapsed().as_secs_f64());
        match &settlement {
            Ok(s) => record["settlement"] = json!(s),
            Err(e) => record["settlement_error"] = json!(format!("{e:#}")),
        }
        let final_error = if stderr_ready { stderr.as_mut().and_then(|s| drain(s, &mut collect).err()) } else { None };
        record["execution_error"] = json!(execution.as_ref().err().map(|e| format!("{e:#}")));
        record["diagnostic_error"] = json!(final_error.as_ref().map(|e| format!("{e:#}")));
        record["stdout_bytes"] = json!(stdout_bytes);
        record["stderr_bytes"] = json!(stderr_bytes);
        record["diagnostics_truncated"] = json!(truncated);
        let name = format!("{label}.stderr");
        record["stderr"] = json!({"path":name,"sha256":io::digest(&diagnostics),"bytes":diagnostics.len()});
        // Retain original actor receipts before any fallible evidence write.
        self.records.push(record);
        budget.save(&output.join(name), &diagnostics)?;
        execution?;
        if let Some(e) = final_error { return Err(e); }
        let s = settlement?;
        ensure!(s.complete && s.leader_reaped && s.group_absent && s.exit_code == Some(0), "helper settlement/exit incomplete");
        if !diagnostics.is_empty() { bail!("helper emitted error diagnostics"); }
        io::check(self.deadline)
    }
}
