//! Offline, bounded CPU decoding of a private MP4 snapshot. Never runs a model.
use crate::capture::unix::OwnedChild;
use crate::schema::{Artifact, AudioConfiguration, MediaSettings, Workload};
use anyhow::{Context, Result, bail, ensure};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::{
    fs::{DirBuilder, File, OpenOptions},
    io::{Read, Write},
    os::{
        fd::AsRawFd,
        unix::{
            fs::{DirBuilderExt, OpenOptionsExt},
            process::CommandExt,
        },
    },
    path::{Path, PathBuf},
    process::{Command, Stdio},
    time::{Duration, Instant},
};

const MIB: u64 = 1024 * 1024;
const SOURCE_LIMIT: u64 = 256 * MIB;
const RGB_LIMIT: u64 = 4096 * MIB;
const PCM_LIMIT: u64 = 256 * MIB;
const METADATA_LIMIT: usize = 4 * 1024 * 1024;
const DIAGNOSTIC_LIMIT: usize = 64 * 1024;

pub struct VideoInspectionOptions {
    pub workload: Workload,
    pub input: PathBuf,
    pub ffmpeg: PathBuf,
    pub ffprobe: PathBuf,
    pub output_dir: PathBuf,
    pub timeout: Duration,
}

#[derive(Debug)]
struct OutputFailure(anyhow::Error);
impl std::fmt::Display for OutputFailure {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "writing private inspection bundle: {:#}", self.0)
    }
}
impl std::error::Error for OutputFailure {}
fn output<T>(result: Result<T>) -> Result<T> {
    result.map_err(|e| OutputFailure(e).into())
}
fn private_file(path: &Path) -> Result<File> {
    output(
        OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(path)
            .map_err(Into::into),
    )
}
fn check_deadline(deadline: Instant) -> Result<()> {
    ensure!(Instant::now() < deadline, "inspection exceeded deadline");
    Ok(())
}
fn regular_file(path: &Path, limit: u64) -> Result<File> {
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(path)?;
    let metadata = file.metadata()?;
    ensure!(metadata.is_file(), "input must be a regular file");
    ensure!(metadata.len() <= limit, "input exceeds {limit} byte bound");
    Ok(file)
}
fn hash_file(path: &Path, limit: u64, deadline: Instant) -> Result<(String, u64)> {
    let mut file = regular_file(path, limit)?;
    let mut hash = Sha256::new();
    let mut bytes = 0;
    let mut buffer = [0; 65536];
    loop {
        check_deadline(deadline)?;
        let count = file.read(&mut buffer)?;
        if count == 0 {
            break;
        }
        bytes += count as u64;
        ensure!(bytes <= limit, "file grew beyond byte bound");
        hash.update(&buffer[..count]);
    }
    Ok((format!("{:x}", hash.finalize()), bytes))
}

/// Creates a new private bundle. Invalid requests/media retain report.json and return false.
/// Bundle I/O failures return Err rather than masquerading as media validation failures.
pub fn inspect(options: VideoInspectionOptions) -> Result<bool> {
    let start = Instant::now();
    DirBuilder::new()
        .mode(0o700)
        .create(&options.output_dir)
        .context("creating new private inspection directory")?;
    let mut report = json!({
        "schema_version": 1, "kind": "offline_h3_video_inspection", "valid": false,
        "errors": [], "workload_identity": null, "source": null, "tools": [],
        "video": null, "audio": null, "artifacts": [], "helpers": [],
        "timings": {},
        "limitations": [
            "CPU-only offline media validation; no Qwen/H3 inference, GPU execution, speedup or quality claim.",
            "RGB24 and little-endian float32 PCM hashes identify converted decoded samples, not original encoded bytes or native model tensors. FFmpeg pixel/color and audio sample conversion may change numerical representation; autorotation is disabled and dimensions refer to the stored raster. No perceptual judgment or color-managed comparison is performed.",
            "Playback FPS is media timing, never generation throughput. Native phases and generation elapsed time are unavailable.",
            "Only one video and one generated-audio stream in self-contained MOV/MP4 are supported; reference/disabled audio is rejected.",
            "Inspection deadline is cooperative for local file I/O and CPU work; owned process-group cleanup has its existing additional TERM/KILL allowance."
        ]
    });
    let result = inspect_inner(&options, start, &mut report);
    if let Err(error) = &result {
        if error.downcast_ref::<OutputFailure>().is_some() {
            return result.map(|_| true);
        }
        report["errors"]
            .as_array_mut()
            .unwrap()
            .push(json!(format!("{error:#}")));
    }
    let valid = result.is_ok();
    report["valid"] = json!(valid);
    let unavailable = json!({"status":"unavailable", "reason":"offline inspection has no native inference timing boundaries"});
    report["timings"] = json!({
        "inspection_wall_seconds": start.elapsed().as_secs_f64(),
        "inspection_includes_owned_cleanup": true,
        "native_total_host_seconds": unavailable,
        "text_encoding": unavailable, "model_load": unavailable, "denoising": unavailable,
        "audio_vae": unavailable, "video_vae": unavailable, "mux_encode": unavailable,
        "seconds_per_generated_clip": unavailable,
        "generated_frames_per_second": unavailable, "generated_media_seconds_per_second": unavailable
    });
    let mut file = private_file(&options.output_dir.join("report.json"))?;
    output(serde_json::to_writer_pretty(&mut file, &report).map_err(Into::into))?;
    output(file.write_all(b"\n").map_err(Into::into))?;
    output(file.sync_all().map_err(Into::into))?;
    Ok(valid)
}

struct Expected {
    frames: u32,
    width: u32,
    height: u32,
    fps: f64,
    rate: u32,
    channels: u8,
}
fn expected(workload: &Workload) -> Result<Expected> {
    workload.validate()?;
    let MediaSettings::Video {
        generation,
        frames,
        playback_fps,
        audio,
        ..
    } = &workload.settings
    else {
        bail!("inspection requires a video workload");
    };
    ensure!(
        generation.batch_size == 1,
        "inspection requires batch_size 1"
    );
    ensure!(
        (56..=362).contains(frames) && (frames - 5) % 17 == 0,
        "video frames must be 56..362 with 5+17n spacing"
    );
    ensure!(
        playback_fps.is_finite() && *playback_fps > 0.0 && *playback_fps <= 120.0,
        "playback FPS must be positive and at most 120"
    );
    // H3's optional render canvas is internal; width/height name the output raster.
    let resolution = &generation.resolution;
    ensure!(
        resolution.width > 0
            && resolution.height > 0
            && resolution.width <= 4096
            && resolution.height <= 4096
            && u64::from(resolution.width) * u64::from(resolution.height) <= 4_000_000,
        "resolution exceeds inspection bounds"
    );
    ensure!(
        u64::from(*frames) * u64::from(resolution.width) * u64::from(resolution.height) * 3
            <= RGB_LIMIT,
        "requested RGB decode exceeds 4 GiB bound"
    );
    let AudioConfiguration::Generate {
        sample_rate_hz,
        channels,
    } = audio
    else {
        bail!(
            "inspection requires declared generated audio; disabled/reference audio is unsupported"
        );
    };
    Ok(Expected {
        frames: *frames,
        width: resolution.width,
        height: resolution.height,
        fps: *playback_fps,
        rate: *sample_rate_hz,
        channels: *channels,
    })
}

fn inspect_inner(
    options: &VideoInspectionOptions,
    start: Instant,
    report: &mut Value,
) -> Result<()> {
    ensure!(
        options.timeout >= Duration::from_secs(1) && options.timeout <= Duration::from_secs(120),
        "inspection timeout must be 1..120 seconds"
    );
    let deadline = start + options.timeout;
    report["workload_identity"] = json!(options.workload.identity()?);
    let request = expected(&options.workload)?;
    report["expected_output"] = json!({
        "frames":request.frames,"width":request.width,"height":request.height,
        "playback_fps":request.fps,"sample_rate_hz":request.rate,"channels":request.channels
    });
    check_deadline(deadline)?;
    let source = options.output_dir.join("source.mp4");
    let mut input = regular_file(&options.input, SOURCE_LIMIT).context("opening source MP4")?;
    let mut snapshot = private_file(&source)?;
    let mut hash = Sha256::new();
    let mut bytes = 0u64;
    let mut buffer = [0; 65536];
    loop {
        check_deadline(deadline)?;
        let count = input.read(&mut buffer)?;
        if count == 0 {
            break;
        }
        bytes += count as u64;
        ensure!(bytes <= SOURCE_LIMIT, "source exceeds 256 MiB bound");
        output(snapshot.write_all(&buffer[..count]).map_err(Into::into))?;
        hash.update(&buffer[..count]);
    }
    output(snapshot.sync_all().map_err(Into::into))?;
    drop(snapshot);
    let digest = format!("{:x}", hash.finalize());
    report["source"] = json!({"path":"source.mp4", "sha256":digest, "bytes":bytes});
    artifact(
        report,
        Artifact {
            path: "source.mp4".into(),
            sha256: digest,
            bytes,
            role: "source_video".into(),
        },
    )?;
    let source = source.canonicalize()?;
    for (name, path) in [("ffprobe", &options.ffprobe), ("ffmpeg", &options.ffmpeg)] {
        ensure!(path.is_absolute(), "{name} tool path must be absolute");
        let canonical = path
            .canonicalize()
            .with_context(|| format!("resolving {name}"))?;
        let (sha256, _) = hash_file(&canonical, SOURCE_LIMIT, deadline)
            .with_context(|| format!("hashing {name}"))?;
        let tool_index = report["tools"].as_array().unwrap().len();
        report["tools"]
            .as_array_mut()
            .unwrap()
            .push(json!({"name":name,"path":canonical,"sha256":sha256,"version":null}));
        let mut version = Vec::new();
        run_helper(
            command(path).arg("-version"),
            &format!("{name}-version"),
            options,
            deadline,
            report,
            |chunk| {
                ensure!(
                    version.len() + chunk.len() <= DIAGNOSTIC_LIMIT,
                    "tool version exceeds bound"
                );
                version.extend_from_slice(chunk);
                Ok(())
            },
        )?;
        let first = std::str::from_utf8(&version)?
            .lines()
            .next()
            .context("missing tool version")?;
        ensure!(
            first.starts_with(&format!("{name} version ")),
            "unexpected {name} version output"
        );
        report["tools"][tool_index]["version"] = json!(first);
    }
    let mut metadata = Vec::new();
    let mut probe = command(&options.ffprobe);
    probe.args(["-v", "error", "-threads", "1", "-protocol_whitelist", "file", "-f", "mov",
        "-enable_drefs", "0", "-use_absolute_path", "0", "-show_streams", "-show_frames", "-show_entries",
        "stream=index,codec_type,width,height,r_frame_rate,avg_frame_rate,sample_rate,channels,duration,nb_frames:frame=media_type,stream_index,width,height,best_effort_timestamp_time,pkt_duration_time,nb_samples,sample_rate,channels",
        "-of", "json"]).arg(&source);
    let probe_result = run_helper(&mut probe, "probe", options, deadline, report, |chunk| {
        ensure!(
            metadata.len() + chunk.len() <= METADATA_LIMIT,
            "frame metadata exceeds 4 MiB bound"
        );
        metadata.extend_from_slice(chunk);
        Ok(())
    });
    let mut probe_file = private_file(&options.output_dir.join("probe.json"))?;
    output(probe_file.write_all(&metadata).map_err(Into::into))?;
    output(probe_file.sync_all().map_err(Into::into))?;
    artifact(
        report,
        Artifact {
            path: "probe.json".into(),
            sha256: format!("{:x}", Sha256::digest(&metadata)),
            bytes: metadata.len() as u64,
            role: "frame_metadata".into(),
        },
    )?;
    probe_result?;
    check_deadline(deadline)?;
    let metadata: Value = serde_json::from_slice(&metadata).context("malformed ffprobe JSON")?;
    let audio_samples = validate_metadata(&metadata, &request, report, deadline)?;
    let frame_bytes = request.width as usize * request.height as usize * 3;
    let selected = [0, request.frames / 2, request.frames - 1];
    let mut decoded = 0u64;
    let mut hash = Sha256::new();
    let mut frame = Vec::new();
    let mut frame_offset = 0usize;
    let mut index = 0u32;
    let mut images: Vec<(u32, Vec<u8>)> = Vec::with_capacity(selected.len());
    let expected_bytes = frame_bytes as u64 * u64::from(request.frames);
    let mut video = decoder(&options.ffmpeg, &source);
    video.args([
        "-map",
        "0:v:0",
        "-an",
        "-sn",
        "-dn",
        "-fps_mode",
        "passthrough",
        "-c:v",
        "rawvideo",
        "-pix_fmt",
        "rgb24",
        "-threads:v",
        "1",
        "-f",
        "rawvideo",
        "pipe:1",
    ]);
    let result = run_helper(
        &mut video,
        "video-decode",
        options,
        deadline,
        report,
        |mut chunk| {
            decoded += chunk.len() as u64;
            ensure!(
                decoded <= expected_bytes && decoded <= RGB_LIMIT,
                "decoded video exceeds expected frame count/byte bound"
            );
            hash.update(chunk);
            while !chunk.is_empty() {
                let count = chunk.len().min(frame_bytes - frame_offset);
                // Only selected frames need storage; all frames contribute to the hash.
                if selected.contains(&index) {
                    frame.extend_from_slice(&chunk[..count]);
                }
                chunk = &chunk[count..];
                frame_offset += count;
                if frame_offset == frame_bytes {
                    if selected.contains(&index) {
                        images.push((index, std::mem::take(&mut frame)));
                    }
                    frame_offset = 0;
                    index += 1;
                }
            }
            Ok(())
        },
    );
    report["video"]["decoded_rgb_bytes"] = json!(decoded);
    result?;
    ensure!(
        decoded == expected_bytes && index == request.frames && frame_offset == 0,
        "decoded video frame count/byte count mismatch"
    );
    report["video"]["decoded_rgb_sha256"] = json!(format!("{:x}", hash.finalize()));
    for (index, pixels) in images {
        check_deadline(deadline)?;
        let name = if index == 0 {
            "first.png"
        } else if index == request.frames - 1 {
            "last.png"
        } else {
            "middle.png"
        };
        let path = options.output_dir.join(name);
        let mut file = private_file(&path)?;
        {
            let mut encoder = png::Encoder::new(&mut file, request.width, request.height);
            encoder.set_color(png::ColorType::Rgb);
            encoder.set_depth(png::BitDepth::Eight);
            let mut writer = output(encoder.write_header().map_err(Into::into))?;
            output(writer.write_image_data(&pixels).map_err(Into::into))?;
            output(writer.finish().map_err(Into::into))?;
        }
        output(file.sync_all().map_err(Into::into))?;
        let (sha256, bytes) = hash_file(&path, 16 * MIB, deadline)?;
        artifact(
            report,
            Artifact {
                path: name.into(),
                sha256,
                bytes,
                role: if index == 0 {
                    "poster_first_frame"
                } else if index == request.frames - 1 {
                    "last_frame"
                } else {
                    "middle_frame"
                }
                .into(),
            },
        )?;
        if index == 0 {
            report["video"]["poster"] = json!(name);
        }
    }
    let mut decoded = 0u64;
    let mut hash = Sha256::new();
    let mut audio = decoder(&options.ffmpeg, &source);
    let expected_pcm_bytes = audio_samples * u64::from(request.channels) * 4;
    audio.args([
        "-map",
        "0:a:0",
        "-vn",
        "-sn",
        "-dn",
        "-c:a",
        "pcm_f32le",
        "-threads:a",
        "1",
        "-f",
        "f32le",
        "pipe:1",
    ]);
    let result = run_helper(
        &mut audio,
        "audio-decode",
        options,
        deadline,
        report,
        |chunk| {
            decoded += chunk.len() as u64;
            ensure!(
                decoded <= PCM_LIMIT && decoded <= expected_pcm_bytes,
                "decoded PCM exceeds full frame probe sample count/byte bound"
            );
            hash.update(chunk);
            Ok(())
        },
    );
    report["audio"]["decoded_pcm_bytes"] = json!(decoded);
    result?;
    let stride = u64::from(request.channels) * 4;
    ensure!(
        decoded > 0 && decoded % stride == 0,
        "incomplete or empty decoded PCM samples"
    );
    let samples = decoded / stride;
    report["audio"]["sample_frames"] = json!(samples);
    report["audio"]["decoded_pcm_sha256"] = json!(format!("{:x}", hash.finalize()));
    ensure!(
        samples == audio_samples,
        "decoded audio sample count differs from full frame probe"
    );
    let duration = samples as f64 / f64::from(request.rate);
    let ratio = duration / (f64::from(request.frames) / request.fps);
    report["audio"]["duration_seconds"] = json!(duration);
    report["audio"]["video_duration_ratio"] = json!(ratio);
    ensure!(
        (0.75..=1.25).contains(&ratio),
        "decoded audio duration must be 75..125% of video duration"
    );
    report["audio"]["validation"] = json!("passed");
    check_deadline(deadline)?;
    Ok(())
}

fn artifact(report: &mut Value, artifact: Artifact) -> Result<()> {
    report["artifacts"]
        .as_array_mut()
        .unwrap()
        .push(serde_json::to_value(artifact)?);
    Ok(())
}
fn number(value: &Value) -> Result<f64> {
    let number = if let Some(value) = value.as_f64() {
        value
    } else {
        value
            .as_str()
            .context("missing numeric media field")?
            .parse()?
    };
    ensure!(number.is_finite(), "nonfinite media number");
    Ok(number)
}
fn integer(value: &Value) -> Result<u64> {
    if let Some(value) = value.as_u64() {
        return Ok(value);
    }
    Ok(value
        .as_str()
        .context("missing integer media field")?
        .parse()?)
}
fn fps(value: &Value) -> Result<f64> {
    let value = value.as_str().context("missing stream FPS")?;
    let (n, d) = value.split_once('/').context("malformed stream FPS")?;
    let result = n.parse::<f64>()? / d.parse::<f64>()?;
    ensure!(result.is_finite() && result > 0.0, "invalid stream FPS");
    Ok(result)
}
fn validate_metadata(
    metadata: &Value,
    request: &Expected,
    report: &mut Value,
    deadline: Instant,
) -> Result<u64> {
    let streams = metadata["streams"].as_array().context("missing streams")?;
    ensure!(
        streams.len() == 2,
        "expected exactly one video and one audio stream"
    );
    let video = streams
        .iter()
        .find(|s| s["codec_type"] == "video")
        .context("missing video stream")?;
    let audio = streams
        .iter()
        .find(|s| s["codec_type"] == "audio")
        .context("missing audio stream")?;
    let width = integer(&video["width"])?;
    let height = integer(&video["height"])?;
    let playback = fps(&video["avg_frame_rate"])?;
    report["video"] = json!({"width":width,"height":height,"playback_fps":playback});
    ensure!(
        width == u64::from(request.width) && height == u64::from(request.height),
        "video dimensions mismatch"
    );
    ensure!(
        (playback - request.fps).abs() <= request.fps * 0.000001
            && (fps(&video["r_frame_rate"])? - request.fps).abs() <= request.fps * 0.000001,
        "video playback FPS mismatch"
    );
    if !video["duration"].is_null() {
        ensure!(
            (number(&video["duration"])? - f64::from(request.frames) / request.fps).abs()
                <= 0.00001,
            "video stream duration mismatch"
        );
    }
    let rate = integer(&audio["sample_rate"])?;
    let channels = integer(&audio["channels"])?;
    report["audio"] = json!({"sample_rate_hz":rate,"channels":channels,"validation":"failed"});
    ensure!(
        rate == u64::from(request.rate) && channels == u64::from(request.channels),
        "audio sample rate/channels mismatch"
    );
    let frames = metadata["frames"]
        .as_array()
        .context("missing decoded frame metadata")?;
    let mut count = 0u32;
    let mut first_video: Option<f64> = None;
    let mut previous_video: Option<f64> = None;
    let mut first_audio: Option<f64> = None;
    let mut next_audio: Option<f64> = None;
    let mut samples = 0u64;
    for frame in frames {
        check_deadline(deadline)?;
        let timestamp = number(&frame["best_effort_timestamp_time"])?;
        match frame["media_type"].as_str() {
            Some("video") => {
                ensure!(
                    frame["stream_index"] == video["index"],
                    "unexpected video stream index"
                );
                ensure!(
                    integer(&frame["width"])? == width && integer(&frame["height"])? == height,
                    "variable video frame dimensions"
                );
                if !frame["pkt_duration_time"].is_null() {
                    ensure!(
                        (number(&frame["pkt_duration_time"])? - 1.0 / request.fps).abs() <= 0.00001,
                        "video frame duration mismatch"
                    );
                }
                if let Some(previous) = previous_video {
                    ensure!(
                        (timestamp - previous - 1.0 / request.fps).abs() <= 0.00001,
                        "video frame timeline gap or FPS mismatch"
                    );
                }
                first_video.get_or_insert(timestamp);
                previous_video = Some(timestamp);
                count += 1;
                report["video"]["frames"] = json!(count);
                ensure!(count <= request.frames, "video has too many frames");
            }
            Some("audio") => {
                ensure!(
                    frame["stream_index"] == audio["index"],
                    "unexpected audio stream index"
                );
                if !frame["sample_rate"].is_null() {
                    ensure!(
                        integer(&frame["sample_rate"])? == rate,
                        "variable audio sample rate"
                    );
                }
                if !frame["channels"].is_null() {
                    ensure!(
                        integer(&frame["channels"])? == channels,
                        "variable audio channels"
                    );
                }
                if let Some(next) = next_audio {
                    ensure!(
                        (timestamp - next).abs() <= 2.0 / rate as f64 + 0.00001,
                        "audio timeline gap/overlap"
                    );
                }
                first_audio.get_or_insert(timestamp);
                let count = integer(&frame["nb_samples"])?;
                ensure!(count > 0, "empty audio frame");
                samples = samples
                    .checked_add(count)
                    .context("audio sample count overflow")?;
                ensure!(
                    samples <= PCM_LIMIT / (channels * 4),
                    "probed audio exceeds decoded PCM bound"
                );
                next_audio = Some(timestamp + count as f64 / rate as f64);
            }
            _ => bail!("unexpected frame media type"),
        }
    }
    ensure!(
        count == request.frames,
        "video frame count mismatch: expected {}, observed {count}",
        request.frames
    );
    let start_video = first_video.context("no video frames")?;
    let start_audio = first_audio.context("no audio frames")?;
    ensure!(
        (start_video - start_audio).abs() <= 1.0 / request.fps,
        "audio/video start timestamps are incoherent"
    );
    report["audio"]["probed_sample_frames"] = json!(samples);
    Ok(samples)
}

fn command(path: &Path) -> Command {
    let mut command = Command::new(path);
    command
        .env_clear()
        .env("LC_ALL", "C")
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    command
}
fn decoder(path: &Path, source: &Path) -> Command {
    let mut command = command(path);
    command
        .args([
            "-nostdin",
            "-hide_banner",
            "-v",
            "error",
            "-xerror",
            "-err_detect",
            "explode",
            "-threads",
            "1",
            "-filter_threads",
            "1",
            "-filter_complex_threads",
            "1",
            "-hwaccel",
            "none",
            "-noautorotate",
            "-protocol_whitelist",
            "file",
            "-f",
            "mov",
            "-enable_drefs",
            "0",
            "-use_absolute_path",
            "0",
            "-i",
        ])
        .arg(source);
    command
}
fn nonblocking(file: &impl AsRawFd) -> Result<()> {
    let flags = unsafe { libc::fcntl(file.as_raw_fd(), libc::F_GETFL) };
    ensure!(
        flags >= 0,
        "reading pipe flags: {}",
        std::io::Error::last_os_error()
    );
    ensure!(
        unsafe { libc::fcntl(file.as_raw_fd(), libc::F_SETFL, flags | libc::O_NONBLOCK) } >= 0,
        "setting nonblocking pipe: {}",
        std::io::Error::last_os_error()
    );
    Ok(())
}
// At most 16 chunks per pipe per poll: a busy producer cannot starve deadlines or stderr.
fn drain(pipe: &mut impl Read, consume: &mut impl FnMut(&[u8]) -> Result<()>) -> Result<bool> {
    let mut buffer = [0; 65536];
    for _ in 0..16 {
        match pipe.read(&mut buffer) {
            Ok(0) => return Ok(true),
            Ok(count) => consume(&buffer[..count])?,
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => return Ok(false),
            Err(error) if error.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(error) => return Err(error.into()),
        }
    }
    Ok(false)
}
fn run_helper(
    command: &mut Command,
    label: &str,
    options: &VideoInspectionOptions,
    deadline: Instant,
    report: &mut Value,
    mut consume: impl FnMut(&[u8]) -> Result<()>,
) -> Result<()> {
    check_deadline(deadline)?;
    unsafe {
        command.pre_exec(|| {
            if libc::setpgid(0, 0) != 0 {
                return Err(std::io::Error::last_os_error());
            }
            Ok(())
        });
    }
    let mut child = OwnedChild::new(
        command
            .spawn()
            .with_context(|| format!("launching {label}"))?,
    );
    let started = Instant::now();
    let mut diagnostics = Vec::new();
    let mut stdout = child.child.stdout.take();
    let mut stderr = child.child.stderr.take();
    let mut stderr_nonblocking = false;
    let execution = (|| -> Result<()> {
        let stdout = stdout.as_mut().context("missing helper stdout")?;
        let stderr = stderr.as_mut().context("missing helper stderr")?;
        nonblocking(stdout)?;
        nonblocking(stderr)?;
        stderr_nonblocking = true;
        loop {
            check_deadline(deadline)?;
            let err_done = drain(stderr, &mut |chunk| {
                let remaining = DIAGNOSTIC_LIMIT.saturating_sub(diagnostics.len());
                diagnostics.extend_from_slice(&chunk[..chunk.len().min(remaining)]);
                ensure!(
                    chunk.len() <= remaining,
                    "helper diagnostics exceed 64 KiB bound"
                );
                Ok(())
            })?;
            let out_done = drain(stdout, &mut consume)?;
            if child.exited()? && out_done && err_done {
                break;
            }
            std::thread::sleep(Duration::from_millis(1));
        }
        Ok(())
    })();
    // Explicit cleanup on every post-spawn path; Drop remains the fallback if cleanup fails.
    let cleanup_start = Instant::now();
    let cleanup = child.cleanup();
    let cleanup_seconds = cleanup_start.elapsed().as_secs_f64();
    // Preserve queued decoder errors even when stdout processing or a deadline failed.
    // This final drain is bounded too, and never risks a blocking read after setup failure.
    let mut final_diagnostic_error = None;
    if stderr_nonblocking && let Some(stderr) = stderr.as_mut() {
        final_diagnostic_error = drain(stderr, &mut |chunk| {
            let remaining = DIAGNOSTIC_LIMIT.saturating_sub(diagnostics.len());
            diagnostics.extend_from_slice(&chunk[..chunk.len().min(remaining)]);
            ensure!(
                chunk.len() <= remaining,
                "helper diagnostics exceed 64 KiB bound"
            );
            Ok(())
        })
        .err();
    }
    let diagnostic_name = format!("{label}.stderr");
    let mut diagnostic_file = private_file(&options.output_dir.join(&diagnostic_name))?;
    output(diagnostic_file.write_all(&diagnostics).map_err(Into::into))?;
    output(diagnostic_file.sync_all().map_err(Into::into))?;
    let helper = json!({"name":label,"wall_seconds":started.elapsed().as_secs_f64(),
        "diagnostics":diagnostic_name,"cleanup_seconds":cleanup_seconds,
        "cleanup_attempted":true,"cleanup_succeeded":cleanup.is_ok(),
        "exit_code":cleanup.as_ref().ok().and_then(|status| status.code()),
        "error":execution.as_ref().err().map(|error| format!("{error:#}")),
        "diagnostic_error":final_diagnostic_error.as_ref().map(|error| format!("{error:#}")),
        "cleanup_error":cleanup.as_ref().err().map(|error| format!("{error:#}"))});
    report["helpers"].as_array_mut().unwrap().push(helper);
    if let Err(error) = cleanup {
        return Err(error).context(format!(
            "{label}: owned cleanup failed; execution outcome: {execution:?}"
        ));
    }
    execution.with_context(|| format!("{label} failed"))?;
    let status = cleanup.unwrap();
    if let Some(error) = final_diagnostic_error {
        return Err(error).context(format!("{label} diagnostics"));
    }
    ensure!(
        status.success(),
        "{label} exited unsuccessfully: {status}; see private {diagnostic_name}"
    );
    ensure!(
        diagnostics.is_empty(),
        "{label} emitted error diagnostics; see private {diagnostic_name}"
    );
    check_deadline(deadline)?;
    Ok(())
}
