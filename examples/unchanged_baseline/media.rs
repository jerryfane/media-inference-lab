//! Study-specific offline sample arithmetic. This never invokes a model, probe,
//! lease, service observer, or a historical actor. Inspection originals are inputs.
#[path = "media_io.rs"]
mod media_io;
#[path = "media_process.rs"]
mod media_process;

use anyhow::{Context, Result, bail, ensure};
use media_inference_lab::{frame_sequence::{self, FrameInput, SequenceInput, SequenceSource}, image_comparison, png_image::{self, DecodedPng, SampleColor}};
use media_io::{self as io, Budget, MIB, METADATA_LIMIT};
use media_process::Helpers;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::{fs::DirBuilder, io::Write, os::unix::fs::DirBuilderExt, path::{Path, PathBuf}, time::{Duration, Instant}};

const WIDTH: u32 = 864;
const HEIGHT: u32 = 480;
const FRAMES: usize = 56;
const FRAME_BYTES: usize = WIDTH as usize * HEIGHT as usize * 3;
const RGB_BYTES: u64 = 69_672_960;
const SOURCE_LIMIT: u64 = 256 * MIB;
const FFMPEG_SHA256: &str = "2e11c6f90993cdb79fff84d3f90044d28316b310e75b3e030cfc9a54f2c9d384";
const WORKLOAD: &str = "05df722e19c240d66c3fc2c73f9fcf172ad1f9035df1e250c878c3e38512b58f";
const TIMELINE_METHOD: &str = "Exact decimal probe PTS converted to nanoseconds; intervals end at the next observed PTS, and the last at the original video stream duration. Original packet-duration fields (including absence) remain separately bound. No invented FPS timestamps, shift, trim, resampling or alignment fitting.";

fn identity(path: &Path, limit: u64, deadline: Instant) -> Result<Value> {
    let (sha256, bytes) = io::hash(path, limit, deadline)?;
    Ok(json!({"path":path,"sha256":sha256,"bytes":bytes}))
}
fn sha_field<'a>(value: &'a Value, key: &str) -> Result<&'a str> {
    let s = io::text(value, key)?;
    ensure!(s.len() == 64 && s.bytes().all(|c| c.is_ascii_digit() || (b'a'..=b'f').contains(&c)), "invalid SHA256 {key}");
    Ok(s)
}
// ffprobe decimal text is retained, not converted through floating point or
// rounded to a nominal frame-rate grid. Missing/negative/excess-precision fails.
fn nanoseconds(value: &Value) -> Result<u64> {
    let s = value.as_str().context("probe timestamp must be decimal text")?;
    let (whole, fraction) = s.split_once('.').unwrap_or((s, ""));
    ensure!(!whole.is_empty() && whole.bytes().all(|b| b.is_ascii_digit()) && fraction.len() <= 9
        && fraction.bytes().all(|b| b.is_ascii_digit()), "unrepresentable probe timestamp");
    let seconds: u64 = whole.parse()?;
    let fraction: u64 = if fraction.is_empty() { 0 } else { fraction.parse::<u64>()? * 10u64.pow(9 - fraction.len() as u32) };
    seconds.checked_mul(1_000_000_000).and_then(|n| n.checked_add(fraction)).context("timestamp overflow")
}
fn original_contract(original: &Value) -> Result<()> {
    ensure!(original["schema_version"] == 1 && original["valid"] == true, "original inspection is not valid");
    ensure!(matches!(original["kind"].as_str(), Some("guarded_h3_video_inspection" | "offline_h3_video_inspection")), "wrong original inspection kind");
    ensure!(original["workload_identity"] == WORKLOAD, "inspection workload differs from fixed study");
    ensure!(original["errors"].as_array().is_some_and(Vec::is_empty), "original inspection has errors");
    for section in ["expected_output", "video"] {
        ensure!(original[section]["width"] == WIDTH && original[section]["height"] == HEIGHT
            && original[section]["frames"] == FRAMES && original[section]["playback_fps"] == 24.0,
            "original video dimensions/count/rate mismatch");
    }
    for section in ["expected_output", "audio"] {
        ensure!(original[section]["channels"] == 2 && original[section]["sample_rate_hz"] == 32000,
            "original PCM rate/channels mismatch");
    }
    ensure!(original["video"]["decoded_rgb_bytes"] == RGB_BYTES, "original RGB byte count mismatch");
    sha_field(&original["video"], "decoded_rgb_sha256")?;
    sha_field(&original["audio"], "decoded_pcm_sha256")?;
    ensure!(original["audio"]["validation"] == "passed", "original audio validation failed");
    let samples = io::integer(&original["audio"]["sample_frames"])?;
    ensure!(samples > 0 && samples <= MIB / 8 && original["audio"]["probed_sample_frames"] == samples
        && original["audio"]["decoded_pcm_bytes"] == samples * 8, "original PCM count mismatch");
    ensure!(original["helpers"].as_array().is_some_and(|a| !a.is_empty()), "missing original helper records");
    Ok(())
}
fn original_tool(original: &Value) -> Result<&Value> {
    let tools = original["tools"].as_array().context("missing original tools")?;
    let matches: Vec<_> = tools.iter().filter(|v| v["name"] == "ffmpeg").collect();
    ensure!(matches.len() == 1, "ambiguous original decoder binding");
    ensure!(matches[0]["sha256"] == FFMPEG_SHA256, "decoder differs from predeclared fingerprint");
    Ok(matches[0])
}
fn probe_artifact(original: &Value) -> Result<&Value> {
    let artifacts = original["artifacts"].as_array().context("missing original artifacts")?;
    let matches: Vec<_> = artifacts.iter().filter(|v| v["role"] == "frame_metadata").collect();
    ensure!(matches.len() == 1, "ambiguous original probe artifact");
    Ok(matches[0])
}

struct Alignment {
    sequence: SequenceInput,
    video_timeline: Vec<Value>,
    audio_timeline: Vec<Value>,
    samples: u64,
    video_stream: Value,
    audio_stream: Value,
}
fn alignment(probe: &Value, original: &Value, deadline: Instant) -> Result<Alignment> {
    original_contract(original)?;
    let streams = probe["streams"].as_array().context("missing original streams")?;
    ensure!(streams.len() == 2, "expected exactly two source streams");
    let video = streams.iter().find(|s| s["codec_type"] == "video").context("missing video stream")?;
    let audio = streams.iter().find(|s| s["codec_type"] == "audio").context("missing audio stream")?;
    ensure!(video["width"] == WIDTH && video["height"] == HEIGHT && video["avg_frame_rate"] == "24/1"
        && video["r_frame_rate"] == "24/1", "source video shape/rate mismatch");
    ensure!(io::integer(&audio["sample_rate"])? == 32000 && io::integer(&audio["channels"])? == 2, "source PCM rate/channels mismatch");
    let video_end = nanoseconds(&video["duration"])?;
    // Match the original validation's representational tolerance, never use it
    // to align different runs. Pair timelines below must be exactly equal.
    ensure!((video_end as f64 / 1e9 - 56.0 / 24.0).abs() <= 0.00001, "source video duration mismatch");
    let mut video_timeline = Vec::with_capacity(FRAMES);
    let mut audio_timeline = Vec::new();
    let mut pts = Vec::with_capacity(FRAMES);
    let mut samples = 0u64;
    let mut next_audio: Option<f64> = None;
    let mut first_audio = None;
    for f in probe["frames"].as_array().context("missing probe frames")? {
        io::check(deadline)?;
        let timestamp = nanoseconds(&f["best_effort_timestamp_time"])?;
        match f["media_type"].as_str() {
            Some("video") => {
                ensure!(f["stream_index"] == video["index"] && f["width"] == WIDTH && f["height"] == HEIGHT, "video frame stream/dimensions mismatch");
                if let Some(previous) = pts.last() {
                    ensure!(timestamp > *previous && ((timestamp - previous) as f64 / 1e9 - 1.0 / 24.0).abs() <= 0.00001, "source video timeline gap");
                } else { ensure!(timestamp == 0, "nonzero video timeline cannot be shifted"); }
                if !f["pkt_duration_time"].is_null() {
                    ensure!((nanoseconds(&f["pkt_duration_time"])? as f64 / 1e9 - 1.0 / 24.0).abs() <= 0.00001, "source packet duration mismatch");
                }
                pts.push(timestamp);
                ensure!(pts.len() <= FRAMES, "extra source video frames");
                video_timeline.push(json!({"stream_index":f["stream_index"],"pts":f["best_effort_timestamp_time"],
                    "packet_duration":f["pkt_duration_time"],"width":f["width"],"height":f["height"]}));
            }
            Some("audio") => {
                ensure!(f["stream_index"] == audio["index"], "audio stream mismatch");
                if !f["sample_rate"].is_null() { ensure!(io::integer(&f["sample_rate"])? == 32000, "variable PCM rate"); }
                if !f["channels"].is_null() { ensure!(io::integer(&f["channels"])? == 2, "variable PCM channels"); }
                if let Some(next) = next_audio {
                    ensure!((timestamp as f64 / 1e9 - next).abs() <= 2.0 / 32000.0 + 0.00001, "source audio gap/overlap");
                }
                first_audio.get_or_insert(timestamp);
                let count = io::integer(&f["nb_samples"])?;
                ensure!(count > 0 && count <= MIB / 8, "invalid audio frame sample count");
                samples = samples.checked_add(count).context("PCM sample count overflow")?;
                ensure!(samples <= MIB / 8, "PCM exceeds 1 MiB");
                next_audio = Some(timestamp as f64 / 1e9 + count as f64 / 32000.0);
                audio_timeline.push(json!({"stream_index":f["stream_index"],"pts":f["best_effort_timestamp_time"],
                    "packet_duration":f["pkt_duration_time"],"sample_frames":count,"sample_rate":f["sample_rate"],"channels":f["channels"]}));
            }
            _ => bail!("unexpected source frame type"),
        }
    }
    ensure!(pts.len() == FRAMES, "source video frame count mismatch");
    ensure!(first_audio.context("no source audio frames")? as f64 / 1e9 <= 1.0 / 24.0, "source A/V start mismatch");
    ensure!(original["audio"]["sample_frames"] == samples, "probe PCM count differs from original inspection");
    ensure!((0.75..=1.25).contains(&(samples as f64 / 32000.0 / (56.0 / 24.0))), "PCM duration outside original validation bounds");
    let frames = pts.iter().enumerate().map(|(index, &p)| {
        let end = pts.get(index + 1).copied().unwrap_or(video_end);
        Ok(FrameInput { index: index as u32, path: format!("frame-{index:02}.png").into(), pts_ns: p,
            duration_ns: end.checked_sub(p).filter(|n| *n > 0).context("source interval is not positive")? })
    }).collect::<Result<Vec<_>>>()?;
    let sequence = SequenceInput { schema_version: 1, frame_count: FRAMES as u32, provenance: TIMELINE_METHOD.into(), frames };
    sequence.validate()?;
    Ok(Alignment { sequence, video_timeline, audio_timeline, samples,
        video_stream: json!({"index":video["index"],"width":video["width"],"height":video["height"],"avg_frame_rate":video["avg_frame_rate"],"r_frame_rate":video["r_frame_rate"],"duration":video["duration"]}),
        audio_stream: json!({"index":audio["index"],"sample_rate":audio["sample_rate"],"channels":audio["channels"],"duration":audio["duration"]}) })
}

fn write_png(path: &Path, pixels: &[u8], budget: &mut Budget, deadline: Instant) -> Result<()> {
    let mut sink = io::BoundedWriter { file: io::private(path)?, budget, deadline };
    let mut encoder = png::Encoder::new(&mut sink, WIDTH, HEIGHT);
    encoder.set_color(png::ColorType::Rgb);
    encoder.set_depth(png::BitDepth::Eight);
    let mut writer = encoder.write_header()?;
    writer.write_image_data(pixels)?;
    writer.finish()?;
    sink.file.sync_all()?;
    Ok(())
}
fn check_frame(decoded: &DecodedPng, record: &Value, index: usize) -> Result<()> {
    let id = decoded.identity();
    ensure!(record["index"] == index && record["sha256"] == id.sha256 && record["bytes"] == id.bytes
        && record["decoded_sha256"] == id.decoded_sha256, "frame {index} hash/index mismatch");
    ensure!(id.width == WIDTH && id.height == HEIGHT && id.color == SampleColor::Rgb && id.bit_depth == 8
        && decoded.samples().len() == FRAME_BYTES, "frame {index} RGB shape mismatch");
    Ok(())
}
// Full-size 8x7 sheet, without resizing/recoloring. One tile row is retained.
fn sheet(output: &Path, frames: &[Value], budget: &mut Budget, deadline: Instant) -> Result<Value> {
    ensure!(frames.len() == FRAMES, "sheet requires every frame");
    let path = output.join("all-frames.png");
    let mut sink = io::BoundedWriter { file: io::private(&path)?, budget, deadline };
    let mut encoder = png::Encoder::new(&mut sink, WIDTH * 8, HEIGHT * 7);
    encoder.set_color(png::ColorType::Rgb);
    encoder.set_depth(png::BitDepth::Eight);
    let mut writer = encoder.write_header()?;
    {
        let mut stream = writer.stream_writer()?;
        for row in 0..7 {
            let mut tiles = Vec::with_capacity(8);
            for col in 0..8 {
                io::check(deadline)?;
                let index = row * 8 + col;
                let decoded = png_image::decode(&io::relative(output, io::text(&frames[index], "path")?)?)?;
                check_frame(&decoded, &frames[index], index)?;
                tiles.push(decoded);
            }
            let stride = WIDTH as usize * 3;
            for y in 0..HEIGHT as usize {
                io::check(deadline)?;
                for tile in &tiles { stream.write_all(&tile.samples()[y * stride..(y + 1) * stride])?; }
            }
        }
        stream.finish()?;
    }
    writer.finish()?;
    sink.file.sync_all()?;
    let mut result = identity(&path, 96 * MIB, deadline)?;
    result["path"] = json!("all-frames.png");
    result["columns"] = json!(8);
    result["rows"] = json!(7);
    result["ordering"] = json!("all 56 frames in ascending index, row-major; unchanged RGB24 samples");
    Ok(result)
}

// Resolve the existing parent before creating even a failed-derivation report.
// Missing input files may still produce a report in a separate output directory.
fn separate_output(source: &Path, inspection: &Path, output: &Path) -> Result<PathBuf> {
    fn parent(path: &Path) -> Result<PathBuf> {
        let parent = path.parent().context("media path has no parent")?;
        Ok(if parent.as_os_str().is_empty() { Path::new(".") } else { parent }.canonicalize()?)
    }
    let output_parent = parent(output)?;
    let name = output.file_name().context("output must name a new directory")?;
    let output = output_parent.join(name);
    for input in [source, inspection] {
        let input_parent = parent(input)?;
        ensure!(!output.starts_with(&input_parent), "derived output must be outside immutable input directories");
        // Also protect the target directory if the selected input is an alias.
        if let Ok(resolved) = input.canonicalize() {
            ensure!(!output.starts_with(resolved.parent().context("input has no parent")?),
                "derived output must be outside immutable input directories");
        }
    }
    Ok(output)
}

/// A new private bundle is retained even when decode/validation fails. True means
/// the complete stream, all PNGs, PCM, provenance and owned settlements validated.
pub fn derive(source: &Path, inspection: &Path, output: &Path, ffmpeg: &Path, deadline: Instant) -> Result<bool> {
    let started = Instant::now();
    let deadline = deadline.min(started + Duration::from_secs(250));
    let output = separate_output(source, inspection, output)?;
    DirBuilder::new().mode(0o700).create(&output).context("creating new private derived bundle")?;
    let mut report = json!({"schema_version":1,"kind":"unchanged_h3_offline_derived_media","valid":false,"errors":[],
        "source":null,"inspection":null,"frames":[],"helpers":[],"limits":{"helper_seconds":120,"shared_cleanup_seconds":10,"total_seconds":250,
        "rgb_bytes":RGB_BYTES,"pcm_bytes":MIB,"png_bytes":96*MIB,"bundle_bytes":128*MIB},
        "limitations":["CPU-only derived representation, not native acceptance or model evidence.",
        "Original RGB24/f32le decoder interpretation; no quality, listening, tolerance or temporal-quality verdict.",
        "Cooperative deadlines and bounded reads/writes, not hard OS syscall deadlines or filesystem quotas."]});
    let mut budget = Budget::new();
    let mut helpers = Helpers { deadline, cleanup_remaining: Duration::from_secs(10), records: Vec::with_capacity(2) };
    let result = derive_inner(source, inspection, &output, ffmpeg, deadline, &mut report, &mut budget, &mut helpers);
    report["helpers"] = json!(helpers.records);
    report["valid"] = json!(result.is_ok());
    if let Err(e) = &result { report["errors"] = json!([format!("{e:#}")]); }
    report["wall_seconds"] = json!(started.elapsed().as_secs_f64());
    report["retained_payload_bytes"] = json!(budget.total);
    let mut bytes = serde_json::to_vec_pretty(&report)?;
    bytes.push(b'\n');
    ensure!(bytes.len() as u64 <= METADATA_LIMIT, "derived report exceeds 16 MiB");
    // Payload writes reserved this terminal report's full 16 MiB allowance.
    ensure!(budget.total + bytes.len() as u64 <= 128 * MIB, "derived bundle exceeds 128 MiB");
    let mut file = io::private(&output.join("report.json"))?;
    file.write_all(&bytes)?;
    file.sync_all()?;
    Ok(result.is_ok())
}

fn derive_inner(source: &Path, inspection: &Path, output: &Path, ffmpeg: &Path, deadline: Instant,
    report: &mut Value, budget: &mut Budget, helpers: &mut Helpers) -> Result<()> {
    io::check(deadline)?;
    // Check the selected final components before resolving their absolute names.
    io::open(source, SOURCE_LIMIT)?;
    io::open(inspection, METADATA_LIMIT)?;
    let source = source.canonicalize()?;
    let inspection = inspection.canonicalize()?;
    let ffmpeg = ffmpeg.canonicalize()?;
    let original_bytes = io::read(&inspection, METADATA_LIMIT, deadline)?;
    let original: Value = serde_json::from_slice(&original_bytes)?;
    report["inspection"] = json!({"path":inspection,"sha256":io::digest(&original_bytes),"bytes":original_bytes.len()});
    budget.save(&output.join("original-inspection.json"), &original_bytes)?;
    report["original_inspection_path"] = json!("original-inspection.json");
    original_contract(&original)?;
    report["source"] = identity(&source, SOURCE_LIMIT, deadline)?;
    ensure!(report["source"]["sha256"] == original["source"]["sha256"]
        && report["source"]["bytes"] == original["source"]["bytes"], "source is detached from original inspection");
    let tool = original_tool(&original)?;
    report["decoder"] = identity(&ffmpeg, SOURCE_LIMIT, deadline)?;
    ensure!(report["decoder"]["sha256"] == tool["sha256"] && Path::new(io::text(tool, "path")?).canonicalize()? == ffmpeg,
        "decoder fingerprint/path differs from original inspection");
    report["original_tools"] = original["tools"].clone();
    let probe_artifact = probe_artifact(&original)?;
    let probe_path = io::relative(inspection.parent().context("inspection has no parent")?, io::text(probe_artifact, "path")?)?;
    let probe_bytes = io::read(&probe_path, METADATA_LIMIT, deadline)?;
    ensure!(probe_artifact["sha256"] == io::digest(&probe_bytes) && probe_artifact["bytes"] == probe_bytes.len(), "original probe artifact hash/count mismatch");
    budget.save(&output.join("probe.json"), &probe_bytes)?;
    report["probe"] = json!({"path":"probe.json","sha256":io::digest(&probe_bytes),"bytes":probe_bytes.len(),"original_path":probe_path});
    let probe: Value = serde_json::from_slice(&probe_bytes)?;
    let aligned = alignment(&probe, &original, deadline)?;
    report["sequence"] = json!(aligned.sequence);
    report["video_timeline"] = json!(aligned.video_timeline);
    report["audio_timeline"] = json!(aligned.audio_timeline);
    report["video_stream"] = aligned.video_stream;
    report["audio_stream"] = aligned.audio_stream;
    report["timing_method"] = json!(TIMELINE_METHOD);
    let mut frame = Vec::with_capacity(FRAME_BYTES);
    let mut frames = Vec::with_capacity(FRAMES);
    let mut hash = Sha256::new();
    let mut decoded = 0u64;
    let result = helpers.run(&ffmpeg, &source, output, false, budget, |mut chunk, budget| {
        decoded += chunk.len() as u64;
        ensure!(decoded <= RGB_BYTES, "RGB stream exceeds exactly 56 frames");
        hash.update(chunk);
        while !chunk.is_empty() {
            io::check(deadline)?;
            let n = chunk.len().min(FRAME_BYTES - frame.len());
            frame.extend_from_slice(&chunk[..n]);
            chunk = &chunk[n..];
            if frame.len() == FRAME_BYTES {
                let index = frames.len();
                ensure!(index < FRAMES, "extra decoded frame");
                let path = format!("frame-{index:02}.png");
                write_png(&output.join(&path), &frame, budget, deadline)?;
                let mut record = identity(&output.join(&path), 16 * MIB, deadline)?;
                record["path"] = json!(path);
                record["index"] = json!(index);
                record["decoded_sha256"] = json!(io::digest(&frame));
                record["pts_ns"] = json!(aligned.sequence.frames[index].pts_ns);
                record["duration_ns"] = json!(aligned.sequence.frames[index].duration_ns);
                frames.push(record);
                frame.clear();
            }
        }
        Ok(())
    });
    report["frames"] = json!(frames);
    let rgb_sha = format!("{:x}", hash.finalize());
    report["video"] = json!({"decoded_rgb_bytes":decoded,"decoded_rgb_sha256":rgb_sha,"completed_frames":frames.len()});
    result?;
    ensure!(decoded == RGB_BYTES && frame.is_empty() && frames.len() == FRAMES, "incomplete decoded RGB stream");
    ensure!(original["video"]["decoded_rgb_sha256"] == rgb_sha, "RGB full-stream hash differs from original inspection");
    let mut reconstructed = Sha256::new();
    for (index, record) in frames.iter().enumerate() {
        io::check(deadline)?;
        let decoded = png_image::decode(&io::relative(output, io::text(record, "path")?)?)?;
        check_frame(&decoded, record, index)?;
        reconstructed.update(decoded.samples());
    }
    let reconstructed = format!("{:x}", reconstructed.finalize());
    ensure!(reconstructed == rgb_sha, "re-concatenated PNG RGB differs from original stream");
    report["video"]["reconstructed_rgb_sha256"] = json!(reconstructed);
    let mut pcm = Vec::with_capacity((aligned.samples * 8) as usize);
    let result = helpers.run(&ffmpeg, &source, output, true, budget, |chunk, _| {
        ensure!(pcm.len() as u64 + chunk.len() as u64 <= aligned.samples * 8 && pcm.len() + chunk.len() <= MIB as usize,
            "decoded PCM exceeds original count/1 MiB");
        pcm.extend_from_slice(chunk);
        Ok(())
    });
    budget.save(&output.join("audio.f32le"), &pcm)?;
    report["audio"] = json!({"path":"audio.f32le","sha256":io::digest(&pcm),"bytes":pcm.len(),
        "sample_frames":aligned.samples,"sample_rate_hz":32000,"channels":2,"duration_seconds":aligned.samples as f64 / 32000.0});
    result?;
    validate_pcm(&pcm, aligned.samples, 2)?;
    ensure!(report["audio"]["sha256"] == original["audio"]["decoded_pcm_sha256"], "PCM full-stream hash differs from original inspection");
    report["contact_sheet"] = sheet(output, &frames, budget, deadline)?;
    // Detect mutation of any externally selected content during extraction.
    io::verify(&source, &report["source"], SOURCE_LIMIT, deadline)?;
    io::verify(&ffmpeg, &report["decoder"], SOURCE_LIMIT, deadline)?;
    io::verify_metadata(&inspection, &report["inspection"], deadline)?;
    io::verify_metadata(&probe_path, probe_artifact, deadline)?;
    io::check(deadline)
}

fn validate_pcm(bytes: &[u8], samples: u64, channels: u64) -> Result<()> {
    ensure!(samples > 0 && channels == 2 && samples <= MIB / 8 && bytes.len() as u64 == samples * channels * 4,
        "PCM sample/channel/byte count mismatch");
    for sample in bytes.chunks_exact(4) {
        ensure!(f32::from_le_bytes(sample.try_into().expect("four-byte sample")).is_finite(), "nonfinite PCM sample");
    }
    Ok(())
}
#[derive(Default)]
struct FloatErrors { n: u64, absolute: f64, squared: f64, max: f64 }
impl FloatErrors {
    fn add(&mut self, difference: f64) {
        self.n += 1;
        let absolute = difference.abs();
        self.absolute += absolute;
        self.squared += difference * difference;
        self.max = self.max.max(absolute);
    }
    fn value(&self) -> Result<Value> {
        ensure!(self.n > 0 && self.absolute.is_finite() && self.squared.is_finite(), "invalid PCM accumulation");
        Ok(json!({"sample_count":self.n,"absolute_error_sum":self.absolute,"squared_error_sum":self.squared,
            "max_absolute_error":self.max,"mean_absolute_error":self.absolute / self.n as f64,
            "root_mean_squared_error":(self.squared / self.n as f64).sqrt()}))
    }
}
fn compare_pcm(left: &[u8], right: &[u8], samples: u64, deadline: Instant) -> Result<Value> {
    validate_pcm(left, samples, 2)?;
    validate_pcm(right, samples, 2)?;
    let mut aggregate = FloatErrors::default();
    let mut channels = [FloatErrors::default(), FloatErrors::default()];
    for (index, (a, b)) in left.chunks_exact(4).zip(right.chunks_exact(4)).enumerate() {
        if index % 4096 == 0 { io::check(deadline)?; }
        let a = f32::from_le_bytes(a.try_into().expect("four-byte sample")) as f64;
        let b = f32::from_le_bytes(b.try_into().expect("four-byte sample")) as f64;
        aggregate.add(a - b);
        channels[index % 2].add(a - b);
    }
    Ok(json!({"full_stream_equal":left == right,"sample_frames":samples,"channels":2,"sample_rate_hz":32000,
        "duration_seconds":samples as f64 / 32000.0,"aggregate":aggregate.value()?,
        "per_channel":[{"channel_index":0,"metrics":channels[0].value()?},{"channel_index":1,"metrics":channels[1].value()?}],
        "units":"decoded float32 amplitude units; float64 differences and accumulation",
        "denominator":"aggregate N = sample_frames * 2; each channel N = sample_frames; no trimming, lag fitting, gain or resampling"}))
}

/// Serial reporter accounting: set its remaining combined metadata allowance
/// before a validation/comparison, and subtract the cumulative counter delta afterward.
pub fn set_metadata_budget(remaining: u64) { io::set_metadata_budget(remaining); }
pub fn metadata_bytes_read() -> u64 { io::metadata_bytes_read() }

pub fn compare_images(left: &Path, right: &Path, deadline: Instant) -> Result<Value> {
    io::check(deadline)?;
    let left = png_image::decode(left)?;
    io::check(deadline)?;
    let right = png_image::decode(right)?;
    io::check(deadline)?;
    let compared = image_comparison::compare(&left, &right, None, None, None)?;
    io::check(deadline)?;
    Ok(json!({"kind":"unchanged_image_sample_metrics","left":compared.baseline,"right":compared.candidate,
        "metrics":compared.metrics,"method":compared.method,"units":compared.units,
        "alignment":compared.alignment,"denominator":compared.denominator}))
}

struct Bundle {
    root: PathBuf,
    report: Value,
    original: Value,
    alignment: Alignment,
    pcm: Vec<u8>,
    report_identity: Value,
}
fn load_bundle(root: &Path, deadline: Instant) -> Result<Bundle> {
    let root = root.canonicalize()?;
    let path = root.join("report.json");
    let bytes = io::read(&path, METADATA_LIMIT, deadline)?;
    let report: Value = serde_json::from_slice(&bytes)?;
    ensure!(report["kind"] == "unchanged_h3_offline_derived_media" && report["schema_version"] == 1 && report["valid"] == true,
        "derived bundle is incomplete/invalid");
    ensure!(report["errors"].as_array().is_some_and(Vec::is_empty), "derived bundle retains errors");
    let original_path = io::relative(&root, io::text(&report, "original_inspection_path")?)?;
    let original_bytes = io::read(&original_path, METADATA_LIMIT, deadline)?;
    ensure!(report["inspection"]["sha256"] == io::digest(&original_bytes) && report["inspection"]["bytes"] == original_bytes.len(),
        "retained original inspection hash/bytes mismatch");
    let original: Value = serde_json::from_slice(&original_bytes)?;
    original_contract(&original)?;
    let source = Path::new(io::text(&report["source"], "path")?);
    ensure!(source.is_absolute(), "source binding is not absolute");
    io::verify(source, &report["source"], SOURCE_LIMIT, deadline)?;
    ensure!(report["source"]["sha256"] == original["source"]["sha256"] && report["source"]["bytes"] == original["source"]["bytes"],
        "detached source binding");
    let inspection = Path::new(io::text(&report["inspection"], "path")?);
    ensure!(inspection.is_absolute(), "inspection binding is not absolute");
    io::verify_metadata(inspection, &report["inspection"], deadline)?;
    let tool = original_tool(&original)?;
    ensure!(report["decoder"]["sha256"] == tool["sha256"]
        && report["decoder"]["path"] == tool["path"]
        && report["original_tools"] == original["tools"], "detached original decoder fingerprint");
    let probe_path = io::relative(&root, io::text(&report["probe"], "path")?)?;
    let probe_bytes = io::read(&probe_path, METADATA_LIMIT, deadline)?;
    let expected_probe = probe_artifact(&original)?;
    ensure!(expected_probe["sha256"] == io::digest(&probe_bytes) && expected_probe["bytes"] == probe_bytes.len()
        && report["probe"]["sha256"] == expected_probe["sha256"] && report["probe"]["bytes"] == expected_probe["bytes"],
        "retained original probe hash/count mismatch");
    let original_probe_path = io::relative(inspection.parent().context("inspection has no parent")?, io::text(expected_probe, "path")?)?;
    ensure!(report["probe"]["original_path"] == json!(original_probe_path), "detached original probe path");
    io::verify_metadata(&original_probe_path, expected_probe, deadline)?;
    let probe: Value = serde_json::from_slice(&probe_bytes)?;
    let aligned = alignment(&probe, &original, deadline)?;
    ensure!(report["sequence"] == serde_json::to_value(&aligned.sequence)? && report["video_timeline"] == json!(aligned.video_timeline)
        && report["audio_timeline"] == json!(aligned.audio_timeline) && report["video_stream"] == aligned.video_stream
        && report["audio_stream"] == aligned.audio_stream && report["timing_method"] == TIMELINE_METHOD,
        "derived timeline/count differs from original probe");
    ensure!(report["video"]["decoded_rgb_bytes"] == RGB_BYTES && report["video"]["completed_frames"] == FRAMES
        && report["video"]["decoded_rgb_sha256"] == original["video"]["decoded_rgb_sha256"]
        && report["video"]["reconstructed_rgb_sha256"] == original["video"]["decoded_rgb_sha256"], "derived RGB stream binding mismatch");
    let frames = report["frames"].as_array().context("missing all-frame records")?;
    ensure!(frames.len() == FRAMES, "derived frame count mismatch");
    let mut png_bytes = 0u64;
    for (index, frame) in frames.iter().enumerate() {
        io::check(deadline)?;
        ensure!(frame["index"] == index && frame["path"] == json!(aligned.sequence.frames[index].path)
            && frame["pts_ns"] == aligned.sequence.frames[index].pts_ns && frame["duration_ns"] == aligned.sequence.frames[index].duration_ns,
            "frame {index} timeline/path/index mismatch");
        let n = io::integer(&frame["bytes"])?;
        ensure!(n <= 16 * MIB, "frame exceeds byte bound");
        png_bytes += n;
    }
    ensure!(report["contact_sheet"].is_object(), "missing predeclared all56-frame contact-sheet record");
    let sheet_path = io::relative(&root, io::text(&report["contact_sheet"], "path")?)?;
    io::verify(&sheet_path, &report["contact_sheet"], 96 * MIB, deadline)?;
    png_bytes += io::integer(&report["contact_sheet"]["bytes"])?;
    ensure!(png_bytes <= 96 * MIB, "derived PNG aggregate exceeds 96 MiB");
    let helpers = report["helpers"].as_array().context("missing owned decode helpers")?;
    ensure!(helpers.len() == 2, "derived bundle must retain two owned helpers");
    for (i, helper) in helpers.iter().enumerate() {
        ensure!(helper["label"] == if i == 0 { "video-decode" } else { "audio-decode" }
            && helper["created"] == true && helper["spawn_failure"].is_null() && helper["execution_error"].is_null()
            && helper["settlement_error"].is_null() && helper["diagnostic_error"].is_null()
            && helper["settlement"]["complete"] == true && helper["settlement"]["leader_reaped"] == true
            && helper["settlement"]["group_absent"] == true && helper["settlement"]["exit_code"] == 0,
            "derived helper did not completely settle");
        let expected_command = media_process::command(Path::new(io::text(&report["decoder"], "path")?), source, &root, i == 1)?;
        ensure!(helper["command"] == serde_json::to_value(expected_command)?
            && helper["stdout_bytes"] == if i == 0 { RGB_BYTES } else { aligned.samples * 8 }
            && helper["stderr_bytes"] == 0 && helper["diagnostics_truncated"] == false,
            "derived helper command/stream binding mismatch");
        let stderr = io::relative(&root, io::text(&helper["stderr"], "path")?)?;
        io::verify(&stderr, &helper["stderr"], 65536, deadline)?;
        ensure!(helper["stderr"]["bytes"] == 0, "derived helper emitted diagnostics");
    }
    let pcm_path = io::relative(&root, io::text(&report["audio"], "path")?)?;
    let pcm = io::read(&pcm_path, MIB, deadline)?;
    ensure!(report["audio"]["sha256"] == io::digest(&pcm) && report["audio"]["sha256"] == original["audio"]["decoded_pcm_sha256"]
        && report["audio"]["bytes"] == pcm.len() && report["audio"]["sample_frames"] == aligned.samples
        && report["audio"]["channels"] == 2 && report["audio"]["sample_rate_hz"] == 32000,
        "PCM hash/count/rate/channel binding mismatch");
    validate_pcm(&pcm, aligned.samples, 2)?;
    let report_identity = json!({"path":path,"sha256":io::digest(&bytes),"bytes":bytes.len()});
    Ok(Bundle { root, report, original, alignment: aligned, pcm, report_identity })
}
/// Validate actual samples once, independently of numerical pair eligibility.
/// This is offline derived-media availability, never native acceptance.
pub fn validate_bundle(root: &Path, deadline: Instant) -> Result<Value> {
    let bundle = load_bundle(root, deadline)?;
    let frames = bundle.report["frames"].as_array().context("missing frame records")?;
    let mut reconstructed = Sha256::new();
    let mut sheet_hash = Sha256::new();
    let mut tiles = Vec::with_capacity(8);
    // At most one tile row is retained; every actual frame is decoded once.
    for row in 0..7 {
        for col in 0..8 {
            io::check(deadline)?;
            let index = row * 8 + col;
            let decoded = png_image::decode(&io::relative(&bundle.root, io::text(&frames[index], "path")?)?)?;
            check_frame(&decoded, &frames[index], index)?;
            reconstructed.update(decoded.samples());
            tiles.push(decoded);
        }
        let stride = WIDTH as usize * 3;
        for y in 0..HEIGHT as usize {
            io::check(deadline)?;
            for tile in &tiles { sheet_hash.update(&tile.samples()[y * stride..(y + 1) * stride]); }
        }
        tiles.clear();
    }
    let reconstructed = format!("{:x}", reconstructed.finalize());
    ensure!(bundle.original["video"]["decoded_rgb_sha256"] == reconstructed,
        "re-concatenated PNG RGB hash mismatch");
    let record = &bundle.report["contact_sheet"];
    ensure!(record["columns"] == 8 && record["rows"] == 7, "contact sheet layout mismatch");
    let path = io::relative(&bundle.root, io::text(record, "path")?)?;
    let mut decoder = png::Decoder::new(std::io::BufReader::new(io::open(&path, 96 * MIB)?));
    decoder.set_transformations(png::Transformations::IDENTITY);
    let mut reader = decoder.read_info()?;
    let info = reader.info();
    ensure!(info.width == WIDTH * 8 && info.height == HEIGHT * 7
        && info.color_type == png::ColorType::Rgb && info.bit_depth == png::BitDepth::Eight
        && !info.interlaced && info.animation_control.is_none(), "contact sheet RGB layout mismatch");
    let mut actual = Sha256::new();
    let mut rows = 0u32;
    while let Some(row) = reader.next_row()? {
        io::check(deadline)?;
        ensure!(rows < HEIGHT * 7 && row.data().len() == WIDTH as usize * 8 * 3,
            "contact sheet row count/width mismatch");
        actual.update(row.data());
        rows += 1;
    }
    // Row exhaustion is not terminal-chunk validation (notably IEND).
    io::check(deadline)?;
    reader.finish().context("finishing contact sheet PNG chunks")?;
    ensure!(rows == HEIGHT * 7 && actual.finalize() == sheet_hash.finalize(),
        "contact sheet differs from complete frame samples");
    io::check(deadline)?;
    Ok(json!({"kind":"unchanged_h3_bundle_validation","bundle":bundle.report_identity,
        "source":bundle.report["source"],"inspection":bundle.report["inspection"],
        "video":{"frame_count":FRAMES,"decoded_rgb_bytes":RGB_BYTES,"reconstructed_rgb_sha256":reconstructed},
        "audio":{"sha256":bundle.report["audio"]["sha256"],"bytes":bundle.pcm.len(),
            "sample_frames":bundle.alignment.samples,"sample_rate_hz":32000,"channels":2},
        "contact_sheet_validated":true,
        "method":"Complete original-bound PNG RGB reconstruction, finite PCM hash/count, source/inspection/probe timeline, tool and settled-helper artifact validation; no decoder invocation or native acceptance verdict."}))
}

fn pair_alignment(left: &Alignment, right: &Alignment) -> Result<()> {
    ensure!(left.video_timeline == right.video_timeline && left.video_stream == right.video_stream,
        "original video PTS/duration/rate/dimension alignment differs");
    ensure!(left.audio_timeline == right.audio_timeline && left.audio_stream == right.audio_stream && left.samples == right.samples,
        "original PCM PTS/count/rate/channel alignment differs");
    Ok(())
}
pub fn compare_videos(left_bundle: &Path, right_bundle: &Path, deadline: Instant) -> Result<Value> {
    let left = load_bundle(left_bundle, deadline)?;
    let right = load_bundle(right_bundle, deadline)?;
    pair_alignment(&left.alignment, &right.alignment)?;
    ensure!(left.report["decoder"]["sha256"] == right.report["decoder"]["sha256"], "decoder fingerprints differ");
    let mut left_hash = Sha256::new();
    let mut right_hash = Sha256::new();
    let compared = frame_sequence::compare(
        SequenceSource { input: &left.alignment.sequence, directory: &left.root },
        SequenceSource { input: &right.alignment.sequence, directory: &right.root }, None, None, None,
        |index, a, b, _| {
            io::check(deadline)?;
            check_frame(a, &left.report["frames"][index as usize], index as usize)?;
            check_frame(b, &right.report["frames"][index as usize], index as usize)?;
            left_hash.update(a.samples());
            right_hash.update(b.samples());
            Ok(())
        })?;
    ensure!(left.original["video"]["decoded_rgb_sha256"] == format!("{:x}", left_hash.finalize())
        && right.original["video"]["decoded_rgb_sha256"] == format!("{:x}", right_hash.finalize()), "re-concatenated comparison PNG RGB hash mismatch");
    let audio = compare_pcm(&left.pcm, &right.pcm, left.alignment.samples, deadline)?;
    let frames: Vec<Value> = compared.frames.into_iter().map(|f| json!({"index":f.index,"pts_ns":f.pts_ns,"duration_ns":f.duration_ns,
        "left":f.baseline,"right":f.candidate,"metrics":f.metrics})).collect();
    io::check(deadline)?;
    Ok(json!({"kind":"unchanged_video_and_audio_sample_metrics","left_bundle":left.report_identity,"right_bundle":right.report_identity,
        "left_source":left.report["source"],"right_source":right.report["source"],
        "left_inspection":left.report["inspection"],"right_inspection":right.report["inspection"],
        "left_sequence":compared.baseline,"right_sequence":compared.candidate,
        "video":{"frames":frames,"aggregate":compared.metrics,"frame_count":FRAMES,
            "method":"frame_sequence::compare, every original-bound RGB24 frame, no tolerance or assessment",
            "units":"unchanged decoded 8-bit RGB sample codes","denominator":"N = 56 * 864 * 480 * 3 = 69672960; exact integer sums; no averaging per-frame MAE/RMSE/PSNR",
            "timing_method":TIMELINE_METHOD},"audio":audio}))
}

#[cfg(test)]
#[path = "media_tests.rs"]
mod media_tests;
