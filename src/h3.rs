//! CPU-only preparation and inspection of caller-supplied evidence; never an executor.
use crate::{
    png_image,
    schema::*,
    video_inspection::{self, VideoInspectionOptions},
};
use anyhow::{Context, Result, bail, ensure};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::{
    collections::{BTreeMap, BTreeSet},
    fs::{self, DirBuilder, File, OpenOptions},
    io::{Read, Write},
    os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt, PermissionsExt},
    path::{Path, PathBuf},
    str::FromStr,
    time::{Duration, Instant},
};

const JSON_LIMIT: u64 = 16 * 1024 * 1024;
const LOG_LIMIT: u64 = 8 * 1024 * 1024;
const FILE_LIMIT: u64 = 256 * 1024 * 1024;
pub const PARSER_ID: &str = "mil-h3-saved-profile-v1";

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Profile {
    Draft,
    Standard,
    Detailed,
}
impl FromStr for Profile {
    type Err = anyhow::Error;
    fn from_str(value: &str) -> Result<Self> {
        match value {
            "draft" => Ok(Self::Draft),
            "standard" => Ok(Self::Standard),
            "detailed" => Ok(Self::Detailed),
            _ => bail!("profile must be draft, standard or detailed"),
        }
    }
}
impl Profile {
    fn settings(self) -> (u32, u32, u32, u32) {
        match self {
            Self::Draft => (864, 480, 8, 1),
            Self::Standard => (1344, 768, 20, 2),
            Self::Detailed => (1344, 768, 20, 1),
        }
    }
}

pub struct PrepareOptions {
    pub workload: Workload,
    pub profile: Profile,
    pub binary: PathBuf,
    pub model_dir: PathBuf,
    pub shader_cwd: PathBuf,
    pub source_dir: PathBuf,
    pub input_dir: PathBuf,
    pub ffmpeg: PathBuf,
    pub ffprobe: PathBuf,
    pub output_dir: PathBuf,
}

pub struct InspectOptions {
    pub plan: PathBuf,
    pub stdout: PathBuf,
    pub stderr: PathBuf,
    pub exit_code: i32,
    pub video: PathBuf,
    pub output_dir: PathBuf,
    pub timeout: Duration,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Fingerprint {
    pub path: PathBuf,
    pub sha256: String,
    pub bytes: u64,
}
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Conditioning {
    pub role: ReferenceRole,
    pub input: Fingerprint,
    pub width: u32,
    pub height: u32,
    pub transformation: String,
}
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Plan {
    pub schema_version: u32,
    pub kind: String,
    pub workload: Workload,
    pub workload_identity: String,
    pub profile: Profile,
    pub preparation_dir: PathBuf,
    pub binary: Fingerprint,
    pub model_dir: PathBuf,
    pub shader_cwd: PathBuf,
    pub source_dir: PathBuf,
    pub input_dir: PathBuf,
    pub shader: Fingerprint,
    pub selected_source: Vec<Fingerprint>,
    pub model_metadata: Vec<Fingerprint>,
    pub ffmpeg: Fingerprint,
    pub ffprobe: Fingerprint,
    pub conditioning: Vec<Conditioning>,
    /// Includes argv[0]; output is absolute and inside the private preparation directory.
    pub argv: Vec<String>,
    pub clear_environment: bool,
    pub environment: BTreeMap<String, String>,
    pub declarations: Value,
}

fn unavailable<T>(reason: &str) -> Observation<T> {
    Observation::Unavailable {
        reason: reason.into(),
    }
}
fn text(path: &Path) -> Result<String> {
    Ok(path.to_str().context("paths must be UTF-8")?.into())
}
fn directory(path: &Path) -> Result<PathBuf> {
    ensure!(
        path.is_absolute(),
        "explicit absolute directory required: {}",
        path.display()
    );
    let path = fs::canonicalize(path)
        .with_context(|| format!("resolving selected directory {}", path.display()))?;
    ensure!(path.is_dir(), "not a directory: {}", path.display());
    text(&path)?;
    Ok(path)
}
fn regular(path: &Path, limit: u64) -> Result<File> {
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(path)
        .with_context(|| format!("opening selected file {}", path.display()))?;
    let meta = file.metadata()?;
    ensure!(
        meta.is_file() && meta.len() <= limit,
        "not a bounded regular file: {}",
        path.display()
    );
    Ok(file)
}
fn bounded(path: &Path, limit: u64) -> Result<Vec<u8>> {
    let file = regular(path, limit)?;
    let mut bytes = Vec::new();
    file.take(limit + 1).read_to_end(&mut bytes)?;
    ensure!(bytes.len() as u64 <= limit, "input grew beyond byte bound");
    Ok(bytes)
}
fn fingerprint(path: &Path, limit: u64, executable: bool) -> Result<Fingerprint> {
    ensure!(
        path.is_absolute(),
        "explicit absolute file required: {}",
        path.display()
    );
    let path = fs::canonicalize(path)
        .with_context(|| format!("resolving selected file {}", path.display()))?;
    text(&path)?;
    let mut file = regular(&path, limit)?;
    let before = file.metadata()?;
    ensure!(
        !executable || before.permissions().mode() & 0o111 != 0,
        "selected tool is not executable"
    );
    let mut hash = Sha256::new();
    let mut bytes = 0;
    let mut buffer = [0; 65536];
    while let count @ 1.. = file.read(&mut buffer)? {
        bytes += count as u64;
        ensure!(bytes <= limit, "identity input grew beyond byte bound");
        hash.update(&buffer[..count]);
    }
    let after = file.metadata()?;
    let current = fs::metadata(&path)?;
    ensure!(
        bytes == before.len()
            && before.len() == after.len()
            && before.mtime() == after.mtime()
            && before.mtime_nsec() == after.mtime_nsec()
            && current.dev() == before.dev()
            && current.ino() == before.ino()
            && current.len() == after.len()
            && current.mtime() == after.mtime()
            && current.mtime_nsec() == after.mtime_nsec(),
        "identity input changed while hashing"
    );
    Ok(Fingerprint {
        path,
        sha256: format!("{:x}", hash.finalize()),
        bytes,
    })
}
fn private_dir(path: &Path) -> Result<()> {
    DirBuilder::new()
        .mode(0o700)
        .create(path)
        .context("creating new private H3 bundle")
}
fn private_write(path: &Path, bytes: &[u8]) -> Result<()> {
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)?;
    file.write_all(bytes)?;
    file.sync_all()?;
    Ok(())
}
fn write_json(path: &Path, value: &impl Serialize) -> Result<()> {
    let mut bytes = serde_json::to_vec_pretty(value)?;
    bytes.push(b'\n');
    private_write(path, &bytes)
}

fn validate_request(workload: &Workload, profile: Profile) -> Result<()> {
    workload.validate()?;
    ensure!(
        workload.process_policy == ProcessPolicy::FreshProcess
            && workload.cache_policy == CachePolicy::Unspecified,
        "H3 requires fresh_process and unspecified cache; cache state cannot be guaranteed"
    );
    let MediaSettings::Video {
        generation: g,
        frames,
        layers,
        playback_fps,
        render_resolution,
        reuse,
        audio,
    } = &workload.settings
    else {
        bail!("H3 requires a video workload")
    };
    let (width, height, steps, interval) = profile.settings();
    ensure!(
        g.resolution == (Resolution { width, height }) && g.steps == steps && *layers == 50,
        "workload dimensions, steps and layers must exactly match selected profile"
    );
    let actual_interval = match reuse {
        ReusePolicy::Disabled => 1,
        ReusePolicy::Interval {
            every,
            core_every: 1,
        } => *every,
        _ => bail!("H3 profile requires denoiser interval reuse and core_every=1"),
    };
    ensure!(
        actual_interval == interval,
        "reuse must exactly match selected profile"
    );
    ensure!(
        (56..=362).contains(frames) && (frames - 5) % 17 == 0,
        "frames must already be aligned to 5+17*n within 56..362; no silent frame rounding"
    );
    ensure!(
        *playback_fps == 24.0,
        "H3 playback FPS is fixed at 24 (not generation throughput)"
    );
    ensure!(
        matches!(
            audio,
            AudioConfiguration::Generate {
                sample_rate_hz: 32000,
                channels: 2
            }
        ),
        "H3 supports generated 32000 Hz stereo audio only"
    );
    if let Some(r) = render_resolution {
        ensure!(
            r.width >= 32
                && r.height >= 32
                && r.width % 32 == 0
                && r.height % 32 == 0
                && r.width <= width
                && r.height <= height
                && u64::from(r.width) * u64::from(height) == u64::from(r.height) * u64::from(width),
            "internal render canvas must be same-aspect multiples of 32 no larger than output"
        );
    }
    ensure!(
        g.negative_prompt.is_none(),
        "negative prompt is unsupported"
    );
    ensure!(
        g.scheduler == "euler" && g.guidance == 1.0,
        "H3 requires euler scheduler and guidance=1; custom scheduler/guidance unsupported"
    );
    ensure!(
        matches!(g.precision, Precision::Auto | Precision::Bfloat16)
            && g.compute_precision.is_none(),
        "H3 BF16 checkpoint storage does not promise BF16 compute: precision must be auto/bfloat16 and compute_precision null (native mixed kernels)"
    );
    ensure!(
        matches!(g.quantization, Quantization::None),
        "requested weight quantization is unsupported; native mixed kernels are separately disclosed"
    );
    ensure!(
        g.batch_size == 1 && g.strength.is_none(),
        "batch_size must be 1 and strength absent"
    );
    ensure!(
        g.optimizations.use_kv_cache.is_none()
            && g.optimizations.step_cache_ratio.is_none()
            && g.optimizations.step_cache_threshold.is_none(),
        "explicit cache optimizations unsupported"
    );
    ensure!(g.prompt.len() <= 64 * 1024, "prompt exceeds 64 KiB bound");
    for input in &g.references {
        ensure!(
            matches!(
                input.role,
                ReferenceRole::FirstFrame | ReferenceRole::LastFrame
            ) && input.strength.is_none(),
            "only first/last PNG frame anchors without strength are supported; schema does not distinguish native full-reference types"
        );
    }
    Ok(())
}

/// Validates paths and bounded metadata, not weight tensors, model readiness or native execution.
pub fn build_plan(options: &PrepareOptions) -> Result<Plan> {
    validate_request(&options.workload, options.profile)?;
    let preparation_dir = std::path::absolute(&options.output_dir)?;
    let input_dir = directory(&options.input_dir)?;
    let binary = fingerprint(&options.binary, FILE_LIMIT, true)?;
    let ffmpeg = fingerprint(&options.ffmpeg, FILE_LIMIT, true)?;
    let ffprobe = fingerprint(&options.ffprobe, FILE_LIMIT, true)?;
    ensure!(
        binary.sha256 != ffmpeg.sha256 && binary.sha256 != ffprobe.sha256,
        "native binary cannot be selected as an offline media tool, including copies or aliases"
    );
    let model_dir = directory(&options.model_dir)?;
    let shader_cwd = directory(&options.shader_cwd)?;
    let source_dir = directory(&options.source_dir)?;
    let shader = fingerprint(&shader_cwd.join("h3_shaders.metal"), JSON_LIMIT, false)?;
    let mut selected_source = Vec::new();
    for name in [
        "main.c",
        "h3.h",
        "h3.c",
        "h3_gpu.m",
        "h3_host.c",
        "h3_host.h",
        "h3_ffmpeg.c",
        "h3_audio_vae.c",
        "h3_video_encoder.c",
        "h3_dit.c",
        "h3_text_encoder.c",
        "h3_video_vae.c",
        "h3_vision_encoder.c",
    ] {
        selected_source.push(fingerprint(&source_dir.join(name), JSON_LIMIT, false)?);
    }
    let mut model_metadata = Vec::new();
    for relative in [
        "FL2VA/transformer/config.json",
        "FL2VA/tokenizer/tokenizer.json",
        "FL2VA/video_vae/config.json",
        "FL2VA/audio_vae/config.json",
    ] {
        let path = model_dir.join(relative);
        let bytes = bounded(&path, JSON_LIMIT)
            .with_context(|| format!("reading model metadata {relative}"))?;
        let value: Value = serde_json::from_slice(&bytes).context("invalid model metadata JSON")?;
        ensure!(
            value.as_object().is_some_and(|o| !o.is_empty()),
            "model metadata must be a nonempty JSON object: {relative}"
        );
        let identity = fingerprint(&path, JSON_LIMIT, false)?;
        ensure!(
            identity.sha256 == format!("{:x}", Sha256::digest(&bytes)),
            "model metadata changed while reading"
        );
        model_metadata.push(identity);
    }
    // Directory metadata only: never open or hash a model weight payload.
    for relative in [
        "FL2VA/text_encoder",
        "FL2VA/transformer",
        "FL2VA/video_vae/source",
        "FL2VA/audio_vae",
    ] {
        let path = model_dir.join(relative);
        let mut weights = false;
        for (index, entry) in fs::read_dir(&path)
            .with_context(|| format!("missing model component {relative}"))?
            .enumerate()
        {
            ensure!(
                index < 4096,
                "model component directory exceeds 4096-entry bound"
            );
            let entry = entry?;
            if entry.path().extension().is_some_and(|e| e == "safetensors") {
                let metadata = fs::metadata(entry.path())?;
                ensure!(
                    metadata.is_file() && metadata.len() > 0,
                    "weight asset must be a nonempty regular file"
                );
                weights = true;
            }
        }
        ensure!(
            weights,
            "missing safetensors assets in {relative}; metadata inspection does not validate tensor payloads"
        );
    }
    let MediaSettings::Video {
        generation: g,
        frames,
        layers,
        render_resolution,
        ..
    } = &options.workload.settings
    else {
        unreachable!()
    };
    let render = render_resolution.as_ref().unwrap_or(&g.resolution);
    let mut conditioning = Vec::new();
    for input in &g.references {
        let input_path = input_dir.join(&input.path);
        let canonical = fs::canonicalize(&input_path)?;
        ensure!(
            canonical.starts_with(&input_dir),
            "conditioning input escapes workload directory"
        );
        let decoded = png_image::decode(&input_path)?;
        let identity = decoded.identity();
        ensure!(
            identity.sha256 == input.sha256 && identity.bytes == input.bytes,
            "conditioning input hash/length mismatch"
        );
        ensure!(
            identity.color == png_image::SampleColor::Rgb && identity.bit_depth == 8,
            "frame anchors must be RGB8 PNGs; alpha/color conversion semantics are not supported"
        );
        let pinned = fingerprint(&canonical, png_image::MAX_ENCODED_BYTES, false)?;
        ensure!(
            pinned.sha256 == identity.sha256,
            "conditioning input changed while decoding"
        );
        conditioning.push(Conditioning { role: input.role, input: pinned, width: identity.width, height: identity.height, transformation: format!("Selected-source recipe only, not executed: FFmpeg first frame, Lanczos {} to {}x{}, RGB24; channel-major float32 /255; video encoder normalization mean [0.485,0.456,0.406], std [0.229,0.224,0.225]. Anchor at {}. No transformed-pixel or latent identity observed.", if input.role == ReferenceRole::FirstFrame { "stretch" } else { "cover scale and centered crop" }, render.width, render.height, if input.role == ReferenceRole::FirstFrame { "frame 0".into() } else { format!("frame {}", frames - 1) }) });
    }
    let output_path = preparation_dir.join("h3-output.mp4");
    let mut argv = vec![
        text(&binary.path)?,
        "-d".into(),
        text(&model_dir)?,
        "-p".into(),
        g.prompt.clone(),
        "-o".into(),
        text(&output_path)?,
    ];
    for (flag, value) in [
        ("--width", g.resolution.width.to_string()),
        ("--height", g.resolution.height.to_string()),
        ("--frames", frames.to_string()),
        ("--steps", g.steps.to_string()),
        ("--layers", layers.to_string()),
        ("--reuse", options.profile.settings().3.to_string()),
        ("--core-reuse", "1".into()),
        ("--seed", g.seed.to_string()),
    ] {
        argv.extend([flag.into(), value]);
    }
    if render_resolution.is_some() {
        argv.extend([
            "--render-width".into(),
            render.width.to_string(),
            "--render-height".into(),
            render.height.to_string(),
        ]);
    }
    for input in &conditioning {
        argv.extend([
            if input.role == ReferenceRole::FirstFrame {
                "--first-frame"
            } else {
                "--last-frame"
            }
            .into(),
            text(&input.input.path)?,
        ]);
    }
    argv.push("--profile".into());
    let environment = BTreeMap::from([
        ("H3_FFMPEG".into(), text(&ffmpeg.path)?),
        ("H3_FFPROBE".into(), text(&ffprobe.path)?),
        ("H3_PROFILE".into(), "1".into()),
    ]);
    Ok(Plan {
        schema_version: 1,
        kind: "h3_preparation_plan".into(),
        workload: options.workload.clone(),
        workload_identity: options.workload.identity()?,
        profile: options.profile,
        preparation_dir,
        binary,
        model_dir,
        shader_cwd,
        source_dir,
        input_dir,
        shader,
        selected_source,
        model_metadata,
        ffmpeg,
        ffprobe,
        conditioning,
        argv,
        clear_environment: true,
        environment,
        declarations: json!({
            "provenance": "caller-requested settings and configured file identities, not observed native settings",
            "model_revision": {"value": options.workload.model.revision, "provenance": "caller declaration; not independently verified"},
            "model_requested_sha256": options.workload.model.sha256,
            "full_observed_model_fingerprint": unavailable::<String>("metadata hashes are not a full model identity; weight payloads not read"),
            "runtime_version": unavailable::<String>("no runtime invoked"),
            "selected_source_version": unavailable::<String>("source files fingerprinted; version not parsed"),
            "compiled_from_selected_source": unavailable::<bool>("binary/source hash selection does not prove compilation provenance"),
            "readiness": "metadata-only inventory; checkpoint payload compatibility and GPU readiness untested",
            "selected_source_defaults": {"token_reduction": false, "int8_row_fc2": false, "reference_rope": false, "ssd_streaming": false, "slower_kernel_overrides": false, "preview_denoise": false, "compute": "native device-selected mixed BF16/FP32/int8 kernels; not BF16-only compute", "scheduler": "Euler, native video sigma shift12/audio shift3; reuse follows selected native algorithm"},
            "modified_internal_canvas": render != &g.resolution,
            "profile_scope": "Profile fixes output dimensions/steps/layers/reuse. An explicitly reduced internal canvas is a distinct workload, not an equivalent-work baseline.",
            "output": {"path": output_path, "scope": "inside preparation directory, not shader/source/model directories; not created or reserved; plan is not execution authorization"}
        }),
    })
}

pub fn prepare(options: PrepareOptions) -> Result<bool> {
    private_dir(&options.output_dir)?;
    let result = build_plan(&options);
    let mut report = json!({
        "schema_version":1, "kind":"h3_preparation", "valid":false,
        "execution_attested":false, "errors":[],
        "requested_workload": options.workload, "requested_profile": options.profile,
        "selected_paths": {
            "binary": options.binary, "model_dir": options.model_dir,
            "shader_cwd": options.shader_cwd, "source_dir": options.source_dir,
            "input_dir": options.input_dir, "ffmpeg": options.ffmpeg, "ffprobe": options.ffprobe
        }
    });
    match result {
        Ok(plan) => {
            write_json(&options.output_dir.join("plan.json"), &plan)?;
            report["valid"] = json!(true);
            report["plan"] = json!("plan.json");
        }
        Err(error) => report["errors"] = json!([format!("{error:#}")]),
    }
    write_json(&options.output_dir.join("report.json"), &report)?;
    Ok(report["valid"] == true)
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ParsedProfile {
    pub parser_id: String,
    pub status: Observation<String>,
    pub timings: Vec<Timing>,
    pub resources: Vec<ResourceMeasurement>,
    pub dispatch_counts: BTreeMap<String, BTreeMap<String, u64>>,
    pub diagnostics: Vec<String>,
}

fn profile_record(line: &str) -> Result<(String, [f64; 6], BTreeMap<String, u64>)> {
    let line = line
        .strip_prefix("h3 profile: ")
        .context("unknown profiling prefix")?;
    let (prefix, rest) = line.split_once("wall=").context("missing wall field")?;
    let label = prefix.split_whitespace().collect::<Vec<_>>().join(" ");
    ensure!(
        [
            "H3 DiT load",
            "H3 DiT GPU Euler denoise",
            "H3 DiT Euler denoise",
            "H3 DiT RES denoise",
            "H3 DiT total",
            "Qwen text encoder total",
            "audio VAE decoder total",
            "audio VAE encoder total",
            "video VAE encoder total",
            "resident video VAE decoder total",
            "video VAE decoder total",
            "Qwen vision encoder total",
            "Metal context total"
        ]
        .contains(&label.as_str()),
        "unknown profiling context or phase"
    );
    let mut rest = rest;
    let mut values = [0.0_f64; 6];
    for (index, (key, suffix)) in [
        ("", "s"),
        ("encode=", "s"),
        ("wait=", "s"),
        ("root-gpu=", "s"),
        ("peak=", "GiB"),
        ("alloc=", "GiB"),
    ]
    .iter()
    .enumerate()
    {
        rest = rest
            .trim_start()
            .strip_prefix(key)
            .context("missing or reordered profiling field")?
            .trim_start();
        let end = rest.find(char::is_whitespace).unwrap_or(rest.len());
        let number = rest[..end]
            .strip_suffix(suffix)
            .context("invalid profiling unit")?;
        let (whole, fraction) = number
            .split_once('.')
            .context("invalid profiling decimal")?;
        ensure!(
            !whole.is_empty()
                && whole.bytes().all(|b| b.is_ascii_digit())
                && fraction.len() == 3
                && fraction.bytes().all(|b| b.is_ascii_digit()),
            "profiling value must match native three-decimal grammar"
        );
        values[index] = number.parse()?;
        ensure!(
            values[index].is_finite() && values[index] >= 0.0,
            "invalid profiling numeric value"
        );
        ensure!(
            index < 4 || (values[index] * 1073741824.0).is_finite(),
            "profiling allocation overflows byte representation"
        );
        rest = &rest[end..];
    }
    let mut counters = BTreeMap::new();
    for key in ["submissions", "direct", "linear", "conv", "attention"] {
        rest = rest
            .trim_start()
            .strip_prefix(key)
            .and_then(|r| r.strip_prefix('='))
            .context("missing or reordered dispatch counter")?;
        let end = rest.find(char::is_whitespace).unwrap_or(rest.len());
        ensure!(
            !rest[..end].is_empty() && rest[..end].bytes().all(|b| b.is_ascii_digit()),
            "malformed dispatch counter"
        );
        counters.insert(key.into(), rest[..end].parse()?);
        rest = &rest[end..];
    }
    ensure!(rest.trim().is_empty(), "unknown trailing profiling fields");
    Ok((label, values, counters))
}

/// Strict saved-stderr grammar, not attestation. Any ambiguous record invalidates all parsed spans.
/// Native totals overlap marks and contexts: values are preserved separately, never added.
pub fn parse_profile(stderr: &[u8]) -> ParsedProfile {
    let mut result = ParsedProfile {
        parser_id: PARSER_ID.into(),
        status: unavailable("no recognized saved profiling records"),
        timings: vec![],
        resources: vec![],
        dispatch_counts: BTreeMap::new(),
        diagnostics: vec![],
    };
    if stderr.len() as u64 > LOG_LIMIT {
        result
            .diagnostics
            .push("saved stderr exceeds byte bound".into());
        return result;
    }
    let Ok(text) = std::str::from_utf8(stderr) else {
        result
            .diagnostics
            .push("saved stderr is not UTF-8; raw bytes retained".into());
        return result;
    };
    let mut seen = BTreeSet::new();
    let mut records = Vec::new();
    for (line_no, line) in text.lines().enumerate() {
        if !line.contains("h3 profile") {
            continue;
        }
        match profile_record(line) {
            Ok((label, values, counts)) if seen.insert(label.clone()) => {
                records.push((label, values, counts))
            }
            Ok(_) => result.diagnostics.push(format!(
                "duplicate profile context/phase at line {}",
                line_no + 1
            )),
            Err(error) => result.diagnostics.push(format!(
                "unrecognized/malformed profile at line {}: {error}",
                line_no + 1
            )),
        }
    }
    if !result.diagnostics.is_empty() {
        result.status = unavailable(
            "ambiguous, malformed, duplicate or unknown saved profiling; no phases inferred",
        );
        return result;
    }
    if records.is_empty() {
        return result;
    }
    for (label, values, counters) in records {
        for (index, name, scope) in [
            (0, "wall", TimingScope::Native),
            (1, "encode", TimingScope::Native),
            (2, "wait", TimingScope::Native),
            (3, "root_gpu", TimingScope::Gpu),
        ] {
            result.timings.push(Timing { phase: format!("{label}/{name}"), scope, unit: TimingUnit::Seconds, method: format!("{PARSER_ID}: caller-supplied stderr, rounded native counters; execution not attested"), boundary: "selected-source context mark or lifetime; overlaps other native spans, not end-to-end host inference time or successful-phase proof".into(), measurement: Observation::Available { value: values[index] } });
        }
        for (index, name) in [(4, "peak_live_bytes"), (5, "allocated_bytes_delta")] {
            result.resources.push(ResourceMeasurement { kind: ResourceKind::TensorBytes, scope: ResourceScope::Runtime, unit: ResourceUnit::Bytes, method: format!("{PARSER_ID}: saved {label}/{name}; rounded GiB * 2^30; not RSS or device-wide allocation"), boundary: if index == 4 { "context lifetime high-water mark, not phase delta" } else { "context mark/lifetime cumulative allocation delta, not peak live memory" }.into(), measurement: Observation::Available { value: values[index] * 1073741824.0 } });
        }
        result.dispatch_counts.insert(label, counters);
    }
    result.status = Observation::Available {
        value: "recognized saved records only; no phase completion or owned execution receipt"
            .into(),
    };
    result
}

fn snapshot(source: &Path, destination: &Path, role: &str, limit: u64) -> Result<Artifact> {
    let bytes = bounded(source, limit)?;
    private_write(destination, &bytes)?;
    Ok(Artifact {
        path: destination
            .file_name()
            .context("snapshot name missing")?
            .to_string_lossy()
            .into_owned(),
        sha256: format!("{:x}", Sha256::digest(&bytes)),
        bytes: bytes.len() as u64,
        role: role.into(),
    })
}

pub fn inspect_saved(options: InspectOptions) -> Result<bool> {
    private_dir(&options.output_dir)?;
    let started = Instant::now();
    let missing = unavailable::<String>(
        "offline caller-supplied evidence; no parent-owned execution receipt",
    );
    let mut report = json!({
        "schema_version":1, "kind":"offline_h3_saved_result_inspection", "valid":false,
        "execution_attested":false, "capture_eligible":false,
        "caller_reported_exit_code": options.exit_code,
        "settings_provenance":"caller-supplied plan; not observed native settings",
        "observed_runtime_identity":missing, "observed_model_identity":missing,
        "native_host_duration":missing, "seconds_per_generated_clip":missing,
        "generated_frames_per_second":missing, "generated_media_seconds_per_second":missing,
        "artifacts":[], "errors":[], "profiling":null, "video_inspection":null,
        "limitations":["Validity means only supplied evidence passes; no native execution or successful inference attested.", "Configured binary/source/model metadata identities are not the observed runtime/model identity or compilation proof.", "Saved profile spans can overlap and can be printed on failure; never summed or interpreted as successful phases."]
    });
    let mut errors = Vec::new();
    let mut artifacts = Vec::new();
    for (source, name, role, limit) in [
        (
            &options.plan,
            "plan.json",
            "caller_supplied_plan",
            JSON_LIMIT,
        ),
        (
            &options.stdout,
            "stdout.log",
            "caller_supplied_stdout",
            LOG_LIMIT,
        ),
        (
            &options.stderr,
            "stderr.log",
            "caller_supplied_stderr",
            LOG_LIMIT,
        ),
    ] {
        match snapshot(source, &options.output_dir.join(name), role, limit) {
            Ok(artifact) => artifacts.push(artifact),
            Err(error) => errors.push(format!("{name}: {error:#}")),
        }
    }
    if options.exit_code != 0 {
        errors.push(format!(
            "caller-reported native exit was nonzero: {}",
            options.exit_code
        ));
    }
    if let Ok(bytes) = bounded(&options.output_dir.join("stderr.log"), LOG_LIMIT) {
        report["profiling"] = serde_json::to_value(parse_profile(&bytes))?;
    }
    let inspection = (|| -> Result<()> {
        ensure!(
            options.timeout >= Duration::from_secs(1)
                && options.timeout <= Duration::from_secs(120),
            "inspection timeout must be 1..120 seconds including preparation"
        );
        let plan: Plan =
            serde_json::from_slice(&bounded(&options.output_dir.join("plan.json"), JSON_LIMIT)?)?;
        let rebuilt = build_plan(&PrepareOptions {
            workload: plan.workload.clone(),
            profile: plan.profile,
            binary: plan.binary.path.clone(),
            model_dir: plan.model_dir.clone(),
            shader_cwd: plan.shader_cwd.clone(),
            source_dir: plan.source_dir.clone(),
            input_dir: plan.input_dir.clone(),
            ffmpeg: plan.ffmpeg.path.clone(),
            ffprobe: plan.ffprobe.path.clone(),
            output_dir: plan.preparation_dir.clone(),
        })?;
        ensure!(
            rebuilt == plan,
            "saved plan is inconsistent with selected paths, hashes, requested settings or supported command/environment contract"
        );
        report["configured_identity"] = serde_json::to_value(&plan)?;
        let remaining = options
            .timeout
            .checked_sub(started.elapsed())
            .context("inspection deadline exceeded during preparation")?;
        let video_dir = options.output_dir.join("video");
        let valid = video_inspection::inspect(VideoInspectionOptions {
            workload: plan.workload,
            input: options.video.clone(),
            ffmpeg: plan.ffmpeg.path,
            ffprobe: plan.ffprobe.path,
            output_dir: video_dir,
            timeout: remaining,
        })?;
        report["video_inspection"] = json!({"report":"video/report.json", "valid":valid});
        ensure!(
            valid,
            "saved video/audio failed full CPU inspection; see video/report.json"
        );
        Ok(())
    })();
    if let Err(error) = inspection {
        errors.push(format!("{error:#}"));
    }
    report["valid"] = json!(errors.is_empty());
    report["errors"] = json!(errors);
    report["artifacts"] = serde_json::to_value(artifacts)?;
    write_json(&options.output_dir.join("report.json"), &report)?;
    Ok(report["valid"] == true)
}
