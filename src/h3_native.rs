//! CPU-only enrollment of a reviewed isolated H3 build; never execution authority.
use crate::{guards::GuardConfig, h3, schema::*};
use anyhow::{Context, Result, bail, ensure};
use serde::{Deserialize, Serialize};
use serde_json::json;
use sha2::{Digest, Sha256};
use std::{
    collections::BTreeMap,
    fs::{self, DirBuilder, File, OpenOptions},
    io::{Read, Write},
    os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt, PermissionsExt},
    path::{Component, Path, PathBuf},
    time::Duration,
};

const JSON_LIMIT: u64 = 1024 * 1024;
const SOURCE_LIMIT: u64 = 16 * 1024 * 1024;
const TOOL_LIMIT: u64 = 256 * 1024 * 1024;
const OUTPUT_LIMIT: u64 = 64 * 1024 * 1024;
const IDENTITY_METHOD: &str = "SHA-256 of bounded compact serde JSON of command in versioned Rust field order; caller-reviewed build receipt consistency, not historical compilation attestation or execution authority";
const NATIVE_SOURCES: &[&str] = &[
    "h3.c", "h3_host.c", "h3_safetensors.c", "h3_weights.c", "h3_text_encoder.c",
    "h3_dit_schedule.c", "h3_dit.c", "h3_video_vae.c", "h3_video_encoder.c",
    "h3_audio_vae.c", "h3_ffmpeg.c", "h3_terminal.c", "h3_vision_encoder.c",
    "h3_multimodal.c", "main.c", "h3_cli.c", "linenoise.c",
    "h3_metal.m", "h3_gpu.m", "h3_tokenizer.m",
];
const CFLAGS: &[&str] = &[
    "-std=c11", "-O3", "-MMD", "-MP", "-Wall", "-Wextra", "-Wpedantic",
    "-Wshadow", "-Wconversion", "-Wno-sign-conversion", "-D_DARWIN_C_SOURCE",
];
const SELECTED_SOURCES: &[&str] = &[
    "main.c", "h3.h", "h3.c", "h3_gpu.m", "h3_host.c", "h3_host.h", "h3_ffmpeg.c",
    "h3_audio_vae.c", "h3_video_encoder.c", "h3_dit.c", "h3_text_encoder.c",
    "h3_video_vae.c", "h3_vision_encoder.c",
];
const METADATA: &[&str] = &[
    "FL2VA/transformer/config.json", "FL2VA/tokenizer/tokenizer.json",
    "FL2VA/video_vae/config.json", "FL2VA/audio_vae/config.json",
];

pub struct PrepareOptions {
    pub preparation: h3::PrepareOptions,
    pub build_receipt: PathBuf,
    pub output_root: PathBuf,
    pub guard_config: GuardConfig,
    pub timeout: Duration,
    pub max_output_bytes: u64,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PreparedPlan {
    pub(crate) sha256: String,
    identity_method: String,
    pub(crate) command: Plan,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Plan {
    schema_version: u32,
    kind: String,
    pub(crate) preparation: h3::Plan,
    pub(crate) output_root: PathBuf,
    pub(crate) timeout_ms: u64,
    pub(crate) max_output_bytes: u64,
    pub(crate) guard_config: GuardConfig,
    build_receipt_file: h3::Fingerprint,
    build_receipt: BuildReceipt,
}

// This is an explicit caller-reviewed record of the actual recipe invocation, not
// proof that a compiler historically consumed these bytes. Hashes alone cannot
// supply that proof. In particular, a matching executable basename is insufficient.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct BuildReceipt {
    schema_version: u32,
    kind: String,
    caller_reviewed: bool,
    build_exit_code: i32,
    build_root: PathBuf,
    source_dir: PathBuf,
    compiler: h3::Fingerprint,
    recipe: h3::Fingerprint,
    bridge_source: h3::Fingerprint,
    bridge_header: h3::Fingerprint,
    native_sources: Vec<h3::Fingerprint>,
    native_headers: Vec<h3::Fingerprint>,
    binary: h3::Fingerprint,
    commands: Vec<BuildCommand>,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct BuildCommand {
    cwd: PathBuf,
    argv: Vec<String>,
}

fn text(path: &Path) -> Result<&str> {
    path.to_str().context("H3 paths must be UTF-8")
}

fn path_shape(path: &Path) -> Result<()> {
    let value = text(path)?;
    ensure!(path.is_absolute() && path != Path::new("/") && value.len() <= 4096
        && !value.bytes().any(|b| b == 0 || b.is_ascii_control())
        && path.components().all(|c| matches!(c, Component::RootDir | Component::Normal(_)))
        && value.split('/').skip(1).all(|part| !matches!(part, "" | "." | "..")),
        "invalid explicit H3 path: {}", path.display());
    Ok(())
}

fn identity_shape(identity: &h3::Fingerprint, limit: u64) -> Result<()> {
    path_shape(&identity.path)?;
    ensure!(identity.bytes > 0 && identity.bytes <= limit
        && identity.sha256.len() == 64
        && identity.sha256.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)),
        "invalid bounded file identity: {}", identity.path.display());
    Ok(())
}

struct DigestWriter { hash: Sha256, bytes: u64 }
impl Write for DigestWriter {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        if bytes.len() as u64 > JSON_LIMIT.saturating_sub(self.bytes) {
            return Err(std::io::Error::other("H3 plan exceeds 1 MiB serialization bound"));
        }
        self.hash.update(bytes);
        self.bytes += bytes.len() as u64;
        Ok(bytes.len())
    }
    fn flush(&mut self) -> std::io::Result<()> { Ok(()) }
}
fn digest(value: &impl Serialize) -> Result<String> {
    let mut sink = DigestWriter { hash: Sha256::new(), bytes: 0 };
    serde_json::to_writer(&mut sink, value)?;
    Ok(format!("{:x}", sink.hash.finalize()))
}

fn regular(path: &Path, limit: u64) -> Result<File> {
    let file = OpenOptions::new().read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK).open(path)
        .with_context(|| format!("opening selected H3 file {}", path.display()))?;
    let metadata = file.metadata()?;
    ensure!(metadata.is_file() && metadata.len() > 0 && metadata.len() <= limit,
        "not a nonempty bounded regular file: {}", path.display());
    Ok(file)
}
fn fingerprint(path: &Path, limit: u64, executable: bool) -> Result<h3::Fingerprint> {
    path_shape(path)?;
    ensure!(fs::canonicalize(path)? == path, "identity path must be canonical: {}", path.display());
    let mut file = regular(path, limit)?;
    let before = file.metadata()?;
    ensure!(!executable || before.permissions().mode() & 0o111 != 0,
        "selected H3 executable lacks executable permissions");
    let mut hash = Sha256::new();
    let mut bytes = 0;
    let mut buffer = [0u8; 65536];
    while let count @ 1.. = file.read(&mut buffer)? {
        bytes += count as u64;
        ensure!(bytes <= limit, "H3 identity file grew beyond bound");
        hash.update(&buffer[..count]);
    }
    let after = file.metadata()?;
    let current = fs::symlink_metadata(path)?;
    ensure!(current.is_file() && bytes == before.len()
        && [after, current].iter().all(|m| m.dev() == before.dev() && m.ino() == before.ino()
            && m.len() == before.len() && m.mtime() == before.mtime()
            && m.mtime_nsec() == before.mtime_nsec() && m.ctime() == before.ctime()
            && m.ctime_nsec() == before.ctime_nsec()), "H3 identity file changed while hashing");
    Ok(h3::Fingerprint { path: path.into(), sha256: format!("{:x}", hash.finalize()), bytes })
}
fn read_receipt(path: &Path) -> Result<(BuildReceipt, h3::Fingerprint)> {
    let identity = fingerprint(path, JSON_LIMIT, false)?;
    let mut bytes = Vec::new();
    regular(path, JSON_LIMIT)?.take(JSON_LIMIT + 1).read_to_end(&mut bytes)?;
    ensure!(bytes.len() as u64 == identity.bytes
        && format!("{:x}", Sha256::digest(&bytes)) == identity.sha256,
        "H3 build receipt changed while reading");
    Ok((serde_json::from_slice(&bytes).context("parsing explicit H3 build receipt v1")?, identity))
}
fn private_directory(path: &Path) -> Result<()> {
    path_shape(path)?;
    ensure!(fs::canonicalize(path)? == path, "private directory must be canonical");
    let metadata = fs::symlink_metadata(path)?;
    ensure!(metadata.is_dir() && metadata.uid() == unsafe { libc::geteuid() }
        && metadata.permissions().mode() & 0o777 == 0o700,
        "H3 directory must be owned by current user with mode 0700: {}", path.display());
    Ok(())
}
fn write_json(path: &Path, value: &impl Serialize) -> Result<()> {
    let mut file = OpenOptions::new().write(true).create_new(true).mode(0o600).open(path)?;
    serde_json::to_writer_pretty(&mut file, value)?;
    file.write_all(b"\n")?;
    file.sync_all()?;
    Ok(())
}

impl BuildReceipt {
    fn project_root(&self) -> Result<&Path> {
        self.recipe.path.parent().and_then(Path::parent).context("build recipe needs project/adapters parent")
    }
    fn expected_commands(&self) -> Result<Vec<BuildCommand>> {
        let cwd = self.project_root()?.to_path_buf();
        let adapter = self.bridge_source.path.parent().context("bridge parent absent")?;
        let source = text(&self.source_dir)?;
        let object = |name: &str| self.build_root.join("obj").join(format!("{}.o", name.rsplit_once('.').expect("fixed source suffix").0));
        let mut commands = Vec::with_capacity(NATIVE_SOURCES.len() + 2);
        for name in NATIVE_SOURCES {
            let mut argv: Vec<String> = std::iter::once("clang").chain(CFLAGS.iter().copied()).map(str::to_owned).collect();
            if name.ends_with(".m") { argv.push("-fobjc-arc".into()); }
            if *name == "linenoise.c" {
                argv.extend(["-Wno-conversion".into(), "-Wno-variadic-macro-arguments-omitted".into()]);
            }
            argv.push(format!("-I{source}"));
            if *name == "h3_ffmpeg.c" {
                argv.extend(["-include".into(), text(&self.bridge_header.path)?.into()]);
            }
            argv.extend(["-c".into(), text(&self.source_dir.join(name))?.into(), "-o".into(), text(&object(name))?.into()]);
            commands.push(BuildCommand { cwd: cwd.clone(), argv });
        }
        let bridge_object = self.build_root.join("obj/mil-h3-owned-helpers.o");
        let mut argv: Vec<String> = std::iter::once("clang").chain(CFLAGS.iter().copied()).map(str::to_owned).collect();
        argv.extend([format!("-I{}/", text(adapter)?), "-c".into(), text(&self.bridge_source.path)?.into(), "-o".into(), text(&bridge_object)?.into()]);
        commands.push(BuildCommand { cwd: cwd.clone(), argv });
        let mut argv = vec!["clang".into(), "-o".into(), text(&self.binary.path)?.into()];
        for name in NATIVE_SOURCES { argv.push(text(&object(name))?.into()); }
        argv.push(text(&bridge_object)?.into());
        for framework in ["Foundation", "Metal", "MetalPerformanceShaders", "MetalPerformanceShadersGraph", "Accelerate"] {
            argv.extend(["-framework".into(), framework.into()]);
        }
        argv.extend(["-licucore".into(), "-lm".into()]);
        commands.push(BuildCommand { cwd, argv });
        Ok(commands)
    }
    fn validate(&self, preparation: &h3::Plan) -> Result<()> {
        ensure!(self.schema_version == 1 && self.kind == "h3_owned_native_build_receipt"
            && self.caller_reviewed && self.build_exit_code == 0,
            "successful caller-reviewed bridge build receipt required");
        for path in [&self.build_root, &self.source_dir] { path_shape(path)?; }
        ensure!(self.source_dir == preparation.source_dir && self.binary == preparation.binary
            && self.binary.path == self.build_root.join("bin/h3-owned")
            && !self.build_root.starts_with(&self.source_dir)
            && !self.build_root.starts_with(self.project_root()?.join("target"))
            && !self.build_root.starts_with(&preparation.model_dir), "build/source/binary isolation differs");
        identity_shape(&self.compiler, TOOL_LIMIT)?;
        ensure!(self.compiler.path == Path::new("/usr/bin/clang"), "reviewed compiler selection must be /usr/bin/clang");
        identity_shape(&self.binary, TOOL_LIMIT)?;
        let adapter = self.project_root()?.join("adapters");
        for (actual, name, reviewed) in [
            (&self.recipe, "h3_owned_native.mk", include_bytes!("../adapters/h3_owned_native.mk").as_slice()),
            (&self.bridge_source, "h3_owned_helpers.c", include_bytes!("../adapters/h3_owned_helpers.c").as_slice()),
            (&self.bridge_header, "h3_owned_helpers.h", include_bytes!("../adapters/h3_owned_helpers.h").as_slice()),
        ] {
            identity_shape(actual, SOURCE_LIMIT)?;
            ensure!(actual.path == adapter.join(name) && actual.bytes == reviewed.len() as u64
                && actual.sha256 == format!("{:x}", Sha256::digest(reviewed)),
                "build receipt differs from compiled-in reviewed bridge/recipe: {name}");
        }
        ensure!(self.native_sources.len() == NATIVE_SOURCES.len(), "incomplete native compilation source set");
        for (identity, name) in self.native_sources.iter().zip(NATIVE_SOURCES) {
            identity_shape(identity, SOURCE_LIMIT)?;
            ensure!(identity.path == self.source_dir.join(name), "native source set/order differs");
        }
        ensure!(!self.native_headers.is_empty() && self.native_headers.len() <= 128, "native header set bound differs");
        for (index, identity) in self.native_headers.iter().enumerate() {
            identity_shape(identity, SOURCE_LIMIT)?;
            ensure!(identity.path.parent() == Some(self.source_dir.as_path())
                && identity.path.extension().is_some_and(|e| e == "h")
                && (index == 0 || self.native_headers[index - 1].path < identity.path),
                "native headers must be unique sorted top-level headers");
        }
        for selected in &preparation.selected_source {
            ensure!(self.native_sources.iter().chain(&self.native_headers).any(|item| item == selected),
                "preparation source is absent or different in build receipt: {}", selected.path.display());
        }
        ensure!(self.commands == self.expected_commands()?, "compile/link argv or cwd differs from reviewed isolated bridge recipe");
        Ok(())
    }
}

fn validate_preparation(plan: &h3::Plan) -> Result<()> {
    ensure!(plan.schema_version == 1 && plan.kind == "h3_preparation_plan"
        && plan.profile == h3::Profile::Draft && plan.clear_environment,
        "native enrollment requires exact draft H3 preparation");
    let workload = &plan.workload;
    workload.validate()?;
    ensure!(plan.workload_identity == workload.identity()?
        && workload.process_policy == ProcessPolicy::FreshProcess && workload.cache_policy == CachePolicy::Unspecified,
        "H3 workload identity/process/cache contract differs");
    let MediaSettings::Video { generation: g, frames, layers, playback_fps, render_resolution, reuse, audio } = &workload.settings else {
        bail!("native H3 requires video");
    };
    ensure!(g.resolution == (Resolution { width: 864, height: 480 }) && g.steps == 8 && *layers == 50
        && *frames == 56 && *playback_fps == 24.0
        && render_resolution.as_ref().is_none_or(|r| r == &g.resolution)
        && matches!(reuse, ReusePolicy::Disabled | ReusePolicy::Interval { every: 1, core_every: 1 })
        && matches!(audio, AudioConfiguration::Generate { sample_rate_hz: 32000, channels: 2 }),
        "native H3 requires unreduced draft864x480/8/50/reuse1/core1,56 frames,24 FPS,32kHz stereo");
    // Preserve explicit checkpoint storage precision without inventing a resolved
    // dtype for Auto or claiming uniform compute precision for mixed native kernels.
    ensure!(g.precision == Precision::Bfloat16,
        "native H3 requires explicit bfloat16 model precision; Auto cannot be resolved from available evidence");
    ensure!(g.negative_prompt.is_none() && g.scheduler == "euler" && g.guidance == 1.0
        && g.compute_precision.is_none()
        && matches!(g.quantization, Quantization::None) && g.batch_size == 1 && g.strength.is_none()
        && g.optimizations.use_kv_cache.is_none() && g.optimizations.step_cache_ratio.is_none()
        && g.optimizations.step_cache_threshold.is_none() && g.prompt.len() <= 64 * 1024,
        "unsupported H3 generation setting");
    for path in [&plan.preparation_dir, &plan.model_dir, &plan.shader_cwd, &plan.source_dir, &plan.input_dir] { path_shape(path)?; }
    for tool in [&plan.binary, &plan.ffmpeg, &plan.ffprobe] { identity_shape(tool, TOOL_LIMIT)?; }
    ensure!(plan.binary.sha256 != plan.ffmpeg.sha256 && plan.binary.sha256 != plan.ffprobe.sha256
        && plan.ffmpeg.sha256 != plan.ffprobe.sha256, "native and codec identities must be distinct");
    identity_shape(&plan.shader, SOURCE_LIMIT)?;
    ensure!(plan.shader.path == plan.shader_cwd.join("h3_shaders.metal"), "shader selection differs");
    for (identities, names, root) in [
        (&plan.selected_source, SELECTED_SOURCES, &plan.source_dir),
        (&plan.model_metadata, METADATA, &plan.model_dir),
    ] {
        ensure!(identities.len() == names.len(), "selected source/model metadata set differs");
        for (identity, name) in identities.iter().zip(names) {
            identity_shape(identity, SOURCE_LIMIT)?;
            ensure!(identity.path == root.join(name), "selected source/model metadata path differs");
        }
    }
    let mut argv = vec![text(&plan.binary.path)?.into(), "-d".into(), text(&plan.model_dir)?.into(),
        "-p".into(), g.prompt.clone(), "-o".into(), text(&plan.preparation_dir.join("h3-output.mp4"))?.into()];
    for (flag, value) in [("--width", "864".into()), ("--height", "480".into()), ("--frames", "56".into()),
        ("--steps", "8".into()), ("--layers", "50".into()), ("--reuse", "1".into()),
        ("--core-reuse", "1".into()), ("--seed", g.seed.to_string())] {
        argv.extend([flag.into(), value]);
    }
    if render_resolution.is_some() { argv.extend(["--render-width".into(), "864".into(), "--render-height".into(), "480".into()]); }
    ensure!(g.references.len() <= 2 && plan.conditioning.len() == g.references.len(), "conditioning set differs");
    for (input, selected) in g.references.iter().zip(&plan.conditioning) {
        ensure!(input.strength.is_none() && matches!(input.role, ReferenceRole::FirstFrame | ReferenceRole::LastFrame)
            && selected.role == input.role && selected.input.sha256 == input.sha256 && selected.input.bytes == input.bytes
            && selected.input.path == plan.input_dir.join(&input.path)
            && selected.width > 0 && selected.height > 0 && selected.width <= 16384 && selected.height <= 16384
            && u64::from(selected.width) * u64::from(selected.height) <= crate::png_image::MAX_PIXELS
            && selected.transformation.len() <= 4096, "conditioning identity/shape differs");
        identity_shape(&selected.input, crate::png_image::MAX_ENCODED_BYTES)?;
        argv.extend([if input.role == ReferenceRole::FirstFrame { "--first-frame" } else { "--last-frame" }.into(), text(&selected.input.path)?.into()]);
    }
    argv.push("--profile".into());
    ensure!(plan.argv == argv, "native H3 argv differs from fixed workload and pinned paths");
    let environment = BTreeMap::from([
        ("H3_FFMPEG".into(), text(&plan.ffmpeg.path)?.into()),
        ("H3_FFPROBE".into(), text(&plan.ffprobe.path)?.into()),
        ("H3_PROFILE".into(), "1".into()),
    ]);
    ensure!(plan.environment == environment, "H3 preparation environment differs");
    Ok(())
}

impl PreparedPlan {
    /// Pure bounded shape/contract validation; no file reads, probes or execution.
    pub(crate) fn validate_enrolled(&self) -> Result<()> {
        let command = &self.command;
        ensure!(self.identity_method == IDENTITY_METHOD && command.schema_version == 1
            && command.kind == "native_h3_owned_launch_plan", "unsupported native H3 launch plan");
        ensure!(self.sha256 == digest(command)?, "native H3 launch plan identity mismatch");
        validate_preparation(&command.preparation)?;
        path_shape(&command.output_root)?;
        ensure!((1000..=600_000).contains(&command.timeout_ms) && command.max_output_bytes == OUTPUT_LIMIT,
            "native H3 timeout/output bounds differ");
        command.guard_config.validate()?;
        ensure!(command.guard_config.min_disk_free_bytes >= 10 * 1024 * 1024 * 1024
            && command.guard_config.max_disk_growth_bytes <= 256 * 1024 * 1024,
            "native H3 resource safety floor weakened");
        for readonly in [&command.preparation.model_dir, &command.preparation.source_dir, &command.preparation.shader_cwd,
            &command.build_receipt.build_root] {
            ensure!(!command.output_root.starts_with(readonly) && !command.preparation.preparation_dir.starts_with(readonly),
                "H3 output/preparation must not write inside selected read-only assets");
        }
        identity_shape(&command.build_receipt_file, JSON_LIMIT)?;
        command.build_receipt.validate(&command.preparation)?;
        Ok(())
    }

    /// Reconstruct the existing CPU preparation and check current bounded bytes.
    /// No subprocess, native import, compiler or model weight payload is opened.
    pub(crate) fn verify_files(&self) -> Result<()> {
        self.validate_enrolled()?;
        let command = &self.command;
        let plan = &command.preparation;
        private_directory(&command.output_root)?;
        private_directory(&plan.preparation_dir)?;
        private_directory(&command.build_receipt.build_root)?;
        let (receipt, identity) = read_receipt(&command.build_receipt_file.path)?;
        ensure!(identity == command.build_receipt_file && digest(&receipt)? == digest(&command.build_receipt)?,
            "reviewed H3 build receipt changed");
        for selected in [&receipt.compiler, &receipt.recipe, &receipt.bridge_source, &receipt.bridge_header]
            .into_iter().chain(&receipt.native_sources).chain(&receipt.native_headers) {
            let executable = selected == &receipt.compiler;
            ensure!(fingerprint(&selected.path, if executable { TOOL_LIMIT } else { SOURCE_LIMIT }, executable)? == *selected,
                "reviewed H3 build input changed: {}", selected.path.display());
        }
        let mut headers = Vec::new();
        for (index, entry) in fs::read_dir(&receipt.source_dir)?.enumerate() {
            ensure!(index < 4096, "native source directory exceeds 4096 entries");
            let path = entry?.path();
            if path.extension().is_some_and(|e| e == "h") {
                ensure!(headers.len() < 128, "native header set exceeds bound");
                headers.push(path);
            }
        }
        headers.sort();
        ensure!(headers.iter().eq(receipt.native_headers.iter().map(|item| &item.path)), "native header set changed");
        let reconstructed = h3::build_plan(&h3::PrepareOptions {
            workload: plan.workload.clone(), profile: plan.profile, binary: plan.binary.path.clone(),
            model_dir: plan.model_dir.clone(), shader_cwd: plan.shader_cwd.clone(), source_dir: plan.source_dir.clone(),
            input_dir: plan.input_dir.clone(), ffmpeg: plan.ffmpeg.path.clone(), ffprobe: plan.ffprobe.path.clone(),
            output_dir: plan.preparation_dir.clone(),
        })?;
        ensure!(reconstructed == *plan, "current H3 files/profile/argv differ from enrolled preparation");
        Ok(())
    }
}

/// Publish a new private CPU report on both validation success and failure.
/// A valid report establishes neither model readiness nor native launch authority.
pub fn prepare(options: PrepareOptions) -> Result<PreparedPlan> {
    DirBuilder::new().mode(0o700).create(&options.preparation.output_dir)
        .context("creating new private native H3 preparation bundle")?;
    let mut report = json!({
        "schema_version": 1, "kind": "native_h3_preparation", "valid": false,
        "execution_attested": false, "capture_eligible": false, "native_execution_authorized": false,
        "requested_workload": options.preparation.workload, "requested_profile": options.preparation.profile,
        "selected_paths": {"binary": options.preparation.binary, "model_dir": options.preparation.model_dir,
            "shader_cwd": options.preparation.shader_cwd, "source_dir": options.preparation.source_dir,
            "input_dir": options.preparation.input_dir, "ffmpeg": options.preparation.ffmpeg,
            "ffprobe": options.preparation.ffprobe, "build_receipt": options.build_receipt,
            "output_root": options.output_root},
        "requested_bounds": {"timeout_ms": options.timeout.as_millis().to_string(),
            "max_output_bytes": options.max_output_bytes, "guard_config": options.guard_config},
        "bounds": {"receipt_and_plan_bytes": JSON_LIMIT, "source_or_metadata_file_bytes": SOURCE_LIMIT,
            "tool_file_bytes": TOOL_LIMIT, "native_headers": 128, "directory_entries": 4096,
            "timeout_ms_max": 600000, "output_bytes": OUTPUT_LIMIT},
        "limits": ["CPU metadata and bounded file identity checks only; no native/tools/compiler execution or model weight payload reads",
            "Caller-reviewed build receipt and current selected bytes are checked against the exact compiled-in bridge recipe; this is not independent historical compilation attestation",
            "Model revision is caller-declared; metadata hashes are not a full model fingerprint; tensor compatibility, GPU readiness, native phases and real output remain unobserved",
            "Native enrollment requires explicit bfloat16 checkpoint storage precision, not Auto; mixed native kernels do not establish a uniform compute dtype, so compute_precision remains unset",
            "Fresh exact transaction authorization, resource grant, guardian lease and owned-process confinement remain mandatory; CPU JSON creates no authority",
            "File checks do not provide immutable filesystem custody; bounds are cooperative, not kernel time/RSS/quota guarantees"],
        "errors": []
    });
    let result = (|| -> Result<PreparedPlan> {
        ensure!(options.timeout >= Duration::from_secs(1) && options.timeout <= Duration::from_secs(600)
            && options.timeout.subsec_nanos().is_multiple_of(1_000_000), "native H3 timeout must be 1..600 seconds in whole milliseconds");
        let preparation = h3::build_plan(&options.preparation)?;
        let (build_receipt, build_receipt_file) = read_receipt(&options.build_receipt)?;
        let command = Plan {
            schema_version: 1, kind: "native_h3_owned_launch_plan".into(), preparation,
            output_root: options.output_root.clone(), timeout_ms: options.timeout.as_millis() as u64,
            max_output_bytes: options.max_output_bytes, guard_config: options.guard_config.clone(),
            build_receipt_file, build_receipt,
        };
        let prepared = PreparedPlan { sha256: digest(&command)?, identity_method: IDENTITY_METHOD.into(), command };
        prepared.verify_files()?;
        write_json(&options.preparation.output_dir.join("plan.json"), &prepared)?;
        Ok(prepared)
    })();
    match &result {
        Ok(plan) => {
            report["valid"] = json!(true);
            report["plan"] = json!("plan.json");
            report["plan_sha256"] = json!(plan.sha256);
        }
        Err(error) => report["errors"] = json!([format!("{error:#}")]),
    }
    write_json(&options.preparation.output_dir.join("report.json"), &report)?;
    result
}

#[cfg(test)]
mod tests {
    use super::*;

    // Deliberately nonexistent paths: enrollment validation must be pure.
    fn enrolled() -> PreparedPlan {
        let base = Path::new("/mil-h3-shape-test");
        let source = base.join("source");
        let model = base.join("model");
        let build = base.join("build");
        let project = base.join("project");
        let preparation_dir = base.join("preparation");
        let file = |path: PathBuf, tag: u8| h3::Fingerprint {
            path, bytes: 1, sha256: format!("{tag:02x}").repeat(32),
        };
        let workload: Workload = serde_json::from_value(json!({
            "schema_version":1, "id":"native-h3-boundary", "model":{"name":"synthetic","revision":null,"sha256":null},
            "settings":{"modality":"video","generation":{
                "prompt":"literal ; $(not-a-shell)", "negative_prompt":null,"seed":17,
                "resolution":{"width":864,"height":480},"steps":8,"scheduler":"euler","guidance":1.0,
                "precision":"bfloat16","compute_precision":null,"quantization":{"kind":"none"},
                "batch_size":1,"references":[],"strength":null,
                "optimizations":{"use_kv_cache":null,"step_cache_ratio":null,"step_cache_threshold":null}},
                "frames":56,"layers":50,"playback_fps":24.0,"render_resolution":null,
                "reuse":{"kind":"interval","every":1,"core_every":1},
                "audio":{"kind":"generate","sample_rate_hz":32000,"channels":2}},
            "process_policy":"fresh_process","cache_policy":"unspecified"
        })).unwrap();
        let binary = file(build.join("bin/h3-owned"), 1);
        let ffmpeg = file(base.join("ffmpeg"), 2);
        let ffprobe = file(base.join("ffprobe"), 3);
        let mut argv: Vec<String> = [
            text(&binary.path).unwrap(), "-d", text(&model).unwrap(), "-p", "literal ; $(not-a-shell)",
            "-o", text(&preparation_dir.join("h3-output.mp4")).unwrap(),
            "--width", "864", "--height", "480", "--frames", "56", "--steps", "8",
            "--layers", "50", "--reuse", "1", "--core-reuse", "1", "--seed", "17",
        ].into_iter().map(str::to_owned).collect();
        argv.push("--profile".into());
        let preparation = h3::Plan {
            schema_version: 1, kind: "h3_preparation_plan".into(),
            workload_identity: workload.identity().unwrap(), workload, profile: h3::Profile::Draft,
            preparation_dir, binary: binary.clone(), model_dir: model,
            shader_cwd: source.clone(), source_dir: source.clone(), input_dir: base.join("input"),
            shader: file(source.join("h3_shaders.metal"), 4),
            selected_source: SELECTED_SOURCES.iter().map(|name| file(source.join(name), 4)).collect(),
            model_metadata: METADATA.iter().map(|name| file(base.join("model").join(name), 4)).collect(),
            environment: BTreeMap::from([
                ("H3_FFMPEG".into(), text(&ffmpeg.path).unwrap().into()),
                ("H3_FFPROBE".into(), text(&ffprobe.path).unwrap().into()),
                ("H3_PROFILE".into(), "1".into()),
            ]),
            ffmpeg, ffprobe, conditioning: vec![], argv, clear_environment: true,
            declarations: json!({}),
        };
        let reviewed = |name: &str, bytes: &[u8]| h3::Fingerprint {
            path: project.join("adapters").join(name), bytes: bytes.len() as u64,
            sha256: format!("{:x}", Sha256::digest(bytes)),
        };
        let mut receipt = BuildReceipt {
            schema_version: 1, kind: "h3_owned_native_build_receipt".into(), caller_reviewed: true,
            build_exit_code: 0, build_root: build, source_dir: source.clone(),
            compiler: file("/usr/bin/clang".into(), 5),
            recipe: reviewed("h3_owned_native.mk", include_bytes!("../adapters/h3_owned_native.mk")),
            bridge_source: reviewed("h3_owned_helpers.c", include_bytes!("../adapters/h3_owned_helpers.c")),
            bridge_header: reviewed("h3_owned_helpers.h", include_bytes!("../adapters/h3_owned_helpers.h")),
            native_sources: NATIVE_SOURCES.iter().map(|name| file(source.join(name), 4)).collect(),
            native_headers: vec![file(source.join("h3.h"), 4), file(source.join("h3_host.h"), 4)],
            binary, commands: vec![],
        };
        receipt.commands = receipt.expected_commands().unwrap();
        let command = Plan {
            schema_version: 1, kind: "native_h3_owned_launch_plan".into(), preparation,
            output_root: base.join("output"), timeout_ms: 600_000, max_output_bytes: OUTPUT_LIMIT,
            guard_config: GuardConfig { min_disk_free_bytes: 10 * 1024 * 1024 * 1024,
                max_disk_growth_bytes: 256 * 1024 * 1024, sample_interval_ms: 500 },
            build_receipt_file: file(base.join("receipt.json"), 6), build_receipt: receipt,
        };
        PreparedPlan { sha256: digest(&command).unwrap(), identity_method: IDENTITY_METHOD.into(), command }
    }

    #[test]
    fn native_enrollment_rejects_auto_without_fabricating_compute_precision() {
        let mut plan = enrolled();
        plan.validate_enrolled().unwrap();
        let MediaSettings::Video { generation, .. } = &mut plan.command.preparation.workload.settings else {
            unreachable!();
        };
        assert_eq!(generation.precision, Precision::Bfloat16);
        assert!(generation.compute_precision.is_none());
        generation.precision = Precision::Auto;
        plan.command.preparation.workload_identity = plan.command.preparation.workload.identity().unwrap();
        plan.sha256 = digest(&plan.command).unwrap();
        assert!(plan.validate_enrolled().is_err());
    }

    #[test]
    fn native_root_environment_rejects_extra_missing_and_changed_entries() {
        use crate::h3_owned::{native_environment, validate_native_environment};
        let plan = enrolled();
        let dir = Path::new("/private/cpu-only-environment-admission");
        let expected = native_environment(&plan, dir, 42).unwrap();
        validate_native_environment(&plan, dir, 42, &expected).unwrap();
        for key in ["H3_TOKEN_REDUCTION", "H3_DIT_LAYER_POLICY", "H3_VAE_TILE_PIXELS", "UNENROLLED_KEY"] {
            let mut actual = expected.clone();
            actual.insert(key.into(), "1".into());
            assert!(validate_native_environment(&plan, dir, 42, &actual).is_err(), "{key}");
        }
        for key in expected.keys() {
            let mut missing = expected.clone();
            missing.remove(key);
            assert!(validate_native_environment(&plan, dir, 42, &missing).is_err(), "missing {key}");
            let mut changed = expected.clone();
            changed.get_mut(key).unwrap().push_str("-changed");
            assert!(validate_native_environment(&plan, dir, 42, &changed).is_err(), "changed {key}");
        }
        assert!(validate_native_environment(&plan, dir, 43, &expected).is_err());
        assert!(validate_native_environment(&plan, Path::new("/private/another-run"), 42, &expected).is_err());
        // Re-hashing a plan cannot enroll otherwise forbidden native knobs.
        let mut forged = plan.clone();
        forged.command.preparation.environment.insert("H3_TOKEN_REDUCTION".into(), "1".into());
        forged.sha256 = digest(&forged.command).unwrap();
        assert!(native_environment(&forged, dir, 42).is_err());
    }

    #[test]
    fn reenrolled_command_cannot_override_profile_tool_or_native_argv() {
        let original = enrolled();
        original.validate_enrolled().unwrap();
        for mutation in 0..5 {
            let mut plan = original.clone();
            match mutation {
                0 => plan.command.preparation.argv.push("--render-width".into()),
                1 => plan.command.preparation.profile = h3::Profile::Standard,
                2 => plan.command.preparation.ffmpeg.path = "/different/ffmpeg".into(),
                3 => plan.command.preparation.selected_source[0].sha256 = "ff".repeat(32),
                _ => plan.command.guard_config.min_disk_free_bytes = 1,
            }
            plan.sha256 = digest(&plan.command).unwrap();
            assert!(plan.validate_enrolled().is_err(), "mutation {mutation} bypassed enrollment");
        }
    }

    #[test]
    fn same_named_binary_does_not_replace_reviewed_bridge_build() {
        let original = enrolled();
        for mutation in 0..4 {
            let mut plan = original.clone();
            let receipt = &mut plan.command.build_receipt;
            match mutation {
                0 => receipt.caller_reviewed = false,
                1 => receipt.bridge_source.sha256 = "ff".repeat(32),
                2 => {
                    let codec = receipt.commands.iter_mut().find(|command|
                        command.argv.iter().any(|arg| arg.ends_with("/h3_ffmpeg.c"))).unwrap();
                    let index = codec.argv.iter().position(|arg| arg == "-include").unwrap();
                    codec.argv.drain(index..index + 2);
                }
                _ => receipt.commands.last_mut().unwrap().argv.retain(|arg| !arg.ends_with("/mil-h3-owned-helpers.o")),
            }
            plan.sha256 = digest(&plan.command).unwrap();
            assert!(plan.validate_enrolled().is_err(), "mutation {mutation} bypassed bridge proof contract");
        }
    }

    #[test]
    fn missing_selected_assets_leave_failed_private_preparation_report() {
        let directory = tempfile::tempdir().unwrap();
        let root = fs::canonicalize(directory.path()).unwrap();
        let output = root.join("preparation");
        let template = enrolled();
        let result = prepare(PrepareOptions {
            preparation: h3::PrepareOptions {
                workload: template.command.preparation.workload, profile: h3::Profile::Draft,
                binary: root.join("missing-native"), model_dir: root.join("missing-model"),
                shader_cwd: root.clone(), source_dir: root.clone(), input_dir: root.clone(),
                ffmpeg: root.join("missing-ffmpeg"), ffprobe: root.join("missing-ffprobe"),
                output_dir: output.clone(),
            },
            build_receipt: root.join("missing-receipt"), output_root: root,
            guard_config: template.command.guard_config, timeout: Duration::from_secs(600),
            max_output_bytes: OUTPUT_LIMIT,
        });
        assert!(result.is_err());
        let report: serde_json::Value = serde_json::from_reader(File::open(output.join("report.json")).unwrap()).unwrap();
        assert_eq!(report["valid"], false);
        assert_eq!(report["execution_attested"], false);
        assert!(report["errors"][0].as_str().unwrap().contains("missing-native"));
        assert!(!output.join("plan.json").exists());
        assert_eq!(fs::metadata(output.join("report.json")).unwrap().permissions().mode() & 0o777, 0o600);
    }
}
