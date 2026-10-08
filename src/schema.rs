use anyhow::{Context, Result, ensure};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::HashSet;

pub const SCHEMA_VERSION: u32 = 1;

/// Every declared field participates in identity. v1 accepts no unknown fields.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Workload {
    pub schema_version: u32,
    pub id: String,
    pub model: ModelRequest,
    pub settings: MediaSettings,
    pub process_policy: ProcessPolicy,
    pub cache_policy: CachePolicy,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ModelRequest {
    pub name: String,
    pub revision: Option<String>,
    pub sha256: Option<String>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProcessPolicy {
    FreshProcess,
    InProcess,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CachePolicy {
    Unspecified,
    Cold,
    Warm,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(tag = "modality", rename_all = "snake_case", deny_unknown_fields)]
pub enum MediaSettings {
    Image {
        generation: GenerationSettings,
    },
    Video {
        generation: GenerationSettings,
        frames: u32,
        layers: u32,
        playback_fps: f64,
        render_resolution: Option<Resolution>,
        reuse: ReusePolicy,
        audio: AudioConfiguration,
    },
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GenerationSettings {
    pub prompt: String,
    pub negative_prompt: Option<String>,
    pub seed: u64,
    pub resolution: Resolution,
    pub steps: u32,
    pub scheduler: String,
    pub guidance: f64,
    pub precision: Precision,
    pub compute_precision: Option<Precision>,
    pub quantization: Quantization,
    pub batch_size: u32,
    pub references: Vec<ReferenceInput>,
    pub strength: Option<f64>,
    pub optimizations: Optimizations,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Resolution {
    pub width: u32,
    pub height: u32,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Precision {
    Auto,
    Float32,
    Float16,
    Bfloat16,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum Quantization {
    None,
    Weights { bits: u8, method: String },
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Optimizations {
    pub use_kv_cache: Option<bool>,
    pub step_cache_ratio: Option<f64>,
    pub step_cache_threshold: Option<f64>,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReferenceInput {
    pub path: String,
    pub sha256: String,
    pub bytes: u64,
    pub role: ReferenceRole,
    pub strength: Option<f64>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReferenceRole {
    Reference,
    FirstFrame,
    LastFrame,
    Mask,
    Audio,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum ReusePolicy {
    Disabled,
    Interval {
        every: u32,
        core_every: u32,
    },
    Approximate {
        method: String,
        ratio: f64,
        core_ratio: f64,
        layers: Vec<u32>,
    },
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum AudioConfiguration {
    Disabled,
    Generate { sample_rate_hz: u32, channels: u8 },
    Reference { input: ReferenceInput },
}

/// An observation is never encoded as a zero or empty string when unavailable.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(tag = "status", rename_all = "snake_case", deny_unknown_fields)]
pub enum Observation<T> {
    Available { value: T },
    Unavailable { reason: String },
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RuntimeIdentity {
    pub name: String,
    pub version: Observation<String>,
    pub source: Observation<SourceIdentity>,
    pub executable: Observation<FileIdentity>,
    pub modules: Vec<FileIdentity>,
    pub model: Observation<ObservedModel>,
    pub device: Observation<String>,
    pub cache_state: Observation<String>,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SourceIdentity {
    pub repository: String,
    pub revision: String,
    pub dirty: Observation<bool>,
}

/// Observed paths can be absolute; unlike artifact references they are not opened by capture.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FileIdentity {
    pub path: String,
    pub sha256: Observation<String>,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ObservedModel {
    pub name: String,
    pub revision: Observation<String>,
    pub files: Vec<FileIdentity>,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AdapterResult {
    pub schema_version: u32,
    pub workload_identity: String,
    pub resolved: Workload,
    pub runtime: RuntimeIdentity,
    pub timings: Vec<Timing>,
    pub resources: Vec<ResourceMeasurement>,
    pub artifacts: Vec<Artifact>,
    pub output_evidence: OutputEvidence,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Artifact {
    pub path: String,
    pub sha256: String,
    pub bytes: u64,
    pub role: String,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TimingScope {
    Host,
    Native,
    Gpu,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TimingUnit {
    Seconds,
    Milliseconds,
    Nanoseconds,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Timing {
    pub phase: String,
    pub scope: TimingScope,
    pub unit: TimingUnit,
    pub method: String,
    pub boundary: String,
    pub measurement: Observation<f64>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ResourceKind {
    ProcessRss,
    TensorBytes,
    DriverAllocation,
    SystemPressure,
    Swap,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ResourceScope {
    Process,
    Runtime,
    Device,
    System,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ResourceUnit {
    Bytes,
    Ratio,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ResourceMeasurement {
    pub kind: ResourceKind,
    pub scope: ResourceScope,
    pub unit: ResourceUnit,
    pub method: String,
    pub boundary: String,
    pub measurement: Observation<f64>,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ComparisonReference {
    pub sha256: String,
    pub provenance: String,
}

/// Comparison evidence describes output agreement, never perceptual quality.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum OutputEvidence {
    Unassessed {
        reason: String,
    },
    Exact {
        reference: ComparisonReference,
        method: String,
        provenance: String,
    },
    Numerical {
        reference: ComparisonReference,
        metric: String,
        value: f64,
        tolerance: f64,
        method: String,
        provenance: String,
    },
    Approximate {
        method: String,
        provenance: String,
    },
}

fn nonempty(value: &str, field: &str) -> Result<()> {
    ensure!(
        !value.trim().is_empty() && !value.contains('\0'),
        "{field} must be nonempty and contain no NUL"
    );
    Ok(())
}

fn hash(value: &str, field: &str) -> Result<()> {
    ensure!(
        value.len() == 64 && value.bytes().all(|b| b.is_ascii_hexdigit()),
        "{field} must be a 64-character SHA-256 hex digest"
    );
    Ok(())
}

fn nonnegative(value: f64, field: &str) -> Result<()> {
    ensure!(
        value.is_finite() && value >= 0.0,
        "{field} must be finite and nonnegative"
    );
    Ok(())
}

fn ratio(value: f64, field: &str) -> Result<()> {
    ensure!(
        value.is_finite() && (0.0..=1.0).contains(&value),
        "{field} must be finite and between 0 and 1"
    );
    Ok(())
}

fn observation<T>(
    value: &Observation<T>,
    field: &str,
    check: impl FnOnce(&T) -> Result<()>,
) -> Result<()> {
    match value {
        Observation::Available { value } => check(value).with_context(|| field.to_owned()),
        Observation::Unavailable { reason } => nonempty(reason, &format!("{field}.reason")),
    }
}

/// Portable relative references: no traversal, platform prefixes, aliases, or reserved names.
pub fn validate_artifact_path(path: &str) -> Result<()> {
    ensure!(!path.is_empty(), "artifact path must not be empty");
    ensure!(
        !path
            .chars()
            .any(|c| c.is_control() || matches!(c, '\\' | ':' | '<' | '>' | '"' | '|' | '?' | '*')),
        "artifact path contains a forbidden platform character: {path:?}"
    );
    for part in path.split('/') {
        ensure!(
            !part.is_empty() && part != "." && part != "..",
            "artifact path must use nonempty relative components without dot or parent traversal: {path:?}"
        );
        ensure!(
            !part.ends_with('.') && !part.ends_with(' '),
            "artifact path component cannot end with a dot or space: {path:?}"
        );
        let base = part.split('.').next().unwrap_or("").to_ascii_uppercase();
        let numbered_device = base
            .strip_prefix("COM")
            .or_else(|| base.strip_prefix("LPT"))
            .is_some_and(|suffix| {
                matches!(
                    suffix,
                    "1" | "2" | "3" | "4" | "5" | "6" | "7" | "8" | "9" | "¹" | "²" | "³"
                )
            });
        ensure!(
            !matches!(
                base.as_str(),
                "CON" | "PRN" | "AUX" | "NUL" | "CONIN$" | "CONOUT$"
            ) && !numbered_device,
            "artifact path contains a reserved device name: {path:?}"
        );
    }
    let first = path.split('/').next().unwrap_or("").to_ascii_lowercase();
    ensure!(
        !matches!(
            first.as_str(),
            "requested.json" | "manifest.json" | "result.json" | "stdout.log" | "stderr.log"
        ),
        "artifact path conflicts with a capture-owned file: {path:?}"
    );
    Ok(())
}

impl Resolution {
    fn validate(&self) -> Result<()> {
        ensure!(
            self.width > 0 && self.height > 0,
            "resolution width and height must be positive"
        );
        Ok(())
    }
}

impl ReferenceInput {
    fn validate(&self) -> Result<()> {
        validate_artifact_path(&self.path).context("reference input path")?;
        hash(&self.sha256, "reference input sha256")?;
        ensure!(self.bytes > 0, "reference input bytes must be positive");
        if let Some(strength) = self.strength {
            ratio(strength, "reference input strength")?;
        }
        Ok(())
    }
}

impl Workload {
    pub fn validate(&self) -> Result<()> {
        ensure!(
            self.schema_version == SCHEMA_VERSION,
            "unsupported workload schema_version {}; expected {SCHEMA_VERSION}",
            self.schema_version
        );
        nonempty(&self.id, "workload id")?;
        nonempty(&self.model.name, "model name")?;
        if let Some(revision) = &self.model.revision {
            nonempty(revision, "model revision")?;
        }
        if let Some(digest) = &self.model.sha256 {
            hash(digest, "model sha256")?;
        }
        let generation = match &self.settings {
            MediaSettings::Image { generation } => {
                ensure!(
                    generation.references.iter().all(|input| matches!(
                        input.role,
                        ReferenceRole::Reference | ReferenceRole::Mask
                    )),
                    "image references cannot use video-frame or audio roles"
                );
                generation
            }
            MediaSettings::Video {
                generation,
                frames,
                layers,
                playback_fps,
                render_resolution,
                reuse,
                audio,
            } => {
                ensure!(*frames > 0, "video frames must be positive");
                ensure!(*layers > 0, "video layers must be positive");
                ensure!(
                    playback_fps.is_finite() && *playback_fps > 0.0,
                    "video playback_fps must be finite and positive"
                );
                if let Some(resolution) = render_resolution {
                    resolution.validate().context("render_resolution")?;
                }
                ensure!(
                    generation
                        .references
                        .iter()
                        .all(|input| input.role != ReferenceRole::Audio),
                    "audio reference must be declared in video audio configuration"
                );
                for role in [ReferenceRole::FirstFrame, ReferenceRole::LastFrame] {
                    ensure!(
                        generation
                            .references
                            .iter()
                            .filter(|input| input.role == role)
                            .count()
                            <= 1,
                        "video cannot have multiple {role:?} inputs"
                    );
                }
                if let ReusePolicy::Approximate {
                    method,
                    ratio: reuse_ratio,
                    core_ratio,
                    layers,
                } = reuse
                {
                    nonempty(method, "reuse method")?;
                    ratio(*reuse_ratio, "reuse ratio")?;
                    ratio(*core_ratio, "core reuse ratio")?;
                    let mut unique = HashSet::new();
                    ensure!(
                        layers.iter().all(|layer| unique.insert(layer)),
                        "reuse layers must be unique"
                    );
                }
                if let ReusePolicy::Interval { every, core_every } = reuse {
                    ensure!(
                        *every > 0 && *core_every > 0,
                        "reuse every and core_every intervals must be positive"
                    );
                }
                match audio {
                    AudioConfiguration::Disabled => {}
                    AudioConfiguration::Generate {
                        sample_rate_hz,
                        channels,
                    } => {
                        ensure!(
                            *sample_rate_hz > 0 && *channels > 0,
                            "audio sample_rate_hz and channels must be positive"
                        );
                    }
                    AudioConfiguration::Reference { input } => {
                        ensure!(
                            input.role == ReferenceRole::Audio,
                            "audio reference must have audio role"
                        );
                        input.validate()?;
                    }
                }
                generation
            }
        };
        generation.resolution.validate()?;
        ensure!(
            generation.steps > 0 && generation.batch_size > 0,
            "steps and batch_size must be positive"
        );
        ensure!(
            generation.compute_precision != Some(Precision::Auto),
            "compute_precision must be concrete or null for runtime selection"
        );
        nonempty(&generation.scheduler, "scheduler")?;
        // Empty prompts are legitimate unconditional generation requests.
        ensure!(
            !generation.prompt.contains('\0')
                && !generation
                    .negative_prompt
                    .as_ref()
                    .is_some_and(|p| p.contains('\0')),
            "prompts must not contain NUL"
        );
        nonnegative(generation.guidance, "guidance")?;
        if let Quantization::Weights { bits, method } = &generation.quantization {
            ensure!(
                *bits > 0 && *bits <= 32,
                "weight quantization bits must be between 1 and 32"
            );
            nonempty(method, "quantization method")?;
        }
        for input in &generation.references {
            input.validate()?;
        }
        if let Some(strength) = generation.strength {
            ratio(strength, "generation strength")?;
        }
        if let Some(value) = generation.optimizations.step_cache_ratio {
            ratio(value, "step_cache_ratio")?;
        }
        if let Some(value) = generation.optimizations.step_cache_threshold {
            nonnegative(value, "step_cache_threshold")?;
        }
        Ok(())
    }

    pub fn identity(&self) -> Result<String> {
        self.validate()?;
        let bytes = serde_json::to_vec(self).context("serializing workload identity")?;
        Ok(format!("{:x}", Sha256::digest(bytes)))
    }
}

impl FileIdentity {
    fn validate(&self) -> Result<()> {
        nonempty(&self.path, "observed file path")?;
        observation(&self.sha256, "observed file sha256", |digest| {
            hash(digest, "sha256")
        })
    }
}

impl RuntimeIdentity {
    fn validate(&self) -> Result<()> {
        nonempty(&self.name, "runtime name")?;
        observation(&self.version, "runtime version", |v| nonempty(v, "version"))?;
        observation(&self.source, "runtime source", |source| {
            nonempty(&source.repository, "source repository")?;
            nonempty(&source.revision, "source revision")?;
            observation(&source.dirty, "source dirty", |_| Ok(()))
        })?;
        observation(
            &self.executable,
            "runtime executable",
            FileIdentity::validate,
        )?;
        for module in &self.modules {
            module.validate()?;
        }
        observation(&self.model, "observed model", |model| {
            nonempty(&model.name, "observed model name")?;
            observation(&model.revision, "observed model revision", |v| {
                nonempty(v, "revision")
            })?;
            for file in &model.files {
                file.validate()?;
            }
            Ok(())
        })?;
        observation(&self.device, "runtime device", |v| nonempty(v, "device"))?;
        observation(&self.cache_state, "runtime cache state", |v| {
            nonempty(v, "cache state")
        })
    }
}

impl AdapterResult {
    pub fn validate(&self, requested: &Workload) -> Result<()> {
        requested.validate().context("requested workload")?;
        ensure!(
            self.schema_version == SCHEMA_VERSION,
            "unsupported adapter result schema_version {}; expected {SCHEMA_VERSION}",
            self.schema_version
        );
        self.resolved.validate().context("resolved workload")?;
        hash(&self.workload_identity, "workload_identity")?;
        ensure!(
            self.workload_identity == requested.identity()?,
            "workload_identity does not match requested workload"
        );
        ensure!(
            self.resolved.matches_request(requested),
            "resolved workload differs from requested workload; only automatic precision choices may resolve to concrete values"
        );
        self.runtime.validate()?;
        if let Observation::Available { value: model } = &self.runtime.model {
            ensure!(
                model.name == requested.model.name,
                "observed model name differs from declared model name"
            );
            if let (Some(expected), Observation::Available { value: observed }) =
                (&requested.model.revision, &model.revision)
            {
                ensure!(
                    expected == observed,
                    "observed model revision differs from declared model revision"
                );
            }
            if let Some(expected) = &requested.model.sha256 {
                let mut available = model
                    .files
                    .iter()
                    .filter_map(|file| match &file.sha256 {
                        Observation::Available { value } => Some(value),
                        Observation::Unavailable { .. } => None,
                    })
                    .peekable();
                if available.peek().is_some() {
                    ensure!(
                        available.any(|digest| digest.eq_ignore_ascii_case(expected)),
                        "observed model file hashes do not include declared model sha256"
                    );
                }
            }
        }
        ensure!(
            !self.timings.is_empty(),
            "adapter result must report timing measurements or explicit unavailability"
        );
        for timing in &self.timings {
            nonempty(&timing.phase, "timing phase")?;
            nonempty(&timing.method, "timing method")?;
            nonempty(&timing.boundary, "timing boundary")?;
            observation(&timing.measurement, "timing measurement", |v| {
                nonnegative(*v, "timing value")
            })?;
        }
        ensure!(
            !self.resources.is_empty(),
            "adapter result must report resource measurements or explicit unavailability"
        );
        for resource in &self.resources {
            nonempty(&resource.method, "resource method")?;
            nonempty(&resource.boundary, "resource boundary")?;
            let (scope, unit) = match resource.kind {
                ResourceKind::ProcessRss => (ResourceScope::Process, ResourceUnit::Bytes),
                ResourceKind::TensorBytes => (ResourceScope::Runtime, ResourceUnit::Bytes),
                ResourceKind::DriverAllocation => (ResourceScope::Device, ResourceUnit::Bytes),
                ResourceKind::SystemPressure => (ResourceScope::System, ResourceUnit::Ratio),
                ResourceKind::Swap => (ResourceScope::System, ResourceUnit::Bytes),
            };
            ensure!(
                resource.scope == scope && resource.unit == unit,
                "resource {:?} requires scope {scope:?} and unit {unit:?}",
                resource.kind
            );
            observation(&resource.measurement, "resource measurement", |value| {
                if unit == ResourceUnit::Ratio {
                    ratio(*value, "resource ratio")
                } else {
                    nonnegative(*value, "resource bytes")?;
                    ensure!(value.fract() == 0.0, "resource byte count must be integral");
                    Ok(())
                }
            })?;
        }
        ensure!(
            !self.artifacts.is_empty(),
            "successful adapter result must contain at least one artifact"
        );
        let mut paths = HashSet::new();
        for artifact in &self.artifacts {
            validate_artifact_path(&artifact.path)?;
            hash(&artifact.sha256, "artifact sha256")?;
            nonempty(&artifact.role, "artifact role")?;
            ensure!(
                paths.insert(artifact.path.to_lowercase()),
                "duplicate artifact path (including case-insensitive aliases): {}",
                artifact.path
            );
        }
        for artifact in &self.artifacts {
            let lower = artifact.path.to_lowercase();
            for (index, _) in lower.match_indices('/') {
                ensure!(
                    !paths.contains(&lower[..index]),
                    "artifact path conflicts with another artifact used as its directory: {}",
                    artifact.path
                );
            }
        }
        match &self.output_evidence {
            OutputEvidence::Unassessed { reason } => nonempty(reason, "unassessed reason")?,
            OutputEvidence::Exact {
                reference,
                method,
                provenance,
            } => {
                reference.validate()?;
                nonempty(method, "exact comparison method")?;
                nonempty(provenance, "exact comparison provenance")?;
                ensure!(
                    self.artifacts
                        .iter()
                        .any(|artifact| artifact.sha256.eq_ignore_ascii_case(&reference.sha256)),
                    "exact evidence reference sha256 must match an output artifact"
                );
            }
            OutputEvidence::Numerical {
                reference,
                metric,
                value,
                tolerance,
                method,
                provenance,
            } => {
                reference.validate()?;
                nonempty(metric, "numerical metric")?;
                ensure!(
                    value.is_finite(),
                    "numerical comparison value must be finite"
                );
                nonnegative(*tolerance, "numerical tolerance")?;
                nonempty(method, "numerical comparison method")?;
                nonempty(provenance, "numerical comparison provenance")?;
            }
            OutputEvidence::Approximate { method, provenance } => {
                nonempty(method, "approximate method")?;
                nonempty(provenance, "approximate provenance")?;
            }
        }
        Ok(())
    }
}

impl ComparisonReference {
    fn validate(&self) -> Result<()> {
        hash(&self.sha256, "comparison reference sha256")?;
        nonempty(&self.provenance, "comparison reference provenance")
    }
}

impl Workload {
    fn matches_request(&self, requested: &Self) -> bool {
        self.schema_version == requested.schema_version
            && self.id == requested.id
            && self.model == requested.model
            && self.process_policy == requested.process_policy
            && self.cache_policy == requested.cache_policy
            && self.settings.matches_request(&requested.settings)
    }
}

impl MediaSettings {
    fn matches_request(&self, requested: &Self) -> bool {
        match (self, requested) {
            (
                Self::Image { generation },
                Self::Image {
                    generation: expected,
                },
            ) => generation.matches_request(expected),
            (
                Self::Video {
                    generation,
                    frames,
                    layers,
                    playback_fps,
                    render_resolution,
                    reuse,
                    audio,
                },
                Self::Video {
                    generation: expected,
                    frames: expected_frames,
                    layers: expected_layers,
                    playback_fps: expected_fps,
                    render_resolution: expected_resolution,
                    reuse: expected_reuse,
                    audio: expected_audio,
                },
            ) => {
                generation.matches_request(expected)
                    && frames == expected_frames
                    && layers == expected_layers
                    && playback_fps.to_bits() == expected_fps.to_bits()
                    && render_resolution == expected_resolution
                    && reuse == expected_reuse
                    && audio == expected_audio
            }
            _ => false,
        }
    }
}

impl GenerationSettings {
    fn matches_request(&self, requested: &Self) -> bool {
        // Exhaustive destructuring makes new settings require a compatibility decision.
        let Self {
            prompt,
            negative_prompt,
            seed,
            resolution,
            steps,
            scheduler,
            guidance,
            precision,
            compute_precision,
            quantization,
            batch_size,
            references,
            strength,
            optimizations,
        } = self;
        *precision != Precision::Auto
            && (requested.precision == Precision::Auto || *precision == requested.precision)
            && matches!(compute_precision, Some(value) if *value != Precision::Auto)
            && (requested.compute_precision.is_none()
                || *compute_precision == requested.compute_precision)
            && prompt == &requested.prompt
            && negative_prompt == &requested.negative_prompt
            && *seed == requested.seed
            && resolution == &requested.resolution
            && *steps == requested.steps
            && scheduler == &requested.scheduler
            && guidance.to_bits() == requested.guidance.to_bits()
            && quantization == &requested.quantization
            && *batch_size == requested.batch_size
            && references == &requested.references
            && strength.map(f64::to_bits) == requested.strength.map(f64::to_bits)
            && optimizations.use_kv_cache == requested.optimizations.use_kv_cache
            && optimizations.step_cache_ratio.map(f64::to_bits)
                == requested.optimizations.step_cache_ratio.map(f64::to_bits)
            && optimizations.step_cache_threshold.map(f64::to_bits)
                == requested
                    .optimizations
                    .step_cache_threshold
                    .map(f64::to_bits)
    }
}
