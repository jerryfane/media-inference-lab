//! CPU-only validation of unchanged produced PNG rasters; never an inference run.
use crate::{
    png_image::{self, PngIdentity, SampleColor},
    schema::{Artifact, GenerationSettings, MediaSettings, Observation, Workload},
};
use anyhow::{Context, Result, ensure};
use serde::Serialize;
use sha2::{Digest, Sha256};
use std::{
    collections::HashSet,
    fs::{self, File, OpenOptions},
    io::Write,
    os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt},
    path::{Path, PathBuf},
    time::{Duration, Instant},
};

pub const MAX_BATCH: usize = 64;
pub const MAX_BATCH_ENCODED_BYTES: u64 = 256 * 1024 * 1024;
pub const MAX_BATCH_DECODED_BYTES: u64 = 512 * 1024 * 1024;
pub const MAX_TIMEOUT: Duration = Duration::from_secs(120);

pub struct ImageInspectionOptions {
    pub workload: Workload,
    pub inputs: Vec<PathBuf>,
    pub output_dir: PathBuf,
    pub timeout: Duration,
}

#[derive(Serialize)]
struct InputOutcome {
    input: PathBuf,
    ok: bool,
    original: Option<Artifact>,
    decoded: Option<PngIdentity>,
    stored_sample_dtype: Option<String>,
    error: Option<String>,
}

fn private_file(path: &Path) -> Result<File> {
    Ok(OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)?)
}

/// Shared by offline inspection and capture acceptance. Model/compute precision
/// is deliberately not compared with the PNG unsigned-integer sample dtype.
pub(crate) fn validate_raster(
    identity: &PngIdentity,
    generation: &GenerationSettings,
    layout: &mut Option<(SampleColor, u8)>,
) -> Result<()> {
    ensure!(
        identity.width == generation.resolution.width
            && identity.height == generation.resolution.height,
        "decoded image dimensions {}x{} differ from requested {}x{}",
        identity.width,
        identity.height,
        generation.resolution.width,
        generation.resolution.height
    );
    let actual = (identity.color, identity.bit_depth);
    if let Some(expected) = *layout {
        ensure!(
            actual == expected,
            "inconsistent stored-raster color/sample dtype within image batch"
        );
    } else {
        *layout = Some(actual);
    }
    Ok(())
}

/// Creates a new private directory, retains original snapshots even for corrupt
/// supported-size inputs, and writes report.json. Invalid media returns false;
/// unsafe/unbounded options or inability to persist evidence return an error.
pub fn inspect(options: ImageInspectionOptions) -> Result<bool> {
    options.workload.validate()?;
    ensure!(
        options.inputs.len() <= MAX_BATCH,
        "input list exceeds {MAX_BATCH}-image inspection limit"
    );
    ensure!(
        !options.timeout.is_zero() && options.timeout <= MAX_TIMEOUT,
        "inspection timeout must be positive and at most 120 seconds"
    );
    ensure!(
        serde_json::to_vec(&options.workload)?.len() <= 1024 * 1024,
        "workload exceeds 1 MiB report limit"
    );
    ensure!(
        options
            .inputs
            .iter()
            .all(|path| path.as_os_str().len() <= 4096),
        "input path exceeds report limit"
    );
    let workload_identity = options.workload.identity()?;
    let generation = match &options.workload.settings {
        MediaSettings::Image { generation } => Some(generation),
        MediaSettings::Video { .. } => None,
    };
    let mut errors = Vec::new();
    if let Some(generation) = generation {
        if generation.batch_size as usize != options.inputs.len() {
            errors.push(format!(
                "image batch count mismatch: requested {}, supplied {}",
                generation.batch_size,
                options.inputs.len()
            ));
        }
        if generation.batch_size as usize > MAX_BATCH {
            errors.push(format!(
                "requested batch exceeds {MAX_BATCH}-image inspection limit"
            ));
        }
    } else {
        errors.push("inspect-images requires image modality".into());
    }
    // create_dir, not create_dir_all: never reuse/overwrite an evidence directory.
    fs::DirBuilder::new()
        .mode(0o700)
        .create(&options.output_dir)
        .with_context(|| {
            format!(
                "creating new inspection directory {}",
                options.output_dir.display()
            )
        })?;
    let deadline = Instant::now() + options.timeout;
    let mut checkpoint = || -> Result<()> {
        ensure!(
            Instant::now() < deadline,
            "image inspection deadline exceeded"
        );
        Ok(())
    };
    let mut physical = HashSet::new();
    let mut encoded_total = 0u64;
    let mut decoded_total = 0u64;
    let mut layout = None;
    let mut outcomes = Vec::with_capacity(options.inputs.len());
    for (index, input) in options.inputs.iter().enumerate() {
        let mut outcome = InputOutcome {
            input: input.clone(),
            ok: false,
            original: None,
            decoded: None,
            stored_sample_dtype: None,
            error: None,
        };
        let checked = (|| -> Result<()> {
            checkpoint()?;
            let generation = generation.context("inspect-images requires image modality")?;
            let file = png_image::regular_file(input)?;
            let metadata = file.metadata()?;
            ensure!(
                physical.insert((metadata.dev(), metadata.ino())),
                "duplicate physical image file"
            );
            let remaining = MAX_BATCH_ENCODED_BYTES - encoded_total;
            let encoded = png_image::read_open_file(file, remaining, &mut checkpoint)?;
            encoded_total += encoded.len() as u64;
            let hash = format!("{:x}", Sha256::digest(&encoded));
            let name = format!("original-{index:04}.png");
            let mut snapshot = private_file(&options.output_dir.join(&name))?;
            snapshot.write_all(&encoded)?;
            snapshot.sync_all()?;
            outcome.original = Some(Artifact {
                path: name,
                sha256: hash.clone(),
                bytes: encoded.len() as u64,
                role: "unchanged-input-snapshot-not-transcoded".into(),
            });
            checkpoint()?;
            let image = png_image::decode_encoded(
                input,
                encoded,
                Some(hash),
                (MAX_BATCH_DECODED_BYTES - decoded_total) as usize,
                &mut checkpoint,
            )?;
            decoded_total += image.samples().len() as u64;
            outcome.stored_sample_dtype = Some(format!("uint{}", image.identity().bit_depth));
            outcome.decoded = Some(image.into_identity());
            validate_raster(outcome.decoded.as_ref().unwrap(), generation, &mut layout)?;
            checkpoint()?;
            Ok(())
        })();
        match checked {
            Ok(()) => outcome.ok = true,
            Err(error) => outcome.error = Some(format!("{error:#}")),
        }
        outcomes.push(outcome);
    }
    let ok = errors.is_empty() && outcomes.iter().all(|outcome| outcome.ok);
    let unavailable: Observation<Vec<String>> = Observation::Unavailable {
        reason: "CPU-only output inspection observes no native execution, phases, speed, latent tensors or generation timing.".into(),
    };
    let report = serde_json::json!({
        "schema_version": 1,
        "kind": "image_output_inspection",
        "ok": ok,
        "workload_identity": workload_identity,
        "declared_workload": options.workload,
        "requested_batch_count": generation.map(|value| value.batch_size),
        "supplied_input_count": outcomes.len(),
        "fully_decoded_count": outcomes.iter().filter(|value| value.decoded.is_some()).count(),
        "accepted_image_count": outcomes.iter().filter(|value| value.ok).count(),
        "inputs": outcomes,
        "errors": errors,
        "native_phases": unavailable,
        "limits": {
            "max_batch": MAX_BATCH,
            "max_encoded_bytes_per_input": png_image::MAX_ENCODED_BYTES,
            "max_pixels_per_input": png_image::MAX_PIXELS,
            "max_decoded_bytes_per_input": png_image::MAX_DECODED_BYTES,
            "max_snapshot_bytes_total": MAX_BATCH_ENCODED_BYTES,
            "max_decoded_bytes_total": MAX_BATCH_DECODED_BYTES,
            "timeout_seconds": options.timeout.as_secs_f64(),
            "deadline_policy": "Cooperative checks between bounded reads, PNG validation/inflate blocks and decode stages; one bounded raster decode or filesystem operation can finish after deadline. Report persistence is outside the media deadline.",
            "disk_scope": "Original snapshots capped in aggregate; report metadata additionally bounded by 64 paths (4096 bytes each) and 1 MiB declared workload."
        },
        "limitations": [
            "Only static 8/16-bit grayscale, grayscale-alpha, RGB and RGBA PNG stored rasters are supported; no transcoding, color management or orientation changes.",
            "Declared model/compute precision and seed/settings are not observed native execution evidence. PNG sample dtype is unsigned integer, not BF16.",
            "A successful output inspection is not a successful Qwen/model smoke run or a visual quality assessment."
        ]
    });
    let mut output = private_file(&options.output_dir.join("report.json"))?;
    serde_json::to_writer_pretty(&mut output, &report)?;
    output.write_all(b"\n")?;
    output.sync_all()?;
    Ok(ok)
}
