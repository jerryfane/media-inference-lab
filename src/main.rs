use anyhow::{Context, Result, ensure};
use clap::{Parser, Subcommand};
use media_inference_lab::{
    capture::{self, CaptureOptions},
    capture_archive::CaptureArchive,
    comparison,
    frame_sequence::{self, SequenceAssessment, SequenceInput, SequenceSource},
    guards::{GuardConfig, GuardMonitor, Lease},
    h3::{self, InspectOptions as H3InspectOptions, PrepareOptions as H3PrepareOptions},
    h3_owned,
    image_comparison::{self, ImageAssessment, Tolerance},
    image_inspection::{self, ImageInspectionOptions},
    maintenance,
    native::{self, NativeOptions},
    png_image::{self, DecodedPng},
    png_report,
    preflight::{self, PreflightOptions},
    schema::{AdapterResult, Artifact, Workload},
    sequence_report,
    study::{StudyInput, StudyPlan},
    study_report,
    video_inspection::{self, VideoInspectionOptions},
};
use serde::Serialize;
use serde::de::DeserializeOwned;
use sha2::{Digest, Sha256};
use std::{
    collections::BTreeMap,
    fs::{DirBuilder, File, OpenOptions},
    io::{BufWriter, Read, Write},
    os::unix::fs::{DirBuilderExt, OpenOptionsExt},
    path::{Path, PathBuf},
    process::ExitCode,
    sync::{Arc, atomic::AtomicBool},
    time::Duration,
};

#[derive(Parser)]
#[command(
    name = "mil",
    version,
    about = "Versioned media evidence and CPU subprocess supervision"
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Validate a declared workload and print its exact v1 identity.
    Validate { workload: PathBuf },
    /// Validate adapter evidence against its declared workload (no artifact I/O).
    ValidateResult {
        #[arg(long)]
        workload: PathBuf,
        result: PathBuf,
    },
    /// Inspect saved evidence offline; a non-success outcome returns exit code 1.
    Inspect { run_dir: PathBuf },
    /// Generate a bounded baseline/candidate/unchanged-control study template; never execute it.
    StudyPlan {
        plan: PathBuf,
        #[arg(long)]
        output: PathBuf,
    },
    /// Compare saved captures offline; retain failures and never launch inference.
    Compare {
        study: PathBuf,
        #[arg(long)]
        output: PathBuf,
        #[arg(long, default_value_t = 60, value_parser = clap::value_parser!(u64).range(1..=120))]
        inspection_seconds: u64,
    },
    /// Compare saved captures and retain a private readable/JSON metadata bundle; never execute.
    StudyReport {
        study: PathBuf,
        #[arg(long)]
        output_dir: PathBuf,
        #[arg(long, default_value_t = 60, value_parser = clap::value_parser!(u64).range(1..=120))]
        inspection_seconds: u64,
    },
    /// Compare full static PNG samples offline; never infer visual quality or execute inference.
    CompareImages {
        #[arg(long)]
        baseline: PathBuf,
        #[arg(long)]
        candidate: PathBuf,
        #[arg(long)]
        baseline_repeat: Option<PathBuf>,
        #[arg(long)]
        output_dir: PathBuf,
        #[arg(long, requires = "tolerance_rationale")]
        max_absolute_error: Option<u16>,
        #[arg(long, requires = "max_absolute_error")]
        tolerance_rationale: Option<String>,
        #[arg(long)]
        assessment: Option<PathBuf>,
    },
    /// Compare every declared PNG frame offline with exact timeline alignment; no codec or inference.
    CompareFrames {
        #[arg(long)]
        baseline: PathBuf,
        #[arg(long)]
        candidate: PathBuf,
        #[arg(long)]
        baseline_repeat: Option<PathBuf>,
        #[arg(long)]
        output_dir: PathBuf,
        #[arg(long, requires = "tolerance_rationale")]
        max_absolute_error: Option<u16>,
        #[arg(long, requires = "max_absolute_error")]
        tolerance_rationale: Option<String>,
        #[arg(long)]
        assessment: Option<PathBuf>,
    },
    /// Validate every requested PNG image offline, including batch count and stored sample type.
    InspectImages {
        #[arg(long)]
        workload: PathBuf,
        #[arg(long = "image", required = true)]
        images: Vec<PathBuf>,
        #[arg(long)]
        output_dir: PathBuf,
        #[arg(long, default_value_t = 60, value_parser = clap::value_parser!(u64).range(1..=120))]
        inspection_seconds: u64,
    },
    /// Prepare explicit H3 profile arguments and file identities; never import or launch H3.
    H3Prepare {
        #[arg(long)]
        workload: PathBuf,
        #[arg(long, value_parser = ["draft", "standard", "detailed"])]
        profile: String,
        #[arg(long)]
        binary: PathBuf,
        #[arg(long)]
        model_dir: PathBuf,
        #[arg(long)]
        shader_cwd: PathBuf,
        /// Selected source snapshot; not proof that the binary was compiled from it.
        #[arg(long)]
        source_dir: PathBuf,
        #[arg(long)]
        ffmpeg: PathBuf,
        #[arg(long)]
        ffprobe: PathBuf,
        #[arg(long)]
        output_dir: PathBuf,
    },
    /// Inspect supplied H3 logs/media offline; reported exit is not owned-execution attestation.
    H3InspectResult {
        #[arg(long)]
        plan: PathBuf,
        #[arg(long)]
        stdout: PathBuf,
        #[arg(long)]
        stderr: PathBuf,
        #[arg(long, allow_hyphen_values = true)]
        exit_code: i32,
        #[arg(long)]
        video: PathBuf,
        #[arg(long)]
        output_dir: PathBuf,
        #[arg(long, default_value_t = 60, value_parser = clap::value_parser!(u64).range(1..=120))]
        inspection_seconds: u64,
    },
    /// Fully decode a local H3-compatible MP4 offline; no inference or GPU authorization.
    InspectVideo {
        #[arg(long)]
        workload: PathBuf,
        #[arg(long)]
        video: PathBuf,
        /// Explicit existing FFmpeg executable; software decoding only.
        #[arg(long)]
        ffmpeg: PathBuf,
        /// Explicit existing FFprobe executable; no PATH lookup or installation.
        #[arg(long)]
        ffprobe: PathBuf,
        #[arg(long)]
        output_dir: PathBuf,
        #[arg(long, default_value_t = 60, value_parser = clap::value_parser!(u64).range(1..=120))]
        inspection_seconds: u64,
    },
    /// Qualify guardian-owned H3 codec IPC using finite CPU fixtures, never native inference.
    H3QualifyOwned {
        #[arg(long)]
        output_dir: PathBuf,
        #[arg(long, default_value = "success")]
        scenario: String,
    },
    #[command(hide = true)]
    H3CpuFixture {
        #[arg(long)]
        scenario: String,
        #[arg(long)]
        output_dir: PathBuf,
    },
    #[command(hide = true)]
    H3CpuCodec {
        #[arg(last = true)]
        args: Vec<String>,
    },
    /// Supervise a trusted CPU-only process without platform guards.
    Supervise(ProcessArguments),
    /// Check lease/memory/swap/disk observations; never grants service exclusion or GPU access.
    GuardCheck {
        #[arg(long)]
        config: PathBuf,
        #[arg(long)]
        output: PathBuf,
    },
    /// Supervise a CPU-only process while continuously applying platform guards.
    SuperviseGuarded {
        #[arg(long)]
        guard_config: PathBuf,
        #[command(flatten)]
        process: ProcessArguments,
    },
    /// Inspect a selected Python/runtime/local model without importing MLX or loading weights.
    MfluxPreflight {
        #[arg(long)]
        python: PathBuf,
        #[arg(long)]
        model_dir: PathBuf,
        #[arg(long)]
        workload: PathBuf,
        #[arg(long)]
        output: PathBuf,
        #[arg(long, default_value_t = 60, value_parser = clap::value_parser!(u64).range(1..=120))]
        timeout_seconds: u64,
    },
    /// Prepare or execute an exactly authorized guardian-owned native transaction.
    MfluxRun {
        #[arg(long)]
        python: PathBuf,
        #[arg(long)]
        source_dir: PathBuf,
        #[arg(long)]
        model_dir: PathBuf,
        #[arg(long)]
        source_sha256: String,
        #[arg(long)]
        workload: PathBuf,
        #[arg(long, default_value = "runs")]
        root: PathBuf,
        /// New private preparation/attempt report; never a native-success claim by itself.
        #[arg(long)]
        output: PathBuf,
        #[arg(long, default_value_t = 600, value_parser = clap::value_parser!(u64).range(1..=600))]
        timeout_seconds: u64,
        #[arg(long, default_value_t = 60, value_parser = clap::value_parser!(u64).range(1..=120))]
        check_timeout_seconds: u64,
        #[arg(long, default_value_t = 64 * 1024 * 1024, value_parser = clap::value_parser!(u64).range(1..=1_073_741_824))]
        max_output_bytes: u64,
        #[arg(long)]
        guard_config: Option<PathBuf>,
        #[arg(long)]
        maintenance_transaction: Option<PathBuf>,
        #[arg(long)]
        authorization: Option<PathBuf>,
        #[arg(long, conflicts_with = "execute", required_unless_present = "execute")]
        check_only: bool,
        #[arg(
            long,
            conflicts_with = "check_only",
            required_unless_present = "check_only"
        )]
        execute: bool,
    },
    /// Run genuine finite CPU services/work under one guardian using a private-root lease.
    MaintenanceCpu {
        #[arg(long)]
        root: PathBuf,
        #[arg(long, default_value = "normal")]
        scenario: String,
    },
    /// Execute an exact reviewed maintenance transaction; no-grant/live gates deny before effects.
    MaintenanceRun {
        #[arg(long)]
        transaction: PathBuf,
        #[arg(long)]
        authorization: PathBuf,
    },
    #[command(hide = true)]
    MaintenanceGuardian {
        #[arg(long)]
        control_fd: i32,
    },
    #[command(hide = true)]
    MaintenanceParticipant {
        #[arg(long)]
        mode: String,
        #[arg(long)]
        duration_ms: u64,
    },
}

#[derive(clap::Args)]
struct ProcessArguments {
    #[arg(long)]
    workload: PathBuf,
    #[arg(long, default_value = "runs")]
    root: PathBuf,
    /// Explicit executable path; the child runs in its isolated run directory.
    #[arg(long)]
    executable: PathBuf,
    /// Acknowledge no GPU/model work; a successful guard check is not authorization.
    #[arg(long, required = true)]
    cpu_only: bool,
    #[arg(long, default_value_t = 60, value_parser = clap::value_parser!(u64).range(1..=86400))]
    timeout_seconds: u64,
    #[arg(long, default_value_t = 16_777_216, value_parser = clap::value_parser!(u64).range(1..))]
    max_output_bytes: u64,
    /// Explicit child environment KEY=VALUE. No parent environment is inherited.
    #[arg(long = "env", value_parser = parse_env)]
    environment: Vec<(String, String)>,
    /// Literal child arguments after -- (never interpolated by mil).
    #[arg(last = true)]
    args: Vec<String>,
}

fn parse_env(value: &str) -> std::result::Result<(String, String), String> {
    let (key, value) = value.split_once('=').ok_or("expected KEY=VALUE")?;
    if key.is_empty() || key.contains('\0') || value.contains('\0') || key.starts_with("MIL_") {
        return Err("invalid or reserved environment key/value".into());
    }
    Ok((key.into(), value.into()))
}

fn load<T: DeserializeOwned>(path: &Path) -> Result<T> {
    const LIMIT: u64 = 16 * 1024 * 1024;
    let file = File::open(path).with_context(|| format!("opening {}", path.display()))?;
    let mut bytes = Vec::new();
    file.take(LIMIT + 1).read_to_end(&mut bytes)?;
    ensure!(bytes.len() as u64 <= LIMIT, "JSON document exceeds 16 MiB");
    serde_json::from_slice(&bytes).with_context(|| format!("reading JSON {}", path.display()))
}

fn load_regular_json<T: DeserializeOwned>(path: &Path, limit: u64) -> Result<T> {
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NONBLOCK | libc::O_NOFOLLOW)
        .open(path)
        .with_context(|| format!("opening JSON {}", path.display()))?;
    ensure!(
        file.metadata()?.is_file(),
        "JSON input must be a regular file"
    );
    let mut bytes = Vec::new();
    file.take(limit + 1).read_to_end(&mut bytes)?;
    ensure!(
        bytes.len() as u64 <= limit,
        "JSON input exceeds {limit} bytes"
    );
    serde_json::from_slice(&bytes).with_context(|| format!("reading JSON {}", path.display()))
}

struct BoundedReport {
    file: BufWriter<File>,
    remaining: usize,
}

impl Write for BoundedReport {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        if bytes.len() > self.remaining {
            return Err(std::io::Error::other(
                "JSON output exceeds configured byte bound",
            ));
        }
        let written = self.file.write(bytes)?;
        self.remaining -= written;
        Ok(written)
    }

    fn flush(&mut self) -> std::io::Result<()> {
        self.file.flush()
    }
}

fn write_json_report(output: &Path, value: &impl Serialize) -> Result<()> {
    let file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(output)
        .with_context(|| format!("creating non-overwriting JSON output {}", output.display()))?;
    let mut writer = BoundedReport {
        file: BufWriter::new(file),
        remaining: 16 * 1024 * 1024,
    };
    serde_json::to_writer_pretty(&mut writer, value)?;
    writer.write_all(b"\n")?;
    writer.flush()?;
    writer.file.get_ref().sync_all()?;
    Ok(())
}

fn write_study_bundle(
    input: &StudyInput,
    source_directory: &Path,
    output_dir: &Path,
    inspection_budget: Duration,
) -> Result<bool> {
    let mut archive = CaptureArchive::new(output_dir.to_path_buf());
    // Comparison validates input/budget before preparing any output directory.
    let comparison = comparison::compare(
        input,
        source_directory,
        inspection_budget,
        Some(&mut archive),
    )?;
    let complete = comparison.is_complete();
    let mut markdown = ArtifactWriter {
        file: BufWriter::new(new_private_file(&output_dir.join("report.md"))?),
        hash: Sha256::new(),
        bytes: 0,
        limit: 64 * 1024 * 1024,
    };
    study_report::write(&mut markdown, input, &comparison, &archive)?;
    markdown.flush()?;
    markdown.file.get_ref().sync_all()?;
    let readable = Artifact {
        path: "report.md".into(),
        sha256: format!("{:x}", markdown.hash.finalize()),
        bytes: markdown.bytes,
        role: "readable_study_report".into(),
    };
    #[derive(Serialize)]
    struct Bundle<'a> {
        schema_version: u32,
        kind: &'static str,
        input: &'a StudyInput,
        source_directory: &'a Path,
        comparison: comparison::ComparisonReport,
        capture_snapshots: &'a [Option<Artifact>],
        readable: Artifact,
        payload_scope: &'static str,
    }
    let bundle = Bundle {
        schema_version: 1,
        kind: "offline_study_comparison_bundle",
        input,
        source_directory,
        comparison,
        capture_snapshots: archive.snapshots(),
        readable,
        payload_scope: "Full typed capture metadata snapshots only. Original media/log/guard payloads are not copied; their recorded paths, hashes and original capture locations are provenance, not bundled links. This is not a replayable capture tree or execution authorization.",
    };
    let report_path = output_dir.join("report.json");
    let mut json = BoundedReport {
        file: BufWriter::new(new_private_file(&report_path)?),
        remaining: 32 * 1024 * 1024,
    };
    serde_json::to_writer_pretty(&mut json, &bundle)?;
    json.write_all(b"\n")?;
    json.flush()?;
    json.file.get_ref().sync_all()?;
    File::open(output_dir)?.sync_all()?;
    println!("{}", report_path.display());
    Ok(complete)
}

struct ArtifactWriter {
    file: BufWriter<File>,
    hash: Sha256,
    bytes: u64,
    limit: u64,
}

impl Write for ArtifactWriter {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        if bytes.len() as u64 > self.limit - self.bytes {
            return Err(std::io::Error::other(format!(
                "artifact exceeds {} bytes",
                self.limit
            )));
        }
        let written = self.file.write(bytes)?;
        self.hash.update(&bytes[..written]);
        self.bytes += written as u64;
        Ok(written)
    }

    fn flush(&mut self) -> std::io::Result<()> {
        self.file.flush()
    }
}

fn new_private_file(path: &Path) -> Result<File> {
    OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)
        .with_context(|| format!("creating non-overwriting artifact {}", path.display()))
}

fn copy_png(directory: &Path, name: &str, role: &str, image: &DecodedPng) -> Result<Artifact> {
    let mut file = new_private_file(&directory.join(name))?;
    // Copy the exact snapshot hashed and decoded, not a later reread of the source path.
    file.write_all(image.encoded())?;
    file.sync_all()?;
    Ok(Artifact {
        path: name.into(),
        sha256: image.identity().sha256.clone(),
        bytes: image.identity().bytes,
        role: role.into(),
    })
}

fn compare_images(
    baseline: &Path,
    candidate: &Path,
    baseline_repeat: Option<&Path>,
    output_dir: &Path,
    tolerance: Option<Tolerance>,
    assessment: Option<ImageAssessment>,
) -> Result<bool> {
    let baseline = png_image::decode(baseline)?;
    let candidate = png_image::decode(candidate)?;
    let baseline_repeat = baseline_repeat.map(png_image::decode).transpose()?;
    let comparison = image_comparison::compare(
        &baseline,
        &candidate,
        baseline_repeat.as_ref(),
        tolerance,
        assessment,
    )?;
    let within_bound = comparison.is_within_numerical_bound();

    // Validate all inputs before creating a bundle. An I/O failure leaves a partial
    // private directory, never a complete-looking report or an overwritten artifact.
    DirBuilder::new()
        .mode(0o700)
        .create(output_dir)
        .with_context(|| format!("creating new PNG bundle {}", output_dir.display()))?;
    let mut artifacts = vec![
        copy_png(output_dir, "baseline.png", "baseline_image", &baseline)?,
        copy_png(output_dir, "candidate.png", "candidate_image", &candidate)?,
    ];
    if let Some(repeat) = &baseline_repeat {
        artifacts.push(copy_png(
            output_dir,
            "baseline-repeat.png",
            "baseline_repeat_image",
            repeat,
        )?);
    }
    let mut sheet = ArtifactWriter {
        file: BufWriter::new(new_private_file(&output_dir.join("sheet.png"))?),
        hash: Sha256::new(),
        bytes: 0,
        limit: 270 * 1024 * 1024,
    };
    png_image::write_sheet(&baseline, &candidate, &mut sheet)?;
    sheet.flush()?;
    sheet.file.get_ref().sync_all()?;
    artifacts.push(Artifact {
        path: "sheet.png".into(),
        sha256: format!("{:x}", sheet.hash.finalize()),
        bytes: sheet.bytes,
        role: "raw_sample_ab_sheet".into(),
    });

    let mut markdown = ArtifactWriter {
        file: BufWriter::new(new_private_file(&output_dir.join("report.md"))?),
        hash: Sha256::new(),
        bytes: 0,
        limit: 1024 * 1024,
    };
    png_report::write(&mut markdown, &comparison)?;
    markdown.flush()?;
    markdown.file.get_ref().sync_all()?;
    artifacts.push(Artifact {
        path: "report.md".into(),
        sha256: format!("{:x}", markdown.hash.finalize()),
        bytes: markdown.bytes,
        role: "readable_comparison_report".into(),
    });

    #[derive(Serialize)]
    struct SheetLayout {
        path: &'static str,
        left: &'static str,
        right: &'static str,
        panel_width: u32,
        panel_height: u32,
        method: &'static str,
    }
    #[derive(Serialize)]
    struct Bundle {
        schema_version: u32,
        kind: &'static str,
        comparison: image_comparison::ImageComparisonReport,
        artifacts: Vec<Artifact>,
        sheet: SheetLayout,
    }
    let bundle = Bundle {
        schema_version: 1,
        kind: "offline_png_comparison_bundle",
        comparison,
        artifacts,
        sheet: SheetLayout {
            path: "sheet.png",
            left: "baseline.png",
            right: "candidate.png",
            panel_width: baseline.identity().width,
            panel_height: baseline.identity().height,
            method: "Unscaled stored-raster samples, baseline left/candidate right; ancillary metadata omitted. No color management, gamma linearization, EXIF orientation or compositing. Inspect original copies for color-managed observations.",
        },
    };
    let report_path = output_dir.join("report.json");
    write_json_report(&report_path, &bundle)?;
    File::open(output_dir)?.sync_all()?;
    println!("{}", report_path.display());
    Ok(within_bound)
}

fn load_sequence(path: &Path) -> Result<(SequenceInput, PathBuf)> {
    let input = load_regular_json(path, 1024 * 1024)?;
    let absolute = std::path::absolute(path)?;
    let directory = absolute.parent().context("sequence path has no parent")?;
    Ok((input, directory.to_path_buf()))
}

fn compare_frames(
    baseline: &Path,
    candidate: &Path,
    baseline_repeat: Option<&Path>,
    output_dir: &Path,
    tolerance: Option<Tolerance>,
    assessment: Option<SequenceAssessment>,
) -> Result<bool> {
    let (baseline, baseline_directory) = load_sequence(baseline)?;
    let (candidate, candidate_directory) = load_sequence(candidate)?;
    let repeat = baseline_repeat.map(load_sequence).transpose()?;
    // Reject even dangling output symlinks; never reuse an existing bundle.
    match std::fs::symlink_metadata(output_dir) {
        Ok(_) => anyhow::bail!("sequence output already exists: {}", output_dir.display()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => return Err(error.into()),
    }
    let mut prepared = false;
    let mut remaining = 1024 * 1024 * 1024_u64;
    let mut artifacts = Vec::new();
    let comparison = frame_sequence::compare(
        SequenceSource {
            input: &baseline,
            directory: &baseline_directory,
        },
        SequenceSource {
            input: &candidate,
            directory: &candidate_directory,
        },
        repeat
            .as_ref()
            .map(|(input, directory)| SequenceSource { input, directory }),
        tolerance,
        assessment,
        |index, baseline, candidate, repeat| {
            // Timeline/structure are checked before this callback. A later bad
            // frame or assessment binding leaves partial evidence, never report.json.
            if !prepared {
                DirBuilder::new().mode(0o700).create(output_dir)?;
                DirBuilder::new()
                    .mode(0o700)
                    .create(output_dir.join("frames"))?;
                prepared = true;
            }
            for (label, image) in [
                ("baseline", Some(baseline)),
                ("candidate", Some(candidate)),
                ("repeat", repeat),
            ] {
                if let Some(image) = image {
                    ensure!(
                        image.identity().bytes <= remaining,
                        "sequence frame payload exceeds 1 GiB"
                    );
                    artifacts.push(copy_png(
                        output_dir,
                        &format!("frames/{index:04}-{label}.png"),
                        &format!("{label}_sequence_frame"),
                        image,
                    )?);
                    remaining -= image.identity().bytes;
                }
            }
            let name = format!("frames/{index:04}-sheet.png");
            let mut sheet = ArtifactWriter {
                file: BufWriter::new(new_private_file(&output_dir.join(&name))?),
                hash: Sha256::new(),
                bytes: 0,
                limit: remaining.min(270 * 1024 * 1024),
            };
            png_image::write_sheet(baseline, candidate, &mut sheet)?;
            sheet.flush()?;
            sheet.file.get_ref().sync_all()?;
            remaining -= sheet.bytes;
            artifacts.push(Artifact {
                path: name,
                sha256: format!("{:x}", sheet.hash.finalize()),
                bytes: sheet.bytes,
                role: "raw_sample_frame_ab_sheet".into(),
            });
            Ok(())
        },
    )?;
    let within_bound = comparison.is_within_numerical_bound();
    let mut markdown = ArtifactWriter {
        file: BufWriter::new(new_private_file(&output_dir.join("report.md"))?),
        hash: Sha256::new(),
        bytes: 0,
        limit: 8 * 1024 * 1024,
    };
    sequence_report::write(&mut markdown, &comparison)?;
    markdown.flush()?;
    markdown.file.get_ref().sync_all()?;
    artifacts.push(Artifact {
        path: "report.md".into(),
        sha256: format!("{:x}", markdown.hash.finalize()),
        bytes: markdown.bytes,
        role: "readable_sequence_comparison_report".into(),
    });
    #[derive(Serialize)]
    struct Bundle {
        schema_version: u32,
        kind: &'static str,
        comparison: frame_sequence::SequenceReport,
        artifacts: Vec<Artifact>,
    }
    let bundle = Bundle {
        schema_version: 1,
        kind: "offline_png_sequence_comparison_bundle",
        comparison,
        artifacts,
    };
    let report_path = output_dir.join("report.json");
    write_json_report(&report_path, &bundle)?;
    File::open(output_dir.join("frames"))?.sync_all()?;
    File::open(output_dir)?.sync_all()?;
    println!("{}", report_path.display());
    Ok(within_bound)
}

fn run(cli: Cli) -> Result<bool> {
    match cli.command {
        Command::H3QualifyOwned {
            output_dir,
            scenario,
        } => {
            let succeeded = h3_owned::qualify(&output_dir, &scenario)?;
            println!("{}", output_dir.join("report.json").display());
            Ok(succeeded)
        }
        Command::H3CpuFixture {
            scenario,
            output_dir,
        } => std::process::exit(h3_owned::cpu_fixture(&scenario, &output_dir)?),
        Command::H3CpuCodec { args } => std::process::exit(h3_owned::cpu_codec(&args)?),
        Command::Validate { workload } => {
            let workload: Workload = load(&workload)?;
            workload.validate()?;
            println!("{}", workload.identity()?);
            Ok(true)
        }
        Command::ValidateResult { workload, result } => {
            let workload: Workload = load(&workload)?;
            let result: AdapterResult = load(&result)?;
            result.validate(&workload)?;
            println!("valid adapter evidence for {}", workload.identity()?);
            Ok(true)
        }
        Command::Inspect { run_dir } => {
            let record = capture::inspect(&run_dir)?;
            println!("{}", serde_json::to_string_pretty(&record)?);
            Ok(record.is_success())
        }
        Command::InspectImages {
            workload,
            images,
            output_dir,
            inspection_seconds,
        } => {
            let workload: Workload = load_regular_json(&workload, 1024 * 1024)?;
            let report_path = output_dir.join("report.json");
            let valid = image_inspection::inspect(ImageInspectionOptions {
                workload,
                inputs: images,
                output_dir,
                timeout: Duration::from_secs(inspection_seconds),
            })?;
            println!("{}", report_path.display());
            Ok(valid)
        }
        Command::H3Prepare {
            workload,
            profile,
            binary,
            model_dir,
            shader_cwd,
            source_dir,
            ffmpeg,
            ffprobe,
            output_dir,
        } => {
            let workload_path = std::path::absolute(&workload)?;
            let input_dir = workload_path
                .parent()
                .context("workload path has no parent")?
                .to_path_buf();
            let workload: Workload = load_regular_json(&workload, 1024 * 1024)?;
            let report_path = output_dir.join("report.json");
            let valid = h3::prepare(H3PrepareOptions {
                workload,
                profile: profile.parse()?,
                binary,
                model_dir,
                shader_cwd,
                source_dir,
                input_dir,
                ffmpeg,
                ffprobe,
                output_dir,
            })?;
            println!("{}", report_path.display());
            Ok(valid)
        }
        Command::H3InspectResult {
            plan,
            stdout,
            stderr,
            exit_code,
            video,
            output_dir,
            inspection_seconds,
        } => {
            let report_path = output_dir.join("report.json");
            let valid = h3::inspect_saved(H3InspectOptions {
                plan,
                stdout,
                stderr,
                exit_code,
                video,
                output_dir,
                timeout: Duration::from_secs(inspection_seconds),
            })?;
            println!("{}", report_path.display());
            Ok(valid)
        }
        Command::InspectVideo {
            workload,
            video,
            ffmpeg,
            ffprobe,
            output_dir,
            inspection_seconds,
        } => {
            let workload: Workload = load_regular_json(&workload, 1024 * 1024)?;
            let report_path = output_dir.join("report.json");
            let valid = video_inspection::inspect(VideoInspectionOptions {
                workload,
                input: video,
                ffmpeg,
                ffprobe,
                output_dir,
                timeout: Duration::from_secs(inspection_seconds),
            })?;
            println!("{}", report_path.display());
            Ok(valid)
        }
        Command::StudyPlan { plan, output } => {
            let plan: StudyPlan = load_regular_json(&plan, 1024 * 1024)?;
            write_json_report(&output, &plan.template()?)?;
            println!("{}", output.display());
            Ok(true)
        }
        Command::Compare {
            study,
            output,
            inspection_seconds,
        } => {
            let input: StudyInput = load_regular_json(&study, 16 * 1024 * 1024)?;
            let absolute = std::path::absolute(&study)?;
            let base = absolute.parent().context("study path has no parent")?;
            let report =
                comparison::compare(&input, base, Duration::from_secs(inspection_seconds), None)?;
            write_json_report(&output, &report)?;
            println!("{}", output.display());
            Ok(report.is_complete())
        }
        Command::StudyReport {
            study,
            output_dir,
            inspection_seconds,
        } => {
            let input: StudyInput = load_regular_json(&study, 16 * 1024 * 1024)?;
            let absolute = std::path::absolute(&study)?;
            let base = absolute.parent().context("study path has no parent")?;
            write_study_bundle(
                &input,
                base,
                &output_dir,
                Duration::from_secs(inspection_seconds),
            )
        }
        Command::CompareImages {
            baseline,
            candidate,
            baseline_repeat,
            output_dir,
            max_absolute_error,
            tolerance_rationale,
            assessment,
        } => {
            let tolerance = max_absolute_error.zip(tolerance_rationale).map(
                |(max_absolute_error, rationale)| Tolerance {
                    max_absolute_error,
                    rationale,
                },
            );
            let assessment = assessment
                .as_deref()
                .map(|path| load_regular_json::<ImageAssessment>(path, 64 * 1024))
                .transpose()?;
            compare_images(
                &baseline,
                &candidate,
                baseline_repeat.as_deref(),
                &output_dir,
                tolerance,
                assessment,
            )
        }
        Command::CompareFrames {
            baseline,
            candidate,
            baseline_repeat,
            output_dir,
            max_absolute_error,
            tolerance_rationale,
            assessment,
        } => {
            let tolerance = max_absolute_error.zip(tolerance_rationale).map(
                |(max_absolute_error, rationale)| Tolerance {
                    max_absolute_error,
                    rationale,
                },
            );
            let assessment = assessment
                .as_deref()
                .map(|path| load_regular_json::<SequenceAssessment>(path, 1024 * 1024))
                .transpose()?;
            compare_frames(
                &baseline,
                &candidate,
                baseline_repeat.as_deref(),
                &output_dir,
                tolerance,
                assessment,
            )
        }
        Command::MaintenanceCpu { root, scenario } => {
            let receipt = maintenance::run_cpu(&root, &scenario)?;
            let evidence: serde_json::Value = maintenance::read_private(&receipt)?;
            println!("{}", receipt.display());
            Ok(evidence["success"] == true)
        }
        Command::MaintenanceRun {
            transaction,
            authorization,
        } => {
            let receipt = maintenance::run_controller(
                maintenance::read_private(&transaction)?,
                maintenance::read_private(&authorization)?,
            )?;
            let evidence: serde_json::Value = maintenance::read_private(&receipt)?;
            println!("{}", receipt.display());
            Ok(evidence["success"] == true)
        }
        Command::MaintenanceGuardian { control_fd } => {
            maintenance::guardian_main(control_fd)?;
            Ok(true)
        }
        Command::MaintenanceParticipant { mode, duration_ms } => {
            maintenance::participant(&mode, duration_ms)
        }
        Command::Supervise(process) => supervise(process, None),
        Command::SuperviseGuarded {
            guard_config,
            process,
        } => supervise(process, Some(load(&guard_config)?)),
        Command::GuardCheck { config, output } => {
            let config: GuardConfig = load(&config)?;
            let lease_path = lease_path()?;
            let _lease = Lease::acquire(&lease_path)?;
            let directory = output
                .parent()
                .filter(|p| !p.as_os_str().is_empty())
                .unwrap_or(Path::new("."));
            let monitor = GuardMonitor::start(config, directory)?;
            let decision = monitor.initial_decision();
            let report = serde_json::json!({
                "schema_version": 1,
                "kind": "guard_preflight",
                "gpu_authorized": false,
                "lease_path": lease_path,
                "lease_acquired": true,
                "guard": monitor.report(),
                "decision_error": decision.as_ref().err().map(|e| format!("{e:#}")),
            });
            let mut file = OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(&output)
                .with_context(|| format!("creating new guard report {}", output.display()))?;
            serde_json::to_writer_pretty(&mut file, &report)?;
            file.write_all(b"\n")?;
            file.sync_all()?;
            println!("{}", output.display());
            Ok(decision.is_ok())
        }
        Command::MfluxPreflight {
            python,
            model_dir,
            workload,
            output,
            timeout_seconds,
        } => {
            let passed = preflight::run(PreflightOptions {
                python,
                model_dir,
                workload,
                output: output.clone(),
                timeout: Duration::from_secs(timeout_seconds),
            })?;
            println!("{}", output.display());
            Ok(passed)
        }
        Command::MfluxRun {
            python,
            source_dir,
            model_dir,
            source_sha256,
            workload,
            root,
            output,
            timeout_seconds,
            check_timeout_seconds,
            max_output_bytes,
            guard_config,
            maintenance_transaction,
            authorization,
            check_only: _,
            execute,
        } => {
            let passed = native::run(NativeOptions {
                python,
                source_dir,
                model_dir,
                source_sha256,
                workload,
                root,
                output: output.clone(),
                timeout: Duration::from_secs(timeout_seconds),
                check_timeout: Duration::from_secs(check_timeout_seconds),
                max_output_bytes,
                guard_config,
                maintenance_transaction,
                authorization,
                execute,
            })?;
            println!("{}", output.display());
            Ok(passed)
        }
    }
}

fn lease_path() -> Result<PathBuf> {
    let home = std::env::var_os("HOME").context("HOME is required for the shared project lease")?;
    let home = PathBuf::from(home);
    ensure!(
        home.is_absolute(),
        "HOME must be absolute for the shared project lease"
    );
    let root = home.join(".local/share/media-inference-lab");
    std::fs::create_dir_all(&root)?;
    Ok(root.join("gpu.lock"))
}

fn supervise(process: ProcessArguments, guard: Option<GuardConfig>) -> Result<bool> {
    ensure!(
        process.cpu_only,
        "GPU/model execution is not authorized by this CPU-only command"
    );
    if guard.is_some() {
        ensure!(
            process.timeout_seconds <= 600,
            "guarded CPU execution is limited to 600 seconds"
        );
    }
    let request: Workload = load(&process.workload)?;
    request.validate()?;
    let mut env = BTreeMap::new();
    for (key, value) in process.environment {
        ensure!(
            env.insert(key, value).is_none(),
            "duplicate environment key"
        );
    }
    let options = CaptureOptions {
        root: process.root,
        executable: process.executable,
        args: process.args,
        env,
        timeout: Duration::from_secs(process.timeout_seconds),
        max_output_bytes: process.max_output_bytes,
    };
    let guarded = guard
        .map(|config| Ok::<_, anyhow::Error>((config, Lease::acquire(&lease_path()?)?)))
        .transpose()?;
    let cancelled = Arc::new(AtomicBool::new(false));
    let mut signals = Vec::new();
    for signal in [signal_hook::consts::SIGINT, signal_hook::consts::SIGTERM] {
        signals.push(signal_hook::flag::register(signal, Arc::clone(&cancelled))?);
    }
    let result = match guarded {
        Some((config, lease)) => {
            capture::capture_guarded(request, options, cancelled, config, lease)
        }
        None => capture::capture(request, options, cancelled),
    };
    for signal in signals {
        signal_hook::low_level::unregister(signal);
    }
    let run_dir = result?;
    println!("{}", run_dir.display());
    Ok(capture::inspect(&run_dir)?.is_success())
}

fn main() -> ExitCode {
    match run(Cli::parse()) {
        Ok(true) => ExitCode::SUCCESS,
        Ok(false) => ExitCode::FAILURE,
        Err(error) => {
            eprintln!("mil: {error:#}");
            ExitCode::from(2)
        }
    }
}
