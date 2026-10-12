use anyhow::{Context, Result, ensure};
use clap::{Parser, Subcommand};
use media_inference_lab::{
    capture::{self, CaptureOptions},
    guards::{GuardConfig, GuardMonitor, Lease},
    preflight::{self, PreflightOptions},
    schema::{AdapterResult, Workload},
};
use serde::de::DeserializeOwned;
use std::{
    collections::BTreeMap,
    fs::{File, OpenOptions},
    io::{Read, Write},
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
    /// Supervise a trusted CPU-only process without platform guards.
    Supervise(ProcessArguments),
    /// Check lease/memory/swap/disk/live-process observations; never grants GPU access.
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

fn run(cli: Cli) -> Result<bool> {
    match cli.command {
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
