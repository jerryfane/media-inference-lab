use anyhow::{Context, Result, bail, ensure};
use clap::{Parser, Subcommand};
use media_inference_lab::{
    capture::{self, CaptureOptions},
    schema::{AdapterResult, Workload},
};
use serde::de::DeserializeOwned;
use std::{
    collections::BTreeMap,
    fs::File,
    io::Read,
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
    /// Supervise a trusted CPU-only process. NOT a guarded model capture command.
    Supervise {
        #[arg(long)]
        workload: PathBuf,
        #[arg(long, default_value = "runs")]
        root: PathBuf,
        /// Explicit executable path; the child runs in its isolated run directory.
        #[arg(long)]
        executable: PathBuf,
        /// Acknowledge no GPU/model work. Resource/live-job guards are not yet integrated.
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
    },
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
        Command::Supervise {
            workload,
            root,
            executable,
            cpu_only,
            timeout_seconds,
            max_output_bytes,
            environment,
            args,
        } => {
            if !cpu_only {
                bail!(
                    "only explicitly acknowledged CPU-only processes are supported; GPU guards are not integrated"
                );
            }
            let request: Workload = load(&workload)?;
            request.validate()?;
            let mut env = BTreeMap::new();
            for (key, value) in environment {
                ensure!(
                    env.insert(key, value).is_none(),
                    "duplicate environment key"
                );
            }
            let cancelled = Arc::new(AtomicBool::new(false));
            let mut signals = Vec::new();
            for signal in [signal_hook::consts::SIGINT, signal_hook::consts::SIGTERM] {
                signals.push(signal_hook::flag::register(signal, Arc::clone(&cancelled))?);
            }
            let result = capture::capture(
                request,
                CaptureOptions {
                    root,
                    executable,
                    args,
                    env,
                    timeout: Duration::from_secs(timeout_seconds),
                    max_output_bytes,
                },
                cancelled,
            );
            for signal in signals {
                signal_hook::low_level::unregister(signal);
            }
            let run_dir = result?;
            println!("{}", run_dir.display());
            Ok(capture::inspect(&run_dir)?.is_success())
        }
    }
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
