//! Study-specific offline analysis; never a native execution or lifecycle entry point.
use anyhow::Result;
use clap::{Parser, Subcommand};
use std::{path::PathBuf, process::ExitCode, time::{Duration, Instant}};

#[path = "unchanged_baseline/media.rs"]
mod media;
#[path = "unchanged_baseline/report.rs"]
mod report;

#[derive(Parser)]
#[command(about = "Bounded offline analysis of the fixed unchanged eight-slot baseline protocol")]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Explicitly derive full-frame and PCM evidence with the pinned software decoder.
    Derive {
        #[arg(long)] source: PathBuf,
        #[arg(long)] inspection: PathBuf,
        #[arg(long)] ffmpeg: PathBuf,
        #[arg(long)] output: PathBuf,
    },
    /// Read existing evidence only; never execute a decoder, model or service helper.
    Report {
        #[arg(long)] protocol: PathBuf,
        #[arg(long)] ledger: PathBuf,
        #[arg(long)] output: PathBuf,
    },
}

fn run() -> Result<bool> {
    let deadline = Instant::now() + Duration::from_secs(1800);
    match Cli::parse().command {
        Command::Derive { source, inspection, ffmpeg, output } =>
            media::derive(&source, &inspection, &output, &ffmpeg, deadline),
        Command::Report { protocol, ledger, output } =>
            report::run(&protocol, &ledger, &output, deadline),
    }
}

fn main() -> ExitCode {
    match run() {
        Ok(true) => ExitCode::SUCCESS,
        Ok(false) => ExitCode::from(1),
        Err(error) => { eprintln!("{error:#}"); ExitCode::from(2) }
    }
}
