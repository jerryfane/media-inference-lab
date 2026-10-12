//! Native execution prerequisites. These observations do not issue manager grants.
use crate::guards::{GuardDecision, Observation};
use anyhow::{Result, ensure};
use serde::{Deserialize, Serialize};
use std::time::{SystemTime, UNIX_EPOCH};

pub const SANDBOX_EXECUTABLE: &str = "/usr/bin/sandbox-exec";
pub const SANDBOX_PROFILE: &str = "(version 1)(allow default)(deny network*)(deny file-write* (require-not (subpath (param \"MIL_RUN\"))))";
/// Supervisor-owned environment, shared with the exact prepared command identity.
pub const OFFLINE_ENVIRONMENT: [(&str, &str); 6] = [
    ("HF_HUB_OFFLINE", "1"),
    ("TRANSFORMERS_OFFLINE", "1"),
    ("HF_HUB_DISABLE_IMPLICIT_TOKEN", "1"),
    ("HF_HUB_DISABLE_TELEMETRY", "1"),
    ("TOKENIZERS_PARALLELISM", "false"),
    ("LC_ALL", "C"),
];
pub const LIVE_QUEUE_UNAVAILABLE: &str = "No authoritative aggregate live queue integration exists: health and per-known-job lookup cannot establish absence of queued or in-process jobs.";
pub const UNRELATED_GPU_UNAVAILABLE: &str = "No global unrelated-GPU freshness, ownership, and continuous readiness integration exists; process and memory observations cannot substitute.";
pub const MAX_READINESS_AGE_MS: u64 = 1000;

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct NativeGuardConfig {
    pub invocation_sha256: String,
    /// Unauthenticated external provenance only, never an authorization override.
    pub manager_grant_reference: Option<String>,
}
impl NativeGuardConfig {
    pub fn validate(&self) -> Result<()> {
        ensure!(
            self.invocation_sha256.len() == 64
                && self
                    .invocation_sha256
                    .bytes()
                    .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)),
            "native invocation SHA-256 must be 64 lowercase hexadecimal characters"
        );
        if let Some(reference) = &self.manager_grant_reference {
            ensure!(
                !reference.trim().is_empty()
                    && reference.len() <= 4096
                    && !reference.chars().any(char::is_control),
                "manager reference must be nonempty bounded provenance without control characters"
            );
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct LiveQueueReadiness {
    pub source: String,
    pub observed_unix_ms: u64,
    pub valid_until_unix_ms: u64,
    pub queued_jobs: u64,
    pub active_jobs: u64,
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct UnrelatedGpuReadiness {
    pub source: String,
    pub observed_unix_ms: u64,
    pub valid_until_unix_ms: u64,
    pub unrelated_gpu_owners: Vec<String>,
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct NativeReadiness {
    pub epoch_ms: u64,
    pub live_queue: Observation<LiveQueueReadiness>,
    pub unrelated_gpu: Observation<UnrelatedGpuReadiness>,
}

/// Production collection is deliberately unavailable. There is no file, environment,
/// callback, command-line flag, historical CPU sample or manager-reference override.
pub fn readiness() -> NativeReadiness {
    NativeReadiness {
        epoch_ms: SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|duration| duration.as_millis().min(u64::MAX as u128) as u64)
            .unwrap_or(0),
        live_queue: Observation::Unavailable {
            reason: LIVE_QUEUE_UNAVAILABLE.into(),
        },
        unrelated_gpu: Observation::Unavailable {
            reason: UNRELATED_GPU_UNAVAILABLE.into(),
        },
    }
}

fn freshness(
    source: &str,
    observed: u64,
    expires: u64,
    now: u64,
    name: &str,
    reasons: &mut Vec<String>,
) {
    if source.trim().is_empty()
        || observed == 0
        || observed > now
        || expires <= now
        || expires <= observed
        || expires.saturating_sub(observed) > MAX_READINESS_AGE_MS
        || now.saturating_sub(observed) > MAX_READINESS_AGE_MS
    {
        reasons.push(format!("{name} lacks a fresh bounded source observation"));
    }
}

/// Pure evidence evaluation, not a producer of readiness or an authorization API.
/// Native capture always obtains its own production observations.
pub fn evaluate(config: &NativeGuardConfig, reading: &NativeReadiness) -> GuardDecision {
    let mut reasons = Vec::new();
    if let Err(error) = config.validate() {
        reasons.push(error.to_string());
    }
    match &reading.live_queue {
        Observation::Unavailable { reason } => {
            reasons.push(format!("authoritative live_queue unavailable: {reason}"))
        }
        Observation::Available { value } => {
            freshness(
                &value.source,
                value.observed_unix_ms,
                value.valid_until_unix_ms,
                reading.epoch_ms,
                "authoritative live_queue",
                &mut reasons,
            );
            if value.queued_jobs != 0 || value.active_jobs != 0 {
                reasons.push("authoritative live_queue contains queued or active jobs".into());
            }
        }
    }
    match &reading.unrelated_gpu {
        Observation::Unavailable { reason } => {
            reasons.push(format!("unrelated_gpu unavailable: {reason}"))
        }
        Observation::Available { value } => {
            freshness(
                &value.source,
                value.observed_unix_ms,
                value.valid_until_unix_ms,
                reading.epoch_ms,
                "unrelated_gpu",
                &mut reasons,
            );
            if !value.unrelated_gpu_owners.is_empty() {
                reasons.push("unrelated_gpu owners are present".into());
            }
        }
    }
    GuardDecision {
        allowed: reasons.is_empty(),
        reasons,
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct NativeGuardReading {
    pub readiness: NativeReadiness,
    pub decision: GuardDecision,
}
impl NativeGuardReading {
    pub(crate) fn collect(config: &NativeGuardConfig) -> Self {
        let readiness = readiness();
        let decision = evaluate(config, &readiness);
        Self {
            readiness,
            decision,
        }
    }
    pub fn validate(&self, config: &NativeGuardConfig) -> Result<()> {
        ensure!(
            self.decision == evaluate(config, &self.readiness),
            "native decision contradicts required observations"
        );
        Ok(())
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct NativeGuardReport {
    pub config: NativeGuardConfig,
    pub baseline: NativeGuardReading,
    pub samples: Vec<NativeGuardReading>,
}
impl NativeGuardReport {
    pub fn validate(&self) -> Result<()> {
        self.config.validate()?;
        self.baseline.validate(&self.config)?;
        ensure!(
            self.samples.len() <= crate::guards::MAX_SAMPLES,
            "native guard history exceeds bound"
        );
        ensure!(
            self.baseline.decision.allowed || self.samples.is_empty(),
            "native sampling continued after initial denial"
        );
        let mut previous = self.baseline.readiness.epoch_ms;
        for (index, sample) in self.samples.iter().enumerate() {
            sample.validate(&self.config)?;
            ensure!(
                sample.readiness.epoch_ms >= previous,
                "native observation time regressed"
            );
            previous = sample.readiness.epoch_ms;
            ensure!(
                sample.decision.allowed || index + 1 == self.samples.len(),
                "native sampling continued after denial"
            );
        }
        Ok(())
    }
}

pub(crate) fn combine(decision: &mut GuardDecision, native: &GuardDecision) {
    decision.allowed &= native.allowed;
    decision.reasons.extend(native.reasons.iter().cloned());
}
