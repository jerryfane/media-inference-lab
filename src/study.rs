use anyhow::{Context, Result, ensure};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::path::PathBuf;

use crate::schema::{TimingScope, Workload};

pub const SCHEMA_VERSION: u32 = 1;
const MAX_SLOTS: usize = 99;

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Role {
    Baseline,
    Candidate,
    Control,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ComparisonMode {
    SameWork,
    Descriptive,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum Metric {
    #[serde(deserialize_with = "deserialize_host_execution")]
    HostExecution,
    Adapter {
        phase: String,
        scope: TimingScope,
        method: String,
        boundary: String,
    },
}

fn deserialize_host_execution<'de, D>(deserializer: D) -> std::result::Result<(), D::Error>
where
    D: serde::Deserializer<'de>,
{
    // Serde's internally tagged unit visitor otherwise ignores unknown fields.
    #[derive(Deserialize)]
    #[serde(deny_unknown_fields)]
    struct Empty {}

    Empty::deserialize(deserializer).map(|_| ())
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StudyPlan {
    pub schema_version: u32,
    pub id: String,
    pub workload: Workload,
    pub mode: ComparisonMode,
    pub metric: Metric,
    pub repetitions: u32,
    pub warmups: u32,
    pub minimum_samples: u32,
    pub baseline_label: String,
    pub candidate_label: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PlannedSample {
    pub index: u32,
    pub role: Role,
    pub warmup: bool,
    pub repetition: u32,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SampleBinding {
    pub index: u32,
    pub capture: Option<PathBuf>,
    pub missing_reason: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StudyInput {
    pub schema_version: u32,
    pub plan: StudyPlan,
    pub samples: Vec<SampleBinding>,
}

fn bounded_text(value: &str, field: &str, maximum: usize) -> Result<()> {
    ensure!(
        !value.trim().is_empty() && !value.contains('\0'),
        "{field} must be nonblank and contain no NUL"
    );
    ensure!(value.len() <= maximum, "{field} exceeds {maximum} bytes");
    Ok(())
}

impl StudyPlan {
    pub fn validate(&self) -> Result<()> {
        ensure!(
            self.schema_version == SCHEMA_VERSION,
            "unsupported study plan schema_version {}; expected {SCHEMA_VERSION}",
            self.schema_version
        );
        bounded_text(&self.id, "study id", 128)?;
        bounded_text(&self.baseline_label, "baseline_label", 128)?;
        bounded_text(&self.candidate_label, "candidate_label", 128)?;
        ensure!(
            (1..=30).contains(&self.repetitions),
            "repetitions must be in 1..=30 per role"
        );
        ensure!(self.warmups <= 3, "warmups must be in 0..=3 per role");
        ensure!(
            (3..=30).contains(&self.minimum_samples),
            "minimum_samples must be in 3..=30"
        );
        if let Metric::Adapter {
            phase,
            method,
            boundary,
            ..
        } = &self.metric
        {
            bounded_text(phase, "metric phase", 128)?;
            bounded_text(method, "metric method", 1024)?;
            bounded_text(boundary, "metric boundary", 1024)?;
        }
        self.workload.validate().context("study workload")?;
        Ok(())
    }

    /// Hash the complete typed plan, independent of JSON key order and sample bindings.
    pub fn identity(&self) -> Result<String> {
        self.validate()?;
        let bytes = serde_json::to_vec(self).context("serializing study plan identity")?;
        Ok(format!("{:x}", Sha256::digest(bytes)))
    }

    /// Warmup cycles precede measurement cycles; control always means unchanged baseline.
    pub fn slots(&self) -> Result<Vec<PlannedSample>> {
        self.validate()?;
        let mut samples = Vec::with_capacity(self.slot_count());
        samples.extend(self.planned_samples());
        Ok(samples)
    }

    pub fn template(&self) -> Result<StudyInput> {
        self.validate()?;
        let mut samples = Vec::with_capacity(self.slot_count());
        samples.extend(self.planned_samples().map(|slot| SampleBinding {
            index: slot.index,
            capture: None,
            missing_reason: Some("not captured".to_owned()),
        }));
        Ok(StudyInput {
            schema_version: SCHEMA_VERSION,
            plan: self.clone(),
            samples,
        })
    }

    // Call only after validation.
    fn slot_count(&self) -> usize {
        ((self.warmups + self.repetitions) * 3) as usize
    }

    // Call only after validation: count arithmetic and allocation stay bounded to 99 slots.
    fn planned_samples(&self) -> impl Iterator<Item = PlannedSample> + '_ {
        [(true, self.warmups), (false, self.repetitions)]
            .into_iter()
            .flat_map(|(warmup, count)| {
                (0..count).flat_map(move |repetition| {
                    [Role::Baseline, Role::Candidate, Role::Control]
                        .into_iter()
                        .map(move |role| (role, warmup, repetition))
                })
            })
            .enumerate()
            .map(|(index, (role, warmup, repetition))| PlannedSample {
                index: index as u32,
                role,
                warmup,
                repetition,
            })
    }
}

impl StudyInput {
    pub fn validate(&self) -> Result<()> {
        ensure!(
            self.schema_version == SCHEMA_VERSION,
            "unsupported study input schema_version {}; expected {SCHEMA_VERSION}",
            self.schema_version
        );
        self.plan.validate()?;
        let expected = self.plan.slot_count();
        ensure!(
            self.samples.len() <= MAX_SLOTS && self.samples.len() == expected,
            "study samples must contain all {expected} slots, including warmup and missing slots"
        );
        for (index, sample) in self.samples.iter().enumerate() {
            ensure!(
                sample.index as usize == index,
                "sample index {} must be {index}; every slot must appear exactly once in planned order",
                sample.index
            );
            match (&sample.capture, &sample.missing_reason) {
                (Some(path), None) => {
                    let value = path.to_str().context("capture path must be UTF-8")?;
                    ensure!(
                        !value.is_empty() && !value.contains('\0') && value.len() <= 4096,
                        "sample {index} capture path must be nonempty, contain no NUL and fit in 4096 bytes"
                    );
                }
                (None, Some(reason)) => {
                    ensure!(
                        !reason.trim().is_empty() && !reason.contains('\0'),
                        "sample {index} missing_reason must be nonblank and contain no NUL"
                    );
                }
                _ => anyhow::bail!(
                    "sample {index} must have exactly one of capture or missing_reason"
                ),
            }
        }
        Ok(())
    }
}
