//! Named-scope exclusion is observed by the independent guardian, not supplied as readiness JSON.
use crate::{
    guards::GuardDecision,
    service_lifecycle::{ServiceHandle, ServiceObservation, ServiceRole},
};
use anyhow::{Context, Result, ensure};
use serde::{Deserialize, Serialize};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

pub const SANDBOX_EXECUTABLE: &str = "/usr/bin/sandbox-exec";
pub const SANDBOX_PROFILE: &str = "(version 1)(allow default)(deny network*)(deny process-fork)(deny file-write* (require-not (subpath (param \"MIL_RUN\"))))";
pub const OFFLINE_ENVIRONMENT: [(&str, &str); 6] = [
    ("HF_HUB_OFFLINE", "1"),
    ("TRANSFORMERS_OFFLINE", "1"),
    ("HF_HUB_DISABLE_IMPLICIT_TOKEN", "1"),
    ("HF_HUB_DISABLE_TELEMETRY", "1"),
    ("TOKENIZERS_PARALLELISM", "false"),
    ("LC_ALL", "C"),
];
pub const MAX_AUTHORITY_GAP: Duration = Duration::from_millis(1000);

#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ScopePurpose {
    Cpu,
    Native,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NativeBinding {
    pub invocation_sha256: String,
    pub transaction_sha256: String,
    pub guardian_pid: u32,
}

/// This clock is created and consumed only inside one guardian. Child timestamps
/// are evidence, never deadlines or leases. Long scheduling gaps (including sleep)
/// and wall-clock discontinuities revoke authority rather than extending a window.
pub(crate) struct GuardianClock {
    started: Instant,
    last: Instant,
    wall: SystemTime,
    recovery_wall: SystemTime,
    deadline: Instant,
    revoked: Option<String>,
}
impl GuardianClock {
    pub(crate) fn new(total: Duration) -> Result<Self> {
        ensure!(
            !total.is_zero() && total <= Duration::from_secs(1800),
            "invalid guardian ceiling"
        );
        let now = Instant::now();
        Ok(Self {
            started: now,
            last: now,
            wall: SystemTime::now(),
            recovery_wall: SystemTime::now(),
            deadline: now + total,
            revoked: None,
        })
    }
    pub(crate) fn check(&mut self) -> Result<()> {
        if let Some(reason) = &self.revoked {
            anyhow::bail!("authority revoked: {reason}");
        }
        let now = Instant::now();
        let wall = SystemTime::now();
        let steady_delta = now.duration_since(self.last);
        let wall_delta = wall.duration_since(self.wall);
        let reason = if now >= self.deadline {
            Some("guardian automation ceiling expired")
        } else if wall_delta.is_err() {
            Some("guardian wall clock regressed")
        } else if steady_delta > MAX_AUTHORITY_GAP
            || wall_delta
                .as_ref()
                .is_ok_and(|delta| *delta > MAX_AUTHORITY_GAP)
        {
            Some("guardian authority stale after observation/suspend gap")
        } else if wall_delta
            .as_ref()
            .is_ok_and(|delta| delta.abs_diff(steady_delta) > Duration::from_millis(250))
        {
            Some("guardian clock domains diverged")
        } else {
            None
        };
        self.last = now;
        self.wall = wall;
        if let Some(reason) = reason {
            self.revoked = Some(reason.into());
            anyhow::bail!("{reason}");
        }
        Ok(())
    }
    pub(crate) fn elapsed_ms(&self) -> u64 {
        self.started.elapsed().as_millis().min(u64::MAX as u128) as u64
    }
    pub(crate) fn phase_deadline(&self, budget: Duration) -> Instant {
        (Instant::now() + budget).min(self.deadline)
    }
    pub(crate) fn hard_deadline(&self) -> Instant {
        self.deadline
    }
    pub(crate) fn recovery_check(&mut self) -> Result<()> {
        ensure!(
            self.revoked.as_deref() != Some("guardian wall clock regressed")
                && self.revoked.as_deref() != Some("guardian clock domains diverged"),
            "clock discontinuity requires manual recovery"
        );
        let wall = SystemTime::now();
        ensure!(
            wall.duration_since(self.recovery_wall).is_ok(),
            "recovery wall clock regressed"
        );
        self.recovery_wall = wall;
        ensure!(
            Instant::now() < self.deadline,
            "guardian automation ceiling expired"
        );
        Ok(())
    }
}

pub fn unix_ms() -> Result<u64> {
    Ok(SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .context("wall clock precedes epoch")?
        .as_millis()
        .try_into()?)
}
pub fn valid_hash(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

#[derive(Clone, Debug, Serialize)]
#[serde(deny_unknown_fields)]
pub struct NamedScopeReading {
    pub guardian_elapsed_ms: u64,
    pub transaction_sha256: String,
    pub services: Vec<ServiceObservation>,
    pub decision: GuardDecision,
    pub authority_scope: String,
}

/// No Deserialize or public constructor. Only the transaction owner can mint this
/// after authorization and live inhibition. Persisted readings cannot grant it.
pub(crate) struct ScopeAuthority {
    transaction_sha256: String,
    revoked: Option<String>,
}
impl ScopeAuthority {
    pub(crate) fn new(transaction_sha256: String) -> Result<Self> {
        ensure!(
            valid_hash(&transaction_sha256),
            "invalid transaction identity"
        );
        Ok(Self {
            transaction_sha256,
            revoked: None,
        })
    }
    pub(crate) fn collect(
        &mut self,
        services: &mut [ServiceHandle],
        clock: &mut GuardianClock,
    ) -> NamedScopeReading {
        let mut reasons = Vec::new();
        if let Err(error) = clock.check() {
            reasons.push(error.to_string());
        }
        if let Some(reason) = &self.revoked {
            reasons.push(reason.clone());
        }
        let mut observations = Vec::with_capacity(services.len());
        for service in services {
            match service.observe_inhibited() {
                Ok(observation) => {
                    if !observation.inhibited || observation.failure.is_some() {
                        reasons.push(format!("{:?} inhibition is unqualified", observation.role));
                    }
                    observations.push(observation);
                }
                Err(error) => reasons.push(format!(
                    "required service observation unavailable: {error:#}"
                )),
            }
        }
        if observations.len() != 2
            || observations[0].role != ServiceRole::Studio
            || observations[1].role != ServiceRole::Omlx
        {
            reasons.push("named scope requires exactly Studio and oMLX, in enrolled order".into());
        }
        if let Err(error) = clock.check() {
            reasons.push(error.to_string());
        }
        if !reasons.is_empty() && self.revoked.is_none() {
            self.revoked = Some(reasons.join("; "));
        }
        NamedScopeReading {
            guardian_elapsed_ms: clock.elapsed_ms(), transaction_sha256: self.transaction_sha256.clone(), services: observations,
            decision: GuardDecision { allowed: reasons.is_empty(), reasons },
            authority_scope: "Only enrolled Studio/oMLX admissions and the guardian-owned experiment; not whole-host GPU exclusion or arbitrary descendants".into(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn stale_authority_is_sticky_even_after_clock_recovery() {
        let mut clock = GuardianClock::new(Duration::from_secs(60)).unwrap();
        clock.check().unwrap();
        clock.last -= Duration::from_secs(2);
        clock.wall -= Duration::from_secs(2);
        assert!(clock.check().is_err());
        clock.last = Instant::now();
        clock.wall = SystemTime::now();
        assert!(
            clock.check().is_err(),
            "new readings cannot revive revoked transaction authority"
        );
    }
    #[test]
    fn backwards_wall_clock_and_automation_ceiling_revoke() {
        let mut clock = GuardianClock::new(Duration::from_secs(60)).unwrap();
        clock.wall = SystemTime::now() + Duration::from_secs(1);
        assert!(clock.check().is_err());
        let mut clock = GuardianClock::new(Duration::from_secs(60)).unwrap();
        let maximum = clock.hard_deadline();
        assert_eq!(clock.phase_deadline(Duration::from_secs(120)), maximum);
        clock.deadline = clock.started;
        assert!(clock.check().is_err());
    }
}
