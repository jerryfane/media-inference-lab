//! Identity-bound restore qualification. Metadata and startup evidence never imply
//! settings fidelity. Only authorization-minted capabilities can run X2 or X3.
//!
//! X2 privately compares the reviewed launcher's three exports. X3 validates an
//! exhaustive source-reviewed configured-profile catalog and compares values in
//! wiped private memory; only reviewed labels and equality booleans are reported.
//! Restore stdio is unchanged (/dev/null), so console diagnostics are unavailable.
//! PF2 is lstat-only change detection, not a content-preservation attestation.
//! The parent authenticates the complete transaction before minting a capability;
//! the service then merges observed Q1/Q2 via `record_service_checks` before any
//! GUI-resume decision. An operational pass without observed fidelity cannot pass.
use std::collections::{BTreeMap, BTreeSet};
use std::fs::{self, File};
use std::io::{Read, Seek, SeekFrom, Write};
use std::net::{SocketAddr, TcpStream};
use std::os::fd::{AsRawFd, FromRawFd};
use std::os::unix::ffi::OsStringExt;
use std::os::unix::fs::MetadataExt;
use std::path::{Component, Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::{
    Arc,
    atomic::{AtomicBool, Ordering},
};
use std::time::{Duration, Instant};

use anyhow::{Context, Result, bail, ensure};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};

use crate::process_scope::{ProcessIdentity, verify_identity};
use crate::qualification_profile::{
    ProfileCatalog, ProfileComparison, ProfileSnapshot, ProfileSummary,
};
use crate::qualification_scope::{self, ReviewedLaunchScope, ScopeObservation};

const ENV_NAMES: [&str; 5] = ["HOME", "LOGNAME", "PATH", "TMPDIR", "USER"];
const RESTORE_PATH: &str = "/usr/bin:/bin:/usr/sbin:/sbin";
const MAX_HTTP: usize = 16 * 1024 * 1024;
const MAX_SECRET: usize = 1024 * 1024;

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct QualificationLimits {
    pub max_files: usize,
    pub max_file_bytes: u64,
    pub max_total_bytes: u64,
    pub max_log_bytes: u64,
    pub max_depth: usize,
}
impl Default for QualificationLimits {
    fn default() -> Self {
        Self {
            max_files: 200_000,
            max_file_bytes: 8 << 30,
            max_total_bytes: 64 << 30,
            max_log_bytes: 16 << 20,
            max_depth: 64,
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct QualificationPlan {
    pub bundle_contents: PathBuf,
    pub reference_worktree: PathBuf,
    pub expected_git_revision: String,
    pub settings_path: PathBuf,
    pub model_settings_path: PathBuf,
    pub model_profiles_path: PathBuf,
    pub global_templates_path: PathBuf,
    pub bootstrap_path: PathBuf,
    pub log_path: PathBuf,
    pub expected_health: Value,
    pub required_startup_substrings: Vec<String>,
    pub forbidden_startup_substrings: Vec<String>,
    #[serde(default)]
    pub limits: QualificationLimits,
}
impl QualificationPlan {
    pub fn validate(&self) -> Result<()> {
        for path in [
            &self.bundle_contents,
            &self.reference_worktree,
            &self.settings_path,
            &self.model_settings_path,
            &self.model_profiles_path,
            &self.global_templates_path,
            &self.bootstrap_path,
            &self.log_path,
        ] {
            validate_absolute(path)?;
        }
        ensure!(
            self.expected_git_revision.len() == 40
                && self
                    .expected_git_revision
                    .bytes()
                    .all(|b| b.is_ascii_hexdigit()),
            "invalid expected code revision"
        );
        let configs = self.config_paths();
        let distinct: BTreeSet<_> = configs.iter().collect();
        ensure!(
            distinct.len() == configs.len(),
            "config references must be distinct"
        );
        for path in configs {
            ensure!(
                !path.starts_with(&self.bundle_contents)
                    && !path.starts_with(&self.reference_worktree),
                "config reference overlaps code"
            );
        }
        let base = self.settings_path.parent();
        ensure!(
            base == self.model_settings_path.parent()
                && base == self.model_profiles_path.parent()
                && base == self.global_templates_path.parent(),
            "config references require one base directory"
        );
        ensure!(
            !self.bundle_contents.starts_with(&self.reference_worktree)
                && !self.reference_worktree.starts_with(&self.bundle_contents),
            "code roots overlap"
        );
        ensure!(
            self.settings_path.file_name().and_then(|s| s.to_str()) == Some("settings.json")
                && self
                    .model_settings_path
                    .file_name()
                    .and_then(|s| s.to_str())
                    == Some("model_settings.json")
                && self
                    .model_profiles_path
                    .file_name()
                    .and_then(|s| s.to_str())
                    == Some("model_profiles.json")
                && self
                    .global_templates_path
                    .file_name()
                    .and_then(|s| s.to_str())
                    == Some("global_templates.json"),
            "unexpected config reference names"
        );
        ensure!(
            self.limits.max_files > 0
                && self.limits.max_files <= 1_000_000
                && self.limits.max_file_bytes > 0
                && self.limits.max_file_bytes <= 64 << 30
                && self.limits.max_total_bytes > 0
                && self.limits.max_total_bytes <= 256 << 30
                && self.limits.max_log_bytes > 0
                && self.limits.max_log_bytes <= 64 << 20
                && self.limits.max_depth > 0
                && self.limits.max_depth <= 128,
            "invalid qualification resource bounds"
        );
        for patterns in [
            &self.required_startup_substrings,
            &self.forbidden_startup_substrings,
        ] {
            ensure!(
                !patterns.is_empty()
                    && patterns.len() <= 256
                    && patterns
                        .iter()
                        .all(|p| !p.is_empty() && p.len() <= 8192 && !p.contains('\n')),
                "invalid fingerprint patterns"
            );
        }
        validate_health_shape(&self.expected_health)?;
        Ok(())
    }
    fn config_paths(&self) -> [&Path; 5] {
        [
            &self.settings_path,
            &self.model_settings_path,
            &self.model_profiles_path,
            &self.global_templates_path,
            &self.bootstrap_path,
        ]
    }
    pub fn sha256(&self) -> Result<String> {
        Ok(format!("{:x}", Sha256::digest(serde_json::to_vec(self)?)))
    }
    /// Pure: this is input completeness, NOT authority. The parent must validate
    /// its exact transaction grant before minting AuthorizedPermissions.
    pub fn validate_reviewed_permissions(
        &self,
        reviewed: Option<&ReviewedPermissionInput>,
    ) -> Result<()> {
        self.validate()?;
        let reviewed =
            reviewed.context("DENY: G1/X3 and G2/X2 unavailable; no reviewed permissions")?;
        reviewed.validate()?;
        ensure!(
            reviewed.plan_sha256 == self.sha256()?,
            "reviewed permission does not bind qualification plan"
        );
        Ok(())
    }
}
pub(crate) fn validate_absolute(path: &Path) -> Result<()> {
    ensure!(
        path.is_absolute()
            && path.as_os_str().len() <= 4096
            && !path
                .components()
                .any(|c| matches!(c, Component::ParentDir | Component::CurDir)),
        "invalid absolute reference path"
    );
    Ok(())
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CredentialReference {
    pub path: PathBuf,
    pub json_pointer: Option<String>,
    /// Exact transaction-bound permission for settings_path /auth/api_key only.
    pub allow_settings_api_key_projection: bool,
}
impl CredentialReference {
    fn validate_for(&self, plan: &QualificationPlan) -> Result<()> {
        validate_absolute(&self.path)?;
        if let Some(pointer) = &self.json_pointer {
            ensure!(valid_pointer(pointer), "invalid credential pointer");
        }
        ensure!(
            !self.path.starts_with(&plan.bundle_contents)
                && !self.path.starts_with(&plan.reference_worktree),
            "credential reference must not read a code reference"
        );
        if self.allow_settings_api_key_projection {
            ensure!(
                self.path.as_os_str() == plan.settings_path.as_os_str()
                    && self.json_pointer.as_deref() == Some("/auth/api_key"),
                "credential settings projection permission does not match reference"
            );
        } else {
            ensure!(
                !plan.config_paths().contains(&self.path.as_path()),
                "credential reference must not read a PF2 config reference"
            );
        }
        Ok(())
    }
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReviewedX3Input {
    pub review_reference: String,
    pub credential: CredentialReference,
    /// Protocol shape must be reviewed, not inferred from an arbitrary response.
    pub login_key_field: String,
    pub session_cookie_name: String,
    pub profile_catalog: ProfileCatalog,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReviewedPermissionInput {
    pub review_reference: String,
    pub plan_sha256: String,
    pub old_identity: ProcessIdentity,
    pub x2_launcher_private_comparison: bool,
    pub existing_log_observation_review_reference: String,
    pub x3: Option<ReviewedX3Input>,
    pub launch_scope: ReviewedLaunchScope,
    /// Explicit review of the residuals reported by FidelityReport, not a bypass
    /// of any mandatory gate or a claim about unread settings bytes.
    pub residuals_review_reference: String,
}
impl ReviewedPermissionInput {
    fn validate(&self) -> Result<()> {
        ensure!(
            review_text(&self.review_reference)
                && review_text(&self.residuals_review_reference)
                && review_text(&self.existing_log_observation_review_reference)
                && valid_digest(&self.plan_sha256)
                && self.x2_launcher_private_comparison,
            "DENY: missing X2 private comparison or explicit review"
        );
        ensure!(self.old_identity.pid > 1, "invalid old process binding");
        let x3 = self.x3.as_ref().context("DENY: X3 unavailable")?;
        ensure!(
            review_text(&x3.review_reference)
                && http_token(&x3.login_key_field)
                && http_token(&x3.session_cookie_name),
            "DENY: X3 protocol not reviewed"
        );
        validate_absolute(&x3.credential.path)?;
        if let Some(pointer) = &x3.credential.json_pointer {
            ensure!(valid_pointer(pointer), "invalid credential pointer");
        }
        self.launch_scope.validate()?;
        x3.profile_catalog.validate()
    }
}
fn review_text(s: &str) -> bool {
    !s.trim().is_empty() && s.len() <= 4096 && !s.contains('\0')
}
fn valid_digest(s: &str) -> bool {
    s.len() == 64 && s.bytes().all(|b| b.is_ascii_hexdigit())
}
fn http_token(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= 128
        && s.bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-')
}
fn valid_pointer(s: &str) -> bool {
    if !s.starts_with('/') || s.len() > 4096 {
        return false;
    }
    let mut bytes = s.bytes();
    while let Some(b) = bytes.next() {
        if b == b'~' && !matches!(bytes.next(), Some(b'0' | b'1')) {
            return false;
        }
        if b == 0 {
            return false;
        }
    }
    true
}

/// Not deserializable. Possession is necessary but observations remain private.
#[derive(Clone)]
pub struct AuthorizedPermissions {
    reviewed: ReviewedPermissionInput,
    transaction_sha256: String,
    usage: Arc<PermissionUsage>,
}
#[derive(Default)]
struct PermissionUsage {
    x2: AtomicBool,
    old_x3: AtomicBool,
    restored_x3: AtomicBool,
}
fn consume_permission(used: &AtomicBool) -> Result<()> {
    ensure!(
        used.compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
            .is_ok(),
        "restricted observation permission already consumed; no retry"
    );
    Ok(())
}
impl AuthorizedPermissions {
    /// AUTHORIZATION BOUNDARY: caller MUST already have verified the explicit
    /// native grant against the entire transaction (including this exact input),
    /// executable hash, identities, operation budgets, and validity interval.
    /// A digest alone is not a grant. No CLI/serde conversion may call this.
    pub(crate) fn from_transaction_authorization(
        reviewed: &ReviewedPermissionInput,
        transaction_sha256: &str,
    ) -> Result<Self> {
        reviewed.validate()?;
        ensure!(
            valid_digest(transaction_sha256),
            "invalid authorized transaction digest"
        );
        Ok(Self {
            reviewed: reviewed.clone(),
            transaction_sha256: transaction_sha256.to_owned(),
            usage: Arc::new(PermissionUsage::default()),
        })
    }
    pub fn validate_for(
        &self,
        plan: &QualificationPlan,
        old_backend: &ProcessIdentity,
    ) -> Result<()> {
        plan.validate_reviewed_permissions(Some(&self.reviewed))?;
        ensure!(
            self.reviewed.old_identity.same_process(old_backend),
            "permission binds another old service"
        );
        self.reviewed
            .x3
            .as_ref()
            .context("X3 unavailable")?
            .credential
            .validate_for(plan)
    }
    pub fn old_identity(&self) -> &ProcessIdentity {
        &self.reviewed.old_identity
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum CheckStatus {
    Pass,
    Fail,
    NotEvaluated,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum FidelityStatus {
    Pass,
    Fail,
    NotEvaluated,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum GateStatus {
    Pass,
    Deny,
}
#[derive(Clone, Debug, Serialize)]
pub struct GateReport {
    pub fidelity_gate: GateStatus,
    pub checks: BTreeMap<String, CheckStatus>,
    pub reasons: Vec<String>,
    pub launch_scope: Option<ScopeObservation>,
}
impl Default for GateReport {
    fn default() -> Self {
        Self {
            fidelity_gate: GateStatus::Deny,
            launch_scope: None,
            checks: [
                "G1_old_in_memory_settings",
                "G2_old_env_overrides",
                "G3_bundle_manifest",
                "PS1_unpinned",
                "PS2_model_inventory",
                "PS3_configured_default",
                "PS4_concurrency",
                "PS5_authentication",
                "SC1_no_distributed_workers",
                "SC2_no_launch_manifest_candidates",
            ]
            .into_iter()
            .map(|s| (s.into(), CheckStatus::NotEvaluated))
            .collect(),
            reasons: vec![
                "G1/X3, G2/X2 and G3/PF1 have no private observations; deny before service effects"
                    .into(),
            ],
        }
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum FidelityDimension {
    OldEffectiveProfile,
    OldInheritedEnvironment,
    EffectiveConcurrency,
    NativeBundleBytes,
    GuiResumeBehavior,
    OnDiskSettingsContents,
    OldLoadedBytes,
    NonSettingsRuntimeState,
    UnenumeratedEnvironmentReads,
}
#[derive(Clone, Debug, Serialize)]
pub struct FidelityReport {
    pub dimensions: BTreeMap<FidelityDimension, String>,
    pub residuals: Vec<String>,
    pub compared_settings_pointers: Vec<String>,
    pub excluded_volatile_pointers: Vec<String>,
    pub comparison_coverage_review_reference: Option<String>,
    pub environment_comparison: Option<EnvironmentComparison>,
    pub old_profile: Option<ProfileSummary>,
    pub restored_profile: Option<ProfileSummary>,
    pub profile_comparison: Option<ProfileComparison>,
}
impl Default for FidelityReport {
    fn default() -> Self {
        Self {
            compared_settings_pointers: Vec::new(), excluded_volatile_pointers: Vec::new(),
            comparison_coverage_review_reference: None, environment_comparison: None,
            old_profile: None, restored_profile: None, profile_comparison: None,
            dimensions: [
                (FidelityDimension::OldEffectiveProfile, "unavailable without identity-bound X3"),
                (FidelityDimension::OldInheritedEnvironment, "unavailable without X2; constructed PF3 is not the old environment"),
                (FidelityDimension::EffectiveConcurrency, "unavailable as an in-process observation; historical value is derived, not proof"),
                (FidelityDimension::NativeBundleBytes, "not observed"),
                (FidelityDimension::GuiResumeBehavior, "unproven"),
                (FidelityDimension::OnDiskSettingsContents, "unattested; PF2 metadata only; the permitted authentication projection does not prove settings content fidelity"),
                (FidelityDimension::OldLoadedBytes, "unavailable; current bundle does not prove old loaded bytes"),
                (FidelityDimension::NonSettingsRuntimeState, "not compared"),
                (FidelityDimension::UnenumeratedEnvironmentReads, "unavailable"),
            ].into_iter().map(|(k,v)| (k,v.into())).collect(),
            residuals: vec![
                "Unenumerated third-party environment reads remain unverified".into(),
                "Non-settings runtime state, including caches and live-applied engine state, is not compared".into(),
                "The old process's loaded bytes are not established by the current bundle manifest".into(),
                "On-disk settings contents are not attested; only the explicitly permitted /auth/api_key projection is read for authentication. Unexposed keys, undiscovered-model settings, model_profiles.json and global_templates.json remain unverified".into(),
                "PF2 metadata equality does not prove contents or absence of writes".into(),
                "Restore stdin/stdout/stderr remain /dev/null; console-only diagnostics are UNAVAILABLE, not observed or proven absent".into(),
                "Equality covers only the reviewed source-exposed configured profile, not the full profile, unexposed configuration, on-disk contents or runtime-applied state".into(),
                "Unexposed configured fields remain unverified: version, logging.log_dir/retention_days, server.cors_origins/max_image_upload_size/max_image_side_length, memory.soft_threshold/hard_threshold/prefill_safe_zone_ratio/prefill_min_chunk_tokens, auth.secret_key/allow_unauthenticated_inference".into(),
                "Existing log observations are bounded and private; request content and raw log bytes are never evidence output".into(),
                "SE8 cluster-python publication, base-directory mkdir and shutdown stats writes are expected non-config writes, not prohibited or attested by PF2".into(),
                "External process identity and listener checks are non-atomic with requests".into(),
                "SC1 and bounded SC2 observations deny known distributed/reaper scope; they do not establish whole-host worker absence or atomic absence between the last observation and replacement exec".into(),
            ],
        }
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum SettingsPreservation {
    MetadataUnchangedOnly,
    Fail,
    NotEvaluated,
}
#[derive(Clone, Debug, Serialize)]
pub struct QualificationReport {
    /// Q3-Q6 only until the service owner supplies Q1 and Q2.
    pub operational_checks_passed: bool,
    pub startup_operational: CheckStatus,
    pub checks: BTreeMap<String, CheckStatus>,
    pub failures: BTreeMap<String, String>,
    pub fidelity_gate: GateReport,
    pub fidelity_qualified: FidelityStatus,
    pub exposed_effective_settings_equal: FidelityStatus,
    pub settings_preservation: SettingsPreservation,
    pub fidelity: FidelityReport,
    pub restore_environment_names: Vec<String>,
}
impl QualificationReport {
    pub fn gui_resume_allowed(&self, q1_identity: bool, q2_launch_record: bool) -> bool {
        q1_identity
            && q2_launch_record
            && self.operational_checks_passed
            && self.startup_operational == CheckStatus::Pass
            && self.fidelity_gate.fidelity_gate == GateStatus::Pass
            && self.fidelity_qualified == FidelityStatus::Pass
    }
    pub fn record_service_checks(&mut self, identity: bool, launch_record: bool) {
        for (check, passed) in [
            ("Q1_identity", identity),
            ("Q2_launch_record", launch_record),
        ] {
            if self.checks.get(check) != Some(&CheckStatus::Fail) {
                self.checks.insert(check.into(), status(passed));
            }
        }
        let identity = self.checks.get("Q1_identity") == Some(&CheckStatus::Pass);
        let launch_record = self.checks.get("Q2_launch_record") == Some(&CheckStatus::Pass);
        self.startup_operational =
            status(identity && launch_record && self.operational_checks_passed);
        if self.fidelity_qualified != FidelityStatus::Fail {
            self.fidelity_qualified = match self.exposed_effective_settings_equal {
                FidelityStatus::Pass
                    if launch_record
                        && self.fidelity_gate.fidelity_gate == GateStatus::Pass
                        && self.checks.get("Q3_runtime_manifest") == Some(&CheckStatus::Pass) =>
                {
                    FidelityStatus::Pass
                }
                FidelityStatus::Pass | FidelityStatus::Fail => FidelityStatus::Fail,
                FidelityStatus::NotEvaluated => FidelityStatus::NotEvaluated,
            };
        }
    }
}
fn status(pass: bool) -> CheckStatus {
    if pass {
        CheckStatus::Pass
    } else {
        CheckStatus::Fail
    }
}
pub(crate) fn checkpoint(deadline: Instant, tick: &mut dyn FnMut() -> Result<()>) -> Result<()> {
    tick()?;
    ensure!(
        Instant::now() < deadline,
        "qualification guardian deadline elapsed"
    );
    Ok(())
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct MetadataRecord {
    pub exists: bool,
    pub dev: u64,
    pub ino: u64,
    pub size: u64,
    pub mode: u32,
    pub uid: u32,
    pub mtime_ns: i128,
    pub ctime_ns: i128,
}
impl MetadataRecord {
    pub(crate) fn from_metadata(m: &fs::Metadata) -> Self {
        Self {
            exists: true,
            dev: m.dev(),
            ino: m.ino(),
            size: m.size(),
            mode: m.mode(),
            uid: m.uid(),
            mtime_ns: i128::from(m.mtime()) * 1_000_000_000 + i128::from(m.mtime_nsec()),
            ctime_ns: i128::from(m.ctime()) * 1_000_000_000 + i128::from(m.ctime_nsec()),
        }
    }
    fn missing() -> Self {
        Self {
            exists: false,
            dev: 0,
            ino: 0,
            size: 0,
            mode: 0,
            uid: 0,
            mtime_ns: 0,
            ctime_ns: 0,
        }
    }
    fn same_inode(&self, other: &Self) -> bool {
        self.exists && other.exists && self.dev == other.dev && self.ino == other.ino
    }
}
/// lstat only: does not open, resolve, hash or claim contents of the reference.
pub fn reference_metadata(path: &Path) -> Result<MetadataRecord> {
    match fs::symlink_metadata(path) {
        Ok(m) => Ok(MetadataRecord::from_metadata(&m)),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(MetadataRecord::missing()),
        Err(e) => Err(e).context("config reference lstat unavailable"),
    }
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
struct ConfigReferences {
    files: BTreeMap<PathBuf, MetadataRecord>,
    side_effect_entry_names: BTreeSet<String>,
}
fn config_references(
    plan: &QualificationPlan,
    deadline: Instant,
    tick: &mut dyn FnMut() -> Result<()>,
) -> Result<ConfigReferences> {
    let mut files = BTreeMap::new();
    for (index, path) in plan.config_paths().into_iter().enumerate() {
        checkpoint(deadline, tick)?;
        let record = reference_metadata(path)?;
        ensure!(index >= 2 || record.exists, "deny:config_reference_missing");
        ensure!(
            !record.exists || record.mode & libc::S_IFMT as u32 == libc::S_IFREG as u32,
            "config reference must be a regular file; symlink target contents/metadata are not authorized"
        );
        files.insert(path.to_path_buf(), record);
    }
    let base = plan.settings_path.parent().context("missing config base")?;
    let before = reference_metadata(base)?;
    ensure!(
        before.mode & libc::S_IFMT as u32 == libc::S_IFDIR as u32,
        "config base must be a real directory"
    );
    let mut names = BTreeSet::new();
    for (count, entry) in fs::read_dir(base)?.enumerate() {
        checkpoint(deadline, tick)?;
        ensure!(
            count < plan.limits.max_files,
            "config base name scan exceeds bound"
        );
        let name = entry?
            .file_name()
            .into_string()
            .map_err(|_| anyhow::anyhow!("config base filename is not UTF-8"))?;
        if name.starts_with("settings.json.corrupt-")
            || name.starts_with("profile-reference-backup-")
        {
            names.insert(name);
        }
    }
    ensure!(
        before == reference_metadata(base)?,
        "config base changed during name scan"
    );
    Ok(ConfigReferences {
        files,
        side_effect_entry_names: names,
    })
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
struct ManifestEntry {
    metadata: MetadataRecord,
    target_metadata: MetadataRecord,
    sha256: Option<String>,
    symlink_target: Option<PathBuf>,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
struct BundleManifest {
    entries: BTreeMap<PathBuf, ManifestEntry>,
    revision: String,
}
struct ManifestWalker<'a> {
    root: PathBuf,
    limits: &'a QualificationLimits,
    entries: BTreeMap<PathBuf, ManifestEntry>,
    total_bytes: u64,
    active_dirs: BTreeSet<(u64, u64)>,
}
impl ManifestWalker<'_> {
    fn walk(
        &mut self,
        actual: &Path,
        relative: &Path,
        depth: usize,
        deadline: Instant,
        tick: &mut dyn FnMut() -> Result<()>,
    ) -> Result<()> {
        self.walk_from(actual, relative, depth, deadline, tick, None)
    }

    fn walk_from(
        &mut self,
        actual: &Path,
        relative: &Path,
        depth: usize,
        deadline: Instant,
        tick: &mut dyn FnMut() -> Result<()>,
        parent: Option<&File>,
    ) -> Result<()> {
        checkpoint(deadline, tick)?;
        ensure!(
            depth <= self.limits.max_depth && self.entries.len() < self.limits.max_files,
            "bundle traversal exceeds bound"
        );
        let before = fs::symlink_metadata(actual)?;
        let metadata = MetadataRecord::from_metadata(&before);
        let (resolved, symlink_target) = if before.file_type().is_symlink() {
            let target = fs::read_link(actual)?;
            let resolved = fs::canonicalize(actual)?;
            ensure!(
                resolved.starts_with(&self.root),
                "bundle symlink escapes code-only root"
            );
            (resolved, Some(target))
        } else {
            (actual.to_path_buf(), None)
        };
        let target_meta = fs::symlink_metadata(&resolved)?;
        ensure!(
            !target_meta.file_type().is_symlink(),
            "bundle resolution raced"
        );
        // Only direct children use the pinned parent. Resolved symlinks still
        // traverse the complete contained path with O_NOFOLLOW at every level.
        let parent = parent.filter(|_| symlink_target.is_none());
        if target_meta.is_file() {
            let target_before = MetadataRecord::from_metadata(&target_meta);
            let hash = hash_regular_from(
                &resolved,
                &target_before,
                self.limits,
                &mut self.total_bytes,
                deadline,
                tick,
                parent,
            )?;
            self.entries.insert(
                relative.to_path_buf(),
                ManifestEntry {
                    metadata: metadata.clone(),
                    target_metadata: target_before,
                    sha256: Some(hash),
                    symlink_target,
                },
            );
        } else if target_meta.is_dir() {
            let identity = (target_meta.dev(), target_meta.ino());
            ensure!(self.active_dirs.insert(identity), "bundle symlink cycle");
            let directory = open_manifest_entry(&resolved, parent, true)?;
            ensure!(
                MetadataRecord::from_metadata(&directory.metadata()?)
                    == MetadataRecord::from_metadata(&target_meta),
                "bundle directory open raced"
            );
            self.entries.insert(
                relative.to_path_buf(),
                ManifestEntry {
                    metadata: metadata.clone(),
                    target_metadata: MetadataRecord::from_metadata(&target_meta),
                    sha256: None,
                    symlink_target,
                },
            );
            let children = directory_names(&directory, self.limits.max_files, deadline, tick)?;
            for child in children {
                self.walk_from(
                    &resolved.join(&child),
                    &relative.join(child),
                    depth + 1,
                    deadline,
                    tick,
                    Some(&directory),
                )?;
            }
            self.active_dirs.remove(&identity);
            ensure!(
                MetadataRecord::from_metadata(&directory.metadata()?)
                    == MetadataRecord::from_metadata(&target_meta)
                    && MetadataRecord::from_metadata(&target_meta)
                        == reference_metadata(&resolved)?,
                "bundle directory changed during traversal"
            );
        } else {
            bail!("bundle contains a non-file/non-directory object");
        }
        ensure!(
            metadata == reference_metadata(actual)?,
            "bundle object changed during traversal"
        );
        if before.file_type().is_symlink() {
            ensure!(
                fs::canonicalize(actual)? == resolved,
                "bundle symlink target changed"
            );
        }
        Ok(())
    }
}

fn directory_names(
    directory: &File,
    max_entries: usize,
    deadline: Instant,
    tick: &mut dyn FnMut() -> Result<()>,
) -> Result<Vec<std::ffi::OsString>> {
    let mut stream = qualification_scope::DirectoryStream::open(directory)?;
    let mut names = Vec::new();
    loop {
        checkpoint(deadline, tick)?;
        let Some(name) = stream.next_name()? else {
            break;
        };
        if name == b"." || name == b".." {
            continue;
        }
        ensure!(names.len() < max_entries, "bundle directory exceeds bound");
        names.push(std::ffi::OsString::from_vec(name.to_vec()));
    }
    names.sort();
    Ok(names)
}
fn open_regular(path: &Path) -> Result<File> {
    open_path(path, false)
}

fn open_path(path: &Path, final_directory: bool) -> Result<File> {
    validate_absolute(path)?;
    let components: Vec<_> = path
        .components()
        .filter_map(|part| {
            if let Component::Normal(name) = part {
                Some(name)
            } else {
                None
            }
        })
        .collect();
    ensure!(!components.is_empty(), "regular file path missing");
    let mut directory = File::open("/")?;
    for (index, name) in components.iter().enumerate() {
        let name = std::ffi::CString::new(name.as_encoded_bytes())?;
        let last = index + 1 == components.len();
        let flags = libc::O_RDONLY
            | libc::O_NOFOLLOW
            | libc::O_CLOEXEC
            | libc::O_NONBLOCK
            | if !last || final_directory {
                libc::O_DIRECTORY
            } else {
                0
            };
        // Descriptor-relative traversal rejects symlinked ancestors, not just
        // the final component, preventing a parent swap from opening config.
        let fd = unsafe { libc::openat(directory.as_raw_fd(), name.as_ptr(), flags) };
        ensure!(fd >= 0, "no-follow file traversal failed");
        let opened = unsafe { File::from_raw_fd(fd) };
        if last {
            ensure!(
                if final_directory {
                    opened.metadata()?.is_dir()
                } else {
                    opened.metadata()?.is_file()
                },
                "unexpected code object type"
            );
            return Ok(opened);
        }
        directory = opened;
    }
    bail!("regular file path missing")
}

fn open_manifest_entry(path: &Path, parent: Option<&File>, directory: bool) -> Result<File> {
    let Some(parent) = parent else {
        return open_path(path, directory);
    };
    // This descriptor is the already-opened, metadata-bound directory of this
    // recursion frame. A replaced path cannot redirect the open into another
    // tree. Its original path and inode are rechecked before the frame returns.
    let name = path.file_name().context("manifest child name missing")?;
    let name = std::ffi::CString::new(name.as_encoded_bytes())?;
    let flags = libc::O_RDONLY
        | libc::O_NOFOLLOW
        | libc::O_CLOEXEC
        | libc::O_NONBLOCK
        | if directory { libc::O_DIRECTORY } else { 0 };
    let fd = unsafe { libc::openat(parent.as_raw_fd(), name.as_ptr(), flags) };
    ensure!(fd >= 0, "no-follow manifest child open failed");
    let file = unsafe { File::from_raw_fd(fd) };
    ensure!(
        if directory {
            file.metadata()?.is_dir()
        } else {
            file.metadata()?.is_file()
        },
        "unexpected code object type"
    );
    Ok(file)
}

fn hash_regular(
    path: &Path,
    expected: &MetadataRecord,
    limits: &QualificationLimits,
    total: &mut u64,
    deadline: Instant,
    tick: &mut dyn FnMut() -> Result<()>,
) -> Result<String> {
    hash_regular_from(path, expected, limits, total, deadline, tick, None)
}

fn hash_regular_from(
    path: &Path,
    expected: &MetadataRecord,
    limits: &QualificationLimits,
    total: &mut u64,
    deadline: Instant,
    tick: &mut dyn FnMut() -> Result<()>,
    parent: Option<&File>,
) -> Result<String> {
    ensure!(
        expected.size <= limits.max_file_bytes,
        "code file exceeds byte bound"
    );
    *total = total
        .checked_add(expected.size)
        .context("bundle byte overflow")?;
    ensure!(
        *total <= limits.max_total_bytes,
        "bundle exceeds byte bound"
    );
    let mut file = open_manifest_entry(path, parent, false)?;
    ensure!(
        &MetadataRecord::from_metadata(&file.metadata()?) == expected,
        "code open raced"
    );
    let mut hasher = Sha256::new();
    let mut buf = [0u8; 64 * 1024];
    let mut count = 0u64;
    loop {
        checkpoint(deadline, tick)?;
        let read = file.read(&mut buf)?;
        if read == 0 {
            break;
        }
        count = count
            .checked_add(read as u64)
            .context("code size overflow")?;
        ensure!(count <= expected.size, "code file grew during hashing");
        hasher.update(&buf[..read]);
    }
    ensure!(
        count == expected.size
            && &MetadataRecord::from_metadata(&file.metadata()?) == expected
            && &reference_metadata(path)? == expected,
        "code file changed during hashing"
    );
    Ok(format!("{:x}", hasher.finalize()))
}
fn git_output(
    root: &Path,
    args: &[&str],
    deadline: Instant,
    tick: &mut dyn FnMut() -> Result<()>,
) -> Result<Vec<u8>> {
    checkpoint(deadline, tick)?;
    let mut child = Command::new("/usr/bin/git")
        .args([
            "-c",
            "core.fsmonitor=false",
            "-c",
            "core.hooksPath=/dev/null",
            "-C",
        ])
        .arg(root)
        .args(args)
        .env_clear()
        .env("PATH", RESTORE_PATH)
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .env("GIT_CONFIG_GLOBAL", "/dev/null")
        .env("GIT_OPTIONAL_LOCKS", "0")
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()?;
    let result = (|| -> Result<Vec<u8>> {
        let mut pipe = child.stdout.take().context("git stdout unavailable")?;
        let fd = pipe.as_raw_fd();
        // The descriptor belongs to this process; preserving its existing flags.
        unsafe {
            let flags = libc::fcntl(fd, libc::F_GETFL);
            ensure!(
                flags >= 0 && libc::fcntl(fd, libc::F_SETFL, flags | libc::O_NONBLOCK) == 0,
                "cannot bound git output"
            );
        }
        let mut output = Vec::new();
        let mut buf = [0u8; 4096];
        loop {
            checkpoint(deadline, tick)?;
            match pipe.read(&mut buf) {
                Ok(n) => {
                    ensure!(output.len() + n <= 1024 * 1024, "git output exceeds bound");
                    output.extend_from_slice(&buf[..n]);
                }
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {}
                Err(e) => return Err(e.into()),
            }
            if let Some(status) = child.try_wait()? {
                ensure!(status.success(), "code worktree git check failed");
                loop {
                    match pipe.read(&mut buf) {
                        Ok(0) => break,
                        Ok(n) => {
                            ensure!(output.len() + n <= 1024 * 1024, "git output exceeds bound");
                            output.extend_from_slice(&buf[..n]);
                        }
                        Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => break,
                        Err(e) => return Err(e.into()),
                    }
                }
                return Ok(output);
            }
            std::thread::sleep(Duration::from_millis(5));
        }
    })();
    if result.is_err() {
        let _ = child.kill();
        let _ = child.wait();
    }
    result
}
fn worktree_revision(
    plan: &QualificationPlan,
    deadline: Instant,
    tick: &mut dyn FnMut() -> Result<()>,
) -> Result<String> {
    let revision = git_output(
        &plan.reference_worktree,
        &["rev-parse", "--verify", "HEAD^{commit}"],
        deadline,
        tick,
    )?;
    let revision = std::str::from_utf8(&revision)?.trim().to_owned();
    ensure!(
        revision == plan.expected_git_revision,
        "deny:runtime_identity_mismatch revision"
    );
    ensure!(
        git_output(
            &plan.reference_worktree,
            &["status", "--porcelain=v1", "--untracked-files=all"],
            deadline,
            tick
        )?
        .is_empty(),
        "deny:runtime_identity_mismatch dirty worktree"
    );
    Ok(revision)
}
fn bundle_manifest(
    plan: &QualificationPlan,
    deadline: Instant,
    tick: &mut dyn FnMut() -> Result<()>,
) -> Result<BundleManifest> {
    ensure!(
        fs::canonicalize(&plan.reference_worktree)? == plan.reference_worktree,
        "reference worktree may not alias another path"
    );
    let revision = worktree_revision(plan, deadline, tick)?;
    let root = fs::canonicalize(&plan.bundle_contents)?;
    ensure!(
        root == plan.bundle_contents,
        "bundle root may not alias another path"
    );
    let mut walker = ManifestWalker {
        root: root.clone(),
        limits: &plan.limits,
        entries: BTreeMap::new(),
        total_bytes: 0,
        active_dirs: BTreeSet::new(),
    };
    walker.walk(&root, Path::new(""), 0, deadline, tick)?;
    let overlay = Path::new("Resources/omlx");
    let python: Vec<_> = walker
        .entries
        .iter()
        .filter(|(path, entry)| {
            path.starts_with(overlay)
                && path.extension().and_then(|s| s.to_str()) == Some("py")
                && entry.sha256.is_some()
        })
        .collect();
    ensure!(!python.is_empty(), "bundle Python overlay missing");
    let listed = git_output(
        &plan.reference_worktree,
        &["ls-files", "-v", "-z", "--", "omlx"],
        deadline,
        tick,
    )?;
    let mut tracked_python = BTreeSet::new();
    for item in listed
        .split(|byte| *byte == 0)
        .filter(|item| !item.is_empty())
    {
        checkpoint(deadline, tick)?;
        ensure!(
            item.len() > 2 && item[0] == b'H' && item[1] == b' ',
            "worktree index has unmerged, skipped or assume-unchanged code"
        );
        let path = PathBuf::from(
            std::str::from_utf8(&item[2..]).context("worktree code path is not UTF-8")?,
        );
        if path.extension().and_then(|s| s.to_str()) == Some("py") {
            tracked_python.insert(path);
        }
    }
    let bundled_python: BTreeSet<_> = python
        .iter()
        .map(|(path, _)| {
            path.strip_prefix(overlay)
                .map(|relative| Path::new("omlx").join(relative))
        })
        .collect::<std::result::Result<_, _>>()?;
    ensure!(
        bundled_python == tracked_python,
        "deny:runtime_identity_mismatch Python file set"
    );
    for (path, entry) in python {
        let source = plan
            .reference_worktree
            .join("omlx")
            .join(path.strip_prefix(overlay)?);
        let canonical = fs::canonicalize(&source)?;
        ensure!(
            canonical.starts_with(&plan.reference_worktree),
            "worktree source escapes code root"
        );
        let metadata = reference_metadata(&source)?;
        ensure!(
            metadata.mode & libc::S_IFMT as u32 == libc::S_IFREG as u32,
            "worktree overlay must be regular code"
        );
        let hash = hash_regular(
            &source,
            &metadata,
            &plan.limits,
            &mut walker.total_bytes,
            deadline,
            tick,
        )?;
        ensure!(
            entry.sha256.as_ref() == Some(&hash),
            "deny:runtime_identity_mismatch overlay"
        );
    }
    ensure!(
        revision == worktree_revision(plan, deadline, tick)?,
        "worktree changed during manifest"
    );
    Ok(BundleManifest {
        entries: walker.entries,
        revision,
    })
}

pub fn validate_restore_environment(env: &BTreeMap<String, String>) -> Result<()> {
    ensure!(
        env.keys().map(String::as_str).eq(ENV_NAMES),
        "deny:launch_env_unconstructible names must exactly equal PF3"
    );
    ensure!(
        env.get("PATH").map(String::as_str) == Some(RESTORE_PATH)
            && env
                .values()
                .all(|v| !v.is_empty() && v.len() <= 8192 && !v.contains('\0')),
        "deny:launch_env_unconstructible values"
    );
    Ok(())
}
#[derive(Clone, Debug)]
struct LogOffset {
    metadata: MetadataRecord,
}
impl LogOffset {
    fn capture(path: &Path) -> Result<Self> {
        let before = reference_metadata(path)?;
        let f = open_regular(path)?;
        ensure!(
            before == MetadataRecord::from_metadata(&f.metadata()?),
            "log open raced"
        );
        Ok(Self { metadata: before })
    }
    fn appended(
        &self,
        path: &Path,
        max: u64,
        deadline: Instant,
        tick: &mut dyn FnMut() -> Result<()>,
    ) -> Result<SecretBytes> {
        let mut file = open_regular(path)?;
        let current = MetadataRecord::from_metadata(&file.metadata()?);
        ensure!(
            self.metadata.same_inode(&current) && current.size >= self.metadata.size,
            "log rotated or truncated"
        );
        let count = current.size - self.metadata.size;
        ensure!(count <= max, "appended log exceeds bound");
        file.seek(SeekFrom::Start(self.metadata.size))?;
        let bytes = read_exact_bounded(&mut file, count, deadline, tick)?;
        let after = MetadataRecord::from_metadata(&file.metadata()?);
        let path_after = reference_metadata(path)?;
        ensure!(
            after.same_inode(&path_after)
                && after.same_inode(&self.metadata)
                && after.size >= current.size
                && path_after.size >= current.size,
            "log rotated or truncated during read"
        );
        Ok(bytes)
    }
}
fn read_exact_bounded(
    file: &mut File,
    count: u64,
    deadline: Instant,
    tick: &mut dyn FnMut() -> Result<()>,
) -> Result<SecretBytes> {
    let mut result = SecretBytes(Vec::with_capacity(usize::try_from(count)?));
    let mut buffer = SecretBuffer([0u8; 32 * 1024]);
    while result.0.len() < count as usize {
        checkpoint(deadline, tick)?;
        let limit = buffer.0.len().min(count as usize - result.0.len());
        let n = file.read(&mut buffer.0[..limit])?;
        ensure!(n > 0, "bounded file read truncated");
        result.0.extend_from_slice(&buffer.0[..n]);
    }
    Ok(result)
}
/// Generic ordered line subsequence; no settings semantics are inferred.
pub fn match_startup_fingerprint(
    log: &[u8],
    required: &[String],
    forbidden: &[String],
) -> Result<()> {
    let log = std::str::from_utf8(log).context("startup log is not UTF-8")?;
    ensure!(
        !required.is_empty()
            && required.iter().all(|s| !s.is_empty())
            && forbidden.iter().all(|s| !s.is_empty()),
        "empty fingerprint pattern"
    );
    ensure!(
        !forbidden.iter().any(|p| log.contains(p)),
        "forbidden startup side-effect/error pattern detected"
    );
    let mut wanted = required.iter();
    let mut next = wanted.next();
    for line in log.lines() {
        if next.is_some_and(|pattern| line.contains(pattern)) {
            next = wanted.next();
        }
    }
    ensure!(
        next.is_none(),
        "startup fingerprint missing or out of order"
    );
    Ok(())
}
fn validate_health_shape(expected: &Value) -> Result<()> {
    let object = expected
        .as_object()
        .context("expected health must be an object")?;
    ensure!(
        object.len() == 3
            && object.get("status").and_then(Value::as_str) == Some("healthy")
            && object
                .get("default_model")
                .and_then(Value::as_str)
                .is_some_and(|s| !s.is_empty()),
        "invalid safe expected health fields"
    );
    let pool = object
        .get("engine_pool")
        .and_then(Value::as_object)
        .context("missing health engine pool")?;
    ensure!(
        pool.len() == 2
            && pool.get("model_count").and_then(Value::as_u64).is_some()
            && pool.get("loaded_count").and_then(Value::as_u64) == Some(0),
        "invalid cold health expectation"
    );
    Ok(())
}
fn health_matches(actual: &Value, expected: &Value) -> bool {
    [
        "/status",
        "/default_model",
        "/engine_pool/model_count",
        "/engine_pool/loaded_count",
    ]
    .iter()
    .all(|pointer| actual.pointer(pointer) == expected.pointer(pointer))
}

/// This type cannot be constructed from serialized evidence or caller booleans.
pub struct GateObservations {
    plan_sha256: String,
    transaction_sha256: String,
    old_identity: ProcessIdentity,
    old_snapshot: ProfileSnapshot,
    manifest: BundleManifest,
    report: GateReport,
    environment_comparison: EnvironmentComparison,
    comparison_fields: Vec<String>,
    volatile_fields: Vec<String>,
    coverage_review_reference: String,
    launch_scope: ReviewedLaunchScope,
}

#[derive(Debug)]
pub struct GateDenial {
    pub report: GateReport,
}
impl std::fmt::Display for GateDenial {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // All reasons come from sanitized adapter errors, never response bodies.
        write!(
            f,
            "DENY: {}",
            serde_json::to_string(&self.report).map_err(|_| std::fmt::Error)?
        )
    }
}
impl std::error::Error for GateDenial {}
fn gate_result<T>(report: &mut GateReport, check: &str, result: Result<T>) -> Result<T> {
    match result {
        Ok(value) => {
            report.checks.insert(check.into(), CheckStatus::Pass);
            Ok(value)
        }
        Err(error) => {
            report.checks.insert(check.into(), CheckStatus::Fail);
            report.reasons.push(error.to_string());
            Err(GateDenial {
                report: report.clone(),
            }
            .into())
        }
    }
}
/// Calls only fixed X2/X3 operations after checking the private capability. The
/// service callback MUST verify sole listener ownership and title/cwd from OS
/// state; it must not consume a caller-supplied readiness document.
pub fn capture_gate(
    plan: &QualificationPlan,
    permissions: &AuthorizedPermissions,
    restore_env: &BTreeMap<String, String>,
    deadline: Instant,
    tick: &mut dyn FnMut() -> Result<()>,
    verify_service: &mut dyn FnMut(&ProcessIdentity) -> Result<()>,
) -> Result<GateObservations> {
    permissions.validate_for(plan, permissions.old_identity())?;
    permissions
        .reviewed
        .launch_scope
        .validate_for(restore_env)?;
    checkpoint(deadline, tick)?;
    let mut report = GateReport::default();
    report.reasons.clear();
    let scope_observation =
        qualification_scope::observe(&permissions.reviewed.launch_scope, deadline, tick);
    let scope_passed = scope_observation.qualifies();
    report.launch_scope = Some(scope_observation);
    gate_result(
        &mut report,
        "SC2_no_launch_manifest_candidates",
        (|| {
            ensure!(
                scope_passed,
                "SC2 launch-manifest scope unavailable or contains candidates"
            );
            Ok(())
        })(),
    )?;
    let manifest = gate_result(
        &mut report,
        "G3_bundle_manifest",
        bundle_manifest(plan, deadline, tick),
    )?;
    let env_result = collect_x2(permissions, deadline, tick).and_then(|observation| {
        ensure!(
            observation.qualifies(),
            "launcher-defined environment missing/mismatched or additional profile override present"
        );
        Ok(observation)
    });
    let environment_comparison = gate_result(&mut report, "G2_old_env_overrides", env_result)?;
    let snapshot_result = collect_x3(
        plan,
        permissions,
        permissions.old_identity(),
        deadline,
        tick,
        verify_service,
    )
    .and_then(|snapshot| {
        let prestop = snapshot.prestop(&plan.expected_health);
        for (name, passed) in [
            ("PS1_unpinned", prestop.ps1),
            ("PS2_model_inventory", prestop.ps2),
            ("PS3_configured_default", prestop.ps3),
            ("PS4_concurrency", prestop.ps4),
            ("PS5_authentication", prestop.ps5),
            ("SC1_no_distributed_workers", prestop.ps6),
        ] {
            report.checks.insert(name.into(), status(passed));
        }
        ensure!(
            prestop.passed(),
            "mandatory old-snapshot pre-stop predicates failed"
        );
        checkpoint(deadline, tick)?;
        verify_identity(permissions.old_identity())?;
        Ok(snapshot)
    });
    let old_snapshot = gate_result(&mut report, "G1_old_in_memory_settings", snapshot_result)?;
    report.fidelity_gate = GateStatus::Pass;
    let catalog = &permissions
        .reviewed
        .x3
        .as_ref()
        .context("reviewed profile catalog unavailable")?
        .profile_catalog;
    Ok(GateObservations {
        plan_sha256: plan.sha256()?,
        transaction_sha256: permissions.transaction_sha256.clone(),
        old_identity: permissions.old_identity().clone(),
        old_snapshot,
        manifest,
        report,
        environment_comparison,
        comparison_fields: catalog.compared_labels(),
        volatile_fields: catalog.volatile_labels(),
        coverage_review_reference: catalog.coverage_review_reference.clone(),
        launch_scope: permissions.reviewed.launch_scope.clone(),
    })
}

pub struct QualificationState {
    plan: QualificationPlan,
    gate: GateObservations,
    references: ConfigReferences,
    log_offset: Option<LogOffset>,
    checks: BTreeMap<String, CheckStatus>,
    failures: BTreeMap<String, String>,
    before_attempted: bool,
    after_attempted: bool,
}
impl QualificationState {
    /// Ungranted entry point: deny without reading any path or process.
    pub fn preflight(
        _plan: &QualificationPlan,
        _restore_env: &BTreeMap<String, String>,
        _deadline: Instant,
        _tick: &mut dyn FnMut() -> Result<()>,
    ) -> Result<Self> {
        bail!("DENY: private G1/X3, G2/X2 and G3/PF1 observations required before effects")
    }
    pub fn preflight_authorized(
        plan: &QualificationPlan,
        restore_env: &BTreeMap<String, String>,
        gate: GateObservations,
        deadline: Instant,
        tick: &mut dyn FnMut() -> Result<()>,
    ) -> Result<Self> {
        plan.validate()?;
        validate_restore_environment(restore_env)?;
        gate.launch_scope.validate_for(restore_env)?;
        ensure!(
            gate.plan_sha256 == plan.sha256()? && gate.report.fidelity_gate == GateStatus::Pass,
            "DENY: gate binding mismatch"
        );
        checkpoint(deadline, tick)?;
        verify_identity(&gate.old_identity)?;
        let references = config_references(plan, deadline, tick)?;
        Ok(Self {
            plan: plan.clone(),
            gate,
            references,
            log_offset: None,
            checks: [
                "Q1_identity",
                "Q2_launch_record",
                "Q3_runtime_manifest",
                "Q4_config_metadata",
                "Q5_health",
                "Q6_startup_fingerprint",
            ]
            .into_iter()
            .map(|s| (s.into(), CheckStatus::NotEvaluated))
            .collect(),
            failures: BTreeMap::new(),
            before_attempted: false,
            after_attempted: false,
        })
    }
    pub(crate) fn check_named_scope_absence(
        &mut self,
        deadline: Instant,
        tick: &mut dyn FnMut() -> Result<()>,
    ) -> Result<ScopeObservation> {
        ensure!(
            self.gate.report.fidelity_gate == GateStatus::Pass,
            "SC2 previous scope denial is sticky; service effects withheld"
        );
        let observation = qualification_scope::observe(&self.gate.launch_scope, deadline, tick);
        let passed = observation.qualifies();
        self.gate.report.launch_scope = Some(observation.clone());
        self.gate
            .report
            .checks
            .insert("SC2_no_launch_manifest_candidates".into(), status(passed));
        if !passed {
            self.gate.report.fidelity_gate = GateStatus::Deny;
            bail!(
                "SC2 service effects withheld: {}",
                serde_json::to_string(&observation)?
            );
        }
        Ok(observation)
    }
    pub fn before_restore(
        &mut self,
        deadline: Instant,
        tick: &mut dyn FnMut() -> Result<()>,
    ) -> Result<()> {
        ensure!(
            !self.before_attempted,
            "restore preconditions are single-attempt"
        );
        self.before_attempted = true;
        let manifest = bundle_manifest(&self.plan, deadline, tick).and_then(|m| {
            ensure!(m == self.gate.manifest, "runtime manifest changed");
            Ok(())
        });
        self.record("Q3_runtime_manifest", manifest);
        let references = config_references(&self.plan, deadline, tick).and_then(|m| {
            ensure!(
                m == self.references,
                "config reference metadata or side-effect names changed"
            );
            Ok(())
        });
        self.record("Q4_config_metadata", references);
        ensure!(
            self.checks["Q3_runtime_manifest"] == CheckStatus::Pass
                && self.checks["Q4_config_metadata"] == CheckStatus::Pass,
            "restore preconditions failed; inspect qualification report"
        );
        checkpoint(deadline, tick)?;
        self.log_offset = Some(LogOffset::capture(&self.plan.log_path)?);
        Ok(())
    }
    fn record(&mut self, check: &str, result: Result<()>) {
        if let Err(error) = result {
            self.checks.insert(check.into(), CheckStatus::Fail);
            self.failures
                .entry(check.into())
                .or_insert_with(|| error.to_string());
        } else if self.checks.get(check) != Some(&CheckStatus::Fail) {
            self.checks.insert(check.into(), CheckStatus::Pass);
        }
    }
    pub fn report(&self) -> QualificationReport {
        let mut fidelity = FidelityReport {
            compared_settings_pointers: self.gate.comparison_fields.clone(),
            excluded_volatile_pointers: self.gate.volatile_fields.clone(),
            comparison_coverage_review_reference: Some(self.gate.coverage_review_reference.clone()),
            environment_comparison: Some(self.gate.environment_comparison.clone()),
            old_profile: Some(self.gate.old_snapshot.summary().clone()),
            ..FidelityReport::default()
        };
        fidelity.dimensions.insert(FidelityDimension::OldEffectiveProfile, "identity-bound source-exposed configured profile observed by X3; mandatory PS1-PS5, SC1 and SC2 passed before stopping services; full-profile equivalence is not claimed".into());
        fidelity.dimensions.insert(FidelityDimension::OldInheritedEnvironment, "X2 privately matched exact launcher exports and found no additional enumerated profile overrides; full old environment not compared".into());
        fidelity.dimensions.insert(
            FidelityDimension::EffectiveConcurrency,
            "old exposed in-memory concurrency observed as 8; restored not yet compared".into(),
        );
        fidelity.dimensions.insert(FidelityDimension::NativeBundleBytes, "full preflight bundle file/symlink-target hashes observed; old loaded bytes remain unavailable".into());
        QualificationReport {
            operational_checks_passed: [
                "Q3_runtime_manifest",
                "Q4_config_metadata",
                "Q5_health",
                "Q6_startup_fingerprint",
            ]
            .iter()
            .all(|k| self.checks.get(*k) == Some(&CheckStatus::Pass)),
            startup_operational: CheckStatus::NotEvaluated,
            checks: self.checks.clone(),
            failures: self.failures.clone(),
            fidelity_gate: self.gate.report.clone(),
            fidelity_qualified: FidelityStatus::NotEvaluated,
            exposed_effective_settings_equal: FidelityStatus::NotEvaluated,
            settings_preservation: match self.checks["Q4_config_metadata"] {
                CheckStatus::Pass if self.after_attempted => {
                    SettingsPreservation::MetadataUnchangedOnly
                }
                CheckStatus::Fail => SettingsPreservation::Fail,
                _ => SettingsPreservation::NotEvaluated,
            },
            fidelity,
            restore_environment_names: ENV_NAMES.iter().map(|s| (*s).into()).collect(),
        }
    }
    pub fn after_restore(
        &mut self,
        health: &Value,
        deadline: Instant,
        tick: &mut dyn FnMut() -> Result<()>,
    ) -> Result<QualificationReport> {
        ensure!(
            self.before_attempted && !self.after_attempted,
            "post-restore checks out of order or repeated"
        );
        self.after_attempted = true;
        let health_result = (|| {
            checkpoint(deadline, tick)?;
            ensure!(
                health_matches(health, &self.plan.expected_health),
                "health subset mismatch"
            );
            Ok(())
        })();
        self.record("Q5_health", health_result);
        let fingerprint = (|| -> Result<()> {
            checkpoint(deadline, tick)?;
            let log = self
                .log_offset
                .as_ref()
                .context("R0 log offset unavailable")?
                .appended(
                    &self.plan.log_path,
                    self.plan.limits.max_log_bytes,
                    deadline,
                    tick,
                )?;
            match_startup_fingerprint(
                &log.0,
                &self.plan.required_startup_substrings,
                &self.plan.forbidden_startup_substrings,
            )
        })();
        self.record("Q6_startup_fingerprint", fingerprint);
        let references = config_references(&self.plan, deadline, tick).and_then(|m| {
            ensure!(
                m == self.references,
                "config reference metadata or side-effect names changed"
            );
            Ok(())
        });
        self.record("Q4_config_metadata", references);
        Ok(self.report())
    }
    pub fn after_restore_authorized(
        &mut self,
        health: &Value,
        restored: &ProcessIdentity,
        permissions: &AuthorizedPermissions,
        deadline: Instant,
        tick: &mut dyn FnMut() -> Result<()>,
        verify_service: &mut dyn FnMut(&ProcessIdentity) -> Result<()>,
    ) -> Result<QualificationReport> {
        let mut report = self.after_restore(health, deadline, tick)?;
        let compare = (|| -> Result<()> {
            permissions.validate_for(&self.plan, &self.gate.old_identity)?;
            ensure!(
                permissions.transaction_sha256 == self.gate.transaction_sha256,
                "fidelity transaction mismatch"
            );
            ensure!(
                report.checks["Q5_health"] == CheckStatus::Pass,
                "X3 restored read requires Q5 health"
            );
            ensure!(
                restored.pid != self.gate.old_identity.pid
                    && restored.uid == self.gate.old_identity.uid
                    && restored.cwd == self.gate.old_identity.cwd
                    && restored.ppid == 1
                    && restored.pgid == restored.pid
                    && restored.sid == restored.pid as i32,
                "restored process identity mismatch"
            );
            let new_snapshot = collect_x3(
                &self.plan,
                permissions,
                restored,
                deadline,
                tick,
                verify_service,
            )?;
            let catalog = &permissions
                .reviewed
                .x3
                .as_ref()
                .context("X3 unavailable")?
                .profile_catalog;
            let comparison = self.gate.old_snapshot.compare(&new_snapshot, catalog)?;
            let equal = comparison.equal;
            report.fidelity.restored_profile = Some(new_snapshot.summary().clone());
            report.fidelity.profile_comparison = Some(comparison);
            ensure!(equal, "source-exposed configured profiles differ");
            checkpoint(deadline, tick)?;
            Ok(())
        })();
        match compare {
            Ok(()) => {
                report.exposed_effective_settings_equal = FidelityStatus::Pass;
                // F2 is not established until the service merges its actual Q2
                // exec-time launch record; constructed PF3 alone is insufficient.
                report.fidelity_qualified =
                    if report.checks["Q3_runtime_manifest"] == CheckStatus::Pass {
                        FidelityStatus::NotEvaluated
                    } else {
                        FidelityStatus::Fail
                    };
                report.fidelity.dimensions.insert(FidelityDimension::OldEffectiveProfile, "PASS for the exhaustive reviewed source-exposed configured profile only; no full-profile, on-disk or runtime-state equivalence claim".into());
                report.fidelity.dimensions.insert(
                    FidelityDimension::EffectiveConcurrency,
                    "old and restored exposed in-memory concurrency observed as 8".into(),
                );
            }
            Err(error) => {
                report.exposed_effective_settings_equal =
                    if report.checks["Q5_health"] == CheckStatus::Pass {
                        FidelityStatus::Fail
                    } else {
                        FidelityStatus::NotEvaluated
                    };
                report.fidelity_qualified = FidelityStatus::Fail;
                report
                    .failures
                    .insert("F1_exposed_effective_settings".into(), error.to_string());
            }
        }
        Ok(report)
    }
}

// Buffers holding credentials, process environment or unredacted responses must
// never implement Debug/Serialize or be attached to error context.
struct SecretBytes(Vec<u8>);
impl Drop for SecretBytes {
    fn drop(&mut self) {
        wipe(&mut self.0);
    }
}
struct SecretBuffer<const N: usize>([u8; N]);
impl<const N: usize> Drop for SecretBuffer<N> {
    fn drop(&mut self) {
        wipe(&mut self.0);
    }
}
fn wipe(bytes: &mut [u8]) {
    for byte in bytes {
        unsafe {
            std::ptr::write_volatile(byte, 0);
        }
    }
    std::sync::atomic::compiler_fence(std::sync::atomic::Ordering::SeqCst);
}
fn wipe_value(value: &mut Value) {
    match value {
        Value::String(s) => unsafe {
            wipe(s.as_bytes_mut());
        },
        Value::Array(a) => {
            for item in a {
                wipe_value(item);
            }
        }
        Value::Object(o) => {
            for (mut key, mut item) in std::mem::take(o) {
                unsafe {
                    wipe(key.as_bytes_mut());
                }
                wipe_value(&mut item);
            }
        }
        _ => {}
    }
}
pub(crate) struct SecretJson(pub(crate) Value);
impl Drop for SecretJson {
    fn drop(&mut self) {
        wipe_value(&mut self.0);
    }
}
fn profile_name(name: &[u8]) -> bool {
    [
        b"OMLX_".as_slice(),
        b"DYLD_",
        b"MLX_",
        b"METAL_",
        b"HF_",
        b"TRANSFORMERS_",
        b"TOKENIZERS_",
    ]
    .iter()
    .any(|prefix| name.starts_with(prefix))
        || [
            b"PYTHONPATH".as_slice(),
            b"PYTHONHOME",
            b"PYTHONDONTWRITEBYTECODE",
            b"PYTHONSTARTUP",
            b"PYTHONOPTIMIZE",
            b"PYTHONHASHSEED",
        ]
        .contains(&name)
}
// Literal expected values are source-reviewed construction, NOT observations.
const LAUNCHER_ENV: [(&str, &str); 3] = [
    (
        "PYTHONHOME",
        "/Applications/oMLX.app/Contents/Resources/Python/cpython-3.11",
    ),
    ("PYTHONDONTWRITEBYTECODE", "1"),
    (
        "PYTHONPATH",
        "/Applications/oMLX.app/Contents/Resources:/Applications/oMLX.app/Contents/Resources/Python/framework-mlx-base/lib/python3.11/site-packages",
    ),
];
#[derive(Clone, Debug, Serialize)]
pub struct EnvironmentComparison {
    names: BTreeSet<String>,
    launcher_values_equal: BTreeMap<String, bool>,
    additional_profile_names: bool,
}
impl EnvironmentComparison {
    fn qualifies(&self) -> bool {
        !self.additional_profile_names
            && self.launcher_values_equal.len() == LAUNCHER_ENV.len()
            && LAUNCHER_ENV
                .iter()
                .all(|(name, _)| self.launcher_values_equal.get(*name) == Some(&true))
    }
}
fn parse_procargs_comparison(bytes: &[u8]) -> Result<EnvironmentComparison> {
    ensure!(bytes.len() >= 4, "X2 truncated argument buffer");
    ensure!(bytes.len() < MAX_SECRET, "X2 oversized argument buffer");
    let argc = i32::from_ne_bytes(bytes[..4].try_into()?);
    ensure!((1..=65536).contains(&argc), "X2 invalid argument count");
    let mut offset = 4;
    fn next<'a>(bytes: &'a [u8], offset: &mut usize) -> Result<&'a [u8]> {
        let end = bytes
            .get(*offset..)
            .and_then(|b| b.iter().position(|v| *v == 0))
            .context("X2 truncated string")?
            + *offset;
        let value = &bytes[*offset..end];
        *offset = end + 1;
        Ok(value)
    }
    ensure!(
        !next(bytes, &mut offset)?.is_empty(),
        "X2 missing executable path"
    );
    // 64-bit Darwin aligns the path area to eight bytes. KERN_PROCARGS2
    // strips the 16-byte "executable_path=" prefix; argc is outside that area.
    // Skip only alignment, never empty argv strings (including argv[0]).
    let argv_start = 4 + (offset - 4).next_multiple_of(8);
    ensure!(
        bytes
            .get(offset..argv_start)
            .is_some_and(|padding| padding.iter().all(|b| *b == 0)),
        "X2 invalid executable path padding"
    );
    offset = argv_start;
    for _ in 0..argc {
        next(bytes, &mut offset)?;
    }
    let mut observation = EnvironmentComparison {
        names: BTreeSet::new(),
        launcher_values_equal: BTreeMap::new(),
        additional_profile_names: false,
    };
    // No envc is returned: the environment/apple split cannot be proven.
    // Inspect EVERY nonempty tail string, including after NUL runs. These
    // can exceed alignment when libSystem clears apple values in place.
    // Never whitelist an apple suffix or infer an empty environment from zeros.
    while offset < bytes.len() {
        let entry = next(bytes, &mut offset)?;
        if entry.is_empty() {
            continue;
        }
        let split = entry
            .iter()
            .position(|b| *b == b'=')
            .context("X2 malformed environment entry")?;
        let name = &entry[..split];
        if profile_name(name) {
            ensure!(
                name.len() <= 1024 && name.iter().all(|b| b.is_ascii_alphanumeric() || *b == b'_'),
                "X2 malformed profile name"
            );
            let name_text =
                std::str::from_utf8(name).map_err(|_| anyhow::anyhow!("X2 non-ASCII name"))?;
            ensure!(
                observation.names.insert(name_text.to_owned()),
                "X2 duplicate profile environment name"
            );
            if let Some((_, expected)) = LAUNCHER_ENV
                .iter()
                .find(|(known, _)| known.as_bytes() == name)
            {
                observation.launcher_values_equal.insert(
                    name_text.to_owned(),
                    &entry[split + 1..] == expected.as_bytes(),
                );
            } else {
                observation.additional_profile_names = true;
            }
        }
    }
    ensure!(
        observation.launcher_values_equal.len() == LAUNCHER_ENV.len(),
        "X2 launcher environment unavailable or incomplete"
    );
    Ok(observation)
}
fn collect_x2(
    permissions: &AuthorizedPermissions,
    deadline: Instant,
    tick: &mut dyn FnMut() -> Result<()>,
) -> Result<EnvironmentComparison> {
    ensure!(
        permissions.reviewed.x2_launcher_private_comparison,
        "X2 private comparison not granted"
    );
    consume_permission(&permissions.usage.x2)?;
    checkpoint(deadline, tick)?;
    let expected = permissions.old_identity();
    verify_identity(expected)?;
    #[cfg(target_os = "macos")]
    {
        // One bounded KERN_PROCARGS2 operation; never emits values or the buffer.
        let mut buffer = SecretBytes(vec![0; MAX_SECRET]);
        let mut length = buffer.0.len();
        let mut mib = [
            libc::CTL_KERN,
            libc::KERN_PROCARGS2,
            i32::try_from(expected.pid)?,
        ];
        let result = unsafe {
            libc::sysctl(
                mib.as_mut_ptr(),
                mib.len() as u32,
                buffer.0.as_mut_ptr().cast(),
                &mut length,
                std::ptr::null_mut(),
                0,
            )
        };
        ensure!(
            // A short-buffer copy returns exactly the allocation (argc included).
            // Reject exact fits too; no second size query/private observation.
            result == 0 && length > 0 && length < buffer.0.len(),
            "X2 unavailable or truncated"
        );
        checkpoint(deadline, tick)?;
        verify_identity(expected)?;
        parse_procargs_comparison(&buffer.0[..length])
    }
    #[cfg(not(target_os = "macos"))]
    {
        bail!("X2 KERN_PROCARGS2 requires macOS")
    }
}
fn validate_credential_metadata(metadata: &MetadataRecord) -> Result<()> {
    ensure!(
        metadata.exists
            && metadata.mode & libc::S_IFMT as u32 == libc::S_IFREG as u32
            && metadata.size > 0
            && metadata.size <= MAX_SECRET as u64
            && metadata.mode & 0o077 == 0
            && metadata.uid == unsafe { libc::geteuid() },
        "X3 credential reference is not private/bounded regular data"
    );
    Ok(())
}
fn check_credential_config_aliases(
    plan: &QualificationPlan,
    reference: &CredentialReference,
    expected: &MetadataRecord,
    deadline: Instant,
    tick: &mut dyn FnMut() -> Result<()>,
) -> Result<()> {
    for (index, path) in plan.config_paths().into_iter().enumerate() {
        checkpoint(deadline, tick)?;
        let metadata = reference_metadata(path)
            .map_err(|_| anyhow::anyhow!("X3 config reference metadata unavailable"))?;
        if reference.allow_settings_api_key_projection && index == 0 {
            ensure!(expected == &metadata, "X3 credential reference changed");
        } else {
            ensure!(
                !expected.same_inode(&metadata),
                "X3 credential reference aliases a metadata-only config reference"
            );
        }
    }
    Ok(())
}
fn credential_bytes(
    plan: &QualificationPlan,
    reference: &CredentialReference,
    deadline: Instant,
    tick: &mut dyn FnMut() -> Result<()>,
) -> Result<SecretBytes> {
    reference.validate_for(plan)?;
    checkpoint(deadline, tick)?;
    let before = reference_metadata(&reference.path)
        .map_err(|_| anyhow::anyhow!("X3 credential reference metadata unavailable"))?;
    validate_credential_metadata(&before)?;
    check_credential_config_aliases(plan, reference, &before, deadline, tick)?;
    let mut file = open_regular(&reference.path)
        .map_err(|_| anyhow::anyhow!("X3 credential reference unavailable"))?;
    ensure!(
        before == MetadataRecord::from_metadata(&file.metadata()?),
        "X3 credential reference open raced"
    );
    let bytes = read_exact_bounded(&mut file, before.size, deadline, tick)
        .map_err(|_| anyhow::anyhow!("X3 credential read failed"))?;
    check_credential_config_aliases(plan, reference, &before, deadline, tick)?;
    // Reopen without following any symlink, including swapped ancestors.
    // This descriptor is used only for metadata; no second content read occurs.
    let current = open_regular(&reference.path)
        .map_err(|_| anyhow::anyhow!("X3 credential reference changed"))?;
    ensure!(
        before == MetadataRecord::from_metadata(&file.metadata()?)
            && before == MetadataRecord::from_metadata(&current.metadata()?)
            && before
                == reference_metadata(&reference.path)
                    .map_err(|_| anyhow::anyhow!("X3 credential reference metadata unavailable"))?,
        "X3 credential reference changed"
    );
    if let Some(pointer) = &reference.json_pointer {
        let parsed: Value = serde_json::from_slice(&bytes.0)
            .map_err(|_| anyhow::anyhow!("X3 credential projection invalid JSON"))?;
        let mut parsed = SecretJson(parsed);
        let key = parsed
            .0
            .pointer_mut(pointer)
            .context("X3 credential projection unavailable")?;
        ensure!(
            key.as_str()
                .is_some_and(|value| !value.is_empty() && value.len() <= 8192),
            "X3 credential projection invalid"
        );
        let Value::String(key) = key.take() else {
            unreachable!("credential string type checked");
        };
        Ok(SecretBytes(key.into_bytes()))
    } else {
        ensure!(
            bytes.0.len() <= 8192 && std::str::from_utf8(&bytes.0).is_ok(),
            "X3 credential bytes invalid"
        );
        Ok(bytes)
    }
}
struct HttpResponse {
    bytes: SecretBytes,
    body_offset: usize,
}
impl HttpResponse {
    fn body(&self) -> &[u8] {
        &self.bytes.0[self.body_offset..]
    }
    fn cookie(&self, name: &str) -> Result<SecretBytes> {
        let header = std::str::from_utf8(&self.bytes.0[..self.body_offset])
            .map_err(|_| anyhow::anyhow!("X3 response headers invalid"))?;
        let mut found = None;
        for line in header.split("\r\n") {
            if let Some((key, value)) = line.split_once(':')
                && key.eq_ignore_ascii_case("set-cookie")
            {
                let pair = value
                    .trim()
                    .split(';')
                    .next()
                    .context("X3 missing session cookie")?;
                if pair
                    .split_once('=')
                    .is_some_and(|(k, v)| k == name && !v.is_empty())
                {
                    ensure!(
                        found.is_none()
                            && pair.len() <= 8192
                            && pair.bytes().all(|b| (0x21..=0x7e).contains(&b)),
                        "X3 ambiguous/invalid session cookie"
                    );
                    found = Some(SecretBytes(pair.as_bytes().to_vec()));
                }
            }
        }
        found.context("X3 reviewed session cookie missing")
    }
}
fn admin_request(
    method: &str,
    endpoint: &str,
    body: &[u8],
    cookie: Option<&SecretBytes>,
    deadline: Instant,
    tick: &mut dyn FnMut() -> Result<()>,
) -> Result<HttpResponse> {
    ensure!(
        matches!(
            (method, endpoint),
            ("POST", "/admin/api/login")
                | ("GET", "/admin/api/global-settings")
                | ("GET", "/admin/api/models")
        ),
        "X3 endpoint not permitted"
    );
    checkpoint(deadline, tick)?;
    let address: SocketAddr = "127.0.0.1:8000".parse()?;
    let timeout = deadline
        .saturating_duration_since(Instant::now())
        .min(Duration::from_millis(100));
    ensure!(!timeout.is_zero(), "X3 deadline elapsed");
    let mut stream = TcpStream::connect_timeout(&address, timeout)
        .map_err(|_| anyhow::anyhow!("X3 local connection failed"))?;
    stream.set_nonblocking(true)?;
    let mut request = SecretBytes(format!("{method} {endpoint} HTTP/1.1\r\nHost: 127.0.0.1:8000\r\nConnection: close\r\nContent-Type: application/json\r\nContent-Length: {}\r\n", body.len()).into_bytes());
    // Reserve before copying any credential/session bytes so growth cannot
    // leave an abandoned allocation containing secret request fragments.
    request
        .0
        .reserve_exact(body.len() + cookie.map_or(0, |c| c.0.len() + 10) + 2);
    if let Some(cookie) = cookie {
        request.0.extend_from_slice(b"Cookie: ");
        request.0.extend_from_slice(&cookie.0);
        request.0.extend_from_slice(b"\r\n");
    }
    request.0.extend_from_slice(b"\r\n");
    request.0.extend_from_slice(body);
    let mut sent = 0;
    while sent < request.0.len() {
        checkpoint(deadline, tick)?;
        match stream.write(&request.0[sent..]) {
            Ok(0) => bail!("X3 connection closed during request"),
            Ok(n) => sent += n,
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                std::thread::sleep(Duration::from_millis(5))
            }
            Err(_) => bail!("X3 request failed"),
        }
    }
    let mut response = SecretBytes(Vec::with_capacity(MAX_HTTP));
    let mut scratch = SecretBytes(vec![0; 16 * 1024]);
    loop {
        checkpoint(deadline, tick)?;
        match stream.read(&mut scratch.0) {
            Ok(0) => break,
            Ok(n) => {
                ensure!(
                    response.0.len() + n <= MAX_HTTP,
                    "X3 response exceeds bound"
                );
                response.0.extend_from_slice(&scratch.0[..n]);
            }
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                std::thread::sleep(Duration::from_millis(5))
            }
            Err(_) => bail!("X3 response read failed"),
        }
    }
    let offset = response
        .0
        .windows(4)
        .position(|w| w == b"\r\n\r\n")
        .context("X3 invalid HTTP response")?
        + 4;
    ensure!(offset <= 64 * 1024, "X3 response headers exceed bound");
    let header = std::str::from_utf8(&response.0[..offset])
        .map_err(|_| anyhow::anyhow!("X3 invalid response headers"))?;
    let mut lines = header.split("\r\n");
    ensure!(
        lines
            .next()
            .is_some_and(|s| s.starts_with("HTTP/1.1 200 ") || s.starts_with("HTTP/1.0 200 ")),
        "X3 admin request denied or failed"
    );
    let mut length = None;
    for line in lines.filter(|l| !l.is_empty()) {
        let (name, value) = line
            .split_once(':')
            .context("X3 malformed response header")?;
        ensure!(
            !name.eq_ignore_ascii_case("transfer-encoding")
                && !name.eq_ignore_ascii_case("content-encoding"),
            "X3 encoded response not permitted"
        );
        if name.eq_ignore_ascii_case("content-length") {
            ensure!(length.is_none(), "X3 ambiguous response length");
            length = Some(
                value
                    .trim()
                    .parse::<usize>()
                    .map_err(|_| anyhow::anyhow!("X3 invalid response length"))?,
            );
        }
    }
    ensure!(
        length == Some(response.0.len() - offset),
        "X3 missing/truncated response length"
    );
    Ok(HttpResponse {
        bytes: response,
        body_offset: offset,
    })
}
fn collect_x3(
    plan: &QualificationPlan,
    permissions: &AuthorizedPermissions,
    identity: &ProcessIdentity,
    deadline: Instant,
    tick: &mut dyn FnMut() -> Result<()>,
    verify_service: &mut dyn FnMut(&ProcessIdentity) -> Result<()>,
) -> Result<ProfileSnapshot> {
    permissions.reviewed.validate()?;
    let reviewed = permissions.reviewed.x3.as_ref().context("X3 unavailable")?;
    if permissions.old_identity().same_process(identity) {
        consume_permission(&permissions.usage.old_x3)?;
    } else {
        let old = permissions.old_identity();
        ensure!(
            identity.pid != old.pid
                && identity.uid == old.uid
                && identity.cwd == old.cwd
                && identity.ppid == 1
                && identity.pgid == identity.pid
                && identity.sid == identity.pid as i32,
            "X3 restored identity is outside the authorized service binding"
        );
        consume_permission(&permissions.usage.restored_x3)?;
    }
    let verify = |tick: &mut dyn FnMut() -> Result<()>,
                  verify_service: &mut dyn FnMut(&ProcessIdentity) -> Result<()>|
     -> Result<()> {
        checkpoint(deadline, tick)?;
        verify_identity(identity)?;
        verify_service(identity)?;
        Ok(())
    };
    verify(tick, verify_service)?;
    let key = credential_bytes(plan, &reviewed.credential, deadline, tick)?;
    let key_text = std::str::from_utf8(&key.0)
        .map_err(|_| anyhow::anyhow!("X3 credential encoding invalid"))?;
    let mut login = SecretJson(Value::Object(serde_json::Map::new()));
    login
        .0
        .as_object_mut()
        .context("X3 login construction failed")?
        .insert(
            reviewed.login_key_field.clone(),
            Value::String(key_text.to_owned()),
        );
    let mut body = SecretBytes(Vec::with_capacity(64 * 1024));
    serde_json::to_writer(&mut body.0, &login.0)
        .map_err(|_| anyhow::anyhow!("X3 login construction failed"))?;
    verify(tick, verify_service)?;
    let response = admin_request("POST", "/admin/api/login", &body.0, None, deadline, tick)?;
    verify(tick, verify_service)?;
    let cookie = response.cookie(&reviewed.session_cookie_name)?;
    drop(response);
    drop(body);
    drop(login);
    drop(key);
    let mut raw = SecretJson(Value::Object(serde_json::Map::new()));
    for (name, endpoint) in [
        ("global_settings", "/admin/api/global-settings"),
        ("models", "/admin/api/models"),
    ] {
        verify(tick, verify_service)?;
        let response = admin_request("GET", endpoint, &[], Some(&cookie), deadline, tick)?;
        verify(tick, verify_service)?;
        let mut json = SecretJson(
            serde_json::from_slice(response.body())
                .map_err(|_| anyhow::anyhow!("X3 invalid admin JSON"))?,
        );
        ensure!(json.0.is_object(), "X3 invalid settings response shape");
        raw.0
            .as_object_mut()
            .context("private response assembly failed")?
            .insert(name.into(), std::mem::take(&mut json.0));
    }
    verify(tick, verify_service)?;
    let snapshot = ProfileSnapshot::capture(std::mem::take(&mut raw.0), &reviewed.profile_catalog)?;
    checkpoint(deadline, tick)?;
    Ok(snapshot)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    use std::os::unix::fs::PermissionsExt;

    const CREDENTIAL_FIXTURE_KEY: &str = "synthetic-credential-alpha";
    const CREDENTIAL_FIXTURE_PRIVATE: &str = "synthetic-unrelated-private-value";

    fn credential_fixture() -> (tempfile::TempDir, QualificationPlan, CredentialReference) {
        let dir = tempfile::tempdir().unwrap();
        let root = fs::canonicalize(dir.path()).unwrap();
        let plan = fixture_plan(&root);
        write_private_credential(
            &plan.settings_path,
            &serde_json::to_vec(&json!({
                "auth": {"api_key": CREDENTIAL_FIXTURE_KEY},
                "unrelated": CREDENTIAL_FIXTURE_PRIVATE,
            }))
            .unwrap(),
        );
        let reference = CredentialReference {
            path: plan.settings_path.clone(),
            json_pointer: Some("/auth/api_key".into()),
            allow_settings_api_key_projection: true,
        };
        (dir, plan, reference)
    }

    fn write_private_credential(path: &Path, bytes: &[u8]) {
        fs::write(path, bytes).unwrap();
        fs::set_permissions(path, fs::Permissions::from_mode(0o600)).unwrap();
    }

    fn assert_credential_denied<T>(result: Result<T>) {
        let error = result.err().expect("credential access must fail closed");
        let diagnostic = format!("{error:#} {error:?}");
        assert!(!diagnostic.contains(CREDENTIAL_FIXTURE_KEY));
        assert!(!diagnostic.contains(CREDENTIAL_FIXTURE_PRIVATE));
    }

    fn credential_permissions(
        plan: &QualificationPlan,
        reference: &CredentialReference,
    ) -> AuthorizedPermissions {
        let mut reviewed = fixture_reviewed();
        reviewed.plan_sha256 = plan.sha256().unwrap();
        reviewed.x3.as_mut().unwrap().credential = reference.clone();
        AuthorizedPermissions::from_transaction_authorization(&reviewed, &"a".repeat(64)).unwrap()
    }

    #[test]
    fn credential_settings_projection_requires_explicit_serialized_permission() {
        for permission in [None, Some(json!(null)), Some(json!("true"))] {
            let mut raw = json!({
                "path": "/synthetic/settings.json",
                "json_pointer": "/auth/api_key",
            });
            if let Some(permission) = permission {
                raw["allow_settings_api_key_projection"] = permission;
            }
            assert!(serde_json::from_value::<CredentialReference>(raw).is_err());
        }
        let (_dir, plan, reference) = credential_fixture();
        let reference: CredentialReference =
            serde_json::from_value(serde_json::to_value(reference).unwrap()).unwrap();
        let permissions = credential_permissions(&plan, &reference);
        permissions
            .validate_for(&plan, permissions.old_identity())
            .unwrap();
        let key = credential_bytes(
            &plan,
            &reference,
            Instant::now() + Duration::from_secs(5),
            &mut || Ok(()),
        )
        .unwrap();
        assert!(key.0 == CREDENTIAL_FIXTURE_KEY.as_bytes());
    }

    #[test]
    fn credential_projection_requires_lexically_exact_settings_path() {
        let (_dir, plan, reference) = credential_fixture();
        let parent = plan.settings_path.parent().unwrap().display();
        for path in [
            format!("{parent}/./settings.json"),
            format!("{parent}//settings.json"),
        ] {
            let alternate = CredentialReference {
                path: path.into(),
                ..reference.clone()
            };
            assert!(alternate.validate_for(&plan).is_err());
        }
    }
    #[test]
    fn credential_projection_permission_cannot_widen_path_or_pointer() {
        let (_dir, plan, reference) = credential_fixture();
        let mut denied = vec![CredentialReference {
            allow_settings_api_key_projection: false,
            ..reference.clone()
        }];
        for pointer in [
            None,
            Some("/auth"),
            Some("/auth/api_key/"),
            Some("/auth/api~1key"),
            Some("/auth/other"),
        ] {
            denied.push(CredentialReference {
                json_pointer: pointer.map(str::to_owned),
                ..reference.clone()
            });
        }
        for path in plan.config_paths().into_iter().skip(1).chain([
            plan.bundle_contents.as_path(),
            plan.reference_worktree.as_path(),
        ]) {
            for allowed in [false, true] {
                denied.push(CredentialReference {
                    path: path.to_path_buf(),
                    allow_settings_api_key_projection: allowed,
                    ..reference.clone()
                });
            }
        }
        denied.push(CredentialReference {
            path: plan.settings_path.with_file_name("standalone"),
            ..reference
        });
        for reference in denied {
            let permissions = credential_permissions(&plan, &reference);
            assert_credential_denied(permissions.validate_for(&plan, permissions.old_identity()));
            let mut ticked = false;
            assert_credential_denied(credential_bytes(
                &plan,
                &reference,
                Instant::now() + Duration::from_secs(5),
                &mut || {
                    ticked = true;
                    Ok(())
                },
            ));
            assert!(!ticked, "permission denial must precede file access");
        }
    }

    #[test]
    fn credential_standalone_private_raw_and_json_references_remain_supported() {
        let (_dir, plan, _) = credential_fixture();
        let path = plan.settings_path.with_file_name("standalone");
        for pointer in [None, Some("/private/key")] {
            let bytes = if pointer.is_some() {
                serde_json::to_vec(&json!({
                    "private": {"key": CREDENTIAL_FIXTURE_KEY},
                    "unrelated": CREDENTIAL_FIXTURE_PRIVATE,
                }))
                .unwrap()
            } else {
                CREDENTIAL_FIXTURE_KEY.as_bytes().to_vec()
            };
            write_private_credential(&path, &bytes);
            let reference = CredentialReference {
                path: path.clone(),
                json_pointer: pointer.map(str::to_owned),
                allow_settings_api_key_projection: false,
            };
            let permissions = credential_permissions(&plan, &reference);
            permissions
                .validate_for(&plan, permissions.old_identity())
                .unwrap();
            let key = credential_bytes(
                &plan,
                &reference,
                Instant::now() + Duration::from_secs(5),
                &mut || Ok(()),
            )
            .unwrap();
            assert!(key.0 == CREDENTIAL_FIXTURE_KEY.as_bytes());
        }
    }

    #[test]
    fn credential_standalone_hardlinks_to_every_pf2_reference_deny_before_read() {
        for config_index in 0..5 {
            let (_dir, plan, _) = credential_fixture();
            let config = plan.config_paths()[config_index];
            write_private_credential(config, CREDENTIAL_FIXTURE_KEY.as_bytes());
            let path = plan.settings_path.with_file_name("standalone");
            fs::hard_link(config, &path).unwrap();
            let reference = CredentialReference {
                path,
                json_pointer: None,
                allow_settings_api_key_projection: false,
            };
            let mut checkpoints = 0;
            assert_credential_denied(credential_bytes(
                &plan,
                &reference,
                Instant::now() + Duration::from_secs(5),
                &mut || {
                    checkpoints += 1;
                    Ok(())
                },
            ));
            assert!(checkpoints < 2 + plan.config_paths().len());
        }
    }

    #[test]
    fn credential_settings_projection_rejects_every_other_pf2_inode_alias() {
        for config_index in 1..5 {
            let (_dir, plan, reference) = credential_fixture();
            fs::hard_link(&reference.path, plan.config_paths()[config_index]).unwrap();
            let mut checkpoints = 0;
            assert_credential_denied(credential_bytes(
                &plan,
                &reference,
                Instant::now() + Duration::from_secs(5),
                &mut || {
                    checkpoints += 1;
                    Ok(())
                },
            ));
            assert!(checkpoints < 2 + plan.config_paths().len());
        }
    }

    #[test]
    fn credential_symlinks_and_nonregular_references_are_never_read() {
        for ancestor in [false, true] {
            let (_dir, plan, mut reference) = credential_fixture();
            if ancestor {
                let actual = plan.settings_path.with_file_name("actual");
                fs::create_dir(&actual).unwrap();
                write_private_credential(&actual.join("key"), CREDENTIAL_FIXTURE_KEY.as_bytes());
                let alias = plan.settings_path.with_file_name("alias");
                std::os::unix::fs::symlink(&actual, &alias).unwrap();
                reference.path = alias.join("key");
                reference.json_pointer = None;
                reference.allow_settings_api_key_projection = false;
            } else {
                let actual = plan.settings_path.with_file_name("actual");
                fs::rename(&reference.path, &actual).unwrap();
                std::os::unix::fs::symlink(&actual, &reference.path).unwrap();
            }
            assert_credential_denied(credential_bytes(
                &plan,
                &reference,
                Instant::now() + Duration::from_secs(5),
                &mut || Ok(()),
            ));
        }
        let (_dir, plan, reference) = credential_fixture();
        fs::remove_file(&reference.path).unwrap();
        fs::create_dir(&reference.path).unwrap();
        assert_credential_denied(credential_bytes(
            &plan,
            &reference,
            Instant::now() + Duration::from_secs(5),
            &mut || Ok(()),
        ));
    }

    #[test]
    fn credential_projection_preserves_mode_owner_and_file_size_boundaries() {
        let (_dir, plan, reference) = credential_fixture();
        for mode in [0o604, 0o640, 0o660, 0o644] {
            fs::set_permissions(&reference.path, fs::Permissions::from_mode(mode)).unwrap();
            assert_credential_denied(credential_bytes(
                &plan,
                &reference,
                Instant::now() + Duration::from_secs(5),
                &mut || Ok(()),
            ));
        }
        fs::set_permissions(&reference.path, fs::Permissions::from_mode(0o400)).unwrap();
        let key = credential_bytes(
            &plan,
            &reference,
            Instant::now() + Duration::from_secs(5),
            &mut || Ok(()),
        )
        .unwrap();
        assert!(key.0 == CREDENTIAL_FIXTURE_KEY.as_bytes());
        let mut wrong_owner = reference_metadata(&reference.path).unwrap();
        wrong_owner.uid = wrong_owner.uid.wrapping_add(1);
        assert_credential_denied(validate_credential_metadata(&wrong_owner));

        fs::set_permissions(&reference.path, fs::Permissions::from_mode(0o600)).unwrap();
        let file = fs::OpenOptions::new()
            .write(true)
            .open(&reference.path)
            .unwrap();
        for size in [0, MAX_SECRET as u64 + 1] {
            file.set_len(size).unwrap();
            let mut checkpoints = 0;
            assert_credential_denied(credential_bytes(
                &plan,
                &reference,
                Instant::now() + Duration::from_secs(5),
                &mut || {
                    checkpoints += 1;
                    Ok(())
                },
            ));
            assert_eq!(checkpoints, 1, "size denial must precede content access");
        }
    }

    #[test]
    fn credential_projection_validates_payload_without_secret_diagnostics() {
        let (_dir, plan, reference) = credential_fixture();
        for bytes in [
            format!(r#"{{"auth":{{"api_key":"{CREDENTIAL_FIXTURE_KEY}"}},"{CREDENTIAL_FIXTURE_PRIVATE}":"#)
                .into_bytes(),
            serde_json::to_vec(&json!({
                "auth": {"api_key": {"private": CREDENTIAL_FIXTURE_KEY}},
                "unrelated": CREDENTIAL_FIXTURE_PRIVATE,
            }))
            .unwrap(),
            serde_json::to_vec(&json!({
                "auth": {"other": CREDENTIAL_FIXTURE_KEY},
                "unrelated": CREDENTIAL_FIXTURE_PRIVATE,
            }))
            .unwrap(),
            serde_json::to_vec(&json!({"auth": {"api_key": ""}})).unwrap(),
            serde_json::to_vec(&json!({"auth": {"api_key": "x".repeat(8193)}})).unwrap(),
        ] {
            write_private_credential(&reference.path, &bytes);
            assert_credential_denied(credential_bytes(
                &plan,
                &reference,
                Instant::now() + Duration::from_secs(5),
                &mut || Ok(()),
            ));
        }
        let mut bytes =
            serde_json::to_vec(&json!({"auth": {"api_key": "x".repeat(8192)}})).unwrap();
        bytes.resize(MAX_SECRET, b' ');
        write_private_credential(&reference.path, &bytes);
        let key = credential_bytes(
            &plan,
            &reference,
            Instant::now() + Duration::from_secs(5),
            &mut || Ok(()),
        )
        .unwrap();
        assert!(key.0 == vec![b'x'; 8192]);
    }

    #[test]
    fn credential_reference_races_fail_closed_before_returning_projection() {
        for after_open in [false, true] {
            for mutation in ["replace", "truncate", "mode", "new_pf2_alias"] {
                let (_dir, plan, reference) = credential_fixture();
                let mutation_checkpoint = 1 + plan.config_paths().len() + usize::from(after_open);
                let mut checkpoints = 0;
                assert_credential_denied(credential_bytes(
                    &plan,
                    &reference,
                    Instant::now() + Duration::from_secs(5),
                    &mut || {
                        checkpoints += 1;
                        if checkpoints == mutation_checkpoint {
                            match mutation {
                                "replace" => {
                                    fs::rename(
                                        &reference.path,
                                        reference.path.with_file_name("previous"),
                                    )?;
                                    write_private_credential(
                                        &reference.path,
                                        br#"{"auth":{"api_key":"replacement"}}"#,
                                    );
                                }
                                "truncate" => {
                                    fs::OpenOptions::new()
                                        .write(true)
                                        .open(&reference.path)?
                                        .set_len(0)?;
                                }
                                "mode" => fs::set_permissions(
                                    &reference.path,
                                    fs::Permissions::from_mode(0o644),
                                )?,
                                "new_pf2_alias" => {
                                    fs::hard_link(&reference.path, &plan.model_settings_path)?;
                                }
                                _ => unreachable!(),
                            }
                        }
                        Ok(())
                    },
                ));
                assert!(checkpoints >= mutation_checkpoint);
            }
        }
    }

    #[test]
    fn credential_ancestor_symlink_swap_during_read_fails_closed() {
        let (_dir, plan, _) = credential_fixture();
        let parent = plan.settings_path.with_file_name("credential-dir");
        let moved = plan.settings_path.with_file_name("moved-credential-dir");
        fs::create_dir(&parent).unwrap();
        let reference = CredentialReference {
            path: parent.join("key"),
            json_pointer: None,
            allow_settings_api_key_projection: false,
        };
        write_private_credential(&reference.path, CREDENTIAL_FIXTURE_KEY.as_bytes());
        let first_read_checkpoint = 2 + plan.config_paths().len();
        let mut checkpoints = 0;
        assert_credential_denied(credential_bytes(
            &plan,
            &reference,
            Instant::now() + Duration::from_secs(5),
            &mut || {
                checkpoints += 1;
                if checkpoints == first_read_checkpoint {
                    fs::rename(&parent, &moved)?;
                    std::os::unix::fs::symlink(&moved, &parent)?;
                }
                Ok(())
            },
        ));
        assert!(checkpoints >= first_read_checkpoint);
    }

    #[test]
    fn metadata_detects_ctime_mode_and_replacement_without_reading_contents() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("opaque");
        fs::write(&path, b"private fixture").unwrap();
        let original = reference_metadata(&path).unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o400)).unwrap();
        assert_ne!(original, reference_metadata(&path).unwrap());
        let mut ctime_only = original.clone();
        ctime_only.ctime_ns += 1;
        assert_ne!(original, ctime_only);
        fs::rename(&path, dir.path().join("previous")).unwrap();
        fs::write(&path, b"private fixture").unwrap();
        assert_ne!(original.ino, reference_metadata(&path).unwrap().ino);
    }
    #[test]
    fn subsequence_forbidden_and_rotation_fail_closed() {
        let required = vec!["stage-one".into(), "stage-two".into()];
        let forbidden = vec!["unsafe-fallback".into()];
        assert!(
            match_startup_fingerprint(
                b"prefix stage-one\nnoise\nstage-two\n",
                &required,
                &forbidden
            )
            .is_ok()
        );
        assert!(
            match_startup_fingerprint(b"stage-two\nstage-one\n", &required, &forbidden).is_err()
        );
        assert!(
            match_startup_fingerprint(
                b"stage-one\nunsafe-fallback\nstage-two\n",
                &required,
                &forbidden
            )
            .is_err()
        );
        let dir = tempfile::tempdir().unwrap();
        let path = fs::canonicalize(dir.path()).unwrap().join("log");
        fs::write(&path, b"old bytes\n").unwrap();
        let offset = LogOffset::capture(&path).unwrap();
        fs::OpenOptions::new()
            .append(true)
            .open(&path)
            .unwrap()
            .write_all(b"stage-one\nstage-two\n")
            .unwrap();
        let deadline = Instant::now() + Duration::from_secs(5);
        assert_eq!(
            offset
                .appended(&path, 1024, deadline, &mut || Ok(()))
                .unwrap()
                .0,
            b"stage-one\nstage-two\n"
        );
        fs::rename(&path, dir.path().join("rotated")).unwrap();
        fs::write(&path, b"new stage-one\nstage-two\n").unwrap();
        assert!(
            offset
                .appended(&path, 1024, deadline, &mut || Ok(()))
                .is_err()
        );
    }
    #[test]
    fn absent_gate_denies_without_invoking_tick_or_stop() {
        let plan = fixture_plan(Path::new("/nonexistent-qualification-fixture"));
        let mut called = false;
        let result =
            QualificationState::preflight(&plan, &BTreeMap::new(), Instant::now(), &mut || {
                called = true;
                Ok(())
            });
        assert!(result.is_err());
        assert!(
            !called,
            "no-grant denial must precede any observer/effect callback"
        );
        assert!(plan.validate_reviewed_permissions(None).is_err());
        assert_eq!(GateReport::default().fidelity_gate, GateStatus::Deny);
    }
    fn launcher_env_fixture() -> Vec<Vec<u8>> {
        LAUNCHER_ENV
            .iter()
            .map(|(name, value)| format!("{name}={value}").into_bytes())
            .collect()
    }
    fn procargs_fixture(argv: &[&[u8]], env: &[Vec<u8>], apple: &[&[u8]]) -> Vec<u8> {
        fn align(bytes: &mut Vec<u8>) {
            bytes.resize(4 + (bytes.len() - 4).next_multiple_of(8), 0);
        }
        let mut bytes = (argv.len() as i32).to_ne_bytes().to_vec();
        bytes.extend_from_slice(b"/bin/tool\0");
        align(&mut bytes);
        for entry in argv.iter().copied().chain(env.iter().map(Vec::as_slice)) {
            bytes.extend_from_slice(entry);
            bytes.push(0);
        }
        align(&mut bytes);
        for entry in apple {
            bytes.extend_from_slice(entry);
            bytes.push(0);
        }
        align(&mut bytes);
        bytes
    }
    #[test]
    fn procargs_scans_all_environment_alignment_variants() {
        for padding in 0..8 {
            let mut env = launcher_env_fixture();
            env.push(format!("SAFE={}", "p".repeat(padding)).into_bytes());
            let bytes = procargs_fixture(
                &[b"tool", b"", b"serve", b""],
                &env,
                &[b"ptr_munge=", b"main_stack=nonsecret"],
            );
            assert!(parse_procargs_comparison(&bytes).unwrap().qualifies());
        }
    }
    #[test]
    fn procargs_empty_argv_cannot_consume_first_environment_override() {
        let argv: &[&[u8]] = &[b""];
        let valid = procargs_fixture(argv, &launcher_env_fixture(), &[b"ptr_munge="]);
        assert!(parse_procargs_comparison(&valid).unwrap().qualifies());
        let mut additional = launcher_env_fixture();
        additional.insert(0, b"OMLX_EXTRA=private".to_vec());
        let bytes = procargs_fixture(argv, &additional, &[b"ptr_munge="]);
        assert!(!parse_procargs_comparison(&bytes).unwrap().qualifies());
        let mut duplicate = launcher_env_fixture();
        duplicate.insert(0, b"PYTHONHOME=private".to_vec());
        let bytes = procargs_fixture(argv, &duplicate, &[b"ptr_munge="]);
        assert!(parse_procargs_comparison(&bytes).is_err());
    }
    #[test]
    fn procargs_checks_overrides_after_long_cleared_apple_runs() {
        let mut bytes = procargs_fixture(&[b"tool"], &launcher_env_fixture(), &[b"ptr_munge="]);
        bytes.extend_from_slice(&[0; 256]);
        bytes.extend_from_slice(b"main_stack=\0");
        bytes.extend_from_slice(&[0; 128]);
        assert!(parse_procargs_comparison(&bytes).unwrap().qualifies());
        for name in [
            "OMLX_X",
            "DYLD_X",
            "MLX_X",
            "METAL_X",
            "HF_X",
            "TRANSFORMERS_X",
            "TOKENIZERS_X",
            "PYTHONSTARTUP",
            "PYTHONOPTIMIZE",
            "PYTHONHASHSEED",
        ] {
            let mut extra = bytes.clone();
            extra.extend_from_slice(format!("{name}=private\0").as_bytes());
            assert!(!parse_procargs_comparison(&extra).unwrap().qualifies());
        }
        for entry in [
            b"PYTHONHOME=private\0".as_slice(),
            b"OMLX_MALFORMED\0",
            b"OMLX_BAD\n=private\0",
            b"OMLX_TRUNCATED=private",
        ] {
            let mut invalid = bytes.clone();
            invalid.extend_from_slice(entry);
            let error = parse_procargs_comparison(&invalid).unwrap_err();
            assert!(!error.to_string().contains("private"));
        }
    }
    #[test]
    fn procargs_cleared_missing_or_partial_exports_are_unavailable() {
        for env in [
            Vec::new(),
            vec![Vec::new(); 512],
            launcher_env_fixture()[..2].to_vec(),
        ] {
            let bytes = procargs_fixture(
                &[b"owned-title", b"", b""],
                &env,
                &[b"ptr_munge=", b"main_stack="],
            );
            assert!(parse_procargs_comparison(&bytes).is_err());
        }
    }
    #[test]
    fn procargs_rejects_invalid_framing_without_disclosure() {
        let valid = procargs_fixture(&[b"tool"], &launcher_env_fixture(), &[]);
        for length in 0..4 {
            assert!(parse_procargs_comparison(&valid[..length]).is_err());
        }
        for argc in [-1i32, 0, 65537] {
            let mut invalid = valid.clone();
            invalid[..4].copy_from_slice(&argc.to_ne_bytes());
            assert!(parse_procargs_comparison(&invalid).is_err());
        }
        let mut invalid_padding = valid.clone();
        invalid_padding[14] = b'x'; // First alignment byte after /bin/tool NUL.
        assert!(parse_procargs_comparison(&invalid_padding).is_err());
        let mut empty_path = valid.clone();
        empty_path[4] = 0;
        assert!(parse_procargs_comparison(&empty_path).is_err());
        let mut oversized = valid;
        oversized.resize(MAX_SECRET, 0);
        assert!(parse_procargs_comparison(&oversized).is_err());
        let mut truncated = 1i32.to_ne_bytes().to_vec();
        truncated.extend_from_slice(b"private");
        let error = parse_procargs_comparison(&truncated).unwrap_err();
        assert!(!error.to_string().contains("private"));
    }
    #[test]
    fn procargs_argument_count_bound_includes_empty_arguments() {
        let argv = vec![b"".as_slice(); 65536];
        let bytes = procargs_fixture(&argv, &launcher_env_fixture(), &[b"ptr_munge="]);
        assert!(parse_procargs_comparison(&bytes).unwrap().qualifies());
    }
    #[test]
    fn launcher_exports_require_private_value_equality_without_secret_output() {
        fn buffer(suffix: &str, extra: bool) -> Vec<u8> {
            let mut env = vec![b"GRILL_OMLX_API_KEY=private".to_vec()];
            for (name, value) in LAUNCHER_ENV {
                let suffix = if name == "PYTHONPATH" { suffix } else { "" };
                env.push(format!("{name}={value}{suffix}").into_bytes());
            }
            if extra {
                env.push(b"OMLX_X=private".to_vec());
            }
            procargs_fixture(&[b"tool", b"serve"], &env, &[b"ptr_munge="])
        }
        let valid = parse_procargs_comparison(&buffer("", false)).unwrap();
        assert!(valid.qualifies());
        assert_eq!(
            valid.names,
            LAUNCHER_ENV
                .iter()
                .map(|(name, _)| (*name).to_owned())
                .collect()
        );
        assert!(
            !parse_procargs_comparison(&buffer(":private", false))
                .unwrap()
                .qualifies()
        );
        assert!(
            !parse_procargs_comparison(&buffer("", true))
                .unwrap()
                .qualifies()
        );
        let output = serde_json::to_string(&valid).unwrap();
        assert!(!output.contains("private") && !output.contains("/Applications"));
    }
    #[test]
    fn environment_cannot_hide_concurrency_override() {
        let mut env: BTreeMap<String, String> = ENV_NAMES
            .iter()
            .map(|name| ((*name).into(), "explicit".into()))
            .collect();
        env.insert("PATH".into(), RESTORE_PATH.into());
        assert!(validate_restore_environment(&env).is_ok());
        env.insert("OMLX_MAX_CONCURRENT_REQUESTS".into(), "8".into());
        assert!(validate_restore_environment(&env).is_err());
    }
    fn fixture_plan(root: &Path) -> QualificationPlan {
        QualificationPlan {
            bundle_contents: root.join("Contents"),
            reference_worktree: root.join("worktree"),
            expected_git_revision: "0".repeat(40),
            settings_path: root.join("settings.json"),
            model_settings_path: root.join("model_settings.json"),
            model_profiles_path: root.join("model_profiles.json"),
            global_templates_path: root.join("global_templates.json"),
            bootstrap_path: root.join("base-path"),
            log_path: root.join("log"),
            expected_health: json!({"status":"healthy","default_model":"fixture","engine_pool":{"model_count":1,"loaded_count":0}}),
            required_startup_substrings: vec!["stage-one".into()],
            forbidden_startup_substrings: vec!["unsafe-fallback".into()],
            limits: QualificationLimits::default(),
        }
    }
    fn fixture_reviewed() -> ReviewedPermissionInput {
        ReviewedPermissionInput {
            review_reference: "synthetic-review".into(),
            plan_sha256: "0".repeat(64),
            old_identity: ProcessIdentity {
                pid: 200,
                ppid: 1,
                pgid: 200,
                sid: 200,
                uid: 501,
                start_seconds: 1,
                start_subseconds: 2,
                executable: "/fixture/program".into(),
                cwd: "/fixture/cwd".into(),
                state: crate::process_scope::ProcessState::Running,
            },
            x2_launcher_private_comparison: true,
            existing_log_observation_review_reference: "synthetic-log-review".into(),
            launch_scope: ReviewedLaunchScope {
                review_reference: "synthetic-scope".into(),
                source_review_reference: "synthetic-scope-source".into(),
                allow_metadata_name_observation: true,
                restore_home: "/fixture".into(),
                runtime_directory: "/fixture/.omlx/cluster/runtime".into(),
                manifest_prefix: "launch-".into(),
                manifest_suffix: ".json".into(),
                max_entries: 4096,
            },
            x3: Some(ReviewedX3Input {
                review_reference: "synthetic-protocol".into(),
                credential: CredentialReference {
                    path: "/fixture/key-reference".into(),
                    json_pointer: None,
                    allow_settings_api_key_projection: false,
                },
                login_key_field: "api_key".into(),
                session_cookie_name: "session".into(),
                profile_catalog: fixture_profile_catalog(),
            }),
            residuals_review_reference: "synthetic-residual-review".into(),
        }
    }
    fn fixture_profile_catalog() -> ProfileCatalog {
        use crate::qualification_profile::{ComparisonMode, ProfileRule, ProfileShape};
        fn rule(shape: ProfileShape) -> ProfileRule {
            ProfileRule {
                required: true,
                comparison: ComparisonMode::Public,
                shape,
            }
        }
        fn object(fields: &[(&str, ProfileRule)]) -> ProfileRule {
            rule(ProfileShape::Object {
                fields: fields
                    .iter()
                    .map(|(key, value)| ((*key).into(), value.clone()))
                    .collect(),
            })
        }
        let boolean = || rule(ProfileShape::Boolean {});
        let mut settings = object(&[("is_pinned", boolean()), ("is_default", boolean())]);
        settings.required = false;
        ProfileCatalog {
            source_review_reference: "synthetic-source".into(),
            coverage_review_reference: "synthetic-coverage".into(),
            model_ids: vec!["fixture".into()],
            virtual_model_id: None,
            global_settings: object(&[
                (
                    "scheduler",
                    object(&[("max_concurrent_requests", rule(ProfileShape::Integer {}))]),
                ),
                (
                    "auth",
                    object(&[
                        ("api_key_set", boolean()),
                        ("skip_api_key_verification", boolean()),
                    ]),
                ),
                (
                    "server",
                    object(&[
                        ("distributed_inference_active", boolean()),
                        ("distributed_inference_enabled", boolean()),
                    ]),
                ),
            ]),
            model: object(&[
                (
                    "id",
                    rule(ProfileShape::Enum {
                        values: vec!["fixture".into()],
                    }),
                ),
                ("pinned", boolean()),
                ("is_default", boolean()),
                ("settings", settings),
                ("distributed", boolean()),
                ("cluster", rule(ProfileShape::Null {})),
            ]),
            virtual_model: None,
        }
    }
    #[test]
    fn corrupt_and_profile_backup_names_are_detected_without_reading_files() {
        let dir = tempfile::tempdir().unwrap();
        let plan = fixture_plan(dir.path());
        fs::write(&plan.settings_path, b"opaque").unwrap();
        fs::write(&plan.model_settings_path, b"opaque").unwrap();
        let deadline = Instant::now() + Duration::from_secs(5);
        let baseline = config_references(&plan, deadline, &mut || Ok(())).unwrap();
        fs::write(dir.path().join("settings.json.corrupt-fixture"), b"opaque").unwrap();
        let corrupt = config_references(&plan, deadline, &mut || Ok(())).unwrap();
        assert_ne!(baseline, corrupt);
        assert!(
            corrupt
                .side_effect_entry_names
                .contains("settings.json.corrupt-fixture")
        );
        fs::create_dir(dir.path().join("profile-reference-backup-fixture")).unwrap();
        let backup = config_references(&plan, deadline, &mut || Ok(())).unwrap();
        assert_ne!(corrupt, backup);
        assert!(
            backup
                .side_effect_entry_names
                .contains("profile-reference-backup-fixture")
        );
    }
    #[test]
    fn operational_pass_without_fidelity_does_not_resume_gui() {
        let mut report = QualificationReport {
            operational_checks_passed: true,
            startup_operational: CheckStatus::NotEvaluated,
            checks: [("Q3_runtime_manifest".into(), CheckStatus::Pass)]
                .into_iter()
                .collect(),
            failures: BTreeMap::new(),
            fidelity_gate: GateReport {
                fidelity_gate: GateStatus::Pass,
                launch_scope: None,
                checks: BTreeMap::new(),
                reasons: Vec::new(),
            },
            fidelity_qualified: FidelityStatus::NotEvaluated,
            exposed_effective_settings_equal: FidelityStatus::NotEvaluated,
            settings_preservation: SettingsPreservation::MetadataUnchangedOnly,
            fidelity: FidelityReport::default(),
            restore_environment_names: Vec::new(),
        };
        report.record_service_checks(true, true);
        assert_eq!(report.startup_operational, CheckStatus::Pass);
        assert!(!report.gui_resume_allowed(true, true));
        report.exposed_effective_settings_equal = FidelityStatus::Pass;
        report.record_service_checks(true, true);
        assert!(report.gui_resume_allowed(true, true));
        assert!(!report.gui_resume_allowed(true, false));
    }
    #[test]
    fn full_bundle_includes_native_files_and_internal_symlink_targets() {
        let dir = tempfile::tempdir().unwrap();
        let root = fs::canonicalize(dir.path()).unwrap();
        fs::create_dir(root.join("native")).unwrap();
        fs::write(root.join("native/library.bin"), b"native-code-a").unwrap();
        std::os::unix::fs::symlink("native/library.bin", root.join("alias")).unwrap();
        let limits = QualificationLimits::default();
        let deadline = Instant::now() + Duration::from_secs(5);
        let manifest = |root: &Path| {
            let mut walker = ManifestWalker {
                root: root.to_owned(),
                limits: &limits,
                entries: BTreeMap::new(),
                total_bytes: 0,
                active_dirs: BTreeSet::new(),
            };
            walker.walk(root, Path::new(""), 0, deadline, &mut || Ok(()))?;
            Ok::<_, anyhow::Error>(walker.entries)
        };
        let before = manifest(&root).unwrap();
        assert_eq!(
            before[Path::new("alias")].sha256,
            before[Path::new("native/library.bin")].sha256
        );
        assert_eq!(
            before[Path::new("alias")].target_metadata.ino,
            before[Path::new("native/library.bin")].metadata.ino
        );
        fs::write(root.join("native/library.bin"), b"native-code-b").unwrap();
        let after = manifest(&root).unwrap();
        assert_ne!(
            before[Path::new("native/library.bin")].sha256,
            after[Path::new("native/library.bin")].sha256
        );
        let outside = tempfile::tempdir().unwrap();
        fs::write(outside.path().join("opaque"), b"never-hash").unwrap();
        std::os::unix::fs::symlink(outside.path().join("opaque"), root.join("escape")).unwrap();
        assert!(manifest(&root).is_err());
    }
    #[test]
    fn qualification_scope_failure_is_sticky_before_replacement() {
        let dir = tempfile::tempdir().unwrap();
        let home = fs::canonicalize(dir.path()).unwrap();
        let mut reviewed = fixture_reviewed();
        reviewed.launch_scope.restore_home = home.clone();
        reviewed.launch_scope.runtime_directory = home.join(".omlx/cluster/runtime");
        fs::create_dir_all(&reviewed.launch_scope.runtime_directory).unwrap();
        let snapshot = ProfileSnapshot::capture(json!({
            "global_settings": {
                "scheduler": {"max_concurrent_requests": 8},
                "auth": {"api_key_set": true, "skip_api_key_verification": false},
                "server": {"distributed_inference_active": false, "distributed_inference_enabled": false}
            },
            "models": {"models": [{"id": "fixture", "pinned": false, "is_default": true,
                "distributed": false, "cluster": null,
                "settings": {"is_pinned": false, "is_default": true}}]}
        }), &reviewed.x3.as_ref().unwrap().profile_catalog).unwrap();
        let candidate = reviewed
            .launch_scope
            .runtime_directory
            .join("launch-SYNTHETIC-PRIVATE.json");
        let mut state = QualificationState {
            plan: fixture_plan(&home),
            gate: GateObservations {
                plan_sha256: "0".repeat(64),
                transaction_sha256: "0".repeat(64),
                old_identity: reviewed.old_identity,
                old_snapshot: snapshot,
                manifest: BundleManifest {
                    entries: BTreeMap::new(),
                    revision: String::new(),
                },
                report: GateReport {
                    fidelity_gate: GateStatus::Pass,
                    ..GateReport::default()
                },
                environment_comparison: EnvironmentComparison {
                    names: BTreeSet::new(),
                    launcher_values_equal: BTreeMap::new(),
                    additional_profile_names: false,
                },
                comparison_fields: Vec::new(),
                volatile_fields: Vec::new(),
                coverage_review_reference: "synthetic".into(),
                launch_scope: reviewed.launch_scope,
            },
            references: ConfigReferences {
                files: BTreeMap::new(),
                side_effect_entry_names: BTreeSet::new(),
            },
            log_offset: None,
            checks: BTreeMap::new(),
            failures: BTreeMap::new(),
            before_attempted: false,
            after_attempted: false,
        };
        let deadline = Instant::now() + Duration::from_secs(5);
        assert!(
            state
                .check_named_scope_absence(deadline, &mut || Ok(()))
                .unwrap()
                .qualifies()
        );
        fs::write(&candidate, b"NEVER-READ-MANIFEST").unwrap();
        let error = state
            .check_named_scope_absence(deadline, &mut || Ok(()))
            .unwrap_err()
            .to_string();
        assert!(!error.contains("SYNTHETIC-PRIVATE") && !error.contains("NEVER-READ"));
        assert_eq!(state.gate.report.fidelity_gate, GateStatus::Deny);
        assert_eq!(
            state
                .gate
                .report
                .launch_scope
                .as_ref()
                .unwrap()
                .candidate_count,
            Some(1)
        );
        fs::remove_file(candidate).unwrap();
        let mut called = false;
        assert!(
            state
                .check_named_scope_absence(deadline, &mut || {
                    called = true;
                    Ok(())
                })
                .is_err()
        );
        assert!(
            !called,
            "known unsupported scope must not become an implicit retry"
        );
    }
    #[test]
    fn cloned_permissions_cannot_repeat_restricted_observations() {
        let permission = AuthorizedPermissions::from_transaction_authorization(
            &fixture_reviewed(),
            &"0".repeat(64),
        )
        .unwrap();
        let cloned = permission.clone();
        consume_permission(&permission.usage.x2).unwrap();
        assert!(consume_permission(&cloned.usage.x2).is_err());
        consume_permission(&cloned.usage.old_x3).unwrap();
        assert!(consume_permission(&permission.usage.old_x3).is_err());
        consume_permission(&permission.usage.restored_x3).unwrap();
        assert!(consume_permission(&cloned.usage.restored_x3).is_err());
    }

    fn timing_manifest(
        root: &Path,
        limits: &QualificationLimits,
    ) -> Result<(BTreeMap<PathBuf, ManifestEntry>, u64)> {
        let mut walker = ManifestWalker {
            root: root.to_owned(),
            limits,
            entries: BTreeMap::new(),
            total_bytes: 0,
            active_dirs: BTreeSet::new(),
        };
        walker.walk(
            root,
            Path::new(""),
            0,
            Instant::now() + Duration::from_secs(5),
            &mut || Ok(()),
        )?;
        Ok((walker.entries, walker.total_bytes))
    }

    #[test]
    fn manifest_timing_preserves_alias_entries_and_rehashes_every_phase() {
        let temp = tempfile::tempdir().unwrap();
        let root = fs::canonicalize(temp.path()).unwrap();
        fs::create_dir(root.join("data")).unwrap();
        let mut bytes: Vec<u8> = (0..131073).map(|n| (n % 251) as u8).collect();
        fs::write(root.join("data/blob"), &bytes).unwrap();
        fs::write(root.join("data/empty"), []).unwrap();
        fs::hard_link(root.join("data/blob"), root.join("hard-link")).unwrap();
        std::os::unix::fs::symlink("data/blob", root.join("file-link")).unwrap();
        std::os::unix::fs::symlink("data", root.join("directory-link")).unwrap();
        let (first, total) = timing_manifest(&root, &QualificationLimits::default()).unwrap();
        let expected_paths: BTreeSet<_> = [
            "",
            "data",
            "data/blob",
            "data/empty",
            "hard-link",
            "file-link",
            "directory-link",
            "directory-link/blob",
            "directory-link/empty",
        ]
        .into_iter()
        .map(PathBuf::from)
        .collect();
        assert_eq!(
            first.keys().cloned().collect::<BTreeSet<_>>(),
            expected_paths
        );
        assert_eq!(total, 4 * bytes.len() as u64);
        for path in ["data/blob", "hard-link", "file-link", "directory-link/blob"] {
            assert_eq!(
                first[Path::new(path)].sha256.as_deref(),
                Some("dd84db969f4ff2abb79c8c2fbc06e8d8e02c46d6481c958e057f7ad7a24c58a7")
            );
        }
        assert_eq!(
            first[Path::new("directory-link/empty")].sha256.as_deref(),
            Some("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855")
        );
        assert_eq!(
            first[Path::new("file-link")].symlink_target,
            Some("data/blob".into())
        );
        assert_eq!(
            first[Path::new("directory-link")].symlink_target,
            Some("data".into())
        );
        *bytes.last_mut().unwrap() ^= 1;
        fs::write(root.join("data/blob"), &bytes).unwrap();
        let (second, total) = timing_manifest(&root, &QualificationLimits::default()).unwrap();
        assert_eq!(total, 4 * bytes.len() as u64);
        for path in ["data/blob", "hard-link", "file-link", "directory-link/blob"] {
            assert_eq!(
                second[Path::new(path)].sha256.as_deref(),
                Some("b9262daaf106d6dafe34c4c36e2b907cd384aeb18c0b49eb6c92183fcbdb84bc")
            );
        }
    }

    #[test]
    fn manifest_timing_pinned_parent_cannot_redirect_file_bytes() {
        let temp = tempfile::tempdir().unwrap();
        let root = fs::canonicalize(temp.path()).unwrap();
        let parent_path = root.join("parent");
        let outside = root.join("outside");
        fs::create_dir(&parent_path).unwrap();
        fs::create_dir(&outside).unwrap();
        let path = parent_path.join("code");
        fs::write(&path, b"original code").unwrap();
        fs::write(outside.join("code"), b"not code; never redirect here").unwrap();
        let expected = reference_metadata(&path).unwrap();
        let parent = open_path(&parent_path, true).unwrap();
        fs::rename(&parent_path, root.join("moved-parent")).unwrap();
        std::os::unix::fs::symlink(&outside, &parent_path).unwrap();
        let mut opened = open_manifest_entry(&path, Some(&parent), false).unwrap();
        let mut bytes = Vec::new();
        opened.read_to_end(&mut bytes).unwrap();
        assert_eq!(bytes, b"original code");
        assert!(
            hash_regular_from(
                &path,
                &expected,
                &QualificationLimits::default(),
                &mut 0,
                Instant::now() + Duration::from_secs(5),
                &mut || Ok(()),
                Some(&parent),
            )
            .is_err()
        );
        assert!(open_regular(&path).is_err());
    }

    #[test]
    fn manifest_timing_replaced_parent_directory_fails_binding() {
        let temp = tempfile::tempdir().unwrap();
        let base = fs::canonicalize(temp.path()).unwrap();
        let root = base.join("bundle");
        fs::create_dir_all(root.join("data")).unwrap();
        fs::write(root.join("data/code"), b"same bytes").unwrap();
        let parent = open_path(&root, true).unwrap();
        fs::rename(&root, base.join("moved-bundle")).unwrap();
        fs::create_dir_all(root.join("data")).unwrap();
        fs::write(root.join("data/code"), b"same bytes").unwrap();
        let limits = QualificationLimits::default();
        let mut walker = ManifestWalker {
            root: root.clone(),
            limits: &limits,
            entries: BTreeMap::new(),
            total_bytes: 0,
            active_dirs: BTreeSet::new(),
        };
        assert!(
            walker
                .walk_from(
                    &root.join("data"),
                    Path::new("data"),
                    1,
                    Instant::now() + Duration::from_secs(5),
                    &mut || Ok(()),
                    Some(&parent),
                )
                .is_err()
        );
        assert_eq!(walker.total_bytes, 0);
    }

    #[test]
    fn manifest_timing_logical_byte_and_entry_bounds_remain_enforced() {
        let temp = tempfile::tempdir().unwrap();
        let root = fs::canonicalize(temp.path()).unwrap();
        fs::write(root.join("code"), b"abcd").unwrap();
        std::os::unix::fs::symlink("code", root.join("alias")).unwrap();
        let mut limits = QualificationLimits {
            max_file_bytes: 4,
            max_total_bytes: 8,
            max_files: 3,
            ..QualificationLimits::default()
        };
        assert_eq!(timing_manifest(&root, &limits).unwrap().1, 8);
        limits.max_total_bytes = 7;
        assert!(timing_manifest(&root, &limits).is_err());
        limits.max_total_bytes = 8;
        limits.max_file_bytes = 3;
        assert!(timing_manifest(&root, &limits).is_err());
        limits.max_file_bytes = 4;
        limits.max_files = 2;
        assert!(timing_manifest(&root, &limits).is_err());
        limits.max_files = 3;
        limits.max_depth = 0;
        assert!(timing_manifest(&root, &limits).is_err());
    }

    #[test]
    fn manifest_timing_stream_changes_and_expired_deadlines_deny() {
        for replace in [false, true] {
            let temp = tempfile::tempdir().unwrap();
            let root = fs::canonicalize(temp.path()).unwrap();
            let path = root.join("code");
            fs::write(&path, vec![7_u8; 131073]).unwrap();
            let expected = reference_metadata(&path).unwrap();
            let parent = open_path(&root, true).unwrap();
            let mut checkpoint_count = 0;
            let mut tick = || {
                checkpoint_count += 1;
                if checkpoint_count == 2 {
                    if replace {
                        fs::rename(&path, root.join("old-code"))?;
                        fs::write(&path, vec![7_u8; 131073])?;
                    } else {
                        fs::OpenOptions::new()
                            .append(true)
                            .open(&path)?
                            .write_all(b"x")?;
                    }
                }
                Ok(())
            };
            assert!(
                hash_regular_from(
                    &path,
                    &expected,
                    &QualificationLimits::default(),
                    &mut 0,
                    Instant::now() + Duration::from_secs(5),
                    &mut tick,
                    Some(&parent),
                )
                .is_err()
            );
            let current = reference_metadata(&path).unwrap();
            assert!(
                hash_regular_from(
                    &path,
                    &current,
                    &QualificationLimits::default(),
                    &mut 0,
                    Instant::now(),
                    &mut || Ok(()),
                    Some(&parent),
                )
                .is_err()
            );
        }
    }

    #[test]
    fn manifest_timing_nonregular_types_and_unsafe_aliases_deny() {
        for case in ["fifo", "cycle", "outside-file", "outside-directory"] {
            let temp = tempfile::tempdir().unwrap();
            let base = fs::canonicalize(temp.path()).unwrap();
            let root = base.join("bundle");
            let outside = base.join("outside");
            fs::create_dir(&root).unwrap();
            fs::create_dir(&outside).unwrap();
            fs::write(outside.join("code"), b"outside code root").unwrap();
            let entry = root.join("entry");
            match case {
                "fifo" => {
                    let name =
                        std::ffi::CString::new(entry.as_os_str().as_encoded_bytes()).unwrap();
                    assert_eq!(unsafe { libc::mkfifo(name.as_ptr(), 0o600) }, 0);
                }
                "cycle" => std::os::unix::fs::symlink(".", &entry).unwrap(),
                "outside-file" => std::os::unix::fs::symlink(outside.join("code"), &entry).unwrap(),
                "outside-directory" => std::os::unix::fs::symlink(&outside, &entry).unwrap(),
                _ => unreachable!(),
            }
            assert!(timing_manifest(&root, &QualificationLimits::default()).is_err());
        }
        let temp = tempfile::tempdir().unwrap();
        let root = fs::canonicalize(temp.path()).unwrap();
        let path = root.join("code");
        fs::write(&path, b"regular code").unwrap();
        let expected = reference_metadata(&path).unwrap();
        let parent = open_path(&root, true).unwrap();
        fs::remove_file(&path).unwrap();
        fs::create_dir(&path).unwrap();
        assert!(
            hash_regular_from(
                &path,
                &expected,
                &QualificationLimits::default(),
                &mut 0,
                Instant::now() + Duration::from_secs(5),
                &mut || Ok(()),
                Some(&parent),
            )
            .is_err()
        );
    }

    #[test]
    fn manifest_timing_pinned_listing_keeps_original_names_under_aba_replacement() {
        let temp = tempfile::tempdir().unwrap();
        let base = fs::canonicalize(temp.path()).unwrap();
        let root = base.join("bundle");
        let replacement = base.join("replacement");
        let saved = base.join("saved");
        fs::create_dir(&root).unwrap();
        fs::create_dir(&replacement).unwrap();
        for name in ["only-original.code", "shared.code"] {
            fs::write(root.join(name), b"original").unwrap();
        }
        for name in ["only-replacement.code", "shared.code"] {
            fs::write(replacement.join(name), b"replacement").unwrap();
        }
        let pinned = open_path(&root, true).unwrap();
        fs::rename(&root, &saved).unwrap();
        fs::rename(&replacement, &root).unwrap();
        let mut path_names: Vec<_> = fs::read_dir(&root)
            .unwrap()
            .map(|entry| entry.unwrap().file_name())
            .collect();
        path_names.sort();
        let pinned_names = directory_names(
            &pinned,
            2,
            Instant::now() + Duration::from_secs(5),
            &mut || Ok(()),
        )
        .unwrap();
        fs::rename(&root, &replacement).unwrap();
        fs::rename(&saved, &root).unwrap();
        let names = |values: [&str; 2]| values.map(std::ffi::OsString::from).to_vec();
        assert_eq!(path_names, names(["only-replacement.code", "shared.code"]));
        assert_eq!(pinned_names, names(["only-original.code", "shared.code"]));
        // Neither name-set assertion consults inode timestamps or ctime changes.
    }

    #[test]
    fn manifest_timing_pinned_listing_enforces_bounds_deadline_and_directory_type() {
        let temp = tempfile::tempdir().unwrap();
        let root = fs::canonicalize(temp.path()).unwrap();
        assert!(
            directory_names(
                &open_path(&root, true).unwrap(),
                0,
                Instant::now() + Duration::from_secs(5),
                &mut || Ok(()),
            )
            .unwrap()
            .is_empty()
        );
        fs::write(root.join("b"), b"code").unwrap();
        fs::write(root.join("a"), b"code").unwrap();
        let names = directory_names(
            &open_path(&root, true).unwrap(),
            2,
            Instant::now() + Duration::from_secs(5),
            &mut || Ok(()),
        )
        .unwrap();
        assert_eq!(names, ["a", "b"].map(std::ffi::OsString::from));
        assert!(
            directory_names(
                &open_path(&root, true).unwrap(),
                1,
                Instant::now() + Duration::from_secs(5),
                &mut || Ok(()),
            )
            .is_err()
        );
        assert!(
            directory_names(
                &open_path(&root, true).unwrap(),
                2,
                Instant::now(),
                &mut || Ok(()),
            )
            .is_err()
        );
        assert!(
            directory_names(
                &open_path(&root, true).unwrap(),
                2,
                Instant::now() + Duration::from_secs(5),
                &mut || bail!("fixture authority revoked"),
            )
            .is_err()
        );
        let mut file = File::open(root.join("a")).unwrap();
        assert!(qualification_scope::DirectoryStream::open(&file).is_err());
        let mut content = String::new();
        file.read_to_string(&mut content).unwrap();
        assert_eq!(content, "code");
    }
}
