//! Source-bound denial of unsupported distributed-worker/reaper scope.
//! Observation is metadata and bounded names only; never manifest contents or controls.
use std::collections::BTreeMap;
use std::ffi::{CStr, CString};
use std::fs::{self, File};
use std::os::fd::{AsRawFd, FromRawFd};
use std::path::{Component, PathBuf};
use std::time::Instant;

use anyhow::{Result, bail, ensure};
use serde::{Deserialize, Serialize};

use crate::restore_qualification::{MetadataRecord, checkpoint, validate_absolute};

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReviewedLaunchScope {
    pub review_reference: String,
    pub source_review_reference: String,
    pub allow_metadata_name_observation: bool,
    pub restore_home: PathBuf,
    pub runtime_directory: PathBuf,
    pub manifest_prefix: String,
    pub manifest_suffix: String,
    pub max_entries: usize,
}
impl ReviewedLaunchScope {
    pub fn validate(&self) -> Result<()> {
        validate_absolute(&self.restore_home)?;
        validate_absolute(&self.runtime_directory)?;
        ensure!(
            [&self.review_reference, &self.source_review_reference]
                .iter()
                .all(|s| !s.trim().is_empty()
                    && s.len() <= 4096
                    && !s.chars().any(char::is_control))
                && self.allow_metadata_name_observation
                && self.runtime_directory.as_os_str()
                    == self.restore_home.join(".omlx/cluster/runtime").as_os_str()
                && self.manifest_prefix == "launch-"
                && self.manifest_suffix == ".json"
                && self.max_entries == 4096,
            "SC2 source-bound metadata/name permission missing or invalid"
        );
        Ok(())
    }
    pub fn validate_for(&self, restore_env: &BTreeMap<String, String>) -> Result<()> {
        self.validate()?;
        ensure!(
            restore_env.get("HOME").map(std::ffi::OsStr::new)
                == Some(self.restore_home.as_os_str()),
            "SC2 restore HOME binding mismatch"
        );
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ScopeState {
    AbsentCluster,
    AbsentRuntime,
    Present,
    Unavailable,
}
#[derive(Clone, Debug, Serialize)]
pub struct ScopeObservation {
    pub state: ScopeState,
    /// Observed candidates, not a total inventory: the first candidate denies.
    pub candidate_count: Option<usize>,
    pub entries_scanned_bounded: bool,
}
impl ScopeObservation {
    pub(crate) fn unavailable() -> Self {
        Self {
            state: ScopeState::Unavailable,
            candidate_count: None,
            entries_scanned_bounded: false,
        }
    }
    pub(crate) fn qualifies(&self) -> bool {
        self.state != ScopeState::Unavailable
            && self.candidate_count == Some(0)
            && self.entries_scanned_bounded
    }
}

struct OpenedScope {
    directory: Option<File>,
    chain: Vec<MetadataRecord>,
    state: ScopeState,
}
fn open_scope(
    scope: &ReviewedLaunchScope,
    deadline: Instant,
    tick: &mut dyn FnMut() -> Result<()>,
) -> Result<OpenedScope> {
    let components: Vec<_> = scope
        .runtime_directory
        .components()
        .filter_map(|c| {
            if let Component::Normal(name) = c {
                Some(name)
            } else {
                None
            }
        })
        .collect();
    let mut directory = File::open("/")?;
    let mut path = PathBuf::from("/");
    let mut chain = Vec::with_capacity(components.len());
    for (index, component) in components.iter().enumerate() {
        checkpoint(deadline, tick)?;
        path.push(component);
        let metadata = match fs::symlink_metadata(&path) {
            Ok(metadata) => metadata,
            Err(error)
                if error.kind() == std::io::ErrorKind::NotFound
                    && index + 2 >= components.len() =>
            {
                return Ok(OpenedScope {
                    directory: None,
                    chain,
                    state: if index + 2 == components.len() {
                        ScopeState::AbsentCluster
                    } else {
                        ScopeState::AbsentRuntime
                    },
                });
            }
            Err(_) => bail!("SC2 scope metadata unavailable"),
        };
        let expected = MetadataRecord::from_metadata(&metadata);
        ensure!(
            metadata.is_dir() && !metadata.file_type().is_symlink(),
            "SC2 non-directory or symlink scope"
        );
        if index + 3 >= components.len() {
            ensure!(
                expected.uid == unsafe { libc::geteuid() } && expected.mode & 0o022 == 0,
                "SC2 scope owner or write access invalid"
            );
        }
        let name = CString::new(component.as_encoded_bytes())?;
        let fd = unsafe {
            libc::openat(
                directory.as_raw_fd(),
                name.as_ptr(),
                libc::O_RDONLY
                    | libc::O_DIRECTORY
                    | libc::O_NOFOLLOW
                    | libc::O_CLOEXEC
                    | libc::O_NONBLOCK,
            )
        };
        ensure!(fd >= 0, "SC2 no-follow scope open failed");
        let opened = unsafe { File::from_raw_fd(fd) };
        ensure!(
            MetadataRecord::from_metadata(&opened.metadata()?) == expected,
            "SC2 scope open raced"
        );
        chain.push(expected);
        directory = opened;
    }
    Ok(OpenedScope {
        directory: Some(directory),
        chain,
        state: ScopeState::Present,
    })
}

/// Owns a CLOEXEC duplicate; enumeration cannot be redirected by path replacement.
/// The duplicate shares the directory offset, so each opened directory is listed once.
pub(crate) struct DirectoryStream(*mut libc::DIR);
impl DirectoryStream {
    pub(crate) fn open(directory: &File) -> Result<Self> {
        let fd = unsafe { libc::fcntl(directory.as_raw_fd(), libc::F_DUPFD_CLOEXEC, 0) };
        ensure!(fd >= 0, "directory descriptor duplication failed");
        let stream = unsafe { libc::fdopendir(fd) };
        if stream.is_null() {
            unsafe {
                libc::close(fd);
            }
            bail!("directory name enumeration unavailable");
        }
        Ok(Self(stream))
    }

    pub(crate) fn next_name(&mut self) -> Result<Option<&[u8]>> {
        unsafe {
            *errno_pointer() = 0;
        }
        let entry = unsafe { libc::readdir(self.0) };
        if entry.is_null() {
            ensure!(
                unsafe { *errno_pointer() } == 0,
                "directory name enumeration failed"
            );
            return Ok(None);
        }
        // readdir owns the storage until its next call. The mutable borrow keeps
        // callers from advancing or dropping this stream while a name is borrowed.
        Ok(Some(unsafe { CStr::from_ptr((*entry).d_name.as_ptr()) }.to_bytes()))
    }
}
impl Drop for DirectoryStream {
    fn drop(&mut self) {
        unsafe {
            libc::closedir(self.0);
        }
    }
}
#[cfg(target_os = "macos")]
fn errno_pointer() -> *mut libc::c_int {
    unsafe { libc::__error() }
}
#[cfg(not(target_os = "macos"))]
fn errno_pointer() -> *mut libc::c_int {
    unsafe { libc::__errno_location() }
}

fn candidate_name(bytes: &[u8], scope: &ReviewedLaunchScope) -> Result<bool> {
    let name =
        std::str::from_utf8(bytes).map_err(|_| anyhow::anyhow!("SC2 malformed entry name"))?;
    Ok(name.starts_with(&scope.manifest_prefix) && name.ends_with(&scope.manifest_suffix))
}

fn observe_inner(
    scope: &ReviewedLaunchScope,
    deadline: Instant,
    tick: &mut dyn FnMut() -> Result<()>,
) -> Result<ScopeObservation> {
    scope.validate()?;
    let before = open_scope(scope, deadline, tick)?;
    if let Some(directory) = &before.directory {
        // Entries are never opened or statted.
        let mut stream = DirectoryStream::open(directory)?;
        let mut entries = 0;
        loop {
            checkpoint(deadline, tick)?;
            let Some(name) = stream.next_name()? else {
                break;
            };
            if name == b"." || name == b".." {
                continue;
            }
            entries += 1;
            ensure!(entries <= scope.max_entries, "SC2 entry bound exceeded");
            if candidate_name(name, scope)? {
                return Ok(ScopeObservation {
                    state: ScopeState::Present,
                    candidate_count: Some(1),
                    entries_scanned_bounded: true,
                });
            }
        }
        ensure!(
            before.chain.last() == Some(&MetadataRecord::from_metadata(&directory.metadata()?)),
            "SC2 scope changed during enumeration"
        );
    }
    let after = open_scope(scope, deadline, tick)?;
    ensure!(
        before.state == after.state && before.chain == after.chain,
        "SC2 scope identity changed"
    );
    checkpoint(deadline, tick)?;
    Ok(ScopeObservation {
        state: before.state,
        candidate_count: Some(0),
        entries_scanned_bounded: true,
    })
}

/// Crate-private: production callers must already hold the transaction-minted capability.
/// All filesystem/observer errors become an unavailable observation; no names or OS error details escape.
pub(crate) fn observe(
    scope: &ReviewedLaunchScope,
    deadline: Instant,
    tick: &mut dyn FnMut() -> Result<()>,
) -> ScopeObservation {
    observe_inner(scope, deadline, tick).unwrap_or_else(|_| ScopeObservation::unavailable())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::{PermissionsExt, symlink};
    use std::time::Duration;
    fn fixture() -> (tempfile::TempDir, ReviewedLaunchScope) {
        let directory = tempfile::tempdir().unwrap();
        let home = fs::canonicalize(directory.path()).unwrap();
        fs::create_dir(home.join(".omlx")).unwrap();
        let scope = ReviewedLaunchScope {
            review_reference: "synthetic-reviewed-permission".into(),
            source_review_reference: "synthetic-source".into(),
            allow_metadata_name_observation: true,
            runtime_directory: home.join(".omlx/cluster/runtime"),
            restore_home: home,
            manifest_prefix: "launch-".into(),
            manifest_suffix: ".json".into(),
            max_entries: 4096,
        };
        (directory, scope)
    }
    fn observation(scope: &ReviewedLaunchScope) -> ScopeObservation {
        observe(scope, Instant::now() + Duration::from_secs(10), &mut || {
            Ok(())
        })
    }
    #[test]
    fn scope_missing_empty_and_source_exact_candidate_grammar() {
        let (_directory, scope) = fixture();
        assert_eq!(observation(&scope).state, ScopeState::AbsentCluster);
        fs::create_dir(scope.runtime_directory.parent().unwrap()).unwrap();
        assert_eq!(observation(&scope).state, ScopeState::AbsentRuntime);
        fs::create_dir(&scope.runtime_directory).unwrap();
        for name in [
            "Launch-a.json",
            "launch-a.JSON",
            "launch-a.json.tmp",
            "marker",
        ] {
            fs::write(scope.runtime_directory.join(name), b"unread").unwrap();
        }
        assert!(observation(&scope).qualifies());
        // '*' is allowed to be empty; directories and dangling links are candidates too.
        for kind in 0..3 {
            let path = scope.runtime_directory.join("launch-.json");
            match kind {
                0 => fs::write(&path, b"not JSON; MUST NOT be parsed").unwrap(),
                1 => fs::create_dir(&path).unwrap(),
                _ => symlink("missing", &path).unwrap(),
            }
            let result = observation(&scope);
            assert!(!result.qualifies());
            assert_eq!(result.candidate_count, Some(1));
            let output = serde_json::to_string(&result).unwrap();
            assert!(!output.contains("launch-") && !output.contains("not JSON"));
            if kind == 1 {
                fs::remove_dir(path).unwrap();
            } else {
                fs::remove_file(path).unwrap();
            }
        }
    }
    #[test]
    fn scope_permissions_path_binding_types_and_symlinks_deny() {
        let (_directory, scope) = fixture();
        let environment = [(
            "HOME".into(),
            scope.restore_home.to_string_lossy().into_owned(),
        )]
        .into();
        assert!(scope.validate_for(&environment).is_ok());
        assert!(scope.validate_for(&BTreeMap::new()).is_err());
        let mut unauthorized = scope.clone();
        unauthorized.allow_metadata_name_observation = false;
        assert!(!observation(&unauthorized).qualifies());
        unauthorized = scope.clone();
        unauthorized.runtime_directory = scope.restore_home.join("elsewhere");
        assert!(!observation(&unauthorized).qualifies());
        unauthorized = scope.clone();
        unauthorized.manifest_prefix = "other-".into();
        assert!(!observation(&unauthorized).qualifies());
        let cluster = scope.runtime_directory.parent().unwrap();
        fs::write(cluster, b"not directory").unwrap();
        assert!(!observation(&scope).qualifies());
        fs::remove_file(cluster).unwrap();
        symlink("missing", cluster).unwrap();
        assert!(!observation(&scope).qualifies());
        fs::remove_file(cluster).unwrap();
        fs::create_dir_all(&scope.runtime_directory).unwrap();
        for path in [
            scope.restore_home.join(".omlx"),
            cluster.to_owned(),
            scope.runtime_directory.clone(),
        ] {
            fs::set_permissions(&path, fs::Permissions::from_mode(0o777)).unwrap();
            assert!(!observation(&scope).qualifies());
            fs::set_permissions(&path, fs::Permissions::from_mode(0o700)).unwrap();
        }
        fs::remove_dir(&scope.runtime_directory).unwrap();
        symlink("missing", &scope.runtime_directory).unwrap();
        assert!(!observation(&scope).qualifies());
    }
    #[test]
    fn scope_entry_bound_malformed_names_deadline_and_races_deny() {
        let (_directory, scope) = fixture();
        fs::create_dir_all(&scope.runtime_directory).unwrap();
        for n in 0..4096 {
            fs::write(scope.runtime_directory.join(n.to_string()), b"").unwrap();
        }
        assert!(observation(&scope).qualifies());
        fs::write(scope.runtime_directory.join("over-bound"), b"").unwrap();
        assert!(!observation(&scope).qualifies());
        fs::remove_file(scope.runtime_directory.join("over-bound")).unwrap();
        // Some filesystems reject non-UTF-8 names at creation; exercise the same decoder
        // used by readdir rather than assuming that the fixture filesystem permits them.
        assert!(candidate_name(&[0xff], &scope).is_err());
        assert!(!observe(&scope, Instant::now(), &mut || Ok(())).qualifies());
        let mutate_after = scope
            .runtime_directory
            .components()
            .filter(|part| matches!(part, Component::Normal(_)))
            .count()
            + 2;
        let mut checkpoints = 0;
        let result = observe(
            &scope,
            Instant::now() + Duration::from_secs(10),
            &mut || {
                checkpoints += 1;
                if checkpoints == mutate_after {
                    fs::rename(
                        &scope.runtime_directory,
                        scope.runtime_directory.with_extension("old"),
                    )?;
                    symlink("runtime.old", &scope.runtime_directory)?;
                }
                Ok(())
            },
        );
        assert!(!result.qualifies());
        assert!(checkpoints >= mutate_after);
    }
    #[test]
    fn scope_home_and_directory_bindings_are_lexically_exact() {
        let (_directory, scope) = fixture();
        let environment = [("HOME".into(), format!("{}/.", scope.restore_home.display()))].into();
        assert!(scope.validate_for(&environment).is_err());
        let mut alternate = scope.clone();
        alternate.runtime_directory = scope.restore_home.join(".omlx/./cluster/runtime");
        assert!(alternate.validate().is_err());
    }
}
