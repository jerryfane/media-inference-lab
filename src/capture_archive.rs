use crate::{capture::CaptureRecord, schema::Artifact, study::PlannedSample};
use anyhow::{Context, Result, ensure};
use sha2::{Digest, Sha256};
use std::{
    fs::{self, File, OpenOptions},
    io::{BufWriter, Read, Write},
    path::{Path, PathBuf},
};

pub const CAPTURE_LIMIT: u64 = 16 * 1024 * 1024;
pub const ARCHIVE_LIMIT: u64 = 256 * 1024 * 1024;

/// Private, slot-indexed copies of the typed records actually inspected.
/// Snapshot hashes identify these serialized bytes, not the source manifest.
pub struct CaptureArchive {
    directory: PathBuf,
    remaining: u64,
    snapshots: Vec<Option<Artifact>>,
}

impl CaptureArchive {
    /// Construction is inert; comparison validates its inputs before preparation.
    pub fn new(directory: PathBuf) -> Self {
        Self {
            directory,
            remaining: ARCHIVE_LIMIT,
            snapshots: Vec::new(),
        }
    }

    pub(crate) fn prepare(&mut self, slots: usize) -> Result<()> {
        ensure!(slots <= 99, "capture archive supports at most 99 slots");
        create_private_directory(&self.directory)?;
        create_private_directory(&self.directory.join("captures"))?;
        self.snapshots = vec![None; slots];
        Ok(())
    }

    pub(crate) fn store(&mut self, slot: &PlannedSample, record: &CaptureRecord) -> Result<()> {
        let index = usize::try_from(slot.index).context("capture slot index is too large")?;
        let snapshot = self
            .snapshots
            .get_mut(index)
            .context("capture archive slot is out of range or archive is not prepared")?;
        ensure!(snapshot.is_none(), "capture archive slot is already stored");
        ensure!(
            self.remaining > 0,
            "capture archive byte quota is exhausted"
        );
        require_directory(&self.directory)?;
        require_directory(&self.directory.join("captures"))?;
        let relative = format!("captures/slot-{index:03}.json");
        let path = self.directory.join(&relative);
        let mut options = OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        let file = options.open(&path).with_context(|| {
            format!(
                "creating non-overwriting capture snapshot {}",
                path.display()
            )
        })?;
        let mut writer = SnapshotWriter {
            file: BufWriter::new(file),
            hash: Sha256::new(),
            bytes: 0,
            remaining: &mut self.remaining,
        };
        // Serialize the inspected record directly: never reopen its source or payloads.
        serde_json::to_writer_pretty(&mut writer, record)
            .with_context(|| format!("archiving capture slot {index}"))?;
        writer.write_all(b"\n")?;
        writer.flush()?;
        writer.file.get_ref().sync_all()?;
        *snapshot = Some(Artifact {
            path: relative,
            sha256: format!("{:x}", writer.hash.finalize()),
            bytes: writer.bytes,
            role: "capture_metadata".into(),
        });
        Ok(())
    }

    pub fn snapshots(&self) -> &[Option<Artifact>] {
        &self.snapshots
    }

    /// Reload only generated metadata, checking its exact saved byte identity.
    /// At most CAPTURE_LIMIT + 1 bytes are read (one oversize sentinel). File
    /// operations remain cooperative: no operating-system I/O timeout is imposed.
    pub fn text(&self, index: usize) -> Result<Option<String>> {
        let Some(snapshot) = self
            .snapshots
            .get(index)
            .context("capture archive slot is out of range")?
        else {
            return Ok(None);
        };
        require_directory(&self.directory)?;
        require_directory(&self.directory.join("captures"))?;
        let path = self.directory.join(&snapshot.path);
        let metadata = fs::symlink_metadata(&path)?;
        ensure!(
            metadata.is_file() && !metadata.file_type().is_symlink(),
            "capture snapshot is not a regular non-symlink file"
        );
        let mut options = OpenOptions::new();
        options.read(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK);
        }
        let file = options
            .open(&path)
            .with_context(|| format!("opening archived capture {}", path.display()))?;
        let metadata = file.metadata()?;
        ensure!(metadata.is_file(), "capture snapshot is not a regular file");
        ensure!(
            metadata.len() <= CAPTURE_LIMIT && metadata.len() == snapshot.bytes,
            "capture snapshot byte count does not match its bounded archived identity"
        );
        let mut bytes = Vec::with_capacity(metadata.len() as usize);
        file.take(CAPTURE_LIMIT + 1).read_to_end(&mut bytes)?;
        ensure!(
            bytes.len() as u64 <= CAPTURE_LIMIT && bytes.len() as u64 == snapshot.bytes,
            "capture snapshot byte count changed"
        );
        ensure!(
            format!("{:x}", Sha256::digest(&bytes)) == snapshot.sha256,
            "capture snapshot SHA256 mismatch"
        );
        Ok(Some(
            String::from_utf8(bytes).context("capture snapshot is not UTF-8")?,
        ))
    }
}

fn create_private_directory(path: &Path) -> Result<()> {
    let mut builder = fs::DirBuilder::new();
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt;
        builder.mode(0o700);
    }
    builder
        .create(path)
        .with_context(|| format!("creating new private archive directory {}", path.display()))
}

fn require_directory(path: &Path) -> Result<()> {
    let metadata = fs::symlink_metadata(path)?;
    ensure!(
        metadata.is_dir() && !metadata.file_type().is_symlink(),
        "archive directory is not a non-symlink directory: {}",
        path.display()
    );
    Ok(())
}

struct SnapshotWriter<'a> {
    file: BufWriter<File>,
    hash: Sha256,
    bytes: u64,
    remaining: &'a mut u64,
}

impl Write for SnapshotWriter<'_> {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        let count = bytes.len() as u64;
        if count > CAPTURE_LIMIT - self.bytes {
            return Err(std::io::Error::other(format!(
                "capture snapshot exceeds {CAPTURE_LIMIT} bytes"
            )));
        }
        if count > *self.remaining {
            return Err(std::io::Error::other(format!(
                "capture archive exceeds {ARCHIVE_LIMIT} bytes"
            )));
        }
        let written = self.file.write(bytes)?;
        self.hash.update(&bytes[..written]);
        self.bytes += written as u64;
        // Retain charges even after an error: a partial private file may remain.
        *self.remaining -= written as u64;
        Ok(written)
    }

    fn flush(&mut self) -> std::io::Result<()> {
        self.file.flush()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn archive_with_text(text: &[u8]) -> (tempfile::TempDir, CaptureArchive) {
        let temporary = tempfile::tempdir().unwrap();
        let mut archive = CaptureArchive::new(temporary.path().join("bundle"));
        archive.prepare(3).unwrap();
        fs::write(archive.directory.join("captures/slot-001.json"), text).unwrap();
        archive.snapshots[1] = Some(Artifact {
            path: "captures/slot-001.json".into(),
            sha256: format!("{:x}", Sha256::digest(text)),
            bytes: text.len() as u64,
            role: "capture_metadata".into(),
        });
        (temporary, archive)
    }

    #[test]
    fn reload_preserves_missing_slots_and_rejects_tampering() {
        let (_temporary, archive) = archive_with_text(b"{\"value\": 1}\n");
        assert!(archive.text(0).unwrap().is_none());
        assert_eq!(
            archive.text(1).unwrap().as_deref(),
            Some("{\"value\": 1}\n")
        );
        assert!(archive.text(2).unwrap().is_none());
        assert!(archive.text(3).is_err());
        let path = archive.directory.join("captures/slot-001.json");
        fs::write(&path, b"{\"value\": 2}\n").unwrap();
        assert!(archive.text(1).is_err());
        fs::write(&path, b"{}").unwrap();
        assert!(archive.text(1).is_err());
        fs::remove_file(&path).unwrap();
        fs::create_dir(&path).unwrap();
        assert!(archive.text(1).is_err());
    }

    #[test]
    fn reload_rejects_oversized_and_non_utf8_snapshots() {
        let (_temporary, archive) = archive_with_text(b"{}");
        let path = archive.directory.join("captures/slot-001.json");
        OpenOptions::new()
            .write(true)
            .open(path)
            .unwrap()
            .set_len(CAPTURE_LIMIT + 1)
            .unwrap();
        assert!(archive.text(1).is_err());
        let (_temporary, archive) = archive_with_text(&[0xff]);
        assert!(archive.text(1).is_err());
    }

    #[test]
    fn preparation_is_inert_bounded_and_never_reuses_directories() {
        let temporary = tempfile::tempdir().unwrap();
        let directory = temporary.path().join("bundle");
        let mut archive = CaptureArchive::new(directory.clone());
        assert!(!directory.exists());
        assert!(archive.prepare(100).is_err());
        assert!(!directory.exists());
        archive.prepare(99).unwrap();
        assert_eq!(archive.snapshots.len(), 99);
        assert!(archive.snapshots.iter().all(Option::is_none));
        assert!(archive.prepare(1).is_err());
        assert_eq!(archive.snapshots.len(), 99);
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            for path in [&directory, &directory.join("captures")] {
                assert_eq!(
                    fs::metadata(path).unwrap().permissions().mode() & 0o777,
                    0o700
                );
            }
        }
    }

    #[cfg(unix)]
    #[test]
    fn reload_and_preparation_reject_symlinks() {
        use std::os::unix::fs::symlink;
        let (temporary, archive) = archive_with_text(b"{}");
        let path = archive.directory.join("captures/slot-001.json");
        let replacement = temporary.path().join("replacement.json");
        fs::write(&replacement, b"{}").unwrap();
        fs::remove_file(&path).unwrap();
        symlink(&replacement, &path).unwrap();
        assert!(archive.text(1).is_err());
        let alias = temporary.path().join("alias");
        symlink(&archive.directory, &alias).unwrap();
        assert!(CaptureArchive::new(alias).prepare(1).is_err());
        fs::remove_file(path).unwrap();
        fs::remove_dir(archive.directory.join("captures")).unwrap();
        symlink(temporary.path(), archive.directory.join("captures")).unwrap();
        assert!(archive.text(1).is_err());
    }

    #[test]
    fn writer_enforces_per_file_and_remaining_archive_quotas() {
        let temporary = tempfile::tempdir().unwrap();
        let path = temporary.path().join("snapshot");
        let mut remaining = ARCHIVE_LIMIT;
        let mut writer = SnapshotWriter {
            file: BufWriter::new(File::create(&path).unwrap()),
            hash: Sha256::new(),
            bytes: 0,
            remaining: &mut remaining,
        };
        std::io::copy(&mut std::io::repeat(b'a').take(CAPTURE_LIMIT), &mut writer).unwrap();
        assert!(writer.write_all(b"!").is_err());
        writer.flush().unwrap();
        assert_eq!(fs::metadata(&path).unwrap().len(), CAPTURE_LIMIT);
        assert_eq!(*writer.remaining, ARCHIVE_LIMIT - CAPTURE_LIMIT);
        drop(writer);
        let mut remaining = 3;
        let mut writer = SnapshotWriter {
            file: BufWriter::new(File::create(&path).unwrap()),
            hash: Sha256::new(),
            bytes: 0,
            remaining: &mut remaining,
        };
        writer.write_all(b"ab").unwrap();
        assert!(writer.write_all(b"cd").is_err());
        writer.write_all(b"c").unwrap();
        assert!(writer.write_all(b"d").is_err());
        writer.flush().unwrap();
        assert_eq!(fs::read(path).unwrap(), b"abc");
        assert_eq!(*writer.remaining, 0);
        assert_eq!(
            format!("{:x}", writer.hash.finalize()),
            format!("{:x}", Sha256::digest(b"abc"))
        );
    }
}
