use anyhow::{Context, Result, ensure};
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::{fs::{File, OpenOptions}, io::{Read, Write}, os::unix::fs::OpenOptionsExt, path::{Component, Path, PathBuf}, time::Instant};

pub(super) const MIB: u64 = 1024 * 1024;
thread_local! {
    static METADATA_REMAINING: std::cell::Cell<u64> = const { std::cell::Cell::new(256 * MIB) };
    static METADATA_READ: std::cell::Cell<u64> = const { std::cell::Cell::new(0) };
}
pub(super) fn set_metadata_budget(remaining: u64) {
    METADATA_REMAINING.with(|v| v.set(remaining.min(256 * MIB)));
}
pub(super) fn metadata_bytes_read() -> u64 { METADATA_READ.with(|v| v.get()) }
fn charge_metadata(n: usize) -> Result<()> {
    METADATA_REMAINING.with(|remaining| {
        ensure!(n as u64 <= remaining.get(), "combined metadata reads exceed budget");
        remaining.set(remaining.get() - n as u64);
        METADATA_READ.with(|v| v.set(v.get() + n as u64));
        Ok(())
    })
}
pub(super) const METADATA_LIMIT: u64 = 16 * MIB;
pub(super) fn check(deadline: Instant) -> Result<()> {
    ensure!(Instant::now() < deadline, "offline media deadline exceeded");
    Ok(())
}
pub(super) fn open(path: &Path, limit: u64) -> Result<File> {
    ensure!(path.as_os_str().len() <= 4095, "media path exceeds bound");
    let file = OpenOptions::new().read(true).custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK).open(path)?;
    let metadata = file.metadata()?;
    ensure!(metadata.is_file() && metadata.len() <= limit, "media input is not a bounded regular file: {}", path.display());
    Ok(file)
}
pub(super) fn private(path: &Path) -> Result<File> {
    Ok(OpenOptions::new().write(true).create_new(true).mode(0o600).open(path)?)
}
pub(super) fn read(path: &Path, limit: u64, deadline: Instant) -> Result<Vec<u8>> {
    let mut file = open(path, limit)?;
    let mut bytes = Vec::new();
    let mut chunk = [0; 65536];
    loop {
        check(deadline)?;
        let allowance = if limit == METADATA_LIMIT {
            METADATA_REMAINING.with(|v| v.get().min(chunk.len() as u64) as usize)
        } else { chunk.len() };
        if allowance == 0 {
            ensure!(file.metadata()?.len() == bytes.len() as u64, "combined metadata reads exceed budget");
            break;
        }
        let n = file.read(&mut chunk[..allowance])?;
        if limit == METADATA_LIMIT { charge_metadata(n)?; }
        if n == 0 { break; }
        ensure!(bytes.len() as u64 + n as u64 <= limit, "media input grew beyond bound");
        bytes.extend_from_slice(&chunk[..n]);
    }
    Ok(bytes)
}
pub(super) fn hash(path: &Path, limit: u64, deadline: Instant) -> Result<(String, u64)> {
    hash_tracked(path, limit, deadline, false)
}
fn hash_tracked(path: &Path, limit: u64, deadline: Instant, metadata: bool) -> Result<(String, u64)> {
    let mut file = open(path, limit)?;
    let mut hash = Sha256::new();
    let mut bytes = 0u64;
    let mut chunk = [0; 65536];
    loop {
        check(deadline)?;
        let allowance = if metadata {
            METADATA_REMAINING.with(|v| v.get().min(chunk.len() as u64) as usize)
        } else { chunk.len() };
        if allowance == 0 {
            ensure!(file.metadata()?.len() == bytes, "combined metadata reads exceed budget");
            break;
        }
        let n = file.read(&mut chunk[..allowance])?;
        if metadata { charge_metadata(n)?; }
        if n == 0 { break; }
        bytes += n as u64;
        ensure!(bytes <= limit, "media input grew beyond bound");
        hash.update(&chunk[..n]);
    }
    Ok((format!("{:x}", hash.finalize()), bytes))
}
pub(super) fn digest(bytes: &[u8]) -> String { format!("{:x}", Sha256::digest(bytes)) }
pub(super) fn text<'a>(v: &'a Value, key: &str) -> Result<&'a str> { v[key].as_str().with_context(|| format!("missing string {key}")) }
pub(super) fn integer(v: &Value) -> Result<u64> {
    v.as_u64().or_else(|| v.as_str().and_then(|s| s.parse().ok())).context("missing nonnegative integer")
}
pub(super) fn relative(root: &Path, path: &str) -> Result<PathBuf> {
    let path = Path::new(path);
    ensure!(!path.as_os_str().is_empty() && path.components().all(|c| matches!(c, Component::Normal(_))), "unsafe bundle member path");
    // No nested directories are needed by this fixed bundle; reject symlink parents.
    ensure!(path.components().count() == 1, "bundle member must be a direct regular file");
    Ok(root.join(path))
}
pub(super) fn verify(path: &Path, identity: &Value, limit: u64, deadline: Instant) -> Result<()> {
    let (sha, bytes) = hash(path, limit, deadline)?;
    ensure!(identity["sha256"] == sha && identity["bytes"] == bytes, "media hash/byte binding mismatch: {}", path.display());
    Ok(())
}
pub(super) fn verify_metadata(path: &Path, identity: &Value, deadline: Instant) -> Result<()> {
    let (sha, bytes) = hash_tracked(path, METADATA_LIMIT, deadline, true)?;
    ensure!(identity["sha256"] == sha && identity["bytes"] == bytes, "metadata hash/byte binding mismatch: {}", path.display());
    Ok(())
}

// Charged before writes, including unsuccessful writes: failure cannot overshoot disk caps.
pub(super) struct Budget { pub total: u64, pub png: u64 }
impl Budget {
    pub fn new() -> Self { Self { total: 0, png: 0 } }
    pub fn charge(&mut self, n: usize, png: bool) -> std::io::Result<()> {
        let n = n as u64;
        // Reserve 16 MiB for the terminal report, including failure records.
        if self.total + n > 112 * MIB || (png && self.png + n > 96 * MIB) {
            return Err(std::io::Error::other("derived bundle/PNG byte bound exceeded"));
        }
        self.total += n;
        if png { self.png += n; }
        Ok(())
    }
    pub fn save(&mut self, path: &Path, bytes: &[u8]) -> Result<()> {
        self.charge(bytes.len(), false)?;
        let mut f = private(path)?;
        f.write_all(bytes)?;
        f.sync_all()?;
        Ok(())
    }
}
pub(super) struct BoundedWriter<'a> {
    pub file: File,
    pub budget: &'a mut Budget,
    pub deadline: Instant,
}
impl Write for BoundedWriter<'_> {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        if Instant::now() >= self.deadline { return Err(std::io::Error::other("PNG deadline exceeded")); }
        self.budget.charge(bytes.len(), true)?;
        self.file.write_all(bytes)?;
        Ok(bytes.len())
    }
    fn flush(&mut self) -> std::io::Result<()> { self.file.flush() }
}
