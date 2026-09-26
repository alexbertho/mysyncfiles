use std::{
    collections::{BTreeMap, BTreeSet},
    path::{Path, PathBuf},
    time::Duration,
};

use anyhow::{Context, Result, anyhow, bail};
use fs2::FileExt;
use notify::{RecursiveMode, Watcher};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use uuid::Uuid;

use crate::local_fs::Mirror;
pub use crate::local_fs::ScanIssue;
use crate::model::Entry;

mod api;
mod enrollment;
pub use api::Api;
pub use enrollment::{
    SetupOutcome, activate_enrollment, enroll, enroll_with_tcti, setup, setup_with_tcti,
};

#[derive(Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ClientConfig {
    pub server: String,
    /// Obtained from the administrator over an independently trusted channel.
    #[serde(default)]
    pub server_public_key: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub identity: Option<crate::tpm::Identity>,
    pub root: PathBuf,
    #[serde(default = "default_auto_update")]
    pub auto_update: bool,
    #[serde(default = "default_update_public_key")]
    pub update_public_key: String,
}

fn default_auto_update() -> bool {
    true
}

fn default_update_public_key() -> String {
    crate::release::PUBLIC_KEY_HEX.trim().to_owned()
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
struct LocalState {
    entries: BTreeMap<String, Seen>,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
struct Seen {
    revision: i64,
    sha256: Option<String>,
}

#[derive(Default)]
pub struct SyncReport {
    pub issues: Vec<ScanIssue>,
    pub uploaded: usize,
    pub downloaded: usize,
    pub deleted_local: usize,
    pub deleted_remote: usize,
    pub conflicts: usize,
}

pub struct Status {
    pub issues: Vec<ScanIssue>,
    pub local_files: usize,
    pub remote_files: usize,
    pub pending_local: usize,
    pub conflicts: usize,
    pub generation: i64,
}

pub fn default_config_path() -> Result<PathBuf> {
    let base = std::env::var_os("XDG_CONFIG_HOME")
        .map(PathBuf::from)
        .or_else(|| std::env::var_os("HOME").map(|home| PathBuf::from(home).join(".config")))
        .ok_or_else(|| anyhow!("HOME or XDG_CONFIG_HOME is required"))?;
    Ok(base.join("mysync").join("config.json"))
}

fn state_path(config_path: &Path) -> PathBuf {
    config_path.with_extension("state.json")
}

fn lock_path(config_path: &Path) -> PathBuf {
    config_path.with_extension("lock")
}

async fn acquire_lock(config_path: &Path) -> Result<std::fs::File> {
    let path = lock_path(config_path);
    tokio::task::spawn_blocking(move || {
        let mut options = std::fs::OpenOptions::new();
        options.read(true).write(true).create(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        let file = options.open(path)?;
        file.lock_exclusive()?;
        Ok(file)
    })
    .await?
}

fn private_write_json<T: Serialize>(path: &Path, value: &T) -> Result<()> {
    let parent = path
        .parent()
        .ok_or_else(|| anyhow!("invalid config path"))?;
    let parent = if parent.as_os_str().is_empty() {
        Path::new(".")
    } else {
        parent
    };
    std::fs::create_dir_all(parent)?;
    let temp = parent.join(format!(".mysync-{}", Uuid::new_v4()));
    let result: Result<()> = (|| {
        let mut options = std::fs::OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        let file = options.open(&temp)?;
        let mut writer = std::io::BufWriter::new(file);
        serde_json::to_writer_pretty(&mut writer, value)?;
        use std::io::Write;
        writer.flush()?;
        writer.get_ref().sync_all()?;
        std::fs::rename(&temp, path)?;
        std::fs::File::open(parent)?.sync_all()?;
        Ok(())
    })();
    if result.is_err() {
        let _ = std::fs::remove_file(&temp);
    }
    result
}

pub fn load_config(path: &Path) -> Result<ClientConfig> {
    let config: ClientConfig = serde_json::from_slice(
        &std::fs::read(path).with_context(|| format!("reading {}", path.display()))?,
    )?;
    if !config.root.is_dir() {
        bail!("sync folder does not exist: {}", config.root.display());
    }
    Ok(config)
}

/// Explicit local trust change; never fetch a trust anchor through the proxy.
pub async fn trust_server(config_path: &Path, public_key: &str) -> Result<()> {
    let key = crate::origin_auth::public_key(public_key)?;
    let _lock = acquire_lock(config_path).await?;
    let mut config = load_config(config_path)?;
    config.server_public_key = hex::encode(key.to_bytes());
    private_write_json(config_path, &config)
}

fn load_state(config_path: &Path) -> Result<LocalState> {
    let path = state_path(config_path);
    let mut state: LocalState = match std::fs::read(&path) {
        Ok(contents) => serde_json::from_slice(&contents).context("reading local sync state")?,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => LocalState::default(),
        Err(error) => return Err(error.into()),
    };
    match std::fs::File::open(journal_path(config_path)) {
        Ok(file) => {
            use std::io::BufRead;
            let mut reader = std::io::BufReader::new(file);
            let mut line = Vec::new();
            loop {
                line.clear();
                reader.read_until(b'\n', &mut line)?;
                // A torn final append has not been acknowledged as durable.
                if line.last() != Some(&b'\n') {
                    break;
                }
                let (path, seen): (String, Seen) =
                    serde_json::from_slice(&line).context("reading local sync journal")?;
                state.entries.insert(path, seen);
            }
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => return Err(error.into()),
    }
    Ok(state)
}

fn save_state(config_path: &Path, state: &LocalState) -> Result<()> {
    private_write_json(&state_path(config_path), state)
}

fn journal_path(config_path: &Path) -> PathBuf {
    config_path.with_extension("state.journal")
}

// One full snapshot per pass. Only mutations need small, individually durable
// records: cancellation must not forget an acknowledged upload or replacement.
struct Checkpoint<'a> {
    config_path: &'a Path,
    state: LocalState,
    dirty: bool,
    journal: Option<std::fs::File>,
}

impl<'a> Checkpoint<'a> {
    fn open(config_path: &'a Path) -> Result<Self> {
        let mut checkpoint = Self {
            config_path,
            state: load_state(config_path)?,
            dirty: journal_path(config_path).exists(),
            journal: None,
        };
        // Compact recovered records (and discard any incomplete tail) before
        // appending again. Replaying after snapshot publication is idempotent.
        checkpoint.finish()?;
        Ok(checkpoint)
    }

    fn record(&mut self, path: String, seen: Seen, mutation: bool) -> Result<()> {
        if self.state.entries.get(&path) == Some(&seen) {
            return Ok(());
        }
        if mutation {
            use std::{io::Write, os::unix::fs::OpenOptionsExt};
            if self.journal.is_none() {
                let path = journal_path(self.config_path);
                let file = std::fs::OpenOptions::new()
                    .create_new(true)
                    .write(true)
                    .mode(0o600)
                    .open(&path)?;
                file.sync_all()?;
                sync_parent(&path)?;
                self.journal = Some(file);
            }
            let mut bytes = serde_json::to_vec(&(&path, &seen))?;
            bytes.push(b'\n');
            let file = self.journal.as_mut().unwrap();
            file.write_all(&bytes)?;
            file.sync_all()?;
        }
        self.state.entries.insert(path, seen);
        self.dirty = true;
        Ok(())
    }

    fn finish(&mut self) -> Result<()> {
        if self.dirty {
            save_state(self.config_path, &self.state)?;
            self.journal = None;
            let path = journal_path(self.config_path);
            match std::fs::remove_file(&path) {
                Ok(()) => sync_parent(&path)?,
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
                Err(error) => return Err(error.into()),
            }
            self.dirty = false;
        }
        Ok(())
    }
}

fn sync_parent(path: &Path) -> Result<()> {
    let parent = path
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or(Path::new("."));
    std::fs::File::open(parent)?.sync_all()?;
    Ok(())
}

fn hash_reader(
    mut reader: impl std::io::Read,
    mut after_read: impl FnMut() -> Result<()>,
) -> Result<String> {
    let mut hash = Sha256::new();
    let mut buffer = [0_u8; 64 * 1024];
    loop {
        let size = reader.read(&mut buffer)?;
        if size == 0 {
            break;
        }
        hash.update(&buffer[..size]);
        after_read()?;
    }
    Ok(hex::encode(hash.finalize()))
}

#[cfg(test)]
fn hash_file(mut file: std::fs::File) -> Result<String> {
    hash_reader(&mut file, || Ok(()))
}

type FileStamp = (u64, u64, u64, u64, i64, i64, i64, i64);

fn file_stamp(file: &std::fs::File) -> Result<FileStamp> {
    use std::os::unix::fs::MetadataExt;
    let m = file.metadata()?;
    Ok((
        m.dev(),
        m.ino(),
        m.len(),
        m.nlink(),
        m.mtime(),
        m.mtime_nsec(),
        m.ctime(),
        m.ctime_nsec(),
    ))
}

fn unchanged_capture(
    file: &mut std::fs::File,
    observed: Option<&String>,
    mut after_read: impl FnMut(),
) -> Result<bool> {
    let before = file_stamp(file)?;
    let digest = hash_reader(&mut *file, || {
        after_read();
        Ok(())
    })?;
    // A digest can match even when an already-read region was edited. ctime
    // also catches writers that restore mtime; atime is deliberately ignored.
    Ok(before == file_stamp(file)? && Some(&digest) == observed)
}

struct Scan {
    files: BTreeMap<String, String>,
    issues: Vec<ScanIssue>,
}

async fn scan(mirror: &Mirror) -> Result<Scan> {
    use std::sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    };
    struct Cancel(Arc<AtomicBool>);
    impl Drop for Cancel {
        fn drop(&mut self) {
            self.0.store(true, Ordering::Relaxed);
        }
    }
    let cancelled = Arc::new(AtomicBool::new(false));
    let _cancel = Cancel(cancelled.clone());
    let mirror = mirror.clone();
    tokio::task::spawn_blocking(move || {
        let mut files = BTreeMap::new();
        let issues = mirror.visit_files(false, |path, file| {
            let digest = hash_reader(file, || {
                anyhow::ensure!(!cancelled.load(Ordering::Relaxed), "scan cancelled");
                Ok(())
            })?;
            files.insert(path, digest);
            Ok(())
        })?;
        Ok(Scan { files, issues })
    })
    .await?
}

async fn apply_remote(
    api: &Api,
    mirror: &Mirror,
    entry: &Entry,
    observed: Option<&String>,
    preserve_local: bool,
    report: &mut SyncReport,
) -> Result<bool> {
    let temp = if entry.deleted {
        None
    } else {
        let temp = mirror.download_file()?;
        if !api.download(entry, temp.file.try_clone()?).await? {
            return Ok(false);
        }
        Some(temp)
    };

    // Resolve again AFTER the network wait. Holding directory descriptors then
    // makes every move, deletion and permission change independent of symlinks
    // installed at a previously checked path.
    let Some(target) = mirror.entry(&entry.path, !entry.deleted)? else {
        return Ok(true); // The parent of a remotely deleted file is absent.
    };
    let directory = target.is_directory()?;
    // A tombstone refers to a file, never to all files below a directory that
    // now occupies its name (including a local file -> directory transition).
    if directory && entry.deleted {
        return Ok(true);
    }
    let current = if directory { None } else { target.read()? };
    if !directory && current.is_none() && observed.is_some() {
        return Ok(false); // A concurrent local deletion needs a fresh scan.
    }

    // Capture the actual file before replacing it. No local data ever enters
    // staging, and an error or cancellation leaves this recovery copy intact.
    let saved = if directory || current.is_some() {
        let (backup, display) = mirror.conflict_entry(&entry.path)?;
        match target.move_to(&backup) {
            Ok(()) => {}
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(false),
            Err(error) => return Err(error.into()),
        }
        eprintln!("local recovery copy: {display}");
        if !backup.is_directory()? {
            let captured = backup
                .read()?
                .ok_or_else(|| anyhow!("recovery copy disappeared"))?;
            captured.sync_all()?;
            if let Some(temp) = &temp {
                temp.file
                    .set_permissions(captured.metadata()?.permissions())?;
                temp.file.sync_all()?;
            }
        }
        Some((backup, display))
    } else {
        None
    };

    if let Some(temp) = &temp {
        match temp.entry.move_to(&target) {
            Ok(()) => report.downloaded += 1,
            // An editor created another file after capture: leave it and the
            // recovery copy untouched, then reconcile on a fresh pass.
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
                if saved.is_some() {
                    report.conflicts += 1;
                }
                return Ok(false);
            }
            Err(error) => return Err(error.into()),
        }
    } else if saved.is_some() {
        report.deleted_local += 1;
    }

    if let Some((backup, display)) = saved {
        if backup.is_directory()? {
            // Preserve whole subtrees, including files created during download.
            if !backup.remove_empty_directory()? {
                eprintln!("directory conflict saved: {display}");
                report.conflicts += 1;
            }
            return Ok(true);
        }
        // Hash the displaced file after publication, not the stale pre-download
        // pathname. Edits made while downloading or just before capture survive.
        let mut captured = backup
            .read()?
            .ok_or_else(|| anyhow!("recovery copy disappeared"))?;
        let changed = !unchanged_capture(&mut captured, observed, || {})?;
        if preserve_local || changed {
            eprintln!("conflict copy saved: {display}");
            report.conflicts += 1;
        } else {
            backup.remove()?;
        }
    }
    Ok(true)
}

async fn sync_pass(
    config_path: &Path,
    api: &Api,
    mirror: &Mirror,
    report: &mut SyncReport,
) -> Result<bool> {
    let manifest = api.manifest().await?;
    let remote: BTreeMap<String, Entry> = manifest
        .entries
        .into_iter()
        .map(|entry| (entry.path.clone(), entry))
        .collect();
    let scanned = scan(mirror).await?;
    let local = scanned.files;
    let pass_issues = scanned.issues;
    for issue in &pass_issues {
        if !report
            .issues
            .iter()
            .any(|previous| previous.path == issue.path && previous.error == issue.error)
        {
            report.issues.push(issue.clone());
        }
        eprintln!("sync skipped {:?}: {}", issue.path, issue.error);
    }
    let mut checkpoint = Checkpoint::open(config_path)?;
    let state = &checkpoint.state;
    let paths: BTreeSet<String> = remote
        .keys()
        .chain(local.keys())
        .chain(state.entries.keys())
        .cloned()
        .collect();
    // Deletions before creations, deepest first, allow both a/b -> a and
    // a -> a/b without transient file/directory collisions.
    let replaced_paths: BTreeSet<String> = paths
        .iter()
        .filter(|path| {
            path.match_indices('/').any(|(index, _)| {
                let ancestor = &path[..index];
                remote.get(ancestor).is_some_and(|e| {
                    !e.deleted
                        && state
                            .entries
                            .get(ancestor)
                            .is_none_or(|s| s.revision != e.revision)
                })
            })
        })
        .cloned()
        .collect();
    let mut paths: Vec<_> = paths.into_iter().collect();
    paths.sort_by_key(|path| {
        let deletion = remote.get(path).is_some_and(|e| {
            e.deleted
                && (!local.contains_key(path)
                    || replaced_paths.contains(path)
                    || state
                        .entries
                        .get(path)
                        .is_none_or(|s| s.revision != e.revision))
        }) || (!local.contains_key(path)
            && state.entries.get(path).is_some_and(|s| s.sha256.is_some()));
        let remote_creation = remote.get(path).is_some_and(|e| {
            !e.deleted
                && state
                    .entries
                    .get(path)
                    .is_none_or(|s| s.revision != e.revision)
        });
        (
            if deletion {
                0
            } else if remote_creation {
                1
            } else {
                2
            },
            std::cmp::Reverse(path.matches('/').count()),
            path.clone(),
        )
    });
    let result = async {
        let mut rescan = false;
        for path in paths {
            if pass_issues.iter().any(|issue| issue.affects(&path)) {
                continue;
            }
            let server = remote.get(&path);
            let observed = local.get(&path);
            let prior = checkpoint.state.entries.get(&path);
            if server.is_none() && prior.is_some() {
                bail!("server lost metadata for {path}; refusing to guess how to reconcile it");
            }
            let remote_revision = server.map(|entry| entry.revision).unwrap_or(0);
            let remote_sha = server.and_then(|entry| entry.sha256.as_ref());
            if remote_revision > 0 && observed == remote_sha {
                checkpoint.record(
                    path.clone(),
                    Seen {
                        revision: remote_revision,
                        sha256: remote_sha.cloned(),
                    },
                    false,
                )?;
                continue;
            }
            let replaced_by_ancestor = replaced_paths.contains(&path);
            if replaced_by_ancestor && server.is_none() {
                continue; // The incoming ancestor captures this untracked subtree.
            }
            let remote_changed = replaced_by_ancestor
                || prior
                    .map(|seen| seen.revision != remote_revision)
                    .unwrap_or(remote_revision != 0);
            let local_changed = prior
                .map(|seen| seen.sha256.as_ref() != observed)
                .unwrap_or(observed.is_some());
            if remote_changed {
                let entry = server.expect("remote revision implies entry");
                let preserve = local_changed && observed.is_some();
                if !apply_remote(api, mirror, entry, observed, preserve, report).await? {
                    return Ok(true);
                }
                checkpoint.record(
                    path.clone(),
                    Seen {
                        revision: entry.revision,
                        sha256: entry.sha256.clone(),
                    },
                    true,
                )?;
                if !entry.deleted && local.keys().any(|p| p.starts_with(&format!("{path}/"))) {
                    rescan = true; // Check all displaced directories on a fresh pass.
                }
            } else if local_changed {
                let base = prior.map(|seen| seen.revision).unwrap_or(0);
                let result = if let Some(observed) = observed {
                    let Some(file) = mirror.read(&path)? else {
                        return Ok(true);
                    };
                    api.upload(&path, base, file, observed).await?
                } else if server.is_some_and(|entry| !entry.deleted) {
                    api.delete(&path, base).await?
                } else {
                    continue;
                };
                let Some(entry) = result else {
                    return Ok(true);
                };
                if entry.deleted {
                    report.deleted_remote += 1;
                } else {
                    report.uploaded += 1;
                }
                checkpoint.record(
                    path.clone(),
                    Seen {
                        revision: entry.revision,
                        sha256: entry.sha256.clone(),
                    },
                    true,
                )?;
            }
        }
        Ok(rescan)
    }
    .await;
    checkpoint.finish()?;
    result
}

async fn sync_passes(config_path: &Path, root: &Path, api: &Api) -> Result<SyncReport> {
    let mirror = Mirror::open(root)?;
    mirror.clear_staging()?;
    let mut report = SyncReport::default();
    for _ in 0..5 {
        if !sync_pass(config_path, api, &mirror, &mut report).await? {
            return Ok(report);
        }
    }
    bail!("files kept changing during sync; retry shortly")
}

pub async fn sync(config_path: &Path) -> Result<SyncReport> {
    let _lock = acquire_lock(config_path).await?;
    let config = load_config(config_path)?;
    let api = Api::new(&config)?;
    sync_passes(config_path, &config.root, &api).await
}

pub async fn status(config_path: &Path) -> Result<Status> {
    let config = load_config(config_path)?;
    let api = Api::new(&config)?;
    let manifest = api.manifest().await?;
    let mirror = Mirror::open(&config.root)?;
    let scanned = scan(&mirror).await?;
    let local = scanned.files;
    let mut issues = scanned.issues;
    let state = load_state(config_path)?;
    let changed_files = local
        .iter()
        .filter(|(path, hash)| {
            state
                .entries
                .get(*path)
                .and_then(|seen| seen.sha256.as_ref())
                != Some(*hash)
        })
        .count();
    let deleted_files = state
        .entries
        .iter()
        .filter(|(path, seen)| {
            seen.sha256.is_some()
                && !local.contains_key(*path)
                && !issues.iter().any(|issue| issue.affects(path))
        })
        .count();
    let mut conflicts = 0;
    issues.extend(mirror.visit_files(true, |_, _| {
        conflicts += 1;
        Ok(())
    })?);
    Ok(Status {
        issues,
        local_files: local.len(),
        remote_files: manifest
            .entries
            .iter()
            .filter(|entry| !entry.deleted)
            .count(),
        pending_local: changed_files + deleted_files,
        conflicts,
        generation: manifest.generation,
    })
}

pub async fn daemon(config_path: &Path) -> Result<()> {
    let config = load_config(config_path)?;
    let api = Api::new(&config)?;
    let mut terminate = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())?;
    let (tx, mut rx) = tokio::sync::mpsc::channel(1);
    let watch_root = config.root.clone();
    let mut watcher: Option<notify::RecommendedWatcher> =
        match notify::recommended_watcher(move |event: notify::Result<notify::Event>| {
            if event.is_ok_and(|event| watch_event_requires_sync(&watch_root, &event)) {
                let _ = tx.try_send(());
            }
        }) {
            Ok(watcher) => Some(watcher),
            Err(error) => {
                eprintln!(
                    "filesystem watcher unavailable ({error}); continuing with 15-second polling"
                );
                None
            }
        };
    let watch_error = watcher
        .as_mut()
        .and_then(|watcher| watcher.watch(&config.root, RecursiveMode::Recursive).err());
    if let Some(error) = watch_error {
        eprintln!("filesystem watcher unavailable ({error}); continuing with 15-second polling");
        drop(watcher.take());
    }
    let mut interval = tokio::time::interval(Duration::from_secs(15));
    interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    interval.tick().await;
    let mut update_interval = tokio::time::interval(Duration::from_secs(6 * 60 * 60));
    update_interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    loop {
        let sync = async {
            let _lock = acquire_lock(config_path).await?;
            sync_passes(config_path, &config.root, &api).await
        };
        tokio::pin!(sync);
        tokio::select! {
            result = &mut sync => {
                if let Err(error) = result {
                    eprintln!("sync failed: {error:#}");
                }
            }
            _ = tokio::signal::ctrl_c() => return Ok(()),
            _ = terminate.recv() => return Ok(()),
        }
        tokio::select! {
            _ = interval.tick() => {},
            event = rx.recv() => {
                if event.is_none() {
                    bail!("filesystem watcher stopped");
                }
                tokio::time::sleep(Duration::from_millis(700)).await;
                while rx.try_recv().is_ok() {}
            },
            _ = update_interval.tick(), if config.auto_update => {
                let update = crate::update::check_and_install(&config.server, &config.update_public_key);
                tokio::pin!(update);
                tokio::select! {
                    result = &mut update => match result {
                        Ok(crate::update::UpdateOutcome::Installed(version)) => {
                            eprintln!("client updated to {version}; restarting service");
                            return Ok(());
                        }
                        Ok(crate::update::UpdateOutcome::Current) => {}
                        Err(error) => eprintln!("client update check failed: {error:#}"),
                    },
                    _ = tokio::signal::ctrl_c() => return Ok(()),
                    _ = terminate.recv() => return Ok(()),
                }
            },
            _ = tokio::signal::ctrl_c() => return Ok(()),
            _ = terminate.recv() => return Ok(()),
        }
    }
}

fn watch_event_requires_sync(root: &Path, event: &notify::Event) -> bool {
    if event.need_rescan() {
        return true;
    }
    use notify::{
        EventKind,
        event::{AccessKind, AccessMode},
    };
    if matches!(event.kind, EventKind::Access(kind) if kind != AccessKind::Close(AccessMode::Write))
    {
        return false;
    }
    event.need_rescan()
        || event.paths.is_empty()
        || event.paths.iter().any(|path| {
            path.strip_prefix(root).map_or(true, |relative| {
                !relative.components().any(|part| {
                    matches!(
                        part.as_os_str().to_str(),
                        Some(".mysync-staging" | ".mysync-conflicts")
                    )
                })
            })
        })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn recovery_hash_detects_writes_to_an_already_read_region() -> Result<()> {
        use std::os::unix::fs::FileExt;
        let temp = tempfile::tempdir()?;
        let path = temp.path().join("recovery");
        std::fs::write(&path, vec![0u8; 3 * 64 * 1024])?;
        let writer = std::fs::OpenOptions::new().write(true).open(&path)?;
        let observed = hash_file(std::fs::File::open(&path)?)?;
        let mut captured = std::fs::File::open(&path)?;
        let mut wrote = false;
        assert!(!unchanged_capture(&mut captured, Some(&observed), || {
            if !wrote {
                writer.write_all_at(b"late edit", 0).unwrap();
                wrote = true;
            }
        })?);
        assert!(wrote);
        let new_hash = hash_file(std::fs::File::open(&path)?)?;
        assert_ne!(new_hash, observed);
        assert!(unchanged_capture(
            &mut std::fs::File::open(&path)?,
            Some(&new_hash),
            || {}
        )?);
        Ok(())
    }

    #[test]
    fn checkpoint_recovers_mutations_and_torn_tail_without_rewriting_noop_state() -> Result<()> {
        use std::{io::Write, os::unix::fs::MetadataExt};
        let temp = tempfile::tempdir()?;
        let config = temp.path().join("config.json");
        let seen = Seen {
            revision: 1,
            sha256: Some("hash".into()),
        };
        let mut checkpoint = Checkpoint::open(&config)?;
        checkpoint.record("a".into(), seen.clone(), true)?;
        checkpoint.record(
            "b".into(),
            Seen {
                revision: 2,
                sha256: None,
            },
            true,
        )?;
        drop(checkpoint); // Simulated cancellation before snapshot publication.
        assert!(!state_path(&config).exists());
        std::fs::OpenOptions::new()
            .append(true)
            .open(journal_path(&config))?
            .write_all(b"[\"torn")?;
        assert_eq!(load_state(&config)?.entries.len(), 2);
        let mut recovered = Checkpoint::open(&config)?;
        assert!(!journal_path(&config).exists());
        let original = std::fs::metadata(state_path(&config))?;
        recovered.record("a".into(), seen, false)?;
        recovered.finish()?;
        let after = std::fs::metadata(state_path(&config))?;
        assert_eq!(
            (original.ino(), original.mtime(), original.mtime_nsec()),
            (after.ino(), after.mtime(), after.mtime_nsec())
        );
        // Crash after publication but before removal of the journal is safe too.
        recovered.record(
            "c".into(),
            Seen {
                revision: 3,
                sha256: None,
            },
            true,
        )?;
        save_state(&config, &recovered.state)?;
        drop(recovered);
        assert_eq!(Checkpoint::open(&config)?.state.entries.len(), 3);
        Ok(())
    }

    #[test]
    fn watcher_keeps_user_mutations_and_filters_reads_and_housekeeping() {
        use notify::{
            Event, EventKind,
            event::{AccessKind, AccessMode, CreateKind, Flag, ModifyKind, RenameMode},
        };
        let root = Path::new("/mirror");
        for kind in [
            AccessKind::Read,
            AccessKind::Open(AccessMode::Any),
            AccessKind::Close(AccessMode::Read),
        ] {
            assert!(!watch_event_requires_sync(
                root,
                &Event::new(EventKind::Access(kind)).add_path(root.join("file"))
            ));
        }
        for kind in [
            EventKind::Modify(ModifyKind::Any),
            EventKind::Create(CreateKind::File),
            EventKind::Access(AccessKind::Close(AccessMode::Write)),
        ] {
            assert!(watch_event_requires_sync(
                root,
                &Event::new(kind).add_path(root.join("file"))
            ));
            for path in [
                ".mysync-staging",
                ".mysync-staging/file",
                ".mysync-conflicts/file",
            ] {
                assert!(!watch_event_requires_sync(
                    root,
                    &Event::new(kind).add_path(root.join(path))
                ));
            }
        }
        let rename = Event::new(EventKind::Modify(ModifyKind::Name(RenameMode::Both)))
            .add_path(root.join(".mysync-conflicts/file"))
            .add_path(root.join("restored"));
        assert!(watch_event_requires_sync(root, &rename));
        assert!(watch_event_requires_sync(
            root,
            &Event::new(EventKind::Other).set_flag(Flag::Rescan)
        ));
    }
}
