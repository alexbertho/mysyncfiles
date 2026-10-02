//! Filesystem capabilities for the Linux mirror. Never reconstruct an absolute
//! path for an operation after checking it: every component is opened relative
//! to an already-open directory, and symlinks are refused by the kernel.
use std::{fs::File, path::Path, sync::Arc};

use anyhow::{Context, Result, bail};
use rustix::{
    fs::{self, AtFlags, FileType, Mode, OFlags, RenameFlags},
    io::Errno,
};
use uuid::Uuid;

use crate::model::valid_path;

/// One reusable inotify instance per mirror: closing an instance may wait for
/// a kernel grace period, so creating/destroying one for every file is costly.
#[derive(Default)]
struct ChangeWatcher(std::sync::Mutex<Option<std::os::fd::OwnedFd>>);

pub(crate) struct ChangeWatch<'a> {
    watcher: std::sync::MutexGuard<'a, Option<std::os::fd::OwnedFd>>,
    id: i32,
}

impl ChangeWatcher {
    fn watch(&self, file: &File) -> std::io::Result<ChangeWatch<'_>> {
        use rustix::fs::inotify::{self, CreateFlags, WatchFlags};
        use std::os::fd::AsRawFd;
        let mut watcher = self.0.lock().unwrap();
        if watcher.is_none() {
            *watcher = Some(inotify::init(CreateFlags::NONBLOCK | CreateFlags::CLOEXEC)?);
        }
        // This kernel-owned name resolves the already-open inode, even after
        // a rename. Never re-resolve a user-supplied mirror pathname here.
        let id = inotify::add_watch(
            watcher.as_ref().unwrap(),
            format!("/proc/self/fd/{}", file.as_raw_fd()),
            WatchFlags::MODIFY
                | WatchFlags::ATTRIB
                | WatchFlags::CLOSE_WRITE
                | WatchFlags::MOVE_SELF
                | WatchFlags::DELETE_SELF,
        )?;
        Ok(ChangeWatch { watcher, id })
    }
}

impl ChangeWatch<'_> {
    pub fn unchanged(&self) -> bool {
        use rustix::fs::inotify::{ReadFlags, Reader};
        let mut buffer = [std::mem::MaybeUninit::uninit(); 512];
        let mut events = Reader::new(self.watcher.as_ref().unwrap(), &mut buffer);
        loop {
            match events.next() {
                Err(Errno::INTR) => continue,
                Err(Errno::AGAIN) => return true,
                Ok(event)
                    if event.wd() != self.id
                        && !event.events().contains(ReadFlags::QUEUE_OVERFLOW) =>
                {
                    continue;
                }
                // A current event, overflow, invalidation or error means the
                // recovery copy must be kept. Ignore old watches' IGNORED events.
                _ => return false,
            }
        }
    }
}

impl Drop for ChangeWatch<'_> {
    fn drop(&mut self) {
        let _ = fs::inotify::remove_watch(self.watcher.as_ref().unwrap(), self.id);
    }
}

const DIRECTORY_FLAGS: OFlags = OFlags::RDONLY
    .union(OFlags::DIRECTORY)
    .union(OFlags::NOFOLLOW)
    .union(OFlags::CLOEXEC);

#[derive(Clone)]
struct Directory(Arc<File>);

impl Directory {
    fn child(&self, name: &str, create: bool) -> Result<Option<Self>> {
        if create {
            match fs::mkdirat(&*self.0, name, Mode::from_raw_mode(0o700)) {
                Ok(()) => self.0.sync_all()?,
                Err(Errno::EXIST) => {}
                Err(error) => return Err(error.into()),
            }
        }
        match fs::openat(&*self.0, name, DIRECTORY_FLAGS, Mode::empty()) {
            Ok(fd) => Ok(Some(Self(Arc::new(File::from(fd))))),
            Err(Errno::NOENT | Errno::NOTDIR) if !create => Ok(None),
            Err(error) => Err(error).with_context(|| format!("opening safe directory {name}")),
        }
    }

    fn entry(&self, name: String) -> LocalEntry {
        LocalEntry {
            directory: self.clone(),
            name,
        }
    }
}

#[derive(Clone)]
pub(crate) struct Mirror {
    root: Directory,
    changes: Arc<ChangeWatcher>,
}

pub(crate) struct LocalEntry {
    directory: Directory,
    name: String,
}

impl LocalEntry {
    pub fn is_directory(&self) -> Result<bool> {
        match fs::statat(
            &*self.directory.0,
            self.name.as_str(),
            AtFlags::SYMLINK_NOFOLLOW,
        ) {
            Ok(stat) => Ok(FileType::from_raw_mode(stat.st_mode) == FileType::Directory),
            Err(Errno::NOENT) => Ok(false),
            Err(error) => Err(error.into()),
        }
    }

    /// Kernel-atomic emptiness check: never recursively delete user contents.
    pub fn remove_empty_directory(&self) -> Result<bool> {
        match fs::unlinkat(&*self.directory.0, self.name.as_str(), AtFlags::REMOVEDIR) {
            Ok(()) => {
                self.directory.0.sync_all()?;
                Ok(true)
            }
            Err(Errno::NOTEMPTY | Errno::EXIST) => Ok(false),
            Err(error) => Err(error.into()),
        }
    }

    pub fn read(&self) -> Result<Option<File>> {
        let fd = match fs::openat(
            &*self.directory.0,
            self.name.as_str(),
            OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::NONBLOCK | OFlags::CLOEXEC,
            Mode::empty(),
        ) {
            Ok(fd) => fd,
            Err(Errno::NOENT) => return Ok(None),
            Err(error) => return Err(error).context("opening a mirror file without symlinks"),
        };
        let file = File::from(fd);
        if !file.metadata()?.is_file() {
            bail!("refusing to access a non-regular file: {}", self.name);
        }
        Ok(Some(file))
    }

    /// Never overwrite a file created since the last observation.
    pub fn move_to(&self, destination: &Self) -> std::io::Result<()> {
        fs::renameat_with(
            &*self.directory.0,
            self.name.as_str(),
            &*destination.directory.0,
            destination.name.as_str(),
            RenameFlags::NOREPLACE,
        )?;
        // Both names must be durable before a checkpoint can acknowledge the
        // move. Keep using the pinned descriptors, including after a rename.
        destination.directory.0.sync_all()?;
        self.directory.0.sync_all()
    }

    pub fn remove(&self) -> Result<()> {
        fs::unlinkat(&*self.directory.0, self.name.as_str(), AtFlags::empty())?;
        self.directory.0.sync_all()?;
        Ok(())
    }
}

/// Contains downloaded bytes only. Displaced local files must never be put in
/// staging: cancellation or startup cleanup would then destroy user data.
pub(crate) struct DownloadFile {
    pub entry: LocalEntry,
    pub file: File,
}

impl Drop for DownloadFile {
    fn drop(&mut self) {
        let _ = self.entry.remove();
    }
}

/// A path that was not completely observed. Its previous state must be kept.
#[derive(Clone, Debug)]
pub struct ScanIssue {
    pub path: String,
    pub error: String,
}

impl ScanIssue {
    pub fn affects(&self, path: &str) -> bool {
        self.path.is_empty()
            || self.path == path
            || path.starts_with(&format!("{}/", self.path))
            || self.path.starts_with(&format!("{path}/"))
    }
}

impl Mirror {
    pub fn open(path: &Path) -> Result<Self> {
        let fd = fs::open(path, DIRECTORY_FLAGS, Mode::empty())
            .context("opening the sync root without symlinks")?;
        Ok(Self {
            root: Directory(Arc::new(File::from(fd))),
            changes: Arc::new(ChangeWatcher::default()),
        })
    }

    pub fn watch_changes(&self, file: &File) -> std::io::Result<ChangeWatch<'_>> {
        self.changes.watch(file)
    }

    pub fn entry(&self, path: &str, create_parents: bool) -> Result<Option<LocalEntry>> {
        if !valid_path(path) {
            bail!("invalid mirror path: {path}");
        }
        let mut directory = self.root.clone();
        let mut components = path.split('/').peekable();
        while let Some(component) = components.next() {
            if components.peek().is_none() {
                return Ok(Some(directory.entry(component.to_owned())));
            }
            let Some(child) = directory.child(component, create_parents)? else {
                return Ok(None);
            };
            directory = child;
        }
        unreachable!("valid paths are nonempty")
    }

    pub fn read(&self, path: &str) -> Result<Option<File>> {
        match self.entry(path, false)? {
            Some(entry) => entry.read(),
            None => Ok(None),
        }
    }

    /// Enumerate and read through capabilities too: a valid relative path can
    /// exceed PATH_MAX once prefixed with the absolute mirror location. Reopen
    /// each queued directory from the root to keep descriptor usage bounded.
    pub fn visit_files(
        &self,
        conflicts: bool,
        mut visit: impl FnMut(String, File) -> Result<()>,
    ) -> Result<Vec<ScanIssue>> {
        let mut issues = Vec::new();
        let mut pending = vec![if conflicts {
            ".mysync-conflicts".to_owned()
        } else {
            String::new()
        }];
        while let Some(path) = pending.pop() {
            let result: Result<()> = (|| {
                let mut directory = Some(self.root.clone());
                for part in path.split('/').filter(|p| !p.is_empty()) {
                    directory = match directory {
                        Some(d) => d.child(part, false)?,
                        None => None,
                    };
                }
                let Some(directory) = directory else {
                    return Ok(());
                };
                for item in fs::Dir::read_from(&*directory.0)? {
                    let item = item?;
                    let raw = item.file_name();
                    let name = raw.to_string_lossy();
                    if name == "."
                        || name == ".."
                        || (!conflicts && matches!(&*name, ".mysync-conflicts" | ".mysync-staging"))
                    {
                        continue;
                    }
                    let relative = if path.is_empty() {
                        name.to_string()
                    } else {
                        format!("{path}/{name}")
                    };
                    let result: Result<()> = (|| {
                        let name = raw.to_str().context("non-UTF-8 filename")?;
                        if (!conflicts && !valid_path(&relative)) || relative.len() > 8192 {
                            bail!("filename is not supported by the sync protocol");
                        }
                        let stat = match fs::statat(&*directory.0, name, AtFlags::SYMLINK_NOFOLLOW)
                        {
                            Ok(stat) => stat,
                            Err(Errno::NOENT) => return Ok(()),
                            Err(error) => return Err(error.into()),
                        };
                        match FileType::from_raw_mode(stat.st_mode) {
                            FileType::Directory => pending.push(relative.clone()),
                            FileType::RegularFile => {
                                if let Some(file) = directory.entry(name.to_owned()).read()? {
                                    visit(relative.clone(), file)?;
                                }
                            }
                            _ => bail!("symlinks and non-regular files are not synchronized"),
                        }
                        Ok(())
                    })();
                    if let Err(error) = result {
                        issues.push(ScanIssue {
                            path: relative,
                            error: format!("{error:#}"),
                        });
                    }
                }
                Ok(())
            })();
            if let Err(error) = result {
                issues.push(ScanIssue {
                    path,
                    error: format!("{error:#}"),
                });
            }
        }
        Ok(issues)
    }

    fn staging(&self) -> Result<Directory> {
        let directory = self.root.child(".mysync-staging", true)?.unwrap();
        fs::fchmod(&*directory.0, Mode::from_raw_mode(0o700))?;
        Ok(directory)
    }

    pub fn download_file(&self) -> Result<DownloadFile> {
        let entry = self.staging()?.entry(Uuid::new_v4().to_string());
        let fd = fs::openat(
            &*entry.directory.0,
            entry.name.as_str(),
            OFlags::RDWR | OFlags::CREATE | OFlags::EXCL | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::from_raw_mode(0o600),
        )?;
        Ok(DownloadFile {
            entry,
            file: File::from(fd),
        })
    }

    pub fn clear_staging(&self) -> Result<()> {
        let directory = self.staging()?;
        for entry in fs::Dir::read_from(&*directory.0)? {
            let entry = entry?;
            let name = entry.file_name();
            let stat = fs::statat(&*directory.0, name, AtFlags::SYMLINK_NOFOLLOW)?;
            if FileType::from_raw_mode(stat.st_mode) == FileType::RegularFile {
                fs::unlinkat(&*directory.0, name, AtFlags::empty())?;
            }
        }
        Ok(())
    }

    pub fn conflict_entry(&self, path: &str) -> Result<(LocalEntry, String)> {
        if !valid_path(path) {
            bail!("invalid conflict path: {path}");
        }
        let mut directory = self.root.child(".mysync-conflicts", true)?.unwrap();
        let (parent, filename) = path.rsplit_once('/').unwrap_or(("", path));
        if !parent.is_empty() {
            for component in parent.split('/') {
                directory = directory.child(component, true)?.unwrap();
            }
        }
        let suffix = format!(".conflict-{}", Uuid::new_v4().simple());
        // The source filename may already occupy all 255 bytes allowed by Linux.
        let mut length = filename.len().min(255 - suffix.len());
        while !filename.is_char_boundary(length) {
            length -= 1;
        }
        let name = format!("{}{suffix}", &filename[..length]);
        let display = if parent.is_empty() {
            format!(".mysync-conflicts/{name}")
        } else {
            format!(".mysync-conflicts/{parent}/{name}")
        };
        Ok((directory.entry(name), display))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn change_watch_follows_the_open_inode_after_a_path_is_replaced() -> Result<()> {
        use std::os::unix::fs::{FileExt, symlink};
        let temp = tempfile::tempdir()?;
        let path = temp.path().join("file");
        let outside = temp.path().join("other");
        std::fs::write(&path, b"original")?;
        std::fs::write(&outside, b"other")?;
        let file = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open(&path)?;
        std::fs::rename(&path, temp.path().join("captured"))?;
        symlink(&outside, &path)?;
        let changes = ChangeWatcher::default();
        let watch = changes.watch(&file)?;
        std::fs::write(&outside, b"unrelated edit")?;
        assert!(watch.unchanged());
        file.write_all_at(b"late edit", 0)?;
        assert!(!watch.unchanged());
        drop(watch);
        // Reusing the instance must ignore the previous watch's removal event.
        let next = changes.watch(&file)?;
        assert!(next.unchanged());
        Ok(())
    }

    #[test]
    fn scan_reports_one_bad_entry_and_keeps_scanning() -> Result<()> {
        let temp = tempfile::tempdir()?;
        std::fs::write(temp.path().join("valid.txt"), b"valid")?;
        #[cfg(unix)]
        std::os::unix::fs::symlink("missing-target", temp.path().join("bad-link"))?;

        let mirror = Mirror::open(temp.path())?;
        let mut files = Vec::new();
        let issues = mirror.visit_files(false, |path, _| {
            files.push(path);
            Ok(())
        })?;
        assert_eq!(files, vec!["valid.txt"]);
        #[cfg(unix)]
        assert!(issues.iter().any(|issue| issue.path == "bad-link"));
        #[cfg(not(unix))]
        assert!(issues.is_empty());
        Ok(())
    }
}
