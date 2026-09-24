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
                Ok(()) | Err(Errno::EXIST) => {}
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

pub(crate) struct Mirror {
    root: Directory,
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
            Ok(()) => Ok(true),
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
        )
        .map_err(Into::into)
    }

    pub fn remove(&self) -> Result<()> {
        fs::unlinkat(&*self.directory.0, self.name.as_str(), AtFlags::empty())?;
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

impl Mirror {
    pub fn open(path: &Path) -> Result<Self> {
        let fd = fs::open(path, DIRECTORY_FLAGS, Mode::empty())
            .context("opening the sync root without symlinks")?;
        Ok(Self {
            root: Directory(Arc::new(File::from(fd))),
        })
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
    ) -> Result<()> {
        let mut pending = vec![if conflicts {
            ".mysync-conflicts".to_owned()
        } else {
            String::new()
        }];
        while let Some(path) = pending.pop() {
            let mut directory = Some(self.root.clone());
            for part in path.split('/').filter(|p| !p.is_empty()) {
                directory = match directory {
                    Some(d) => d.child(part, false)?,
                    None => None,
                };
            }
            let Some(directory) = directory else { continue };
            for item in fs::Dir::read_from(&*directory.0)? {
                let item = item?;
                let name = item.file_name().to_str().context("non-UTF-8 filename")?;
                if name == "."
                    || name == ".."
                    || (!conflicts && matches!(name, ".mysync-conflicts" | ".mysync-staging"))
                {
                    continue;
                }
                let relative = if path.is_empty() {
                    name.to_owned()
                } else {
                    format!("{path}/{name}")
                };
                let stat = fs::statat(&*directory.0, name, AtFlags::SYMLINK_NOFOLLOW)?;
                let kind = FileType::from_raw_mode(stat.st_mode);
                if !matches!(kind, FileType::Directory | FileType::RegularFile) {
                    continue;
                }
                if (!conflicts && !valid_path(&relative)) || relative.len() > 8192 {
                    bail!("invalid filename in sync folder: {relative}");
                }
                if kind == FileType::Directory {
                    pending.push(relative);
                } else if let Some(file) = directory.entry(name.to_owned()).read()? {
                    visit(relative, file)?;
                }
            }
        }
        Ok(())
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
