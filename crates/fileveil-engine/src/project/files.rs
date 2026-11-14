// SPDX-License-Identifier: MPL-2.0
//! Directory-handle-bound project I/O, with caller-supplied MCP root identities.
use super::{ProjectKey, ProjectScope};
use fileveil_core::{Error, Result};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    ffi::OsStr,
    fs::{self, File},
    io::{Read, Seek, SeekFrom, Write},
    path::{Component, Path, PathBuf},
    sync::atomic::{AtomicBool, Ordering},
    time::UNIX_EPOCH,
};

pub(super) fn blocked(message: &str) -> Error {
    Error::Blocked(format!("Project access denied. {message}"))
}
pub(super) fn cancelled(flag: &AtomicBool) -> Result<()> {
    if flag.load(Ordering::Relaxed) {
        Err(Error::Interrupted("Project operation cancelled".into()))
    } else {
        Ok(())
    }
}

pub(super) fn absolute(path: &Path, base: &Path) -> Result<PathBuf> {
    let joined = if path.is_absolute() {
        path.to_path_buf()
    } else {
        base.join(path)
    };
    let mut result = PathBuf::new();
    for part in joined.components() {
        match part {
            Component::ParentDir => {
                if !result.pop() {
                    return Err(blocked("Path traverses beyond its filesystem root"));
                }
            }
            Component::CurDir => {}
            _ => result.push(part.as_os_str()),
        }
    }
    if !result.is_absolute() {
        return Err(blocked("Expected an absolute project path"));
    }
    #[cfg(target_os = "macos")]
    for alias in ["/var", "/tmp", "/etc"] {
        if let Ok(relative) = result.strip_prefix(alias) {
            return Ok(Path::new("/private")
                .join(alias.trim_start_matches('/'))
                .join(relative));
        }
    }
    #[cfg(windows)]
    if matches!(result.components().next(), Some(Component::Prefix(prefix)) if matches!(prefix.kind(), std::path::Prefix::Disk(_)))
    {
        return Ok(PathBuf::from(format!("\\\\?\\{}", result.display())));
    }
    Ok(result)
}

pub(super) fn relative_name(path: &Path) -> Result<String> {
    if path.as_os_str().is_empty()
        || path.is_absolute()
        || path
            .components()
            .any(|c| !matches!(c, Component::Normal(_)))
    {
        return Err(blocked("Manifest paths must be relative file paths"));
    }
    let raw = path
        .to_str()
        .ok_or_else(|| blocked("Project file names must be valid UTF-8"))?;
    #[cfg(not(windows))]
    if raw.contains('\\') {
        return Err(blocked(
            "Project file names cannot contain literal backslashes",
        ));
    }
    let value = raw.replace('\\', "/");
    if value.len() > 4096
        || value.contains(['\0', ':', '\r', '\n'])
        || value.split('/').any(|part| matches!(part, "" | "." | ".."))
    {
        return Err(blocked("Project file name contains unsupported characters"));
    }
    Ok(value)
}

fn relative_to(path: &Path, root: &Path) -> Option<PathBuf> {
    #[cfg(not(windows))]
    {
        path.strip_prefix(root).ok().map(Path::to_path_buf)
    }
    #[cfg(windows)]
    {
        let path: Vec<_> = path.components().collect();
        let root: Vec<_> = root.components().collect();
        if path.len() < root.len()
            || !path.iter().zip(&root).all(|(left, right)| {
                left.as_os_str()
                    .to_string_lossy()
                    .eq_ignore_ascii_case(&right.as_os_str().to_string_lossy())
            })
        {
            return None;
        }
        Some(
            path[root.len()..]
                .iter()
                .map(|component| component.as_os_str())
                .collect(),
        )
    }
}

pub(super) fn sensitive(path: &Path) -> bool {
    let components: Vec<_> = path
        .components()
        .filter_map(|component| match component {
            Component::Normal(name) => Some(name.to_string_lossy().to_ascii_lowercase()),
            _ => None,
        })
        .collect();
    #[cfg(unix)]
    if components
        .first()
        .is_some_and(|name| matches!(name.as_str(), "proc" | "sys" | "dev"))
    {
        return true;
    }
    components.iter().any(|name| {
        matches!(
            name.as_str(),
            ".ssh" | ".gnupg" | ".aws" | ".azure" | ".kube" | ".codex" | ".git" | "keychains"
        ) || name == ".env"
            || name.starts_with(".env.")
    }) || components.windows(2).any(|pair| {
        matches!(
            (pair[0].as_str(), pair[1].as_str()),
            (".config", "gcloud") | ("microsoft", "credentials") | ("microsoft", "vault")
        )
    })
}

pub(super) struct Directory {
    pub file: File,
    pub path: PathBuf,
    _namespace: Vec<File>,
}
impl Directory {
    pub fn bound_path(&self) -> Result<PathBuf> {
        platform::directory_path(&self.file, &self.path)
    }
    pub fn child_path(&self, name: &OsStr) -> Result<PathBuf> {
        Ok(self.bound_path()?.join(name))
    }
    pub fn list(&self, cap: usize) -> Result<Vec<std::ffi::OsString>> {
        let mut names = Vec::new();
        for entry in fs::read_dir(self.bound_path()?)
            .map_err(|_| blocked("Could not enumerate project directory"))?
        {
            names.push(
                entry
                    .map_err(|_| blocked("Could not enumerate a project entry"))?
                    .file_name(),
            );
            if names.len() > cap {
                return Err(blocked("Project directory entry limit exceeded"));
            }
        }
        names.sort();
        Ok(names)
    }
    pub fn child(&self, name: &OsStr, create: bool) -> Result<Self> {
        let bound = self.child_path(name)?;
        if create {
            #[cfg(unix)]
            let result = {
                use std::os::unix::fs::DirBuilderExt;
                fs::DirBuilder::new().mode(0o700).create(&bound)
            };
            #[cfg(not(unix))]
            let result = fs::create_dir(&bound);
            match result {
                Ok(()) => {}
                Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
                Err(_) => return Err(blocked("Could not create project directory")),
            }
        }
        let file = platform::open_directory_child(&self.file, name, &bound)?;
        #[cfg(not(windows))]
        let namespace = Vec::new();
        #[cfg(windows)]
        let mut namespace = Vec::new();
        #[cfg(windows)]
        {
            namespace.push(
                self.file
                    .try_clone()
                    .map_err(|_| blocked("Could not retain directory namespace"))?,
            );
            for parent in &self._namespace {
                namespace.push(
                    parent
                        .try_clone()
                        .map_err(|_| blocked("Could not retain directory namespace"))?,
                );
            }
        }
        Ok(Self {
            file,
            path: self.path.join(name),
            _namespace: namespace,
        })
    }
    pub fn sync(&self) -> Result<()> {
        #[cfg(unix)]
        self.file
            .sync_all()
            .map_err(|_| blocked("Could not synchronize project directory"))?;
        Ok(())
    }
}

pub(super) struct Access {
    scope: Option<ProjectScope>,
    roots: Vec<Directory>,
}
impl Access {
    pub fn scoped(&self) -> bool {
        self.scope.is_some()
    }
    pub fn new(scope: Option<&ProjectScope>) -> Result<Self> {
        let mut roots = Vec::new();
        if let Some(scope) = scope {
            for path in scope.read_roots.iter().chain(&scope.write_roots) {
                if roots.iter().any(|root: &Directory| root.path == *path) {
                    continue;
                }
                let directory = platform::absolute_directory(path)?;
                let identity = platform::identity(&directory.file)?;
                if !scope.root_identities.iter().any(|expected| {
                    expected.path == *path && (expected.device, expected.file) == identity
                }) {
                    return Err(blocked("An authorized project directory changed identity"));
                }
                roots.push(directory);
            }
        }
        Ok(Self {
            scope: scope.cloned(),
            roots,
        })
    }
    pub fn check(&self, path: &Path, write: bool) -> Result<()> {
        if let Some(scope) = &self.scope {
            if sensitive(path) {
                return Err(blocked(
                    "Sensitive credential and configuration paths are protected",
                ));
            }
            let grants = if write {
                &scope.write_roots
            } else {
                &scope.read_roots
            };
            if !grants.iter().any(|root| relative_to(path, root).is_some()) {
                return Err(blocked(if write {
                    "Output or private state is outside authorized write folders"
                } else {
                    "Input is outside authorized read folders"
                }));
            }
        }
        Ok(())
    }
    pub fn key(&self, key: &ProjectKey) -> Result<()> {
        if let Some(scope) = &self.scope {
            match key {
                ProjectKey::File { path } => {
                    self.check(path, false)?;
                    if !scope.key_paths.iter().any(|grant| {
                        relative_to(path, grant)
                            .is_some_and(|relative| relative.as_os_str().is_empty())
                    }) {
                        return Err(blocked("Signing key is not explicitly authorized"));
                    }
                }
                ProjectKey::System { key_id } if !scope.key_refs.contains(key_id) => {
                    return Err(blocked(
                        "System signing identity is not explicitly authorized",
                    ));
                }
                _ => {}
            }
        }
        Ok(())
    }
    pub fn directory(&self, path: &Path, write: bool, create: bool) -> Result<Directory> {
        self.check(path, write)?;
        if self.scope.is_some() {
            let root = self
                .roots
                .iter()
                .filter(|root| relative_to(path, &root.path).is_some())
                .filter(|root| {
                    self.scope.as_ref().is_some_and(|scope| {
                        (if write {
                            &scope.write_roots
                        } else {
                            &scope.read_roots
                        })
                        .contains(&root.path)
                    })
                })
                .max_by_key(|root| root.path.components().count())
                .ok_or_else(|| blocked("No bound directory grant covers this path"))?;
            let mut directory = Directory {
                file: root
                    .file
                    .try_clone()
                    .map_err(|_| blocked("Could not retain authorized root"))?,
                path: root.path.clone(),
                _namespace: Vec::new(),
            };
            for part in relative_to(path, &root.path)
                .ok_or_else(|| blocked("Path left its authorized root"))?
                .components()
            {
                let Component::Normal(name) = part else {
                    return Err(blocked("Unexpected project path component"));
                };
                directory = directory.child(name, create)?;
            }
            return Ok(directory);
        }
        let mut anchor = PathBuf::new();
        let mut remainder = Vec::new();
        for part in path.components() {
            match part {
                Component::Prefix(_) | Component::RootDir => anchor.push(part.as_os_str()),
                Component::Normal(name) => remainder.push(name),
                _ => return Err(blocked("Unexpected project path component")),
            }
        }
        let mut directory = platform::absolute_directory(&anchor)?;
        for name in remainder {
            directory = directory.child(name, create)?;
        }
        Ok(directory)
    }
    pub fn open(&self, path: &Path) -> Result<File> {
        self.check(path, false)?;
        if let Some(file) = crate::access_guard::open_bound(path)? {
            platform::regular(&file)?;
            return Ok(file);
        }
        let parent = self.directory(
            path.parent()
                .ok_or_else(|| blocked("Input has no parent"))?,
            false,
            false,
        )?;
        platform::open_input(
            &parent,
            path.file_name()
                .ok_or_else(|| blocked("Input has no name"))?,
        )
    }
    pub fn read(&self, path: &Path, cap: u64) -> Result<Vec<u8>> {
        let mut file = self.open(path)?;
        let before = stamp(&file)?;
        if before.size > cap {
            return Err(blocked("Project metadata exceeds its byte budget"));
        }
        let mut bytes = Vec::new();
        Read::by_ref(&mut file)
            .take(cap.saturating_add(1))
            .read_to_end(&mut bytes)
            .map_err(|_| blocked("Could not read project metadata"))?;
        if bytes.len() as u64 > cap || stamp(&file)? != before {
            return Err(blocked("Project metadata changed while reading"));
        }
        Ok(bytes)
    }
    pub fn hash(&self, path: &Path, cap: u64, flag: &AtomicBool) -> Result<Sample> {
        let mut file = self.open(path)?;
        let before = stamp(&file)?;
        if before.size > cap {
            return Err(blocked("Project file exceeds its streaming byte budget"));
        }
        let mut hash = Sha256::new();
        let mut bytes = 0u64;
        let mut buffer = [0u8; 64 * 1024];
        loop {
            cancelled(flag)?;
            let count = file
                .read(&mut buffer)
                .map_err(|_| blocked("Could not hash project file"))?;
            if count == 0 {
                break;
            }
            bytes = bytes.saturating_add(count as u64);
            if bytes > cap {
                return Err(blocked("Project file grew beyond its byte budget"));
            }
            hash.update(&buffer[..count]);
        }
        if before != stamp(&file)? || bytes != before.size || stamp(&self.open(path)?)? != before {
            return Err(blocked("Project source changed while hashing"));
        }
        Ok(Sample {
            sha256: format!("{:x}", hash.finalize()),
            stamp: before,
            fresh: true,
        })
    }
    pub fn write_new(&self, path: &Path, data: &[u8]) -> Result<()> {
        let parent = self.directory(
            path.parent()
                .ok_or_else(|| blocked("Output has no parent"))?,
            true,
            true,
        )?;
        let mut file = platform::create(
            &parent,
            path.file_name()
                .ok_or_else(|| blocked("Output has no file name"))?,
            false,
        )?;
        file.write_all(data)
            .and_then(|_| file.sync_all())
            .map_err(|_| blocked("Could not write project output"))?;
        parent.sync()
    }
    pub fn replace(&self, path: &Path, data: &[u8]) -> Result<()> {
        let parent = self.directory(
            path.parent()
                .ok_or_else(|| blocked("State has no parent"))?,
            true,
            true,
        )?;
        let temporary = tempfile::NamedTempFile::new_in(parent.bound_path()?)
            .map_err(|_| blocked("Could not stage private project state"))?;
        temporary
            .as_file()
            .write_all(data)
            .and_then(|_| temporary.as_file().sync_all())
            .map_err(|_| blocked("Could not stage private project state"))?;
        if fs::symlink_metadata(
            parent.child_path(
                path.file_name()
                    .ok_or_else(|| blocked("State has no name"))?,
            )?,
        )
        .is_ok()
        {
            platform::regular(&platform::open_input(&parent, path.file_name().unwrap())?)?;
        }
        temporary
            .persist(parent.child_path(path.file_name().unwrap())?)
            .map_err(|_| blocked("Could not commit private project state"))?;
        parent.sync()
    }
    pub fn copy(
        &self,
        source: &Path,
        target: &Path,
        expected: &Sample,
        cap: u64,
        limits: &fileveil_core::Limits,
        flag: &AtomicBool,
    ) -> Result<()> {
        let mut source_file = self.open(source)?;
        if stamp(&source_file)? != expected.stamp {
            return Err(blocked("Source identity changed before release copy"));
        }
        let attributes = crate::os::read(&source_file, source, limits)?;
        if attributes
            .iter()
            .any(|attribute| attribute.name == "com.apple.ResourceFork")
        {
            return Err(blocked(
                "Resource-fork release copies require a content-preserving filesystem backend",
            ));
        }
        source_file
            .seek(SeekFrom::Start(0))
            .map_err(|_| blocked("Could not rewind release source"))?;
        let parent = self.directory(
            target
                .parent()
                .ok_or_else(|| blocked("Release copy has no parent"))?,
            true,
            true,
        )?;
        let mut output = platform::create(
            &parent,
            target
                .file_name()
                .ok_or_else(|| blocked("Release copy has no name"))?,
            false,
        )?;
        let mut hash = Sha256::new();
        let mut copied = 0u64;
        let mut buffer = [0u8; 64 * 1024];
        loop {
            cancelled(flag)?;
            let count = source_file
                .read(&mut buffer)
                .map_err(|_| blocked("Could not read release source"))?;
            if count == 0 {
                break;
            }
            copied = copied.saturating_add(count as u64);
            if copied > cap {
                return Err(blocked("Release source grew beyond the copy budget"));
            }
            hash.update(&buffer[..count]);
            output
                .write_all(&buffer[..count])
                .map_err(|_| blocked("Could not write release copy"))?;
        }
        if copied != expected.stamp.size
            || format!("{:x}", hash.finalize()) != expected.sha256
            || stamp(&source_file)? != expected.stamp
        {
            return Err(blocked("Release source changed during copy"));
        }
        crate::os::write(&output, target, &attributes)?;
        if crate::os::read(&output, target, limits)? != attributes
            || crate::os::read(&source_file, source, limits)? != attributes
        {
            return Err(blocked("Release-copy filesystem metadata changed"));
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::{MetadataExt, PermissionsExt};
            let mode = source_file
                .metadata()
                .map_err(|_| blocked("Could not inspect source permissions"))?
                .mode()
                & 0o700;
            output
                .set_permissions(fs::Permissions::from_mode(mode))
                .map_err(|_| blocked("Could not preserve restrictive file permissions"))?;
        }
        output
            .sync_all()
            .map_err(|_| blocked("Could not synchronize release copy"))?;
        parent.sync()
    }
    pub fn lock(&self, state: &Path) -> Result<File> {
        let directory = self.directory(state, true, true)?;
        platform::lock(&directory)
    }
    pub fn publish_directory(
        &self,
        parent: &Directory,
        source: &OsStr,
        target: &OsStr,
    ) -> Result<()> {
        self.check(&parent.path.join(target), true)?;
        platform::rename_new(parent, source, target)?;
        parent.sync()
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub(super) struct Stamp {
    pub device: u64,
    pub file: u64,
    pub size: u64,
    pub modified_ns: String,
    pub changed_ns: String,
    pub executable: bool,
}
#[derive(Debug, Clone)]
pub(super) struct Sample {
    pub sha256: String,
    pub stamp: Stamp,
    pub fresh: bool,
}
pub(super) fn stamp(file: &File) -> Result<Stamp> {
    let metadata = file
        .metadata()
        .map_err(|_| blocked("Could not inspect project input"))?;
    let identity = platform::identity(file)?;
    #[cfg(unix)]
    let (changed_ns, executable) = {
        use std::os::unix::fs::MetadataExt;
        (
            format!("{}:{}", metadata.ctime(), metadata.ctime_nsec()),
            metadata.mode() & 0o111 != 0,
        )
    };
    #[cfg(windows)]
    let (changed_ns, executable) = (platform::change_time(file)?, false);
    Ok(Stamp {
        device: identity.0,
        file: identity.1,
        size: metadata.len(),
        modified_ns: metadata
            .modified()
            .ok()
            .and_then(|time| time.duration_since(UNIX_EPOCH).ok())
            .map(|time| time.as_nanos().to_string())
            .unwrap_or_default(),
        changed_ns,
        executable,
    })
}

#[cfg(unix)]
mod platform {
    use super::*;
    use std::{
        ffi::CString,
        os::{
            fd::{AsRawFd, FromRawFd},
            unix::{ffi::OsStrExt, fs::MetadataExt},
        },
    };
    fn component(name: &OsStr) -> Result<CString> {
        CString::new(name.as_bytes()).map_err(|_| blocked("A path component contains NUL"))
    }
    pub fn absolute_directory(path: &Path) -> Result<Directory> {
        let mut directory = Directory {
            file: File::open("/").map_err(|_| blocked("Could not open filesystem root"))?,
            path: "/".into(),
            _namespace: Vec::new(),
        };
        for part in path.components() {
            match part {
                Component::RootDir => {}
                Component::Normal(name) => directory = directory.child(name, false)?,
                _ => return Err(blocked("Unsupported directory path")),
            }
        }
        Ok(directory)
    }
    pub fn open_directory_child(parent: &File, name: &OsStr, _hint: &Path) -> Result<File> {
        let name = component(name)?;
        let fd = unsafe {
            libc::openat(
                parent.as_raw_fd(),
                name.as_ptr(),
                libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
            )
        };
        if fd < 0 {
            return Err(blocked(
                "Directory is unavailable or includes a symbolic link",
            ));
        }
        Ok(unsafe { File::from_raw_fd(fd) })
    }
    pub fn open_input(parent: &Directory, name: &OsStr) -> Result<File> {
        let name = component(name)?;
        let fd = unsafe {
            libc::openat(
                parent.file.as_raw_fd(),
                name.as_ptr(),
                libc::O_RDONLY | libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_CLOEXEC,
            )
        };
        if fd < 0 {
            return Err(blocked("Input is unavailable or is a symbolic link"));
        }
        let file = unsafe { File::from_raw_fd(fd) };
        regular(&file)?;
        Ok(file)
    }
    pub fn regular(file: &File) -> Result<()> {
        let metadata = file
            .metadata()
            .map_err(|_| blocked("Could not inspect input identity"))?;
        if !metadata.is_file() || metadata.nlink() != 1 {
            return Err(blocked(
                "Project inputs must be regular files with one filesystem link",
            ));
        }
        Ok(())
    }
    pub fn identity(file: &File) -> Result<(u64, u64)> {
        let info = file
            .metadata()
            .map_err(|_| blocked("Could not inspect filesystem identity"))?;
        Ok((info.dev(), info.ino()))
    }
    pub fn directory_path(directory: &File, _hint: &Path) -> Result<PathBuf> {
        #[cfg(target_os = "macos")]
        let path = {
            let (device, file) = identity(directory)?;
            PathBuf::from(format!("/.vol/{device}/{file}"))
        };
        #[cfg(not(target_os = "macos"))]
        let path = PathBuf::from(format!("/dev/fd/{}", directory.as_raw_fd()));
        let check =
            File::open(&path).map_err(|_| blocked("Bound directory namespace is unavailable"))?;
        if identity(&check)? != identity(directory)? {
            return Err(blocked("Bound directory identity changed"));
        }
        Ok(path)
    }
    pub fn create(parent: &Directory, name: &OsStr, existing: bool) -> Result<File> {
        let name = component(name)?;
        let flags = libc::O_RDWR
            | libc::O_NOFOLLOW
            | libc::O_CLOEXEC
            | libc::O_CREAT
            | if existing { 0 } else { libc::O_EXCL };
        let fd = unsafe { libc::openat(parent.file.as_raw_fd(), name.as_ptr(), flags, 0o600) };
        if fd < 0 {
            return Err(blocked("Output exists or cannot be created safely"));
        }
        let file = unsafe { File::from_raw_fd(fd) };
        regular(&file)?;
        Ok(file)
    }
    pub fn lock(parent: &Directory) -> Result<File> {
        let file = create(parent, OsStr::new(".lock"), true)?;
        if unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } != 0 {
            return Err(blocked("Another project transaction is already running"));
        }
        Ok(file)
    }
    pub fn rename_new(parent: &Directory, source: &OsStr, target: &OsStr) -> Result<()> {
        let source = component(source)?;
        let target = component(target)?;
        #[cfg(target_os = "macos")]
        let result = unsafe {
            libc::renameatx_np(
                parent.file.as_raw_fd(),
                source.as_ptr(),
                parent.file.as_raw_fd(),
                target.as_ptr(),
                libc::RENAME_EXCL,
            )
        };
        #[cfg(target_os = "linux")]
        let result = unsafe {
            libc::renameat2(
                parent.file.as_raw_fd(),
                source.as_ptr(),
                parent.file.as_raw_fd(),
                target.as_ptr(),
                libc::RENAME_NOREPLACE,
            )
        };
        if result != 0 {
            return Err(blocked(
                "Generation destination exists or atomic publication failed",
            ));
        }
        Ok(())
    }
}

#[cfg(windows)]
mod platform {
    use super::*;
    use std::fs::OpenOptions;
    use std::os::windows::{ffi::OsStringExt, fs::OpenOptionsExt, io::AsRawHandle};
    use windows_sys::Win32::Storage::FileSystem::{
        BY_HANDLE_FILE_INFORMATION, FILE_ATTRIBUTE_REPARSE_POINT, FILE_FLAG_BACKUP_SEMANTICS,
        FILE_FLAG_OPEN_REPARSE_POINT, FILE_NAME_NORMALIZED, FILE_SHARE_READ, FILE_SHARE_WRITE,
        GetFileInformationByHandle, GetFinalPathNameByHandleW, VOLUME_NAME_GUID,
    };
    fn information(file: &File) -> Result<BY_HANDLE_FILE_INFORMATION> {
        let mut info = unsafe { std::mem::zeroed() };
        if unsafe { GetFileInformationByHandle(file.as_raw_handle(), &mut info) } == 0 {
            return Err(blocked("Could not inspect Windows file identity"));
        }
        if info.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
            return Err(blocked("Reparse points are protected"));
        }
        Ok(info)
    }
    fn open(path: &Path, directory: bool) -> Result<File> {
        let file = OpenOptions::new()
            .read(true)
            .share_mode(FILE_SHARE_READ | FILE_SHARE_WRITE)
            .custom_flags(FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT)
            .open(path)
            .map_err(|_| blocked("Windows path cannot be locked against replacement"))?;
        information(&file)?;
        if file
            .metadata()
            .map_err(|_| blocked("Could not inspect Windows object type"))?
            .is_dir()
            != directory
        {
            return Err(blocked("Unexpected Windows object type"));
        }
        Ok(file)
    }
    pub fn absolute_directory(path: &Path) -> Result<Directory> {
        let mut prefix = PathBuf::new();
        let mut namespace = Vec::new();
        for part in path.components() {
            prefix.push(part.as_os_str());
            if matches!(part, Component::Normal(_)) {
                namespace.push(open(&prefix, true)?);
            }
        }
        Ok(Directory {
            file: open(path, true)?,
            path: path.to_path_buf(),
            _namespace: namespace,
        })
    }
    pub fn open_directory_child(_parent: &File, _name: &OsStr, hint: &Path) -> Result<File> {
        open(hint, true)
    }
    pub fn open_input(parent: &Directory, name: &OsStr) -> Result<File> {
        let file = open(&parent.child_path(name)?, false)?;
        regular(&file)?;
        Ok(file)
    }
    pub fn regular(file: &File) -> Result<()> {
        if information(file)?.nNumberOfLinks != 1
            || !file
                .metadata()
                .map_err(|_| blocked("Could not inspect Windows input"))?
                .is_file()
        {
            return Err(blocked(
                "Project inputs must be regular files with one filesystem link",
            ));
        }
        Ok(())
    }
    pub fn identity(file: &File) -> Result<(u64, u64)> {
        let info = information(file)?;
        Ok((
            u64::from(info.dwVolumeSerialNumber),
            (u64::from(info.nFileIndexHigh) << 32) | u64::from(info.nFileIndexLow),
        ))
    }
    pub fn change_time(file: &File) -> Result<String> {
        use windows_sys::Win32::Storage::FileSystem::{
            FILE_BASIC_INFO, FileBasicInfo, GetFileInformationByHandleEx,
        };
        let mut info: FILE_BASIC_INFO = unsafe { std::mem::zeroed() };
        if unsafe {
            GetFileInformationByHandleEx(
                file.as_raw_handle(),
                FileBasicInfo,
                &mut info as *mut _ as *mut _,
                std::mem::size_of::<FILE_BASIC_INFO>() as u32,
            )
        } == 0
        {
            return Err(blocked("Could not inspect Windows file change time"));
        }
        Ok(info.ChangeTime.to_string())
    }
    pub fn directory_path(directory: &File, _hint: &Path) -> Result<PathBuf> {
        let mut buffer = vec![0u16; 32768];
        let size = unsafe {
            GetFinalPathNameByHandleW(
                directory.as_raw_handle(),
                buffer.as_mut_ptr(),
                buffer.len() as u32,
                FILE_NAME_NORMALIZED | VOLUME_NAME_GUID,
            )
        };
        if size == 0 || size as usize >= buffer.len() {
            return Err(blocked("Stable Windows volume path unavailable"));
        }
        Ok(PathBuf::from(std::ffi::OsString::from_wide(
            &buffer[..size as usize],
        )))
    }
    pub fn create(parent: &Directory, name: &OsStr, existing: bool) -> Result<File> {
        let mut options = OpenOptions::new();
        options
            .read(true)
            .write(true)
            .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT)
            .share_mode(0);
        if existing {
            options.create(true);
        } else {
            options.create_new(true);
        }
        let file = options
            .open(parent.child_path(name)?)
            .map_err(|_| blocked("Windows output exists or cannot be created safely"))?;
        regular(&file)?;
        Ok(file)
    }
    pub fn lock(parent: &Directory) -> Result<File> {
        create(parent, OsStr::new(".lock"), true)
    }
    pub fn rename_new(parent: &Directory, source: &OsStr, target: &OsStr) -> Result<()> {
        fs::rename(parent.child_path(source)?, parent.child_path(target)?)
            .map_err(|_| blocked("Generation destination exists or atomic publication failed"))
    }
}

// FVPROV1 31913 W3siYm9keSI6eyJhY3Rvcl9rZXlfaWQiOiI5OWVhNjNlZmNjZmQwZmRiZDY4ZTE2ZWQ4ZjAzZDMzN2YxNWVjMmU0YTZhM2Q2NGUxMWQ3MTRlYTFlNTQyNTMzIiwiYWxnb3JpdGhtIjoiRWQyNTUxOSIsImF1dGhvciI6IkoteC1aL0ZpbGVWZWlsIiwiY29udGVudF9zaGEyNTYiOiJiNDYxZjUzMjZhN2MzODYyMDhkODhhYTJjODVmODFjZWI2ZmM5ZGEzOTA0NDE2YTlhMzVjYjM1NjE3MDg1YzcyIiwiY29weV9pZCI6InYwLjYuMC1hbHBoYS4xIiwiY3JlYXRlZF9hdCI6IjIwMjYtMTEtMTQiLCJlZGl0aW9uIjoiYWxwaGEiLCJpc3N1ZXJfcG9saWN5IjpudWxsLCJraW5kIjoiY3JlYXRlIiwibW9kZSI6InNlbGZfc2lnbiIsInBhcmVudF92ZXJzaW9uIjpudWxsLCJwcmV2aW91c19yZWNvcmRfc2hhMjU2IjpudWxsLCJzY2hlbWEiOiJmaWxldmVpbC5wcm92ZW5hbmNlLnNpZ25hdHVyZS52MiIsInNlcXVlbmNlIjowLCJ0cmFuc2Zlcl90b19rZXlfaWQiOm51bGwsInZlcnNpb24iOiJ2MC42LjAtYWxwaGEuMSIsIndvcmtfaWQiOiJodHRwczovL2dpdGh1Yi5jb20vSi14LVovZmlsZXZlaWwvc291cmNlL2NyYXRlcy9maWxldmVpbC1lbmdpbmUvc3JjL3Byb2plY3QvZmlsZXMucnMifSwic2lnbmF0dXJlcyI6W3sia2V5X2lkIjoiOTllYTYzZWZjY2ZkMGZkYmQ2OGUxNmVkOGYwM2QzMzdmMTVlYzJlNGE2YTNkNjRlMTFkNzE0ZWExZTU0MjUzMyIsInB1YmxpY19rZXlfaGV4IjoiYWRiM2UxN2NkMTJmOTU2ZDAwNzBlMTY2M2Y1MzE1MzdmY2VkZjczMDhkMDE2NThmZWE0NTZmZWVhOGY3ZmJjNSIsInNpZ25hdHVyZV9oZXgiOiIwNmIwYzBjOWFmODdhMjE0ZGFiNmUyZjYzZDViM2E4Nzg4MmE5Y2Y0NWMxYWVkMmZhZDk1ODYzNzA0ZjM4N2QwYTllYzdlODhjZDAzY2VjNmY5ZGY3MDM3ZWE5ZWI2ZDM5ZjU4NGZhYjA3NGRiNmU5NzI1ODRiOWViMTJlMGIwYyJ9XX1d FVPROV1-END
