// SPDX-License-Identifier: MPL-2.0
//! Read-only descriptors bound by the local MCP authorization broker.
//!
//! Ordinary CLI and GUI calls retain the normal path-opening behavior. The MCP
//! broker uses this scope so that worker reads use already-authorized file
//! objects even when another process changes their names during an operation.
use fileveil_core::{Error, Result};
use std::{
    cell::RefCell,
    fs::File,
    io::{Seek, SeekFrom},
    path::{Path, PathBuf},
};

thread_local! {
    static BOUND_FILES: RefCell<Vec<(PathBuf, File)>> = const { RefCell::new(Vec::new()) };
}

/// Run one operation using explicitly bound, read-only file objects.
pub fn with_bound_files<T>(
    files: Vec<(PathBuf, File)>,
    operation: impl FnOnce() -> Result<T>,
) -> Result<T> {
    struct Restore(Option<Vec<(PathBuf, File)>>);
    impl Drop for Restore {
        fn drop(&mut self) {
            if let Some(previous) = self.0.take() {
                BOUND_FILES.with(|bindings| *bindings.borrow_mut() = previous);
            }
        }
    }
    let previous = BOUND_FILES.with(|bindings| bindings.replace(files));
    let _restore = Restore(Some(previous));
    operation()
}

pub(crate) fn open_bound(path: &Path) -> Result<Option<File>> {
    BOUND_FILES.with(|bindings| {
        let bindings = bindings.borrow();
        let Some((_, file)) = bindings.iter().find(|(name, _)| name == path) else {
            return Ok(None);
        };
        let metadata = file
            .metadata()
            .map_err(|_| Error::Blocked("Authorized input descriptor is unavailable".into()))?;
        if !metadata.is_file() {
            return Err(Error::Blocked(
                "Authorized input is no longer a regular file".into(),
            ));
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::MetadataExt;
            if metadata.nlink() != 1 {
                return Err(Error::Blocked(
                    "MCP input has multiple filesystem links".into(),
                ));
            }
        }
        let mut duplicate = file.try_clone().map_err(|_| {
            Error::Blocked("Could not duplicate authorized input descriptor".into())
        })?;
        duplicate
            .seek(SeekFrom::Start(0))
            .map_err(|_| Error::Blocked("Could not rewind authorized input descriptor".into()))?;
        Ok(Some(duplicate))
    })
}
