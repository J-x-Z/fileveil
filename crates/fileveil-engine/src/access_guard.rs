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

// FVPROV1 2394 W3siYm9keSI6eyJhY3Rvcl9rZXlfaWQiOiI5OWVhNjNlZmNjZmQwZmRiZDY4ZTE2ZWQ4ZjAzZDMzN2YxNWVjMmU0YTZhM2Q2NGUxMWQ3MTRlYTFlNTQyNTMzIiwiYWxnb3JpdGhtIjoiRWQyNTUxOSIsImF1dGhvciI6IkoteC1aL0ZpbGVWZWlsIiwiY29udGVudF9zaGEyNTYiOiIyMzkxYjU5ZTJhZDVmNmE1YWNkNzkyM2JmNWJmMTZmODY5NGJiZThlNmUwZDVkN2Q4MTVlZDAwNzRhMTlhNDQwIiwiY29weV9pZCI6InYwLjUuMC1hbHBoYS4xIiwiY3JlYXRlZF9hdCI6IjIwMjYtMTEtMTQiLCJlZGl0aW9uIjoiYWxwaGEiLCJpc3N1ZXJfcG9saWN5IjpudWxsLCJraW5kIjoiY3JlYXRlIiwibW9kZSI6InNlbGZfc2lnbiIsInBhcmVudF92ZXJzaW9uIjpudWxsLCJwcmV2aW91c19yZWNvcmRfc2hhMjU2IjpudWxsLCJzY2hlbWEiOiJmaWxldmVpbC5wcm92ZW5hbmNlLnNpZ25hdHVyZS52MiIsInNlcXVlbmNlIjowLCJ0cmFuc2Zlcl90b19rZXlfaWQiOm51bGwsInZlcnNpb24iOiJ2MC41LjAtYWxwaGEuMSIsIndvcmtfaWQiOiJodHRwczovL2dpdGh1Yi5jb20vSi14LVovZmlsZXZlaWwvc291cmNlL2NyYXRlcy9maWxldmVpbC1lbmdpbmUvc3JjL2FjY2Vzc19ndWFyZC5ycyJ9LCJzaWduYXR1cmVzIjpbeyJrZXlfaWQiOiI5OWVhNjNlZmNjZmQwZmRiZDY4ZTE2ZWQ4ZjAzZDMzN2YxNWVjMmU0YTZhM2Q2NGUxMWQ3MTRlYTFlNTQyNTMzIiwicHVibGljX2tleV9oZXgiOiJhZGIzZTE3Y2QxMmY5NTZkMDA3MGUxNjYzZjUzMTUzN2ZjZWRmNzMwOGQwMTY1OGZlYTQ1NmZlZWE4ZjdmYmM1Iiwic2lnbmF0dXJlX2hleCI6IjRjZGUyNTg5YjdiZjM1NjE1OTljOTY1YTkxNGYwNjU1MzA3NGVmMjk5NjNjZGFiZDA4ZDM2ZWY4ZjY5OGU2ZTE0ODhhOGEzMGI3Zjk5MjQ3OGViMzFhOWRmMDFmOTk5MzEwNmQ1MzY5ZWVkZGZlY2UzNGMyMWRjMTZiY2VlOTBiIn1dfV0= FVPROV1-END
