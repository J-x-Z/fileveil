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

// FVPROV1 2394 W3siYm9keSI6eyJhY3Rvcl9rZXlfaWQiOiI5OWVhNjNlZmNjZmQwZmRiZDY4ZTE2ZWQ4ZjAzZDMzN2YxNWVjMmU0YTZhM2Q2NGUxMWQ3MTRlYTFlNTQyNTMzIiwiYWxnb3JpdGhtIjoiRWQyNTUxOSIsImF1dGhvciI6IkoteC1aL0ZpbGVWZWlsIiwiY29udGVudF9zaGEyNTYiOiIyMzkxYjU5ZTJhZDVmNmE1YWNkNzkyM2JmNWJmMTZmODY5NGJiZThlNmUwZDVkN2Q4MTVlZDAwNzRhMTlhNDQwIiwiY29weV9pZCI6InYwLjcuMC1iZXRhLjEiLCJjcmVhdGVkX2F0IjoiMjAyNi0xMS0xNSIsImVkaXRpb24iOiJiZXRhIiwiaXNzdWVyX3BvbGljeSI6bnVsbCwia2luZCI6ImNyZWF0ZSIsIm1vZGUiOiJzZWxmX3NpZ24iLCJwYXJlbnRfdmVyc2lvbiI6bnVsbCwicHJldmlvdXNfcmVjb3JkX3NoYTI1NiI6bnVsbCwic2NoZW1hIjoiZmlsZXZlaWwucHJvdmVuYW5jZS5zaWduYXR1cmUudjIiLCJzZXF1ZW5jZSI6MCwidHJhbnNmZXJfdG9fa2V5X2lkIjpudWxsLCJ2ZXJzaW9uIjoidjAuNy4wLWJldGEuMSIsIndvcmtfaWQiOiJodHRwczovL2dpdGh1Yi5jb20vSi14LVovZmlsZXZlaWwvc291cmNlL2NyYXRlcy9maWxldmVpbC1lbmdpbmUvc3JjL2FjY2Vzc19ndWFyZC5ycyJ9LCJzaWduYXR1cmVzIjpbeyJrZXlfaWQiOiI5OWVhNjNlZmNjZmQwZmRiZDY4ZTE2ZWQ4ZjAzZDMzN2YxNWVjMmU0YTZhM2Q2NGUxMWQ3MTRlYTFlNTQyNTMzIiwicHVibGljX2tleV9oZXgiOiJhZGIzZTE3Y2QxMmY5NTZkMDA3MGUxNjYzZjUzMTUzN2ZjZWRmNzMwOGQwMTY1OGZlYTQ1NmZlZWE4ZjdmYmM1Iiwic2lnbmF0dXJlX2hleCI6IjFmODBmOWUzNjQ4Zjc1N2M5YzlmOGIwNDcxM2I2MjgzZmMyNTEzNDU5YTMzZjY1ZTA5OGJhOGJlNTM0YTNhYTA1N2Q0ODM5YmJjMWJmYTE5OTk4OWUwYjMzOTBmMDNhMTNhNzEwZWE1NmQ3ZGE0ZjI1NmE4NzVjMjM4NWU4MDA0In1dfV0= FVPROV1-END
