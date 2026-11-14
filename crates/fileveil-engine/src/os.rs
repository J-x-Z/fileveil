// SPDX-License-Identifier: MPL-2.0
//! Platform metadata audit. Attribute values are never included in reports.
use fileveil_core::{Action, Error, Finding, Limits, Result, RiskLayer};
use std::{ffi::OsString, fs::File, path::Path};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Attribute {
    pub name: OsString,
    pub value: Vec<u8>,
}

pub fn findings(attributes: &[Attribute]) -> Vec<Finding> {
    attributes.iter().enumerate().map(|(index, attribute)| {
        let name = attribute.name.to_string_lossy();
        let (code, location, action, summary) = match name.as_ref() {
            "com.apple.ResourceFork" => ("filesystem.resource_fork", "com.apple.ResourceFork".into(), Action::AskUser, "Resource fork present; safe rewriting requires a semantic-preservation backend"),
            "com.apple.quarantine" => ("filesystem.quarantine", "com.apple.quarantine".into(), Action::Preserve, "macOS quarantine security marker is preserved"),
            ":Zone.Identifier:$DATA" => ("filesystem.motw", "Zone.Identifier".into(), Action::Preserve, "Windows Mark-of-the-Web security marker is preserved"),
            "com.apple.metadata:kMDItemWhereFroms" => ("filesystem.download_origin", "com.apple.metadata:kMDItemWhereFroms".into(), Action::AskUser, "Download-origin attribute remains on the copy"),
            "com.apple.metadata:kMDItemDownloadedDate" => ("filesystem.download_date", "com.apple.metadata:kMDItemDownloadedDate".into(), Action::AskUser, "Download-date attribute remains on the copy"),
            "com.apple.lastuseddate#PS" | "com.apple.metadata:kMDItemLastUsedDate" => ("filesystem.usage_time", name.to_string(), Action::AskUser, "Last-use timestamp attribute remains on the copy"),
            "com.apple.metadata:_kMDItemUserTags" => ("filesystem.finder_tags", "com.apple.metadata:_kMDItemUserTags".into(), Action::AskUser, "Finder tags remain on the copy"),
            _ => ("filesystem.extended_attribute", format!("Platform attribute {}", index + 1), Action::AskUser, "Platform metadata is preserved; its privacy impact requires review"),
        };
        Finding::new(code, RiskLayer::Filesystem, &location, summary, action)
    }).collect()
}

#[cfg(unix)]
pub fn read(file: &File, _path: &Path, limits: &Limits) -> Result<Vec<Attribute>> {
    use xattr::FileExt;
    let names = file
        .list_xattr()
        .map_err(|_| Error::Blocked("Could not audit extended attributes".into()))?;
    let mut attributes = Vec::new();
    let mut total = 0;
    for name in names {
        if attributes.len() >= limits.max_members {
            return Err(Error::Blocked("Too many extended attributes".into()));
        }
        if name == "com.apple.ResourceFork" {
            attributes.push(Attribute {
                name,
                value: Vec::new(),
            });
            continue;
        }
        let value = file
            .get_xattr(&name)
            .map_err(|_| Error::Blocked("Could not read an extended attribute".into()))?
            .ok_or_else(|| Error::Blocked("An extended attribute changed during audit".into()))?;
        total += value.len();
        if total > limits.max_metadata_bytes {
            return Err(Error::Blocked(
                "Extended attributes exceed the metadata byte limit".into(),
            ));
        }
        attributes.push(Attribute { name, value });
    }
    attributes.sort_by(|a, b| a.name.cmp(&b.name));
    Ok(attributes)
}
#[cfg(unix)]
pub fn write(file: &File, _path: &Path, attributes: &[Attribute]) -> Result<()> {
    use xattr::FileExt;
    for attribute in attributes {
        file.set_xattr(&attribute.name, &attribute.value)
            .map_err(|_| {
                Error::Blocked("Could not preserve platform metadata and security markers".into())
            })?;
    }
    Ok(())
}

#[cfg(windows)]
fn path_from_handle(file: &File) -> Result<std::path::PathBuf> {
    use std::os::windows::{ffi::OsStringExt, io::AsRawHandle};
    use windows_sys::Win32::Storage::FileSystem::{
        FILE_NAME_NORMALIZED, GetFinalPathNameByHandleW, VOLUME_NAME_GUID,
    };
    let mut path = vec![0u16; 32768];
    // Local-volume names preserve the MCP broker's stable namespace. SMB
    // handles use their final UNC name, retaining ordinary CLI share support.
    for flags in [
        FILE_NAME_NORMALIZED | VOLUME_NAME_GUID,
        FILE_NAME_NORMALIZED,
    ] {
        let length = unsafe {
            GetFinalPathNameByHandleW(
                file.as_raw_handle(),
                path.as_mut_ptr(),
                path.len() as u32,
                flags,
            )
        };
        if length > 0 && (length as usize) < path.len() {
            return Ok(std::path::PathBuf::from(OsString::from_wide(
                &path[..length as usize],
            )));
        }
    }
    Err(Error::Blocked(
        "Could not resolve the open file for NTFS stream auditing".into(),
    ))
}

#[cfg(windows)]
pub fn read(file: &File, _path: &Path, limits: &Limits) -> Result<Vec<Attribute>> {
    use std::{
        io::Read,
        os::windows::ffi::{OsStrExt, OsStringExt},
    };
    use windows_sys::Win32::{
        Foundation::{
            ERROR_HANDLE_EOF, ERROR_INVALID_PARAMETER, GetLastError, INVALID_HANDLE_VALUE,
        },
        Storage::FileSystem::{
            FindClose, FindFirstStreamW, FindNextStreamW, FindStreamInfoStandard,
            WIN32_FIND_STREAM_DATA,
        },
    };
    let path = path_from_handle(file)?;
    let path_wide: Vec<u16> = path.as_os_str().encode_wide().chain(Some(0)).collect();
    let mut data: WIN32_FIND_STREAM_DATA = unsafe { std::mem::zeroed() };
    // The path buffer is NUL-terminated and data remains alive for each Win32 call.
    let handle = unsafe {
        FindFirstStreamW(
            path_wide.as_ptr(),
            FindStreamInfoStandard,
            &mut data as *mut _ as *mut _,
            0,
        )
    };
    if handle == INVALID_HANDLE_VALUE {
        let error = unsafe { GetLastError() };
        if error == ERROR_HANDLE_EOF || error == ERROR_INVALID_PARAMETER {
            return Ok(Vec::new());
        }
        return Err(Error::Blocked("Could not enumerate NTFS streams".into()));
    }
    struct SearchHandle(windows_sys::Win32::Foundation::HANDLE);
    impl Drop for SearchHandle {
        fn drop(&mut self) {
            unsafe {
                FindClose(self.0);
            }
        }
    }
    let _search = SearchHandle(handle);
    let mut result = Vec::new();
    let mut total = 0usize;
    loop {
        let length = data
            .cStreamName
            .iter()
            .position(|v| *v == 0)
            .unwrap_or(data.cStreamName.len());
        let name = OsString::from_wide(&data.cStreamName[..length]);
        if name != "::$DATA" {
            if data.StreamSize < 0 || data.StreamSize as u64 > limits.max_metadata_bytes as u64 {
                return Err(Error::Blocked(
                    "NTFS stream exceeds the metadata byte limit".into(),
                ));
            }
            let mut stream_path = path.as_os_str().to_os_string();
            stream_path.push(&name);
            let mut value = Vec::new();
            File::open(stream_path)
                .map_err(|_| Error::Blocked("Could not open NTFS stream".into()))?
                .take(limits.max_metadata_bytes as u64 + 1)
                .read_to_end(&mut value)
                .map_err(|_| Error::Blocked("Could not audit NTFS stream".into()))?;
            total += value.len();
            if total > limits.max_metadata_bytes || result.len() >= limits.max_members {
                return Err(Error::Blocked(
                    "NTFS streams exceed the configured limits".into(),
                ));
            }
            result.push(Attribute { name, value });
        }
        if unsafe { FindNextStreamW(handle, &mut data as *mut _ as *mut _) } == 0 {
            if unsafe { GetLastError() } != ERROR_HANDLE_EOF {
                return Err(Error::Blocked(
                    "Could not finish NTFS stream enumeration".into(),
                ));
            }
            break;
        }
    }
    result.sort_by(|a, b| a.name.cmp(&b.name));
    Ok(result)
}
#[cfg(windows)]
pub fn write(file: &File, _path: &Path, attributes: &[Attribute]) -> Result<()> {
    use std::io::Write;
    let path = path_from_handle(file)?;
    for attribute in attributes {
        let mut stream_path = path.as_os_str().to_os_string();
        stream_path.push(&attribute.name);
        let mut stream = File::create(stream_path)
            .map_err(|_| Error::Blocked("Could not preserve NTFS stream".into()))?;
        stream
            .write_all(&attribute.value)
            .map_err(|_| Error::Blocked("Could not write NTFS stream".into()))?;
        stream
            .sync_all()
            .map_err(|_| Error::Blocked("Could not synchronize NTFS stream".into()))?;
    }
    Ok(())
}
#[cfg(not(any(unix, windows)))]
pub fn read(_file: &File, _path: &Path, _limits: &Limits) -> Result<Vec<Attribute>> {
    Err(Error::Unsupported(
        "Platform security-marker auditing is unavailable".into(),
    ))
}
#[cfg(not(any(unix, windows)))]
pub fn write(_file: &File, _path: &Path, _attributes: &[Attribute]) -> Result<()> {
    Err(Error::Unsupported(
        "Platform security-marker preservation is unavailable".into(),
    ))
}

// FVPROV1 9386 W3siYm9keSI6eyJhY3Rvcl9rZXlfaWQiOiI5OWVhNjNlZmNjZmQwZmRiZDY4ZTE2ZWQ4ZjAzZDMzN2YxNWVjMmU0YTZhM2Q2NGUxMWQ3MTRlYTFlNTQyNTMzIiwiYWxnb3JpdGhtIjoiRWQyNTUxOSIsImF1dGhvciI6IkoteC1aL0ZpbGVWZWlsIiwiY29udGVudF9zaGEyNTYiOiIwZmU5ZDE2NmFlOWY3N2VjYTk0ODg1ZGMzZjkyY2M1MDRiMTcwMzA4MDk5NDE0ODU5YmI2NjQxM2M3MGY2YjBlIiwiY29weV9pZCI6InYwLjUuMC1hbHBoYS4yIiwiY3JlYXRlZF9hdCI6IjIwMjYtMTEtMTQiLCJlZGl0aW9uIjoiYWxwaGEiLCJpc3N1ZXJfcG9saWN5IjpudWxsLCJraW5kIjoiY3JlYXRlIiwibW9kZSI6InNlbGZfc2lnbiIsInBhcmVudF92ZXJzaW9uIjpudWxsLCJwcmV2aW91c19yZWNvcmRfc2hhMjU2IjpudWxsLCJzY2hlbWEiOiJmaWxldmVpbC5wcm92ZW5hbmNlLnNpZ25hdHVyZS52MiIsInNlcXVlbmNlIjowLCJ0cmFuc2Zlcl90b19rZXlfaWQiOm51bGwsInZlcnNpb24iOiJ2MC41LjAtYWxwaGEuMiIsIndvcmtfaWQiOiJodHRwczovL2dpdGh1Yi5jb20vSi14LVovZmlsZXZlaWwvc291cmNlL2NyYXRlcy9maWxldmVpbC1lbmdpbmUvc3JjL29zLnJzIn0sInNpZ25hdHVyZXMiOlt7ImtleV9pZCI6Ijk5ZWE2M2VmY2NmZDBmZGJkNjhlMTZlZDhmMDNkMzM3ZjE1ZWMyZTRhNmEzZDY0ZTExZDcxNGVhMWU1NDI1MzMiLCJwdWJsaWNfa2V5X2hleCI6ImFkYjNlMTdjZDEyZjk1NmQwMDcwZTE2NjNmNTMxNTM3ZmNlZGY3MzA4ZDAxNjU4ZmVhNDU2ZmVlYThmN2ZiYzUiLCJzaWduYXR1cmVfaGV4IjoiODk4NjA5NjdiZjYxY2FhYTgwZGQzODQ0ZDFlOTVhZjA3YWU2MzRhYjk3NjcyMjhiNTA2MWEyZWRiMjMyNjNiNDgzNWQzMjgxYjQwYjE0NWYxZTA0MWFlZmRjMTA2NzQ3NmU3ODE2MTM1NDU1MmQ4N2Q1MTg2ZWVmN2YxZDU5MGQifV19XQ== FVPROV1-END
