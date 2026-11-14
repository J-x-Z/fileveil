// SPDX-License-Identifier: MPL-2.0
//! Explicit current-user operating-system credential storage for signing seeds.
use super::signing::{PublicKey, SigningKey};
use fileveil_core::{Error, Result};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct KeyStoreRef {
    pub key_id: String,
}

pub fn backend_name() -> &'static str {
    if cfg!(target_os = "macos") {
        "macos_keychain"
    } else if cfg!(windows) {
        "windows_credential_manager"
    } else if cfg!(target_os = "linux") {
        "linux_secret_service"
    } else {
        "unsupported"
    }
}
pub fn store(key: &SigningKey) -> Result<KeyStoreRef> {
    let reference = KeyStoreRef {
        key_id: key.public_key().key_id,
    };
    backend::store(&reference.key_id, key.secret_seed().as_ref())?;
    Ok(reference)
}
pub fn load(reference: &KeyStoreRef) -> Result<SigningKey> {
    validate_id(&reference.key_id)?;
    let bytes = backend::load(&reference.key_id)?;
    let seed = <&[u8; 32]>::try_from(bytes.as_slice())
        .map_err(|_| Error::Blocked("System signing credential has an invalid size".into()))?;
    let key = SigningKey::from_secret_seed(seed);
    if key.public_key().key_id != reference.key_id {
        return Err(Error::Verification(
            "System credential does not match its requested public-key identity".into(),
        ));
    }
    Ok(key)
}
pub fn generate() -> Result<(KeyStoreRef, PublicKey)> {
    let key = SigningKey::generate()?;
    let public = key.public_key();
    let reference = store(&key)?;
    Ok((reference, public))
}
pub fn delete(reference: &KeyStoreRef) -> Result<()> {
    validate_id(&reference.key_id)?;
    backend::delete(&reference.key_id)
}
fn validate_id(id: &str) -> Result<()> {
    if id.len() != 64
        || !id
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    {
        return Err(Error::Input(
            "System key reference must be a lower-case public-key SHA-256".into(),
        ));
    }
    Ok(())
}

#[cfg(target_os = "macos")]
mod backend {
    use super::*;
    use std::{ffi::c_void, ptr};
    use zeroize::Zeroizing;
    const SERVICE: &[u8] = b"org.fileveil.signing.v1";
    type Keychain = *mut c_void;
    #[link(name = "Security", kind = "framework")]
    unsafe extern "C" {
        fn SecKeychainAddGenericPassword(
            keychain: Keychain,
            service_len: u32,
            service: *const u8,
            account_len: u32,
            account: *const u8,
            password_len: u32,
            password: *const c_void,
            item: *mut *mut c_void,
        ) -> i32;
        fn SecKeychainFindGenericPassword(
            keychain: Keychain,
            service_len: u32,
            service: *const u8,
            account_len: u32,
            account: *const u8,
            password_len: *mut u32,
            password: *mut *mut c_void,
            item: *mut *mut c_void,
        ) -> i32;
        fn SecKeychainItemFreeContent(attributes: *mut c_void, data: *mut c_void) -> i32;
        fn SecKeychainItemDelete(item: *mut c_void) -> i32;
    }
    #[link(name = "CoreFoundation", kind = "framework")]
    unsafe extern "C" {
        fn CFRelease(value: *const c_void);
    }
    fn error(status: i32) -> Error {
        Error::Blocked(format!(
            "macOS Keychain operation failed with OSStatus {status}"
        ))
    }
    pub fn store(id: &str, seed: &[u8]) -> Result<()> {
        store_in(ptr::null_mut(), id, seed)
    }
    pub fn load(id: &str) -> Result<Zeroizing<Vec<u8>>> {
        load_in(ptr::null_mut(), id)
    }
    pub fn delete(id: &str) -> Result<()> {
        delete_in(ptr::null_mut(), id)
    }
    fn store_in(chain: Keychain, id: &str, seed: &[u8]) -> Result<()> {
        let status = unsafe {
            SecKeychainAddGenericPassword(
                chain,
                SERVICE.len() as u32,
                SERVICE.as_ptr(),
                id.len() as u32,
                id.as_ptr(),
                seed.len() as u32,
                seed.as_ptr().cast(),
                ptr::null_mut(),
            )
        };
        if status != 0 {
            return Err(error(status));
        }
        Ok(())
    }
    fn load_in(chain: Keychain, id: &str) -> Result<Zeroizing<Vec<u8>>> {
        let mut length = 0;
        let mut raw = ptr::null_mut();
        let status = unsafe {
            SecKeychainFindGenericPassword(
                chain,
                SERVICE.len() as u32,
                SERVICE.as_ptr(),
                id.len() as u32,
                id.as_ptr(),
                &mut length,
                &mut raw,
                ptr::null_mut(),
            )
        };
        if status != 0 {
            return Err(error(status));
        }
        let result = if length == 32 && !raw.is_null() {
            Ok(Zeroizing::new(
                unsafe { std::slice::from_raw_parts(raw.cast::<u8>(), 32) }.to_vec(),
            ))
        } else {
            Err(Error::Blocked(
                "macOS signing credential has an invalid size".into(),
            ))
        };
        if !raw.is_null() {
            unsafe {
                std::ptr::write_bytes(raw, 0, length as usize);
                SecKeychainItemFreeContent(ptr::null_mut(), raw);
            }
        }
        result
    }
    fn delete_in(chain: Keychain, id: &str) -> Result<()> {
        let mut item = ptr::null_mut();
        let status = unsafe {
            SecKeychainFindGenericPassword(
                chain,
                SERVICE.len() as u32,
                SERVICE.as_ptr(),
                id.len() as u32,
                id.as_ptr(),
                ptr::null_mut(),
                ptr::null_mut(),
                &mut item,
            )
        };
        if status != 0 {
            return Err(error(status));
        }
        let status = unsafe { SecKeychainItemDelete(item) };
        unsafe { CFRelease(item) };
        if status != 0 {
            return Err(error(status));
        }
        Ok(())
    }
    #[cfg(test)]
    mod tests {
        use super::*;
        use std::os::unix::ffi::OsStrExt;
        #[link(name = "Security", kind = "framework")]
        unsafe extern "C" {
            fn SecKeychainCreate(
                path: *const i8,
                password_len: u32,
                password: *const c_void,
                prompt: bool,
                access: *mut c_void,
                keychain: *mut Keychain,
            ) -> i32;
            fn SecKeychainDelete(keychain: Keychain) -> i32;
        }
        #[test]
        #[ignore = "Creates and deletes an isolated temporary macOS Keychain through native Security.framework"]
        fn isolated_native_keychain_roundtrip() {
            let directory = tempfile::tempdir().unwrap();
            let path = directory.path().join("FileVeil-test.keychain-db");
            let name = std::ffi::CString::new(path.as_os_str().as_bytes()).unwrap();
            let mut password = Zeroizing::new([0u8; 32]);
            getrandom::getrandom(password.as_mut()).unwrap();
            let mut chain = ptr::null_mut();
            assert_eq!(
                unsafe {
                    SecKeychainCreate(
                        name.as_ptr(),
                        32,
                        password.as_ptr().cast(),
                        false,
                        ptr::null_mut(),
                        &mut chain,
                    )
                },
                0
            );
            struct Cleanup(Keychain);
            impl Drop for Cleanup {
                fn drop(&mut self) {
                    unsafe {
                        SecKeychainDelete(self.0);
                        CFRelease(self.0);
                    }
                }
            }
            let _cleanup = Cleanup(chain);
            let key = SigningKey::generate().unwrap();
            let id = key.public_key().key_id;
            store_in(chain, &id, key.secret_seed().as_ref()).unwrap();
            assert!(store_in(chain, &id, &[8; 32]).is_err());
            assert_eq!(
                load_in(chain, &id).unwrap().as_slice(),
                key.secret_seed().as_ref()
            );
            delete_in(chain, &id).unwrap();
            assert!(load_in(chain, &id).is_err());
        }
    }
}

#[cfg(windows)]
mod backend {
    use super::*;
    use std::{ffi::c_void, ptr};
    use zeroize::Zeroizing;
    #[repr(C)]
    struct FileTime {
        low: u32,
        high: u32,
    }
    #[repr(C)]
    struct Credential {
        flags: u32,
        kind: u32,
        target: *mut u16,
        comment: *mut u16,
        written: FileTime,
        blob_size: u32,
        blob: *mut u8,
        persist: u32,
        attribute_count: u32,
        attributes: *mut c_void,
        alias: *mut u16,
        user: *mut u16,
    }
    #[link(name = "Advapi32")]
    unsafe extern "system" {
        fn CredWriteW(credential: *const Credential, flags: u32) -> i32;
        fn CredReadW(
            target: *const u16,
            kind: u32,
            flags: u32,
            credential: *mut *mut Credential,
        ) -> i32;
        fn CredDeleteW(target: *const u16, kind: u32, flags: u32) -> i32;
        fn CredFree(buffer: *mut c_void);
    }
    fn target(id: &str) -> Vec<u16> {
        format!("FileVeil/signing/v1/{id}")
            .encode_utf16()
            .chain(Some(0))
            .collect()
    }
    pub fn store(id: &str, seed: &[u8]) -> Result<()> {
        let mut name = target(id);
        let mut previous = ptr::null_mut();
        if unsafe { CredReadW(name.as_ptr(), 1, 0, &mut previous) } != 0 {
            unsafe { CredFree(previous.cast()) };
            return Err(Error::Blocked(
                "A system credential with this key ID already exists".into(),
            ));
        }
        let missing = std::io::Error::last_os_error().raw_os_error() == Some(1168);
        if !missing {
            return Err(Error::Blocked(
                "Windows credential store cannot be queried in this logon session".into(),
            ));
        }
        let mut owner: Vec<u16> = "FileVeil".encode_utf16().chain(Some(0)).collect();
        let credential = Credential {
            flags: 0,
            kind: 1,
            target: name.as_mut_ptr(),
            comment: ptr::null_mut(),
            written: FileTime { low: 0, high: 0 },
            blob_size: seed.len() as u32,
            blob: seed.as_ptr().cast_mut(),
            persist: 2,
            attribute_count: 0,
            attributes: ptr::null_mut(),
            alias: ptr::null_mut(),
            user: owner.as_mut_ptr(),
        };
        if unsafe { CredWriteW(&credential, 0) } == 0 {
            return Err(Error::Blocked(
                "Windows Credential Manager rejected the current-user signing credential".into(),
            ));
        }
        Ok(())
    }
    pub fn load(id: &str) -> Result<Zeroizing<Vec<u8>>> {
        let name = target(id);
        let mut pointer = ptr::null_mut();
        if unsafe { CredReadW(name.as_ptr(), 1, 0, &mut pointer) } == 0 {
            return Err(Error::Blocked(
                "Windows signing credential is unavailable in the current logon session".into(),
            ));
        }
        let credential = unsafe { &*pointer };
        let result = if credential.blob_size == 32 && !credential.blob.is_null() {
            Ok(Zeroizing::new(
                unsafe { std::slice::from_raw_parts(credential.blob, 32) }.to_vec(),
            ))
        } else {
            Err(Error::Blocked(
                "Windows signing credential has an invalid size".into(),
            ))
        };
        if !credential.blob.is_null() {
            unsafe {
                ptr::write_bytes(credential.blob, 0, credential.blob_size as usize);
            }
        }
        unsafe { CredFree(pointer.cast()) };
        result
    }
    pub fn delete(id: &str) -> Result<()> {
        let name = target(id);
        if unsafe { CredDeleteW(name.as_ptr(), 1, 0) } == 0 {
            return Err(Error::Blocked(
                "Windows signing credential could not be removed".into(),
            ));
        }
        Ok(())
    }
}

#[cfg(target_os = "linux")]
mod backend {
    use super::*;
    use crate::heritage::timestamp::bounded_command;
    use std::path::Path;
    use zeroize::Zeroizing;
    fn program() -> Result<&'static Path> {
        let p = Path::new("/usr/bin/secret-tool");
        if !p.is_file() {
            return Err(Error::Unsupported(
                "Linux Secret Service requires secret-tool and an unlocked current-user service"
                    .into(),
            ));
        }
        Ok(p)
    }
    pub fn store(id: &str, seed: &[u8]) -> Result<()> {
        let program = program()?;
        let previous = bounded_command(
            program,
            &[
                "lookup",
                "application",
                "org.fileveil.signing.v1",
                "key_id",
                id,
            ],
            Path::new("/"),
            None,
        )?;
        if previous.success && !previous.stdout.is_empty() {
            return Err(Error::Blocked(
                "A Secret Service credential with this key ID already exists".into(),
            ));
        }
        let mut encoded = Zeroizing::new(String::with_capacity(65));
        for b in seed {
            use std::fmt::Write;
            write!(encoded, "{b:02x}").unwrap();
        }
        encoded.push('\n');
        let output = bounded_command(
            program,
            &[
                "store",
                "--label",
                "FileVeil signing key",
                "application",
                "org.fileveil.signing.v1",
                "key_id",
                id,
            ],
            Path::new("/"),
            Some(encoded.as_bytes()),
        )?;
        if !output.success {
            return Err(Error::Blocked(
                "Secret Service rejected the signing credential".into(),
            ));
        }
        Ok(())
    }
    pub fn load(id: &str) -> Result<Zeroizing<Vec<u8>>> {
        let output = bounded_command(
            program()?,
            &[
                "lookup",
                "application",
                "org.fileveil.signing.v1",
                "key_id",
                id,
            ],
            Path::new("/"),
            None,
        )?;
        if !output.success {
            return Err(Error::Blocked(
                "Secret Service signing credential is unavailable".into(),
            ));
        }
        let text = std::str::from_utf8(&output.stdout)
            .map_err(|_| Error::Blocked("Invalid Secret Service signing credential".into()))?
            .trim_end_matches(['\r', '\n']);
        if text.len() != 64 {
            return Err(Error::Blocked(
                "Invalid Secret Service signing credential size".into(),
            ));
        }
        let mut result = Zeroizing::new(Vec::with_capacity(32));
        for pair in text.as_bytes().as_chunks::<2>().0 {
            let s = std::str::from_utf8(pair).unwrap();
            result.push(u8::from_str_radix(s, 16).map_err(|_| {
                Error::Blocked("Invalid Secret Service signing credential encoding".into())
            })?);
        }
        Ok(result)
    }
    pub fn delete(id: &str) -> Result<()> {
        let output = bounded_command(
            program()?,
            &[
                "clear",
                "application",
                "org.fileveil.signing.v1",
                "key_id",
                id,
            ],
            Path::new("/"),
            None,
        )?;
        if !output.success {
            return Err(Error::Blocked(
                "Secret Service signing credential could not be removed".into(),
            ));
        }
        Ok(())
    }
}
#[cfg(not(any(target_os = "macos", target_os = "linux", windows)))]
mod backend {
    use super::*;
    use zeroize::Zeroizing;
    pub fn store(_id: &str, _seed: &[u8]) -> Result<()> {
        Err(Error::Unsupported(
            "System key storage is unavailable on this platform".into(),
        ))
    }
    pub fn load(_id: &str) -> Result<Zeroizing<Vec<u8>>> {
        Err(Error::Unsupported(
            "System key storage is unavailable on this platform".into(),
        ))
    }
    pub fn delete(_id: &str) -> Result<()> {
        Err(Error::Unsupported(
            "System key storage is unavailable on this platform".into(),
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn invalid_references_fail_before_accessing_os_store() {
        for id in ["", "../key", "A", &"a".repeat(65)] {
            assert!(load(&KeyStoreRef { key_id: id.into() }).is_err());
        }
    }
    #[test]
    #[ignore = "Explicit current-user OS credential store smoke test with one generated temporary signing key"]
    fn current_user_system_store_roundtrip() {
        let key = SigningKey::generate().unwrap();
        let public = key.public_key();
        let reference = store(&key).unwrap();
        struct Cleanup(KeyStoreRef);
        impl Drop for Cleanup {
            fn drop(&mut self) {
                let _ = delete(&self.0);
            }
        }
        let _cleanup = Cleanup(reference.clone());
        assert_eq!(load(&reference).unwrap().public_key(), public);
        assert!(store(&key).is_err());
        delete(&reference).unwrap();
        assert!(load(&reference).is_err());
    }
}

// FVPROV1 17658 W3siYm9keSI6eyJhY3Rvcl9rZXlfaWQiOiI5OWVhNjNlZmNjZmQwZmRiZDY4ZTE2ZWQ4ZjAzZDMzN2YxNWVjMmU0YTZhM2Q2NGUxMWQ3MTRlYTFlNTQyNTMzIiwiYWxnb3JpdGhtIjoiRWQyNTUxOSIsImF1dGhvciI6IkoteC1aL0ZpbGVWZWlsIiwiY29udGVudF9zaGEyNTYiOiIxMGQ5ZjI5NjBjYWM5YzRkYzllNTAzZjIyYTQ4Y2I4ZDIzNGRhZmE2OTFhMGYwNzdjYzJkMGIxYTY2ZjYzZDU3IiwiY29weV9pZCI6InYwLjUuMC1hbHBoYS4zIiwiY3JlYXRlZF9hdCI6IjIwMjYtMTEtMTQiLCJlZGl0aW9uIjoiYWxwaGEiLCJpc3N1ZXJfcG9saWN5IjpudWxsLCJraW5kIjoiY3JlYXRlIiwibW9kZSI6InNlbGZfc2lnbiIsInBhcmVudF92ZXJzaW9uIjpudWxsLCJwcmV2aW91c19yZWNvcmRfc2hhMjU2IjpudWxsLCJzY2hlbWEiOiJmaWxldmVpbC5wcm92ZW5hbmNlLnNpZ25hdHVyZS52MiIsInNlcXVlbmNlIjowLCJ0cmFuc2Zlcl90b19rZXlfaWQiOm51bGwsInZlcnNpb24iOiJ2MC41LjAtYWxwaGEuMyIsIndvcmtfaWQiOiJodHRwczovL2dpdGh1Yi5jb20vSi14LVovZmlsZXZlaWwvc291cmNlL2NyYXRlcy9maWxldmVpbC1lbmdpbmUvc3JjL2hlcml0YWdlL2tleV9zdG9yZS5ycyJ9LCJzaWduYXR1cmVzIjpbeyJrZXlfaWQiOiI5OWVhNjNlZmNjZmQwZmRiZDY4ZTE2ZWQ4ZjAzZDMzN2YxNWVjMmU0YTZhM2Q2NGUxMWQ3MTRlYTFlNTQyNTMzIiwicHVibGljX2tleV9oZXgiOiJhZGIzZTE3Y2QxMmY5NTZkMDA3MGUxNjYzZjUzMTUzN2ZjZWRmNzMwOGQwMTY1OGZlYTQ1NmZlZWE4ZjdmYmM1Iiwic2lnbmF0dXJlX2hleCI6IjczYmViYjM1MWVjM2RjYTFhMWJlMDI0MmFiMjM1NzlkMTA2YTJlOTQxNGE1ZThlMjNmOTk0M2E1NmFlZDk2MzZlODhkMzhhZjBkNWI1MDkyODQ3NjJjNjM1MjdmZWU3MTczZDgzMTJjYTk2OWJhZjAxODcyZDIwYmIzYzI1NjA5In1dfV0= FVPROV1-END
