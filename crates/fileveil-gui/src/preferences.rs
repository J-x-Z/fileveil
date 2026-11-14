// SPDX-License-Identifier: MPL-2.0
//! Small local UI preferences. No file paths, reports or credentials are persisted.
use crate::i18n::Language;
use serde::{Deserialize, Serialize};
use std::{
    io::{Read, Write},
    path::{Path, PathBuf},
};

#[derive(Serialize, Deserialize)]
struct Preferences {
    language: Language,
}

pub(crate) fn load() -> Language {
    preference_path()
        .and_then(|path| read_language(&path))
        .unwrap_or_else(system_language)
}

fn read_language(path: &Path) -> Option<Language> {
    let file = std::fs::File::open(path).ok()?;
    let mut data = Vec::new();
    file.take(8193).read_to_end(&mut data).ok()?;
    if data.len() > 8192 {
        return None;
    }
    serde_json::from_slice::<Preferences>(&data)
        .ok()
        .map(|preferences| preferences.language)
}

pub(crate) fn save(language: Language) -> Result<(), &'static str> {
    let path = preference_path().ok_or("Language preference could not be saved")?;
    write_language(&path, language).map_err(|_| "Language preference could not be saved")
}

fn write_language(path: &Path, language: Language) -> std::io::Result<()> {
    let parent = path
        .parent()
        .ok_or_else(|| std::io::Error::other("Missing preferences directory"))?;
    std::fs::create_dir_all(parent)?;
    let mut temporary = tempfile::NamedTempFile::new_in(parent)?;
    temporary.write_all(&serde_json::to_vec(&Preferences { language })?)?;
    temporary.as_file().sync_all()?;
    temporary.persist(path).map_err(|error| error.error)?;
    Ok(())
}

fn preference_path() -> Option<PathBuf> {
    #[cfg(target_os = "macos")]
    let root = std::env::var_os("HOME")
        .map(|home| PathBuf::from(home).join("Library/Application Support"));
    #[cfg(target_os = "windows")]
    let root = std::env::var_os("APPDATA").map(PathBuf::from);
    #[cfg(not(any(target_os = "macos", target_os = "windows")))]
    let root = std::env::var_os("XDG_CONFIG_HOME")
        .filter(|value| Path::new(value).is_absolute())
        .map(PathBuf::from)
        .or_else(|| std::env::var_os("HOME").map(|home| PathBuf::from(home).join(".config")));
    root.map(|root| root.join("FileVeil").join("preferences.json"))
}

fn system_language() -> Language {
    // POSIX locale overrides are also useful for launchers on Windows and macOS.
    for name in ["LC_ALL", "LC_MESSAGES", "LANGUAGE", "LANG"] {
        if let Ok(value) = std::env::var(name) {
            for locale in value.split(':').filter(|locale| !locale.is_empty()) {
                if let Some(language) = Language::from_locale(locale) {
                    return language;
                }
                if locale == "C" || locale == "POSIX" || locale.starts_with("C.") {
                    return Language::English;
                }
            }
        }
    }
    platform_language().unwrap_or(Language::English)
}

#[cfg(target_os = "macos")]
fn platform_language() -> Option<Language> {
    let output = std::process::Command::new("/usr/bin/defaults")
        .args(["read", "-g", "AppleLanguages"])
        .output()
        .ok()?;
    if !output.status.success() {
        return None;
    }
    String::from_utf8(output.stdout)
        .ok()?
        .split(|c: char| c.is_whitespace() || matches!(c, '"' | ',' | '(' | ')'))
        .find_map(Language::from_locale)
}

#[cfg(target_os = "windows")]
fn platform_language() -> Option<Language> {
    #[link(name = "kernel32")]
    unsafe extern "system" {
        fn GetUserDefaultLocaleName(name: *mut u16, length: i32) -> i32;
    }
    let mut name = [0u16; 85];
    // SAFETY: the buffer has the exact advertised capacity and outlives the call.
    let length = unsafe { GetUserDefaultLocaleName(name.as_mut_ptr(), name.len() as i32) };
    (length > 1)
        .then(|| String::from_utf16_lossy(&name[..length as usize - 1]))
        .and_then(|locale| Language::from_locale(&locale))
}

#[cfg(not(any(target_os = "macos", target_os = "windows")))]
fn platform_language() -> Option<Language> {
    None
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn languages_roundtrip_and_legacy_names_remain_readable() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("settings/preferences.json");
        for language in Language::ALL {
            write_language(&path, language).unwrap();
            assert_eq!(read_language(&path), Some(language));
        }
        for (name, language) in [
            ("Chinese", Language::Chinese),
            ("English", Language::English),
        ] {
            std::fs::write(&path, format!("{{\"language\":\"{name}\"}}")).unwrap();
            assert_eq!(read_language(&path), Some(language));
        }
        for malformed in ["{", "{\"language\":\"unknown\"}", "{}"] {
            std::fs::write(&path, malformed).unwrap();
            assert_eq!(read_language(&path), None);
        }
        std::fs::write(&path, vec![b' '; 8193]).unwrap();
        assert_eq!(read_language(&path), None);
    }
    #[test]
    fn supported_os_locales_and_fallbacks() {
        for (locale, language) in [
            ("zh-Hant-TW", Language::Chinese),
            ("en_US.UTF-8", Language::English),
            ("ja_JP", Language::Japanese),
            ("ko-KR", Language::Korean),
            ("es-MX", Language::Spanish),
            ("fr_CA", Language::French),
            ("de-DE", Language::German),
            ("pt_BR.UTF-8", Language::Portuguese),
            ("ru_RU@variant", Language::Russian),
        ] {
            assert_eq!(Language::from_locale(locale), Some(language));
        }
        for locale in ["", "C", "ar_EG", "xx-YY"] {
            assert_eq!(Language::from_locale(locale), None);
        }
    }
}

// FVPROV1 5757 W3siYm9keSI6eyJhY3Rvcl9rZXlfaWQiOiI5OWVhNjNlZmNjZmQwZmRiZDY4ZTE2ZWQ4ZjAzZDMzN2YxNWVjMmU0YTZhM2Q2NGUxMWQ3MTRlYTFlNTQyNTMzIiwiYWxnb3JpdGhtIjoiRWQyNTUxOSIsImF1dGhvciI6IkoteC1aL0ZpbGVWZWlsIiwiY29udGVudF9zaGEyNTYiOiJiODY3NDBmZWI0YTdhZmNhOGYxNzA0MzEwMGRiMjhhNGNkNTJlOTFkY2E2NTgxYmY2NGFhNWQ4ZWU3YWIwOTkxIiwiY29weV9pZCI6InYwLjYuMC1hbHBoYS4xIiwiY3JlYXRlZF9hdCI6IjIwMjYtMTEtMTQiLCJlZGl0aW9uIjoiYWxwaGEiLCJpc3N1ZXJfcG9saWN5IjpudWxsLCJraW5kIjoiY3JlYXRlIiwibW9kZSI6InNlbGZfc2lnbiIsInBhcmVudF92ZXJzaW9uIjpudWxsLCJwcmV2aW91c19yZWNvcmRfc2hhMjU2IjpudWxsLCJzY2hlbWEiOiJmaWxldmVpbC5wcm92ZW5hbmNlLnNpZ25hdHVyZS52MiIsInNlcXVlbmNlIjowLCJ0cmFuc2Zlcl90b19rZXlfaWQiOm51bGwsInZlcnNpb24iOiJ2MC42LjAtYWxwaGEuMSIsIndvcmtfaWQiOiJodHRwczovL2dpdGh1Yi5jb20vSi14LVovZmlsZXZlaWwvc291cmNlL2NyYXRlcy9maWxldmVpbC1ndWkvc3JjL3ByZWZlcmVuY2VzLnJzIn0sInNpZ25hdHVyZXMiOlt7ImtleV9pZCI6Ijk5ZWE2M2VmY2NmZDBmZGJkNjhlMTZlZDhmMDNkMzM3ZjE1ZWMyZTRhNmEzZDY0ZTExZDcxNGVhMWU1NDI1MzMiLCJwdWJsaWNfa2V5X2hleCI6ImFkYjNlMTdjZDEyZjk1NmQwMDcwZTE2NjNmNTMxNTM3ZmNlZGY3MzA4ZDAxNjU4ZmVhNDU2ZmVlYThmN2ZiYzUiLCJzaWduYXR1cmVfaGV4IjoiOTZhZGI2MDk1YTVmZjAwNGUxMzEzNGNhZmQ5YTVkNmQxOWIzMzc0ZTk5OThmYzBmZWQ1NzY3NDlmOTNjM2UwYzIwYzgyZWY5NjMyMGQwYmFjYWUyNWE0ZTQ2NjZmNDc4OWU4OGEzMGIxNGU2Y2FhMGZjMjQyYjE5NTMyZjU2MDIifV19XQ== FVPROV1-END
