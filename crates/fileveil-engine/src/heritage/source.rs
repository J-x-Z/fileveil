// SPDX-License-Identifier: MPL-2.0
//! Bounded, reversible provenance records in source-language line comments.
use super::container::{Extracted, MAX_MANIFEST};
use base64::{Engine, engine::general_purpose::STANDARD};
use fileveil_core::{Error, Result};
use std::path::Path;

const MAGIC: &[u8] = b"FVPROV1 ";
const END: &[u8] = b" FVPROV1-END";
const PREFIXES: [&[u8]; 4] = [b"// ", b"# ", b"-- ", b"; "];

fn invalid() -> Error {
    Error::Blocked("Malformed, duplicate or nonterminal source provenance comment".into())
}

fn comment(path: &Path) -> Option<&'static [u8]> {
    let extension = path.extension()?.to_str()?.to_ascii_lowercase();
    match extension.as_str() {
        "rs" | "c" | "h" | "cc" | "cpp" | "hpp" | "cs" | "java" | "go" | "swift" | "js" | "ts"
        | "jsx" | "tsx" | "kt" | "kts" => Some(b"// "),
        "py" | "sh" | "bash" | "zsh" | "toml" | "yaml" | "yml" | "r" | "rb" | "pl" => Some(b"# "),
        "lua" | "sql" => Some(b"-- "),
        "ini" | "cfg" => Some(b"; "),
        _ => None,
    }
}

pub fn supported_path(path: &Path) -> bool {
    comment(path).is_some()
}

pub fn validate(data: &[u8]) -> Result<()> {
    if data.contains(&0) || std::str::from_utf8(data).is_err() {
        return Err(Error::Unsupported(
            "Source provenance requires UTF-8 source without NUL bytes".into(),
        ));
    }
    Ok(())
}

pub fn validate_path(data: &[u8], path: &Path) -> Result<()> {
    validate(data)?;
    let end = data
        .len()
        .saturating_sub(usize::from(data.ends_with(b"\n")));
    let start = data[..end]
        .iter()
        .rposition(|&byte| byte == b'\n')
        .map_or(0, |offset| offset + 1);
    let line = &data[start..end];
    if prefix(line).is_some() && comment(path).is_some_and(|expected| !line.starts_with(expected)) {
        return Err(Error::Blocked(
            "Source provenance comment does not match the selected language".into(),
        ));
    }
    Ok(())
}

fn prefix(line: &[u8]) -> Option<&[u8]> {
    PREFIXES
        .iter()
        .find_map(|prefix| line.strip_prefix(*prefix)?.strip_prefix(MAGIC))
}

fn packet(line: &[u8], line_start: usize, data: &[u8]) -> Result<Option<(usize, Vec<u8>)>> {
    let Some(fields) = prefix(line) else {
        return Ok(None);
    };
    let value = std::str::from_utf8(fields).map_err(|_| invalid())?;
    let (length, encoded) = value.split_once(' ').ok_or_else(invalid)?;
    let base_len = length.parse::<usize>().map_err(|_| invalid())?;
    if length != base_len.to_string()
        || base_len.checked_add(1) != Some(line_start)
        || data.get(base_len) != Some(&b'\n')
    {
        return Err(invalid());
    }
    let encoded = encoded.as_bytes().strip_suffix(END).ok_or_else(invalid)?;
    if encoded.is_empty() || encoded.len() > MAX_MANIFEST * 2 {
        return Err(invalid());
    }
    let manifest = STANDARD.decode(encoded).map_err(|_| invalid())?;
    if manifest.is_empty() || manifest.len() > MAX_MANIFEST {
        return Err(invalid());
    }
    Ok(Some((base_len, manifest)))
}

pub fn extract(data: &[u8]) -> Result<Extracted> {
    validate(data)?;
    let mut found = None;
    let mut start = 0;
    while start < data.len() {
        let end = data[start..]
            .iter()
            .position(|&byte| byte == b'\n')
            .map_or(data.len(), |offset| start + offset);
        let line = &data[start..end];
        if prefix(line).is_some() {
            match packet(line, start, data) {
                Ok(Some(value)) => {
                    if found.is_some() || end.checked_add(1) != Some(data.len()) {
                        return Err(invalid());
                    }
                    found = Some(value);
                }
                // Literal marker examples inside strings have no matching
                // byte-offset boundary. Only a final reserved line is a packet.
                Err(error) if end == data.len() || end + 1 == data.len() => {
                    return Err(error);
                }
                _ => {}
            }
        }
        start = end.saturating_add(1);
    }
    let (base, manifest) = match found {
        Some((length, manifest)) => (data[..length].to_vec(), Some(manifest)),
        None => (data.to_vec(), None),
    };
    Ok(Extracted {
        base,
        manifest,
        carrier: "source_comment_fvprov1",
    })
}

pub fn embed(data: &[u8], path: &Path, manifest: &[u8]) -> Result<Vec<u8>> {
    validate_path(data, path)?;
    let prefix = comment(path).ok_or_else(|| {
        Error::Unsupported("This source language has no supported line-comment carrier".into())
    })?;
    if manifest.is_empty() || manifest.len() > MAX_MANIFEST {
        return Err(invalid());
    }
    let clean = extract(data)?;
    let yaml = path
        .extension()
        .and_then(|extension| extension.to_str())
        .is_some_and(|extension| {
            extension.eq_ignore_ascii_case("yaml") || extension.eq_ignore_ascii_case("yml")
        });
    if yaml && !clean.base.is_empty() && !clean.base.ends_with(b"\n") {
        return Err(Error::Blocked(
            "YAML source requires a final newline to preserve block-scalar semantics".into(),
        ));
    }
    let mut output = clean.base;
    let length = output.len();
    output.push(b'\n');
    output.extend_from_slice(prefix);
    output.extend_from_slice(MAGIC);
    output.extend_from_slice(length.to_string().as_bytes());
    output.push(b' ');
    output.extend_from_slice(STANDARD.encode(manifest).as_bytes());
    output.extend_from_slice(END);
    output.push(b'\n');
    Ok(output)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn carriers_preserve_exact_bytes_and_language_prefixes() {
        for (name, source, prefix) in [
            ("a.rs", "fn main() {}", "// "),
            ("a.py", "#!/usr/bin/env python3\nprint('你好')\n", "# "),
            ("a.toml", "[package]\r\nname = 'sample'\r\n", "# "),
            ("a.yaml", "value: |\n  text\n", "# "),
            ("a.lua", "return 1\n", "-- "),
            ("a.ini", "[section]\nname=value\n", "; "),
        ] {
            let marked = embed(source.as_bytes(), Path::new(name), b"[]").unwrap();
            assert!(marked.is_ascii() || source.contains('你'));
            assert!(marked.ends_with(b" FVPROV1-END\n"));
            assert!(marked[source.len() + 1..].starts_with(prefix.as_bytes()));
            let extracted = extract(&marked).unwrap();
            assert_eq!(extracted.base, source.as_bytes());
            assert_eq!(extracted.manifest.as_deref(), Some(b"[]".as_slice()));
        }
    }

    #[test]
    fn reserved_tail_rejects_mutation_duplicates_and_injected_bytes() {
        let marked = embed(b"fn main() {}\n", Path::new("a.rs"), b"[]").unwrap();
        for suffix in [b"\n".as_slice(), b"fn extra() {}\n", b" "] {
            let mut injected = marked.clone();
            injected.extend_from_slice(suffix);
            assert!(extract(&injected).is_err());
        }
        let mut duplicated = marked.clone();
        duplicated.extend_from_slice(&marked[b"fn main() {}\n".len()..]);
        assert!(extract(&duplicated).is_err());
        assert!(extract(&marked[..marked.len() - 1]).is_err());
        let invalid = String::from_utf8(marked).unwrap().replace("W10=", "!!!!");
        assert!(extract(invalid.as_bytes()).is_err());
        let oversized = format!(
            "fn main() {{}}\n\n// FVPROV1 13 {} FVPROV1-END\n",
            "A".repeat(MAX_MANIFEST * 2 + 4)
        );
        assert!(extract(oversized.as_bytes()).is_err());
    }

    #[test]
    fn literal_markers_inside_valid_strings_are_not_carriers() {
        let code = b"const EXAMPLE: &str = r#\"\n// FVPROV1 0 W10= FVPROV1-END\n\"#;\n";
        let extracted = extract(code).unwrap();
        assert_eq!(extracted.base, code);
        assert!(extracted.manifest.is_none());
        assert!(embed(b"value: |\n  text", Path::new("a.yaml"), b"[]").is_err());
        assert!(embed(b"{}\n", Path::new("a.json"), b"[]").is_err());
        assert!(extract(b"nul\0source").is_err());
        let python = embed(b"print('hello')\n", Path::new("a.py"), b"[]").unwrap();
        assert!(validate_path(&python, Path::new("a.rs")).is_err());
    }
}
