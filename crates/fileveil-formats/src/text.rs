// SPDX-License-Identifier: MPL-2.0
use fileveil_core::{
    Action, Confidence, Error, Finding, Format, Inspection, Limits, Result, RiskLayer, digest,
};

pub fn inspect(data: &[u8], format: Format, limits: &Limits) -> Result<Inspection> {
    if data.len() as u64 > limits.max_file_bytes {
        return Err(Error::Blocked("Text exceeds the input byte budget".into()));
    }
    let text = std::str::from_utf8(data)
        .map_err(|_| Error::Unsupported("Text audit requires UTF-8".into()))?;
    let mut result = Inspection::new(format, digest(data));
    result.rewrite_supported = false;
    for (offset, character) in text.char_indices() {
        let code = match character {
            '\u{feff}' if offset == 0 => Some("text.bom"),
            '\u{200b}'..='\u{200f}'
            | '\u{202a}'..='\u{202e}'
            | '\u{2060}'..='\u{206f}'
            | '\u{feff}'
            | '\u{00ad}'
            | '\u{034f}'
            | '\u{061c}' => Some("text.invisible_unicode"),
            '\u{0}'..='\u{8}' | '\u{b}'..='\u{c}' | '\u{e}'..='\u{1f}' | '\u{7f}'..='\u{9f}' => {
                Some("text.control_character")
            }
            _ => None,
        };
        if let Some(code) = code {
            if result.findings.len() >= limits.max_members {
                return Err(Error::Blocked(
                    "Text finding count exceeds the configured limit".into(),
                ));
            }
            let mut finding = Finding::new(
                code,
                RiskLayer::EmbeddedMetadata,
                &format!("UTF-8 byte {offset}"),
                "Invisible or control character present; audit only",
                Action::Preserve,
            );
            finding.confidence = Confidence::Verified;
            result.findings.push(finding);
        }
    }
    if format == Format::Html {
        let lower = text.to_ascii_lowercase();
        for (code, pattern, summary) in [
            (
                "html.comment",
                "<!--",
                "HTML comment marker present; audit only",
            ),
            (
                "html.meta",
                "<meta",
                "HTML metadata tag candidate present; audit only",
            ),
        ] {
            for (index, _) in lower.match_indices(pattern) {
                if result.findings.len() >= limits.max_members {
                    return Err(Error::Blocked(
                        "HTML finding count exceeds the configured limit".into(),
                    ));
                }
                let mut finding = Finding::new(
                    code,
                    RiskLayer::EmbeddedMetadata,
                    &format!("HTML byte {index}"),
                    summary,
                    Action::Preserve,
                );
                finding.confidence = Confidence::Heuristic;
                result.findings.push(finding);
            }
        }
    }
    Ok(result)
}

/// Joiners, bidirectional text controls, line separators and discretionary breaks stay intact.
fn removable_control(character: char) -> bool {
    matches!(character, '\u{0}'..='\u{8}' | '\u{e}'..='\u{1f}' | '\u{7f}'..='\u{84}' | '\u{86}'..='\u{9f}')
}

pub fn inspect_with_options(
    data: &[u8],
    format: Format,
    limits: &Limits,
    options: &fileveil_core::TextOptions,
) -> Result<Inspection> {
    let mut result = inspect(data, format, limits)?;
    result.rewrite_supported = true;
    for finding in &mut result.findings {
        let character = finding
            .location
            .strip_prefix("UTF-8 byte ")
            .and_then(|offset| offset.parse::<usize>().ok())
            .and_then(|offset| {
                std::str::from_utf8(data)
                    .ok()?
                    .get(offset..)?
                    .chars()
                    .next()
            });
        if (finding.code == "text.bom" && options.remove_bom)
            || (finding.code == "text.control_character"
                && options.remove_control_characters
                && character.is_some_and(removable_control))
        {
            finding.action = Action::Remove;
            finding.summary =
                "Explicitly selected UTF-8 marker or non-whitespace control character is present"
                    .into();
        }
    }
    if format == Format::Html && (options.remove_html_metadata || options.remove_html_comments) {
        for range in html_ranges(
            std::str::from_utf8(data)
                .map_err(|_| Error::Unsupported("HTML cleaning requires UTF-8".into()))?,
            limits,
            options,
        )? {
            if result.findings.len() >= limits.max_members {
                return Err(Error::Blocked(
                    "HTML finding count exceeds the report budget".into(),
                ));
            }
            let mut finding = Finding::new(
                range.code,
                RiskLayer::EmbeddedMetadata,
                &format!("HTML byte {}", range.start),
                "Explicitly selected HTML metadata or comment token is present",
                Action::Remove,
            );
            finding.confidence = Confidence::Verified;
            result.findings.push(finding);
        }
    }
    Ok(result)
}

pub fn sanitize_with_options(
    data: &[u8],
    format: Format,
    limits: &Limits,
    options: &fileveil_core::TextOptions,
) -> Result<Vec<u8>> {
    if data.len() as u64 > limits.max_file_bytes {
        return Err(Error::Blocked("Text exceeds the input byte budget".into()));
    }
    let text = std::str::from_utf8(data)
        .map_err(|_| Error::Unsupported("Text cleaning requires UTF-8".into()))?;
    let mut selected = Vec::new();
    if format == Format::Html && (options.remove_html_metadata || options.remove_html_comments) {
        let ranges = html_ranges(text, limits, options)?;
        let mut cursor = 0;
        for range in ranges {
            selected.extend_from_slice(
                data.get(cursor..range.start)
                    .ok_or_else(|| Error::Blocked("HTML token range is invalid".into()))?,
            );
            cursor = range.end;
        }
        selected.extend_from_slice(
            data.get(cursor..)
                .ok_or_else(|| Error::Blocked("HTML token range is invalid".into()))?,
        );
    } else {
        selected.extend_from_slice(data);
    }
    let text = std::str::from_utf8(&selected)
        .map_err(|_| Error::Blocked("HTML token range split a UTF-8 character".into()))?;
    let clean: String = text
        .char_indices()
        .filter_map(|(offset, character)| {
            if (offset == 0 && character == '\u{feff}' && options.remove_bom)
                || (options.remove_control_characters && removable_control(character))
            {
                None
            } else {
                Some(character)
            }
        })
        .collect();
    Ok(clean.into_bytes())
}

pub fn verify_scoped(
    before: &[u8],
    after: &[u8],
    format: Format,
    limits: &Limits,
    options: &fileveil_core::TextOptions,
) -> Result<crate::ScopedVerification> {
    if sanitize_with_options(before, format, limits, options)? != after {
        return Err(Error::Verification(
            "Text changed outside the selected character or metadata ranges".into(),
        ));
    }
    let original = inspect_with_options(before, format, limits, options)?;
    let output = inspect_with_options(after, format, limits, options)?;
    let mut findings = output.findings;
    for mut found in original.findings {
        if found.action == Action::Remove {
            found.state = fileveil_core::FindingState::RemovedVerified;
            findings.push(found);
        }
    }
    Ok(crate::ScopedVerification {findings,warnings:vec!["Only explicitly selected UTF-8 markers and metadata are removed. Linguistic joiners and bidirectional controls are retained. Full rendering equivalence remains unassessed.".into()],integrity:fileveil_core::Integrity {parseable:true,content_equal:None,..Default::default()},result:fileveil_core::Outcome::PartiallyVerified})
}

struct HtmlRange {
    start: usize,
    end: usize,
    code: &'static str,
}
fn html_ranges(
    text: &str,
    limits: &Limits,
    options: &fileveil_core::TextOptions,
) -> Result<Vec<HtmlRange>> {
    use html5gum::{DefaultEmitter, Token, Tokenizer};
    let mut emitter = DefaultEmitter::<usize>::new_with_span();
    emitter.naively_switch_states(true);
    let mut result = Vec::new();
    for (count, token) in Tokenizer::new_with_emitter(text, emitter).enumerate() {
        if count > limits.max_members.saturating_mul(32) {
            return Err(Error::Blocked(
                "HTML tokenizer exceeds the node budget".into(),
            ));
        }
        match token.map_err(|_|Error::Blocked("HTML tokenization failed".into()))? {
            Token::Error(_)=>return Err(Error::Blocked("Malformed HTML requires recovery and cannot be safely edited by the token-range cleaner".into())),
            Token::StartTag(tag)=>{
                if matches!(tag.name.as_ref(),b"svg"|b"math"|b"template"|b"noscript"|b"noframes") {
                    return Err(Error::Blocked("HTML foreign content, templates and scripting-dependent parsing require a DOM-aware cleaner and are protected in this build".into()));
                }
                if options.remove_html_metadata&&tag.name.as_ref()==b"meta" {
                    let selected=tag.attributes.iter().any(|(key,value)|{
                        if !matches!(key.as_ref(),b"name"|b"property") {return false;}
                        let name=String::from_utf8_lossy(value.as_ref()).trim().to_ascii_lowercase();
                        matches!(name.as_str(),"author"|"generator"|"creator"|"publisher"|"copyright"|"source"|"origin"|"provenance"|"date"|"created"|"creation-date"|"creation_date"|"last-modified"|"dc.creator"|"dc.publisher"|"dc.date.created"|"dcterms.creator"|"dcterms.created"|"article:author"|"article:published_time"|"article:modified_time"|"og:url"|"og:site_name")
                    });
                    if selected {result.push(HtmlRange {start:tag.span.start,end:tag.span.end,code:"html.provenance_metadata"});}
                }
            }
            Token::Comment(comment) if options.remove_html_comments=>{
                if String::from_utf8_lossy(comment.as_ref()).trim_start().starts_with("[if") {
                    return Err(Error::Blocked("Legacy conditional HTML comments can affect visible content and are protected".into()));
                }
                result.push(HtmlRange {start:comment.span.start,end:comment.span.end,code:"html.comment"});
            }
            _=>{}
        }
        if result.len() > limits.max_members {
            return Err(Error::Blocked(
                "HTML cleanup range count exceeds the report budget".into(),
            ));
        }
    }
    Ok(result)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn invisible_unicode_is_audited_without_vendor_attribution() {
        let result = inspect(
            "Visible\u{200b}text".as_bytes(),
            Format::Text,
            &Limits::default(),
        )
        .unwrap();
        assert_eq!(result.findings[0].code, "text.invisible_unicode");
        assert!(!result.rewrite_supported);
    }
    #[test]
    fn html_is_a_read_only_heuristic() {
        let result = inspect(
            b"<html><meta name='author' content='Synthetic'><!--private--></html>",
            Format::Html,
            &Limits::default(),
        )
        .unwrap();
        assert_eq!(result.findings.len(), 2);
        assert!(!format!("{:?}", result.findings).contains("Synthetic"));
    }
}
