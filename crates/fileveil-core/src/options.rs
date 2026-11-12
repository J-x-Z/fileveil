// SPDX-License-Identifier: MPL-2.0
//! Explicit, additive transformation choices. Intrusive document operations are opt-in.
use crate::Policy;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct SanitizeOptions {
    pub policy: Policy,
    pub deep: DeepOptions,
    pub text: TextOptions,
    pub filesystem: FilesystemOptions,
    pub pdf: PdfOptions,
    pub remove_provenance: bool,
}
impl SanitizeOptions {
    pub fn any(&self) -> bool {
        self.deep.any()
            || self.text.any()
            || self.filesystem.any()
            || self.pdf.any()
            || self.remove_provenance
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct PdfOptions {
    pub remove_attachments: bool,
    pub remove_javascript: bool,
    pub remove_annotations: bool,
}
impl PdfOptions {
    pub fn any(&self) -> bool {
        self.remove_attachments || self.remove_javascript || self.remove_annotations
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct FilesystemOptions {
    pub remove_download_origin: bool,
    pub remove_finder_tags: bool,
    pub remove_user_attributes: bool,
    pub remove_ntfs_private_streams: bool,
    pub normalize_output_timestamps: bool,
    pub normalize_creation_time: bool,
    pub remove_usage_metadata: bool,
}
impl FilesystemOptions {
    pub fn any(&self) -> bool {
        self.remove_download_origin
            || self.remove_finder_tags
            || self.remove_user_attributes
            || self.remove_ntfs_private_streams
            || self.normalize_output_timestamps
            || self.normalize_creation_time
            || self.remove_usage_metadata
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct DeepOptions {
    pub remove_comments: bool,
    pub accept_revisions: bool,
    pub remove_hidden_text: bool,
    pub remove_hidden_sheets: bool,
    pub remove_custom_xml: bool,
    pub remove_embedded_objects: bool,
    pub remove_external_relationships: bool,
    pub remove_internal_identifiers: bool,
}
impl DeepOptions {
    pub fn any(&self) -> bool {
        self.remove_comments
            || self.accept_revisions
            || self.remove_hidden_text
            || self.remove_hidden_sheets
            || self.remove_custom_xml
            || self.remove_embedded_objects
            || self.remove_external_relationships
            || self.remove_internal_identifiers
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct TextOptions {
    pub remove_bom: bool,
    pub remove_control_characters: bool,
    pub remove_html_metadata: bool,
    pub remove_html_comments: bool,
}
impl TextOptions {
    pub fn any(&self) -> bool {
        self.remove_bom
            || self.remove_control_characters
            || self.remove_html_metadata
            || self.remove_html_comments
    }
}
