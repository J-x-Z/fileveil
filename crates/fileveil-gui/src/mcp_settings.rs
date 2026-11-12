// SPDX-License-Identifier: MPL-2.0
//! User-selected MCP roots become explicit client launch arguments.
use crate::{
    i18n::{Language, tr},
    mcp_access::McpAccessConfig,
};
use eframe::egui;
use std::path::PathBuf;

#[derive(Default)]
pub struct McpSettings {
    pub access: McpAccessConfig,
    notice: Option<String>,
}
impl McpSettings {
    pub fn ui(&mut self, ui: &mut egui::Ui, language: Language) {
        ui.strong(tr(language, "MCP permissions"));
        ui.label(tr(
            language,
            "Choose readable folders and folders for new output copies",
        ));
        let mut changed = root_controls(
            ui,
            language,
            "Readable folders",
            &mut self.access.read_roots,
        );
        changed |= root_controls(ui, language, "Output folders", &mut self.access.write_roots);
        ui.add_space(10.0);
        ui.label(if language == Language::Chinese {
            "允许 MCP 使用的签名密钥"
        } else {
            "Explicit MCP signing keys"
        });
        ui.small(if language == Language::Chinese { "默认禁止签名。所选密钥还需位于可读目录中，连接期间绑定文件身份。" } else { "Signing is disabled by default. Selected keys must also be inside readable folders and remain identity-bound during the connection." });
        let mut remove_key = None;
        for (index, key) in self.access.signing_keys.iter().enumerate() {
            ui.horizontal(|ui| {
                ui.label(key.file_name().unwrap_or(key.as_os_str()).to_string_lossy())
                    .on_hover_text(key.to_string_lossy());
                if ui.small_button(tr(language, "Remove")).clicked() {
                    remove_key = Some(index);
                }
            });
        }
        if let Some(index) = remove_key {
            self.access.signing_keys.remove(index);
            changed = true;
        }
        if ui
            .button(if language == Language::Chinese {
                "授权签名密钥"
            } else {
                "Authorize signing key"
            })
            .clicked()
            && let Some(key) = rfd::FileDialog::new().pick_file()
            && !self.access.signing_keys.contains(&key)
        {
            self.access.signing_keys.push(key);
            changed = true;
        }
        ui.horizontal(|ui| {
            ui.label(tr(language, "Operations per MCP connection"));
            changed |= ui
                .add(egui::DragValue::new(&mut self.access.max_operations).range(1..=10_000))
                .changed();
        });
        if changed {
            self.notice = None;
        }
        ui.label(tr(
            language,
            "Update the client configuration and reconnect to apply permission changes",
        ));
        if ui.button(tr(language, "Copy MCP configuration")).clicked() {
            self.notice = Some(match self.configuration() {
                Ok(configuration) => {
                    ui.ctx().copy_text(configuration);
                    "MCP configuration copied".into()
                }
                Err(message) => message,
            });
        }
        if let Some(notice) = &self.notice {
            ui.label(tr(language, notice));
        }
    }

    fn configuration(&self) -> Result<String, String> {
        self.access.validate().map_err(|error| error.to_string())?;
        let executable = std::env::current_exe()
            .ok()
            .and_then(|path| path.into_os_string().into_string().ok())
            .ok_or_else(|| "Could not locate MCP executable".to_string())?;
        let mut arguments = vec!["--mcp".to_string()];
        for (option, roots) in [
            ("--mcp-read-root", &self.access.read_roots),
            ("--mcp-write-root", &self.access.write_roots),
            ("--mcp-signing-key", &self.access.signing_keys),
        ] {
            for root in roots {
                let path = root
                    .to_str()
                    .ok_or_else(|| "MCP configuration requires Unicode paths".to_string())?;
                arguments.push(option.into());
                arguments.push(path.into());
            }
        }
        arguments.extend([
            "--mcp-max-operations".into(),
            self.access.max_operations.to_string(),
        ]);
        serde_json::to_string_pretty(&serde_json::json!({
            "mcpServers": {"fileveil": {"command": executable, "args": arguments}}
        }))
        .map_err(|_| "Could not serialize MCP configuration".to_string())
    }
}
fn root_controls(
    ui: &mut egui::Ui,
    language: Language,
    title: &str,
    roots: &mut Vec<PathBuf>,
) -> bool {
    ui.add_space(10.0);
    ui.label(tr(language, title));
    let mut remove = None;
    let mut changed = false;
    for (index, root) in roots.iter().enumerate() {
        ui.horizontal(|ui| {
            ui.add(egui::Label::new(root.to_string_lossy()).truncate())
                .on_hover_text(root.to_string_lossy());
            if ui.small_button(tr(language, "Remove")).clicked() {
                remove = Some(index);
            }
        });
    }
    if let Some(index) = remove {
        roots.remove(index);
        changed = true;
    }
    if ui
        .button(tr(
            language,
            if title == "Readable folders" {
                "Add readable folder"
            } else {
                "Add output folder"
            },
        ))
        .clicked()
        && let Some(path) = rfd::FileDialog::new()
            .set_title(tr(language, title))
            .pick_folder()
        && !roots.contains(&path)
    {
        roots.push(path);
        changed = true;
    }
    changed
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_grants_export_a_denied_by_default_configuration() {
        let configuration = McpSettings::default().configuration().unwrap();
        let value: serde_json::Value = serde_json::from_str(&configuration).unwrap();
        let arguments = value["mcpServers"]["fileveil"]["args"].as_array().unwrap();
        assert!(arguments.iter().any(|argument| argument == "--mcp"));
        assert!(
            !arguments
                .iter()
                .any(|argument| argument == "--mcp-read-root" || argument == "--mcp-write-root")
        );
    }

    #[test]
    fn invalid_authorization_roots_cannot_be_copied_as_working_grants() {
        let mut settings = McpSettings::default();
        settings
            .access
            .read_roots
            .push(PathBuf::from("relative-folder"));
        assert!(settings.configuration().is_err());
    }
}
