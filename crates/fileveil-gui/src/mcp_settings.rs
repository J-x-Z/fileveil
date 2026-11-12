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
        root_controls(
            ui,
            language,
            "Readable folders",
            &mut self.access.read_roots,
        );
        root_controls(ui, language, "Output folders", &mut self.access.write_roots);
        ui.horizontal(|ui| {
            ui.label(tr(language, "Operations per MCP connection"));
            ui.add(egui::DragValue::new(&mut self.access.max_operations).range(1..=10_000));
        });
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
fn root_controls(ui: &mut egui::Ui, language: Language, title: &str, roots: &mut Vec<PathBuf>) {
    ui.add_space(10.0);
    ui.label(tr(language, title));
    let mut remove = None;
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
    }
}
