// SPDX-License-Identifier: MPL-2.0
//! Native workbench. All file decisions and verification come from shared engine reports.
use crate::{
    i18n::{self, Language, tr},
    image_processing::ImageProcessingDialog,
    mcp_settings::McpSettings,
    session::{FileItem, ItemStatus, Session},
    workspaces::{Workspace, Workspaces},
};
use eframe::egui::{
    self, Align, Color32, FontFamily, FontId, Frame, Layout, RichText, Stroke, TextStyle, Vec2,
};
use fileveil_core::{Action, Finding, FindingState, Outcome, Report, RiskLayer, SCHEMA_VERSION};
use std::{
    io::Write,
    path::{Path, PathBuf},
    process::Command,
    time::Duration,
};

#[derive(Clone, Copy, Default, PartialEq, Eq)]
enum Appearance {
    Light,
    #[default]
    Dark,
    HighContrast,
}
#[derive(Clone, Copy)]
struct Palette {
    background: Color32,
    surface: Color32,
    sidebar: Color32,
    text: Color32,
    muted: Color32,
    border: Color32,
    primary: Color32,
    button_fill: Color32,
    selected: Color32,
    caution: Color32,
    danger: Color32,
    shadow: egui::epaint::Shadow,
}
impl Palette {
    fn new(appearance: Appearance) -> Self {
        match appearance {
            Appearance::Light => Self {
                background: Color32::from_rgba_unmultiplied(235, 235, 235, 242),
                surface: Color32::from_rgba_unmultiplied(249, 249, 249, 246),
                sidebar: Color32::from_rgba_unmultiplied(225, 225, 225, 232),
                text: Color32::from_gray(31),
                muted: Color32::from_gray(84),
                border: Color32::from_gray(194),
                primary: Color32::from_gray(45),
                button_fill: Color32::from_gray(64),
                selected: Color32::from_gray(213),
                caution: Color32::from_gray(67),
                danger: Color32::from_gray(32),
                shadow: egui::epaint::Shadow {
                    offset: [0, 4],
                    blur: 16,
                    spread: 0,
                    color: Color32::from_black_alpha(22),
                },
            },
            Appearance::Dark => Self {
                background: Color32::from_rgba_unmultiplied(20, 20, 20, 239),
                surface: Color32::from_rgba_unmultiplied(36, 36, 36, 246),
                sidebar: Color32::from_rgba_unmultiplied(27, 27, 27, 231),
                text: Color32::from_gray(244),
                muted: Color32::from_gray(187),
                border: Color32::from_gray(74),
                primary: Color32::from_gray(235),
                button_fill: Color32::from_gray(70),
                selected: Color32::from_gray(60),
                caution: Color32::from_gray(216),
                danger: Color32::from_gray(248),
                shadow: egui::epaint::Shadow {
                    offset: [0, 4],
                    blur: 16,
                    spread: 0,
                    color: Color32::from_black_alpha(76),
                },
            },
            Appearance::HighContrast => Self {
                background: Color32::BLACK,
                surface: Color32::BLACK,
                sidebar: Color32::BLACK,
                text: Color32::WHITE,
                muted: Color32::from_gray(220),
                border: Color32::WHITE,
                primary: Color32::WHITE,
                button_fill: Color32::from_gray(64),
                selected: Color32::from_gray(48),
                caution: Color32::from_gray(235),
                danger: Color32::WHITE,
                shadow: egui::epaint::Shadow::NONE,
            },
        }
    }
}

#[derive(Default)]
struct FindingView {
    search: String,
    layer: Option<RiskLayer>,
    page: usize,
    fingerprint: Option<u64>,
    matching: Vec<usize>,
}

#[derive(Clone, Copy)]
enum PlanAction {
    Save,
    Verify,
    Process,
}

pub struct FileVeilApp {
    pub session: Session,
    language: Language,
    appearance: Appearance,
    finding_view: FindingView,
    settings_open: bool,
    json: Option<String>,
    image_processing: Option<ImageProcessingDialog>,
    mcp_settings: McpSettings,
    logo: egui::TextureHandle,
    smoke: Option<crate::smoke::SmokeProbe>,
    workspaces: Workspaces,
}
impl FileVeilApp {
    pub fn new(context: &eframe::CreationContext<'_>, paths: Vec<PathBuf>) -> Self {
        Self::new_with_language(context, paths, crate::preferences::load())
    }

    /// Create an embedded workbench with an explicitly selected interface language.
    pub fn new_with_language(
        context: &eframe::CreationContext<'_>,
        paths: Vec<PathBuf>,
        language: Language,
    ) -> Self {
        install_fonts(&context.egui_ctx);
        let appearance = Appearance::default();
        apply_style(&context.egui_ctx, appearance);
        #[cfg(target_os = "macos")]
        if let Some(window) = context.winit_window() {
            window.set_blur(true);
        }
        let icon = image::load_from_memory(include_bytes!("../../../assets/icon.png"))
            .expect("bundled icon")
            .into_rgba8();
        let logo = context.egui_ctx.load_texture(
            "fileveil-logo",
            egui::ColorImage::from_rgba_unmultiplied(
                [icon.width() as usize, icon.height() as usize],
                icon.as_raw(),
            ),
            egui::TextureOptions::LINEAR,
        );
        let mut session = Session::default();
        session.add_paths(paths);
        Self {
            session,
            language,
            appearance,
            finding_view: FindingView::default(),
            settings_open: false,
            json: None,
            image_processing: None,
            mcp_settings: McpSettings::default(),
            logo,
            smoke: None,
            workspaces: Workspaces::default(),
        }
    }
    pub fn with_smoke_report(mut self, report: Option<PathBuf>) -> Self {
        self.smoke = report.map(crate::smoke::SmokeProbe::new);
        self
    }
    fn choose_files(&mut self) {
        if let Some(paths) = rfd::FileDialog::new()
            .set_title(tr(self.language, "Add files"))
            .pick_files()
        {
            self.session.add_paths(paths);
        }
    }
    fn choose_folder(&mut self) {
        if let Some(path) = rfd::FileDialog::new()
            .set_title(tr(self.language, "Add folder"))
            .pick_folder()
        {
            self.session.add_paths(vec![path]);
        }
    }
    fn save_selected(&mut self) {
        let Some(item) = self.session.selected_item() else {
            return;
        };
        if !self.session.can_sanitize(item.id) {
            return;
        }
        let id = item.id;
        let input = item.path.clone();
        let directory = self
            .session
            .output_directory
            .clone()
            .unwrap_or_else(|| input.parent().unwrap_or(Path::new(".")).to_path_buf());
        let mut name = input.file_stem().unwrap_or_default().to_os_string();
        name.push(".clean");
        if let Some(extension) = input.extension() {
            name.push(".");
            name.push(extension);
        }
        if let Some(output) = rfd::FileDialog::new()
            .set_title(tr(self.language, "Save clean copy"))
            .set_directory(directory)
            .set_file_name(name.to_string_lossy())
            .save_file()
        {
            self.session.queue_sanitize(id, Some(output));
        }
    }
    fn verify_selected(&mut self) {
        let Some(item) = self.session.selected_item() else {
            return;
        };
        let id = item.id;
        if self.session.busy(id) {
            return;
        }
        let directory = item
            .output_path
            .as_ref()
            .unwrap_or(&item.path)
            .parent()
            .unwrap_or(Path::new("."))
            .to_path_buf();
        if let Some(output) = rfd::FileDialog::new()
            .set_title(tr(self.language, "Choose a copy to verify"))
            .set_directory(directory)
            .pick_file()
        {
            self.session.queue_verify(id, output);
        }
    }
    fn export_report(&mut self, all: bool) {
        let reports: Vec<&Report> = if all {
            self.session
                .items
                .iter()
                .filter_map(|item| item.latest.as_ref())
                .collect()
        } else {
            self.session
                .selected_item()
                .and_then(|item| item.latest.as_ref())
                .into_iter()
                .collect()
        };
        if reports.is_empty() {
            return;
        }
        let data = if all {
            serde_json::to_vec_pretty(
                &serde_json::json!({"schema_version": SCHEMA_VERSION,"tool":"FileVeil","version":env!("CARGO_PKG_VERSION"),"operation":"batch_export","reports":reports}),
            )
        } else {
            serde_json::to_vec_pretty(reports[0])
        };
        let Ok(data) = data else {
            self.session.notice = Some("Could not serialize report".into());
            return;
        };
        if let Some(path) = rfd::FileDialog::new()
            .set_title(tr(self.language, "Export report"))
            .set_file_name(if all {
                "fileveil-reports.json"
            } else {
                "fileveil-report.json"
            })
            .add_filter("JSON", &["json"])
            .save_file()
        {
            self.session.notice = Some(match save_report(&path, &data) {
                Ok(()) => tr(self.language, "Report exported").into(),
                Err(error) => error,
            });
        }
    }
    fn shortcuts(&mut self, context: &egui::Context) {
        if self.image_processing.is_some() {
            if context
                .input_mut(|input| input.consume_key(egui::Modifiers::NONE, egui::Key::Escape))
            {
                self.image_processing = None;
            }
            return;
        }
        if context.input_mut(|input| input.consume_key(egui::Modifiers::COMMAND, egui::Key::O)) {
            self.choose_files();
        }
        if context.input_mut(|input| input.consume_key(egui::Modifiers::COMMAND, egui::Key::R))
            && let Some(id) = self.session.selected
        {
            self.session.queue_scan(id);
        }
        if context.input_mut(|input| input.consume_key(egui::Modifiers::COMMAND, egui::Key::S)) {
            self.save_selected();
        }
        if context.input_mut(|input| input.consume_key(egui::Modifiers::COMMAND, egui::Key::E)) {
            self.export_report(false);
        }
        if context.input_mut(|input| input.consume_key(egui::Modifiers::NONE, egui::Key::Escape)) {
            if self.json.is_some() {
                self.json = None;
            } else if self.settings_open {
                self.settings_open = false;
            } else {
                self.session.cancel_all();
                self.workspaces.cancel();
            }
        }
    }
    fn sidebar(&mut self, ui: &mut egui::Ui, colors: Palette) {
        let language = self.language;
        let previous_appearance = self.appearance;
        let context = ui.ctx().clone();
        egui::Panel::left("file_queue")
            .default_size(264.0)
            .size_range(236.0..=340.0)
            .frame(
                Frame::new()
                    .fill(colors.sidebar)
                    .stroke(Stroke::new(1.0, colors.border))
                    .inner_margin(18),
            )
            .show(ui, |ui| {
                ui.horizontal(|ui| {
                    ui.image((self.logo.id(), Vec2::splat(38.0)));
                    ui.vertical(|ui| {
                        ui.label(RichText::new("FileVeil").size(23.0).strong());
                        ui.label(
                            RichText::new(tr(language, "Offline privacy audit"))
                                .size(12.0)
                                .color(colors.muted),
                        );
                    });
                });
                ui.add_space(23.0);
                if primary_button(ui, tr(language, "Add files"), colors, ui.available_width()) {
                    self.choose_files();
                }
                if ui
                    .add_sized(
                        [ui.available_width(), 32.0],
                        egui::Button::new(tr(language, "Add folder")),
                    )
                    .clicked()
                {
                    self.choose_folder();
                }
                ui.add_space(18.0);
                ui.horizontal(|ui| {
                    ui.label(RichText::new(tr(language, "File queue")).strong());
                    ui.label(
                        RichText::new(self.session.items.len().to_string()).color(colors.muted),
                    );
                });
                ui.horizontal(|ui| {
                    if ui
                        .add_enabled(
                            !self.session.items.is_empty(),
                            egui::Button::new(tr(language, "Scan all")).small(),
                        )
                        .clicked()
                    {
                        self.session.queue_scan_all();
                    }
                    ui.menu_button("···", |ui| {
                        if ui.button(tr(language, "Export all reports")).clicked() {
                            self.export_report(true);
                            ui.close();
                        }
                        if ui.button(tr(language, "Clear completed")).clicked() {
                            self.session.clear_completed();
                            ui.close();
                        }
                        if ui.button(tr(language, "Clear queue")).clicked() {
                            self.session.clear_all();
                            ui.close();
                        }
                    });
                });
                ui.add_space(8.0);
                let height = (ui.available_height() - 153.0).max(120.0);
                egui::ScrollArea::vertical()
                    .id_salt("queue_scroll")
                    .max_height(height)
                    .auto_shrink([false, false])
                    .show(ui, |ui| {
                        let mut selected = None;
                        let mut remove = None;
                        for item in &self.session.items {
                            let chosen = self.session.selected == Some(item.id);
                            let response = Frame::new()
                                .fill(if chosen {
                                    colors.selected
                                } else {
                                    Color32::TRANSPARENT
                                })
                                .corner_radius(8)
                                .inner_margin(10)
                                .show(ui, |ui| {
                                    ui.set_width((ui.available_width() - 1.0).max(100.0));
                                    ui.add(
                                        egui::Label::new(
                                            RichText::new(filename(&item.path)).strong().size(13.0),
                                        )
                                        .truncate(),
                                    );
                                    ui.horizontal(|ui| {
                                        ui.label(
                                            RichText::new(format_size(item.size))
                                                .size(11.0)
                                                .color(colors.muted),
                                        );
                                        ui.label(
                                            RichText::new(item_status(language, item))
                                                .size(11.0)
                                                .color(status_color(item.latest.as_ref(), colors)),
                                        );
                                    });
                                })
                                .response
                                .interact(egui::Sense::click())
                                .on_hover_text(item.path.to_string_lossy());
                            response.widget_info(|| {
                                egui::WidgetInfo::selected(
                                    egui::Role::Button,
                                    ui.is_enabled(),
                                    chosen,
                                    filename(&item.path),
                                )
                            });
                            if response.clicked() {
                                selected = Some(item.id);
                            }
                            response.context_menu(|ui| {
                                let idle = !matches!(
                                    item.status,
                                    ItemStatus::Queued
                                        | ItemStatus::Scanning
                                        | ItemStatus::Sanitizing
                                        | ItemStatus::Verifying
                                );
                                if ui
                                    .add_enabled(idle, egui::Button::new(tr(language, "Remove")))
                                    .clicked()
                                {
                                    remove = Some(item.id);
                                    ui.close();
                                }
                            });
                            ui.add_space(4.0);
                        }
                        if self.session.items.is_empty() {
                            ui.label(
                                RichText::new(tr(language, "Add files to get started"))
                                    .size(13.0)
                                    .color(colors.muted),
                            );
                        }
                        if let Some(id) = selected {
                            self.session.selected = Some(id);
                            self.finding_view.search.clear();
                            self.finding_view.page = 0;
                        }
                        if let Some(id) = remove {
                            self.session.remove(id);
                        }
                    });
                ui.with_layout(Layout::bottom_up(Align::Min), |ui| {
                    ui.add_space(3.0);
                    ui.horizontal(|ui| {
                        ui.spacing_mut().button_padding.x = 8.0;
                        ui.spacing_mut().item_spacing.x = 6.0;
                        if ui.button(tr(language, "Settings")).clicked() {
                            self.settings_open = true;
                        }
                        for (appearance, label) in
                            [(Appearance::Light, "Light"), (Appearance::Dark, "Dark")]
                        {
                            ui.selectable_value(
                                &mut self.appearance,
                                appearance,
                                tr(language, label),
                            );
                        }
                    });
                    ui.separator();
                    let can_save = self
                        .session
                        .items
                        .iter()
                        .any(|item| self.session.can_sanitize(item.id));
                    if ui
                        .add_enabled(
                            can_save,
                            egui::Button::new(tr(language, "Save all copies"))
                                .min_size(Vec2::new(ui.available_width(), 34.0)),
                        )
                        .clicked()
                    {
                        self.session.queue_sanitize_all();
                    }
                    let folder = self
                        .session
                        .output_directory
                        .as_ref()
                        .map(|p| filename(p))
                        .unwrap_or_else(|| tr(language, "Same as original").into());
                    ui.horizontal(|ui| {
                        if ui
                            .add(egui::Button::new(folder).truncate())
                            .on_hover_text(tr(language, "Choose output folder"))
                            .clicked()
                            && let Some(folder) = rfd::FileDialog::new()
                                .set_title(tr(language, "Choose output folder"))
                                .pick_folder()
                        {
                            self.session.output_directory = Some(folder);
                        }
                        if self.session.output_directory.is_some() && ui.small_button("×").clicked()
                        {
                            self.session.output_directory = None;
                        }
                    });
                    ui.label(
                        RichText::new(tr(language, "Output folder"))
                            .size(11.0)
                            .color(colors.muted),
                    );
                });
            });
        if previous_appearance != self.appearance {
            apply_style(&context, self.appearance);
            context.request_repaint();
        }
    }
    fn footer(&mut self, ui: &mut egui::Ui, colors: Palette) {
        egui::Panel::bottom("activity")
            .exact_size(35.0)
            .resizable(false)
            .frame(
                Frame::new()
                    .fill(colors.surface)
                    .stroke(Stroke::new(1.0, colors.border))
                    .inner_margin(egui::Margin::symmetric(20, 7)),
            )
            .show(ui, |ui| {
                ui.horizontal(|ui| {
                    if let Some(active) = &self.session.active {
                        ui.spinner();
                        let name = self
                            .session
                            .items
                            .iter()
                            .find(|item| item.id == active.id)
                            .map(|item| filename(&item.path))
                            .unwrap_or_default();
                        ui.label(format!(
                            "{} · {:.0}s",
                            name,
                            active.started.elapsed().as_secs_f32()
                        ));
                        ui.label(
                            RichText::new(format!(
                                "{} {}",
                                self.session.pending.len(),
                                tr(self.language, "Queued")
                            ))
                            .color(colors.muted),
                        );
                    } else {
                        ui.label(RichText::new(tr(self.language, "Ready")).color(colors.muted));
                    }
                    ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                        if (self.session.active.is_some() || !self.session.pending.is_empty())
                            && ui.button(tr(self.language, "Cancel")).clicked()
                        {
                            self.session.cancel_all();
                        }
                        ui.label(
                            RichText::new(tr(self.language, "Offline"))
                                .size(12.0)
                                .color(colors.muted),
                        );
                    });
                });
            });
    }
    fn workbench(&mut self, ui: &mut egui::Ui, colors: Palette) {
        let identity = egui::Id::unique("fileveil_details");
        egui::CentralPanel::default()
            .frame(Frame::new().fill(colors.background).inner_margin(24))
            .show(ui, |ui| {
                self.workspaces.tabs(ui, self.language);
                if self.workspaces.selected != Workspace::Files {
                    let mut open_processing = false;
                    egui::ScrollArea::vertical()
                        .id_salt("advanced_workspace_scroll")
                        .show(ui, |ui| {
                            open_processing =
                                self.workspaces.ui(ui, self.language, &mut self.session);
                        });
                    if open_processing && let Some(item) = self.session.selected_item() {
                        self.image_processing = Some(ImageProcessingDialog::new(
                            item.id,
                            item.path.clone(),
                            self.session.output_directory.clone(),
                        ));
                    }
                    return;
                }
                if self.session.selected_item().is_none() {
                    self.empty(ui, colors);
                    return;
                }
                let viewport_height = ui.available_height();
                egui::ScrollArea::vertical()
                    .id_salt("workbench_scroll")
                    .auto_shrink([false, false])
                    .show(ui, |ui| {
                        ui.scope_builder(
                            egui::UiBuilder::new()
                                .scope_id(identity)
                                .accessibility_role(egui::Role::Pane)
                                .accessibility_label(tr(self.language, "Selected file"))
                                .accessibility_parent(egui::accesskit_root_id()),
                            |ui| {
                                ui.set_min_width(ui.available_width());
                                self.workbench_content(ui, colors, viewport_height);
                            },
                        );
                    });
            });
    }
    fn workbench_content(&mut self, ui: &mut egui::Ui, colors: Palette, viewport_height: f32) {
        let language = self.language;
        let content_top = ui.cursor().top();
        if let Some(message) = self.session.notice.clone() {
            Frame::new()
                .fill(colors.selected)
                .corner_radius(6)
                .inner_margin(10)
                .show(ui, |ui| {
                    ui.horizontal_wrapped(|ui| {
                        ui.label(tr(language, &message));
                        if ui.small_button("×").clicked() {
                            self.session.notice = None;
                        }
                    });
                });
            ui.add_space(10.0);
        }
        let Some(item) = self.session.selected_item() else {
            return;
        };
        let selected_id = item.id;
        let selected_status = item_status(language, item);
        let name = filename(&item.path);
        let full_path = item.path.clone();
        let size = item.size;
        let report = item.latest.as_ref();
        let mut scan_requested = false;
        let mut export_requested = false;
        let mut json_requested = false;
        let mut plan_action = None;
        ui.horizontal(|ui| {
            ui.vertical(|ui| {
                ui.add(egui::Label::new(RichText::new(name).size(24.0).strong()).truncate())
                    .on_hover_text(full_path.to_string_lossy());
                let format = report
                    .as_ref()
                    .map(|r| format_label(&r.input_format))
                    .unwrap_or_else(|| tr(language, "Pending").into());
                ui.label(
                    RichText::new(format!("{}  ·  {}", format, format_size(size)))
                        .color(colors.muted)
                        .size(12.0),
                );
            });
        });
        ui.add_space(12.0);
        ui.horizontal_wrapped(|ui| {
            if ui
                .add_enabled(
                    !self.session.busy(selected_id),
                    egui::Button::new(tr(language, "Scan selected")),
                )
                .clicked()
            {
                scan_requested = true;
            }
            if ui
                .add_enabled(
                    report.is_some(),
                    egui::Button::new(tr(language, "Export report")),
                )
                .clicked()
            {
                export_requested = true;
            }
            if ui
                .add_enabled(
                    report.is_some(),
                    egui::Button::new(tr(language, "View JSON")),
                )
                .clicked()
            {
                json_requested = true;
            }
            if let Some(report) = &report {
                ui.label(
                    RichText::new(selected_status)
                        .strong()
                        .color(status_color(Some(report), colors)),
                );
            }
        });
        ui.add_space(16.0);
        let used_height = ui.cursor().top() - content_top;
        let content_height = (viewport_height - used_height - 12.0).max(260.0);
        let width = ui.available_width();
        let right_width = (width * 0.33).clamp(260.0, 340.0);
        ui.horizontal_top(|ui| {
            ui.spacing_mut().item_spacing.x = 16.0;
            ui.allocate_ui_with_layout(
                Vec2::new((width - right_width - 16.0).max(250.0), content_height),
                Layout::top_down(Align::Min),
                |ui| {
                    Self::findings(
                        ui,
                        report,
                        colors,
                        content_height,
                        language,
                        &mut self.finding_view,
                    );
                },
            );
            ui.allocate_ui_with_layout(
                Vec2::new(right_width, content_height),
                Layout::top_down(Align::Min),
                |ui| {
                    plan_action =
                        Self::plan(ui, item, &self.session, language, colors, content_height);
                },
            );
        });
        if json_requested {
            self.json = report.and_then(|report| serde_json::to_string_pretty(report).ok());
        }
        if scan_requested {
            self.session.queue_scan(selected_id);
        }
        if export_requested {
            self.export_report(false);
        }
        match plan_action {
            Some(PlanAction::Save) => self.save_selected(),
            Some(PlanAction::Verify) => self.verify_selected(),
            Some(PlanAction::Process) => {
                if let Some(item) = self.session.selected_item() {
                    self.image_processing = Some(ImageProcessingDialog::new(
                        item.id,
                        item.path.clone(),
                        self.session.output_directory.clone(),
                    ));
                }
            }
            None => {}
        }
    }
    fn empty(&mut self, ui: &mut egui::Ui, colors: Palette) {
        ui.vertical_centered(|ui| {
            ui.add_space((ui.available_height() * 0.17).max(20.0));
            ui.image((self.logo.id(), Vec2::splat(82.0)));
            ui.add_space(22.0);
            ui.heading(tr(self.language, "File privacy, before you share"));
            ui.add_space(10.0);
            ui.label(
                RichText::new(tr(self.language, "Choose files to inspect their metadata"))
                    .color(colors.muted),
            );
            ui.add_space(24.0);
            if primary_button(ui, tr(self.language, "Add files"), colors, 180.0) {
                self.choose_files();
            }
            ui.add_space(14.0);
            ui.label(
                RichText::new(tr(self.language, "Drop files here"))
                    .size(13.0)
                    .color(colors.muted),
            );
            ui.add_space(32.0);
            ui.label(
                RichText::new(tr(self.language, "Images · PDF · Office · Text · Media"))
                    .size(12.0)
                    .color(colors.muted),
            );
        });
    }
    fn findings(
        ui: &mut egui::Ui,
        report: Option<&Report>,
        colors: Palette,
        height: f32,
        language: Language,
        view: &mut FindingView,
    ) {
        Frame::new()
            .fill(colors.surface)
            .corner_radius(12)
            .stroke(Stroke::new(1.0, colors.border))
            .shadow(colors.shadow)
            .inner_margin(16)
            .show(ui, |ui| {
                ui.set_min_height(height - 34.0);
                let content_top = ui.cursor().top();
                ui.horizontal(|ui| {
                    ui.label(RichText::new(tr(language, "Findings")).size(17.0).strong());
                    if let Some(report) = report {
                        ui.label(
                            RichText::new(report.findings.len().to_string()).color(colors.muted),
                        );
                    }
                });
                ui.add_space(12.0);
                let old_filter = (view.search.clone(), view.layer);
                ui.horizontal(|ui| {
                    let search_width = (ui.available_width() - 143.0).max(100.0);
                    ui.add_sized(
                        [search_width, 30.0],
                        egui::TextEdit::singleline(&mut view.search)
                            .hint_text(tr(language, "Search findings")),
                    );
                    egui::ComboBox::from_id_salt("layer_filter")
                        .width(123.0)
                        .selected_text(
                            view.layer
                                .map(|layer| i18n::layer(language, layer))
                                .unwrap_or_else(|| tr(language, "All categories")),
                        )
                        .show_ui(ui, |ui| {
                            if ui
                                .selectable_value(
                                    &mut view.layer,
                                    None,
                                    tr(language, "All categories"),
                                )
                                .clicked()
                            {
                                ui.close();
                            }
                            for layer in [
                                RiskLayer::EmbeddedMetadata,
                                RiskLayer::ContainerStructure,
                                RiskLayer::Filesystem,
                                RiskLayer::ProvenanceCredential,
                                RiskLayer::ContentWatermark,
                                RiskLayer::StatisticalWatermark,
                            ] {
                                if ui
                                    .selectable_value(
                                        &mut view.layer,
                                        Some(layer),
                                        i18n::layer(language, layer),
                                    )
                                    .clicked()
                                {
                                    ui.close();
                                }
                            }
                        });
                });
                if old_filter != (view.search.clone(), view.layer) {
                    view.page = 0;
                }
                let search = view.search.to_lowercase();
                use std::hash::{Hash, Hasher};
                let mut fingerprint = std::collections::hash_map::DefaultHasher::new();
                (language as u8, &search, view.layer.map(|layer| layer as u8))
                    .hash(&mut fingerprint);
                if let Some(report) = report {
                    report.findings.len().hash(&mut fingerprint);
                    for finding in &report.findings {
                        (
                            &finding.code,
                            &finding.summary,
                            &finding.location,
                            finding.layer as u8,
                            finding.state as u8,
                            finding.action as u8,
                        )
                            .hash(&mut fingerprint);
                    }
                }
                let fingerprint = fingerprint.finish();
                if view.fingerprint != Some(fingerprint) {
                    view.matching = report
                        .map(|report| {
                            report
                                .findings
                                .iter()
                                .enumerate()
                                .filter(|(_, finding)| {
                                    if view.layer.is_some_and(|layer| layer != finding.layer) {
                                        return false;
                                    }
                                    search.is_empty()
                                        || format!(
                                            "{} {} {} {}",
                                            i18n::finding_title(language, finding),
                                            i18n::finding_summary(language, finding),
                                            finding.code,
                                            finding.location
                                        )
                                        .to_lowercase()
                                        .contains(&search)
                                })
                                .map(|(index, _)| index)
                                .collect()
                        })
                        .unwrap_or_default();
                    view.fingerprint = Some(fingerprint);
                }
                let pages = view.matching.len().div_ceil(100).max(1);
                view.page = view.page.min(pages - 1);
                if pages > 1 {
                    ui.horizontal(|ui| {
                        if ui
                            .add_enabled(
                                view.page > 0,
                                egui::Button::new(tr(language, "Previous page")),
                            )
                            .clicked()
                        {
                            view.page -= 1;
                        }
                        ui.label(format!("{} / {}", view.page + 1, pages));
                        if ui
                            .add_enabled(
                                view.page + 1 < pages,
                                egui::Button::new(tr(language, "Next page")),
                            )
                            .clicked()
                        {
                            view.page += 1;
                        }
                    });
                }
                ui.add_space(10.0);
                let list_height = (height - 34.0 - (ui.cursor().top() - content_top)).max(40.0);
                egui::ScrollArea::vertical()
                    .id_salt("findings_scroll")
                    .max_height(list_height)
                    .auto_shrink([false, false])
                    .show(ui, |ui| {
                        let Some(report) = report else {
                            ui.label(tr(language, "No report yet"));
                            return;
                        };
                        for index in view.matching.iter().skip(view.page * 100).take(100) {
                            let finding = &report.findings[*index];
                            let title = i18n::finding_title(language, finding);
                            let summary = i18n::finding_summary(language, finding);
                            finding_row(ui, finding, &title, &summary, language, colors);
                            ui.add_space(9.0);
                        }
                        if view.matching.is_empty() {
                            ui.label(
                                RichText::new(tr(language, "No findings match the filter"))
                                    .color(colors.muted),
                            );
                        }
                    });
            });
    }
    fn plan(
        ui: &mut egui::Ui,
        item: &FileItem,
        session: &Session,
        language: Language,
        colors: Palette,
        height: f32,
    ) -> Option<PlanAction> {
        let id = item.id;
        let scan = session.current_scan(id);
        let report = item.latest.as_ref();
        let mut action = None;
        Frame::new()
            .fill(colors.surface)
            .corner_radius(12)
            .stroke(Stroke::new(1.0, colors.border))
            .shadow(colors.shadow)
            .inner_margin(16)
            .show(ui, |ui| {
                ui.set_min_height(height - 34.0);
                let content_top = ui.cursor().top();
                ui.label(
                    RichText::new(tr(language, "Cleaning plan"))
                        .size(17.0)
                        .strong(),
                );
                ui.add_space(6.0);
                ui.label(
                    RichText::new(tr(language, "Safe profile"))
                        .color(colors.primary)
                        .strong()
                        .size(12.0),
                );
                ui.add_space(10.0);
                let can_save = session.can_sanitize(id);
                if ui
                    .add_enabled(
                        can_save,
                        egui::Button::new(
                            RichText::new(tr(language, "Save clean copy")).color(Color32::WHITE),
                        )
                        .fill(colors.button_fill)
                        .min_size(Vec2::new(ui.available_width(), 39.0)),
                    )
                    .clicked()
                {
                    action = Some(PlanAction::Save);
                }
                if ui
                    .add_enabled(
                        scan.is_some() && !session.busy(id),
                        egui::Button::new(tr(language, "Verify copy"))
                            .min_size(Vec2::new(ui.available_width(), 32.0)),
                    )
                    .clicked()
                {
                    action = Some(PlanAction::Verify);
                }
                if ui
                    .add_enabled(
                        session.can_process_image(id),
                        egui::Button::new(tr(language, "Image watermark processing"))
                            .min_size(Vec2::new(ui.available_width(), 32.0)),
                    )
                    .clicked()
                {
                    action = Some(PlanAction::Process);
                }
                ui.add_space(12.0);
                let list_height = (height - 34.0 - (ui.cursor().top() - content_top)).max(40.0);
                egui::ScrollArea::vertical()
                    .id_salt("plan_scroll")
                    .max_height(list_height)
                    .auto_shrink([false, false])
                    .show(ui, |ui| {
                        if let Some(scan) = scan {
                            let mut removable = std::collections::BTreeMap::new();
                            for finding in scan.findings.iter().filter(|finding| {
                                matches!(
                                    finding.action,
                                    Action::Remove | Action::Normalize | Action::Rebuild
                                )
                            }) {
                                let entry = removable
                                    .entry((finding.code.as_str(), finding.action as u8))
                                    .or_insert((finding, 0usize));
                                entry.1 += 1;
                            }
                            if removable.is_empty() {
                                ui.label(
                                    RichText::new(tr(language, "No supported fields to remove"))
                                        .size(12.0)
                                        .color(colors.muted),
                                );
                            }
                            for (finding, count) in removable.values() {
                                ui.horizontal_wrapped(|ui| {
                                    ui.label(
                                        RichText::new(i18n::action(language, finding.action))
                                            .size(11.0)
                                            .color(colors.primary),
                                    );
                                    ui.label(
                                        RichText::new(format!(
                                            "{} · {}",
                                            i18n::finding_title(language, finding),
                                            count
                                        ))
                                        .size(12.0),
                                    );
                                });
                                ui.add_space(4.0);
                            }
                            let retained = scan
                                .findings
                                .iter()
                                .filter(|f| f.action == Action::AskUser)
                                .count();
                            if retained > 0 {
                                ui.add_space(8.0);
                                ui.label(
                                    RichText::new(format!(
                                        "{} · {}",
                                        tr(language, "Needs review"),
                                        retained
                                    ))
                                    .strong()
                                    .size(12.0)
                                    .color(colors.caution),
                                );
                            }
                        } else {
                            ui.label(
                                RichText::new(tr(
                                    language,
                                    if report.is_some() {
                                        "No safe cleanup plan is available"
                                    } else {
                                        "Scan a file to see its plan"
                                    },
                                ))
                                .size(12.0)
                                .color(colors.muted),
                            );
                        }
                        if let Some(report) = report {
                            for warning in &report.warnings {
                                ui.add_space(9.0);
                                ui.label(RichText::new(tr(language, warning)).size(11.0).color(
                                    if matches!(report.result, Outcome::Blocked | Outcome::Failed) {
                                        colors.danger
                                    } else {
                                        colors.muted
                                    },
                                ));
                            }
                        }
                    });
            });
        action
    }
    fn verification(
        &self,
        ui: &mut egui::Ui,
        report: &Report,
        output: Option<&Path>,
        colors: Palette,
    ) {
        let language = self.language;
        Frame::new()
            .fill(colors.surface)
            .corner_radius(12)
            .stroke(Stroke::new(1.0, colors.border))
            .shadow(colors.shadow)
            .inner_margin(15)
            .show(ui, |ui| {
                ui.set_min_width(ui.available_width());
                ui.horizontal(|ui| {
                    ui.label(
                        RichText::new(tr(language, "Verification"))
                            .strong()
                            .size(15.0),
                    );
                    ui.label(
                        RichText::new(if report.operation == "scan" {
                            tr(language, "Not verified yet")
                        } else {
                            i18n::outcome(language, report.result)
                        })
                        .size(12.0)
                        .color(status_color(Some(report), colors)),
                    );
                });
                ui.add_space(8.0);
                ui.horizontal_wrapped(|ui| {
                    let metrics = if report.image_processing.is_some() {
                        [
                            ("Processing parameters verified", Some(true)),
                            ("Original unchanged", report.integrity.original_unchanged),
                            (
                                "Security markers preserved",
                                report.integrity.security_markers_preserved,
                            ),
                        ]
                    } else {
                        [
                            ("Content preserved", report.integrity.content_equal),
                            ("Pixels identical", report.integrity.pixel_equal),
                            (
                                "Security markers preserved",
                                report.integrity.security_markers_preserved,
                            ),
                        ]
                    };
                    for (key, value) in metrics {
                        {
                            ui.label(
                                RichText::new(format!(
                                    "{} {}",
                                    match value {
                                        Some(true) => "✓",
                                        Some(false) => "×",
                                        None => "—",
                                    },
                                    tr(language, key)
                                ))
                                .size(12.0)
                                .color(match value {
                                    Some(true) => colors.primary,
                                    Some(false) => colors.danger,
                                    None => colors.muted,
                                }),
                            );
                            ui.add_space(10.0);
                        }
                    }
                });
                if let Some(processing) = &report.image_processing {
                    ui.add_space(5.0);
                    let mode = match processing.mode {
                        fileveil_core::ImageProcessMode::LowBits => {
                            tr(language, "Low-bit clearing")
                        }
                        fileveil_core::ImageProcessMode::Signal => {
                            tr(language, "Signal processing")
                        }
                    };
                    ui.label(
                        RichText::new(format!(
                            "{} · {} {} · {} {}/255 · MSE {:.3}",
                            mode,
                            tr(language, "Changed samples"),
                            processing.changed_samples,
                            tr(language, "Maximum change"),
                            processing.max_delta,
                            processing.mse,
                        ))
                        .size(11.0)
                        .color(colors.muted),
                    );
                    ui.label(
                        RichText::new(tr(
                            language,
                            "Unknown keyed-watermark detection remains unassessed",
                        ))
                        .size(11.0)
                        .color(colors.caution),
                    );
                    if let Some(summary) =
                        crate::workspaces::method_retest_summary(language, report)
                    {
                        ui.label(RichText::new(summary).size(11.0).color(colors.muted));
                    }
                }
                ui.add_space(8.0);
                for (key, hash) in [
                    ("Original SHA-256", &report.input_sha256),
                    ("Output SHA-256", &report.output_sha256),
                ] {
                    {
                        let hash = hash.as_deref().unwrap_or("—");
                        ui.horizontal(|ui| {
                            ui.add_sized(
                                [145.0, 18.0],
                                egui::Label::new(
                                    RichText::new(tr(language, key))
                                        .size(11.0)
                                        .color(colors.muted),
                                ),
                            );
                            ui.add(
                                egui::Label::new(RichText::new(hash).monospace().size(10.0))
                                    .truncate(),
                            )
                            .on_hover_text(hash);
                        });
                    }
                }
                ui.add_space(7.0);
                ui.horizontal(|ui| {
                    let name = output
                        .map(filename)
                        .unwrap_or_else(|| tr(language, "Output copy").into());
                    ui.add(egui::Label::new(RichText::new(name).size(12.0)).truncate());
                    if ui
                        .add_enabled(
                            output.is_some(),
                            egui::Button::new(tr(language, "Open output folder")).small(),
                        )
                        .clicked()
                        && let Some(path) = output
                    {
                        reveal_output(path);
                    }
                });
            });
    }
    fn dialogs(&mut self, context: &egui::Context) {
        let language = self.language;
        if self.settings_open {
            let mut open = true;
            let old = self.appearance;
            egui::Window::new(tr(language, "Settings"))
                .id(egui::Id::unique("settings_window"))
                .open(&mut open)
                .resizable(false)
                .default_width(420.0)
                .max_height((context.viewport_rect().height() - 100.0).max(400.0))
                .vscroll(true)
                .default_pos(context.viewport_rect().center() - Vec2::new(210.0, 280.0))
                .show(context, |ui| {
                    ui.label(RichText::new("FileVeil").size(21.0).strong());
                    ui.label(format!("v{}", env!("CARGO_PKG_VERSION")));
                    ui.add_space(14.0);
                    ui.horizontal(|ui| {
                        ui.label(tr(language, "Language"));
                        egui::ComboBox::from_id_salt("settings_language")
                            .width(140.0)
                            .selected_text(self.language.native_name())
                            .show_ui(ui, |ui| {
                                for choice in Language::ALL {
                                    let label = choice.native_name();
                                    if ui
                                        .selectable_value(&mut self.language, choice, label)
                                        .clicked()
                                    {
                                        ui.close();
                                    }
                                }
                            });
                    });
                    ui.small(tr(self.language, "Technical report values and unrecognized backend messages are shown in English."));
                    ui.add_space(14.0);
                    ui.label(tr(language, "Appearance"));
                    ui.horizontal(|ui| {
                        for (appearance, label) in [
                            (Appearance::Light, "Light"),
                            (Appearance::Dark, "Dark"),
                            (Appearance::HighContrast, "High contrast"),
                        ] {
                            ui.selectable_value(
                                &mut self.appearance,
                                appearance,
                                tr(language, label),
                            );
                        }
                    });
                    ui.add_space(14.0);
                    ui.small(tr(language, "Pixel and archive budgets constrain decoded images and archive/Lab inputs. They are separate from total process memory."));
                    let mut file_mib = self.session.limits.max_file_bytes / (1024 * 1024);
                    egui::Grid::new("settings_grid")
                        .spacing([24.0, 12.0])
                        .show(ui, |ui| {
                            ui.label(tr(language, "File size limit (MiB)"));
                            if ui
                                .add(egui::DragValue::new(&mut file_mib).range(1..=512))
                                .changed()
                            {
                                self.session.limits.max_file_bytes = file_mib * 1024 * 1024;
                            }
                            ui.end_row();
                            let mut megapixels = (self.session.limits.max_pixels / 1_000_000).max(1);
                            ui.label(tr(language, "Image pixel budget (MP)"));
                            if ui.add(egui::DragValue::new(&mut megapixels).range(1..=64)).changed() {
                                self.session.limits.max_pixels = megapixels * 1_000_000;
                            }
                            ui.end_row();
                            let mut aggregate_mib = self.session.limits.max_uncompressed_bytes / (1024 * 1024);
                            ui.label(tr(language, "Archive and Lab budget (MiB)"));
                            if ui.add(egui::DragValue::new(&mut aggregate_mib).range(1..=1024)).changed() {
                                self.session.limits.max_uncompressed_bytes = aggregate_mib * 1024 * 1024;
                            }
                            ui.end_row();
                            ui.label(tr(language, "Timeout (seconds)"));
                            ui.add(
                                egui::DragValue::new(&mut self.session.timeout_seconds)
                                    .range(1..=3600),
                            );
                            ui.end_row();
                        });
                    ui.add_space(13.0);
                    ui.checkbox(
                        &mut self.session.include_subfolders,
                        tr(language, "Include subfolders"),
                    );
                    ui.add_space(14.0);
                    ui.separator();
                    self.mcp_settings.ui(ui, language);
                    ui.add_space(14.0);
                    ui.separator();
                    ui.label(
                        RichText::new(tr(
                            language,
                            "Files are processed locally. Reports redact metadata values.",
                        ))
                        .size(12.0),
                    );
                });
            self.settings_open = open;
            if language != self.language {
                if let Err(message) = crate::preferences::save(self.language) {
                    self.session.notice = Some(message.into());
                }
                context.request_repaint();
            }
            if old != self.appearance {
                apply_style(context, self.appearance);
                context.request_repaint();
            }
        }
        if let Some(mut json) = self.json.take() {
            let mut open = true;
            egui::Window::new(tr(language, "JSON report"))
                .id(egui::Id::unique("json_window"))
                .open(&mut open)
                .default_size([760.0, 540.0])
                .default_pos(context.viewport_rect().center() - Vec2::new(380.0, 270.0))
                .show(context, |ui| {
                    if ui.button(tr(language, "Copy JSON")).clicked() {
                        ui.ctx().copy_text(json.clone());
                    }
                    egui::ScrollArea::both().show(ui, |ui| {
                        ui.add(
                            egui::TextEdit::multiline(&mut json)
                                .code_editor()
                                .desired_width(f32::INFINITY)
                                .desired_rows(28)
                                .interactive(false),
                        );
                    });
                });
            if open {
                self.json = Some(json);
            }
        }
    }
}
impl eframe::App for FileVeilApp {
    fn clear_color(&self, _visuals: &egui::Visuals) -> [f32; 4] {
        if cfg!(target_os = "macos") && self.appearance != Appearance::HighContrast {
            [0.0; 4]
        } else {
            Palette::new(self.appearance)
                .background
                .to_opaque()
                .to_normalized_gamma_f32()
        }
    }
    fn logic(&mut self, context: &egui::Context, _frame: &mut eframe::Frame) {
        self.workspaces.poll(context, &self.session);
        if !self.workspaces.busy() {
            self.session.poll(context);
        }
        if self.session.active.is_some() {
            context.request_repaint_after(Duration::from_millis(100));
        }
    }
    fn ui(&mut self, ui: &mut egui::Ui, _frame: &mut eframe::Frame) {
        let context = ui.ctx().clone();
        self.shortcuts(&context);
        let dropped = context.input(|input| {
            input
                .raw
                .dropped_files
                .iter()
                .map(|file| file.path().to_path_buf())
                .collect::<Vec<_>>()
        });
        if !dropped.is_empty() {
            self.session.add_paths(dropped);
        }
        let colors = Palette::new(self.appearance);
        #[cfg(target_os = "macos")]
        egui::Panel::top("native_titlebar")
            .exact_size(30.0)
            .resizable(false)
            .frame(Frame::new().fill(colors.background))
            .show(ui, |ui| {
                let response = ui.allocate_response(ui.available_size(), egui::Sense::drag());
                if response.drag_started() {
                    context.send_viewport_cmd(egui::ViewportCommand::StartDrag);
                }
            });
        self.footer(ui, colors);
        self.sidebar(ui, colors);
        if self.workspaces.selected == Workspace::Files
            && let Some(item) = self.session.selected_item()
        {
            let pending = Report::new("scan", fileveil_core::Format::Unknown);
            let report = item.latest.as_ref().unwrap_or(&pending);
            let output = item
                .output_path
                .as_deref()
                .filter(|_| report.output_sha256.is_some());
            egui::Panel::bottom("verification_panel")
                .resizable(true)
                .default_size(275.0)
                .min_size(270.0)
                .max_size(360.0)
                .frame(
                    Frame::new()
                        .fill(colors.background)
                        .inner_margin(egui::Margin {
                            left: 24,
                            right: 24,
                            top: 0,
                            bottom: 16,
                        }),
                )
                .show(ui, |ui| {
                    self.verification(ui, report, output, colors);
                });
        }
        self.workbench(ui, colors);
        self.dialogs(&context);
        if let Some(probe) = &mut self.smoke {
            probe.frame(&context);
        }
        if let Some(mut dialog) = self.image_processing.take()
            && dialog.show(&context, self.language, &mut self.session)
        {
            self.image_processing = Some(dialog);
        }
        if context.input(|input| !input.raw.hovered_files.is_empty()) {
            let painter = context.layer_painter(egui::LayerId::new(
                egui::Order::Foreground,
                egui::Id::unique("file_drop_overlay"),
            ));
            let rect = context.viewport_rect().shrink(8.0);
            painter.rect_stroke(
                rect,
                12.0,
                Stroke::new(4.0, colors.primary),
                egui::StrokeKind::Inside,
            );
        }
    }
}

fn install_fonts(context: &egui::Context) {
    let mut fonts = egui::FontDefinitions::default();
    fonts.font_data.insert(
        "Inter".into(),
        egui::FontData::from_static(include_bytes!("../../../assets/fonts/Inter.ttf")).into(),
    );
    fonts.font_data.insert(
        "Noto Sans SC".into(),
        egui::FontData::from_static(include_bytes!("../../../assets/fonts/NotoSansSC.ttf")).into(),
    );
    fonts.font_data.insert(
        "Noto Sans KR Hangul".into(),
        egui::FontData::from_static(include_bytes!(
            "../../../assets/fonts/NotoSansKR-Hangul.ttf"
        ))
        .into(),
    );
    fonts
        .families
        .get_mut(&FontFamily::Proportional)
        .expect("proportional family")
        .splice(
            0..0,
            [
                "Inter".into(),
                "Noto Sans SC".into(),
                "Noto Sans KR Hangul".into(),
            ],
        );
    fonts
        .families
        .get_mut(&FontFamily::Monospace)
        .expect("monospace family")
        .push("Noto Sans SC".into());
    fonts
        .families
        .get_mut(&FontFamily::Monospace)
        .expect("monospace family")
        .push("Noto Sans KR Hangul".into());
    context.set_fonts(fonts);
}
fn apply_style(context: &egui::Context, appearance: Appearance) {
    let colors = Palette::new(appearance);
    context.send_viewport_cmd(egui::ViewportCommand::SetTheme(
        if appearance == Appearance::Light {
            egui::SystemTheme::Light
        } else {
            egui::SystemTheme::Dark
        },
    ));
    context.set_theme(if appearance == Appearance::Light {
        egui::Theme::Light
    } else {
        egui::Theme::Dark
    });
    let mut style = (*context.global_style()).clone();
    style.visuals = if appearance == Appearance::Light {
        egui::Visuals::light()
    } else {
        egui::Visuals::dark()
    };
    style.visuals.override_text_color = Some(colors.text);
    style.visuals.weak_text_color = Some(colors.muted);
    style.visuals.panel_fill = colors.background;
    style.visuals.window_fill = colors.surface;
    style.visuals.extreme_bg_color = colors.background;
    style.visuals.faint_bg_color = colors.selected;
    style.visuals.text_edit_bg_color = Some(colors.background);
    style.visuals.code_bg_color = colors.selected;
    style.visuals.hyperlink_color = colors.primary;
    style.visuals.warn_fg_color = colors.caution;
    style.visuals.error_fg_color = colors.danger;
    style.visuals.text_cursor.stroke = Stroke::new(1.5, colors.primary);
    style.visuals.ime_composition.active_underline_stroke = Stroke::new(1.5, colors.primary);
    style.visuals.ime_composition.inactive_underline_stroke = Stroke::new(1.0, colors.muted);
    style.visuals.window_corner_radius = 12.into();
    style.visuals.menu_corner_radius = 8.into();
    style.visuals.window_stroke = Stroke::new(1.0, colors.border);
    style.visuals.window_shadow = egui::epaint::Shadow {
        offset: [0, 8],
        blur: 24,
        ..colors.shadow
    };
    style.visuals.popup_shadow = colors.shadow;
    style.visuals.selection.bg_fill = colors.selected;
    style.visuals.selection.stroke = Stroke::new(1.0, colors.primary);
    for widget in [
        &mut style.visuals.widgets.noninteractive,
        &mut style.visuals.widgets.inactive,
        &mut style.visuals.widgets.hovered,
        &mut style.visuals.widgets.active,
        &mut style.visuals.widgets.open,
    ] {
        widget.bg_fill = colors.surface;
        widget.weak_bg_fill = colors.surface;
        widget.bg_stroke = Stroke::new(1.0, colors.border);
        widget.fg_stroke = Stroke::new(1.0, colors.text);
        widget.corner_radius = 7.into();
        widget.expansion = 0.0;
    }
    style.visuals.widgets.hovered.bg_fill = colors.selected;
    style.visuals.widgets.hovered.weak_bg_fill = colors.selected;
    style.visuals.widgets.hovered.bg_stroke = Stroke::new(1.0, colors.primary);
    style.visuals.widgets.active.bg_fill = colors.selected;
    style.visuals.widgets.active.weak_bg_fill = colors.selected;
    style.visuals.widgets.active.bg_stroke = Stroke::new(1.0, colors.primary);
    style.visuals.widgets.open.bg_fill = colors.selected;
    style.visuals.widgets.open.weak_bg_fill = colors.selected;
    style.visuals.widgets.open.bg_stroke = Stroke::new(1.0, colors.primary);
    style.spacing.item_spacing = Vec2::new(8.0, 7.0);
    style.spacing.button_padding = Vec2::new(12.0, 8.0);
    style.spacing.interact_size = Vec2::new(32.0, 30.0);
    style
        .text_styles
        .insert(TextStyle::Body, FontId::proportional(14.0));
    style
        .text_styles
        .insert(TextStyle::Button, FontId::proportional(13.0));
    style
        .text_styles
        .insert(TextStyle::Small, FontId::proportional(11.0));
    style
        .text_styles
        .insert(TextStyle::Heading, FontId::proportional(24.0));
    context.set_global_style(style);
}
fn primary_button(ui: &mut egui::Ui, label: &str, colors: Palette, width: f32) -> bool {
    ui.add_sized(
        [width, 39.0],
        egui::Button::new(RichText::new(label).color(Color32::WHITE))
            .fill(colors.button_fill)
            .corner_radius(7),
    )
    .clicked()
}
fn filename(path: &Path) -> String {
    path.file_name()
        .unwrap_or(path.as_os_str())
        .to_string_lossy()
        .into_owned()
}
fn format_size(bytes: u64) -> String {
    if bytes >= 1024 * 1024 {
        format!("{:.1} MB", bytes as f64 / (1024.0 * 1024.0))
    } else if bytes >= 1024 {
        format!("{:.1} KB", bytes as f64 / 1024.0)
    } else {
        format!("{bytes} B")
    }
}
fn format_label(mime: &str) -> String {
    match mime {
        "image/jpeg" => "JPEG",
        "image/png" => "PNG",
        "image/heif" => "HEIC / HEIF",
        "image/avif" => "AVIF",
        "video/mp4" => "MP4",
        "video/quicktime" => "MOV",
        "audio/wav" => "WAV",
        "audio/flac" => "FLAC",
        "audio/mpeg" => "MP3",
        "text/plain" => "UTF-8",
        "text/html" => "HTML",
        "application/pdf" => "PDF",
        value if value.contains("wordprocessingml") => "DOCX",
        value if value.contains("spreadsheetml") => "XLSX",
        value if value.contains("presentationml") => "PPTX",
        _ => mime,
    }
    .into()
}
fn item_status(language: Language, item: &FileItem) -> &'static str {
    match item.status {
        ItemStatus::Ready => tr(language, "Pending"),
        ItemStatus::Queued => tr(language, "Queued"),
        ItemStatus::Scanning => tr(language, "Scanning"),
        ItemStatus::Sanitizing => tr(language, "Sanitizing"),
        ItemStatus::Verifying => tr(language, "Verifying"),
        ItemStatus::Cancelled => tr(language, "Cancelled"),
        ItemStatus::Finished => item
            .latest
            .as_ref()
            .map(|report| report_status(language, report))
            .unwrap_or_else(|| tr(language, "Ready")),
    }
}
fn report_status(language: Language, report: &Report) -> &'static str {
    if report.operation == "scan"
        && report
            .pdf
            .as_ref()
            .is_some_and(|pdf| pdf["scan_status"] == "complete")
    {
        return tr(language, "Scan complete");
    }
    if report.operation == "scan" && report.result == Outcome::VerifiedWithinScope {
        if report.findings.iter().any(|finding| {
            matches!(
                finding.action,
                Action::Remove | Action::Normalize | Action::Rebuild
            )
        }) {
            return tr(language, "Ready to clean");
        }
        return tr(language, "Scan complete");
    }
    i18n::outcome(language, report.result)
}
fn status_color(report: Option<&Report>, colors: Palette) -> Color32 {
    match report.map(|report| report.result) {
        Some(Outcome::VerifiedWithinScope) => colors.primary,
        Some(Outcome::PartiallyVerified) => colors.caution,
        Some(Outcome::Blocked | Outcome::Failed) => colors.danger,
        _ => colors.muted,
    }
}
fn finding_row(
    ui: &mut egui::Ui,
    finding: &Finding,
    title: &str,
    summary: &str,
    language: Language,
    colors: Palette,
) {
    let tint = match finding.state {
        FindingState::RemovedVerified => colors.primary,
        FindingState::NotAssessed => colors.muted,
        _ if finding.action == Action::AskUser => colors.caution,
        _ => colors.text,
    };
    Frame::new()
        .stroke(Stroke::new(1.0, colors.border))
        .corner_radius(7)
        .inner_margin(12)
        .show(ui, |ui| {
            ui.set_width(ui.available_width().max(150.0));
            ui.horizontal_wrapped(|ui| {
                ui.label(RichText::new(title).strong().size(13.0));
                ui.label(
                    RichText::new(i18n::state(language, finding.state))
                        .size(11.0)
                        .color(tint),
                );
            });
            ui.label(RichText::new(summary).size(12.0).color(colors.muted));
            ui.horizontal_wrapped(|ui| {
                ui.label(
                    RichText::new(&finding.location)
                        .monospace()
                        .size(10.0)
                        .color(colors.muted),
                );
                ui.label(
                    RichText::new(i18n::layer(language, finding.layer))
                        .size(10.0)
                        .color(colors.muted),
                );
            });
            ui.label(
                RichText::new(&finding.code)
                    .monospace()
                    .size(10.0)
                    .color(colors.muted),
            )
            .on_hover_text(format!(
                "{} · {}",
                i18n::action(language, finding.action),
                i18n::confidence(language, finding.confidence)
            ));
        });
}
pub(crate) fn save_report(path: &Path, data: &[u8]) -> std::result::Result<(), String> {
    let directory = path
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or(Path::new("."));
    let mut temporary = tempfile::NamedTempFile::new_in(directory)
        .map_err(|_| "Could not create report staging file".to_string())?;
    temporary
        .write_all(data)
        .map_err(|_| "Could not write report".to_string())?;
    temporary
        .as_file()
        .sync_all()
        .map_err(|_| "Could not synchronize report".to_string())?;
    temporary.persist_noclobber(path).map_err(|_| {
        "Report path already exists or could not be published; choose a new path".to_string()
    })?;
    Ok(())
}
pub(crate) fn reveal_output(path: &Path) {
    #[cfg(target_os = "macos")]
    let _ = Command::new("/usr/bin/open").arg("-R").arg(path).spawn();
    #[cfg(target_os = "windows")]
    let _ = Command::new("explorer.exe")
        .arg(path.parent().unwrap_or(Path::new(".")))
        .spawn();
    #[cfg(all(unix, not(target_os = "macos")))]
    let _ = Command::new("xdg-open")
        .arg(path.parent().unwrap_or(Path::new(".")))
        .spawn();
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn report_export_is_atomic_and_protects_existing_files() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("report.json");
        save_report(&path, b"{\"synthetic\":true}").unwrap();
        assert!(save_report(&path, b"different").is_err());
        assert_eq!(std::fs::read(&path).unwrap(), b"{\"synthetic\":true}");
        assert_eq!(std::fs::read_dir(directory.path()).unwrap().count(), 1);
    }
    fn render_test_frame(
        app: &mut FileVeilApp,
        context: &egui::Context,
        events: Vec<egui::Event>,
    ) -> egui::accesskit::TreeUpdate {
        let input = egui::RawInput {
            screen_rect: Some(egui::Rect::from_min_size(
                egui::Pos2::ZERO,
                egui::vec2(1060.0, 700.0),
            )),
            events,
            ..egui::RawInput::default()
        };
        let mut frame = eframe::Frame::_new_kittest();
        let mut output = context.run_ui(input, |ui| eframe::App::ui(app, ui, &mut frame));
        let update = output.platform_output.accesskit_update.take().unwrap();
        output.drop_without_applying_deltas();
        update
    }

    fn click_test_control(
        app: &mut FileVeilApp,
        context: &egui::Context,
        update: &egui::accesskit::TreeUpdate,
        label: &str,
    ) {
        let bounds = update
            .nodes
            .iter()
            .find_map(|(_, node)| {
                if node.role() == egui::Role::Button && node.label() == Some(label) {
                    node.bounds()
                } else {
                    None
                }
            })
            .unwrap_or_else(|| panic!("Missing control {label}"));
        assert!(
            bounds.x1 <= 246.0,
            "Sidebar control overflows the content bounds"
        );
        let position = egui::pos2(
            ((bounds.x0 + bounds.x1) / 2.0) as f32,
            ((bounds.y0 + bounds.y1) / 2.0) as f32,
        );
        for pressed in [true, false] {
            render_test_frame(
                app,
                context,
                vec![
                    egui::Event::PointerMoved(position),
                    egui::Event::PointerButton {
                        pos: position,
                        button: egui::PointerButton::Primary,
                        pressed,
                        modifiers: egui::Modifiers::NONE,
                    },
                ],
            );
        }
    }

    #[test]
    fn all_language_settings_render_and_bundled_fonts_cover_translations() {
        let context = egui::Context::default();
        context.enable_accesskit();
        let creation = eframe::CreationContext::_new_kittest(context.clone());
        let mut app = FileVeilApp::new(&creation, Vec::new());
        app.settings_open = true;
        for language in Language::ALL {
            app.language = language;
            let mut update = render_test_frame(&mut app, &context, Vec::new());
            for _ in 0..2 {
                update = render_test_frame(&mut app, &context, Vec::new());
            }
            assert!(
                update
                    .nodes
                    .iter()
                    .any(|(_, node)| node.label() == Some(tr(language, "Language"))
                        || node.value() == Some(tr(language, "Language"))),
                "Language settings missing for {language:?}"
            );
            assert!(
                update
                    .nodes
                    .iter()
                    .any(|(_, node)| node.label() == Some(language.native_name())
                        || node.value() == Some(language.native_name())),
                "Language selection missing for {language:?}"
            );
            for (_, node) in &update.nodes {
                if let Some(bounds) = node.bounds() {
                    assert!(
                        bounds.x0.is_finite()
                            && bounds.y0.is_finite()
                            && bounds.x1.is_finite()
                            && bounds.y1.is_finite()
                    );
                }
            }
        }
        let catalogs = [
            include_str!("../locales/short.json"),
            include_str!("../locales/long.json"),
            include_str!("../locales/findings.json"),
        ];
        let mut characters = std::collections::BTreeSet::new();
        for source in catalogs {
            let entries: std::collections::BTreeMap<String, [String; 7]> =
                serde_json::from_str(source).unwrap();
            for values in entries.values() {
                for value in values {
                    characters.extend(value.chars().filter(|c| !c.is_whitespace()));
                }
            }
        }
        characters
            .extend("日本語かなカナ한국어설정中文EspañolFrançaisDeutschPortuguêsРусский".chars());
        let output = context.run_ui(egui::RawInput::default(), |ui| {
            ui.fonts_mut(|fonts| {
                for character in &characters {
                    assert!(
                        fonts.has_glyph(&FontId::proportional(14.0), *character),
                        "Missing UI glyph {character}"
                    );
                }
            });
        });
        output.drop_without_applying_deltas();
    }

    #[test]
    fn dark_default_and_compact_theme_controls_keep_language_in_settings() {
        let context = egui::Context::default();
        context.enable_accesskit();
        let creation = eframe::CreationContext::_new_kittest(context.clone());
        let mut app = FileVeilApp::new(&creation, Vec::new());
        assert!(app.appearance == Appearance::Dark);
        assert!(context.global_style().visuals.dark_mode);
        for language in [Language::Chinese, Language::English] {
            app.language = language;
            let mut update = render_test_frame(&mut app, &context, Vec::new());
            for _ in 0..2 {
                update = render_test_frame(&mut app, &context, Vec::new());
            }
            assert!(!update.nodes.iter().any(|(_, node)| matches!(
                node.label(),
                Some("中文" | "English")
            ) || matches!(
                node.value(),
                Some("中文" | "English")
            )));
            click_test_control(&mut app, &context, &update, tr(language, "Light"));
            assert!(app.appearance == Appearance::Light);
            assert!(!context.global_style().visuals.dark_mode);
            update = render_test_frame(&mut app, &context, Vec::new());
            click_test_control(&mut app, &context, &update, tr(language, "Dark"));
            assert!(app.appearance == Appearance::Dark);
            assert!(context.global_style().visuals.dark_mode);
        }
        app.appearance = Appearance::HighContrast;
        apply_style(&context, app.appearance);
        let update = render_test_frame(&mut app, &context, Vec::new());
        click_test_control(&mut app, &context, &update, "Light");
        assert!(app.appearance == Appearance::Light);
        app.settings_open = true;
        let mut update = render_test_frame(&mut app, &context, Vec::new());
        for _ in 0..2 {
            update = render_test_frame(&mut app, &context, Vec::new());
        }
        assert!(
            update
                .nodes
                .iter()
                .any(|(_, node)| node.label() == Some("Language")
                    || node.value() == Some("Language")),
            "Settings labels {:?}",
            update
                .nodes
                .iter()
                .filter_map(|(_, node)| node.label())
                .collect::<Vec<_>>()
        );
        assert!(
            update
                .nodes
                .iter()
                .any(|(_, node)| (node.label() == Some("English")
                    || node.value() == Some("English"))
                    && node.bounds().is_some_and(|bounds| bounds.x0 > 264.0))
        );
    }

    #[test]
    fn file_queue_rows_expose_selection_and_accept_accessibility_activation() {
        let context = egui::Context::default();
        context.enable_accesskit();
        let creation = eframe::CreationContext::_new_kittest(context.clone());
        let mut app = FileVeilApp::new(&creation, Vec::new());
        for id in 1..=2 {
            app.session.items.push(crate::session::FileItem {
                id,
                path: format!("selection-{id}.png").into(),
                size: 12,
                scan: None,
                latest: None,
                output_path: None,
                output_processing: None,
                status: ItemStatus::Finished,
            });
        }
        app.session.selected = Some(1);
        let mut update = render_test_frame(&mut app, &context, Vec::new());
        for _ in 0..2 {
            update = render_test_frame(&mut app, &context, Vec::new());
        }
        let target = update
            .nodes
            .iter()
            .find_map(|(id, node)| {
                (node.role() == egui::Role::Button && node.label() == Some("selection-2.png"))
                    .then_some(*id)
            })
            .expect("File row has an accessible button");
        render_test_frame(
            &mut app,
            &context,
            vec![egui::Event::AccessKitActionRequest(
                egui::accesskit::ActionRequest {
                    action: egui::accesskit::Action::Click,
                    target_node: target,
                    target_tree: egui::accesskit::TreeId::ROOT,
                    data: None,
                },
            )],
        );
        assert_eq!(app.session.selected, Some(2));
        let update = render_test_frame(&mut app, &context, Vec::new());
        assert!(update.nodes.iter().any(|(_, node)| {
            node.label() == Some("selection-2.png")
                && node.toggled() == Some(egui::accesskit::Toggled::True)
        }));
    }

    #[test]
    fn normally_scanned_nul_text_exposes_enabled_deep_control_cleanup() {
        fn click_label(
            app: &mut FileVeilApp,
            context: &egui::Context,
            update: &egui::accesskit::TreeUpdate,
            label: &str,
        ) {
            let bounds = update
                .nodes
                .iter()
                .find_map(|(_, node)| {
                    (node.label() == Some(label) || node.value() == Some(label))
                        .then(|| node.bounds())
                        .flatten()
                })
                .unwrap_or_else(|| panic!("Missing visible control {label}"));
            let position = egui::pos2(
                ((bounds.x0 + bounds.x1) / 2.0) as f32,
                ((bounds.y0 + bounds.y1) / 2.0) as f32,
            );
            for pressed in [true, false] {
                render_test_frame(
                    app,
                    context,
                    vec![
                        egui::Event::PointerMoved(position),
                        egui::Event::PointerButton {
                            pos: position,
                            button: egui::PointerButton::Primary,
                            pressed,
                            modifiers: egui::Modifiers::NONE,
                        },
                    ],
                );
            }
        }

        let directory = tempfile::tempdir().unwrap();
        let input = directory.path().join("control.TXT");
        let source = b"Visible\0 control text";
        std::fs::write(&input, source).unwrap();
        let report = fileveil_engine::scan(&input, &fileveil_core::Limits::default()).unwrap();
        assert_eq!(report.input_format, "text/plain");
        assert_ne!(report.result, Outcome::Unsupported);
        let context = egui::Context::default();
        context.enable_accesskit();
        let creation = eframe::CreationContext::_new_kittest(context.clone());
        let mut app = FileVeilApp::new(&creation, Vec::new());
        app.language = Language::English;
        app.session.items.push(FileItem {
            id: 1,
            path: input.clone(),
            size: source.len() as u64,
            scan: Some(report.clone()),
            latest: Some(report),
            output_path: None,
            output_processing: None,
            status: ItemStatus::Finished,
        });
        app.session.selected = Some(1);
        let mut update = render_test_frame(&mut app, &context, Vec::new());
        for _ in 0..2 {
            update = render_test_frame(&mut app, &context, Vec::new());
        }
        click_label(&mut app, &context, &update, "Clean files");
        assert!(app.workspaces.selected == Workspace::Deep);
        update = render_test_frame(&mut app, &context, Vec::new());
        click_label(&mut app, &context, &update, "Office content scope");
        update = render_test_frame(&mut app, &context, Vec::new());
        click_label(&mut app, &context, &update, "Text and HTML");
        for _ in 0..4 {
            update = render_test_frame(&mut app, &context, Vec::new());
        }
        let control = update
            .nodes
            .iter()
            .find_map(|(_, node)| {
                (node.role() == egui::Role::CheckBox
                    && node.label() == Some("Abnormal controls and nonlinguistic markers"))
                .then_some(node)
            })
            .expect("Normal text scan exposes the cleanup checkbox");
        assert!(!control.is_disabled());
        assert_eq!(std::fs::read(&input).unwrap(), source);
    }

    #[test]
    fn theme_text_and_action_colors_remain_readable() {
        fn luminance(color: Color32) -> f64 {
            let channel = |value: u8| {
                let value = f64::from(value) / 255.0;
                if value <= 0.04045 {
                    value / 12.92
                } else {
                    ((value + 0.055) / 1.055).powf(2.4)
                }
            };
            0.2126 * channel(color.r()) + 0.7152 * channel(color.g()) + 0.0722 * channel(color.b())
        }
        for appearance in [
            Appearance::Light,
            Appearance::Dark,
            Appearance::HighContrast,
        ] {
            let colors = Palette::new(appearance);
            for color in [
                colors.background,
                colors.surface,
                colors.sidebar,
                colors.text,
                colors.muted,
                colors.border,
                colors.primary,
                colors.button_fill,
                colors.selected,
                colors.caution,
                colors.danger,
            ] {
                assert_eq!(color.r(), color.g(), "Theme must remain neutral gray");
                assert_eq!(color.g(), color.b(), "Theme must remain neutral gray");
                if appearance == Appearance::HighContrast {
                    assert_eq!(color.a(), 255, "High contrast must remain opaque");
                }
            }
            for desktop in [Color32::BLACK, Color32::WHITE] {
                let background = desktop.blend(colors.background);
                let surface = background.blend(colors.surface);
                let sidebar = desktop.blend(colors.sidebar);
                let selected = sidebar.blend(colors.selected);
                for (foreground, background) in [
                    (colors.text, background),
                    (colors.text, surface),
                    (colors.text, sidebar),
                    (colors.muted, background),
                    (colors.muted, surface),
                    (colors.muted, sidebar),
                    (colors.muted, selected),
                    (colors.primary, surface),
                    (colors.caution, surface),
                    (colors.danger, surface),
                    (Color32::WHITE, colors.button_fill),
                ] {
                    let first = luminance(background.blend(foreground));
                    let second = luminance(background);
                    let ratio = (first.max(second) + 0.05) / (first.min(second) + 0.05);
                    assert!(
                        ratio >= 4.5,
                        "Composited text contrast ratio fell below 4.5, got {ratio}"
                    );
                }
            }
        }
        assert_ne!(Palette::new(Appearance::Light).surface, Color32::WHITE);
    }

    #[test]
    fn labels_do_not_infer_cleanup_from_extension() {
        assert_eq!(format_label("image/png"), "PNG");
        assert_eq!(format_size(2048), "2.0 KB");
    }
    #[test]
    fn large_reports_keep_filter_results_accessible_on_bounded_pages() {
        let context = egui::Context::default();
        let mut report = Report::new("scan", fileveil_core::Format::Png);
        report.findings = (0..10_001)
            .map(|index| {
                Finding::new(
                    "png.text",
                    RiskLayer::EmbeddedMetadata,
                    &format!("chunk/{index}"),
                    "Synthetic field",
                    Action::Remove,
                )
            })
            .collect();
        let mut view = FindingView {
            page: usize::MAX,
            ..Default::default()
        };
        let start = std::time::Instant::now();
        let output = context.run_ui(
            egui::RawInput {
                screen_rect: Some(egui::Rect::from_min_size(
                    egui::Pos2::ZERO,
                    egui::vec2(900.0, 700.0),
                )),
                ..Default::default()
            },
            |ui| {
                FileVeilApp::findings(
                    ui,
                    Some(&report),
                    Palette::new(Appearance::Dark),
                    600.0,
                    Language::English,
                    &mut view,
                );
            },
        );
        output.drop_without_applying_deltas();
        assert_eq!(view.page, 100);
        view.search = "nonexistent-field".into();
        let output = context.run_ui(Default::default(), |ui| {
            FileVeilApp::findings(
                ui,
                Some(&report),
                Palette::new(Appearance::Dark),
                600.0,
                Language::English,
                &mut view,
            );
        });
        output.drop_without_applying_deltas();
        assert_eq!(view.page, 0);
        assert!(view.matching.is_empty());
        // Public report fields may change without changing the report allocation.
        report.findings[0].location = "nonexistent-field".into();
        let output = context.run_ui(Default::default(), |ui| {
            FileVeilApp::findings(
                ui,
                Some(&report),
                Palette::new(Appearance::Dark),
                600.0,
                Language::English,
                &mut view,
            );
        });
        output.drop_without_applying_deltas();
        assert_eq!(view.matching, vec![0]);
        eprintln!(
            "10001 findings, three paginated frames including searches: {:?}",
            start.elapsed()
        );
    }
}

// FVPROV1 95855 W3siYm9keSI6eyJhY3Rvcl9rZXlfaWQiOiI5OWVhNjNlZmNjZmQwZmRiZDY4ZTE2ZWQ4ZjAzZDMzN2YxNWVjMmU0YTZhM2Q2NGUxMWQ3MTRlYTFlNTQyNTMzIiwiYWxnb3JpdGhtIjoiRWQyNTUxOSIsImF1dGhvciI6IkoteC1aL0ZpbGVWZWlsIiwiY29udGVudF9zaGEyNTYiOiJiZGY1Yzk3MjZkNTc2ODQ2MTRmYWY4ZjM2OGIwMDMxY2M4YzA0OTdlOTk5MzE5MTgzMmYwZWZkNDNlOTM4MGQ1IiwiY29weV9pZCI6InYwLjYuMC1hbHBoYS4xIiwiY3JlYXRlZF9hdCI6IjIwMjYtMTEtMTQiLCJlZGl0aW9uIjoiYWxwaGEiLCJpc3N1ZXJfcG9saWN5IjpudWxsLCJraW5kIjoiY3JlYXRlIiwibW9kZSI6InNlbGZfc2lnbiIsInBhcmVudF92ZXJzaW9uIjpudWxsLCJwcmV2aW91c19yZWNvcmRfc2hhMjU2IjpudWxsLCJzY2hlbWEiOiJmaWxldmVpbC5wcm92ZW5hbmNlLnNpZ25hdHVyZS52MiIsInNlcXVlbmNlIjowLCJ0cmFuc2Zlcl90b19rZXlfaWQiOm51bGwsInZlcnNpb24iOiJ2MC42LjAtYWxwaGEuMSIsIndvcmtfaWQiOiJodHRwczovL2dpdGh1Yi5jb20vSi14LVovZmlsZXZlaWwvc291cmNlL2NyYXRlcy9maWxldmVpbC1ndWkvc3JjL2FwcC5ycyJ9LCJzaWduYXR1cmVzIjpbeyJrZXlfaWQiOiI5OWVhNjNlZmNjZmQwZmRiZDY4ZTE2ZWQ4ZjAzZDMzN2YxNWVjMmU0YTZhM2Q2NGUxMWQ3MTRlYTFlNTQyNTMzIiwicHVibGljX2tleV9oZXgiOiJhZGIzZTE3Y2QxMmY5NTZkMDA3MGUxNjYzZjUzMTUzN2ZjZWRmNzMwOGQwMTY1OGZlYTQ1NmZlZWE4ZjdmYmM1Iiwic2lnbmF0dXJlX2hleCI6ImNkMmU3NGNiMzU5ZTZlMzUxMDcwNjVjYjQwNTlhOTZhNjM3MmQ2OTNlM2Y0YzJlY2IxNzA2NjRmMTRkMmM4NjBjYjExMjMyN2QzMThiMDk0OWZlODQ0NzcyMTlmYjYwOWFiZTE2ZTExMGUwYTg4NjRiYTZhYmQ3ZDVhYjJkYTAyIn1dfV0= FVPROV1-END
