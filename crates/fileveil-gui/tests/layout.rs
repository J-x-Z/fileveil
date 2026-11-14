// SPDX-License-Identifier: MPL-2.0
//! Headless regressions for the native workbench's egui accessibility tree.
use accesskit_consumer::{NodeRef, Tree, TreeChangeHandler as ChangeHandler, common_filter};
use eframe::{App, egui};
use fileveil_core::{Action, Finding, FindingState, Format, Integrity, Outcome, Report, RiskLayer};
use fileveil_gui::{
    app::FileVeilApp,
    i18n::{Language, tr},
    jobs::{JobHandle, JobKind, JobRequest},
    session::{ActiveTask, FileItem, ItemStatus, TaskKind},
};
use std::{
    collections::{HashMap, HashSet},
    path::{Path, PathBuf},
    sync::Arc,
    time::{Duration, Instant},
};

const INPUT_HASH: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
const OUTPUT_HASH: &str = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";

fn report(operation: &str) -> Report {
    let mut report = Report::new(operation, Format::Png);
    report.result = Outcome::VerifiedWithinScope;
    report.input_sha256 = Some(INPUT_HASH.into());
    report.integrity.parseable = true;
    let mut metadata = Finding::new(
        "png.text",
        RiskLayer::EmbeddedMetadata,
        "PNG/text",
        "Synthetic text metadata",
        Action::Remove,
    );
    if operation != "scan" {
        metadata.state = FindingState::RemovedVerified;
        report.integrity = Integrity {
            parseable: true,
            decodeable: Some(true),
            pixel_equal: Some(true),
            content_equal: Some(true),
            original_unchanged: Some(true),
            security_markers_preserved: Some(true),
        };
        report.output_sha256 = Some(OUTPUT_HASH.into());
        report.output_name = Some("synthetic-layout.clean.png".into());
    }
    report.findings.push(metadata);
    report.findings.push(Finding::unassessed(
        "image.content_watermark",
        RiskLayer::ContentWatermark,
        "image_data",
        "Content watermark detection was not performed",
    ));
    report
}

fn frame(
    app: &mut FileVeilApp,
    context: &egui::Context,
    dimensions: egui::Vec2,
    time: f64,
) -> egui::accesskit::TreeUpdate {
    scaled_frame(app, context, dimensions, time, 1.0)
}

fn scaled_frame(
    app: &mut FileVeilApp,
    context: &egui::Context,
    dimensions: egui::Vec2,
    time: f64,
    scale: f32,
) -> egui::accesskit::TreeUpdate {
    input_frame(app, context, dimensions, time, scale, Vec::new())
}

fn input_frame(
    app: &mut FileVeilApp,
    context: &egui::Context,
    dimensions: egui::Vec2,
    time: f64,
    scale: f32,
    events: Vec<egui::Event>,
) -> egui::accesskit::TreeUpdate {
    let mut input = egui::RawInput {
        screen_rect: Some(egui::Rect::from_min_size(egui::Pos2::ZERO, dimensions)),
        events,
        time: Some(time),
        ..egui::RawInput::default()
    };
    let viewport = input.viewports.entry(egui::ViewportId::ROOT).or_default();
    viewport.native_pixels_per_point = Some(scale);
    viewport.inner_rect = input.screen_rect;
    viewport.outer_rect = input.screen_rect;
    viewport.monitor_size = Some(dimensions);
    let mut frame = eframe::Frame::_new_kittest();
    let mut output = context.run_ui(input, |ui| app.ui(ui, &mut frame));
    let update = output
        .platform_output
        .accesskit_update
        .take()
        .expect("AccessKit is enabled");
    output.drop_without_applying_deltas();
    update
}

fn tree_text(update: &egui::accesskit::TreeUpdate) -> Vec<String> {
    update
        .nodes
        .iter()
        .flat_map(|(_, node)| [node.label(), node.value()])
        .flatten()
        .map(str::to_owned)
        .collect()
}

fn root_descendants(update: &egui::accesskit::TreeUpdate) -> usize {
    let nodes: HashMap<_, _> = update.nodes.iter().map(|(id, node)| (*id, node)).collect();
    let root = update.tree.as_ref().expect("full tree update").root;
    let mut pending = vec![root];
    let mut seen = HashSet::new();
    while let Some(id) = pending.pop() {
        if seen.insert(id) {
            let node = nodes
                .get(&id)
                .expect("every referenced node is in this full update");
            pending.extend(node.children().iter().copied());
        }
    }
    seen.len().saturating_sub(1)
}

#[test]
fn scan_sanitize_scan_keeps_workbench_accessible_at_supported_sizes() {
    for dimensions in [egui::vec2(1360.0, 850.0), egui::vec2(1060.0, 700.0)] {
        let context = egui::Context::default();
        context.enable_accesskit();
        let creation = eframe::CreationContext::_new_kittest(context.clone());
        let mut app = FileVeilApp::new_with_language(&creation, Vec::new(), Language::Chinese);
        let scan = report("scan");
        app.session.items.push(FileItem {
            id: 1,
            path: "synthetic-layout.png".into(),
            size: 128,
            scan: Some(scan.clone()),
            latest: Some(scan),
            output_path: None,
            output_processing: None,
            status: ItemStatus::Finished,
        });
        app.session.selected = Some(1);
        let mut time = 0.0;
        for operation in ["scan", "sanitize", "scan"] {
            app.session.items[0].latest = Some(report(operation));
            app.session.items[0].output_path =
                (operation == "sanitize").then(|| PathBuf::from("synthetic-layout.clean.png"));
            // Check the first transition frame as well as settled geometry.
            let mut update = None;
            for pass in 0..4 {
                time += 0.1;
                let next = frame(&mut app, &context, dimensions, time);
                let text = tree_text(&next);
                assert!(
                    root_descendants(&next) > 25,
                    "{dimensions:?} {operation} transition pass {pass} tree collapsed, {text:?}"
                );
                for label in ["文件队列", "发现信息", "净化计划", "扫描所选"] {
                    assert!(
                        text.iter().any(|text| text.contains(label)),
                        "{dimensions:?} {operation} transition pass {pass} lost {label}, {text:?}"
                    );
                }
                update = Some(next);
            }
            let update = update.unwrap();
            let text = tree_text(&update);
            assert!(
                root_descendants(&update) > 25,
                "{dimensions:?} {operation} tree collapsed, {text:?}"
            );
            for label in ["文件队列", "发现信息", "净化计划", "扫描所选"] {
                assert!(
                    text.iter().any(|text| text.contains(label)),
                    "{dimensions:?} {operation} lost {label}, {text:?}"
                );
            }
            let expected_status = if operation == "scan" {
                "可净化"
            } else {
                "范围内验证通过"
            };
            assert!(
                text.iter().any(|text| text.contains(expected_status)),
                "{dimensions:?} {operation} lost its operation-specific status, {text:?}"
            );
            if operation == "sanitize" && dimensions.x > 1200.0 {
                assert!(
                    text.iter().any(|text| text.contains("验证结果")),
                    "{text:?}"
                );
                for hash in [INPUT_HASH, OUTPUT_HASH] {
                    let hash_nodes: Vec<_> = update
                        .nodes
                        .iter()
                        .filter(|(_, node)| {
                            node.label().is_some_and(|label| label.contains(hash))
                                || node.value().is_some_and(|value| value.contains(hash))
                        })
                        .collect();
                    assert!(
                        !hash_nodes.is_empty(),
                        "Hash is missing from accessibility tree, {text:?}"
                    );
                    assert!(
                        hash_nodes.iter().any(|(_, node)| node
                            .bounds()
                            .is_some_and(|bounds| bounds.width() >= 280.0)),
                        "Hash layout is too narrow to be readable, {hash_nodes:?}"
                    );
                }
                assert!(
                    text.iter().any(|text| text.contains("打开输出文件夹")),
                    "{text:?}"
                );
            }
        }
    }
}

#[test]
fn localized_workbench_keeps_controls_and_verification_at_minimum_size() {
    let dimensions = egui::vec2(1060.0, 700.0);
    for language in Language::ALL
        .into_iter()
        .filter(|language| *language != Language::Chinese)
    {
        let context = egui::Context::default();
        context.enable_accesskit();
        let creation = eframe::CreationContext::_new_kittest(context.clone());
        let mut app = FileVeilApp::new_with_language(&creation, Vec::new(), language);
        let scan = report("scan");
        app.session.items.push(FileItem {
            id: 1,
            path: "synthetic-layout.png".into(),
            size: 128,
            scan: Some(scan.clone()),
            latest: Some(scan),
            output_path: None,
            output_processing: None,
            status: ItemStatus::Finished,
        });
        app.session.selected = Some(1);
        let mut time = 0.0;
        for operation in ["scan", "sanitize", "scan"] {
            app.session.items[0].latest = Some(report(operation));
            app.session.items[0].output_path =
                (operation == "sanitize").then(|| PathBuf::from("synthetic-layout.clean.png"));
            for pass in 0..4 {
                time += 0.1;
                let update = frame(&mut app, &context, dimensions, time);
                let text = tree_text(&update);
                assert!(
                    root_descendants(&update) > 25,
                    "{language:?} {operation} transition {pass} collapsed, {text:?}"
                );
                for key in ["File queue", "Findings", "Cleaning plan", "Scan selected"] {
                    let expected = tr(language, key);
                    assert!(
                        text.iter().any(|text| text.contains(expected)),
                        "{language:?} {operation} transition {pass} lost {expected}, {text:?}"
                    );
                }
                let status = tr(
                    language,
                    if operation == "scan" {
                        "Ready to clean"
                    } else {
                        "Verified within scope"
                    },
                );
                assert!(
                    text.iter().any(|text| text.contains(status)),
                    "{language:?} {operation} transition {pass} lost status {status}, {text:?}"
                );
                for (_, node) in &update.nodes {
                    if let Some(bounds) = node.bounds() {
                        assert!(
                            bounds.x0.is_finite()
                                && bounds.x1.is_finite()
                                && bounds.y0.is_finite()
                                && bounds.y1.is_finite()
                        );
                    }
                }
            }
        }
    }
}

fn begin_real_sanitization(app: &mut FileVeilApp, id: u64, output: PathBuf) {
    let item = app
        .session
        .items
        .iter_mut()
        .find(|item| item.id == id)
        .unwrap();
    item.status = ItemStatus::Sanitizing;
    let handle = JobHandle::spawn_with_executable(
        JobRequest::new(JobKind::Sanitize {
            input: item.path.clone(),
            output: Some(output.clone()),
        }),
        PathBuf::from(env!("CARGO_BIN_EXE_fileveil-gui")),
        Arc::new(|| {}),
    );
    app.session.active = Some(ActiveTask {
        id,
        kind: TaskKind::Sanitize {
            output: Some(output),
        },
        handle,
        started: Instant::now(),
    });
}

fn finish_real_sanitization(app: &mut FileVeilApp) {
    let deadline = Instant::now() + Duration::from_secs(20);
    let result = loop {
        let active = app.session.active.as_ref().unwrap();
        if let Some(result) = active.handle.try_recv() {
            break result;
        }
        assert!(Instant::now() < deadline, "Worker did not finish");
        std::thread::sleep(Duration::from_millis(5));
    };
    assert!(
        matches!(
            result.report.result,
            Outcome::VerifiedWithinScope | Outcome::PartiallyVerified
        ),
        "{:?}",
        result.report
    );
    let active = app.session.active.take().unwrap();
    let item = app
        .session
        .items
        .iter_mut()
        .find(|item| item.id == active.id)
        .unwrap();
    item.status = ItemStatus::Finished;
    item.latest = Some(result.report);
    item.output_path = result.output_path;
    // Joining here keeps worker completion timing under this headless render test's control.
    drop(active);
}

struct IgnoreChanges;
impl ChangeHandler for IgnoreChanges {
    fn node_added(&mut self, _node: &NodeRef) {}
    fn node_updated(&mut self, _old_node: &NodeRef, _new_node: &NodeRef) {}
    fn focus_moved(&mut self, _old_node: Option<&NodeRef>, _new_node: Option<&NodeRef>) {}
    fn node_removed(&mut self, _node: &NodeRef) {}
}

fn assert_real_frame(
    update: &egui::accesskit::TreeUpdate,
    label: &str,
    consumer: &mut Option<Tree>,
) {
    if let Some(tree) = consumer {
        tree.update_and_process_changes(update.clone(), &mut IgnoreChanges);
    } else {
        *consumer = Some(Tree::new(update.clone(), true));
    }
    let tree = consumer.as_ref().unwrap();
    let mut pending = vec![tree.state().root()];
    let mut filtered_text = Vec::new();
    while let Some(node) = pending.pop() {
        filtered_text.extend([node.label(), node.value()].into_iter().flatten());
        pending.extend(node.filtered_children(&common_filter));
    }
    let text = tree_text(update);
    for expected in ["文件队列", "发现信息", "净化计划", "扫描所选"] {
        if !filtered_text.iter().any(|text| text.contains(expected)) {
            let diagnostics: Vec<_> = update
                .nodes
                .iter()
                .filter_map(|(id, _)| {
                    let node = tree
                        .state()
                        .node_by_tree_local_id(*id, egui::accesskit::TreeId::ROOT)?;
                    let is_scope = matches!(
                        node.role(),
                        egui::accesskit::Role::ScrollView | egui::accesskit::Role::Pane
                    );
                    let is_label = node.label().is_some_and(|text| text.contains(expected));
                    (is_scope || is_label).then(|| {
                        format!(
                            "{:?} {:?} filter={:?} bounds={:?} clips={} parent={:?}",
                            node.role(),
                            node.label(),
                            common_filter(&node),
                            node.bounding_box(),
                            node.clips_children(),
                            node.parent().map(|parent| (
                                parent.role(),
                                parent.label(),
                                parent.bounding_box(),
                                parent.clips_children()
                            ))
                        )
                    })
                })
                .collect();
            panic!(
                "{label} platform-filtered tree lost {expected}, filtered={filtered_text:?}, scopes={diagnostics:#?}"
            );
        }
    }
    assert!(
        root_descendants(update) > 60,
        "{label} tree collapsed, {text:?}"
    );
    for expected in ["文件队列", "发现信息", "净化计划", "扫描所选"] {
        assert!(
            text.iter().any(|text| text.contains(expected)),
            "{label} lost {expected}, {text:?}"
        );
    }
    for (_, node) in &update.nodes {
        if let Some(bounds) = node.bounds() {
            assert!(
                bounds.x0.is_finite()
                    && bounds.x1.is_finite()
                    && bounds.y0.is_finite()
                    && bounds.y1.is_finite(),
                "{label} has non-finite bounds"
            );
        }
    }
}

#[test]
fn real_png_report_stays_accessible_through_batch_footer_changes_on_retina() {
    let fixtures = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../tests/fixtures");
    for dimensions in [egui::vec2(1360.0, 850.0), egui::vec2(1060.0, 700.0)] {
        let directory = tempfile::tempdir().unwrap();
        let context = egui::Context::default();
        context.enable_accesskit();
        let creation = eframe::CreationContext::_new_kittest(context.clone());
        let mut app = FileVeilApp::new_with_language(&creation, Vec::new(), Language::Chinese);
        for (index, name) in [
            "jpeg_exif_gps_author.jpg",
            "png_itxt_exif_icc.png",
            "docx_author_comments_rels.docx",
            "xlsx_author_custom_formula.xlsx",
            "pptx_author_media.pptx",
            "unicode_invisible.txt",
            "pdf_corrupt.pdf",
        ]
        .iter()
        .enumerate()
        {
            let path = fixtures.join(name);
            let scan = match fileveil_engine::scan(&path, &fileveil_core::Limits::default()) {
                Ok(report) => report,
                Err(fileveil_core::Error::Blocked(message)) if *name == "pdf_corrupt.pdf" => {
                    let mut report = Report::new("scan", fileveil_core::Format::Unknown);
                    report.result = Outcome::Blocked;
                    report.warnings.push(message);
                    report
                }
                Err(error) => panic!("Unexpected scan failure for {name}: {error}"),
            };
            app.session.items.push(FileItem {
                id: index as u64 + 1,
                size: path.metadata().unwrap().len(),
                path,
                scan: Some(scan.clone()),
                latest: Some(scan),
                output_path: None,
                output_processing: None,
                status: ItemStatus::Finished,
            });
        }
        app.session.selected = Some(2);
        assert!(app.session.items[1].scan.as_ref().unwrap().findings.len() >= 10);
        let mut time = 0.0;
        let mut consumer = None;
        let mut scan_update = None;
        for pass in 0..4 {
            time += 0.1;
            let update = scaled_frame(&mut app, &context, dimensions, time, 2.0);
            assert_real_frame(
                &update,
                &format!("{dimensions:?} scan {pass}"),
                &mut consumer,
            );
            scan_update = Some(update);
        }
        let bounds = scan_update
            .as_ref()
            .unwrap()
            .nodes
            .iter()
            .find_map(|(_, node)| {
                if node.role() == egui::accesskit::Role::Button
                    && node.label() == Some("保存全部副本")
                {
                    node.bounds()
                } else {
                    None
                }
            })
            .expect("Save all copies button has an accessible bound");
        let position = egui::pos2(
            ((bounds.x0 + bounds.x1) / 2.0) as f32,
            ((bounds.y0 + bounds.y1) / 2.0) as f32,
        );
        for pressed in [true, false] {
            time += 0.1;
            let update = input_frame(
                &mut app,
                &context,
                dimensions,
                time,
                2.0,
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
            assert_real_frame(
                &update,
                &format!("{dimensions:?} save-all click {pressed}"),
                &mut consumer,
            );
        }
        assert_eq!(app.session.pending.len(), 5);
        app.session.pending.pop_front();
        begin_real_sanitization(
            &mut app,
            1,
            directory.path().join("synthetic-batch.clean.jpg"),
        );
        for pass in 0..4 {
            time += 0.1;
            assert_real_frame(
                &scaled_frame(&mut app, &context, dimensions, time, 2.0),
                &format!("{dimensions:?} JPEG active {pass}"),
                &mut consumer,
            );
        }
        finish_real_sanitization(&mut app);
        app.session.pending.pop_front();
        begin_real_sanitization(
            &mut app,
            2,
            directory.path().join("synthetic-batch.clean.png"),
        );
        for pass in 0..4 {
            time += 0.1;
            assert_real_frame(
                &scaled_frame(&mut app, &context, dimensions, time, 2.0),
                &format!("{dimensions:?} PNG active {pass}"),
                &mut consumer,
            );
        }
        finish_real_sanitization(&mut app);
        app.session.pending.pop_front();
        begin_real_sanitization(
            &mut app,
            3,
            directory.path().join("synthetic-batch.clean.docx"),
        );
        for pass in 0..4 {
            time += 0.1;
            assert_real_frame(
                &scaled_frame(&mut app, &context, dimensions, time, 2.0),
                &format!("{dimensions:?} selected PNG done and batch active {pass}"),
                &mut consumer,
            );
        }
        finish_real_sanitization(&mut app);
        app.session.pending.clear();
        for item in &mut app.session.items {
            item.status = ItemStatus::Finished;
        }
        for pass in 0..4 {
            time += 0.1;
            let update = scaled_frame(&mut app, &context, dimensions, time, 2.0);
            assert_real_frame(
                &update,
                &format!("{dimensions:?} batch idle {pass}"),
                &mut consumer,
            );
            let text = tree_text(&update);
            assert!(
                text.iter().any(|text| text.contains("范围内验证通过")),
                "{text:?}"
            );
            if dimensions.x > 1200.0 {
                assert!(
                    text.iter().any(|text| text.contains("打开输出文件夹")),
                    "{text:?}"
                );
            }
        }
    }
}

// FVPROV1 22868 W3siYm9keSI6eyJhY3Rvcl9rZXlfaWQiOiI5OWVhNjNlZmNjZmQwZmRiZDY4ZTE2ZWQ4ZjAzZDMzN2YxNWVjMmU0YTZhM2Q2NGUxMWQ3MTRlYTFlNTQyNTMzIiwiYWxnb3JpdGhtIjoiRWQyNTUxOSIsImF1dGhvciI6IkoteC1aL0ZpbGVWZWlsIiwiY29udGVudF9zaGEyNTYiOiIzMDM3Y2I4Njg3MDk3YmMzZDc1NTg1MjQzZDU3MGE5ZmNkYjhhOTU4NDcxYzE5ZDBhY2E5ZjAzYzQyM2E1YWI1IiwiY29weV9pZCI6InYwLjUuMC1hbHBoYS40IiwiY3JlYXRlZF9hdCI6IjIwMjYtMTEtMTQiLCJlZGl0aW9uIjoiYWxwaGEiLCJpc3N1ZXJfcG9saWN5IjpudWxsLCJraW5kIjoiY3JlYXRlIiwibW9kZSI6InNlbGZfc2lnbiIsInBhcmVudF92ZXJzaW9uIjpudWxsLCJwcmV2aW91c19yZWNvcmRfc2hhMjU2IjpudWxsLCJzY2hlbWEiOiJmaWxldmVpbC5wcm92ZW5hbmNlLnNpZ25hdHVyZS52MiIsInNlcXVlbmNlIjowLCJ0cmFuc2Zlcl90b19rZXlfaWQiOm51bGwsInZlcnNpb24iOiJ2MC41LjAtYWxwaGEuNCIsIndvcmtfaWQiOiJodHRwczovL2dpdGh1Yi5jb20vSi14LVovZmlsZXZlaWwvc291cmNlL2NyYXRlcy9maWxldmVpbC1ndWkvdGVzdHMvbGF5b3V0LnJzIn0sInNpZ25hdHVyZXMiOlt7ImtleV9pZCI6Ijk5ZWE2M2VmY2NmZDBmZGJkNjhlMTZlZDhmMDNkMzM3ZjE1ZWMyZTRhNmEzZDY0ZTExZDcxNGVhMWU1NDI1MzMiLCJwdWJsaWNfa2V5X2hleCI6ImFkYjNlMTdjZDEyZjk1NmQwMDcwZTE2NjNmNTMxNTM3ZmNlZGY3MzA4ZDAxNjU4ZmVhNDU2ZmVlYThmN2ZiYzUiLCJzaWduYXR1cmVfaGV4IjoiODQ3NmZlZmI0ZDBmN2RlMTMyMzM5ZThjMjBlNTU0NmYwZmFkZjdiNWE5NDExNDI2ODRkMzRlYWJlYjcwMjUzM2Q2NTI5ZmJiMWE1OGMzMjg3ZmI5NmE1NTQwNTdjYjNkYzI3ZDljOWM3NWM3ZjE0MGE4MWE2NzM0YjU5ZTc5MDUifV19XQ== FVPROV1-END
