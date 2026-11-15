// SPDX-License-Identifier: MPL-2.0
//! Recipe dispatch and metadata-safe caller compatibility through the GUI session.
use eframe::egui;
use fileveil_core::{ImageProcessOptions, Limits};
use fileveil_gui::{
    jobs::{JobHandle, JobKind, JobRequest},
    session::{ActiveTask, FileItem, ItemStatus, Session, TaskKind},
};
use std::{
    path::PathBuf,
    sync::Arc,
    time::{Duration, Instant},
};

fn prepared_session() -> (tempfile::TempDir, Session, PathBuf, PathBuf) {
    let directory = tempfile::tempdir().unwrap();
    let original = directory.path().join("source.png");
    let fixture = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../tests/fixtures/png_itxt_exif_icc.png");
    std::fs::copy(fixture, &original).unwrap();
    let processed = directory.path().join("processed.png");
    let safe = directory.path().join("safe.clean.png");
    let options = ImageProcessOptions::default();
    let latest = fileveil_engine::process_image_in(
        &original,
        Some(&processed),
        &options,
        &Limits::default(),
        None,
    )
    .unwrap();
    fileveil_engine::sanitize(&original, Some(&safe), &Limits::default()).unwrap();
    let scan = fileveil_engine::scan(&original, &Limits::default()).unwrap();
    let mut session = Session::default();
    session.items.push(FileItem {
        id: 1,
        size: original.metadata().unwrap().len(),
        path: original,
        scan: Some(scan),
        latest: Some(latest),
        output_path: Some(processed.clone()),
        output_processing: Some(options),
        status: ItemStatus::Finished,
    });
    session.selected = Some(1);
    (directory, session, processed, safe)
}

fn finish_worker(session: &mut Session, kind: TaskKind, job: JobKind) {
    finish_worker_for(session, 1, kind, job);
}

fn finish_worker_for(session: &mut Session, id: u64, kind: TaskKind, job: JobKind) {
    session
        .items
        .iter_mut()
        .find(|item| item.id == id)
        .unwrap()
        .status = match kind {
        TaskKind::Scan | TaskKind::DetectWatermark => ItemStatus::Scanning,
        _ => ItemStatus::Sanitizing,
    };
    session.active = Some(ActiveTask {
        id,
        kind,
        handle: JobHandle::spawn_with_executable(
            JobRequest::new(job),
            PathBuf::from(env!("CARGO_BIN_EXE_fileveil-gui")),
            Arc::new(|| {}),
        ),
        started: Instant::now(),
    });
    let deadline = Instant::now() + Duration::from_secs(20);
    let context = egui::Context::default();
    while session.active.is_some() {
        assert!(Instant::now() < deadline, "GUI worker did not finish");
        session.poll(&context);
        std::thread::sleep(Duration::from_millis(5));
    }
}

#[test]
fn another_copy_uses_the_normal_verifier_after_research_processing() {
    let (_directory, mut session, _processed, safe) = prepared_session();
    session.queue_verify(1, safe.clone());
    assert!(matches!(&session.pending.front().unwrap().kind,
        TaskKind::Verify { output } if *output == safe));
}

#[test]
fn tracked_processing_recipe_survives_a_successful_rescan() {
    let (_directory, mut session, processed, _safe) = prepared_session();
    let original = session.items[0].path.clone();
    finish_worker(
        &mut session,
        TaskKind::Scan,
        JobKind::Scan { path: original },
    );
    assert_eq!(session.items[0].latest.as_ref().unwrap().operation, "scan");
    assert_eq!(
        session.items[0].output_processing,
        Some(ImageProcessOptions::default())
    );
    assert_eq!(session.items[0].output_path.as_ref(), Some(&processed));
    session.queue_verify(1, processed.clone());
    assert!(matches!(&session.pending.front().unwrap().kind,
        TaskKind::VerifyImage { output, options } if *output == processed && *options == ImageProcessOptions::default()));
}

#[test]
fn subsequent_metadata_safe_save_clears_the_research_recipe() {
    let (directory, mut session, _processed, _safe) = prepared_session();
    let original = session.items[0].path.clone();
    let output = directory.path().join("later.safe.png");
    finish_worker(
        &mut session,
        TaskKind::Sanitize {
            output: Some(output.clone()),
        },
        JobKind::Sanitize {
            input: original,
            output: Some(output.clone()),
        },
    );
    assert_eq!(session.items[0].output_path.as_ref(), Some(&output));
    assert!(session.items[0].output_processing.is_none());
    session.queue_verify(1, output.clone());
    assert!(matches!(&session.pending.front().unwrap().kind,
        TaskKind::Verify { output: selected } if *selected == output));
}

#[test]
fn a_new_unsupported_scan_disables_image_processing_until_rescanned() {
    let (_directory, mut session, _processed, _safe) = prepared_session();
    assert!(session.can_process_image(1));
    std::fs::write(&session.items[0].path, b"changed into an unsupported file").unwrap();
    session.items[0].latest =
        Some(fileveil_engine::scan(&session.items[0].path, &Limits::default()).unwrap());
    assert!(!session.can_sanitize(1));
    assert!(!session.can_process_image(1));
}

#[test]
fn queued_detection_runs_real_workers_and_keeps_existing_copy_recipes() {
    let (_directory, mut session, processed, _) = prepared_session();
    let mut second = session.items[0].clone();
    second.id = 2;
    second.path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../fileveil-engine/tests/fixtures/watermark/astronaut-sdxl.png");
    session.items.push(second);
    session.queue_detect_images();
    let queued: Vec<_> = session.pending.drain(..).collect();
    assert_eq!(queued.len(), 2);
    for task in queued {
        let job = JobKind::DetectWatermark {
            path: session
                .items
                .iter()
                .find(|item| item.id == task.id)
                .unwrap()
                .path
                .clone(),
        };
        finish_worker_for(&mut session, task.id, task.kind, job);
        let item = session
            .items
            .iter()
            .find(|item| item.id == task.id)
            .unwrap();
        assert_eq!(item.latest.as_ref().unwrap().operation, "detect_watermark");
        assert_eq!(item.scan.as_ref().unwrap().operation, "scan");
        assert_eq!(item.output_path.as_ref().unwrap(), &processed);
        assert!(item.output_processing.is_some());
        if task.id == 2 {
            assert!(
                item.latest.as_ref().unwrap().advanced.as_ref().unwrap()["detections"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .any(
                        |result| result["method_id"] == "stable_diffusion_xl_dwt_dct"
                            && result["status"] == "detected"
                    )
            );
        }
    }
}

// FVPROV1 6890 W3siYm9keSI6eyJhY3Rvcl9rZXlfaWQiOiI5OWVhNjNlZmNjZmQwZmRiZDY4ZTE2ZWQ4ZjAzZDMzN2YxNWVjMmU0YTZhM2Q2NGUxMWQ3MTRlYTFlNTQyNTMzIiwiYWxnb3JpdGhtIjoiRWQyNTUxOSIsImF1dGhvciI6IkoteC1aL0ZpbGVWZWlsIiwiY29udGVudF9zaGEyNTYiOiJjMTk5ZTM5MTE3NWE4MzE2YWY0MTRmZjQzZTY5OGZhNThhNzA4MTA5NWJmNGEzYTFjYTg5MTUzYmM1MzRkMWI3IiwiY29weV9pZCI6InYwLjcuMC1iZXRhLjEiLCJjcmVhdGVkX2F0IjoiMjAyNi0xMS0xNSIsImVkaXRpb24iOiJiZXRhIiwiaXNzdWVyX3BvbGljeSI6bnVsbCwia2luZCI6ImNyZWF0ZSIsIm1vZGUiOiJzZWxmX3NpZ24iLCJwYXJlbnRfdmVyc2lvbiI6bnVsbCwicHJldmlvdXNfcmVjb3JkX3NoYTI1NiI6bnVsbCwic2NoZW1hIjoiZmlsZXZlaWwucHJvdmVuYW5jZS5zaWduYXR1cmUudjIiLCJzZXF1ZW5jZSI6MCwidHJhbnNmZXJfdG9fa2V5X2lkIjpudWxsLCJ2ZXJzaW9uIjoidjAuNy4wLWJldGEuMSIsIndvcmtfaWQiOiJodHRwczovL2dpdGh1Yi5jb20vSi14LVovZmlsZXZlaWwvc291cmNlL2NyYXRlcy9maWxldmVpbC1ndWkvdGVzdHMvc2Vzc2lvbl9wcm9jZXNzaW5nLnJzIn0sInNpZ25hdHVyZXMiOlt7ImtleV9pZCI6Ijk5ZWE2M2VmY2NmZDBmZGJkNjhlMTZlZDhmMDNkMzM3ZjE1ZWMyZTRhNmEzZDY0ZTExZDcxNGVhMWU1NDI1MzMiLCJwdWJsaWNfa2V5X2hleCI6ImFkYjNlMTdjZDEyZjk1NmQwMDcwZTE2NjNmNTMxNTM3ZmNlZGY3MzA4ZDAxNjU4ZmVhNDU2ZmVlYThmN2ZiYzUiLCJzaWduYXR1cmVfaGV4IjoiNjdlYTNkN2VlYzdiODc5NzAwZTViYjBiZmU0OTBmOTI1NDhiMWI3MmVmMGRkODY5YzcwYzNjOWYyZWNiMmZjNjkwOGJkYmE5YjQ2YzdiYzkxNGM0MzgxZmE1NmNmMzA5NjQyYmVjNTJjZDBlZDUwM2I4OTBkMGZmMjNhY2Q5MDAifV19XQ== FVPROV1-END
