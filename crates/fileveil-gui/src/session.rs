// SPDX-License-Identifier: MPL-2.0
//! Ephemeral file queue. The engine owns all format and sanitization decisions.
use crate::jobs::{JobHandle, JobKind, JobRequest, JobResult};
use eframe::egui;
use fileveil_core::{Action, Format, ImageProcessOptions, Limits, Outcome, Report};
use std::{
    collections::{HashSet, VecDeque},
    ffi::OsString,
    fs,
    path::{Path, PathBuf},
    sync::Arc,
    time::{Duration, Instant},
};

const MAX_FILES: usize = 2_000;
const MAX_RETAINED_FINDINGS: usize = 100_000;
const MAX_IMPORT_ENTRIES: usize = 10_000;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum ItemStatus {
    #[default]
    Ready,
    Queued,
    Scanning,
    Sanitizing,
    Verifying,
    Cancelled,
    Finished,
}

#[derive(Debug, Clone)]
pub struct FileItem {
    pub id: u64,
    pub path: PathBuf,
    pub size: u64,
    pub scan: Option<Report>,
    pub latest: Option<Report>,
    pub output_path: Option<PathBuf>,
    pub output_processing: Option<ImageProcessOptions>,
    pub status: ItemStatus,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TaskKind {
    Scan,
    Sanitize {
        output: Option<PathBuf>,
    },
    ProcessImage {
        output: PathBuf,
        options: ImageProcessOptions,
    },
    Verify {
        output: PathBuf,
    },
    VerifyImage {
        output: PathBuf,
        options: ImageProcessOptions,
    },
}

#[derive(Debug, Clone)]
pub struct PendingTask {
    pub id: u64,
    pub kind: TaskKind,
}

#[derive(Debug)]
pub struct ActiveTask {
    pub id: u64,
    pub kind: TaskKind,
    pub handle: JobHandle,
    pub started: Instant,
}

#[derive(Debug)]
pub struct Session {
    pub items: Vec<FileItem>,
    pub selected: Option<u64>,
    pub pending: VecDeque<PendingTask>,
    pub active: Option<ActiveTask>,
    pub notice: Option<String>,
    pub output_directory: Option<PathBuf>,
    pub include_subfolders: bool,
    pub limits: Limits,
    pub timeout_seconds: u64,
    next_id: u64,
}

impl Default for Session {
    fn default() -> Self {
        Self {
            items: Vec::new(),
            selected: None,
            pending: VecDeque::new(),
            active: None,
            notice: None,
            output_directory: None,
            include_subfolders: false,
            limits: Limits::default(),
            timeout_seconds: 120,
            next_id: 1,
        }
    }
}

impl Session {
    /// Import only explicitly selected files or directories. Symlinks are skipped.
    pub fn add_paths(&mut self, paths: Vec<PathBuf>) {
        if paths.is_empty() {
            return;
        }
        let mut paths: VecDeque<_> = paths.into();
        let mut known: HashSet<_> = self.items.iter().map(|item| item.path.clone()).collect();
        let mut added = Vec::new();
        let mut visited = 0;
        let mut skipped = false;
        let mut limited = false;
        while let Some(path) = paths.pop_front() {
            if self.items.len() >= MAX_FILES || visited >= MAX_IMPORT_ENTRIES {
                limited = true;
                break;
            }
            visited += 1;
            let Ok(metadata) = fs::symlink_metadata(&path) else {
                skipped = true;
                continue;
            };
            if metadata.is_symlink() {
                skipped = true;
                continue;
            }
            if metadata.is_dir() {
                let Ok(entries) = fs::read_dir(&path) else {
                    skipped = true;
                    continue;
                };
                for entry in entries {
                    if visited + paths.len() >= MAX_IMPORT_ENTRIES {
                        limited = true;
                        break;
                    }
                    visited += 1;
                    match entry {
                        Ok(entry) => {
                            let Ok(kind) = entry.file_type() else {
                                skipped = true;
                                continue;
                            };
                            if kind.is_file() || (self.include_subfolders && kind.is_dir()) {
                                paths.push_back(entry.path());
                            } else if kind.is_symlink() {
                                skipped = true;
                            }
                        }
                        Err(_) => skipped = true,
                    }
                }
                continue;
            }
            if !metadata.is_file() {
                skipped = true;
                continue;
            }
            let Ok(canonical) = path.canonicalize() else {
                skipped = true;
                continue;
            };
            if !known.insert(canonical.clone()) {
                continue;
            }
            let id = self.next_id;
            self.next_id += 1;
            self.items.push(FileItem {
                id,
                path: canonical,
                size: metadata.len(),
                scan: None,
                latest: None,
                output_path: None,
                output_processing: None,
                status: ItemStatus::Ready,
            });
            added.push(id);
        }
        if self.selected.is_none() {
            self.selected = self.items.first().map(|item| item.id);
        }
        for id in &added {
            self.queue_scan(*id);
        }
        self.notice = if limited {
            Some(
                "Import limit reached. The queue supports 2000 files and 10000 inspected entries"
                    .into(),
            )
        } else if skipped {
            Some("Some symbolic links, unreadable paths or special files were skipped".into())
        } else if added.is_empty() {
            Some("No new regular files were added".into())
        } else {
            None
        };
    }

    pub fn selected_item(&self) -> Option<&FileItem> {
        let selected = self.selected?;
        self.items.iter().find(|item| item.id == selected)
    }

    pub fn busy(&self, id: u64) -> bool {
        self.active.as_ref().is_some_and(|task| task.id == id)
            || self.pending.iter().any(|task| task.id == id)
    }

    fn enqueue(&mut self, id: u64, kind: TaskKind) {
        if self.busy(id) {
            return;
        }
        if let Some(item) = self.items.iter_mut().find(|item| item.id == id) {
            item.status = ItemStatus::Queued;
            self.pending.push_back(PendingTask { id, kind });
        }
    }

    pub fn queue_scan(&mut self, id: u64) {
        self.enqueue(id, TaskKind::Scan);
    }

    pub fn queue_scan_all(&mut self) {
        let ids: Vec<_> = self.items.iter().map(|item| item.id).collect();
        for id in ids {
            self.queue_scan(id);
        }
    }

    fn eligible_scan(&self, id: u64) -> Option<&Report> {
        if self.busy(id) {
            return None;
        }
        let item = self.items.iter().find(|item| item.id == id)?;
        if item
            .latest
            .as_ref()
            .is_some_and(|report| report.operation == "scan" && !successful_report(report))
        {
            return None;
        }
        item.scan
            .as_ref()
            .filter(|report| successful_report(report) && report.integrity.parseable)
    }

    pub fn can_sanitize(&self, id: u64) -> bool {
        self.eligible_scan(id).is_some_and(|report| {
            report
                .findings
                .iter()
                .any(|finding| matches!(finding.action, Action::Remove | Action::Normalize))
        })
    }

    pub fn queue_sanitize(&mut self, id: u64, output: Option<PathBuf>) {
        if self.can_sanitize(id) {
            self.enqueue(id, TaskKind::Sanitize { output });
        }
    }

    pub fn queue_sanitize_all(&mut self) {
        let ids: Vec<_> = self.items.iter().map(|item| item.id).collect();
        for id in ids {
            self.queue_sanitize(id, None);
        }
    }

    pub fn queue_verify(&mut self, id: u64, output: PathBuf) {
        let processing = self
            .items
            .iter()
            .find(|item| item.id == id)
            .filter(|item| item.output_path.as_ref() == Some(&output))
            .and_then(|item| item.output_processing.clone());
        let kind = match processing {
            Some(processing) => TaskKind::VerifyImage {
                output,
                options: processing,
            },
            None => TaskKind::Verify { output },
        };
        self.enqueue(id, kind);
    }

    pub fn can_process_image(&self, id: u64) -> bool {
        self.eligible_scan(id).is_some_and(|report| {
            matches!(report.input_format.as_str(), "image/png" | "image/jpeg")
        })
    }

    pub fn queue_image_process(&mut self, id: u64, output: PathBuf, options: ImageProcessOptions) {
        if self.can_process_image(id) {
            self.enqueue(id, TaskKind::ProcessImage { output, options });
        }
    }

    pub fn start_next(&mut self, context: &egui::Context) {
        if self.active.is_some() {
            return;
        }
        let retained_findings: usize = self
            .items
            .iter()
            .map(|item| {
                item.scan.as_ref().map_or(0, |report| report.findings.len())
                    + item
                        .latest
                        .as_ref()
                        .map_or(0, |report| report.findings.len())
            })
            .sum();
        if !self.pending.is_empty() && retained_findings >= MAX_RETAINED_FINDINGS {
            self.cancel_all();
            self.notice = Some("Report memory budget reached. Export reports and clear completed items to continue".into());
            return;
        }
        while let Some(task) = self.pending.pop_front() {
            let Some(item) = self.items.iter_mut().find(|item| item.id == task.id) else {
                continue;
            };
            let mut kind = task.kind;
            let operation = match &mut kind {
                TaskKind::Scan => {
                    item.status = ItemStatus::Scanning;
                    JobKind::Scan {
                        path: item.path.clone(),
                    }
                }
                TaskKind::Sanitize { output } => {
                    if output.is_none()
                        && let Some(directory) = &self.output_directory
                    {
                        match available_output(&item.path, directory) {
                            Ok(path) => *output = Some(path),
                            Err(message) => {
                                let mut report = Report::new("sanitize", Format::Unknown);
                                report.result = Outcome::Failed;
                                report.warnings.push(message.clone());
                                item.latest = Some(report);
                                item.status = ItemStatus::Finished;
                                self.notice = Some(message);
                                context.request_repaint();
                                continue;
                            }
                        }
                    }
                    item.status = ItemStatus::Sanitizing;
                    JobKind::Sanitize {
                        input: item.path.clone(),
                        output: output.clone(),
                    }
                }
                TaskKind::Verify { output } => {
                    item.status = ItemStatus::Verifying;
                    JobKind::Verify {
                        original: item.path.clone(),
                        output: output.clone(),
                    }
                }
                TaskKind::ProcessImage { output, options } => {
                    item.status = ItemStatus::Sanitizing;
                    JobKind::ProcessImage {
                        input: item.path.clone(),
                        output: Some(output.clone()),
                        options: options.clone(),
                    }
                }
                TaskKind::VerifyImage { output, options } => {
                    item.status = ItemStatus::Verifying;
                    JobKind::VerifyImage {
                        original: item.path.clone(),
                        output: output.clone(),
                        options: options.clone(),
                    }
                }
            };
            let repaint_context = context.clone();
            let handle = JobHandle::spawn(
                JobRequest {
                    kind: operation,
                    limits: self.limits.clone(),
                    timeout_seconds: self.timeout_seconds,
                },
                Arc::new(move || repaint_context.request_repaint()),
            );
            self.active = Some(ActiveTask {
                id: task.id,
                kind,
                handle,
                started: Instant::now(),
            });
            context.request_repaint();
            break;
        }
    }

    pub fn poll(&mut self, context: &egui::Context) {
        let completed = self.active.as_ref().and_then(|task| task.handle.try_recv());
        if let Some(result) = completed {
            if let Some(task) = self.active.take() {
                self.complete(task.id, &task.kind, result);
            }
            context.request_repaint();
        }
        self.start_next(context);
        if self.active.is_some() {
            context.request_repaint_after(Duration::from_millis(100));
        }
    }

    fn complete(&mut self, id: u64, kind: &TaskKind, result: JobResult) {
        let Some(item) = self.items.iter_mut().find(|item| item.id == id) else {
            return;
        };
        item.status = if result.exit_code == 6 && item.status == ItemStatus::Cancelled {
            ItemStatus::Cancelled
        } else {
            ItemStatus::Finished
        };
        match kind {
            TaskKind::Scan if successful_report(&result.report) => {
                item.scan = Some(result.report.clone());
                if let Ok(metadata) = fs::metadata(&item.path) {
                    item.size = metadata.len();
                }
            }
            TaskKind::Sanitize { .. } | TaskKind::ProcessImage { .. }
                if successful_report(&result.report) =>
            {
                if let Some(path) = result.output_path {
                    item.output_path = Some(path);
                    item.output_processing =
                        result.report.image_processing.as_ref().map(|processing| {
                            ImageProcessOptions {
                                mode: processing.mode,
                                low_bits: processing.low_bits.unwrap_or(2),
                            }
                        });
                }
            }
            TaskKind::Verify { output } | TaskKind::VerifyImage { output, .. }
                if result.report.output_sha256.is_some() =>
            {
                item.output_path = Some(output.clone());
                item.output_processing =
                    result
                        .report
                        .image_processing
                        .as_ref()
                        .map(|processing| ImageProcessOptions {
                            mode: processing.mode,
                            low_bits: processing.low_bits.unwrap_or(2),
                        });
            }
            _ => {}
        }
        item.latest = Some(result.report);
    }

    pub fn cancel_all(&mut self) {
        for task in self.pending.drain(..) {
            if let Some(item) = self.items.iter_mut().find(|item| item.id == task.id) {
                item.status = if item.latest.is_some() {
                    ItemStatus::Finished
                } else {
                    ItemStatus::Ready
                };
            }
        }
        if let Some(task) = &self.active
            && task.handle.cancel()
            && let Some(item) = self.items.iter_mut().find(|item| item.id == task.id)
        {
            item.status = ItemStatus::Cancelled;
        }
    }

    pub fn remove(&mut self, id: u64) -> bool {
        if self.busy(id) {
            return false;
        }
        let Some(index) = self.items.iter().position(|item| item.id == id) else {
            return false;
        };
        self.items.remove(index);
        if self.selected == Some(id) {
            self.selected = self
                .items
                .get(index)
                .or_else(|| self.items.last())
                .map(|item| item.id);
        }
        true
    }

    pub fn clear_completed(&mut self) {
        let busy: HashSet<_> = self
            .pending
            .iter()
            .map(|task| task.id)
            .chain(self.active.iter().map(|task| task.id))
            .collect();
        self.items
            .retain(|item| item.status != ItemStatus::Finished || busy.contains(&item.id));
        if self
            .selected
            .is_some_and(|selected| !self.items.iter().any(|item| item.id == selected))
        {
            self.selected = self.items.first().map(|item| item.id);
        }
    }

    pub fn clear_all(&mut self) {
        self.cancel_all();
        drop(self.active.take());
        self.items.clear();
        self.selected = None;
        self.notice = None;
    }
}

fn successful_report(report: &Report) -> bool {
    matches!(
        report.result,
        Outcome::VerifiedWithinScope | Outcome::PartiallyVerified
    )
}

fn available_output(input: &Path, directory: &Path) -> Result<PathBuf, String> {
    for counter in 0..=10_000 {
        let mut name = input
            .file_stem()
            .unwrap_or(input.as_os_str())
            .to_os_string();
        name.push(if counter == 0 {
            OsString::from(".clean")
        } else {
            OsString::from(format!(".clean.{counter}"))
        });
        if let Some(extension) = input.extension() {
            name.push(".");
            name.push(extension);
        }
        let path = directory.join(name);
        match fs::symlink_metadata(&path) {
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(path),
            Ok(_) => {}
            Err(_) => return Err("The output folder could not be inspected".into()),
        }
    }
    Err("No available output name was found in the selected folder".into())
}

#[cfg(test)]
mod tests {
    use super::*;
    use fileveil_core::{Finding, Format, RiskLayer};

    fn report(operation: &str) -> Report {
        let mut report = Report::new(operation, Format::Png);
        report.result = Outcome::VerifiedWithinScope;
        report.integrity.parseable = true;
        report.findings.push(Finding::new(
            "png.text",
            RiskLayer::EmbeddedMetadata,
            "PNG/text",
            "Synthetic text metadata",
            Action::Remove,
        ));
        report
    }

    #[test]
    fn empty_startup_has_no_import_notice() {
        let mut session = Session::default();
        session.add_paths(Vec::new());
        assert!(session.notice.is_none());
        assert!(session.pending.is_empty());
    }

    #[test]
    fn import_deduplicates_canonical_paths_and_automatically_queues_scans() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("合成 file.png");
        fs::write(&path, b"synthetic").unwrap();
        let mut session = Session::default();
        session.add_paths(vec![path.clone(), path.clone()]);
        assert_eq!(session.items.len(), 1);
        assert_eq!(session.pending.len(), 1);
        assert_eq!(session.selected, Some(session.items[0].id));
        assert_eq!(session.items[0].status, ItemStatus::Queued);
        assert!(!session.remove(session.items[0].id));
        session.cancel_all();
        assert!(session.pending.is_empty());
        assert!(session.remove(session.items[0].id));
        session.add_paths(vec![path]);
        assert_eq!(session.items[0].id, 2);
    }

    #[test]
    fn folder_recursion_requires_the_session_setting() {
        let directory = tempfile::tempdir().unwrap();
        fs::create_dir(directory.path().join("nested")).unwrap();
        fs::write(directory.path().join("direct.png"), b"synthetic").unwrap();
        fs::write(directory.path().join("nested/inner.png"), b"synthetic").unwrap();
        let mut session = Session::default();
        session.add_paths(vec![directory.path().to_path_buf()]);
        assert_eq!(session.items.len(), 1);
        session.include_subfolders = true;
        session.add_paths(vec![directory.path().to_path_buf()]);
        assert_eq!(session.items.len(), 2);
    }

    #[test]
    fn eligibility_comes_from_successful_core_reports_and_supported_actions() {
        let mut session = Session::default();
        session.items.push(FileItem {
            id: 1,
            path: "synthetic.png".into(),
            size: 1,
            scan: Some(report("scan")),
            latest: None,
            output_path: None,
            output_processing: None,
            status: ItemStatus::Finished,
        });
        assert!(session.can_sanitize(1));
        session.queue_scan(1);
        assert!(!session.can_sanitize(1));
        session.cancel_all();
        assert!(session.can_sanitize(1));
        session.items[0].scan.as_mut().unwrap().findings[0].action = Action::Preserve;
        assert!(!session.can_sanitize(1));
        session.items[0].scan.as_mut().unwrap().findings[0].action = Action::Remove;
        let mut failed = report("scan");
        failed.result = Outcome::Blocked;
        session.items[0].latest = Some(failed);
        assert!(!session.can_sanitize(1));
    }

    #[test]
    fn output_names_never_reuse_an_existing_file() {
        let directory = tempfile::tempdir().unwrap();
        let first = available_output(Path::new("合成 example.png"), directory.path()).unwrap();
        fs::write(&first, b"existing content").unwrap();
        let next = available_output(Path::new("合成 example.png"), directory.path()).unwrap();
        assert_ne!(first, next);
        assert_eq!(next.file_name().unwrap(), "合成 example.clean.1.png");
        assert_eq!(fs::read(first).unwrap(), b"existing content");
    }

    #[test]
    fn failed_rescan_preserves_prior_evidence_and_successful_output() {
        let mut session = Session::default();
        session.items.push(FileItem {
            id: 1,
            path: "synthetic.png".into(),
            size: 1,
            scan: Some(report("scan")),
            latest: None,
            output_path: Some("earlier.clean.png".into()),
            output_processing: None,
            status: ItemStatus::Scanning,
        });
        let mut failed = report("scan");
        failed.result = Outcome::Failed;
        session.complete(
            1,
            &TaskKind::Scan,
            JobResult {
                report: failed,
                exit_code: 2,
                output_path: None,
            },
        );
        assert!(session.items[0].scan.is_some());
        assert_eq!(
            session.items[0].latest.as_ref().unwrap().result,
            Outcome::Failed
        );
        assert_eq!(
            session.items[0].output_path.as_deref(),
            Some(Path::new("earlier.clean.png"))
        );
        assert!(!session.can_sanitize(1));
    }

    #[test]
    fn clearing_completed_preserves_pending_and_cancelled_items() {
        let mut session = Session::default();
        for id in 1..=3 {
            session.items.push(FileItem {
                id,
                path: format!("{id}.png").into(),
                size: 1,
                scan: None,
                latest: None,
                output_path: None,
                output_processing: None,
                status: ItemStatus::Finished,
            });
        }
        session.items[2].status = ItemStatus::Cancelled;
        session.pending.push_back(PendingTask {
            id: 2,
            kind: TaskKind::Scan,
        });
        session.selected = Some(1);
        session.clear_completed();
        assert_eq!(
            session.items.iter().map(|item| item.id).collect::<Vec<_>>(),
            vec![2, 3]
        );
        assert_eq!(session.selected, Some(2));
    }

    #[test]
    fn invalid_output_folder_records_a_failed_sanitization() {
        let directory = tempfile::tempdir().unwrap();
        let not_a_directory = directory.path().join("ordinary-file");
        fs::write(&not_a_directory, b"existing content").unwrap();
        let mut session = Session {
            output_directory: Some(not_a_directory.clone()),
            ..Session::default()
        };
        session.items.push(FileItem {
            id: 1,
            path: "synthetic.png".into(),
            size: 1,
            scan: Some(report("scan")),
            latest: None,
            output_path: None,
            output_processing: None,
            status: ItemStatus::Finished,
        });
        session.queue_sanitize(1, None);
        session.start_next(&egui::Context::default());
        assert!(session.active.is_none());
        assert_eq!(
            session.items[0].latest.as_ref().unwrap().operation,
            "sanitize"
        );
        assert_eq!(
            session.items[0].latest.as_ref().unwrap().result,
            Outcome::Failed
        );
        assert_eq!(fs::read(not_a_directory).unwrap(), b"existing content");
    }

    #[cfg(unix)]
    #[test]
    fn import_skips_symlinks() {
        let directory = tempfile::tempdir().unwrap();
        let source = directory.path().join("source.png");
        let link = directory.path().join("link.png");
        fs::write(&source, b"synthetic").unwrap();
        std::os::unix::fs::symlink(source, &link).unwrap();
        let mut session = Session::default();
        session.add_paths(vec![link]);
        assert!(session.items.is_empty());
        assert!(session.notice.is_some());
    }
    #[test]
    fn timeout_and_user_cancellation_have_distinct_queue_statuses() {
        let mut session = Session::default();
        session.items.push(FileItem {
            id: 1,
            path: "synthetic.png".into(),
            size: 1,
            scan: None,
            latest: None,
            output_path: None,
            output_processing: None,
            status: ItemStatus::Scanning,
        });
        let mut stopped = report("scan");
        stopped.result = Outcome::Failed;
        session.complete(
            1,
            &TaskKind::Scan,
            JobResult {
                report: stopped.clone(),
                exit_code: 6,
                output_path: None,
            },
        );
        assert_eq!(session.items[0].status, ItemStatus::Finished);
        session.items[0].status = ItemStatus::Cancelled;
        session.complete(
            1,
            &TaskKind::Scan,
            JobResult {
                report: stopped,
                exit_code: 6,
                output_path: None,
            },
        );
        assert_eq!(session.items[0].status, ItemStatus::Cancelled);
    }
    #[test]
    fn failed_comparison_tracks_the_compared_copy_when_its_hash_is_available() {
        let mut session = Session::default();
        session.items.push(FileItem {
            id: 1,
            path: "synthetic.png".into(),
            size: 1,
            scan: None,
            latest: None,
            output_path: Some("prior-copy.png".into()),
            output_processing: None,
            status: ItemStatus::Verifying,
        });
        let mut failed = report("verify");
        failed.result = Outcome::Failed;
        failed.output_sha256 = Some("0".repeat(64));
        session.complete(
            1,
            &TaskKind::Verify {
                output: "compared-copy.png".into(),
            },
            JobResult {
                report: failed,
                exit_code: 4,
                output_path: None,
            },
        );
        assert_eq!(
            session.items[0].output_path,
            Some("compared-copy.png".into())
        );
    }
    #[test]
    fn report_budget_stops_pending_work_without_discarding_completed_reports() {
        let mut session = Session::default();
        let mut large = report("scan");
        large.findings.resize(5_000, large.findings[0].clone());
        for id in 1..=10 {
            session.items.push(FileItem {
                id,
                path: format!("synthetic-{id}.png").into(),
                size: 1,
                scan: Some(large.clone()),
                latest: Some(large.clone()),
                output_path: None,
                output_processing: None,
                status: ItemStatus::Finished,
            });
        }
        session.items.push(FileItem {
            id: 11,
            path: "pending.png".into(),
            size: 1,
            scan: None,
            latest: None,
            output_path: None,
            output_processing: None,
            status: ItemStatus::Queued,
        });
        session.pending.push_back(PendingTask {
            id: 11,
            kind: TaskKind::Scan,
        });
        session.start_next(&egui::Context::default());
        assert!(session.active.is_none());
        assert!(session.pending.is_empty());
        assert_eq!(
            session.items[0].latest.as_ref().unwrap().findings.len(),
            5_000
        );
        assert_eq!(session.items[10].status, ItemStatus::Ready);
        assert!(session.notice.as_ref().unwrap().contains("memory budget"));
    }
}
