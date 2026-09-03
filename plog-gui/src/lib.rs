//! Minimal GUI runtime for plog-core.
//!
//! Lets the user pick a log/binary file and a `.ksy` definition, choose how
//! to interpret the file (auto-detected text/binary, line-by-line, or whole
//! file), and view the decoded packets.
use std::path::PathBuf;
use std::sync::mpsc::Receiver;

use eframe::egui;
use plog_core::filekind::{self, FileKind};
use plog_core::pipeline::{self, AnalysisConfig, AnalysisEvent};
use plog_core::result::DecodedPacket;

pub const DEFAULT_PATTERN: &str = r"(?P<hex>[0-9a-fA-F]{2}(?:[ ]?[0-9a-fA-F]{2})+)";

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum Mode {
    Auto,
    Line,
    Whole,
    Binary,
}

impl Mode {
    pub const ALL: [Mode; 4] = [Mode::Auto, Mode::Line, Mode::Whole, Mode::Binary];

    pub fn label(self) -> &'static str {
        match self {
            Mode::Auto => "Auto (detect text/binary)",
            Mode::Line => "Text: line by line",
            Mode::Whole => "Text: whole file",
            Mode::Binary => "Binary: whole file",
        }
    }
}

/// Resolve `Auto` into a concrete mode given the detected file kind.
/// Explicit (non-`Auto`) requests pass through unchanged.
pub fn resolve_mode(requested: Mode, detected: FileKind) -> Mode {
    match requested {
        Mode::Auto => match detected {
            FileKind::Binary => Mode::Binary,
            FileKind::Text => Mode::Line,
        },
        other => other,
    }
}

/// A background job in progress: either a streaming line-mode analysis, or a
/// one-shot whole-file/binary analysis.
enum Job {
    Streaming(Receiver<AnalysisEvent>),
    Once(Receiver<Result<DecodedPacket, String>>),
}

pub struct App {
    pub file: Option<PathBuf>,
    pub ksy: Option<PathBuf>,
    pub pattern: String,
    pub mode: Mode,
    pub watch: bool,

    packets: Vec<DecodedPacket>,
    messages: Vec<String>,
    job: Option<Job>,
    selected_packet: Option<usize>,
}

impl Default for App {
    fn default() -> Self {
        Self {
            file: None,
            ksy: None,
            pattern: DEFAULT_PATTERN.to_string(),
            mode: Mode::Auto,
            watch: false,
            packets: Vec::new(),
            messages: Vec::new(),
            job: None,
            selected_packet: None,
        }
    }
}

impl App {
    pub fn packets(&self) -> &[DecodedPacket] {
        &self.packets
    }

    pub fn messages(&self) -> &[String] {
        &self.messages
    }

    /// `true` while a background job is running.
    pub fn is_busy(&self) -> bool {
        self.job.is_some()
    }

    pub fn resolved_mode(&self) -> Mode {
        if self.mode != Mode::Auto {
            return self.mode;
        }
        match self.file.as_ref().map(filekind::detect) {
            Some(Ok(kind)) => resolve_mode(Mode::Auto, kind),
            _ => Mode::Line,
        }
    }

    pub fn start(&mut self) {
        self.packets.clear();
        self.messages.clear();
        self.selected_packet = None;

        let (Some(file), Some(ksy_path)) = (self.file.clone(), self.ksy.clone()) else {
            self.messages
                .push("Select both a log file and a .ksy file first.".to_string());
            return;
        };

        let ksy_source = match std::fs::read_to_string(&ksy_path) {
            Ok(s) => s,
            Err(e) => {
                self.messages.push(format!("could not read ksy file: {e}"));
                return;
            }
        };

        match self.resolved_mode() {
            Mode::Binary => {
                let (tx, rx) = std::sync::mpsc::channel();
                std::thread::spawn(move || {
                    let result =
                        pipeline::analyze_binary(&file, &ksy_source).map_err(|e| e.to_string());
                    let _ = tx.send(result);
                });
                self.job = Some(Job::Once(rx));
            }
            Mode::Whole => {
                let config = AnalysisConfig {
                    pattern: self.pattern.clone(),
                    ksy_source,
                };
                let (tx, rx) = std::sync::mpsc::channel();
                std::thread::spawn(move || {
                    let result =
                        pipeline::analyze_text_whole(&file, config).map_err(|e| e.to_string());
                    let _ = tx.send(result);
                });
                self.job = Some(Job::Once(rx));
            }
            Mode::Line => {
                let config = AnalysisConfig {
                    pattern: self.pattern.clone(),
                    ksy_source,
                };
                let result = if self.watch {
                    pipeline::start_analysis_watch(file, config)
                } else {
                    pipeline::start_analysis(file, config)
                };
                match result {
                    Ok(rx) => self.job = Some(Job::Streaming(rx)),
                    Err(e) => self.messages.push(format!("could not start analysis: {e}")),
                }
            }
            Mode::Auto => unreachable!("resolved above"),
        }
    }

    /// Drain any pending results from the current background job.
    pub fn poll(&mut self) {
        match &self.job {
            Some(Job::Streaming(rx)) => {
                let mut finished = false;
                loop {
                    match rx.try_recv() {
                        Ok(AnalysisEvent::Packet(pkt)) => self.packets.push(pkt),
                        Ok(AnalysisEvent::Warning(w)) => {
                            self.messages.push(format!("warning: {w}"))
                        }
                        Ok(AnalysisEvent::Error(e)) => {
                            self.messages.push(format!("error: {e}"));
                            finished = true;
                        }
                        Ok(AnalysisEvent::Done { packets_found }) => {
                            self.messages
                                .push(format!("done: {packets_found} packet(s) found"));
                            finished = true;
                        }
                        Err(std::sync::mpsc::TryRecvError::Empty) => break,
                        Err(std::sync::mpsc::TryRecvError::Disconnected) => {
                            finished = true;
                            break;
                        }
                    }
                }
                if finished {
                    self.job = None;
                }
            }
            Some(Job::Once(rx)) => {
                if let Ok(result) = rx.try_recv() {
                    match result {
                        Ok(pkt) => self.packets.push(pkt),
                        Err(e) => self.messages.push(format!("error: {e}")),
                    }
                    self.job = None;
                }
            }
            None => {}
        }
    }
}

impl eframe::App for App {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        self.poll();
        if self.is_busy() {
            ctx.request_repaint();
        }

        egui::TopBottomPanel::top("controls").show(ctx, |ui| {
            ui.horizontal(|ui| {
                if ui.button("Choose log/binary file...").clicked() {
                    if let Some(path) = rfd::FileDialog::new().pick_file() {
                        self.file = Some(path);
                    }
                }
                ui.label(
                    self.file
                        .as_ref()
                        .map(|p| p.display().to_string())
                        .unwrap_or_else(|| "(none)".to_string()),
                );
            });
            ui.horizontal(|ui| {
                if ui.button("Choose .ksy file...").clicked() {
                    if let Some(path) = rfd::FileDialog::new().pick_file() {
                        self.ksy = Some(path);
                    }
                }
                ui.label(
                    self.ksy
                        .as_ref()
                        .map(|p| p.display().to_string())
                        .unwrap_or_else(|| "(none)".to_string()),
                );
            });
            ui.horizontal(|ui| {
                ui.label("Pattern:");
                ui.text_edit_singleline(&mut self.pattern);
            });
            ui.horizontal(|ui| {
                ui.label("Mode:");
                egui::ComboBox::from_id_source("mode")
                    .selected_text(self.mode.label())
                    .show_ui(ui, |ui| {
                        for m in Mode::ALL {
                            ui.selectable_value(&mut self.mode, m, m.label());
                        }
                    });
                ui.add_enabled(
                    self.resolved_mode() == Mode::Line,
                    egui::Checkbox::new(&mut self.watch, "Watch (tail -f)"),
                );
            });
            ui.horizontal(|ui| {
                if ui.button("Run").clicked() {
                    self.start();
                }
                ui.label(format!("{} packet(s)", self.packets.len()));
            });
        });

        egui::TopBottomPanel::bottom("messages")
            .resizable(true)
            .default_height(100.0)
            .show(ctx, |ui| {
                egui::ScrollArea::vertical().show(ui, |ui| {
                    for m in &self.messages {
                        ui.label(m);
                    }
                });
            });

        egui::CentralPanel::default().show(ctx, |ui| {
            // With large logs (tens/hundreds of thousands of packets), laying
            // out a `ui.group` + one label per field for *every* packet on
            // *every* frame makes the UI thread do O(total packets) work per
            // repaint, regardless of what's actually visible - that's what
            // caused the lag. `show_rows` only builds widgets for the rows
            // that are actually scrolled into view, so cost stays bounded by
            // viewport height instead of by log size. Each row is rendered as
            // a single fixed-height summary line to keep row height uniform,
            // which `show_rows` requires for its viewport math; expanding a
            // packet still shows all of its fields (only when selected).
            let row_height = ui.text_style_height(&egui::TextStyle::Body);
            let total = self.packets.len();
            egui::ScrollArea::vertical()
                .auto_shrink([false, false])
                .show_rows(ui, row_height, total, |ui, row_range| {
                    for i in row_range {
                        let pkt = &self.packets[i];
                        let selected = self.selected_packet == Some(i);
                        let summary: String = pkt
                            .fields
                            .iter()
                            .map(|(k, v)| format!("{k}={}", v.display()))
                            .collect::<Vec<_>>()
                            .join(", ");
                        let text =
                            format!("#{} ({} bytes): {summary}", pkt.index, pkt.raw_bytes.len());
                        if ui.selectable_label(selected, text).clicked() {
                            self.selected_packet = if selected { None } else { Some(i) };
                        }
                    }
                });
        });

        if let Some(i) = self.selected_packet {
            if let Some(pkt) = self.packets.get(i) {
                egui::Window::new(format!("packet #{}", pkt.index))
                    .id(egui::Id::new("packet-detail"))
                    .show(ctx, |ui| {
                        for (key, value) in &pkt.fields {
                            ui.label(format!("{key}: {}", value.display()));
                        }
                    });
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::{Duration, Instant};

    fn write_file(dir: &std::path::Path, name: &str, content: &[u8]) -> PathBuf {
        let path = dir.join(name);
        std::fs::write(&path, content).unwrap();
        path
    }

    /// Poll `app` until `job` completes or the timeout elapses.
    fn wait_until_idle(app: &mut App, timeout: Duration) {
        let start = Instant::now();
        while app.is_busy() {
            app.poll();
            if start.elapsed() > timeout {
                panic!("job did not finish within {timeout:?}");
            }
            std::thread::sleep(Duration::from_millis(5));
        }
    }

    #[test]
    fn resolve_mode_auto_picks_binary() {
        assert_eq!(resolve_mode(Mode::Auto, FileKind::Binary), Mode::Binary);
    }

    #[test]
    fn resolve_mode_auto_picks_line_for_text() {
        assert_eq!(resolve_mode(Mode::Auto, FileKind::Text), Mode::Line);
    }

    #[test]
    fn resolve_mode_explicit_passthrough() {
        assert_eq!(resolve_mode(Mode::Whole, FileKind::Binary), Mode::Whole);
    }

    #[test]
    fn default_app_has_no_packets_or_messages() {
        let app = App::default();
        assert!(app.packets().is_empty());
        assert!(app.messages().is_empty());
        assert!(!app.is_busy());
    }

    #[test]
    fn start_without_files_reports_message() {
        let mut app = App::default();
        app.start();
        assert!(!app.is_busy());
        assert_eq!(app.messages().len(), 1);
        assert!(app.messages()[0].contains("Select both"));
    }

    #[test]
    fn start_binary_mode_decodes_file() {
        let dir = tempfile::tempdir().unwrap();
        let ksy = write_file(dir.path(), "schema.ksy", b"name: test\n");
        let bin = write_file(dir.path(), "sample.bin", &[0xde, 0xad, 0xbe, 0xef]);

        let mut app = App {
            file: Some(bin),
            ksy: Some(ksy),
            mode: Mode::Binary,
            ..Default::default()
        };

        app.start();
        wait_until_idle(&mut app, Duration::from_secs(2));

        assert_eq!(app.packets().len(), 1);
        assert_eq!(app.packets()[0].raw_bytes, vec![0xde, 0xad, 0xbe, 0xef]);
    }

    #[test]
    fn start_whole_mode_concatenates_matches() {
        let dir = tempfile::tempdir().unwrap();
        let ksy = write_file(dir.path(), "schema.ksy", b"name: test\n");
        let log = write_file(
            dir.path(),
            "sample.log",
            b"PACKET: deadbeef\nnoise\nPACKET: cafebabe\n",
        );

        let mut app = App {
            file: Some(log),
            ksy: Some(ksy),
            mode: Mode::Whole,
            pattern: r"PACKET: (?P<hex>[0-9a-fA-F ]+)".to_string(),
            ..Default::default()
        };

        app.start();
        wait_until_idle(&mut app, Duration::from_secs(2));

        assert_eq!(app.packets().len(), 1);
        assert_eq!(
            app.packets()[0].raw_bytes,
            vec![0xde, 0xad, 0xbe, 0xef, 0xca, 0xfe, 0xba, 0xbe]
        );
    }

    #[test]
    fn start_line_mode_emits_one_packet_per_line() {
        let dir = tempfile::tempdir().unwrap();
        let ksy = write_file(dir.path(), "schema.ksy", b"name: test\n");
        let log = write_file(
            dir.path(),
            "sample.log",
            b"PACKET: deadbeef\nnoise\nPACKET: cafebabe\n",
        );

        let mut app = App {
            file: Some(log),
            ksy: Some(ksy),
            mode: Mode::Line,
            pattern: r"PACKET: (?P<hex>[0-9a-fA-F ]+)".to_string(),
            ..Default::default()
        };

        app.start();
        wait_until_idle(&mut app, Duration::from_secs(2));

        assert_eq!(app.packets().len(), 2);
        assert!(app
            .messages()
            .iter()
            .any(|m| m.contains("done: 2 packet(s) found")));
    }

    #[test]
    fn resolved_mode_auto_detects_binary_file() {
        let dir = tempfile::tempdir().unwrap();
        let bin = write_file(dir.path(), "sample.bin", &[0x00, 0xde, 0xad]);

        let app = App {
            file: Some(bin),
            mode: Mode::Auto,
            ..Default::default()
        };

        assert_eq!(app.resolved_mode(), Mode::Binary);
    }

    #[test]
    fn start_reports_error_for_missing_ksy() {
        let dir = tempfile::tempdir().unwrap();
        let bin = write_file(dir.path(), "sample.bin", &[0x01]);

        let mut app = App {
            file: Some(bin),
            ksy: Some(dir.path().join("does-not-exist.ksy")),
            ..Default::default()
        };

        app.start();
        assert!(!app.is_busy());
        assert!(app.messages()[0].contains("could not read ksy file"));
    }
}
