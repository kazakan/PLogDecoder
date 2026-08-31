/// Streaming log reader and background analysis pipeline.
///
/// [`AnalysisPipeline`] processes a log file in chunks, publishing
/// [`DecodedPacket`]s incrementally via a channel so the GUI can start
/// displaying results before the full file has been read.
///
/// # Design
///
/// ```text
/// AnalysisPipeline::run()
///     │
///     ├─ BufReader (streaming, no full-file load)
///     │       │  line by line
///     │       ▼
///     ├─ Extractor (compiled-once regex)
///     │       │  RawPacket (borrowed hex str)
///     │       ▼
///     ├─ hex::decode  (direct byte conversion)
///     │       │  Vec<u8>
///     │       ▼
///     ├─ DecoderCache (reuse prepared protocol decoder)
///     │       │  DecodedPacket
///     │       ▼
///     └─ Sender<AnalysisEvent>  (mpsc channel → GUI)
/// ```
use std::fs::File;
use std::io::{BufRead, BufReader};
use std::path::Path;
use std::sync::mpsc::{self, Receiver, Sender};
use std::thread;

use crate::decoder::DecoderCache;
use crate::extractor::Extractor;
use crate::result::DecodedPacket;
use crate::{hex, Error};

/// Events emitted by the analysis pipeline.
#[derive(Debug)]
pub enum AnalysisEvent {
    /// A packet has been decoded and is ready to display.
    Packet(DecodedPacket),
    /// Analysis finished; `packets_found` is the total count.
    Done { packets_found: u64 },
    /// A non-fatal error occurred (e.g. bad hex in one line).
    Warning(String),
    /// A fatal error aborted the analysis.
    Error(Error),
}

/// Configuration for an analysis run.
pub struct AnalysisConfig {
    pub pattern: String,
    pub ksy_source: String,
}

/// Start an analysis on a background thread.
///
/// Returns a [`Receiver`] that will produce [`AnalysisEvent`]s as they become
/// available.  The receiver can be polled or integrated into an async runtime.
pub fn start_analysis(
    path: impl AsRef<Path> + Send + 'static,
    config: AnalysisConfig,
) -> Result<Receiver<AnalysisEvent>, Error> {
    let (tx, rx) = mpsc::channel::<AnalysisEvent>();
    let extractor = Extractor::new(&config.pattern)?;
    let ksy = config.ksy_source;

    thread::spawn(move || {
        run_analysis(path.as_ref(), extractor, &ksy, tx);
    });

    Ok(rx)
}

fn run_analysis(
    path: &Path,
    extractor: Extractor,
    ksy_source: &str,
    tx: Sender<AnalysisEvent>,
) {
    let file = match File::open(path) {
        Ok(f) => f,
        Err(e) => {
            let _ = tx.send(AnalysisEvent::Error(Error::Io(e)));
            return;
        }
    };

    let mut cache = DecoderCache::new();
    let decoder = match cache.get_or_prepare(ksy_source) {
        Ok(d) => d,
        Err(e) => {
            let _ = tx.send(AnalysisEvent::Error(e));
            return;
        }
    };

    let reader = BufReader::with_capacity(256 * 1024, file);
    let mut packet_index: u64 = 0;
    let mut packets_found: u64 = 0;

    for line_result in reader.lines() {
        let line = match line_result {
            Ok(l) => l,
            Err(e) => {
                let _ = tx.send(AnalysisEvent::Warning(format!("IO error reading line: {e}")));
                continue;
            }
        };
        packet_index += 1;

        if let Some(raw) = extractor.extract_from_line(&line) {
            let bytes = match hex::decode(raw.hex) {
                Ok(b) => b,
                Err(e) => {
                    let _ = tx.send(AnalysisEvent::Warning(format!(
                        "hex decode error on line {packet_index}: {e}"
                    )));
                    continue;
                }
            };

            match decoder.decode(packets_found, bytes) {
                Ok(pkt) => {
                    packets_found += 1;
                    // If the receiver has gone away we stop processing.
                    if tx.send(AnalysisEvent::Packet(pkt)).is_err() {
                        return;
                    }
                }
                Err(e) => {
                    let _ = tx.send(AnalysisEvent::Warning(format!(
                        "decode error on line {packet_index}: {e}"
                    )));
                }
            }
        }
    }

    let _ = tx.send(AnalysisEvent::Done { packets_found });
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use tempfile::NamedTempFile;

    fn write_log(lines: &[&str]) -> NamedTempFile {
        let mut f = NamedTempFile::new().unwrap();
        for l in lines {
            writeln!(f, "{}", l).unwrap();
        }
        f
    }

    #[test]
    fn pipeline_emits_packets_and_done() {
        let f = write_log(&[
            "2024-01-01 PACKET: deadbeef",
            "some other log line",
            "2024-01-01 PACKET: cafebabe",
        ]);
        let config = AnalysisConfig {
            pattern: r"PACKET: (?P<hex>[0-9a-fA-F ]+)".to_string(),
            ksy_source: "name: test".to_string(),
        };
        let rx = start_analysis(f.path().to_path_buf(), config).unwrap();

        let mut packets = 0u64;
        let mut done = false;
        for event in rx {
            match event {
                AnalysisEvent::Packet(_) => packets += 1,
                AnalysisEvent::Done { packets_found } => {
                    assert_eq!(packets_found, 2);
                    done = true;
                }
                AnalysisEvent::Error(e) => panic!("unexpected error: {e}"),
                AnalysisEvent::Warning(w) => panic!("unexpected warning: {w}"),
            }
        }
        assert_eq!(packets, 2);
        assert!(done);
    }

    #[test]
    fn pipeline_missing_file_sends_error() {
        let config = AnalysisConfig {
            pattern: r"(?P<hex>[0-9a-fA-F]+)".to_string(),
            ksy_source: "name: test".to_string(),
        };
        let rx = start_analysis(
            std::path::PathBuf::from("/tmp/__nonexistent_plog_test__"),
            config,
        )
        .unwrap();
        let events: Vec<_> = rx.into_iter().collect();
        assert!(events
            .iter()
            .any(|e| matches!(e, AnalysisEvent::Error(_))));
    }
}
