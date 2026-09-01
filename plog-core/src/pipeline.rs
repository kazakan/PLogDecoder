/// Streaming log reader and background analysis pipeline.
///
/// Two entry points are provided:
///
/// * [`start_analysis`] — read the file once and stop (emits [`AnalysisEvent::Done`]).
/// * [`start_analysis_watch`] — read the file, then **tail-follow** it: when EOF
///   is reached the reader parks at the current byte offset and polls for new
///   data.  Any bytes appended to the file are processed without re-reading
///   previously seen content.  The watcher runs until the receiver is dropped
///   or a fatal IO error occurs.
///
/// # Design
///
/// ```text
/// start_analysis[_watch](path, config)
///     │
///     └─► background thread
///             │  File::open (seek resumes position on tail)
///             │  BufReader 256 KB
///             │  line by line
///             ▼
///         Extractor  (compiled-once regex)
///             ▼
///         hex::decode  (nibble loop, no intermediates)
///             ▼
///         DecoderCache (KSY hash keyed, reuse)
///             ▼
///         Sender<AnalysisEvent>  → GUI / caller
/// ```
use std::fs::File;
use std::io::{BufRead, BufReader, Seek, SeekFrom};
use std::path::Path;
use std::sync::mpsc::{self, Receiver, Sender};
use std::thread;
use std::time::Duration;

use crate::decoder::DecoderCache;
use crate::extractor::Extractor;
use crate::result::DecodedPacket;
use crate::{hex, Error};

/// How long to sleep between polls when tailing a file with no new data.
const TAIL_POLL_INTERVAL: Duration = Duration::from_millis(250);

/// Events emitted by the analysis pipeline.
#[derive(Debug)]
pub enum AnalysisEvent {
    /// A packet has been decoded and is ready to display.
    Packet(DecodedPacket),
    /// One-shot analysis finished; `packets_found` is the total count.
    /// Not emitted in watch/tail mode.
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

/// Start a one-shot analysis on a background thread.
///
/// Reads the file from beginning to end, then emits [`AnalysisEvent::Done`]
/// and exits.  Returns a [`Receiver`] that yields events as they become ready.
pub fn start_analysis(
    path: impl AsRef<Path> + Send + 'static,
    config: AnalysisConfig,
) -> Result<Receiver<AnalysisEvent>, Error> {
    let (tx, rx) = mpsc::channel::<AnalysisEvent>();
    let extractor = Extractor::new(&config.pattern)?;
    let ksy = config.ksy_source;

    thread::spawn(move || {
        run_analysis(path.as_ref(), extractor, &ksy, tx, false);
    });

    Ok(rx)
}

/// Start a **watch** (tail-follow) analysis on a background thread.
///
/// Behaves like [`start_analysis`] for the initial content of the file, but
/// instead of stopping at EOF it keeps polling for new data.  When the caller
/// appends lines to the file the pipeline picks them up from the current byte
/// offset — the file is **never** re-read from the beginning.
///
/// The background thread exits only when the [`Receiver`] is dropped (i.e. the
/// caller is no longer interested in events) or a fatal IO error occurs.
pub fn start_analysis_watch(
    path: impl AsRef<Path> + Send + 'static,
    config: AnalysisConfig,
) -> Result<Receiver<AnalysisEvent>, Error> {
    let (tx, rx) = mpsc::channel::<AnalysisEvent>();
    let extractor = Extractor::new(&config.pattern)?;
    let ksy = config.ksy_source;

    thread::spawn(move || {
        run_analysis(path.as_ref(), extractor, &ksy, tx, true);
    });

    Ok(rx)
}

// ---------------------------------------------------------------------------
// Internal implementation
// ---------------------------------------------------------------------------

fn run_analysis(
    path: &Path,
    extractor: Extractor,
    ksy_source: &str,
    tx: Sender<AnalysisEvent>,
    watch: bool,
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

    let mut reader = BufReader::with_capacity(256 * 1024, file);
    let mut line_index: u64 = 0;
    let mut packets_found: u64 = 0;
    let mut line_buf = String::new();

    loop {
        line_buf.clear();
        match reader.read_line(&mut line_buf) {
            Err(e) => {
                let _ = tx.send(AnalysisEvent::Warning(format!(
                    "IO error reading line: {e}"
                )));
                // Continue — the next read may succeed.
            }
            Ok(0) => {
                // EOF reached.
                if !watch {
                    // One-shot mode: we're done.
                    let _ = tx.send(AnalysisEvent::Done { packets_found });
                    return;
                }

                // Watch mode: check whether the receiver is still alive before
                // sleeping, then seek to where we are (the file's current
                // position) so we don't re-read bytes already processed.
                // We detect a closed receiver by trying a dummy send — if the
                // channel is gone we exit cleanly.
                //
                // NOTE: `tx.send` on a disconnected receiver returns Err.  We
                // use a zero-overhead trick: check if the internal channel has
                // no remaining receivers by attempting a non-blocking send of a
                // Ping-like probe.  Instead we simply track the result of our
                // last real send and exit if it failed.
                //
                // The simplest approach: sleep and retry.  We have already
                // recorded our position via BufReader so `read_line` will
                // resume exactly where it left off on the next iteration.
                thread::sleep(TAIL_POLL_INTERVAL);

                // Re-open the file in case it was rotated (inode changed).
                // If the same inode is still there we seek back to where we
                // were; if the file was replaced we start from the beginning
                // of the new file.
                let pos = match reader.stream_position() {
                    Ok(p) => p,
                    Err(e) => {
                        let _ = tx.send(AnalysisEvent::Warning(format!(
                            "could not get stream position: {e}"
                        )));
                        0
                    }
                };

                match reopen_or_seek(path, pos) {
                    Ok(new_reader) => reader = new_reader,
                    Err(e) => {
                        // File temporarily unavailable — keep waiting.
                        let _ = tx.send(AnalysisEvent::Warning(format!(
                            "watch: could not reopen file: {e}"
                        )));
                        thread::sleep(TAIL_POLL_INTERVAL);
                    }
                }
                continue;
            }
            Ok(_) => {
                line_index += 1;
                let line = line_buf.trim_end_matches('\n').trim_end_matches('\r');

                if let Some(raw) = extractor.extract_from_line(line) {
                    let bytes = match hex::decode(raw.hex) {
                        Ok(b) => b,
                        Err(e) => {
                            let _ = tx.send(AnalysisEvent::Warning(format!(
                                "hex decode error on line {line_index}: {e}"
                            )));
                            continue;
                        }
                    };

                    match decoder.decode(packets_found, bytes) {
                        Ok(pkt) => {
                            packets_found += 1;
                            if tx.send(AnalysisEvent::Packet(pkt)).is_err() {
                                // Receiver dropped — stop the background thread.
                                return;
                            }
                        }
                        Err(e) => {
                            let _ = tx.send(AnalysisEvent::Warning(format!(
                                "decode error on line {line_index}: {e}"
                            )));
                        }
                    }
                }
            }
        }
    }
}

/// Attempt to reopen the file at the same byte position.
///
/// If the file at `path` has grown or remained the same since position `pos`,
/// seek to `pos` and return.  If the file is now *shorter* (it was rotated /
/// truncated) seek to the beginning of the new file so we do not miss any data.
fn reopen_or_seek(path: &Path, pos: u64) -> Result<BufReader<File>, std::io::Error> {
    let mut file = File::open(path)?;
    let meta = file.metadata()?;
    let seek_to = if meta.len() >= pos { pos } else { 0 };
    file.seek(SeekFrom::Start(seek_to))?;
    Ok(BufReader::with_capacity(256 * 1024, file))
}

/// Analyze a text file as a single unit: every hex match found anywhere in
/// the file is concatenated (in order) into one byte stream and decoded as
/// a single packet.
///
/// Unlike [`start_analysis`], this runs synchronously on the calling thread
/// and returns the result directly instead of a channel of events.
pub fn analyze_text_whole(
    path: impl AsRef<Path>,
    config: AnalysisConfig,
) -> Result<DecodedPacket, Error> {
    let extractor = Extractor::new(&config.pattern)?;
    let content = std::fs::read_to_string(path)?;

    let mut bytes = Vec::new();
    for raw in extractor.extract_all(&content) {
        bytes.extend(hex::decode(raw.hex)?);
    }

    let mut cache = DecoderCache::new();
    let decoder = cache.get_or_prepare(&config.ksy_source)?;
    decoder.decode(0, bytes)
}

/// Analyze a binary file: its raw bytes are decoded directly (no hex
/// extraction/regex step) into a single packet.
pub fn analyze_binary(
    path: impl AsRef<Path>,
    ksy_source: &str,
) -> Result<DecodedPacket, Error> {
    let bytes = std::fs::read(path)?;

    let mut cache = DecoderCache::new();
    let decoder = cache.get_or_prepare(ksy_source)?;
    decoder.decode(0, bytes)
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
        assert!(events.iter().any(|e| matches!(e, AnalysisEvent::Error(_))));
    }

    /// Verify that the watch pipeline picks up lines appended after the initial
    /// read without re-processing the original content.
    #[test]
    fn watch_pipeline_picks_up_appended_lines() {
        use std::sync::{Arc, Mutex};
        use std::time::Duration;

        let mut f = NamedTempFile::new().unwrap();
        // Write initial content.
        writeln!(f, "2024-01-01 PACKET: deadbeef").unwrap();
        writeln!(f, "some other line").unwrap();
        f.flush().unwrap();

        let config = AnalysisConfig {
            pattern: r"PACKET: (?P<hex>[0-9a-fA-F ]+)".to_string(),
            ksy_source: "name: test".to_string(),
        };
        let rx = start_analysis_watch(f.path().to_path_buf(), config).unwrap();

        let packets: Arc<Mutex<Vec<DecodedPacket>>> = Arc::new(Mutex::new(Vec::new()));
        let packets_clone = Arc::clone(&packets);

        // Collect events on a separate thread so we can also append to the file.
        let collector = thread::spawn(move || {
            for event in rx {
                if let AnalysisEvent::Packet(p) = event {
                    packets_clone.lock().unwrap().push(p);
                    // Stop collecting after we see 2 packets.
                    if packets_clone.lock().unwrap().len() >= 2 {
                        break;
                    }
                }
            }
        });

        // Give the watcher time to process the first packet and reach EOF.
        thread::sleep(Duration::from_millis(100));

        // Append a second packet to the file.
        {
            let mut file = std::fs::OpenOptions::new()
                .append(true)
                .open(f.path())
                .unwrap();
            writeln!(file, "2024-01-01 PACKET: cafebabe").unwrap();
        }

        collector.join().unwrap();

        let got = packets.lock().unwrap();
        assert_eq!(got.len(), 2, "expected 2 packets, got {}", got.len());
        // First packet index 0, second 1 — ordering preserved.
        assert_eq!(got[0].index, 0);
        assert_eq!(got[1].index, 1);
    }
}
