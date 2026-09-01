use std::path::{Path, PathBuf};

use clap::{Parser, ValueEnum};
use plog_core::filekind::FileKind;
use plog_core::pipeline::{self, AnalysisConfig, AnalysisEvent};
use plog_core::result::DecodedPacket;

/// Default pattern used when the user does not supply one: any run of hex
/// digits (optionally space-separated) of at least 2 bytes.
pub const DEFAULT_PATTERN: &str = r"(?P<hex>[0-9a-fA-F]{2}(?:[ ]?[0-9a-fA-F]{2})+)";

#[derive(Copy, Clone, Debug, PartialEq, Eq, ValueEnum)]
pub enum Mode {
    /// Detect text vs. binary automatically (text defaults to line-by-line).
    Auto,
    /// Text file, analyzed line by line (one packet per matching line).
    Line,
    /// Text file, analyzed as a whole (all matches concatenated into one packet).
    Whole,
    /// Raw binary file, decoded directly without regex extraction.
    Binary,
}

/// Decode hex-encoded packets embedded in a log file using a Kaitai Struct definition.
#[derive(Parser, Debug)]
#[command(name = "plog", version, about)]
pub struct Cli {
    /// Path to the log/binary file to analyze.
    pub file: PathBuf,

    /// Path to the .ksy (Kaitai Struct) definition file.
    #[arg(short, long)]
    pub ksy: PathBuf,

    /// Regex pattern with a `hex` capture group used to find hex payloads in text mode.
    #[arg(short, long, default_value = DEFAULT_PATTERN)]
    pub pattern: String,

    /// How to interpret the file.
    #[arg(short, long, value_enum, default_value_t = Mode::Auto)]
    pub mode: Mode,

    /// Keep watching the file for appended content (text + line mode only).
    #[arg(short, long)]
    pub watch: bool,
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

/// Render a decoded packet the same way for both stdout and tests.
pub fn format_packet(pkt: &DecodedPacket) -> String {
    let mut out = format!(
        "--- packet #{} ({} bytes) ---\n",
        pkt.index,
        pkt.raw_bytes.len()
    );
    let mut keys: Vec<&String> = pkt.fields.keys().collect();
    keys.sort();
    for key in keys {
        out.push_str(&format!("{key}: {}\n", pkt.fields[key].display()));
    }
    out
}

pub fn run_binary(file: &Path, ksy_source: &str) -> Result<String, plog_core::Error> {
    let pkt = pipeline::analyze_binary(file, ksy_source)?;
    Ok(format_packet(&pkt))
}

pub fn run_whole(file: &Path, pattern: &str, ksy_source: &str) -> Result<String, plog_core::Error> {
    let config = AnalysisConfig {
        pattern: pattern.to_string(),
        ksy_source: ksy_source.to_string(),
    };
    let pkt = pipeline::analyze_text_whole(file, config)?;
    Ok(format_packet(&pkt))
}

pub fn run_line(
    file: &Path,
    pattern: &str,
    ksy_source: &str,
    watch: bool,
) -> Result<String, plog_core::Error> {
    let config = AnalysisConfig {
        pattern: pattern.to_string(),
        ksy_source: ksy_source.to_string(),
    };
    let rx = if watch {
        pipeline::start_analysis_watch(file.to_path_buf(), config)?
    } else {
        pipeline::start_analysis(file.to_path_buf(), config)?
    };

    let mut out = String::new();
    for event in rx {
        match event {
            AnalysisEvent::Packet(pkt) => out.push_str(&format_packet(&pkt)),
            AnalysisEvent::Warning(w) => out.push_str(&format!("warning: {w}\n")),
            AnalysisEvent::Error(e) => out.push_str(&format!("error: {e}\n")),
            AnalysisEvent::Done { packets_found } => {
                out.push_str(&format!("done: {packets_found} packet(s) found\n"));
            }
        }
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    #[test]
    fn cli_parses_defaults() {
        let cli = Cli::try_parse_from(["plog", "input.log", "--ksy", "schema.ksy"]).unwrap();
        assert_eq!(cli.file, PathBuf::from("input.log"));
        assert_eq!(cli.ksy, PathBuf::from("schema.ksy"));
        assert_eq!(cli.pattern, DEFAULT_PATTERN);
        assert_eq!(cli.mode, Mode::Auto);
        assert!(!cli.watch);
    }

    #[test]
    fn cli_parses_explicit_mode_and_watch() {
        let cli = Cli::try_parse_from([
            "plog",
            "input.log",
            "--ksy",
            "schema.ksy",
            "--mode",
            "whole",
            "--watch",
        ])
        .unwrap();
        assert_eq!(cli.mode, Mode::Whole);
        assert!(cli.watch);
    }

    #[test]
    fn cli_requires_ksy() {
        assert!(Cli::try_parse_from(["plog", "input.log"]).is_err());
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
        assert_eq!(resolve_mode(Mode::Binary, FileKind::Text), Mode::Binary);
    }

    #[test]
    fn format_packet_contains_index_and_fields() {
        let pkt = DecodedPacket {
            index: 3,
            raw_bytes: vec![0xde, 0xad],
            fields: [(
                "raw".to_string(),
                plog_core::result::Value::Bytes(vec![0xde, 0xad]),
            )]
            .into_iter()
            .collect(),
        };
        let text = format_packet(&pkt);
        assert!(text.contains("packet #3"));
        assert!(text.contains("2 bytes"));
        assert!(text.contains("raw: de ad"));
    }

    fn write_temp(dir: &tempfile::TempDir, name: &str, content: &str) -> PathBuf {
        let path = dir.path().join(name);
        let mut f = std::fs::File::create(&path).unwrap();
        f.write_all(content.as_bytes()).unwrap();
        path
    }

    #[test]
    fn run_binary_decodes_raw_bytes() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("data.bin");
        std::fs::write(&path, [0xde, 0xad, 0xbe, 0xef]).unwrap();

        let out = run_binary(&path, "name: test").unwrap();
        assert!(out.contains("packet #0"));
        assert!(out.contains("raw: de ad be ef"));
    }

    #[test]
    fn run_whole_concatenates_all_matches() {
        let dir = tempfile::tempdir().unwrap();
        let path = write_temp(
            &dir,
            "log.txt",
            "PACKET: deadbeef\nnoise\nPACKET: cafebabe\n",
        );

        let out = run_whole(&path, r"PACKET: (?P<hex>[0-9a-fA-F ]+)", "name: test").unwrap();
        assert!(out.contains("packet #0"));
        assert!(out.contains("8 bytes"));
        assert!(out.contains("raw: de ad be ef ca fe ba be"));
    }

    #[test]
    fn run_line_emits_one_packet_per_line() {
        let dir = tempfile::tempdir().unwrap();
        let path = write_temp(
            &dir,
            "log.txt",
            "PACKET: deadbeef\nnoise\nPACKET: cafebabe\n",
        );

        let out = run_line(
            &path,
            r"PACKET: (?P<hex>[0-9a-fA-F ]+)",
            "name: test",
            false,
        )
        .unwrap();
        assert!(out.contains("packet #0"));
        assert!(out.contains("packet #1"));
        assert!(out.contains("done: 2 packet(s) found"));
    }

    #[test]
    fn run_binary_rejects_empty_ksy() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("data.bin");
        std::fs::write(&path, [0x01]).unwrap();

        assert!(run_binary(&path, "   ").is_err());
    }
}
