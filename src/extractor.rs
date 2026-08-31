/// Packet extractor built on a *compiled-once* regex.
///
/// The caller constructs an [`Extractor`] from a regex pattern string once
/// and then calls [`Extractor::extract_from_line`] for every log line.
/// The compiled [`regex::Regex`] is stored inside the extractor and never
/// recompiled unless the pattern changes.
use regex::Regex;

use crate::{Error, RawPacket};

/// A compiled regex extractor.
///
/// Create once, reuse for every line.
pub struct Extractor {
    /// The compiled regex.  Must have a capture group named `hex`
    /// (or at least capture group 1) that contains the hex payload.
    re: Regex,
    /// Name of the capture group holding the hex payload.
    capture_group: CaptureGroup,
}

enum CaptureGroup {
    Named(String),
    Index(usize),
}

impl Extractor {
    /// Build an extractor from a regex pattern.
    ///
    /// The pattern **must** contain either:
    /// - a named group `(?P<hex>…)` — preferred, or
    /// - at least one unnamed capture group — group 1 is used.
    ///
    /// The pattern is validated for catastrophic-backtracking heuristics by
    /// the `regex` crate itself (which uses a linear-time NFA engine).
    pub fn new(pattern: &str) -> Result<Self, Error> {
        let re = Regex::new(pattern).map_err(|e| Error::Regex(e.to_string()))?;
        let capture_group = if re.capture_names().any(|n| n == Some("hex")) {
            CaptureGroup::Named("hex".to_string())
        } else if re.captures_len() > 1 {
            CaptureGroup::Index(1)
        } else {
            return Err(Error::Regex(
                "pattern must have a 'hex' named capture group or at least one capture group"
                    .to_string(),
            ));
        };
        Ok(Self { re, capture_group })
    }

    /// Try to extract a [`RawPacket`] from a single log line.
    ///
    /// Returns `None` if the line does not match.
    pub fn extract_from_line<'a>(&self, line: &'a str) -> Option<RawPacket<'a>> {
        let caps = self.re.captures(line)?;
        let hex_str = match &self.capture_group {
            CaptureGroup::Named(name) => caps.name(name)?.as_str(),
            CaptureGroup::Index(i) => caps.get(*i)?.as_str(),
        };
        Some(RawPacket { hex: hex_str })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const PATTERN: &str = r"PACKET: (?P<hex>[0-9a-fA-F ]+)";

    #[test]
    fn matches_line() {
        let ext = Extractor::new(PATTERN).unwrap();
        let pkt = ext
            .extract_from_line("2024-01-01 PACKET: deadbeef extra")
            .unwrap();
        // Greedy match captures all hex+space chars up to 'x' in "extra"
        assert!(pkt.hex.starts_with("deadbeef"));
    }

    #[test]
    fn no_match_returns_none() {
        let ext = Extractor::new(PATTERN).unwrap();
        assert!(ext.extract_from_line("no packet here").is_none());
    }

    #[test]
    fn no_capture_group_errors() {
        assert!(Extractor::new("no_capture").is_err());
    }
}
