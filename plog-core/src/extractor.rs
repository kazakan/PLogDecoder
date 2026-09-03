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
    /// (or one of [`PAYLOAD_GROUP_ALIASES`], or at least one capture group)
    /// that contains the hex payload.
    re: Regex,
    /// Name of the capture group holding the hex payload.
    capture_group: CaptureGroup,
}

enum CaptureGroup {
    Named(String),
    Index(usize),
}

/// Names, in priority order, recognized as holding the hex payload when no
/// group is named `hex`. Covers the extractor pattern commonly suggested for
/// `[timestamp] channel> hex...` style logs, e.g.
/// `^\[(?<timestamp>[^\]]+)\]\s+(?<channel>\S+)>\s+(?<packet>[0-9A-Fa-f ]+)$`.
const PAYLOAD_GROUP_ALIASES: &[&str] = &["hex", "packet", "payload", "data"];

impl Extractor {
    /// Build an extractor from a regex pattern.
    ///
    /// The pattern **must** contain either:
    /// - a named group `(?P<hex>…)` (or one of [`PAYLOAD_GROUP_ALIASES`]) — preferred, or
    /// - at least one capture group — the *last* one is used, since prefix
    ///   groups like timestamp/channel typically come before the payload.
    ///
    /// The pattern is validated for catastrophic-backtracking heuristics by
    /// the `regex` crate itself (which uses a linear-time NFA engine).
    pub fn new(pattern: &str) -> Result<Self, Error> {
        let re = Regex::new(pattern).map_err(|e| Error::Regex(e.to_string()))?;
        let names: Vec<&str> = re.capture_names().flatten().collect();
        let capture_group = if let Some(&alias) = PAYLOAD_GROUP_ALIASES
            .iter()
            .find(|alias| names.contains(*alias))
        {
            CaptureGroup::Named(alias.to_string())
        } else if re.captures_len() > 1 {
            CaptureGroup::Index(re.captures_len() - 1)
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
    /// Returns `None` if the line does not match. When the pattern can match
    /// more than once on the same line (e.g. a generic hex-run pattern with
    /// no anchors, which can also match a leading numeric timestamp), the
    /// *last* match is used, since prefix content like timestamps/sequence
    /// numbers typically precedes the actual payload.
    pub fn extract_from_line<'a>(&self, line: &'a str) -> Option<RawPacket<'a>> {
        let caps = self.re.captures_iter(line).last()?;
        let hex_str = match &self.capture_group {
            CaptureGroup::Named(name) => caps.name(name)?.as_str(),
            CaptureGroup::Index(i) => caps.get(*i)?.as_str(),
        };
        Some(RawPacket { hex: hex_str })
    }

    /// Find every match in `text`, in order.
    ///
    /// Used for "whole file" analysis where the hex payload may be spread
    /// across multiple matches within a single blob of text.
    pub fn extract_all<'a>(&self, text: &'a str) -> Vec<RawPacket<'a>> {
        self.re
            .captures_iter(text)
            .filter_map(|caps| {
                let hex_str = match &self.capture_group {
                    CaptureGroup::Named(name) => caps.name(name)?.as_str(),
                    CaptureGroup::Index(i) => caps.get(*i)?.as_str(),
                };
                Some(RawPacket { hex: hex_str })
            })
            .collect()
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

    #[test]
    fn recognizes_packet_alias_group_name() {
        // The extractor regex suggested for `[timestamp] channel> hex` logs
        // names its payload group `packet`, not `hex`.
        let ext = Extractor::new(
            r"^\[(?<timestamp>[^\]]+)\]\s+(?<channel>\S+)>\s+(?<packet>[0-9A-Fa-f ]+)$",
        )
        .unwrap();
        let pkt = ext
            .extract_from_line("[20260908 1939] 1:1> AA 01 10 00")
            .unwrap();
        assert_eq!(pkt.hex, "AA 01 10 00");
    }

    #[test]
    fn unnamed_groups_use_the_last_one() {
        // A leading timestamp-like group must not be mistaken for the payload.
        let ext = Extractor::new(r"(\d+) (\w+) ([0-9a-fA-F]+)").unwrap();
        let pkt = ext.extract_from_line("20260908 tag deadbeef").unwrap();
        assert_eq!(pkt.hex, "deadbeef");
    }
}
