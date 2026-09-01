/// Heuristic detection of whether a file is text or binary.
use std::fs::File;
use std::io::Read;
use std::path::Path;

use crate::Error;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FileKind {
    Text,
    Binary,
}

/// Sniff the first bytes of a file to decide whether it should be treated as
/// text (line-oriented log) or raw binary.
///
/// A file is considered binary if it contains a NUL byte or is not valid
/// UTF-8 within the sampled prefix.
pub fn detect(path: impl AsRef<Path>) -> Result<FileKind, Error> {
    let mut file = File::open(path)?;
    let mut buf = [0u8; 8192];
    let n = file.read(&mut buf)?;
    let sample = &buf[..n];

    if sample.contains(&0) {
        return Ok(FileKind::Binary);
    }
    if std::str::from_utf8(sample).is_err() {
        return Ok(FileKind::Binary);
    }
    Ok(FileKind::Text)
}
