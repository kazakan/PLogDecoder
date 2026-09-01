/// plog-core — streaming log analysis engine.
///
/// # Architecture
///
/// ```text
/// start_analysis(path, config)
///     │
///     └─► background thread
///             │  BufReader (streaming)
///             │  Extractor (compiled-once regex)
///             │  hex::decode (zero-copy nibble loop)
///             │  DecoderCache (KSY hash-based, reuse)
///             ▼
///         mpsc::channel → AnalysisEvent → GUI
/// ```
///
/// # Performance guarantees
///
/// - The file is **never** loaded fully into memory.
/// - The regex is compiled **once** per [`Extractor`] instance.
/// - The protocol decoder is prepared **once** per unique KSY content hash.
/// - Hex decoding uses a single nibble loop with no intermediate collections.
/// - Packets are published to the receiver as they are decoded (incremental).
/// - All heavy processing happens on a **background thread**.
pub mod decoder;
pub mod extractor;
pub mod filekind;
pub mod hex;
pub mod pipeline;
pub mod result;

/// A borrowed reference to a hex-encoded packet payload found in a log line.
#[derive(Debug, Clone, Copy)]
pub struct RawPacket<'a> {
    /// The hex string as it appears in the log (may contain whitespace).
    pub hex: &'a str,
}

/// Errors produced by plog-core.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),

    #[error("Regex error: {0}")]
    Regex(String),

    #[error("Hex decode error: {0}")]
    HexDecode(String),

    #[error("Protocol error: {0}")]
    Protocol(String),
}
