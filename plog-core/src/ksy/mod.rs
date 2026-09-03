//! Runtime interpreter for a useful subset of Kaitai Struct (`.ksy`).
//!
//! Kaitai Struct's official tooling only supports compiling a `.ksy` into
//! target-language source code ahead of time; there is no library (in Rust
//! or otherwise) that loads an arbitrary `.ksy` file and parses data against
//! it at runtime, which is what a "pick any schema file in the GUI" tool
//! needs. This module is that runtime interpreter, covering: primitive
//! integer/float/string/byte fields, `size`/`size-eos`, `if` conditions,
//! `repeat` (`expr`/`eos`/`until`), `contents` magic checks, `enum` value
//! naming, and user-defined nested types (including switch types).
pub mod expr;
mod interp;
pub mod schema;

use indexmap::IndexMap;

use crate::result::Value;
use crate::Error;

/// A parsed, ready-to-use `.ksy` schema.
#[derive(Debug, Clone)]
pub struct KsySchema {
    inner: schema::KsySchema,
}

impl KsySchema {
    /// Parse a `.ksy` YAML document.
    pub fn parse(source: &str) -> Result<Self, Error> {
        Ok(Self {
            inner: schema::parse(source)?,
        })
    }

    /// `true` if the schema declares no top-level fields (used as a signal
    /// to fall back to raw-bytes decoding for minimal/placeholder KSYs).
    pub fn is_empty(&self) -> bool {
        self.inner.root.seq.is_empty()
    }

    /// Decode `bytes` according to this schema, in field declaration order.
    pub fn decode(&self, bytes: &[u8]) -> Result<IndexMap<String, Value>, Error> {
        interp::decode_root(&self.inner.root, self.inner.endian, bytes)
    }
}
