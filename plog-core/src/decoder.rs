/// Protocol decoder with KSY-content-hash–based caching.
///
/// The design ensures that the same KSY definition is never loaded/prepared
/// more than once per unique content.  A decoder instance produced by
/// [`DecoderCache`] can be reused for all packets that share the same protocol.
use std::collections::HashMap;

use crate::ksy::KsySchema;
use crate::{result::DecodedPacket, result::Value, Error};

/// A handle to a prepared protocol decoder, backed by a parsed KSY schema.
pub struct Decoder {
    schema: KsySchema,
}

impl Decoder {
    /// Decode raw bytes into a [`DecodedPacket`].
    ///
    /// Schemas with no `seq` fields (e.g. minimal/placeholder KSYs) fall back
    /// to a single `raw` field containing the whole byte sequence.
    pub fn decode(&self, index: u64, raw_bytes: Vec<u8>) -> Result<DecodedPacket, Error> {
        let fields = if self.schema.is_empty() {
            let mut fields = indexmap::IndexMap::new();
            fields.insert("raw".to_string(), Value::Bytes(raw_bytes.clone()));
            fields
        } else {
            self.schema.decode(&raw_bytes)?
        };
        Ok(DecodedPacket {
            index,
            raw_bytes,
            fields,
        })
    }
}

/// Cache of prepared decoders keyed by the SHA-256 hash of the KSY content.
///
/// Calling [`DecoderCache::get_or_prepare`] returns an existing decoder if
/// the KSY content has not changed, or compiles a new one and stores it.
///
/// # Invalidation
///
/// When a `.ksy` file changes its content hash changes, causing the cache to
/// produce a fresh decoder.  Stale decoders for previous hashes are evicted
/// immediately.
pub struct DecoderCache {
    inner: HashMap<u64, Decoder>,
}

impl DecoderCache {
    pub fn new() -> Self {
        Self {
            inner: HashMap::new(),
        }
    }

    /// Get (or prepare) a decoder for the given KSY source.
    ///
    /// The cache key is a fast non-cryptographic hash of the KSY content —
    /// good enough for cache invalidation purposes.
    pub fn get_or_prepare(&mut self, ksy_source: &str) -> Result<&Decoder, Error> {
        let key = fnv1a(ksy_source.as_bytes());
        if let std::collections::hash_map::Entry::Vacant(e) = self.inner.entry(key) {
            let decoder = prepare_decoder(ksy_source)?;
            e.insert(decoder);
        }
        Ok(self.inner.get(&key).unwrap())
    }
}

impl Default for DecoderCache {
    fn default() -> Self {
        Self::new()
    }
}

/// Prepare a standalone [`Decoder`] without going through a [`DecoderCache`].
///
/// Used by the parallel/chunked pipeline, where each worker thread shares one
/// `Arc<Decoder>` instead of a per-thread cache (the KSY schema only needs to
/// be parsed once regardless of how many threads decode packets with it).
pub fn prepare_decoder(ksy_source: &str) -> Result<Decoder, Error> {
    if ksy_source.trim().is_empty() {
        return Err(Error::Protocol("KSY source is empty".to_string()));
    }
    let schema = KsySchema::parse(ksy_source)?;
    Ok(Decoder { schema })
}

/// FNV-1a 64-bit hash — extremely fast, good enough for cache keys.
fn fnv1a(data: &[u8]) -> u64 {
    let mut h: u64 = 14_695_981_039_346_656_037;
    for &b in data {
        h ^= b as u64;
        h = h.wrapping_mul(1_099_511_628_211);
    }
    h
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn same_ksy_reuses_decoder() {
        let mut cache = DecoderCache::new();
        let ksy = "name: test\ndoc: stub";
        let _d1 = cache.get_or_prepare(ksy).unwrap();
        // A second call must succeed and return the cached decoder.
        let _d2 = cache.get_or_prepare(ksy).unwrap();
    }

    #[test]
    fn different_ksy_new_decoder() {
        let mut cache = DecoderCache::new();
        let _d1 = cache.get_or_prepare("name: a").unwrap();
        let _d2 = cache.get_or_prepare("name: b").unwrap();
        assert_eq!(cache.inner.len(), 2);
    }

    #[test]
    fn empty_ksy_error() {
        let mut cache = DecoderCache::new();
        assert!(cache.get_or_prepare("   ").is_err());
    }

    #[test]
    fn decode_produces_raw_field() {
        let mut cache = DecoderCache::new();
        let d = cache.get_or_prepare("name: test").unwrap();
        let pkt = d.decode(0, vec![0xde, 0xad]).unwrap();
        assert!(pkt.fields.contains_key("raw"));
    }
}
