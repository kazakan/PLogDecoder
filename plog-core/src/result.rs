/// Typed value representation for decoded protocol fields.
///
/// Values are stored in their natural types and converted to display strings
/// only when needed, to avoid unnecessary allocations.
use indexmap::IndexMap;

/// A single decoded value from a protocol field.
#[derive(Debug, Clone, PartialEq)]
pub enum Value {
    Integer(i64),
    UnsignedInteger(u64),
    Float(f64),
    Boolean(bool),
    Bytes(Vec<u8>),
    Str(String),
    Array(Vec<Value>),
    /// A nested struct, preserving the field declaration order (as in a KSY `seq`).
    Struct(IndexMap<String, Value>),
    Null,
}

impl Value {
    /// Convert to a display string only when required.
    pub fn display(&self) -> String {
        match self {
            Value::Integer(n) => n.to_string(),
            Value::UnsignedInteger(n) => n.to_string(),
            Value::Float(f) => f.to_string(),
            Value::Boolean(b) => b.to_string(),
            Value::Bytes(b) => {
                let mut s = String::with_capacity(b.len() * 3);
                for (i, byte) in b.iter().enumerate() {
                    if i > 0 {
                        s.push(' ');
                    }
                    s.push_str(&format!("{:02x}", byte));
                }
                s
            }
            Value::Str(s) => s.clone(),
            Value::Array(a) => {
                let parts: Vec<String> = a.iter().map(|v| v.display()).collect();
                format!("[{}]", parts.join(", "))
            }
            Value::Struct(m) => {
                let parts: Vec<String> = m
                    .iter()
                    .map(|(k, v)| format!("{}: {}", k, v.display()))
                    .collect();
                format!("{{{}}}", parts.join(", "))
            }
            Value::Null => "null".to_string(),
        }
    }
}

/// A fully decoded packet result containing typed field values.
#[derive(Debug, Clone)]
pub struct DecodedPacket {
    /// Packet index (0-based, preserving original order).
    pub index: u64,
    /// Raw bytes that were decoded.
    pub raw_bytes: Vec<u8>,
    /// Decoded fields, in declaration order (as in the KSY `seq`).
    pub fields: IndexMap<String, Value>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn display_integer() {
        assert_eq!(Value::Integer(-42).display(), "-42");
    }

    #[test]
    fn display_bytes() {
        assert_eq!(Value::Bytes(vec![0xde, 0xad]).display(), "de ad");
    }

    #[test]
    fn display_null() {
        assert_eq!(Value::Null.display(), "null");
    }
}
