/// Efficient hex decoder.
///
/// Decodes a hex string (with optional whitespace) directly into a `Vec<u8>`.
/// No intermediate `split()` / `Vec<&str>` / `String` allocations are made.
use crate::Error;

/// Decode a hex-encoded byte string into bytes.
///
/// Whitespace (space, tab, newline, carriage-return) is silently skipped.
/// Any other non-hex character is an error.
///
/// # Examples
///
/// ```
/// use plog_core::hex::decode;
/// assert_eq!(decode("deadbeef").unwrap(), &[0xde, 0xad, 0xbe, 0xef]);
/// assert_eq!(decode("de ad be ef").unwrap(), &[0xde, 0xad, 0xbe, 0xef]);
/// assert_eq!(decode("DE AD BE EF").unwrap(), &[0xde, 0xad, 0xbe, 0xef]);
/// ```
pub fn decode(input: &str) -> Result<Vec<u8>, Error> {
    decode_bytes(input.as_bytes())
}

/// Decode from a byte slice.
pub fn decode_bytes(input: &[u8]) -> Result<Vec<u8>, Error> {
    let mut out = Vec::with_capacity(input.len() / 2 + 1);
    let mut nibble: Option<u8> = None;

    for &b in input {
        let val = match b {
            b'0'..=b'9' => b - b'0',
            b'a'..=b'f' => b - b'a' + 10,
            b'A'..=b'F' => b - b'A' + 10,
            b' ' | b'\t' | b'\n' | b'\r' => continue,
            _ => {
                return Err(Error::HexDecode(format!(
                    "invalid hex character: {:?}",
                    b as char
                )))
            }
        };
        match nibble.take() {
            None => nibble = Some(val << 4),
            Some(hi) => out.push(hi | val),
        }
    }

    if nibble.is_some() {
        return Err(Error::HexDecode(
            "odd number of hex digits".to_string(),
        ));
    }

    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn basic() {
        assert_eq!(decode("deadbeef").unwrap(), &[0xde, 0xad, 0xbe, 0xef]);
    }

    #[test]
    fn with_spaces() {
        assert_eq!(
            decode("de ad be ef").unwrap(),
            &[0xde, 0xad, 0xbe, 0xef]
        );
    }

    #[test]
    fn uppercase() {
        assert_eq!(decode("DEADBEEF").unwrap(), &[0xde, 0xad, 0xbe, 0xef]);
    }

    #[test]
    fn empty() {
        assert_eq!(decode("").unwrap(), &[] as &[u8]);
    }

    #[test]
    fn odd_digits_error() {
        assert!(decode("abc").is_err());
    }

    #[test]
    fn invalid_char_error() {
        assert!(decode("zz").is_err());
    }
}
