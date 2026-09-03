//! Runtime interpreter: walks a [`TypeDef`] tree and consumes bytes from a
//! cursor to produce [`Value`]s, honoring `if`, `repeat`, `size`, `contents`,
//! `enum`, nested/user-defined types, and switch types.
use indexmap::IndexMap;

use crate::ksy::expr::{self, EvalScope};
use crate::ksy::schema::{Endian, FieldDef, PrimType, RepeatSpec, SwitchCase, TypeDef, TypeSpec};
use crate::result::Value;
use crate::Error;

struct Cursor<'a> {
    bytes: &'a [u8],
    pos: usize,
}

impl<'a> Cursor<'a> {
    fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, pos: 0 }
    }

    fn remaining(&self) -> usize {
        self.bytes.len() - self.pos
    }

    fn read(&mut self, n: usize, field_id: &str) -> Result<&'a [u8], Error> {
        if self.pos + n > self.bytes.len() {
            return Err(Error::Protocol(format!(
                "unexpected end of data while reading field `{field_id}` ({n} bytes needed, {} available)",
                self.remaining()
            )));
        }
        let slice = &self.bytes[self.pos..self.pos + n];
        self.pos += n;
        Ok(slice)
    }
}

/// Decode `bytes` according to the schema's root type.
pub fn decode_root(
    root: &TypeDef,
    endian: Endian,
    bytes: &[u8],
) -> Result<IndexMap<String, Value>, Error> {
    let mut cursor = Cursor::new(bytes);
    decode_type(root, root, endian, &mut cursor)
}

fn decode_type(
    type_def: &TypeDef,
    root: &TypeDef,
    endian: Endian,
    cursor: &mut Cursor,
) -> Result<IndexMap<String, Value>, Error> {
    let mut fields: IndexMap<String, Value> = IndexMap::new();

    for field in &type_def.seq {
        if let Some(cond) = &field.if_cond {
            let scope = EvalScope {
                fields: &fields,
                current: None,
            };
            if !expr::eval_bool(cond, &scope)? {
                continue;
            }
        }

        let value = match &field.repeat {
            None => decode_field_value(field, type_def, root, endian, cursor, &fields)?,
            Some(RepeatSpec::Expr(count_expr)) => {
                let scope = EvalScope {
                    fields: &fields,
                    current: None,
                };
                let count = expr::eval_usize(count_expr, &scope)?;
                let mut items = Vec::with_capacity(count);
                for _ in 0..count {
                    items.push(decode_field_value(
                        field, type_def, root, endian, cursor, &fields,
                    )?);
                }
                Value::Array(items)
            }
            Some(RepeatSpec::Eos) => {
                let mut items = Vec::new();
                while cursor.remaining() > 0 {
                    items.push(decode_field_value(
                        field, type_def, root, endian, cursor, &fields,
                    )?);
                }
                Value::Array(items)
            }
            Some(RepeatSpec::Until(until_expr)) => {
                let mut items = Vec::new();
                loop {
                    let item = decode_field_value(field, type_def, root, endian, cursor, &fields)?;
                    let scope = EvalScope {
                        fields: &fields,
                        current: Some(&item),
                    };
                    let stop = expr::eval_bool(until_expr, &scope)?;
                    items.push(item);
                    if stop {
                        break;
                    }
                    if cursor.remaining() == 0 {
                        return Err(Error::Protocol(format!(
                            "field `{}`: `repeat-until` condition never became true before end of data",
                            field.id
                        )));
                    }
                }
                Value::Array(items)
            }
        };

        fields.insert(field.id.clone(), value);
    }

    Ok(fields)
}

/// Decode a single (non-repeated) occurrence of `field`.
fn decode_field_value(
    field: &FieldDef,
    type_def: &TypeDef,
    root: &TypeDef,
    endian: Endian,
    cursor: &mut Cursor,
    fields_so_far: &IndexMap<String, Value>,
) -> Result<Value, Error> {
    if let Some(expected) = &field.contents {
        let actual = cursor.read(expected.len(), &field.id)?;
        if actual != expected.as_slice() {
            return Err(Error::Protocol(format!(
                "field `{}`: magic bytes mismatch: expected {expected:02x?}, found {actual:02x?}",
                field.id
            )));
        }
        return Ok(Value::Bytes(actual.to_vec()));
    }

    let effective_endian = field.endian_override.unwrap_or(endian);
    let byte_len = resolve_size(field, cursor, fields_so_far)?;

    let type_spec = field.type_spec.as_ref();
    let value = decode_by_type_spec(
        type_spec,
        byte_len,
        field.encoding.as_deref(),
        type_def,
        root,
        effective_endian,
        cursor,
        &field.id,
        fields_so_far,
    )?;

    Ok(apply_enum(value, field, type_def, root))
}

/// Resolve how many bytes this field occupies, if determinable up front
/// (raw/`str` fields and sized nested types need this; fixed-size
/// primitives ignore it).
fn resolve_size(
    field: &FieldDef,
    cursor: &Cursor,
    fields_so_far: &IndexMap<String, Value>,
) -> Result<Option<usize>, Error> {
    if field.size_eos {
        return Ok(Some(cursor.remaining()));
    }
    if let Some(size_expr) = &field.size {
        let scope = EvalScope {
            fields: fields_so_far,
            current: None,
        };
        return Ok(Some(expr::eval_usize(size_expr, &scope)?));
    }
    Ok(None)
}

#[allow(clippy::too_many_arguments)]
fn decode_by_type_spec(
    type_spec: Option<&TypeSpec>,
    byte_len: Option<usize>,
    encoding: Option<&str>,
    type_def: &TypeDef,
    root: &TypeDef,
    endian: Endian,
    cursor: &mut Cursor,
    field_id: &str,
    fields_so_far: &IndexMap<String, Value>,
) -> Result<Value, Error> {
    match type_spec {
        None => {
            let n = byte_len.ok_or_else(|| {
                Error::Protocol(format!(
                    "field `{field_id}`: needs a `type`, or a `size`/`size-eos` for raw bytes"
                ))
            })?;
            Ok(Value::Bytes(cursor.read(n, field_id)?.to_vec()))
        }
        Some(TypeSpec::Primitive(prim)) => {
            read_primitive(*prim, byte_len, encoding, endian, cursor, field_id)
        }
        Some(TypeSpec::Named(name)) => {
            let nested_def = type_def
                .types
                .get(name)
                .or_else(|| root.types.get(name))
                .ok_or_else(|| Error::Protocol(format!("unknown type reference `{name}`")))?;
            match byte_len {
                Some(n) => {
                    let slice = cursor.read(n, field_id)?;
                    let mut sub = Cursor::new(slice);
                    let nested_fields = decode_type(nested_def, root, endian, &mut sub)?;
                    Ok(Value::Struct(nested_fields))
                }
                None => {
                    let nested_fields = decode_type(nested_def, root, endian, cursor)?;
                    Ok(Value::Struct(nested_fields))
                }
            }
        }
        Some(TypeSpec::Switch { on, cases }) => {
            let scope = EvalScope {
                fields: fields_so_far,
                current: None,
            };
            let on_value = expr::eval(on, &scope)?;
            let matched = cases
                .iter()
                .find(|(case, _)| match case {
                    SwitchCase::Default => true,
                    SwitchCase::Value(e) => expr::eval(e, &scope)
                        .map(|v| expr::values_equal(&v, &on_value))
                        .unwrap_or(false),
                })
                .map(|(_, spec)| spec)
                .ok_or_else(|| {
                    Error::Protocol(format!(
                        "field `{field_id}`: no switch case matches value {on_value:?}"
                    ))
                })?;
            decode_by_type_spec(
                Some(matched),
                byte_len,
                encoding,
                type_def,
                root,
                endian,
                cursor,
                field_id,
                fields_so_far,
            )
        }
    }
}

fn read_primitive(
    prim: PrimType,
    byte_len: Option<usize>,
    encoding: Option<&str>,
    endian: Endian,
    cursor: &mut Cursor,
    field_id: &str,
) -> Result<Value, Error> {
    match prim {
        PrimType::Str => {
            let n = byte_len.ok_or_else(|| {
                Error::Protocol(format!(
                    "field `{field_id}`: `str` type needs a `size` or `size-eos`"
                ))
            })?;
            let bytes = cursor.read(n, field_id)?;
            Ok(Value::Str(decode_string(bytes, encoding, field_id)?))
        }
        PrimType::StrZ => {
            let start = cursor.pos;
            let end = cursor.bytes[start..]
                .iter()
                .position(|&b| b == 0)
                .map(|i| start + i)
                .unwrap_or(cursor.bytes.len());
            let bytes = cursor.read(end - start, field_id)?;
            if end < cursor.bytes.len() {
                cursor.pos += 1; // consume the NUL terminator
            }
            Ok(Value::Str(decode_string(bytes, encoding, field_id)?))
        }
        _ => {
            let n = prim
                .fixed_size()
                .expect("non-string primitives always have a fixed size");
            let bytes = cursor.read(n, field_id)?;
            Ok(read_number(prim, bytes, endian))
        }
    }
}

fn decode_string(bytes: &[u8], encoding: Option<&str>, field_id: &str) -> Result<String, Error> {
    let is_ascii = matches!(
        encoding.map(|e| e.to_ascii_uppercase()).as_deref(),
        Some("ASCII")
    );
    if is_ascii && !bytes.is_ascii() {
        return Err(Error::Protocol(format!(
            "field `{field_id}`: expected ASCII, found non-ASCII bytes"
        )));
    }
    std::str::from_utf8(bytes)
        .map(str::to_string)
        .map_err(|e| Error::Protocol(format!("field `{field_id}`: invalid string encoding: {e}")))
}

fn read_number(prim: PrimType, bytes: &[u8], endian: Endian) -> Value {
    let raw = match endian {
        Endian::Little => {
            let mut buf = [0u8; 8];
            buf[..bytes.len()].copy_from_slice(bytes);
            u64::from_le_bytes(buf)
        }
        Endian::Big => {
            let mut buf = [0u8; 8];
            buf[8 - bytes.len()..].copy_from_slice(bytes);
            u64::from_be_bytes(buf)
        }
    };

    match prim {
        PrimType::U1 | PrimType::U2 | PrimType::U4 | PrimType::U8 => Value::UnsignedInteger(raw),
        PrimType::S1 => Value::Integer(raw as u8 as i8 as i64),
        PrimType::S2 => Value::Integer(raw as u16 as i16 as i64),
        PrimType::S4 => Value::Integer(raw as u32 as i32 as i64),
        PrimType::S8 => Value::Integer(raw as i64),
        PrimType::F4 => Value::Float(f32::from_bits(raw as u32) as f64),
        PrimType::F8 => Value::Float(f64::from_bits(raw)),
        PrimType::Str | PrimType::StrZ => unreachable!("handled separately"),
    }
}

fn apply_enum(value: Value, field: &FieldDef, type_def: &TypeDef, root: &TypeDef) -> Value {
    let Some(enum_name) = &field.enum_name else {
        return value;
    };
    let Some(table) = type_def
        .enums
        .get(enum_name)
        .or_else(|| root.enums.get(enum_name))
    else {
        return value;
    };
    let numeric = match &value {
        Value::Integer(n) => Some(*n),
        Value::UnsignedInteger(n) => Some(*n as i64),
        _ => None,
    };
    match numeric.and_then(|n| table.get(&n)) {
        Some(symbol) => Value::Str(symbol.clone()),
        None => value,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ksy::schema;

    fn decode(source: &str, bytes: &[u8]) -> IndexMap<String, Value> {
        let schema = schema::parse(source).unwrap();
        decode_root(&schema.root, schema.endian, bytes).unwrap()
    }

    #[test]
    fn decodes_fixed_primitives_little_endian() {
        let fields = decode(
            "meta:\n  endian: le\nseq:\n  - id: a\n    type: u1\n  - id: b\n    type: u2\n  - id: c\n    type: u4\n",
            &[0x01, 0x02, 0x00, 0x03, 0x00, 0x00, 0x00],
        );
        assert_eq!(fields["a"], Value::UnsignedInteger(1));
        assert_eq!(fields["b"], Value::UnsignedInteger(2));
        assert_eq!(fields["c"], Value::UnsignedInteger(3));
    }

    #[test]
    fn decodes_big_endian() {
        let fields = decode(
            "meta:\n  endian: be\nseq:\n  - id: a\n    type: u2\n",
            &[0x01, 0x02],
        );
        assert_eq!(fields["a"], Value::UnsignedInteger(0x0102));
    }

    #[test]
    fn signed_integers_sign_extend() {
        let fields = decode("seq:\n  - id: a\n    type: s1\n", &[0xFF]);
        assert_eq!(fields["a"], Value::Integer(-1));
    }

    #[test]
    fn size_expression_references_sibling_field() {
        let fields = decode(
            "seq:\n  - id: length\n    type: u1\n  - id: payload\n    size: length\n",
            &[0x03, b'A', b'B', b'C'],
        );
        assert_eq!(fields["payload"], Value::Bytes(vec![b'A', b'B', b'C']));
    }

    #[test]
    fn truncated_payload_is_an_error() {
        let schema = schema::parse(
            "seq:\n  - id: length\n    type: u1\n  - id: payload\n    size: length\n",
        )
        .unwrap();
        let err = decode_root(&schema.root, schema.endian, &[0x05, b'A']).unwrap_err();
        assert!(err.to_string().contains("unexpected end of data"));
    }

    #[test]
    fn if_condition_skips_field() {
        let fields = decode(
            "seq:\n  - id: flag\n    type: u1\n  - id: extra\n    type: u1\n    if: flag != 0\n",
            &[0x00],
        );
        assert!(!fields.contains_key("extra"));
    }

    #[test]
    fn if_condition_includes_field_when_true() {
        let fields = decode(
            "seq:\n  - id: flag\n    type: u1\n  - id: extra\n    type: u1\n    if: flag != 0\n",
            &[0x01, 0x09],
        );
        assert_eq!(fields["extra"], Value::UnsignedInteger(9));
    }

    #[test]
    fn repeat_expr_reads_fixed_count() {
        let fields = decode(
            "seq:\n  - id: count\n    type: u1\n  - id: items\n    type: u1\n    repeat: expr\n    repeat-expr: count\n",
            &[0x03, 1, 2, 3],
        );
        assert_eq!(
            fields["items"],
            Value::Array(vec![
                Value::UnsignedInteger(1),
                Value::UnsignedInteger(2),
                Value::UnsignedInteger(3)
            ])
        );
    }

    #[test]
    fn repeat_eos_reads_until_end_of_data() {
        let fields = decode(
            "seq:\n  - id: items\n    type: u1\n    repeat: eos\n",
            &[1, 2, 3],
        );
        assert_eq!(
            fields["items"],
            Value::Array(vec![
                Value::UnsignedInteger(1),
                Value::UnsignedInteger(2),
                Value::UnsignedInteger(3)
            ])
        );
    }

    #[test]
    fn repeat_until_stops_on_condition() {
        let fields = decode(
            "seq:\n  - id: items\n    type: u1\n    repeat: until\n    repeat-until: _ == 0\n",
            &[5, 6, 0, 9, 9],
        );
        assert_eq!(
            fields["items"],
            Value::Array(vec![
                Value::UnsignedInteger(5),
                Value::UnsignedInteger(6),
                Value::UnsignedInteger(0),
            ])
        );
    }

    #[test]
    fn nested_named_type_shares_stream() {
        let fields = decode(
            "seq:\n  - id: header\n    type: header\n  - id: rest\n    type: u1\ntypes:\n  header:\n    seq:\n      - id: magic\n        type: u1\n",
            &[0xAA, 0x42],
        );
        let Value::Struct(header) = &fields["header"] else {
            panic!("expected struct");
        };
        assert_eq!(header["magic"], Value::UnsignedInteger(0xAA));
        assert_eq!(fields["rest"], Value::UnsignedInteger(0x42));
    }

    #[test]
    fn nested_named_type_with_size_bounds_substream() {
        let schema = schema::parse(
            "seq:\n  - id: header\n    type: header\n    size: 1\n  - id: rest\n    type: u1\ntypes:\n  header:\n    seq:\n      - id: magic\n        type: u2\n",
        )
        .unwrap();
        // `header` is only given 1 byte, but its own `u2` field needs 2 —
        // the bounded substream must reject the truncated read.
        let err = decode_root(&schema.root, schema.endian, &[0xAA, 0x99]).unwrap_err();
        assert!(err.to_string().contains("unexpected end of data"));
    }

    #[test]
    fn switch_type_picks_matching_case() {
        let fields = decode(
            "seq:\n  - id: kind\n    type: u1\n  - id: body\n    type:\n      switch-on: kind\n      cases:\n        1: u1\n        2: u2\n",
            &[0x02, 0x34, 0x12],
        );
        assert_eq!(fields["body"], Value::UnsignedInteger(0x1234));
    }

    #[test]
    fn switch_type_default_case() {
        let fields = decode(
            "seq:\n  - id: kind\n    type: u1\n  - id: body\n    type:\n      switch-on: kind\n      cases:\n        1: u1\n        _: u2\n",
            &[0x09, 0x34, 0x12],
        );
        assert_eq!(fields["body"], Value::UnsignedInteger(0x1234));
    }

    #[test]
    fn contents_magic_matches() {
        let fields = decode(
            "seq:\n  - id: magic\n    contents: [0xAA, 0x55]\n",
            &[0xAA, 0x55],
        );
        assert_eq!(fields["magic"], Value::Bytes(vec![0xAA, 0x55]));
    }

    #[test]
    fn contents_magic_mismatch_is_an_error() {
        let schema = schema::parse("seq:\n  - id: magic\n    contents: [0xAA, 0x55]\n").unwrap();
        let err = decode_root(&schema.root, schema.endian, &[0xAA, 0x00]).unwrap_err();
        assert!(err.to_string().contains("magic bytes mismatch"));
    }

    #[test]
    fn enum_maps_integer_to_symbol() {
        let fields = decode(
            "seq:\n  - id: cmd\n    type: u1\n    enum: command\nenums:\n  command:\n    1: start\n    2: stop\n",
            &[0x02],
        );
        assert_eq!(fields["cmd"], Value::Str("stop".to_string()));
    }

    #[test]
    fn enum_unknown_value_keeps_integer() {
        let fields = decode(
            "seq:\n  - id: cmd\n    type: u1\n    enum: command\nenums:\n  command:\n    1: start\n",
            &[0x09],
        );
        assert_eq!(fields["cmd"], Value::UnsignedInteger(9));
    }

    #[test]
    fn str_type_decodes_utf8_with_size() {
        let fields = decode(
            "seq:\n  - id: name\n    type: str\n    size: 5\n    encoding: UTF-8\n",
            b"HELLO",
        );
        assert_eq!(fields["name"], Value::Str("HELLO".to_string()));
    }

    #[test]
    fn strz_reads_until_nul() {
        let fields = decode(
            "seq:\n  - id: name\n    type: strz\n  - id: after\n    type: u1\n",
            b"HI\x00\x07",
        );
        assert_eq!(fields["name"], Value::Str("HI".to_string()));
        assert_eq!(fields["after"], Value::UnsignedInteger(7));
    }

    #[test]
    fn raw_bytes_field_without_type() {
        let fields = decode("seq:\n  - id: payload\n    size: 3\n", &[1, 2, 3]);
        assert_eq!(fields["payload"], Value::Bytes(vec![1, 2, 3]));
    }

    #[test]
    fn float_fields_decode() {
        let fields = decode(
            "meta:\n  endian: le\nseq:\n  - id: a\n    type: f4\n",
            &1.5f32.to_le_bytes(),
        );
        assert_eq!(fields["a"], Value::Float(1.5));
    }
}
