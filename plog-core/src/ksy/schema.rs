//! Parses a `.ksy` YAML document into a [`TypeDef`] tree.
//!
//! Supports the subset of Kaitai Struct needed for real-world simple/medium
//! protocols: primitive integer/float/string/byte fields, `size`/`size-eos`,
//! `if` conditions, `repeat` (`expr`/`eos`/`until`), `contents` magic checks,
//! `enum` value naming, and user-defined nested types (including switch
//! types) referenced by name via `type:`.
use std::collections::HashMap;

use crate::ksy::expr::{self, Expr};
use crate::Error;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Endian {
    Little,
    Big,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PrimType {
    U1,
    U2,
    U4,
    U8,
    S1,
    S2,
    S4,
    S8,
    F4,
    F8,
    Str,
    StrZ,
}

impl PrimType {
    /// Fixed byte size, or `None` for variable-length (`str`/`strz`).
    pub fn fixed_size(self) -> Option<usize> {
        use PrimType::*;
        match self {
            U1 | S1 => Some(1),
            U2 | S2 => Some(2),
            U4 | S4 | F4 => Some(4),
            U8 | S8 | F8 => Some(8),
            Str | StrZ => None,
        }
    }

    fn parse(s: &str) -> Option<Self> {
        use PrimType::*;
        Some(match s {
            "u1" => U1,
            "u2" | "u2le" | "u2be" => U2,
            "u4" | "u4le" | "u4be" => U4,
            "u8" | "u8le" | "u8be" => U8,
            "s1" => S1,
            "s2" | "s2le" | "s2be" => S2,
            "s4" | "s4le" | "s4be" => S4,
            "s8" | "s8le" | "s8be" => S8,
            "f4" | "f4le" | "f4be" => F4,
            "f8" | "f8le" | "f8be" => F8,
            "str" => Str,
            "strz" => StrZ,
            _ => return None,
        })
    }

    /// A `u2le`/`u4be`/... suffix overrides the schema-wide endian for this field.
    fn endian_override(s: &str) -> Option<Endian> {
        if s.ends_with("le") && s.len() > 2 {
            Some(Endian::Little)
        } else if s.ends_with("be") && s.len() > 2 {
            Some(Endian::Big)
        } else {
            None
        }
    }
}

#[derive(Debug, Clone, PartialEq)]
pub enum TypeSpec {
    Primitive(PrimType),
    /// Reference to a type defined in the enclosing `types:` map (or an ancestor's).
    Named(String),
    /// `type: {switch-on: expr, cases: {value: type, ...}}`.
    Switch {
        on: Expr,
        cases: Vec<(SwitchCase, TypeSpec)>,
    },
}

#[derive(Debug, Clone, PartialEq)]
pub enum SwitchCase {
    Value(Expr),
    Default,
}

#[derive(Debug, Clone, PartialEq)]
pub enum RepeatSpec {
    Expr(Expr),
    Until(Expr),
    Eos,
}

#[derive(Debug, Clone)]
pub struct FieldDef {
    pub id: String,
    pub type_spec: Option<TypeSpec>,
    pub size: Option<Expr>,
    pub size_eos: bool,
    pub repeat: Option<RepeatSpec>,
    pub if_cond: Option<Expr>,
    pub encoding: Option<String>,
    pub contents: Option<Vec<u8>>,
    pub enum_name: Option<String>,
    /// Per-field endian override parsed from a `u2le`/`u4be`-style type suffix.
    pub endian_override: Option<Endian>,
}

#[derive(Debug, Clone, Default)]
pub struct TypeDef {
    pub seq: Vec<FieldDef>,
    /// Nested/user-defined types declared in this type's own `types:` map.
    pub types: HashMap<String, TypeDef>,
    /// `enums:` declared in this type's scope: name -> (value -> symbol).
    pub enums: HashMap<String, HashMap<i64, String>>,
}

#[derive(Debug, Clone)]
pub struct KsySchema {
    pub root: TypeDef,
    pub endian: Endian,
}

pub fn parse(source: &str) -> Result<KsySchema, Error> {
    let doc: serde_yaml::Value =
        serde_yaml::from_str(source).map_err(|e| Error::Protocol(format!("invalid YAML: {e}")))?;
    let mapping = doc
        .as_mapping()
        .ok_or_else(|| Error::Protocol("KSY document must be a YAML mapping".to_string()))?;

    let endian = mapping
        .get("meta")
        .and_then(|m| m.as_mapping())
        .and_then(|m| m.get("endian"))
        .and_then(|v| v.as_str())
        .map(|s| match s {
            "be" => Ok(Endian::Big),
            "le" => Ok(Endian::Little),
            other => Err(Error::Protocol(format!("unknown endian `{other}`"))),
        })
        .transpose()?
        .unwrap_or(Endian::Little);

    let root = parse_type_body(mapping)?;
    Ok(KsySchema { root, endian })
}

/// Parse the `seq`/`types`/`enums` keys shared by the root document and by
/// every entry in a `types:` map.
fn parse_type_body(mapping: &serde_yaml::Mapping) -> Result<TypeDef, Error> {
    let seq = match mapping.get("seq") {
        Some(serde_yaml::Value::Sequence(items)) => {
            items.iter().map(parse_field).collect::<Result<_, _>>()?
        }
        Some(_) => return Err(Error::Protocol("`seq` must be a YAML sequence".to_string())),
        None => Vec::new(),
    };

    let types = match mapping.get("types") {
        Some(serde_yaml::Value::Mapping(map)) => {
            let mut out = HashMap::new();
            for (name, def) in map {
                let name = name
                    .as_str()
                    .ok_or_else(|| Error::Protocol("type name must be a string".to_string()))?
                    .to_string();
                let def = def
                    .as_mapping()
                    .ok_or_else(|| Error::Protocol(format!("type `{name}` must be a mapping")))?;
                out.insert(name, parse_type_body(def)?);
            }
            out
        }
        Some(_) => {
            return Err(Error::Protocol(
                "`types` must be a YAML mapping".to_string(),
            ))
        }
        None => HashMap::new(),
    };

    let enums = match mapping.get("enums") {
        Some(serde_yaml::Value::Mapping(map)) => {
            let mut out = HashMap::new();
            for (name, values) in map {
                let name = name
                    .as_str()
                    .ok_or_else(|| Error::Protocol("enum name must be a string".to_string()))?
                    .to_string();
                let values = values
                    .as_mapping()
                    .ok_or_else(|| Error::Protocol(format!("enum `{name}` must be a mapping")))?;
                let mut symbols = HashMap::new();
                for (val, sym) in values {
                    let val = val.as_i64().ok_or_else(|| {
                        Error::Protocol(format!("enum `{name}` value must be an integer"))
                    })?;
                    let sym = sym
                        .as_str()
                        .ok_or_else(|| {
                            Error::Protocol(format!("enum `{name}` symbol must be a string"))
                        })?
                        .to_string();
                    symbols.insert(val, sym);
                }
                out.insert(name, symbols);
            }
            out
        }
        Some(_) => {
            return Err(Error::Protocol(
                "`enums` must be a YAML mapping".to_string(),
            ))
        }
        None => HashMap::new(),
    };

    Ok(TypeDef { seq, types, enums })
}

fn parse_field(value: &serde_yaml::Value) -> Result<FieldDef, Error> {
    let map = value
        .as_mapping()
        .ok_or_else(|| Error::Protocol("each `seq` entry must be a mapping".to_string()))?;

    let id = map
        .get("id")
        .and_then(|v| v.as_str())
        .ok_or_else(|| Error::Protocol("`seq` entry is missing a string `id`".to_string()))?
        .to_string();

    let mut endian_override = None;
    let type_spec = match map.get("type") {
        Some(serde_yaml::Value::String(s)) => {
            endian_override = PrimType::endian_override(s);
            match PrimType::parse(s) {
                Some(p) => Some(TypeSpec::Primitive(p)),
                None => Some(TypeSpec::Named(s.clone())),
            }
        }
        Some(serde_yaml::Value::Mapping(m)) => Some(parse_switch(m)?),
        Some(other) => {
            return Err(Error::Protocol(format!(
                "field `{id}`: unsupported `type` value {other:?}"
            )))
        }
        None => None,
    };

    let size =
        match map.get("size") {
            Some(serde_yaml::Value::Number(n)) => Some(Expr::Int(n.as_i64().ok_or_else(|| {
                Error::Protocol(format!("field `{id}`: `size` must be an integer"))
            })?)),
            Some(serde_yaml::Value::String(s)) => Some(expr::parse(s)?),
            Some(other) => {
                return Err(Error::Protocol(format!(
                    "field `{id}`: unsupported `size` value {other:?}"
                )))
            }
            None => None,
        };

    let size_eos = map
        .get("size-eos")
        .and_then(|v| v.as_bool())
        .unwrap_or(false);

    let if_cond = match map.get("if") {
        Some(serde_yaml::Value::String(s)) => Some(expr::parse(s)?),
        Some(other) => {
            return Err(Error::Protocol(format!(
                "field `{id}`: `if` must be a string expression, found {other:?}"
            )))
        }
        None => None,
    };

    let repeat = match map.get("repeat").and_then(|v| v.as_str()) {
        Some("expr") => {
            let e = match map.get("repeat-expr") {
                Some(serde_yaml::Value::String(s)) => expr::parse(s)?,
                Some(serde_yaml::Value::Number(n)) => Expr::Int(n.as_i64().ok_or_else(|| {
                    Error::Protocol(format!("field `{id}`: `repeat-expr` must be an integer"))
                })?),
                _ => {
                    return Err(Error::Protocol(format!(
                        "field `{id}`: `repeat: expr` needs `repeat-expr`"
                    )))
                }
            };
            Some(RepeatSpec::Expr(e))
        }
        Some("until") => {
            let e = map
                .get("repeat-until")
                .and_then(|v| v.as_str())
                .ok_or_else(|| {
                    Error::Protocol(format!(
                        "field `{id}`: `repeat: until` needs `repeat-until`"
                    ))
                })?;
            Some(RepeatSpec::Until(expr::parse(e)?))
        }
        Some("eos") => Some(RepeatSpec::Eos),
        Some(other) => {
            return Err(Error::Protocol(format!(
                "field `{id}`: unknown `repeat` mode `{other}`"
            )))
        }
        None => None,
    };

    let encoding = map
        .get("encoding")
        .and_then(|v| v.as_str())
        .map(|s| s.to_string());

    let contents = match map.get("contents") {
        Some(serde_yaml::Value::String(s)) => Some(s.as_bytes().to_vec()),
        Some(serde_yaml::Value::Sequence(items)) => Some(
            items
                .iter()
                .map(|v| {
                    v.as_i64()
                        .filter(|n| (0..=255).contains(n))
                        .map(|n| n as u8)
                        .ok_or_else(|| {
                            Error::Protocol(format!(
                                "field `{id}`: `contents` list entries must be bytes 0-255"
                            ))
                        })
                })
                .collect::<Result<_, _>>()?,
        ),
        Some(other) => {
            return Err(Error::Protocol(format!(
                "field `{id}`: unsupported `contents` value {other:?}"
            )))
        }
        None => None,
    };

    let enum_name = map
        .get("enum")
        .and_then(|v| v.as_str())
        .map(|s| s.to_string());

    Ok(FieldDef {
        id,
        type_spec,
        size,
        size_eos,
        repeat,
        if_cond,
        encoding,
        contents,
        enum_name,
        endian_override,
    })
}

fn parse_switch(map: &serde_yaml::Mapping) -> Result<TypeSpec, Error> {
    let on = map
        .get("switch-on")
        .and_then(|v| v.as_str())
        .ok_or_else(|| Error::Protocol("switch type is missing `switch-on`".to_string()))?;
    let on = expr::parse(on)?;

    let cases_map = map
        .get("cases")
        .and_then(|v| v.as_mapping())
        .ok_or_else(|| Error::Protocol("switch type is missing `cases` mapping".to_string()))?;

    let mut cases = Vec::new();
    for (key, val) in cases_map {
        let case = match key {
            serde_yaml::Value::String(s) if s == "_" => SwitchCase::Default,
            serde_yaml::Value::String(s) => SwitchCase::Value(expr::parse(s)?),
            serde_yaml::Value::Number(n) => {
                SwitchCase::Value(Expr::Int(n.as_i64().ok_or_else(|| {
                    Error::Protocol("switch case key must be an integer".to_string())
                })?))
            }
            other => {
                return Err(Error::Protocol(format!(
                    "unsupported switch case key {other:?}"
                )))
            }
        };
        let type_spec = match val {
            serde_yaml::Value::String(s) => match PrimType::parse(s) {
                Some(p) => TypeSpec::Primitive(p),
                None => TypeSpec::Named(s.clone()),
            },
            other => {
                return Err(Error::Protocol(format!(
                    "unsupported switch case value {other:?}"
                )))
            }
        };
        cases.push((case, type_spec));
    }

    Ok(TypeSpec::Switch { on, cases })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_meta_endian() {
        let schema = parse("meta:\n  endian: be\nseq: []\n").unwrap();
        assert_eq!(schema.endian, Endian::Big);
    }

    #[test]
    fn defaults_to_little_endian() {
        let schema = parse("meta:\n  id: x\nseq: []\n").unwrap();
        assert_eq!(schema.endian, Endian::Little);
    }

    #[test]
    fn parses_primitive_seq_fields() {
        let schema = parse(
            "seq:\n  - id: magic\n    type: u1\n  - id: length\n    type: u2\n  - id: payload\n    size: length\n",
        )
        .unwrap();
        assert_eq!(schema.root.seq.len(), 3);
        assert_eq!(
            schema.root.seq[0].type_spec,
            Some(TypeSpec::Primitive(PrimType::U1))
        );
        assert!(schema.root.seq[2].size.is_some());
    }

    #[test]
    fn parses_nested_named_type() {
        let schema = parse(
            "seq:\n  - id: header\n    type: header\ntypes:\n  header:\n    seq:\n      - id: magic\n        type: u1\n",
        )
        .unwrap();
        assert_eq!(
            schema.root.seq[0].type_spec,
            Some(TypeSpec::Named("header".to_string()))
        );
        assert!(schema.root.types.contains_key("header"));
    }

    #[test]
    fn parses_repeat_and_if_and_contents() {
        let schema = parse(
            "seq:\n  - id: magic\n    contents: [0xAA, 0x01]\n  - id: flag\n    type: u1\n  - id: extra\n    type: u1\n    if: flag != 0\n  - id: items\n    type: u1\n    repeat: until\n    repeat-until: _ == 0\n",
        )
        .unwrap();
        assert_eq!(schema.root.seq[0].contents, Some(vec![0xAA, 0x01]));
        assert!(schema.root.seq[2].if_cond.is_some());
        assert!(matches!(
            schema.root.seq[3].repeat,
            Some(RepeatSpec::Until(_))
        ));
    }

    #[test]
    fn parses_switch_type() {
        let schema = parse(
            "seq:\n  - id: kind\n    type: u1\n  - id: body\n    type:\n      switch-on: kind\n      cases:\n        1: u1\n        2: u2\n        _: u1\n",
        )
        .unwrap();
        match &schema.root.seq[1].type_spec {
            Some(TypeSpec::Switch { cases, .. }) => assert_eq!(cases.len(), 3),
            other => panic!("expected switch type, got {other:?}"),
        }
    }

    #[test]
    fn parses_enums() {
        let schema = parse(
            "seq:\n  - id: cmd\n    type: u1\n    enum: command\nenums:\n  command:\n    1: start\n    2: stop\n",
        )
        .unwrap();
        assert_eq!(schema.root.seq[0].enum_name, Some("command".to_string()));
        assert_eq!(
            schema.root.enums.get("command").unwrap().get(&1),
            Some(&"start".to_string())
        );
    }

    #[test]
    fn rejects_non_mapping_document() {
        assert!(parse("- 1\n- 2\n").is_err());
    }
}
