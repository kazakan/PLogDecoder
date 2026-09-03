//! A minimal subset of the Kaitai Struct Expression Language (KSEL).
//!
//! Supports the constructs commonly needed by `if`, `size`, `repeat-expr`
//! and `repeat-until`: integer/hex/bool literals, dotted field references,
//! arithmetic, comparisons, bitwise ops, and `and`/`or`/`not`.
use indexmap::IndexMap;

use crate::result::Value;
use crate::Error;

#[derive(Debug, Clone, PartialEq)]
pub enum Expr {
    Int(i64),
    Bool(bool),
    Str(String),
    /// Dotted field reference, e.g. `header.length`. A single `_` element
    /// refers to the current element in a `repeat-until` loop.
    Field(Vec<String>),
    Unary(UnOp, Box<Expr>),
    Binary(BinOp, Box<Expr>, Box<Expr>),
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum UnOp {
    Neg,
    Not,
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum BinOp {
    Add,
    Sub,
    Mul,
    Div,
    Mod,
    Eq,
    Ne,
    Lt,
    Le,
    Gt,
    Ge,
    And,
    Or,
    BitAnd,
    BitOr,
    BitXor,
    Shl,
    Shr,
}

/// The values visible while evaluating an expression: sibling fields parsed
/// so far in the enclosing struct, plus the current loop element (`_`) when
/// evaluating a `repeat-until` condition.
pub struct EvalScope<'a> {
    pub fields: &'a IndexMap<String, Value>,
    pub current: Option<&'a Value>,
}

pub fn parse(source: &str) -> Result<Expr, Error> {
    let tokens = lex(source)?;
    let mut parser = Parser { tokens, pos: 0 };
    let expr = parser.parse_or()?;
    parser.expect_eof()?;
    Ok(expr)
}

pub fn eval(expr: &Expr, scope: &EvalScope) -> Result<Value, Error> {
    match expr {
        Expr::Int(n) => Ok(Value::Integer(*n)),
        Expr::Bool(b) => Ok(Value::Boolean(*b)),
        Expr::Str(s) => Ok(Value::Str(s.clone())),
        Expr::Field(path) => lookup(path, scope),
        Expr::Unary(op, inner) => {
            let v = eval(inner, scope)?;
            match op {
                UnOp::Neg => Ok(Value::Integer(-as_i64(&v)?)),
                UnOp::Not => Ok(Value::Boolean(!as_bool(&v))),
            }
        }
        Expr::Binary(op, lhs, rhs) => {
            let l = eval(lhs, scope)?;
            match op {
                BinOp::And => {
                    if !as_bool(&l) {
                        return Ok(Value::Boolean(false));
                    }
                    Ok(Value::Boolean(as_bool(&eval(rhs, scope)?)))
                }
                BinOp::Or => {
                    if as_bool(&l) {
                        return Ok(Value::Boolean(true));
                    }
                    Ok(Value::Boolean(as_bool(&eval(rhs, scope)?)))
                }
                _ => {
                    let r = eval(rhs, scope)?;
                    eval_binary(*op, &l, &r)
                }
            }
        }
    }
}

/// Evaluate an expression in a boolean context (an `if` or `repeat-until` condition).
pub fn eval_bool(expr: &Expr, scope: &EvalScope) -> Result<bool, Error> {
    Ok(as_bool(&eval(expr, scope)?))
}

/// Evaluate an expression that must produce a non-negative byte count (a `size`).
pub fn eval_usize(expr: &Expr, scope: &EvalScope) -> Result<usize, Error> {
    let n = as_i64(&eval(expr, scope)?)?;
    if n < 0 {
        return Err(Error::Protocol(format!(
            "size expression evaluated to negative value: {n}"
        )));
    }
    Ok(n as usize)
}

fn eval_binary(op: BinOp, l: &Value, r: &Value) -> Result<Value, Error> {
    use BinOp::*;
    match op {
        Eq => Ok(Value::Boolean(values_equal(l, r))),
        Ne => Ok(Value::Boolean(!values_equal(l, r))),
        Lt | Le | Gt | Ge => {
            let (a, b) = (as_i64(l)?, as_i64(r)?);
            let result = match op {
                Lt => a < b,
                Le => a <= b,
                Gt => a > b,
                Ge => a >= b,
                _ => unreachable!(),
            };
            Ok(Value::Boolean(result))
        }
        Add | Sub | Mul | Div | Mod | BitAnd | BitOr | BitXor | Shl | Shr => {
            let (a, b) = (as_i64(l)?, as_i64(r)?);
            let result = match op {
                Add => a.wrapping_add(b),
                Sub => a.wrapping_sub(b),
                Mul => a.wrapping_mul(b),
                Div => {
                    if b == 0 {
                        return Err(Error::Protocol(
                            "division by zero in expression".to_string(),
                        ));
                    }
                    a / b
                }
                Mod => {
                    if b == 0 {
                        return Err(Error::Protocol("modulo by zero in expression".to_string()));
                    }
                    a % b
                }
                BitAnd => a & b,
                BitOr => a | b,
                BitXor => a ^ b,
                Shl => a.wrapping_shl(b as u32),
                Shr => a.wrapping_shr(b as u32),
                _ => unreachable!(),
            };
            Ok(Value::Integer(result))
        }
        And | Or => unreachable!("handled with short-circuit evaluation"),
    }
}

/// Numeric-aware equality (`Integer(2) == UnsignedInteger(2)`), used for
/// switch-type case matching as well as the `==`/`!=` operators.
pub(crate) fn values_equal(l: &Value, r: &Value) -> bool {
    if let (Ok(a), Ok(b)) = (as_i64(l), as_i64(r)) {
        return a == b;
    }
    match (l, r) {
        (Value::Str(a), Value::Str(b)) => a == b,
        (Value::Boolean(a), Value::Boolean(b)) => a == b,
        _ => l == r,
    }
}

fn as_bool(v: &Value) -> bool {
    match v {
        Value::Boolean(b) => *b,
        Value::Integer(n) => *n != 0,
        Value::UnsignedInteger(n) => *n != 0,
        _ => false,
    }
}

fn as_i64(v: &Value) -> Result<i64, Error> {
    match v {
        Value::Integer(n) => Ok(*n),
        Value::UnsignedInteger(n) => Ok(*n as i64),
        Value::Boolean(b) => Ok(*b as i64),
        other => Err(Error::Protocol(format!(
            "expected an integer in expression, found {other:?}"
        ))),
    }
}

fn lookup(path: &[String], scope: &EvalScope) -> Result<Value, Error> {
    if path.first().map(String::as_str) == Some("_") && path.len() == 1 {
        return scope
            .current
            .cloned()
            .ok_or_else(|| Error::Protocol("`_` is not available in this context".to_string()));
    }

    let (head, rest) = path
        .split_first()
        .ok_or_else(|| Error::Protocol("empty field reference".to_string()))?;
    let mut value = scope
        .fields
        .get(head)
        .cloned()
        .ok_or_else(|| Error::Protocol(format!("unknown field reference: `{head}`")))?;

    for part in rest {
        value = match value {
            Value::Struct(map) => map.get(part).cloned().ok_or_else(|| {
                Error::Protocol(format!("unknown nested field reference: `{part}`"))
            })?,
            other => {
                return Err(Error::Protocol(format!(
                    "cannot access field `{part}` on non-struct value {other:?}"
                )))
            }
        };
    }
    Ok(value)
}

// ---------------------------------------------------------------------------
// Tokenizer
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq)]
enum Token {
    Int(i64),
    Str(String),
    Ident(String),
    Dot,
    LParen,
    RParen,
    Op(&'static str),
}

fn lex(source: &str) -> Result<Vec<Token>, Error> {
    let chars: Vec<char> = source.chars().collect();
    let mut tokens = Vec::new();
    let mut i = 0;
    while i < chars.len() {
        let c = chars[i];
        if c.is_whitespace() {
            i += 1;
            continue;
        }
        if c == '(' {
            tokens.push(Token::LParen);
            i += 1;
        } else if c == ')' {
            tokens.push(Token::RParen);
            i += 1;
        } else if c == '.' {
            tokens.push(Token::Dot);
            i += 1;
        } else if c == '"' || c == '\'' {
            let quote = c;
            let mut s = String::new();
            i += 1;
            while i < chars.len() && chars[i] != quote {
                s.push(chars[i]);
                i += 1;
            }
            if i >= chars.len() {
                return Err(Error::Protocol(
                    "unterminated string literal in expression".to_string(),
                ));
            }
            i += 1;
            tokens.push(Token::Str(s));
        } else if c.is_ascii_digit() {
            let start = i;
            if c == '0' && chars.get(i + 1) == Some(&'x') {
                i += 2;
                let hex_start = i;
                while i < chars.len() && chars[i].is_ascii_hexdigit() {
                    i += 1;
                }
                let n = i64::from_str_radix(&chars[hex_start..i].iter().collect::<String>(), 16)
                    .map_err(|e| Error::Protocol(format!("invalid hex literal: {e}")))?;
                tokens.push(Token::Int(n));
            } else {
                while i < chars.len() && chars[i].is_ascii_digit() {
                    i += 1;
                }
                let n: i64 = chars[start..i]
                    .iter()
                    .collect::<String>()
                    .parse()
                    .map_err(|e| Error::Protocol(format!("invalid integer literal: {e}")))?;
                tokens.push(Token::Int(n));
            }
        } else if c.is_alphabetic() || c == '_' {
            let start = i;
            while i < chars.len() && (chars[i].is_alphanumeric() || chars[i] == '_') {
                i += 1;
            }
            let word: String = chars[start..i].iter().collect();
            tokens.push(Token::Ident(word));
        } else {
            let two: String = chars[i..(i + 2).min(chars.len())].iter().collect();
            match two.as_str() {
                "==" | "!=" | "<=" | ">=" | "<<" | ">>" => {
                    tokens.push(Token::Op(match two.as_str() {
                        "==" => "==",
                        "!=" => "!=",
                        "<=" => "<=",
                        ">=" => ">=",
                        "<<" => "<<",
                        ">>" => ">>",
                        _ => unreachable!(),
                    }));
                    i += 2;
                }
                _ => {
                    let op = match c {
                        '+' => "+",
                        '-' => "-",
                        '*' => "*",
                        '/' => "/",
                        '%' => "%",
                        '<' => "<",
                        '>' => ">",
                        '&' => "&",
                        '|' => "|",
                        '^' => "^",
                        other => {
                            return Err(Error::Protocol(format!(
                                "unexpected character `{other}` in expression"
                            )))
                        }
                    };
                    tokens.push(Token::Op(op));
                    i += 1;
                }
            }
        }
    }
    Ok(tokens)
}

// ---------------------------------------------------------------------------
// Recursive-descent parser (precedence climbing)
// ---------------------------------------------------------------------------

struct Parser {
    tokens: Vec<Token>,
    pos: usize,
}

impl Parser {
    fn peek(&self) -> Option<&Token> {
        self.tokens.get(self.pos)
    }

    fn advance(&mut self) -> Option<Token> {
        let t = self.tokens.get(self.pos).cloned();
        self.pos += 1;
        t
    }

    fn expect_eof(&self) -> Result<(), Error> {
        if self.pos == self.tokens.len() {
            Ok(())
        } else {
            Err(Error::Protocol(format!(
                "unexpected trailing tokens in expression starting at {:?}",
                self.tokens[self.pos]
            )))
        }
    }

    fn parse_or(&mut self) -> Result<Expr, Error> {
        let mut lhs = self.parse_and()?;
        while matches!(self.peek(), Some(Token::Ident(w)) if w == "or") {
            self.advance();
            let rhs = self.parse_and()?;
            lhs = Expr::Binary(BinOp::Or, Box::new(lhs), Box::new(rhs));
        }
        Ok(lhs)
    }

    fn parse_and(&mut self) -> Result<Expr, Error> {
        let mut lhs = self.parse_not()?;
        while matches!(self.peek(), Some(Token::Ident(w)) if w == "and") {
            self.advance();
            let rhs = self.parse_not()?;
            lhs = Expr::Binary(BinOp::And, Box::new(lhs), Box::new(rhs));
        }
        Ok(lhs)
    }

    fn parse_not(&mut self) -> Result<Expr, Error> {
        if matches!(self.peek(), Some(Token::Ident(w)) if w == "not") {
            self.advance();
            let inner = self.parse_not()?;
            return Ok(Expr::Unary(UnOp::Not, Box::new(inner)));
        }
        self.parse_cmp()
    }

    fn parse_cmp(&mut self) -> Result<Expr, Error> {
        let lhs = self.parse_bitor()?;
        if let Some(Token::Op(op @ ("==" | "!=" | "<" | "<=" | ">" | ">="))) = self.peek().cloned()
        {
            self.advance();
            let rhs = self.parse_bitor()?;
            let bin_op = match op {
                "==" => BinOp::Eq,
                "!=" => BinOp::Ne,
                "<" => BinOp::Lt,
                "<=" => BinOp::Le,
                ">" => BinOp::Gt,
                ">=" => BinOp::Ge,
                _ => unreachable!(),
            };
            return Ok(Expr::Binary(bin_op, Box::new(lhs), Box::new(rhs)));
        }
        Ok(lhs)
    }

    fn parse_bitor(&mut self) -> Result<Expr, Error> {
        let mut lhs = self.parse_bitxor()?;
        while matches!(self.peek(), Some(Token::Op("|"))) {
            self.advance();
            let rhs = self.parse_bitxor()?;
            lhs = Expr::Binary(BinOp::BitOr, Box::new(lhs), Box::new(rhs));
        }
        Ok(lhs)
    }

    fn parse_bitxor(&mut self) -> Result<Expr, Error> {
        let mut lhs = self.parse_bitand()?;
        while matches!(self.peek(), Some(Token::Op("^"))) {
            self.advance();
            let rhs = self.parse_bitand()?;
            lhs = Expr::Binary(BinOp::BitXor, Box::new(lhs), Box::new(rhs));
        }
        Ok(lhs)
    }

    fn parse_bitand(&mut self) -> Result<Expr, Error> {
        let mut lhs = self.parse_shift()?;
        while matches!(self.peek(), Some(Token::Op("&"))) {
            self.advance();
            let rhs = self.parse_shift()?;
            lhs = Expr::Binary(BinOp::BitAnd, Box::new(lhs), Box::new(rhs));
        }
        Ok(lhs)
    }

    fn parse_shift(&mut self) -> Result<Expr, Error> {
        let mut lhs = self.parse_add()?;
        loop {
            match self.peek() {
                Some(Token::Op("<<")) => {
                    self.advance();
                    let rhs = self.parse_add()?;
                    lhs = Expr::Binary(BinOp::Shl, Box::new(lhs), Box::new(rhs));
                }
                Some(Token::Op(">>")) => {
                    self.advance();
                    let rhs = self.parse_add()?;
                    lhs = Expr::Binary(BinOp::Shr, Box::new(lhs), Box::new(rhs));
                }
                _ => break,
            }
        }
        Ok(lhs)
    }

    fn parse_add(&mut self) -> Result<Expr, Error> {
        let mut lhs = self.parse_mul()?;
        loop {
            match self.peek() {
                Some(Token::Op("+")) => {
                    self.advance();
                    let rhs = self.parse_mul()?;
                    lhs = Expr::Binary(BinOp::Add, Box::new(lhs), Box::new(rhs));
                }
                Some(Token::Op("-")) => {
                    self.advance();
                    let rhs = self.parse_mul()?;
                    lhs = Expr::Binary(BinOp::Sub, Box::new(lhs), Box::new(rhs));
                }
                _ => break,
            }
        }
        Ok(lhs)
    }

    fn parse_mul(&mut self) -> Result<Expr, Error> {
        let mut lhs = self.parse_unary()?;
        loop {
            match self.peek() {
                Some(Token::Op("*")) => {
                    self.advance();
                    let rhs = self.parse_unary()?;
                    lhs = Expr::Binary(BinOp::Mul, Box::new(lhs), Box::new(rhs));
                }
                Some(Token::Op("/")) => {
                    self.advance();
                    let rhs = self.parse_unary()?;
                    lhs = Expr::Binary(BinOp::Div, Box::new(lhs), Box::new(rhs));
                }
                Some(Token::Op("%")) => {
                    self.advance();
                    let rhs = self.parse_unary()?;
                    lhs = Expr::Binary(BinOp::Mod, Box::new(lhs), Box::new(rhs));
                }
                _ => break,
            }
        }
        Ok(lhs)
    }

    fn parse_unary(&mut self) -> Result<Expr, Error> {
        if matches!(self.peek(), Some(Token::Op("-"))) {
            self.advance();
            let inner = self.parse_unary()?;
            return Ok(Expr::Unary(UnOp::Neg, Box::new(inner)));
        }
        self.parse_primary()
    }

    fn parse_primary(&mut self) -> Result<Expr, Error> {
        match self.advance() {
            Some(Token::Int(n)) => Ok(Expr::Int(n)),
            Some(Token::Str(s)) => Ok(Expr::Str(s)),
            Some(Token::Ident(w)) if w == "true" => Ok(Expr::Bool(true)),
            Some(Token::Ident(w)) if w == "false" => Ok(Expr::Bool(false)),
            Some(Token::Ident(w)) => {
                let mut path = vec![w];
                while matches!(self.peek(), Some(Token::Dot)) {
                    self.advance();
                    match self.advance() {
                        Some(Token::Ident(part)) => path.push(part),
                        other => {
                            return Err(Error::Protocol(format!(
                                "expected identifier after `.` in expression, found {other:?}"
                            )))
                        }
                    }
                }
                Ok(Expr::Field(path))
            }
            Some(Token::LParen) => {
                let inner = self.parse_or()?;
                match self.advance() {
                    Some(Token::RParen) => Ok(inner),
                    other => Err(Error::Protocol(format!(
                        "expected `)` in expression, found {other:?}"
                    ))),
                }
            }
            other => Err(Error::Protocol(format!(
                "unexpected token in expression: {other:?}"
            ))),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn scope(fields: &IndexMap<String, Value>) -> EvalScope<'_> {
        EvalScope {
            fields,
            current: None,
        }
    }

    #[test]
    fn arithmetic_and_comparison() {
        let fields = IndexMap::new();
        let expr = parse("1 + 2 * 3 == 7").unwrap();
        assert!(eval_bool(&expr, &scope(&fields)).unwrap());
    }

    #[test]
    fn field_reference() {
        let mut fields = IndexMap::new();
        fields.insert("length".to_string(), Value::UnsignedInteger(5));
        let expr = parse("length - 1").unwrap();
        assert_eq!(eval_usize(&expr, &scope(&fields)).unwrap(), 4);
    }

    #[test]
    fn bitwise_and_flags() {
        let mut fields = IndexMap::new();
        fields.insert("flags".to_string(), Value::UnsignedInteger(0x03));
        let expr = parse("flags & 0x01 != 0").unwrap();
        assert!(eval_bool(&expr, &scope(&fields)).unwrap());
    }

    #[test]
    fn logical_and_or() {
        let mut fields = IndexMap::new();
        fields.insert("command".to_string(), Value::UnsignedInteger(0x10));
        let expr = parse("command == 0x10 or command == 0x20").unwrap();
        assert!(eval_bool(&expr, &scope(&fields)).unwrap());
    }

    #[test]
    fn underscore_refers_to_current_element() {
        let fields = IndexMap::new();
        let current = Value::UnsignedInteger(0);
        let expr = parse("_ == 0").unwrap();
        let scope = EvalScope {
            fields: &fields,
            current: Some(&current),
        };
        assert!(eval_bool(&expr, &scope).unwrap());
    }

    #[test]
    fn dotted_nested_field_reference() {
        let mut nested = IndexMap::new();
        nested.insert("length".to_string(), Value::UnsignedInteger(9));
        let mut fields = IndexMap::new();
        fields.insert("header".to_string(), Value::Struct(nested));
        let expr = parse("header.length == 9").unwrap();
        assert!(eval_bool(&expr, &scope(&fields)).unwrap());
    }

    #[test]
    fn unknown_field_is_an_error() {
        let fields = IndexMap::new();
        let expr = parse("missing == 1").unwrap();
        assert!(eval_bool(&expr, &scope(&fields)).is_err());
    }
}
