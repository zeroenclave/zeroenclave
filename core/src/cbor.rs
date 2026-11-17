//! Deterministic CBOR (RFC 8949 §4.2.1) on top of minicbor's low-level codec.
//!
//! Only definite lengths, shortest integer forms and bytewise sorted map keys are
//! produced. The decoder re-encodes what it parsed and rejects any difference, so
//! non-canonical input (indefinite lengths, unsorted or duplicate keys, padded
//! integers) never gets through.

use minicbor::data::Type;
use minicbor::{Decoder, Encoder};

use crate::error::{Error, Result};

const MAX_DEPTH: usize = 16;

/// Subset of CBOR data items used by the vault formats.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Value {
    Uint(u64),
    /// Negative integer, always `< 0`.
    Neg(i64),
    Bytes(Vec<u8>),
    Text(String),
    Array(Vec<Value>),
    Map(Vec<(Value, Value)>),
    Bool(bool),
    Null,
}

impl Value {
    pub fn int(v: i64) -> Self {
        if v >= 0 {
            Self::Uint(v as u64)
        } else {
            Self::Neg(v)
        }
    }

    pub fn text(s: &str) -> Self {
        Self::Text(s.to_owned())
    }

    pub fn bytes(b: &[u8]) -> Self {
        Self::Bytes(b.to_vec())
    }

    /// Map with text keys.
    pub fn map<const N: usize>(entries: [(&str, Value); N]) -> Self {
        Self::Map(
            entries
                .into_iter()
                .map(|(k, v)| (Self::text(k), v))
                .collect(),
        )
    }

    pub fn as_u64(&self) -> Option<u64> {
        match self {
            Self::Uint(v) => Some(*v),
            _ => None,
        }
    }

    pub fn as_i64(&self) -> Option<i64> {
        match self {
            Self::Uint(v) => i64::try_from(*v).ok(),
            Self::Neg(v) => Some(*v),
            _ => None,
        }
    }

    pub fn as_str(&self) -> Option<&str> {
        match self {
            Self::Text(s) => Some(s),
            _ => None,
        }
    }

    pub fn as_bytes(&self) -> Option<&[u8]> {
        match self {
            Self::Bytes(b) => Some(b),
            _ => None,
        }
    }

    pub fn as_array(&self) -> Option<&[Value]> {
        match self {
            Self::Array(a) => Some(a),
            _ => None,
        }
    }

    pub fn as_map(&self) -> Option<&[(Value, Value)]> {
        match self {
            Self::Map(m) => Some(m),
            _ => None,
        }
    }

    /// Looks up a text key in a map.
    pub fn get(&self, key: &str) -> Option<&Value> {
        self.as_map()?
            .iter()
            .find(|(k, _)| k.as_str() == Some(key))
            .map(|(_, v)| v)
    }
}

/// Encodes canonically; map entries are sorted by the encoding of their keys.
pub fn encode(v: &Value) -> Result<Vec<u8>> {
    let mut e = Encoder::new(Vec::new());
    put(&mut e, v, 0)?;
    Ok(e.into_writer())
}

fn put(e: &mut Encoder<Vec<u8>>, v: &Value, depth: usize) -> Result<()> {
    if depth > MAX_DEPTH {
        return Err(Error::Cbor);
    }
    let enc = |_| Error::Cbor;
    match v {
        Value::Uint(n) => drop(e.u64(*n).map_err(enc)?),
        Value::Neg(n) => drop(e.i64(*n).map_err(enc)?),
        Value::Bytes(b) => drop(e.bytes(b).map_err(enc)?),
        Value::Text(s) => drop(e.str(s).map_err(enc)?),
        Value::Bool(b) => drop(e.bool(*b).map_err(enc)?),
        Value::Null => drop(e.null().map_err(enc)?),
        Value::Array(a) => {
            e.array(a.len() as u64).map_err(enc)?;
            for x in a {
                put(e, x, depth + 1)?;
            }
        }
        Value::Map(m) => {
            let mut entries = Vec::with_capacity(m.len());
            for (k, x) in m {
                let mut ke = Encoder::new(Vec::new());
                put(&mut ke, k, depth + 1)?;
                entries.push((ke.into_writer(), x));
            }
            entries.sort_by(|a, b| a.0.cmp(&b.0));
            e.map(m.len() as u64).map_err(enc)?;
            for (k, x) in entries {
                e.writer_mut().extend_from_slice(&k);
                put(e, x, depth + 1)?;
            }
        }
    }
    Ok(())
}

/// Decodes one canonical data item that spans all of `data`.
pub fn decode(data: &[u8]) -> Result<Value> {
    let mut d = Decoder::new(data);
    let v = take(&mut d, 0)?;
    if d.position() != data.len() || encode(&v)? != data {
        return Err(Error::Cbor);
    }
    Ok(v)
}

fn take(d: &mut Decoder<'_>, depth: usize) -> Result<Value> {
    if depth > MAX_DEPTH {
        return Err(Error::Cbor);
    }
    let dec = |_| Error::Cbor;
    Ok(match d.datatype().map_err(dec)? {
        Type::U8 | Type::U16 | Type::U32 | Type::U64 => Value::Uint(d.u64().map_err(dec)?),
        Type::I8 | Type::I16 | Type::I32 | Type::I64 => Value::Neg(d.i64().map_err(dec)?),
        Type::Bytes => Value::Bytes(d.bytes().map_err(dec)?.to_vec()),
        Type::String => Value::Text(d.str().map_err(dec)?.to_owned()),
        Type::Bool => Value::Bool(d.bool().map_err(dec)?),
        Type::Null => {
            d.null().map_err(dec)?;
            Value::Null
        }
        Type::Array => {
            let n = d.array().map_err(dec)?.ok_or(Error::Cbor)?;
            let mut out = Vec::new();
            for _ in 0..n {
                out.push(take(d, depth + 1)?);
            }
            Value::Array(out)
        }
        Type::Map => {
            let n = d.map().map_err(dec)?.ok_or(Error::Cbor)?;
            let mut out: Vec<(Value, Value)> = Vec::new();
            for _ in 0..n {
                let k = take(d, depth + 1)?;
                if out.iter().any(|(o, _)| *o == k) {
                    return Err(Error::Cbor);
                }
                out.push((k, take(d, depth + 1)?));
            }
            Value::Map(out)
        }
        _ => return Err(Error::Cbor),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn map_keys_sorted_bytewise() {
        let v = Value::map([
            ("bb", Value::Uint(1)),
            ("a", Value::Uint(2)),
            ("c", Value::Null),
        ]);
        // Shorter keys sort first, then bytewise.
        assert_eq!(hex::encode(encode(&v).unwrap()), "a36161026163f662626201");
        assert_eq!(
            decode(&encode(&v).unwrap()).unwrap().get("bb"),
            Some(&Value::Uint(1))
        );
    }

    #[test]
    fn shortest_integers() {
        assert_eq!(encode(&Value::Uint(23)).unwrap(), [0x17]);
        assert_eq!(encode(&Value::Uint(24)).unwrap(), [0x18, 24]);
        assert_eq!(encode(&Value::Uint(256)).unwrap(), [0x19, 1, 0]);
        assert_eq!(encode(&Value::int(-1)).unwrap(), [0x20]);
        assert_eq!(decode(&[0x18, 0x05]), Err(Error::Cbor));
        assert_eq!(decode(&[0x19, 0x00, 0x05]), Err(Error::Cbor));
    }

    #[test]
    fn rejects_non_canonical() {
        // Indefinite array / map / byte string.
        assert_eq!(decode(&[0x9f, 0x01, 0xff]), Err(Error::Cbor));
        assert_eq!(decode(&[0xbf, 0x61, 0x61, 0x01, 0xff]), Err(Error::Cbor));
        assert_eq!(decode(&[0x5f, 0x41, 0x01, 0xff]), Err(Error::Cbor));
        // Duplicate keys.
        assert_eq!(
            decode(&[0xa2, 0x61, 0x61, 0x01, 0x61, 0x61, 0x02]),
            Err(Error::Cbor)
        );
        // Unsorted keys.
        assert_eq!(
            decode(&[0xa2, 0x61, 0x62, 0x01, 0x61, 0x61, 0x02]),
            Err(Error::Cbor)
        );
        // Trailing bytes, floats, tags.
        assert_eq!(decode(&[0x01, 0x02]), Err(Error::Cbor));
        assert_eq!(decode(&[0xf9, 0x3c, 0x00]), Err(Error::Cbor));
        assert_eq!(decode(&[0xc1, 0x01]), Err(Error::Cbor));
    }

    #[test]
    fn rejects_deep_nesting() {
        let data = vec![0x81; 40];
        assert_eq!(decode(&data), Err(Error::Cbor));
    }
}
