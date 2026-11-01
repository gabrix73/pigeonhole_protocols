//! CBOR as the Go implementation writes it: canonical encoding (map keys
//! sorted shortest first, then bytewise), structs as maps keyed by field
//! name, nil byte slices as null. Decoding accepts one item followed only
//! by zero padding, since Sphinx payloads arrive padded.

pub use ciborium::Value;

use crate::services::Error;

/// Encodes a value. Maps built with [`map`] are already in canonical order.
pub fn encode(v: &Value) -> Vec<u8> {
    let mut out = Vec::new();
    ciborium::into_writer(v, &mut out).expect("CBOR encoding into a Vec cannot fail");
    out
}

/// Decodes one item, allowing trailing zero bytes.
pub fn decode(b: &[u8]) -> Result<Value, Error> {
    let mut cursor = std::io::Cursor::new(b);
    let v: Value = ciborium::from_reader(&mut cursor).map_err(|e| Error::Decode(e.to_string()))?;
    let rest = &b[cursor.position() as usize..];
    if rest.iter().any(|&c| c != 0) {
        return Err(Error::Decode("trailing data after CBOR".into()));
    }
    Ok(v)
}

/// Decodes a sequence of items that fills `b` exactly.
pub fn decode_seq(b: &[u8]) -> Result<Vec<Value>, Error> {
    let mut cursor = std::io::Cursor::new(b);
    let mut out = Vec::new();
    while (cursor.position() as usize) < b.len() {
        out.push(ciborium::from_reader(&mut cursor).map_err(|e| Error::Decode(e.to_string()))?);
    }
    Ok(out)
}

/// Builds a map with text keys in canonical order.
pub fn map(entries: Vec<(&str, Value)>) -> Value {
    let mut entries: Vec<(Vec<u8>, Value)> = entries
        .into_iter()
        .map(|(k, v)| (encode(&Value::Text(k.to_string())), v))
        .collect();
    entries.sort_by(|a, b| a.0.len().cmp(&b.0.len()).then_with(|| a.0.cmp(&b.0)));
    Value::Map(
        entries
            .into_iter()
            .map(|(k, v)| (ciborium::from_reader(&k[..]).unwrap(), v))
            .collect(),
    )
}

/// Byte string.
pub fn bytes(b: &[u8]) -> Value {
    Value::Bytes(b.to_vec())
}

/// Byte string, or null when absent, as Go writes a nil slice.
pub fn opt_bytes(b: Option<&[u8]>) -> Value {
    b.map_or(Value::Null, bytes)
}

/// Unsigned integer.
pub fn uint(n: u64) -> Value {
    Value::Integer(n.into())
}

/// Text string.
pub fn text(s: &str) -> Value {
    Value::Text(s.to_string())
}

/// Reads fields out of a decoded map by name.
pub struct Fields<'a>(&'a [(Value, Value)]);

impl<'a> Fields<'a> {
    pub fn of(v: &'a Value) -> Result<Self, Error> {
        match v {
            Value::Map(m) => Ok(Fields(m)),
            _ => Err(Error::Decode("expected a map".into())),
        }
    }

    /// The field named `name`, absent when missing or null.
    pub fn get(&self, name: &str) -> Option<&'a Value> {
        self.0
            .iter()
            .find(|(k, _)| matches!(k, Value::Text(t) if t == name))
            .map(|(_, v)| v)
            .filter(|v| !v.is_null())
    }

    pub fn bytes(&self, name: &str) -> Result<Vec<u8>, Error> {
        Ok(self.opt_bytes(name)?.unwrap_or_default())
    }

    pub fn opt_bytes(&self, name: &str) -> Result<Option<Vec<u8>>, Error> {
        match self.get(name) {
            None => Ok(None),
            Some(Value::Bytes(b)) => Ok(Some(b.clone())),
            Some(_) => Err(Error::Decode(format!("{name}: expected bytes"))),
        }
    }

    pub fn array32(&self, name: &str) -> Result<[u8; 32], Error> {
        self.bytes(name)?
            .try_into()
            .map_err(|_| Error::Decode(format!("{name}: expected 32 bytes")))
    }

    pub fn text(&self, name: &str) -> Result<String, Error> {
        match self.get(name) {
            None => Ok(String::new()),
            Some(Value::Text(t)) => Ok(t.clone()),
            Some(_) => Err(Error::Decode(format!("{name}: expected text"))),
        }
    }

    pub fn uint(&self, name: &str) -> Result<u64, Error> {
        match self.get(name) {
            None => Ok(0),
            Some(Value::Integer(i)) => u64::try_from(*i).map_err(|_| Error::Decode(format!("{name}: out of range"))),
            Some(_) => Err(Error::Decode(format!("{name}: expected an integer"))),
        }
    }

    pub fn array(&self, name: &str) -> Result<&'a [Value], Error> {
        match self.get(name) {
            None => Ok(&[]),
            Some(Value::Array(a)) => Ok(a),
            Some(_) => Err(Error::Decode(format!("{name}: expected an array"))),
        }
    }
}
