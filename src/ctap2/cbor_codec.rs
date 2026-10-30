use ciborium::{cbor, value::Value};
use ciborium_ll::{Decoder, Header};
use std::{cmp::Ordering, ops::Range};

use super::ErrorStatus;

pub(super) fn decode_map(body: &[u8]) -> Result<Vec<(Value, Value)>, ErrorStatus> {
    validate_canonical(body)?;
    match ciborium::from_reader::<Value, _>(body) {
        Ok(Value::Map(map)) => Ok(map),
        Ok(_) => Err(ErrorStatus::CborUnexpectedType),
        Err(_) => Err(ErrorStatus::InvalidCbor),
    }
}

/// Validate CTAP's wire-level canonical form before allocating a Value tree.
/// Ciborium does the CBOR parsing; this adds the restrictions from CTAP §8.
/// In particular, round-trip serialization is not a validator: CTAP preserves
/// float widths, whereas a general-purpose encoder may shorten floats.
fn validate_canonical(body: &[u8]) -> Result<(), ErrorStatus> {
    let mut offset = 0;
    scan_item(body, &mut offset, 0)?;
    if offset != body.len() {
        return Err(ErrorStatus::InvalidCbor);
    }
    Ok(())
}

fn integer_width(value: u64) -> usize {
    match value {
        0..=23 => 1,
        24..=0xff => 2,
        0x100..=0xffff => 3,
        0x10000..=0xffff_ffff => 5,
        _ => 9,
    }
}

fn key_order(left: &[u8], right: &[u8]) -> Ordering {
    (left[0] >> 5)
        .cmp(&(right[0] >> 5))
        .then_with(|| left.len().cmp(&right.len()))
        .then_with(|| left.cmp(right))
}

fn scan_item(body: &[u8], offset: &mut usize, depth: usize) -> Result<Range<usize>, ErrorStatus> {
    let start = *offset;
    let mut decoder = Decoder::from(body.get(start..).ok_or(ErrorStatus::InvalidCbor)?);
    let header = decoder.pull().map_err(|_| ErrorStatus::InvalidCbor)?;
    let width = decoder.offset();
    *offset += width;
    let value = match header {
        Header::Positive(value) | Header::Negative(value) => Some(value),
        Header::Bytes(Some(len))
        | Header::Text(Some(len))
        | Header::Array(Some(len))
        | Header::Map(Some(len)) => Some(len as u64),
        Header::Float(_) => None, // All three float widths are canonical in CTAP.
        Header::Simple(value) if value < 24 && width == 1 => None,
        Header::Simple(value) if value >= 32 && width == 2 => None,
        _ => return Err(ErrorStatus::InvalidCbor), // No tags or indefinite items.
    };
    if value.is_some_and(|value| integer_width(value) != width) {
        return Err(ErrorStatus::InvalidCbor);
    }
    match header {
        Header::Bytes(Some(len)) | Header::Text(Some(len)) => {
            *offset = offset
                .checked_add(len)
                .filter(|end| *end <= body.len())
                .ok_or(ErrorStatus::InvalidCbor)?;
        }
        Header::Array(Some(len)) => {
            if depth >= 4 {
                return Err(ErrorStatus::InvalidCbor);
            }
            for _ in 0..len {
                scan_item(body, offset, depth + 1)?;
            }
        }
        Header::Map(Some(len)) => {
            if depth >= 4 {
                return Err(ErrorStatus::InvalidCbor);
            }
            let mut previous: Option<Range<usize>> = None;
            for _ in 0..len {
                let key = scan_item(body, offset, depth + 1)?;
                if previous.as_ref().is_some_and(|previous| {
                    key_order(&body[previous.clone()], &body[key.clone()]) != Ordering::Less
                }) {
                    return Err(ErrorStatus::InvalidCbor);
                }
                scan_item(body, offset, depth + 1)?;
                previous = Some(key);
            }
        }
        _ => {}
    }
    Ok(start..*offset)
}

/// Return a parameter's exact canonical bytes (including float widths).
/// Authenticated command parameters must not be decoded and reserialized before
/// MAC verification, which would change valid wide-float encodings (§8).
pub(super) fn encoded_map_value(body: &[u8], key: u64) -> Result<Option<&[u8]>, ErrorStatus> {
    validate_canonical(body)?;
    let mut decoder = Decoder::from(body);
    let Header::Map(Some(len)) = decoder.pull().map_err(|_| ErrorStatus::InvalidCbor)? else {
        return Err(ErrorStatus::CborUnexpectedType);
    };
    let mut offset = decoder.offset();
    for _ in 0..len {
        let key_range = scan_item(body, &mut offset, 1)?;
        let value_range = scan_item(body, &mut offset, 1)?;
        let mut key_decoder = Decoder::from(&body[key_range]);
        if matches!(key_decoder.pull(), Ok(Header::Positive(found)) if found == key) {
            return Ok(Some(&body[value_range]));
        }
    }
    Ok(None)
}

pub(super) trait MapKey {
    fn matches(&self, value: &Value) -> bool;
}

impl MapKey for i128 {
    fn matches(&self, value: &Value) -> bool {
        value.as_integer().map(i128::from) == Some(*self)
    }
}

impl MapKey for &str {
    fn matches(&self, value: &Value) -> bool {
        value.as_text() == Some(*self)
    }
}

pub(super) fn map_value<K: MapKey>(map: &[(Value, Value)], key: K) -> Option<&Value> {
    map.iter()
        .find_map(|(candidate, value)| key.matches(candidate).then_some(value))
}

pub(super) fn map_bytes<K: MapKey>(map: &[(Value, Value)], key: K) -> Option<&[u8]> {
    map_value(map, key)
        .and_then(Value::as_bytes)
        .map(Vec::as_slice)
}

pub(super) fn map_integer<K: MapKey>(map: &[(Value, Value)], key: K) -> Option<i128> {
    map_value(map, key)
        .and_then(Value::as_integer)
        .map(i128::from)
}

pub(super) fn map_text<K: MapKey>(map: &[(Value, Value)], key: K) -> Option<&str> {
    map_value(map, key).and_then(Value::as_text)
}

pub(super) fn map_bool<K: MapKey>(map: &[(Value, Value)], key: K) -> Option<bool> {
    map_value(map, key).and_then(Value::as_bool)
}

#[cfg(test)]
pub(super) fn map_map<K: MapKey>(map: &[(Value, Value)], key: K) -> Option<&[(Value, Value)]> {
    map_value(map, key)
        .and_then(Value::as_map)
        .map(Vec::as_slice)
}

pub(super) fn optional_bytes(
    map: &[(Value, Value)],
    key: i128,
) -> Result<Option<&[u8]>, ErrorStatus> {
    map_value(map, key)
        .map(|value| {
            value
                .as_bytes()
                .map(Vec::as_slice)
                .ok_or(ErrorStatus::InvalidCbor)
        })
        .transpose()
}

pub(super) fn optional_integer(
    map: &[(Value, Value)],
    key: i128,
) -> Result<Option<i128>, ErrorStatus> {
    map_value(map, key)
        .map(|value| {
            value
                .as_integer()
                .map(i128::from)
                .ok_or(ErrorStatus::InvalidCbor)
        })
        .transpose()
}

pub(super) fn optional_array(
    map: &[(Value, Value)],
    key: i128,
) -> Result<Option<&[Value]>, ErrorStatus> {
    map_value(map, key)
        .map(|value| {
            value
                .as_array()
                .map(Vec::as_slice)
                .ok_or(ErrorStatus::InvalidCbor)
        })
        .transpose()
}

pub(super) fn optional_map(
    map: &[(Value, Value)],
    key: i128,
) -> Result<Option<&[(Value, Value)]>, ErrorStatus> {
    map_value(map, key)
        .map(|value| {
            value
                .as_map()
                .map(Vec::as_slice)
                .ok_or(ErrorStatus::InvalidCbor)
        })
        .transpose()
}

pub(super) fn byte_string(bytes: impl Into<Vec<u8>>) -> Value {
    Value::Bytes(bytes.into())
}

pub(super) fn map(entries: Vec<(Value, Value)>) -> Value {
    Value::Map(entries)
}

pub(super) fn cbor_map_entries(value: Value) -> Vec<(Value, Value)> {
    let Value::Map(entries) = value else {
        unreachable!("cbor! map expression returned a non-map value");
    };
    entries
}

pub(super) fn encode_empty_response() -> Vec<u8> {
    encode_response(cbor!({}).expect("empty response map"))
}

pub(super) fn encode_response(response: Value) -> Vec<u8> {
    let mut payload = vec![0x00];
    let response = canonicalize_value(response);
    ciborium::into_writer(&response, &mut payload).expect("serializing CTAP2 response");
    payload
}

pub(super) fn canonicalize_value(value: Value) -> Value {
    match value {
        Value::Array(values) => Value::Array(values.into_iter().map(canonicalize_value).collect()),
        Value::Map(entries) => {
            let mut entries: Vec<_> = entries
                .into_iter()
                .map(|(key, value)| (key, canonicalize_value(value)))
                .collect();
            entries.sort_by(|(left_key, _), (right_key, _)| {
                key_order(
                    &canonical_key_bytes(left_key),
                    &canonical_key_bytes(right_key),
                )
            });
            Value::Map(entries)
        }
        other => other,
    }
}

fn canonical_key_bytes(value: &Value) -> Vec<u8> {
    let mut encoded = Vec::new();
    ciborium::into_writer(value, &mut encoded).expect("serializing CTAP2 map key");
    encoded
}

pub(super) fn error_response(status: ErrorStatus) -> Vec<u8> {
    vec![status.into()]
}
