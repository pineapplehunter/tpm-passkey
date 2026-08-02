use ciborium::{cbor, value::Value};

use super::ErrorStatus;

pub(super) fn decode_map(body: &[u8]) -> Result<Vec<(Value, Value)>, ErrorStatus> {
    match ciborium::from_reader::<Value, _>(body) {
        Ok(Value::Map(map)) => Ok(map),
        Ok(_) | Err(_) => Err(ErrorStatus::InvalidCbor),
    }
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

pub(super) fn map_array<K: MapKey>(map: &[(Value, Value)], key: K) -> Option<&[Value]> {
    map_value(map, key)
        .and_then(Value::as_array)
        .map(Vec::as_slice)
}

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
                canonical_key_bytes(left_key).cmp(&canonical_key_bytes(right_key))
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
