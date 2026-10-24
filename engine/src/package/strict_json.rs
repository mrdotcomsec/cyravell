// Copyright 2026 Cyravell Contributors
// SPDX-License-Identifier: Apache-2.0

use serde::de::{DeserializeSeed, Deserializer, MapAccess, SeqAccess, Visitor};
use std::collections::HashSet;
use std::fmt;

/// Validates that a JSON string has no duplicate keys at any nesting level.
/// Reuses standard `serde_json` lexing/parsing for standards-compliant behavior.
pub fn validate_no_duplicate_keys(json_str: &str) -> Result<(), String> {
    let mut deserializer = serde_json::Deserializer::from_str(json_str);
    StrictValueVisitor
        .deserialize(&mut deserializer)
        .map_err(|e| e.to_string())?;
    Ok(())
}

struct StrictValueVisitor;

impl<'de> DeserializeSeed<'de> for StrictValueVisitor {
    type Value = ();

    fn deserialize<D>(self, deserializer: D) -> Result<Self::Value, D::Error>
    where
        D: Deserializer<'de>,
    {
        deserializer.deserialize_any(StrictVisitor)
    }
}

struct StrictVisitor;

impl<'de> Visitor<'de> for StrictVisitor {
    type Value = ();

    fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
        formatter.write_str("any valid JSON value without duplicate keys")
    }

    fn visit_bool<E>(self, _v: bool) -> Result<Self::Value, E> {
        Ok(())
    }

    fn visit_i64<E>(self, _v: i64) -> Result<Self::Value, E> {
        Ok(())
    }

    fn visit_u64<E>(self, _v: u64) -> Result<Self::Value, E> {
        Ok(())
    }

    fn visit_f64<E>(self, _v: f64) -> Result<Self::Value, E> {
        Ok(())
    }

    fn visit_str<E>(self, _v: &str) -> Result<Self::Value, E> {
        Ok(())
    }

    fn visit_none<E>(self) -> Result<Self::Value, E> {
        Ok(())
    }

    fn visit_some<D>(self, deserializer: D) -> Result<Self::Value, D::Error>
    where
        D: Deserializer<'de>,
    {
        deserializer.deserialize_any(StrictVisitor)
    }

    fn visit_unit<E>(self) -> Result<Self::Value, E> {
        Ok(())
    }

    fn visit_seq<A>(self, mut seq: A) -> Result<Self::Value, A::Error>
    where
        A: SeqAccess<'de>,
    {
        while let Some(()) = seq.next_element_seed(StrictValueVisitor)? {}
        Ok(())
    }

    fn visit_map<A>(self, mut map: A) -> Result<Self::Value, A::Error>
    where
        A: MapAccess<'de>,
    {
        let mut keys = HashSet::new();
        while let Some(key) = map.next_key::<String>()? {
            if !keys.insert(key.clone()) {
                return Err(serde::de::Error::custom(format!(
                    "Duplicate JSON key detected: '{}'",
                    key
                )));
            }
            map.next_value_seed(StrictValueVisitor)?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_valid_json_passes() {
        let json = r#"{"a": 1, "b": [1, 2, {"c": 3}], "d": "hello"}"#;
        assert!(validate_no_duplicate_keys(json).is_ok());
    }

    #[test]
    fn test_duplicate_root_key_fails() {
        let json = r#"{"key": 1, "other": 2, "key": 3}"#;
        let res = validate_no_duplicate_keys(json);
        assert!(res.is_err());
        assert!(res
            .unwrap_err()
            .contains("Duplicate JSON key detected: 'key'"));
    }

    #[test]
    fn test_duplicate_nested_key_fails() {
        let json = r#"{"parent": {"nested": "a", "nested": "b"}}"#;
        let res = validate_no_duplicate_keys(json);
        assert!(res.is_err());
        assert!(res
            .unwrap_err()
            .contains("Duplicate JSON key detected: 'nested'"));
    }

    #[test]
    fn test_duplicate_key_in_array_object_fails() {
        let json = r#"[{"id": 1}, {"foo": 1, "foo": 2}]"#;
        let res = validate_no_duplicate_keys(json);
        assert!(res.is_err());
        assert!(res
            .unwrap_err()
            .contains("Duplicate JSON key detected: 'foo'"));
    }
}
