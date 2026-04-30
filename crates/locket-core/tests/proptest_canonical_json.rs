//! Property tests for [`locket_core::canonical_json`].
//!
//! Asserts the documented invariants:
//! - **Stable across permutations.** Two objects with identical
//!   key/value pairs but different insertion order encode to the
//!   same byte sequence.
//! - **Idempotent.** Re-parsing canonical output and re-encoding it
//!   produces the same string.
//! - **Total-ordered keys.** Every nested object's keys appear in
//!   strict lexicographic byte order in the output.
//! - **Round-trip preserves value equality.** The encoded string is
//!   valid JSON whose parsed `Value` equals the input.

#![allow(clippy::panic, clippy::unwrap_used)]

use locket_core::canonical_json;
use proptest::prelude::*;
use serde_json::Value;

fn primitive_strategy() -> impl Strategy<Value = Value> {
    prop_oneof![
        Just(Value::Null),
        any::<bool>().prop_map(Value::Bool),
        any::<i64>().prop_map(|n| Value::Number(n.into())),
        any::<u64>().prop_map(|n| Value::Number(n.into())),
        ".{0,16}".prop_map(Value::String),
    ]
}

fn key_strategy() -> impl Strategy<Value = String> {
    "[a-zA-Z0-9_\\- ]{1,12}".prop_map(String::from)
}

fn value_strategy() -> impl Strategy<Value = Value> {
    let leaf = primitive_strategy();
    leaf.prop_recursive(4, 32, 6, |inner| {
        prop_oneof![
            prop::collection::vec(inner.clone(), 0..6).prop_map(Value::Array),
            prop::collection::vec((key_strategy(), inner), 0..6)
                .prop_map(|entries| Value::Object(entries.into_iter().collect())),
        ]
    })
}

/// Serializes `value` into a non-canonical JSON string by emitting
/// each object's keys in a permuted (often non-sorted) order.
/// `indices` provides a stream of swap offsets used at every depth.
fn render_non_canonical(value: &Value, indices: &[usize]) -> String {
    fn render(out: &mut String, value: &Value, indices: &[usize], cursor: &mut usize) {
        match value {
            Value::Null => out.push_str("null"),
            Value::Bool(true) => out.push_str("true"),
            Value::Bool(false) => out.push_str("false"),
            Value::Number(n) => out.push_str(&n.to_string()),
            Value::String(s) => out.push_str(&serde_json::to_string(s).unwrap()),
            Value::Array(items) => {
                out.push('[');
                for (i, item) in items.iter().enumerate() {
                    if i != 0 {
                        out.push(',');
                    }
                    render(out, item, indices, cursor);
                }
                out.push(']');
            }
            Value::Object(map) => {
                let mut entries: Vec<(&String, &Value)> = map.iter().collect();
                if !entries.is_empty() && !indices.is_empty() {
                    let len = entries.len();
                    let shift = indices[*cursor % indices.len()];
                    *cursor += 1;
                    for i in 0..len {
                        let j = (i + shift) % len;
                        entries.swap(i, j);
                    }
                }
                out.push('{');
                for (i, (k, v)) in entries.iter().enumerate() {
                    if i != 0 {
                        out.push(',');
                    }
                    out.push_str(&serde_json::to_string(*k).unwrap());
                    out.push(':');
                    render(out, v, indices, cursor);
                }
                out.push('}');
            }
        }
    }
    let mut out = String::new();
    let mut cursor = 0usize;
    render(&mut out, value, indices, &mut cursor);
    out
}

fn collect_object_keys_in_output(input: &str) -> Vec<Vec<String>> {
    // Walk the canonical string and capture key sequences for every
    // object encountered. The encoder produces a strict subset of
    // JSON (no whitespace, sorted keys), so a small hand-roll suffices.
    let bytes = input.as_bytes();
    let mut keys_per_object: Vec<Vec<String>> = Vec::new();
    let mut stack: Vec<Vec<String>> = Vec::new();
    let mut in_string = false;
    let mut escape = false;
    let mut current_key: Option<String> = None;
    let mut buffer = String::new();
    let mut expecting_key = false;
    let mut idx = 0;
    while idx < bytes.len() {
        let ch = bytes[idx] as char;
        if in_string {
            if escape {
                buffer.push(ch);
                escape = false;
            } else if ch == '\\' {
                buffer.push(ch);
                escape = true;
            } else if ch == '"' {
                in_string = false;
                if expecting_key {
                    current_key = Some(buffer.clone());
                }
                buffer.clear();
            } else {
                buffer.push(ch);
            }
        } else {
            match ch {
                '{' => {
                    stack.push(Vec::new());
                    expecting_key = true;
                }
                '}' => {
                    if let Some(keys) = stack.pop() {
                        keys_per_object.push(keys);
                    }
                    expecting_key = false;
                }
                '[' => {
                    expecting_key = false;
                }
                ']' => {}
                '"' => {
                    in_string = true;
                }
                ':' => {
                    if let Some(key) = current_key.take() {
                        if let Some(top) = stack.last_mut() {
                            top.push(key);
                        }
                    }
                    expecting_key = false;
                }
                ',' => {
                    if !stack.is_empty() {
                        expecting_key = true;
                    }
                }
                _ => {}
            }
        }
        idx += 1;
    }
    keys_per_object
}

proptest! {
    /// Encoding twice produces the same string (idempotent on the
    /// canonical form): canonicalize → parse → canonicalize is a
    /// fixed point.
    #[test]
    fn canonical_json_is_idempotent(value in value_strategy()) {
        let once = canonical_json(&value);
        let parsed: Value = serde_json::from_str(&once)
            .expect("canonical JSON must be valid JSON");
        let twice = canonical_json(&parsed);
        prop_assert_eq!(once, twice);
    }

    /// The encoded output is a valid JSON document whose parsed
    /// value is structurally equal to the input.
    #[test]
    fn canonical_json_round_trips_through_serde(value in value_strategy()) {
        let encoded = canonical_json(&value);
        let parsed: Value = serde_json::from_str(&encoded)
            .expect("canonical JSON must be valid JSON");
        prop_assert_eq!(parsed, value);
    }

    /// Object key insertion order in the input source does not
    /// affect canonical encoding. We serialize the value with
    /// permuted object-key order, parse it back, and verify the
    /// canonical encoding still matches.
    #[test]
    fn canonical_json_is_stable_across_permutations(
        value in value_strategy(),
        indices in prop::collection::vec(0usize..8, 1..8),
    ) {
        let permuted_text = render_non_canonical(&value, &indices);
        let parsed: Value = serde_json::from_str(&permuted_text)
            .expect("permuted JSON must still parse");
        prop_assert_eq!(canonical_json(&value), canonical_json(&parsed));
    }

    /// Every object in the output emits its keys in strict
    /// lexicographic byte order — total-ordering invariant.
    #[test]
    fn canonical_json_orders_object_keys_lexicographically(value in value_strategy()) {
        let encoded = canonical_json(&value);
        for keys in collect_object_keys_in_output(&encoded) {
            for window in keys.windows(2) {
                prop_assert!(
                    window[0] < window[1],
                    "expected strictly ascending object keys, got {:?} then {:?} in {encoded}",
                    window[0], window[1]
                );
            }
        }
    }

    /// The encoded form contains no whitespace between tokens — the
    /// canonical form is the unique compact representation.
    #[test]
    fn canonical_json_emits_no_inter_token_whitespace(value in value_strategy()) {
        let encoded = canonical_json(&value);
        let mut in_string = false;
        let mut escape = false;
        for ch in encoded.chars() {
            if in_string {
                if escape {
                    escape = false;
                } else if ch == '\\' {
                    escape = true;
                } else if ch == '"' {
                    in_string = false;
                }
            } else if ch == '"' {
                in_string = true;
            } else {
                prop_assert!(
                    !ch.is_whitespace(),
                    "unexpected whitespace {ch:?} in {encoded}"
                );
            }
        }
    }
}
