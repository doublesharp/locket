//! Property tests for audit HMAC canonical byte construction.
//!
//! The audit chain verifier relies on byte-for-byte stable canonical input.
//! These tests decode generated HMAC inputs back into their fixed and
//! length-prefixed fields so regressions in order, defaults, or metadata
//! canonicalization fail before they can corrupt a chain.

#![allow(clippy::expect_used, clippy::panic, clippy::unwrap_used, unused_crate_dependencies)]

use locket_core::{AUDIT_HMAC_LEN, AuditHmacInput, Timestamp, audit_hmac_v1_bytes, canonical_json};
use proptest::prelude::*;
use serde_json::{Map, Value};

const DOMAIN_SEPARATOR: &[u8] = b"locket-audit-v1";

#[derive(Debug)]
struct DecodedAuditBytes {
    schema_version: u16,
    sequence: u64,
    timestamp: i128,
    fields: Vec<(String, Vec<u8>)>,
}

fn primitive_strategy() -> impl Strategy<Value = Value> {
    prop_oneof![
        Just(Value::Null),
        any::<bool>().prop_map(Value::Bool),
        any::<i64>().prop_map(|n| Value::Number(n.into())),
        any::<u64>().prop_map(|n| Value::Number(n.into())),
        ".{0,16}".prop_map(Value::String),
    ]
}

fn metadata_strategy() -> impl Strategy<Value = Value> {
    let leaf = primitive_strategy();
    leaf.prop_recursive(3, 24, 5, |inner| {
        prop_oneof![
            prop::collection::vec(inner.clone(), 0..5).prop_map(Value::Array),
            prop::collection::vec(("[a-zA-Z0-9_\\- ]{1,12}".prop_map(String::from), inner), 0..5)
                .prop_map(|entries| Value::Object(entries.into_iter().collect())),
        ]
    })
}

fn optional_label_strategy() -> impl Strategy<Value = Option<String>> {
    prop_oneof![Just(None), "[A-Za-z0-9_\\-]{1,24}".prop_map(String::from).prop_map(Some)]
}

fn required_label_strategy() -> impl Strategy<Value = String> {
    "[A-Z_][A-Z0-9_]{0,24}".prop_map(String::from)
}

fn decode_audit_bytes(bytes: &[u8]) -> DecodedAuditBytes {
    assert!(bytes.starts_with(DOMAIN_SEPARATOR));
    let mut cursor = DOMAIN_SEPARATOR.len();

    let schema_version = u16::from_le_bytes(bytes[cursor..cursor + 2].try_into().unwrap());
    cursor += 2;
    let sequence = u64::from_le_bytes(bytes[cursor..cursor + 8].try_into().unwrap());
    cursor += 8;
    let timestamp = i128::from_le_bytes(bytes[cursor..cursor + 16].try_into().unwrap());
    cursor += 16;

    let mut fields = Vec::new();
    while cursor < bytes.len() {
        let name_len = u16::from_le_bytes(bytes[cursor..cursor + 2].try_into().unwrap());
        cursor += 2;
        let name_end = cursor + usize::from(name_len);
        let name = String::from_utf8(bytes[cursor..name_end].to_vec()).unwrap();
        cursor = name_end;

        let value_len = u32::from_le_bytes(bytes[cursor..cursor + 4].try_into().unwrap());
        cursor += 4;
        let value_end = cursor + usize::try_from(value_len).unwrap();
        fields.push((name, bytes[cursor..value_end].to_vec()));
        cursor = value_end;
    }

    DecodedAuditBytes { schema_version, sequence, timestamp, fields }
}

fn as_metadata_bytes(metadata: Option<&Value>) -> Vec<u8> {
    metadata.map_or_else(|| b"null".to_vec(), |value| canonical_json(value).into_bytes())
}

fn reversed_object(value: &Value) -> Value {
    match value {
        Value::Array(values) => Value::Array(values.iter().map(reversed_object).collect()),
        Value::Object(values) => {
            let mut map = Map::new();
            for (key, nested) in values.iter().rev() {
                map.insert(key.clone(), reversed_object(nested));
            }
            Value::Object(map)
        }
        other => other.clone(),
    }
}

proptest! {
    #[test]
    fn audit_hmac_bytes_decode_to_their_canonical_fields(
        schema_version in any::<u16>(),
        sequence in any::<u64>(),
        timestamp in any::<i64>(),
        project_id in optional_label_strategy(),
        profile_id in optional_label_strategy(),
        action in required_label_strategy(),
        status in required_label_strategy(),
        metadata in prop::option::of(metadata_strategy()),
        previous_hmac in prop::option::of(any::<[u8; AUDIT_HMAC_LEN]>()),
    ) {
        let input = AuditHmacInput {
            schema_version,
            sequence,
            timestamp: Timestamp::from_unix_nanos(timestamp),
            project_id: project_id.as_deref(),
            profile_id: profile_id.as_deref(),
            action: &action,
            status: &status,
            metadata_json: metadata.as_ref(),
            previous_hmac: previous_hmac.as_ref(),
        };

        let encoded = audit_hmac_v1_bytes(&input).expect("generated values stay within limits");
        let decoded = decode_audit_bytes(&encoded);

        prop_assert_eq!(decoded.schema_version, schema_version);
        prop_assert_eq!(decoded.sequence, sequence);
        prop_assert_eq!(decoded.timestamp, i128::from(timestamp));
        prop_assert_eq!(
            decoded.fields,
            vec![
                ("project_id".to_owned(), project_id.unwrap_or_default().into_bytes()),
                ("profile_id".to_owned(), profile_id.unwrap_or_default().into_bytes()),
                ("action".to_owned(), action.into_bytes()),
                ("status".to_owned(), status.into_bytes()),
                ("metadata_json".to_owned(), as_metadata_bytes(metadata.as_ref())),
                (
                    "previous_hmac".to_owned(),
                    previous_hmac.unwrap_or([0; AUDIT_HMAC_LEN]).to_vec(),
                ),
            ]
        );
    }

    #[test]
    fn audit_hmac_metadata_encoding_is_stable_across_object_order(
        metadata in metadata_strategy(),
        previous_hmac in any::<[u8; AUDIT_HMAC_LEN]>(),
    ) {
        let reversed = reversed_object(&metadata);
        let left = AuditHmacInput {
            schema_version: 1,
            sequence: 42,
            timestamp: Timestamp::from_unix_nanos(1_700_000_000),
            project_id: Some("lk_proj_test"),
            profile_id: Some("lk_prof_test"),
            action: "SET",
            status: "SUCCESS",
            metadata_json: Some(&metadata),
            previous_hmac: Some(&previous_hmac),
        };
        let right = AuditHmacInput { metadata_json: Some(&reversed), ..left };

        prop_assert_eq!(
            audit_hmac_v1_bytes(&left).expect("generated left input is valid"),
            audit_hmac_v1_bytes(&right).expect("generated right input is valid"),
        );
    }
}
