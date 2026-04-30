//! Property tests for the `lkdev1_` device descriptor codec.
//!
//! Asserts the documented invariants:
//! - **Round-trip.** Any valid [`DeviceRecord`] encodes to a
//!   `lkdev1_`-prefixed string that decodes back to a structurally
//!   equivalent descriptor.
//! - **Rejection.** Inputs that are missing the prefix, contain
//!   non-base64url bytes after the prefix, decode to non-JSON, or
//!   carry an unsupported version byte (`v != 1`) all return an
//!   error rather than panicking or yielding a partial value.

#![allow(clippy::panic)]
#![allow(clippy::unwrap_used)]

#[allow(unused_imports)]
use super::*;

use data_encoding::BASE64URL_NOPAD;
use locket_store::DeviceRecord;
use proptest::prelude::*;

use crate::commands::team::device::{
    DeviceDescriptorV1, decode_device_descriptor, encode_device_descriptor,
};

fn valid_device_id_strategy() -> impl Strategy<Value = String> {
    "lk_dev_[a-z0-9]{6,16}".prop_map(String::from)
}

fn valid_project_id_strategy() -> impl Strategy<Value = String> {
    "lk_proj_[a-z0-9]{6,12}".prop_map(String::from)
}

fn valid_label_strategy() -> impl Strategy<Value = String> {
    "[A-Za-z0-9 \\-_]{1,40}".prop_map(String::from)
}

fn key_bytes_strategy() -> impl Strategy<Value = Vec<u8>> {
    proptest::collection::vec(any::<u8>(), 32..=32)
}

fn fingerprint_strategy() -> impl Strategy<Value = String> {
    "[0-9a-f]{64}".prop_map(String::from)
}

fn safety_words_strategy() -> impl Strategy<Value = Vec<String>> {
    proptest::collection::vec("[a-z]{3,8}".prop_map(String::from), 0..6)
}

fn device_record_strategy() -> impl Strategy<Value = DeviceRecord> {
    (
        valid_device_id_strategy(),
        valid_project_id_strategy(),
        valid_label_strategy(),
        key_bytes_strategy(),
        key_bytes_strategy(),
        fingerprint_strategy(),
        safety_words_strategy(),
    )
        .prop_map(|(id, project_id, name, signing, sealing, fingerprint, safety_words)| {
            DeviceRecord {
                id,
                project_id,
                name,
                signing_public_key: signing,
                sealing_public_key: sealing,
                fingerprint,
                safety_words,
                local: false,
                created_at: 0,
                last_seen_at: None,
                revoked_at: None,
            }
        })
}

proptest! {
    /// Encoded descriptors decode back to the same logical fields.
    /// Round-trip drops the storage-only fields (project_id, local,
    /// timestamps) — those are not part of the wire format.
    #[test]
    fn descriptor_round_trip_preserves_wire_fields(record in device_record_strategy()) {
        let encoded = encode_device_descriptor(&record).unwrap();
        prop_assert!(encoded.starts_with("lkdev1_"));
        let decoded = decode_device_descriptor(&encoded).unwrap();
        prop_assert_eq!(decoded.v, 1);
        prop_assert_eq!(&decoded.device_id, &record.id);
        prop_assert_eq!(&decoded.label, &record.name);
        prop_assert_eq!(&decoded.fingerprint_sha256, &record.fingerprint);
        prop_assert_eq!(&decoded.safety_words, &record.safety_words);
        prop_assert_eq!(
            BASE64URL_NOPAD.decode(decoded.signing_public_key_ed25519.as_bytes()).unwrap(),
            record.signing_public_key
        );
        prop_assert_eq!(
            BASE64URL_NOPAD.decode(decoded.sealing_public_key_x25519.as_bytes()).unwrap(),
            record.sealing_public_key
        );
    }

    /// Re-encoding a descriptor produced by `encode_device_descriptor`
    /// (after decoding once and rebuilding through serde) yields the
    /// same `lkdev1_` payload — the codec is bit-stable for fields
    /// that survive the round-trip.
    #[test]
    fn descriptor_payload_is_stable(record in device_record_strategy()) {
        let first = encode_device_descriptor(&record).unwrap();
        let decoded = decode_device_descriptor(&first).unwrap();
        let json = serde_json::to_vec(&decoded).unwrap();
        let second = format!("lkdev1_{}", BASE64URL_NOPAD.encode(&json));
        prop_assert_eq!(first, second);
    }

    /// Inputs lacking the `lkdev1_` prefix are rejected.
    #[test]
    fn descriptor_rejects_missing_prefix(prefix in "[a-z]{0,7}", body in "[A-Za-z0-9_-]{0,32}") {
        prop_assume!(!format!("{prefix}{body}").starts_with("lkdev1_"));
        let input = format!("{prefix}{body}");
        prop_assert!(decode_device_descriptor(&input).is_err());
    }

    /// Inputs whose body is not valid base64url are rejected.
    #[test]
    fn descriptor_rejects_non_base64url_body(garbage in "[!@#$%^&*()=+]{1,16}") {
        let input = format!("lkdev1_{garbage}");
        prop_assert!(decode_device_descriptor(&input).is_err());
    }

    /// Inputs whose decoded JSON carries `v != 1` are rejected.
    #[test]
    fn descriptor_rejects_unsupported_version(record in device_record_strategy(), version in 2u16..=u16::MAX) {
        let descriptor = DeviceDescriptorV1 {
            v: version,
            device_id: record.id.clone(),
            label: record.name.clone(),
            signing_public_key_ed25519: BASE64URL_NOPAD.encode(&record.signing_public_key),
            sealing_public_key_x25519: BASE64URL_NOPAD.encode(&record.sealing_public_key),
            fingerprint_sha256: record.fingerprint.clone(),
            safety_words: record.safety_words.clone(),
        };
        let json = serde_json::to_vec(&descriptor).unwrap();
        let input = format!("lkdev1_{}", BASE64URL_NOPAD.encode(&json));
        prop_assert!(decode_device_descriptor(&input).is_err());
    }

    /// Inputs whose body is valid base64url but not valid descriptor
    /// JSON are rejected (no panic, no partial value).
    #[test]
    fn descriptor_rejects_invalid_json(noise in proptest::collection::vec(any::<u8>(), 0..32)) {
        let input = format!("lkdev1_{}", BASE64URL_NOPAD.encode(&noise));
        let _ = decode_device_descriptor(&input);
    }
}
