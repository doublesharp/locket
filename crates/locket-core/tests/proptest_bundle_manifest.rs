//! Property tests for [`locket_core::bundle::BundleContainer`].
//!
//! Asserts the documented invariants from
//! `docs/specs/team-sync-recovery.md:111-224` and the slice TODO:
//!
//! - **Round-trip.** Any well-formed [`BundleManifest`] + opaque
//!   payload survives serialize-then-deserialize byte-for-byte.
//! - **Idempotence.** Re-serializing a deserialized container
//!   produces the same bytes (the format has no implicit padding).
//! - **Rejection.** Manifests carrying any field outside the
//!   documented allow-list are rejected — no profile/secret/policy/
//!   member/device names can leak through the plaintext header.
//! - **Cap enforcement.** Payloads or manifest-length headers above
//!   the documented caps are rejected without allocating.

#![allow(clippy::panic, clippy::unwrap_used)]

use locket_core::bundle::{
    BUNDLE_MAGIC, BUNDLE_MANIFEST_ALLOWED_FIELDS, BUNDLE_MAX_MANIFEST_LEN, BUNDLE_MAX_PAYLOAD_LEN,
    BUNDLE_SCHEMA_V1, BundleContainer, BundleContainerError, BundleManifest,
};
use proptest::prelude::*;
use serde_json::{Map, Value};

const FORBIDDEN_FIELDS: &[&str] = &[
    "profile_name",
    "profile_names",
    "secret_name",
    "secret_names",
    "policy_name",
    "policy_names",
    "member_name",
    "member_names",
    "device_label",
    "device_labels",
    "secret_value",
];

fn fingerprint_strategy() -> impl Strategy<Value = String> {
    "[0-9a-f]{64}".prop_map(String::from)
}

fn project_id_strategy() -> impl Strategy<Value = String> {
    "lk_proj_[a-z0-9]{6,12}".prop_map(String::from)
}

fn manifest_strategy() -> impl Strategy<Value = BundleManifest> {
    (
        prop::collection::vec(fingerprint_strategy(), 0..4),
        project_id_strategy(),
        any::<i64>(),
        any::<u32>(),
        fingerprint_strategy(),
    )
        .prop_map(|(recipient_fingerprints, project_id, created_at, profile_count, payload_digest)| {
            BundleManifest {
                recipient_fingerprints,
                project_id,
                schema_version: BUNDLE_SCHEMA_V1,
                created_at,
                profile_count,
                payload_digest,
            }
        })
}

fn payload_strategy() -> impl Strategy<Value = Vec<u8>> {
    prop::collection::vec(any::<u8>(), 0..1024)
}

fn forbidden_field_strategy() -> impl Strategy<Value = &'static str> {
    proptest::sample::select(FORBIDDEN_FIELDS)
}

proptest! {
    /// Serializing then deserializing a well-formed container yields
    /// a structurally equal container.
    #[test]
    fn container_round_trips_through_bytes(
        manifest in manifest_strategy(),
        payload in payload_strategy(),
    ) {
        let container = BundleContainer::new(manifest, payload).unwrap();
        let bytes = container.serialize().unwrap();
        let parsed = BundleContainer::deserialize(&bytes).unwrap();
        prop_assert_eq!(parsed, container);
    }

    /// Serialization is idempotent on the canonical bytes — the
    /// canonical-JSON manifest plus fixed-width binary header gives
    /// a unique encoding per container.
    #[test]
    fn container_serialization_is_idempotent(
        manifest in manifest_strategy(),
        payload in payload_strategy(),
    ) {
        let container = BundleContainer::new(manifest, payload).unwrap();
        let first = container.serialize().unwrap();
        let parsed = BundleContainer::deserialize(&first).unwrap();
        let second = parsed.serialize().unwrap();
        prop_assert_eq!(first, second);
    }

    /// Every well-formed bundle starts with the LKBNDL magic header.
    #[test]
    fn container_emits_magic_header(
        manifest in manifest_strategy(),
        payload in payload_strategy(),
    ) {
        let container = BundleContainer::new(manifest, payload).unwrap();
        let bytes = container.serialize().unwrap();
        prop_assert!(bytes.len() >= BUNDLE_MAGIC.len());
        prop_assert_eq!(&bytes[..BUNDLE_MAGIC.len()], BUNDLE_MAGIC.as_slice());
    }

    /// Hand-crafted manifests carrying any forbidden field name are
    /// rejected at parse time. This proves the minimization rule is
    /// enforced in code, not just by spec convention.
    #[test]
    fn deserialize_rejects_forbidden_manifest_fields(
        manifest in manifest_strategy(),
        payload in payload_strategy(),
        forbidden in forbidden_field_strategy(),
    ) {
        // Build a JSON object with all required fields plus one
        // forbidden field, then frame it as a v1 container.
        let mut object = Map::new();
        object.insert(
            "recipient_fingerprints".to_owned(),
            Value::Array(
                manifest.recipient_fingerprints.iter().cloned().map(Value::String).collect(),
            ),
        );
        object.insert("project_id".to_owned(), Value::String(manifest.project_id.clone()));
        object.insert(
            "schema_version".to_owned(),
            Value::Number(serde_json::Number::from(manifest.schema_version)),
        );
        object.insert(
            "created_at".to_owned(),
            Value::Number(serde_json::Number::from(manifest.created_at)),
        );
        object.insert(
            "profile_count".to_owned(),
            Value::Number(serde_json::Number::from(manifest.profile_count)),
        );
        object.insert("payload_digest".to_owned(), Value::String(manifest.payload_digest.clone()));
        // The forbidden field — the writer/reader must reject this
        // even though every required field above is present.
        object.insert(forbidden.to_owned(), Value::String("plain-text-name".to_owned()));
        let manifest_bytes = locket_core::canonical_json(&Value::Object(object)).into_bytes();

        let mut bytes = Vec::new();
        bytes.extend_from_slice(BUNDLE_MAGIC);
        bytes.extend_from_slice(&BUNDLE_SCHEMA_V1.to_le_bytes());
        prop_assert!(manifest_bytes.len() <= u32::MAX as usize);
        bytes.extend_from_slice(&(manifest_bytes.len() as u32).to_le_bytes());
        bytes.extend_from_slice(&manifest_bytes);
        bytes.extend_from_slice(&(payload.len() as u64).to_le_bytes());
        bytes.extend_from_slice(&payload);

        let result = BundleContainer::deserialize(&bytes);
        let Err(BundleContainerError::ManifestForbiddenField(field)) = result else {
            prop_assert!(
                false,
                "expected ManifestForbiddenField({forbidden}), got {result:?}"
            );
            return Ok(());
        };
        prop_assert_eq!(field.as_str(), forbidden);
    }

    /// The plaintext manifest never contains any forbidden field
    /// after serialization. This is the inverse of the rejection
    /// check above: it confirms the writer cannot introduce one
    /// even when the caller's `BundleManifest` is well-formed.
    #[test]
    fn serialized_manifest_contains_only_allowed_fields(
        manifest in manifest_strategy(),
        payload in payload_strategy(),
    ) {
        let container = BundleContainer::new(manifest, payload).unwrap();
        let bytes = container.serialize().unwrap();

        // Locate the manifest bytes inside the framed container.
        let header_len = BUNDLE_MAGIC.len() + 2 + 4;
        let manifest_len = u32::from_le_bytes(
            bytes[BUNDLE_MAGIC.len() + 2..header_len].try_into().unwrap(),
        ) as usize;
        let manifest_bytes = &bytes[header_len..header_len + manifest_len];

        let value: Value = serde_json::from_slice(manifest_bytes).unwrap();
        let Value::Object(map) = value else {
            prop_assert!(false, "manifest must be a JSON object");
            return Ok(());
        };
        let allowed: std::collections::BTreeSet<&str> =
            BUNDLE_MANIFEST_ALLOWED_FIELDS.iter().copied().collect();
        for key in map.keys() {
            prop_assert!(
                allowed.contains(key.as_str()),
                "serialized manifest contains forbidden field {key:?}"
            );
        }
    }

    /// Container construction (the public API) rejects any manifest
    /// whose schema_version is not the supported one.
    #[test]
    fn new_rejects_manifest_with_unsupported_schema(
        manifest in manifest_strategy(),
        bad_schema in 2u16..=u16::MAX,
    ) {
        let mut tampered = manifest;
        tampered.schema_version = bad_schema;
        let result = BundleContainer::new(tampered, Vec::new());
        prop_assert!(matches!(result, Err(BundleContainerError::UnsupportedSchema(_))));
    }

    /// A container whose manifest declares an empty project_id is
    /// rejected at construction, mirroring the parse-time check.
    #[test]
    fn new_rejects_manifest_with_empty_project_id(
        manifest in manifest_strategy(),
    ) {
        let mut tampered = manifest;
        tampered.project_id.clear();
        let result = BundleContainer::new(tampered, Vec::new());
        prop_assert!(matches!(
            result,
            Err(BundleContainerError::ManifestMissingField("project_id"))
        ));
    }

    /// Hand-crafted byte streams whose payload-length header exceeds
    /// the documented cap are rejected without ever attempting to
    /// allocate a buffer of that size.
    #[test]
    fn deserialize_rejects_oversized_payload_length_header(
        manifest in manifest_strategy(),
        excess in 1u64..=1024,
    ) {
        let container = BundleContainer::new(manifest, Vec::new()).unwrap();
        let mut bytes = container.serialize().unwrap();
        let payload_len_offset = bytes.len() - 8;
        let oversized = (BUNDLE_MAX_PAYLOAD_LEN.saturating_add(excess)).to_le_bytes();
        bytes[payload_len_offset..].copy_from_slice(&oversized);
        let result = BundleContainer::deserialize(&bytes);
        prop_assert!(matches!(result, Err(BundleContainerError::PayloadTooLarge(_, _))));
    }

    /// Truncation at any offset before the payload yields a
    /// truncation error or magic mismatch — never a partial value.
    #[test]
    fn deserialize_rejects_arbitrary_truncation(
        manifest in manifest_strategy(),
        payload in payload_strategy(),
        cut_ratio in 0u32..1024,
    ) {
        let container = BundleContainer::new(manifest, payload).unwrap();
        let bytes = container.serialize().unwrap();
        if bytes.is_empty() {
            return Ok(());
        }
        let cut = (cut_ratio as usize) % bytes.len();
        let truncated = &bytes[..cut];
        let result = BundleContainer::deserialize(truncated);
        prop_assert!(matches!(
            result,
            Err(BundleContainerError::Truncated(_)
                | BundleContainerError::MagicMismatch
                | BundleContainerError::UnsupportedSchema(_))
        ));
    }
}

#[test]
fn manifest_max_lengths_are_self_consistent() {
    // Smoke: the documented manifest-length cap fits in a u32, and
    // the payload-length cap fits in a u64. The proptest harness
    // depends on both invariants when it casts.
    assert!(BUNDLE_MAX_MANIFEST_LEN <= u32::MAX as usize);
    assert!(BUNDLE_MAX_PAYLOAD_LEN <= u64::MAX);
}
