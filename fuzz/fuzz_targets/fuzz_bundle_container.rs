#![no_main]

use libfuzzer_sys::fuzz_target;
use serde::Deserialize;

const BUNDLE_MAGIC_V1: &str = "LOCKET-BUNDLE-V1";

fuzz_target!(|data: &[u8]| {
    if data.len() > 8192 {
        return;
    }
    let Ok(bundle) = serde_json::from_slice::<SealedBundleFileV1>(data) else {
        return;
    };
    if bundle.magic == BUNDLE_MAGIC_V1
        && bundle.schema_version == 1
        && bundle.kind == "sealed-bundle"
    {
        assert_eq!(bundle.payload.profile_count, bundle.payload.profiles.len());
        let active_secret_count: usize =
            bundle.payload.profiles.iter().map(|profile| profile.active_secret_count).sum();
        assert_eq!(bundle.payload.active_secret_count, active_secret_count);
        assert!(!bundle.project_id.contains('\0'));
        assert_eq!(bundle.payload.audit_rows_included, bundle.include_audit);
        assert!(!bundle.payload_status.contains('\0'));
        assert!(!bundle.manifest_digest_sha256.contains('\0'));
        let _ = bundle.created_at;
        for fingerprint in &bundle.recipient_fingerprints {
            assert!(!fingerprint.contains('\0'));
        }
        for profile in &bundle.payload.profiles {
            assert!(!profile.profile_id.contains('\0'));
            let _ = profile.dangerous;
        }
    }
});

#[derive(Debug, Deserialize)]
struct SealedBundleFileV1 {
    magic: String,
    schema_version: u16,
    kind: String,
    created_at: i64,
    project_id: String,
    include_audit: bool,
    recipient_fingerprints: Vec<String>,
    payload_status: String,
    manifest_digest_sha256: String,
    payload: SealedBundlePayloadV1,
}

#[derive(Debug, Deserialize)]
struct SealedBundlePayloadV1 {
    profiles: Vec<SealedBundleProfileV1>,
    profile_count: usize,
    active_secret_count: usize,
    audit_rows_included: bool,
}

#[derive(Debug, Deserialize)]
struct SealedBundleProfileV1 {
    profile_id: String,
    dangerous: bool,
    active_secret_count: usize,
}
