#![no_main]

use libfuzzer_sys::fuzz_target;
use locket_core::bundle::{BUNDLE_SCHEMA_V1, BundleContainer};

fuzz_target!(|data: &[u8]| {
    if data.len() > 8192 {
        return;
    }
    let Ok(bundle) = BundleContainer::deserialize(data) else {
        return;
    };

    assert_eq!(bundle.manifest.schema_version, BUNDLE_SCHEMA_V1);
    assert!(!bundle.manifest.project_id.is_empty());
    assert!(!bundle.manifest.payload_digest.is_empty());
    assert!(!bundle.manifest.project_id.contains('\0'));
    assert!(!bundle.manifest.payload_digest.contains('\0'));
    for fingerprint in &bundle.manifest.recipient_fingerprints {
        assert!(!fingerprint.contains('\0'));
    }

    let serialized = bundle.serialize().expect("accepted bundle should serialize");
    let reparsed =
        BundleContainer::deserialize(&serialized).expect("serialized bundle should parse");
    assert_eq!(bundle, reparsed);
});
