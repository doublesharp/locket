#![no_main]

use libfuzzer_sys::fuzz_target;
use locket_scan::{FindingKind, redact_text};

fuzz_target!(|data: &[u8]| {
    if data.len() > 8192 {
        return;
    }
    let input = String::from_utf8_lossy(data);
    let redacted = redact_text(&input);
    let replacement_count: usize = redacted.counts.values().sum();
    let max_marker_len = [
        FindingKind::HighEntropy,
        FindingKind::ProviderTokenPattern,
        FindingKind::KnownSecretValue,
    ]
    .into_iter()
    .map(redaction_marker_len)
    .max()
    .unwrap_or(0);
    let max_len = input.len().saturating_add(replacement_count.saturating_mul(max_marker_len));
    assert!(redacted.text.len() <= max_len);
});

const fn redaction_marker_len(kind: FindingKind) -> usize {
    match kind {
        FindingKind::HighEntropy => "lk_redacted_HIGH_ENTROPY".len(),
        FindingKind::ProviderTokenPattern => "lk_redacted_PROVIDER_TOKEN".len(),
        FindingKind::KnownSecretValue => "lk_redacted_KNOWN_SECRET".len(),
        FindingKind::EnvFileMarker => 0,
    }
}
