#![no_main]

use libfuzzer_sys::fuzz_target;
use locket_scan::{FindingKind, KnownRedaction, redact_text, redact_text_with_known_values};

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

    // Two occurrences of a doubled value overlap across three copies. Every
    // byte must be covered, including UTF-8 and heuristic token boundaries.
    if !input.is_empty() {
        let text = input.repeat(3);
        let known = input.repeat(2);
        let result = redact_text_with_known_values(
            &text,
            &[KnownRedaction { value: &known, marker: "[REDACTED]" }],
        );
        assert_eq!(result.text, "[REDACTED]");
        assert_eq!(result.counts.get(&FindingKind::KnownSecretValue), Some(&1));
    }
});

const fn redaction_marker_len(kind: FindingKind) -> usize {
    match kind {
        FindingKind::HighEntropy => "lk_redacted_HIGH_ENTROPY".len(),
        FindingKind::ProviderTokenPattern => "lk_redacted_PROVIDER_TOKEN".len(),
        FindingKind::KnownSecretValue => "lk_redacted_KNOWN_SECRET".len(),
        FindingKind::EnvFileMarker => 0,
    }
}
