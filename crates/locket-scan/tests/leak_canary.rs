//! Leak-canary coverage for scanner/redactor outputs.

use locket_scan::{
    FindingKind, KnownRedaction, redact_text, redact_text_with_known_values, scan_text,
};

// `thiserror` is a transitive build dependency through `locket-scan`'s lib but is not
// used in this integration test crate; silence `unused_crate_dependencies`.
use thiserror as _;

fn provider_canary() -> String {
    format!("{}{}", "sk", "_test_locketCanaryValue1234567890")
}

fn known_value_canary() -> String {
    format!("{}{}", "locket-canary-", "known-value-1234567890")
}

#[test]
fn leak_canary_redacts_provider_tokens_without_echoing_values() {
    let canary = provider_canary();
    let input = format!("token={canary}\n");

    let result = redact_text(&input);
    let findings = scan_text("canary.log", &input);
    let finding_debug = format!("{findings:?}");

    assert!(result.text.contains("lk_redacted_PROVIDER_TOKEN"));
    assert!(!result.text.contains(&canary));
    assert!(!finding_debug.contains(&canary));
    assert!(findings.iter().any(|finding| finding.kind == FindingKind::ProviderTokenPattern));
}

#[test]
fn leak_canary_redacts_known_values_without_echoing_values() {
    let canary = known_value_canary();
    let input = format!("database_url={canary}\n");
    let known = [KnownRedaction { value: canary.as_str(), marker: "lk_redacted_DATABASE_URL" }];

    let result = redact_text_with_known_values(&input, &known);

    assert!(result.text.contains("lk_redacted_DATABASE_URL"));
    assert!(!result.text.contains(&canary));
}
