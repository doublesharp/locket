//! Scanner and redactor for Locket.

mod detect;
mod finding;
mod redact;
mod rules;
mod suppressions;

#[cfg(test)]
mod tests;

pub use finding::{
    FindingKind, ScanFinding, Severity, SuppressedFinding, SuppressionResult,
    partition_inline_suppressions, partition_inline_suppressions_strict,
};
pub use redact::{KnownRedaction, RedactionResult, redact_text, redact_text_with_known_values};
pub use rules::{
    DEFAULT_ENTROPY_THRESHOLD, DEFAULT_MIN_ENTROPY_TOKEN_LEN, EntropyRule,
    is_default_high_entropy_token, is_high_entropy_token, is_high_entropy_token_with_rule,
    is_provider_token, shannon_entropy,
};
pub use suppressions::{
    FILE_LEVEL_MAX_LINE, MAX_REASON_LENGTH, MIN_REASON_LENGTH, SUPPRESS_BLOCK_END_MARKER,
    SUPPRESS_BLOCK_START_MARKER, SUPPRESS_FILE_MARKER, SUPPRESS_LINE_MARKER, SuppressionMap,
    SuppressionParseError, parse_suppression_map,
};

use detect::sensitive_detections_with_entropy_rule;
use rules::is_env_file_label;

/// Inline suppression marker that suppresses high-entropy findings on the same line.
pub const INLINE_SUPPRESS_LINE_MARKER: &str = "locket-allow";

/// Inline suppression marker that suppresses high-entropy findings on the next non-empty line.
pub const INLINE_SUPPRESS_NEXT_MARKER: &str = "locket-allow-next-line";

/// Stable rule identifier for high-entropy findings.
pub const RULE_ID_HIGH_ENTROPY: &str = "high-entropy";

/// Stable rule identifier for provider-token pattern findings.
pub const RULE_ID_PROVIDER_TOKEN: &str = "provider-token-pattern";

/// Stable rule identifier for `.env` file findings.
pub const RULE_ID_ENV_FILE: &str = "env-file";

/// Stable rule identifier for known-secret value findings.
pub const RULE_ID_KNOWN_SECRET: &str = "known-secret";

/// Scans text for metadata-safe findings.
///
/// Findings contain only path, position, length, and kind. They never include
/// the original token value.
#[must_use]
pub fn scan_text(path_label: &str, text: &str) -> Vec<ScanFinding> {
    scan_text_with_entropy_rule(path_label, text, EntropyRule::default())
}

/// Scans text using a configured high-entropy rule.
#[must_use]
pub fn scan_text_with_entropy_rule(
    path_label: &str,
    text: &str,
    entropy_rule: EntropyRule,
) -> Vec<ScanFinding> {
    let mut findings = Vec::new();

    if is_env_file_label(path_label) {
        findings.push(ScanFinding {
            path_label: path_label.to_owned(),
            line: 1,
            column: 1,
            token_length: 0,
            kind: FindingKind::EnvFileMarker,
        });
    }

    for detection in sensitive_detections_with_entropy_rule(text, entropy_rule) {
        findings.push(ScanFinding {
            path_label: path_label.to_owned(),
            line: detection.line,
            column: detection.column,
            token_length: detection.end - detection.start,
            kind: detection.kind,
        });
    }

    findings
}
