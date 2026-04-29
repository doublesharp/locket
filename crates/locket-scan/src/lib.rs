//! Scanner and redactor for Locket.

use std::collections::BTreeMap;
use std::path::Path;

/// Default minimum length for high-entropy token detection.
pub const DEFAULT_MIN_ENTROPY_TOKEN_LEN: usize = 20;

/// Default Shannon entropy threshold in bits per character.
pub const DEFAULT_ENTROPY_THRESHOLD: f64 = 4.5;

/// Type of scanner finding.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum FindingKind {
    /// Token matched the default high-entropy fallback rule.
    HighEntropy,
    /// Token matched a built-in provider token prefix rule.
    ProviderTokenPattern,
    /// Path label identifies an environment file.
    EnvFileMarker,
    /// Text exactly matched a known vault secret value.
    KnownSecretValue,
}

/// Metadata-only scanner finding.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ScanFinding {
    /// Caller-provided path label.
    pub path_label: String,
    /// One-based line number.
    pub line: usize,
    /// One-based column number.
    pub column: usize,
    /// Length of the detected token in bytes.
    pub token_length: usize,
    /// Finding kind.
    pub kind: FindingKind,
}

/// Result of redacting secret-looking text.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RedactionResult {
    /// Redacted text.
    pub text: String,
    /// Number of replacements by finding kind.
    pub counts: BTreeMap<FindingKind, usize>,
}

/// Returns true when `token` matches the default high-entropy fallback rule.
#[must_use]
pub fn is_default_high_entropy_token(token: &str) -> bool {
    is_high_entropy_token(token, DEFAULT_MIN_ENTROPY_TOKEN_LEN, DEFAULT_ENTROPY_THRESHOLD)
}

/// Returns true when `token` is a printable non-whitespace token with Shannon
/// entropy greater than or equal to `threshold`.
#[must_use]
pub fn is_high_entropy_token(token: &str, min_len: usize, threshold: f64) -> bool {
    token.len() >= min_len
        && token.chars().all(|character| !character.is_whitespace() && !character.is_control())
        && shannon_entropy(token) >= threshold
}

/// Computes Shannon entropy in bits per character.
#[must_use]
#[allow(clippy::cast_precision_loss)]
pub fn shannon_entropy(token: &str) -> f64 {
    if token.is_empty() {
        return 0.0;
    }

    let mut counts = BTreeMap::<char, usize>::new();
    for character in token.chars() {
        *counts.entry(character).or_default() += 1;
    }

    let total = token.chars().count() as f64;
    counts
        .values()
        .map(|count| {
            let probability = *count as f64 / total;
            -probability * probability.log2()
        })
        .sum()
}

/// Scans text for metadata-safe findings.
///
/// Findings contain only path, position, length, and kind. They never include
/// the original token value.
#[must_use]
pub fn scan_text(path_label: &str, text: &str) -> Vec<ScanFinding> {
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

    for detection in sensitive_detections(text) {
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

/// Redacts provider-looking and high-entropy tokens from text.
#[must_use]
pub fn redact_text(text: &str) -> RedactionResult {
    let mut redacted = String::with_capacity(text.len());
    let mut counts = BTreeMap::<FindingKind, usize>::new();
    let mut cursor = 0;

    for detection in sensitive_detections(text) {
        redacted.push_str(&text[cursor..detection.start]);
        redacted.push_str(redaction_marker(detection.kind));
        cursor = detection.end;
        *counts.entry(detection.kind).or_default() += 1;
    }

    redacted.push_str(&text[cursor..]);

    RedactionResult { text: redacted, counts }
}

fn sensitive_detections(text: &str) -> Vec<Detection> {
    let mut detections = Vec::new();

    for token in printable_tokens(text) {
        for candidate in candidate_segments(token) {
            if is_provider_token(candidate.value) {
                detections.push(Detection {
                    start: candidate.start,
                    end: candidate.end,
                    line: token.line,
                    column: token.column + token.value[..candidate.relative_start].chars().count(),
                    kind: FindingKind::ProviderTokenPattern,
                });
            } else if is_default_high_entropy_token(candidate.value) {
                detections.push(Detection {
                    start: candidate.start,
                    end: candidate.end,
                    line: token.line,
                    column: token.column + token.value[..candidate.relative_start].chars().count(),
                    kind: FindingKind::HighEntropy,
                });
            }
        }
    }

    detections
}

const fn redaction_marker(kind: FindingKind) -> &'static str {
    match kind {
        FindingKind::HighEntropy => "lk_redacted_HIGH_ENTROPY",
        FindingKind::ProviderTokenPattern => "lk_redacted_PROVIDER_TOKEN",
        FindingKind::EnvFileMarker => "",
        FindingKind::KnownSecretValue => "lk_redacted_KNOWN_SECRET",
    }
}

#[derive(Debug, Clone, Copy)]
struct Detection {
    start: usize,
    end: usize,
    line: usize,
    column: usize,
    kind: FindingKind,
}

/// Returns true when `token` matches a built-in provider prefix rule.
#[must_use]
pub fn is_provider_token(token: &str) -> bool {
    const PROVIDER_PREFIXES: &[&str] = &["sk_live_", "sk_test_", "ghp_", "github_pat_", "xoxb-"];

    PROVIDER_PREFIXES.iter().any(|prefix| token.starts_with(prefix) && token.len() > prefix.len())
}

#[derive(Debug, Clone, Copy)]
struct Token<'a> {
    value: &'a str,
    start: usize,
    line: usize,
    column: usize,
}

#[derive(Debug, Clone, Copy)]
struct CandidateSegment<'a> {
    value: &'a str,
    start: usize,
    end: usize,
    relative_start: usize,
}

fn candidate_segments(token: Token<'_>) -> Vec<CandidateSegment<'_>> {
    let mut candidates = Vec::new();
    let mut segment_start = 0;

    for (index, character) in token.value.char_indices() {
        if is_token_boundary(character) {
            push_candidate_segment(&mut candidates, token, segment_start, index);
            segment_start = index + character.len_utf8();
        }
    }

    push_candidate_segment(&mut candidates, token, segment_start, token.value.len());
    candidates
}

fn push_candidate_segment<'a>(
    candidates: &mut Vec<CandidateSegment<'a>>,
    token: Token<'a>,
    relative_start: usize,
    relative_end: usize,
) {
    if relative_start < relative_end {
        candidates.push(CandidateSegment {
            value: &token.value[relative_start..relative_end],
            start: token.start + relative_start,
            end: token.start + relative_end,
            relative_start,
        });
    }
}

const fn is_token_boundary(character: char) -> bool {
    matches!(
        character,
        '=' | ':' | '"' | '\'' | '`' | ',' | ';' | '(' | ')' | '[' | ']' | '{' | '}' | '<' | '>'
    )
}

fn printable_tokens(text: &str) -> Vec<Token<'_>> {
    let mut tokens = Vec::new();
    let mut token_start = None;
    let mut token_line = 1;
    let mut token_column = 1;
    let mut line = 1;
    let mut column = 1;

    for (index, character) in text.char_indices() {
        if character == '\n' {
            if let Some(start) = token_start.take() {
                tokens.push(Token {
                    value: &text[start..index],
                    start,
                    line: token_line,
                    column: token_column,
                });
            }
            line += 1;
            column = 1;
            continue;
        }

        if character.is_whitespace() || character.is_control() {
            if let Some(start) = token_start.take() {
                tokens.push(Token {
                    value: &text[start..index],
                    start,
                    line: token_line,
                    column: token_column,
                });
            }
        } else if token_start.is_none() {
            token_start = Some(index);
            token_line = line;
            token_column = column;
        }

        column += 1;
    }

    if let Some(start) = token_start {
        tokens.push(Token { value: &text[start..], start, line: token_line, column: token_column });
    }

    tokens
}

fn is_env_file_label(path_label: &str) -> bool {
    Path::new(path_label)
        .file_name()
        .and_then(|file_name| file_name.to_str())
        .is_some_and(|file_name| file_name == ".env" || file_name.starts_with(".env."))
}

#[cfg(test)]
mod tests {
    use super::{
        FindingKind, is_default_high_entropy_token, is_high_entropy_token, redact_text, scan_text,
        shannon_entropy,
    };

    #[test]
    fn entropy_is_zero_for_empty_or_repeated_tokens() {
        assert!(shannon_entropy("").abs() < f64::EPSILON);
        assert!(shannon_entropy("aaaaaaaaaaaaaaaaaaaa").abs() < f64::EPSILON);
    }

    #[test]
    fn default_rule_rejects_short_tokens() {
        assert!(!is_default_high_entropy_token("aB3$dE5&gH7*"));
    }

    #[test]
    fn default_rule_rejects_whitespace_and_control_characters() {
        assert!(!is_default_high_entropy_token("abcd efgh ijkl mnop qrst uvwx yz12"));
        assert!(!is_default_high_entropy_token("abcd\nefghijklmnopqrstuvwxyz123456"));
    }

    #[test]
    fn default_rule_flags_high_entropy_tokens() {
        assert!(is_default_high_entropy_token("Z9a$kLmN2pQx7R!sT4vW8yB3cD6eF"));
    }

    #[test]
    fn custom_threshold_can_be_lowered() {
        assert!(is_high_entropy_token("abcabcabcabcabcabcab", 20, 1.0));
    }

    #[test]
    fn scan_text_reports_metadata_without_token_values() {
        let token = "sk_live_sampleTokenValue123";
        let findings = scan_text("config.txt", &format!("prefix\n  {token}\n"));

        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].path_label, "config.txt");
        assert_eq!(findings[0].line, 2);
        assert_eq!(findings[0].column, 3);
        assert_eq!(findings[0].token_length, token.len());
        assert_eq!(findings[0].kind, FindingKind::ProviderTokenPattern);
        assert!(!format!("{:?}", findings[0]).contains(token));
    }

    #[test]
    fn scan_text_flags_default_high_entropy_tokens() {
        let token = "Z9a$kLmN2pQx7R!sT4vW8yB3cD6eF";
        let findings = scan_text("notes.txt", token);

        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].line, 1);
        assert_eq!(findings[0].column, 1);
        assert_eq!(findings[0].token_length, token.len());
        assert_eq!(findings[0].kind, FindingKind::HighEntropy);
        assert!(!format!("{:?}", findings[0]).contains(token));
    }

    #[test]
    fn scan_text_flags_env_file_names_without_reading_values() {
        let findings = scan_text("service/.env.local", "DATABASE_URL=postgres://user:pass@host/db");

        assert!(findings.iter().any(|finding| finding.kind == FindingKind::EnvFileMarker));
        assert!(!format!("{findings:?}").contains("postgres://user:pass@host/db"));
    }

    #[test]
    fn redact_text_replaces_provider_and_high_entropy_tokens() {
        let provider = "github_pat_sampleTokenValue123";
        let entropy = "Z9a$kLmN2pQx7R!sT4vW8yB3cD6eF";
        let result = redact_text(&format!("token={provider}\nrandom={entropy}\n"));

        assert!(!result.text.contains(provider));
        assert!(!result.text.contains(entropy));
        assert!(result.text.contains("lk_redacted_PROVIDER_TOKEN"));
        assert!(result.text.contains("lk_redacted_HIGH_ENTROPY"));
        assert_eq!(result.counts.get(&FindingKind::ProviderTokenPattern), Some(&1));
        assert_eq!(result.counts.get(&FindingKind::HighEntropy), Some(&1));
    }
}
