//! Scanner and redactor for Locket.

use std::collections::BTreeMap;
use std::path::Path;

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

impl FindingKind {
    /// Returns the stable rule identifier for this finding kind.
    #[must_use]
    pub const fn rule_id(self) -> &'static str {
        match self {
            Self::HighEntropy => RULE_ID_HIGH_ENTROPY,
            Self::ProviderTokenPattern => RULE_ID_PROVIDER_TOKEN,
            Self::EnvFileMarker => RULE_ID_ENV_FILE,
            Self::KnownSecretValue => RULE_ID_KNOWN_SECRET,
        }
    }

    /// Returns true when inline suppression comments may suppress findings of this kind.
    ///
    /// Per spec, inline suppression applies to high-entropy findings only. Known-secret,
    /// provider-token, and `.env` file findings are not suppressible inline.
    #[must_use]
    pub const fn allows_inline_suppression(self) -> bool {
        matches!(self, Self::HighEntropy)
    }
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

/// A finding that an inline suppression comment removed from the active set.
///
/// Suppressed findings carry only metadata-safe context (path, line, column, rule id,
/// and reason text). They never carry the matched token value.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SuppressedFinding {
    /// Caller-provided path label.
    pub path_label: String,
    /// One-based line number where the finding occurred.
    pub line: usize,
    /// One-based column number where the finding occurred.
    pub column: usize,
    /// Length of the detected token in bytes.
    pub token_length: usize,
    /// Finding kind that was suppressed.
    pub kind: FindingKind,
    /// Stable rule identifier for the suppressed finding kind.
    pub rule_id: &'static str,
    /// Caller-provided reason text from the suppression comment, or empty when none.
    pub reason: String,
}

/// Result of partitioning scan findings against inline suppression comments in the
/// scanned text.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct SuppressionResult {
    /// Findings that remain after applying inline suppression.
    pub kept: Vec<ScanFinding>,
    /// Findings that an inline comment suppressed.
    pub suppressed: Vec<SuppressedFinding>,
}

/// Partitions `findings` into kept and inline-suppressed groups.
///
/// Suppression markers are case-sensitive comment fragments anywhere on a line:
///
/// - `locket-allow` (optionally followed by `: <reason>`) suppresses high-entropy
///   findings on the same line.
/// - `locket-allow-next-line` (optionally followed by `: <reason>`) suppresses
///   high-entropy findings on the next non-empty line.
///
/// Per the scan spec, only high-entropy findings may be suppressed inline. Known-secret,
/// provider-token, and `.env` file findings always pass through unchanged so suppression
/// can never silence a known-secret match.
///
/// `findings` must come from a scan of the same `text`; line numbers are matched
/// directly. Suppressed findings carry path, line, column, length, rule id, and reason
/// only — they never include the matched value.
#[must_use]
pub fn partition_inline_suppressions(text: &str, findings: Vec<ScanFinding>) -> SuppressionResult {
    let directives = collect_inline_suppressions(text);
    let mut kept = Vec::new();
    let mut suppressed = Vec::new();

    for finding in findings {
        if finding.kind.allows_inline_suppression()
            && let Some(reason) = directives.get(&finding.line)
        {
            suppressed.push(SuppressedFinding {
                path_label: finding.path_label,
                line: finding.line,
                column: finding.column,
                token_length: finding.token_length,
                kind: finding.kind,
                rule_id: finding.kind.rule_id(),
                reason: reason.clone(),
            });
        } else {
            kept.push(finding);
        }
    }

    SuppressionResult { kept, suppressed }
}

/// Returns a map from line numbers to reason text for every inline suppression
/// directive that targets a finding line in `text`.
///
/// Same-line `locket-allow` directives map to the same line they appear on. Next-line
/// `locket-allow-next-line` directives map to the next non-empty line after the
/// directive. Both directives on the same line activate independently.
fn collect_inline_suppressions(text: &str) -> BTreeMap<usize, String> {
    let mut directives = BTreeMap::new();
    let lines: Vec<&str> = text.split('\n').collect();

    for (index, line) in lines.iter().enumerate() {
        let line_number = index + 1;

        if let Some(reason) = parse_suppression_marker(line, INLINE_SUPPRESS_NEXT_MARKER) {
            let mut target = index + 1;
            while target < lines.len() && lines[target].trim().is_empty() {
                target += 1;
            }
            if target < lines.len() {
                directives.entry(target + 1).or_insert_with(|| reason.clone());
            }
        }

        if let Some(reason) = parse_suppression_marker(line, INLINE_SUPPRESS_LINE_MARKER) {
            directives.insert(line_number, reason);
        }
    }

    directives
}

/// Returns the reason text for a suppression marker if `line` contains `marker`.
///
/// Reason text is the trimmed portion after the first `:` following the marker. Markers
/// not followed by `:` map to an empty reason. The same-line marker `locket-allow` must
/// not match the longer `locket-allow-next-line` marker; callers handle the longer
/// marker first to avoid ambiguity.
fn parse_suppression_marker(line: &str, marker: &str) -> Option<String> {
    let mut search_from = 0;
    while let Some(relative) = line[search_from..].find(marker) {
        let start = search_from + relative;
        let end = start + marker.len();

        let next_char = line[end..].chars().next();
        let is_word_continuation =
            next_char.is_some_and(|character| character.is_alphanumeric() || character == '-');
        if is_word_continuation {
            search_from = end;
            continue;
        }

        let reason = line[end..].split_once(':').map_or(String::new(), |(_prefix, after)| {
            after.split(['\n', '\r']).next().unwrap_or("").trim().to_owned()
        });
        return Some(reason);
    }
    None
}

/// Result of redacting secret-looking text.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RedactionResult {
    /// Redacted text.
    pub text: String,
    /// Number of replacements by finding kind.
    pub counts: BTreeMap<FindingKind, usize>,
}

/// A plaintext known secret value and the label that should replace it.
#[derive(Debug, Clone, Copy)]
pub struct KnownRedaction<'a> {
    /// Secret value to match exactly.
    pub value: &'a str,
    /// Redaction label to emit in place of the value.
    pub marker: &'a str,
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
    redact_text_with_known_values(text, &[])
}

/// Redacts known secret values, provider-looking tokens, and high-entropy tokens from text.
#[must_use]
pub fn redact_text_with_known_values(
    text: &str,
    known_values: &[KnownRedaction<'_>],
) -> RedactionResult {
    let mut redacted = String::with_capacity(text.len());
    let mut counts = BTreeMap::<FindingKind, usize>::new();
    let mut cursor = 0;

    for detection in redaction_detections(text, known_values) {
        redacted.push_str(&text[cursor..detection.start]);
        redacted.push_str(detection.marker.unwrap_or_else(|| redaction_marker(detection.kind)));
        cursor = detection.end;
        *counts.entry(detection.kind).or_default() += 1;
    }

    redacted.push_str(&text[cursor..]);

    RedactionResult { text: redacted, counts }
}

fn redaction_detections<'a>(text: &str, known_values: &[KnownRedaction<'a>]) -> Vec<Detection<'a>> {
    let mut detections = sensitive_detections(text);
    detections.extend(known_value_detections(text, known_values));
    detections.sort_by(|left, right| {
        left.start
            .cmp(&right.start)
            .then_with(|| detection_priority(right).cmp(&detection_priority(left)))
            .then_with(|| (right.end - right.start).cmp(&(left.end - left.start)))
    });

    let mut non_overlapping = Vec::new();
    let mut cursor = 0;
    for detection in detections {
        if detection.start >= cursor {
            cursor = detection.end;
            non_overlapping.push(detection);
        }
    }
    non_overlapping
}

const fn detection_priority(detection: &Detection<'_>) -> u8 {
    match detection.kind {
        FindingKind::KnownSecretValue => 3,
        FindingKind::ProviderTokenPattern => 2,
        FindingKind::HighEntropy => 1,
        FindingKind::EnvFileMarker => 0,
    }
}

fn sensitive_detections(text: &str) -> Vec<Detection<'static>> {
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
                    marker: None,
                });
            } else if is_default_high_entropy_token(candidate.value) {
                detections.push(Detection {
                    start: candidate.start,
                    end: candidate.end,
                    line: token.line,
                    column: token.column + token.value[..candidate.relative_start].chars().count(),
                    kind: FindingKind::HighEntropy,
                    marker: None,
                });
            }
        }
    }

    detections
}

fn known_value_detections<'a>(
    text: &str,
    known_values: &[KnownRedaction<'a>],
) -> Vec<Detection<'a>> {
    let mut detections = Vec::new();
    for known_value in known_values {
        if known_value.value.is_empty() {
            continue;
        }

        let mut cursor = 0;
        while let Some(relative_start) = text[cursor..].find(known_value.value) {
            let start = cursor + relative_start;
            let end = start + known_value.value.len();
            let (line, column) = line_column(text, start);
            detections.push(Detection {
                start,
                end,
                line,
                column,
                kind: FindingKind::KnownSecretValue,
                marker: Some(known_value.marker),
            });
            cursor = end;
        }
    }
    detections
}

fn line_column(text: &str, byte_index: usize) -> (usize, usize) {
    let mut line = 1;
    let mut column = 1;
    for character in text[..byte_index].chars() {
        if character == '\n' {
            line += 1;
            column = 1;
        } else {
            column += 1;
        }
    }
    (line, column)
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
struct Detection<'a> {
    start: usize,
    end: usize,
    line: usize,
    column: usize,
    kind: FindingKind,
    marker: Option<&'a str>,
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
        FindingKind, KnownRedaction, RULE_ID_HIGH_ENTROPY, ScanFinding,
        is_default_high_entropy_token, is_high_entropy_token, partition_inline_suppressions,
        redact_text, redact_text_with_known_values, scan_text, shannon_entropy,
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

    #[test]
    fn redact_text_replaces_known_values_with_specific_markers() {
        let result = redact_text_with_known_values(
            "db=postgres://localhost/app token=sk_test_sampleTokenValue123\n",
            &[KnownRedaction {
                value: "postgres://localhost/app",
                marker: "lk_redacted_DATABASE_URL",
            }],
        );

        assert!(!result.text.contains("postgres://localhost/app"));
        assert!(result.text.contains("db=lk_redacted_DATABASE_URL"));
        assert!(result.text.contains("token=lk_redacted_PROVIDER_TOKEN"));
        assert_eq!(result.counts.get(&FindingKind::KnownSecretValue), Some(&1));
        assert_eq!(result.counts.get(&FindingKind::ProviderTokenPattern), Some(&1));
    }

    #[test]
    fn known_value_redaction_wins_over_pattern_redaction() {
        let provider = "sk_test_sampleTokenValue123";
        let result = redact_text_with_known_values(
            &format!("token={provider}\n"),
            &[KnownRedaction { value: provider, marker: "lk_redacted_OPENAI_API_KEY" }],
        );

        assert_eq!(result.text, "token=lk_redacted_OPENAI_API_KEY\n");
        assert_eq!(result.counts.get(&FindingKind::KnownSecretValue), Some(&1));
        assert_eq!(result.counts.get(&FindingKind::ProviderTokenPattern), None);
    }

    #[test]
    fn longer_known_value_wins_when_known_values_start_together() {
        let result = redact_text_with_known_values(
            "token=abcdef",
            &[
                KnownRedaction { value: "abc", marker: "lk_redacted_SHORT" },
                KnownRedaction { value: "abcdef", marker: "lk_redacted_LONG" },
            ],
        );

        assert_eq!(result.text, "token=lk_redacted_LONG");
        assert_eq!(result.counts.get(&FindingKind::KnownSecretValue), Some(&1));
    }

    #[test]
    fn empty_known_values_are_ignored() {
        let result = redact_text_with_known_values(
            "plain text",
            &[KnownRedaction { value: "", marker: "lk_redacted_EMPTY" }],
        );

        assert_eq!(result.text, "plain text");
        assert!(result.counts.is_empty());
    }

    #[test]
    fn scan_text_reports_candidate_column_after_boundaries() {
        let token = "sk_live_sampleTokenValue123";
        let findings = scan_text("config.json", &format!("  api_key=\"{token}\""));

        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].line, 1);
        assert_eq!(findings[0].column, 12);
        assert_eq!(findings[0].token_length, token.len());
        assert_eq!(findings[0].kind, FindingKind::ProviderTokenPattern);
    }

    #[test]
    fn inline_suppression_removes_high_entropy_findings_on_same_line() {
        let entropy = "Z9a$kLmN2pQx7R!sT4vW8yB3cD6eF";
        let text = format!("token={entropy} # locket-allow: known random fixture\n");
        let findings = scan_text("notes.txt", &text);

        let result = partition_inline_suppressions(&text, findings);

        assert!(result.kept.is_empty());
        assert_eq!(result.suppressed.len(), 1);
        let suppressed = &result.suppressed[0];
        assert_eq!(suppressed.kind, FindingKind::HighEntropy);
        assert_eq!(suppressed.rule_id, RULE_ID_HIGH_ENTROPY);
        assert_eq!(suppressed.path_label, "notes.txt");
        assert_eq!(suppressed.line, 1);
        assert_eq!(suppressed.reason, "known random fixture");
        assert!(!format!("{suppressed:?}").contains(entropy));
    }

    #[test]
    fn inline_suppression_supports_next_line_marker() {
        let entropy = "Z9a$kLmN2pQx7R!sT4vW8yB3cD6eF";
        let text = format!("// locket-allow-next-line: fixture\n{entropy}\n");
        let findings = scan_text("notes.txt", &text);

        let result = partition_inline_suppressions(&text, findings);

        assert!(result.kept.is_empty());
        assert_eq!(result.suppressed.len(), 1);
        assert_eq!(result.suppressed[0].kind, FindingKind::HighEntropy);
        assert_eq!(result.suppressed[0].line, 2);
        assert_eq!(result.suppressed[0].reason, "fixture");
    }

    #[test]
    fn next_line_marker_skips_blank_lines_to_next_non_empty_line() {
        let entropy = "Z9a$kLmN2pQx7R!sT4vW8yB3cD6eF";
        let text = format!("// locket-allow-next-line\n\n   \n{entropy}\n");
        let findings = scan_text("notes.txt", &text);

        let result = partition_inline_suppressions(&text, findings);

        assert!(result.kept.is_empty());
        assert_eq!(result.suppressed.len(), 1);
        assert_eq!(result.suppressed[0].line, 4);
        assert_eq!(result.suppressed[0].reason, "");
    }

    #[test]
    fn inline_suppression_does_not_silence_known_secret_matches() {
        let path = "leak.txt";
        let suppressed_finding = ScanFinding {
            path_label: path.to_owned(),
            line: 1,
            column: 1,
            token_length: 16,
            kind: FindingKind::KnownSecretValue,
        };
        let text = "secret-value # locket-allow: hide it\n";

        let result = partition_inline_suppressions(text, vec![suppressed_finding.clone()]);

        assert_eq!(result.kept, vec![suppressed_finding]);
        assert!(result.suppressed.is_empty());
    }

    #[test]
    fn inline_suppression_does_not_silence_provider_token_or_env_file_findings() {
        let provider_token = "sk_live_sampleTokenValue123";
        let text = format!("token={provider_token} # locket-allow: nope\n");
        let findings = scan_text(".env.local", &text);

        let result = partition_inline_suppressions(&text, findings);

        assert!(result.suppressed.is_empty());
        assert!(
            result.kept.iter().any(|finding| finding.kind == FindingKind::ProviderTokenPattern)
        );
        assert!(result.kept.iter().any(|finding| finding.kind == FindingKind::EnvFileMarker));
    }

    #[test]
    fn next_line_marker_on_last_line_is_a_noop() {
        let text = "// locket-allow-next-line: nothing follows\n";
        let findings = scan_text("notes.txt", text);

        let result = partition_inline_suppressions(text, findings);

        assert!(result.kept.is_empty());
        assert!(result.suppressed.is_empty());
    }

    #[test]
    fn line_marker_does_not_match_next_line_marker_substring() {
        let entropy = "Z9a$kLmN2pQx7R!sT4vW8yB3cD6eF";
        let text = format!("token={entropy} # locket-allow-next-line: previous-line note\n");
        let findings = scan_text("notes.txt", &text);

        let result = partition_inline_suppressions(&text, findings);

        assert_eq!(result.kept.len(), 1);
        assert_eq!(result.kept[0].kind, FindingKind::HighEntropy);
        assert!(result.suppressed.is_empty());
    }
}
