//! Scanner finding types and inline suppression handling.

use std::collections::BTreeMap;

use crate::{
    INLINE_SUPPRESS_LINE_MARKER, INLINE_SUPPRESS_NEXT_MARKER, RULE_ID_ENV_FILE,
    RULE_ID_HIGH_ENTROPY, RULE_ID_KNOWN_SECRET, RULE_ID_PROVIDER_TOKEN,
};

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

/// Severity level assigned to a scanner finding.
///
/// `Blocking` findings make `locket scan` fail closed; `Warning` findings are
/// reported but exit successfully. Order is meaningful: `Warning < Blocking` so
/// callers may compute the max severity over a finding set.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Severity {
    /// Reported but does not fail the command.
    Warning,
    /// Fails the command with a typed `ScanFindingBlocked` error.
    Blocking,
}

impl Severity {
    /// Stable lowercase label used in CLI output and audit metadata.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Warning => "warning",
            Self::Blocking => "blocking",
        }
    }
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

    /// Default severity per `docs/specs/scan-redaction.md:51-56`.
    ///
    /// Known-secret matches are blocking by default; provider-token, high-entropy,
    /// and `.env` findings are warnings by default. Project policy may upgrade
    /// provider-token and `.env` findings to blocking; that policy hook is not
    /// yet wired here.
    #[must_use]
    pub const fn default_severity(self) -> Severity {
        match self {
            Self::KnownSecretValue => Severity::Blocking,
            Self::HighEntropy | Self::ProviderTokenPattern | Self::EnvFileMarker => {
                Severity::Warning
            }
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
