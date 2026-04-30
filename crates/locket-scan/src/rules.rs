//! Provider-token rules, env-file detection, and high-entropy heuristics.

use std::collections::BTreeMap;
use std::path::Path;

/// Default minimum length for high-entropy token detection.
pub const DEFAULT_MIN_ENTROPY_TOKEN_LEN: usize = 20;

/// Default Shannon entropy threshold in bits per character.
pub const DEFAULT_ENTROPY_THRESHOLD: f64 = 4.5;

/// High-entropy scanner rule thresholds.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct EntropyRule {
    /// Minimum printable token byte length to consider.
    pub min_len: usize,
    /// Shannon entropy threshold in bits per character.
    pub threshold: f64,
}

impl Default for EntropyRule {
    fn default() -> Self {
        Self { min_len: DEFAULT_MIN_ENTROPY_TOKEN_LEN, threshold: DEFAULT_ENTROPY_THRESHOLD }
    }
}

/// Returns true when `token` matches the default high-entropy fallback rule.
#[must_use]
pub fn is_default_high_entropy_token(token: &str) -> bool {
    is_high_entropy_token_with_rule(token, EntropyRule::default())
}

/// Returns true when `token` is a printable non-whitespace token with Shannon
/// entropy greater than or equal to `threshold`.
#[must_use]
pub fn is_high_entropy_token(token: &str, min_len: usize, threshold: f64) -> bool {
    is_high_entropy_token_with_rule(token, EntropyRule { min_len, threshold })
}

/// Returns true when `token` matches the configured high-entropy fallback rule.
#[must_use]
pub fn is_high_entropy_token_with_rule(token: &str, rule: EntropyRule) -> bool {
    token.len() >= rule.min_len
        && token.chars().all(|character| !character.is_whitespace() && !character.is_control())
        && !is_excluded_public_identifier(token)
        && shannon_entropy(token) >= rule.threshold
}

fn is_excluded_public_identifier(token: &str) -> bool {
    is_uuid_like(token) || is_checksum_like(token) || is_documented_public_id(token)
}

fn is_uuid_like(token: &str) -> bool {
    let bytes = token.as_bytes();
    bytes.len() == 36
        && [8, 13, 18, 23].iter().all(|index| bytes[*index] == b'-')
        && bytes
            .iter()
            .enumerate()
            .all(|(index, byte)| [8, 13, 18, 23].contains(&index) || byte.is_ascii_hexdigit())
}

fn is_checksum_like(token: &str) -> bool {
    matches!(token.len(), 32 | 40 | 64 | 128) && token.bytes().all(|byte| byte.is_ascii_hexdigit())
}

fn is_documented_public_id(token: &str) -> bool {
    token.starts_with("lk_proj_")
        || token.starts_with("lk_prof_")
        || token.starts_with("lk_sec_")
        || token.starts_with("lk_key_")
        || token.starts_with("lkdev1_")
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

/// Returns true when `token` matches a built-in provider prefix rule.
#[must_use]
pub fn is_provider_token(token: &str) -> bool {
    const PROVIDER_PREFIXES: &[&str] = &["sk_live_", "sk_test_", "ghp_", "github_pat_", "xoxb-"];

    PROVIDER_PREFIXES.iter().any(|prefix| token.starts_with(prefix) && token.len() > prefix.len())
}

pub fn is_env_file_label(path_label: &str) -> bool {
    Path::new(path_label)
        .file_name()
        .and_then(|file_name| file_name.to_str())
        .is_some_and(|file_name| file_name == ".env" || file_name.starts_with(".env."))
}
