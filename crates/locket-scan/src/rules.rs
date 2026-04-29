//! Provider-token rules, env-file detection, and high-entropy heuristics.

use std::collections::BTreeMap;
use std::path::Path;

/// Default minimum length for high-entropy token detection.
pub const DEFAULT_MIN_ENTROPY_TOKEN_LEN: usize = 20;

/// Default Shannon entropy threshold in bits per character.
pub const DEFAULT_ENTROPY_THRESHOLD: f64 = 4.5;

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
