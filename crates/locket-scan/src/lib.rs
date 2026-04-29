//! Scanner and redactor for Locket.

use std::collections::BTreeMap;

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

#[cfg(test)]
mod tests {
    use super::{is_default_high_entropy_token, is_high_entropy_token, shannon_entropy};

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
}
