//! Redaction of provider, high-entropy, and known secret values from text.

use std::collections::BTreeMap;

use crate::FindingKind;
use crate::detect::sensitive_detections;

struct RedactionSpan<'a> {
    start: usize,
    end: usize,
    kind: FindingKind,
    marker: Option<&'a str>,
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

/// Redacts provider-looking and high-entropy tokens from text.
#[must_use]
pub fn redact_text(text: &str) -> RedactionResult {
    redact_text_with_known_values(text, &[])
}

/// Redacts known secret values, provider-looking tokens, and high-entropy tokens from text.
///
/// Overlapping matches become one replacement covering their entire union. Known
/// values take marker priority over heuristics; ties keep the earliest match,
/// or the longest known value when matches start together. Counts track replacements.
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

fn redaction_detections<'a>(
    text: &str,
    known_values: &[KnownRedaction<'a>],
) -> Vec<RedactionSpan<'a>> {
    let mut detections: Vec<_> = sensitive_detections(text)
        .into_iter()
        .map(|detection| RedactionSpan {
            start: detection.start,
            end: detection.end,
            kind: detection.kind,
            marker: None,
        })
        .collect();
    detections.extend(known_value_detections(text, known_values));
    detections.sort_by(|left, right| {
        left.start
            .cmp(&right.start)
            .then_with(|| detection_priority(right).cmp(&detection_priority(left)))
            .then_with(|| (right.end - right.start).cmp(&(left.end - left.start)))
    });

    let mut non_overlapping: Vec<RedactionSpan<'a>> = Vec::new();
    for detection in detections {
        if let Some(previous) = non_overlapping.last_mut()
            && detection.start < previous.end
        {
            // Dropping overlapping matches can expose their trailing bytes.
            // Extend the covered range even when their marker loses priority.
            previous.end = previous.end.max(detection.end);
            if detection_priority(&detection) > detection_priority(previous) {
                previous.kind = detection.kind;
                previous.marker = detection.marker;
            }
        } else {
            non_overlapping.push(detection);
        }
    }
    non_overlapping
}

const fn detection_priority(detection: &RedactionSpan<'_>) -> u8 {
    match detection.kind {
        FindingKind::KnownSecretValue => 3,
        FindingKind::ProviderTokenPattern => 2,
        FindingKind::HighEntropy => 1,
        FindingKind::EnvFileMarker => 0,
    }
}

fn known_value_detections<'a>(
    text: &str,
    known_values: &[KnownRedaction<'a>],
) -> Vec<RedactionSpan<'a>> {
    let mut detections = Vec::new();
    for known_value in known_values {
        if known_value.value.is_empty() || known_value.value.len() > text.len() {
            continue;
        }

        for start in overlapping_match_indices(text, known_value.value) {
            let end = start + known_value.value.len();
            detections.push(RedactionSpan {
                start,
                end,
                kind: FindingKind::KnownSecretValue,
                marker: Some(known_value.marker),
            });
        }
    }
    detections
}

/// KMP retains the matched prefix after each hit, so even long repetitive
/// secrets take linear search time. Exact UTF-8 byte matches start and end on
/// character boundaries because the needle is a nonempty valid string.
fn overlapping_match_indices<'a>(
    text: &'a str,
    value: &'a str,
) -> impl Iterator<Item = usize> + 'a {
    let needle = value.as_bytes();
    let mut prefixes = vec![0; needle.len()];
    let mut matched = 0;
    for index in 1..needle.len() {
        while matched > 0 && needle[index] != needle[matched] {
            matched = prefixes[matched - 1];
        }
        if needle[index] == needle[matched] {
            matched += 1;
        }
        prefixes[index] = matched;
    }

    let mut bytes = text.bytes().enumerate();
    matched = 0;
    std::iter::from_fn(move || {
        for (index, byte) in bytes.by_ref() {
            while matched > 0 && byte != needle[matched] {
                matched = prefixes[matched - 1];
            }
            if byte == needle[matched] {
                matched += 1;
            }
            if matched == needle.len() {
                matched = prefixes[matched - 1];
                return Some(index + 1 - needle.len());
            }
        }
        None
    })
}

const fn redaction_marker(kind: FindingKind) -> &'static str {
    match kind {
        FindingKind::HighEntropy => "lk_redacted_HIGH_ENTROPY",
        FindingKind::ProviderTokenPattern => "lk_redacted_PROVIDER_TOKEN",
        FindingKind::EnvFileMarker => "",
        FindingKind::KnownSecretValue => "lk_redacted_KNOWN_SECRET",
    }
}

#[cfg(test)]
mod tests {
    use super::overlapping_match_indices;

    #[test]
    fn overlapping_matcher_agrees_with_search_at_every_character_boundary() {
        for text in ["ababaaba", "aaaaaaaa", "abcababcab", "ééé", "🦀é🦀é🦀", "", "xyz"]
        {
            for needle in ["a", "aa", "aaa", "aba", "ababcab", "éé", "🦀é🦀", "missing"] {
                let expected: Vec<_> = text
                    .char_indices()
                    .filter_map(|(start, _)| text[start..].starts_with(needle).then_some(start))
                    .collect();
                assert_eq!(overlapping_match_indices(text, needle).collect::<Vec<_>>(), expected);
            }
        }
    }
}
