//! Redaction of provider, high-entropy, and known secret values from text.

use std::collections::BTreeMap;

use crate::FindingKind;
use crate::detect::{Detection, line_column, sensitive_detections};

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

const fn redaction_marker(kind: FindingKind) -> &'static str {
    match kind {
        FindingKind::HighEntropy => "lk_redacted_HIGH_ENTROPY",
        FindingKind::ProviderTokenPattern => "lk_redacted_PROVIDER_TOKEN",
        FindingKind::EnvFileMarker => "",
        FindingKind::KnownSecretValue => "lk_redacted_KNOWN_SECRET",
    }
}
