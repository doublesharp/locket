//! Repeatable known-secret redaction timing with an output correctness check.

#![allow(clippy::print_stdout)]

use std::hint::black_box;
use std::time::Instant;

use locket_scan::{FindingKind, KnownRedaction, redact_text_with_known_values};
use thiserror as _;

fn main() {
    let known = [KnownRedaction { value: "secret-value", marker: "[REDACTED]" }];
    for count in [1_000, 5_000, 10_000] {
        let text = "key=secret-value\n".repeat(count);
        let expected = "key=[REDACTED]\n".repeat(count);
        let mut durations = Vec::new();
        for _ in 0..7 {
            let start = Instant::now();
            let result = redact_text_with_known_values(black_box(&text), black_box(&known));
            durations.push(start.elapsed());
            assert_eq!(result.text, expected);
            assert_eq!(result.counts.get(&FindingKind::KnownSecretValue), Some(&count));
        }
        durations.sort_unstable();
        println!("{count} matches, {} bytes: median {:?}", text.len(), durations[3]);
    }

    for size in [1_000, 5_000, 10_000] {
        let value = "a".repeat(size);
        let text = value.repeat(3);
        let known = [KnownRedaction { value: &value, marker: "[REDACTED]" }];
        let mut durations = Vec::new();
        for _ in 0..7 {
            let start = Instant::now();
            let result = redact_text_with_known_values(black_box(&text), black_box(&known));
            durations.push(start.elapsed());
            assert_eq!(result.text, "[REDACTED]");
            assert_eq!(result.counts.get(&FindingKind::KnownSecretValue), Some(&1));
        }
        durations.sort_unstable();
        println!("{size}-byte repetitive secret, {} bytes: median {:?}", text.len(), durations[3]);
    }
}
