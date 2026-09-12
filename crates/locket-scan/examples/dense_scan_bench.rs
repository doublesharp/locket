//! Measures scanning many delimiter-separated secrets on one Unicode line.

#![allow(clippy::print_stdout)]

use std::hint::black_box;
use std::time::Instant;

use locket_scan::{FindingKind, scan_text};
use thiserror as _;

fn main() {
    let record = "é=ghp_example,";
    for count in [1_000, 5_000, 10_000] {
        let text = record.repeat(count);
        let mut durations = Vec::new();
        for _ in 0..7 {
            let start = Instant::now();
            let findings = scan_text("dense.txt", black_box(&text));
            durations.push(start.elapsed());
            assert_eq!(findings.len(), count);
            for (index, finding) in findings.iter().enumerate() {
                assert_eq!(finding.line, 1);
                assert_eq!(finding.column, index * record.chars().count() + 3);
                assert_eq!(finding.kind, FindingKind::ProviderTokenPattern);
                assert_eq!(finding.token_length, "ghp_example".len());
            }
        }
        durations.sort_unstable();
        println!("{count} findings, {} bytes: median {:?}", text.len(), durations[3]);
    }
}
