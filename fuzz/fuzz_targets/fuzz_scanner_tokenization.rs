#![no_main]

use libfuzzer_sys::fuzz_target;
use locket_scan::{FindingKind, scan_text};

fuzz_target!(|data: &[u8]| {
    if data.len() > 8192 {
        return;
    }
    let input = String::from_utf8_lossy(data);
    let findings = scan_text("fuzz.txt", &input);
    for finding in findings {
        assert!(finding.line >= 1);
        assert!(finding.column >= 1);
        match finding.kind {
            FindingKind::HighEntropy | FindingKind::ProviderTokenPattern => {
                assert!(finding.token_length > 0);
            }
            FindingKind::EnvFileMarker => {
                assert_eq!(finding.token_length, 0);
            }
        }
    }
});
