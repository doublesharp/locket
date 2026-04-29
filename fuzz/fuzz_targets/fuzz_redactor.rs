#![no_main]

use libfuzzer_sys::fuzz_target;
use locket_scan::redact_text;

fuzz_target!(|data: &[u8]| {
    if data.len() > 8192 {
        return;
    }
    let input = String::from_utf8_lossy(data);
    let redacted = redact_text(&input);
    assert!(redacted.text.len() <= input.len().saturating_mul(2).saturating_add(256));
});
