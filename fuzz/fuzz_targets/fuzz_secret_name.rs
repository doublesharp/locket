#![no_main]

use libfuzzer_sys::fuzz_target;
use locket_core::SecretName;

fuzz_target!(|data: &[u8]| {
    if let Ok(value) = std::str::from_utf8(data) {
        let parsed = SecretName::new(value);
        if let Ok(name) = parsed {
            assert_eq!(name.as_str(), value);
            assert!(!value.is_empty());
        }
    }
});
