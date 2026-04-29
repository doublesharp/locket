#![no_main]

use libfuzzer_sys::fuzz_target;
use locket_core::LkReferenceUri;

fuzz_target!(|data: &[u8]| {
    if data.len() > 2048 {
        return;
    }
    let Ok(input) = std::str::from_utf8(data) else {
        return;
    };

    let Ok(parsed) = LkReferenceUri::parse(input) else {
        return;
    };
    let mut rendered = format!("lk://{}/{}", parsed.profile().as_str(), parsed.key().as_str());
    if let Some(version) = parsed.version() {
        rendered.push_str(&format!("@v{version}"));
    }
    if let Some(source) = parsed.source() {
        rendered.push_str(&format!("?source={source}"));
    }

    let reparsed = LkReferenceUri::parse(&rendered).expect("rendered URI should parse");
    assert_eq!(parsed.into_parts(), reparsed.into_parts());
});
