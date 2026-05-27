#![no_main]

use libfuzzer_sys::fuzz_target;
use locket_core::{PROJECT_CONFIG_SCHEMA_VERSION, ProjectConfig};

fuzz_target!(|data: &[u8]| {
    if data.len() > 4096 {
        return;
    }
    let Ok(input) = std::str::from_utf8(data) else {
        return;
    };
    let parsed = toml::from_str::<ProjectConfig>(input);
    if let Ok(config) = parsed {
        if config.schema_version != PROJECT_CONFIG_SCHEMA_VERSION {
            return;
        }
        assert!(config.project_id.as_str().starts_with("lk_proj_"));
        assert!(!config.name.contains('\0'));
        assert!(!config.default_profile.as_str().is_empty());
    }
});
