#![no_main]

use libfuzzer_sys::fuzz_target;
use locket_core::{EnvMap, EnvMode, EnvOverrideMode, merge_environment};

fuzz_target!(|data: &[u8]| {
    let parent = build_env(data, b"PARENT_");
    let external = build_env(data, b"EXTERNAL_");
    let locket = build_env(data, b"LOCKET_");

    for mode in [EnvMode::Strict, EnvMode::Minimal, EnvMode::Merge, EnvMode::Passthrough] {
        for override_mode in [
            EnvOverrideMode::Locket,
            EnvOverrideMode::Preserve,
            EnvOverrideMode::Error,
        ] {
            let _ = merge_environment(
                &parent,
                &["PARENT_0", "PARENT_1"],
                &["PARENT_2"],
                &external,
                &locket,
                mode,
                override_mode,
            );
        }
    }
});

fn build_env(data: &[u8], prefix: &[u8]) -> EnvMap {
    let mut env = EnvMap::new();
    for (index, chunk) in data.chunks(4).take(8).enumerate() {
        let name = format!("{}{}", String::from_utf8_lossy(prefix), index);
        let value = String::from_utf8_lossy(chunk).into_owned();
        env.insert(name, value);
    }
    env
}
