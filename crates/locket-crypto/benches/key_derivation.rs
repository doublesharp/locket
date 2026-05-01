//! Microbenchmarks for `derive_wrapping_key_v1`.
//!
//! The bench covers the cold first-call and warm steady-state paths so that
//! HKDF expansion stays inside the budget set in
//! `docs/specs/performance.md`. The cold case constructs a fresh
//! `HkdfWrapInfo` and master key on every iteration; the warm case reuses a
//! pre-built wrap info to measure the steady-state HKDF cost only.

#![allow(missing_docs)]
#![allow(clippy::expect_used)]
#![allow(clippy::unwrap_used)]
#![allow(unused_crate_dependencies)]

use criterion::{Criterion, black_box, criterion_group, criterion_main};
use locket_crypto::{HkdfWrapInfo, KEY_LEN, KeyPurpose, derive_wrapping_key_v1};

const MASTER_KEY: [u8; KEY_LEN] = [42_u8; KEY_LEN];

fn bench_key_derivation(c: &mut Criterion) {
    let mut group = c.benchmark_group("key_derivation");

    group.bench_function("cold_first_call", |b| {
        b.iter(|| {
            let info = HkdfWrapInfo::new(
                black_box("lk_proj_bench"),
                Some(black_box("lk_prof_bench")),
                black_box(KeyPurpose::ProfileSecret),
            );
            let key = derive_wrapping_key_v1(black_box(&MASTER_KEY), &info)
                .expect("derive_wrapping_key_v1 should succeed for cold-call bench");
            black_box(key);
        });
    });

    let warm_info = HkdfWrapInfo::new(
        "lk_proj_bench",
        Some("lk_prof_bench"),
        KeyPurpose::ProfileSecret,
    );
    group.bench_function("warm_repeat_call", |b| {
        b.iter(|| {
            let key = derive_wrapping_key_v1(black_box(&MASTER_KEY), black_box(&warm_info))
                .expect("derive_wrapping_key_v1 should succeed for warm-call bench");
            black_box(key);
        });
    });

    group.finish();
}

criterion_group!(benches, bench_key_derivation);
criterion_main!(benches);
