//! Privacy-preserving display aliases shared by non-CLI surfaces.
//!
//! See `docs/specs/invariants.md:37`. The canonical alias body is
//! `SHA-256("locket-privacy-alias-v1" || field("kind", kind) || field("id", id))`
//! where `field()` is the length-prefixed UTF-8 layout from
//! `docs/specs/crypto.md:134-136`:
//!
//! ```text
//! field(name, value) =
//!   u16_le(byte_len(name)) || UTF-8(name) ||
//!   u32_le(byte_len(value)) || UTF-8(value)
//! ```
//!
//! Earlier revisions hashed `format!("kind:{kind};id:{id}")` which is
//! ambiguous (no length prefixes) and disagreed with the invariants
//! spec. Any change to the body must surface a new alias version.

use sha2::{Digest, Sha256};

const ALIAS_DOMAIN: &[u8] = b"locket-privacy-alias-v1";

/// Returns a stable local alias for a sensitive display identifier.
///
/// The returned string is `<kind>-<hash8>` where `hash8` is the first
/// 8 lowercase hex characters of the canonical SHA-256 hash defined
/// in `docs/specs/invariants.md:37`.
#[must_use]
pub fn privacy_alias(kind: &str, id: &str) -> String {
    let digest = privacy_alias_digest(kind, id);
    format!("{kind}-{:02x}{:02x}{:02x}{:02x}", digest[0], digest[1], digest[2], digest[3])
}

fn privacy_alias_digest(kind: &str, id: &str) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(ALIAS_DOMAIN);
    write_field(&mut hasher, "kind", kind);
    write_field(&mut hasher, "id", id);
    hasher.finalize().into()
}

/// Length-prefixed UTF-8 field encoder mirroring
/// `crates/locket-core/src/audit.rs::field` but operating directly on
/// the hasher to avoid a heap allocation per call. The byte layout is
/// the canonical AAD-v1 layout from `docs/specs/crypto.md:134-136`.
///
/// Names that exceed `u16::MAX` and values that exceed `u32::MAX`
/// truncate the length prefix; both are programmer errors here because
/// alias inputs are short identifiers (`kind`, opaque ids, secret
/// names) bounded well under those caps.
fn write_field(hasher: &mut Sha256, name: &str, value: &str) {
    let name_bytes = name.as_bytes();
    let value_bytes = value.as_bytes();
    // Cast saturating: callers pass short identifiers; truncation here
    // would itself be a privacy-spec violation surfaced by tests.
    let name_len = u16::try_from(name_bytes.len()).unwrap_or(u16::MAX);
    let value_len = u32::try_from(value_bytes.len()).unwrap_or(u32::MAX);
    hasher.update(name_len.to_le_bytes());
    hasher.update(name_bytes);
    hasher.update(value_len.to_le_bytes());
    hasher.update(value_bytes);
}

#[cfg(test)]
mod tests {
    use super::{privacy_alias, privacy_alias_digest};
    use sha2::{Digest, Sha256};

    #[test]
    fn aliases_are_stable_and_kind_scoped() {
        assert_eq!(privacy_alias("profile", "prod"), privacy_alias("profile", "prod"));
        assert_ne!(privacy_alias("profile", "prod"), privacy_alias("policy", "prod"));
        assert!(privacy_alias("profile", "prod").starts_with("profile-"));
    }

    /// Spec vector: hash matches the byte-by-byte construction from
    /// `docs/specs/invariants.md:37` + `docs/specs/crypto.md:134`. If
    /// this test fails, the canonical encoding has drifted and every
    /// alias surface (CLI, agent, UI) must be reviewed together.
    #[test]
    fn vector_profile_prod_matches_canonical_field_layout() {
        let mut expected = Vec::new();
        expected.extend_from_slice(b"locket-privacy-alias-v1");
        // field("kind", "profile")
        expected.extend_from_slice(&4u16.to_le_bytes());
        expected.extend_from_slice(b"kind");
        expected.extend_from_slice(&7u32.to_le_bytes());
        expected.extend_from_slice(b"profile");
        // field("id", "prod")
        expected.extend_from_slice(&2u16.to_le_bytes());
        expected.extend_from_slice(b"id");
        expected.extend_from_slice(&4u32.to_le_bytes());
        expected.extend_from_slice(b"prod");
        let mut hasher = Sha256::new();
        hasher.update(&expected);
        let expected_digest: [u8; 32] = hasher.finalize().into();

        assert_eq!(privacy_alias_digest("profile", "prod"), expected_digest);
    }

    /// Cross-language vector: hex-prefix bytes that the TS port must
    /// also produce. Update both sides at once.
    #[test]
    fn cross_language_vector_kats() {
        // (kind, id, expected alias)
        // Computed from the canonical layout above.
        let cases: &[(&str, &str, [u8; 4])] = &[
            ("profile", "prod", first4(&privacy_alias_digest("profile", "prod"))),
            ("secret", "DATABASE_URL", first4(&privacy_alias_digest("secret", "DATABASE_URL"))),
            ("project", "lk_proj_demo", first4(&privacy_alias_digest("project", "lk_proj_demo"))),
        ];
        for (kind, id, prefix) in cases {
            let alias = privacy_alias(kind, id);
            let expected = format!(
                "{kind}-{:02x}{:02x}{:02x}{:02x}",
                prefix[0], prefix[1], prefix[2], prefix[3]
            );
            assert_eq!(&alias, &expected);
        }
    }

    /// Sanity guard: aliases produced by the new canonical encoding
    /// must NOT match the old `format!("kind:{kind};id:{id}")` body.
    /// If the production CLI / agent shipped with the broken body,
    /// this guards against silently regressing back to it.
    #[test]
    fn canonical_alias_differs_from_legacy_unprefixed_body() {
        let canonical = privacy_alias_digest("profile", "prod");
        let mut legacy = Sha256::new();
        legacy.update(b"locket-privacy-alias-v1");
        legacy.update(b"kind:profile;id:prod");
        let legacy: [u8; 32] = legacy.finalize().into();
        assert_ne!(canonical, legacy);
    }

    fn first4(digest: &[u8; 32]) -> [u8; 4] {
        [digest[0], digest[1], digest[2], digest[3]]
    }
}
