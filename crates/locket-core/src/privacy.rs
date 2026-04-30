//! Privacy-preserving display aliases shared by non-CLI surfaces.

use sha2::{Digest, Sha256};

/// Returns a stable local alias for a sensitive display identifier.
#[must_use]
pub fn privacy_alias(kind: &str, id: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(b"locket-privacy-alias-v1");
    hasher.update(format!("kind:{kind};id:{id}").as_bytes());
    let digest = hasher.finalize();
    format!("{kind}-{:02x}{:02x}{:02x}{:02x}", digest[0], digest[1], digest[2], digest[3])
}

#[cfg(test)]
mod tests {
    use super::privacy_alias;

    #[test]
    fn aliases_are_stable_and_kind_scoped() {
        assert_eq!(privacy_alias("profile", "prod"), privacy_alias("profile", "prod"));
        assert_ne!(privacy_alias("profile", "prod"), privacy_alias("policy", "prod"));
        assert!(privacy_alias("profile", "prod").starts_with("profile-"));
    }
}
