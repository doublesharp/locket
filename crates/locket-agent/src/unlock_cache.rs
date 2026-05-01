//! Per-project in-memory unlock-key cache with TTL eviction.
//!
//! The cache holds unwrapped key material after an `Unlock` RPC and
//! evicts entries lazily on `lookup` or explicitly via
//! `evict_expired`. The agent emits `LOCK` audit rows when keys are
//! evicted; the cache itself stays free of audit dependencies so it
//! can be unit-tested without a `Store`.

use std::collections::BTreeMap;
use std::path::PathBuf;
use std::time::Duration;

use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

/// Unlock method recorded for the `UNLOCK` audit row.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "PascalCase")]
pub enum UnlockMethod {
    /// OS keychain unwrap path.
    OsKeychain,
    /// Interactive passphrase fallback.
    Passphrase,
    /// Recovery envelope path.
    RecoveryEnvelope,
}

/// One per-project unlock entry. The key is `Zeroizing` so it is
/// wiped when the entry drops.
pub struct UnlockEntry {
    /// Unwrapped key material. Wiped on drop.
    key: Zeroizing<Vec<u8>>,
    /// Insertion timestamp in nanoseconds since the Unix epoch.
    inserted_at_unix_nanos: i128,
    /// TTL after which `lookup` should treat the entry as expired.
    ttl: Duration,
    /// Unlock method recorded on the corresponding audit row.
    method: UnlockMethod,
    /// Optional metadata needed to append `LOCK` rows when project
    /// context is available.
    audit_context: Option<UnlockAuditContext>,
}

impl std::fmt::Debug for UnlockEntry {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("UnlockEntry")
            .field("key_len", &self.key.len())
            .field("inserted_at_unix_nanos", &self.inserted_at_unix_nanos)
            .field("ttl", &self.ttl)
            .field("method", &self.method)
            .field("has_audit_context", &self.audit_context.is_some())
            .finish()
    }
}

/// Metadata needed to append lock rows for a cached project key.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct UnlockAuditContext {
    /// `SQLite` store path for the project.
    pub store_path: PathBuf,
    /// Optional active profile id.
    pub profile_id: Option<String>,
}

impl UnlockEntry {
    /// Creates an unlock entry with the given key/TTL/method.
    #[must_use]
    pub fn new(
        key: Vec<u8>,
        inserted_at_unix_nanos: i128,
        ttl: Duration,
        method: UnlockMethod,
    ) -> Self {
        Self { key: Zeroizing::new(key), inserted_at_unix_nanos, ttl, method, audit_context: None }
    }

    /// Adds metadata-only audit context to an unlock entry.
    #[must_use]
    pub fn with_audit_context(mut self, audit_context: UnlockAuditContext) -> Self {
        self.audit_context = Some(audit_context);
        self
    }

    /// Returns the unlock method without exposing the key.
    #[must_use]
    pub const fn method(&self) -> UnlockMethod {
        self.method
    }

    /// Computes the absolute expiry time in Unix nanoseconds.
    #[must_use]
    pub fn expires_at_unix_nanos(&self) -> i128 {
        let clamped = self.ttl.as_nanos().min(u128::from(u64::MAX));
        let ttl_nanos = u64::try_from(clamped).unwrap_or(u64::MAX);
        self.inserted_at_unix_nanos.saturating_add(i128::from(ttl_nanos))
    }

    /// Returns true if `now_unix_nanos` is at or after the expiry.
    #[must_use]
    pub fn is_expired(&self, now_unix_nanos: i128) -> bool {
        now_unix_nanos >= self.expires_at_unix_nanos()
    }

    /// Borrows the unwrapped key bytes. Callers must not log them.
    #[must_use]
    #[allow(dead_code)]
    pub(crate) fn key_bytes(&self) -> &[u8] {
        &self.key
    }

    /// Returns metadata-only audit context for this cached key.
    pub(crate) const fn audit_context(&self) -> Option<&UnlockAuditContext> {
        self.audit_context.as_ref()
    }
}

/// In-memory unlock-key cache keyed by project id.
#[derive(Debug, Default)]
pub struct UnlockCache {
    entries: BTreeMap<String, UnlockEntry>,
}

impl UnlockCache {
    /// Inserts or replaces an unlock entry for a project.
    pub fn insert(&mut self, project_id: String, entry: UnlockEntry) {
        self.entries.insert(project_id, entry);
    }

    /// Returns the live entry for `project_id`, or `None` if absent or
    /// expired. A lookup never mutates the cache; callers must call
    /// `evict_expired` to garbage-collect.
    #[must_use]
    pub fn lookup(&self, project_id: &str, now_unix_nanos: i128) -> Option<&UnlockEntry> {
        let entry = self.entries.get(project_id)?;
        if entry.is_expired(now_unix_nanos) { None } else { Some(entry) }
    }

    /// Removes one project's entry and returns it, if present.
    pub fn evict(&mut self, project_id: &str) -> Option<UnlockEntry> {
        self.entries.remove(project_id)
    }

    /// Removes every entry whose TTL has elapsed by `now_unix_nanos`.
    /// Returns the project ids that were evicted so the caller can
    /// emit `LOCK` audit rows for them.
    pub fn evict_expired(&mut self, now_unix_nanos: i128) -> Vec<String> {
        let expired: Vec<String> = self
            .entries
            .iter()
            .filter(|(_, entry)| entry.is_expired(now_unix_nanos))
            .map(|(id, _)| id.clone())
            .collect();
        for id in &expired {
            self.entries.remove(id);
        }
        expired
    }

    /// Clears every entry (`Lock` for all projects).
    pub fn clear(&mut self) -> Vec<String> {
        let ids: Vec<String> = self.entries.keys().cloned().collect();
        self.entries.clear();
        ids
    }

    /// Drains every entry (`Lock` for all projects) and returns the
    /// removed entries for audit emission.
    pub fn drain(&mut self) -> Vec<(String, UnlockEntry)> {
        let entries = std::mem::take(&mut self.entries);
        entries.into_iter().collect()
    }

    /// Returns true when no live entries are held.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Iterates current entries without copying. Sealed to crate use
    /// because callers must not leak the `UnlockEntry` reference.
    pub(crate) fn entries_for_status(&self) -> impl Iterator<Item = &UnlockEntry> + '_ {
        self.entries.values()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    #[test]
    fn cache_returns_none_after_ttl_elapses() {
        let mut cache = UnlockCache::default();
        cache.insert(
            "proj-1".to_owned(),
            UnlockEntry::new(b"k".to_vec(), 1, Duration::from_secs(60), UnlockMethod::Passphrase),
        );
        assert!(cache.lookup("proj-1", 30_999_999_999).is_some());
        let evicted = cache.evict_expired(60_000_000_001);
        assert_eq!(evicted, vec!["proj-1".to_owned()]);
        assert!(cache.lookup("proj-1", 60_000_000_001).is_none());
    }

    #[test]
    fn lookup_does_not_mutate_cache() {
        let mut cache = UnlockCache::default();
        cache.insert(
            "p".to_owned(),
            UnlockEntry::new(b"k".to_vec(), 0, Duration::from_secs(1), UnlockMethod::OsKeychain),
        );
        let _ = cache.lookup("p", 5_000_000_000); // expired
        assert!(!cache.is_empty(), "lookup must not evict expired entries");
    }

    #[test]
    fn clear_returns_every_project_id() {
        let mut cache = UnlockCache::default();
        cache.insert(
            "a".to_owned(),
            UnlockEntry::new(b"x".to_vec(), 0, Duration::from_secs(60), UnlockMethod::Passphrase),
        );
        cache.insert(
            "b".to_owned(),
            UnlockEntry::new(b"y".to_vec(), 0, Duration::from_secs(60), UnlockMethod::OsKeychain),
        );
        let mut cleared = cache.clear();
        cleared.sort();
        assert_eq!(cleared, vec!["a".to_owned(), "b".to_owned()]);
        assert!(cache.is_empty());
    }
}
