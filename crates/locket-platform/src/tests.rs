use super::{
    KEY_LEN, LocalUserVerificationMethod, LocalUserVerificationRequest, LocalUserVerifier,
    MasterKeyStore, MemoryLocalUserVerifier, MemoryMasterKeyStore, NONCE_LEN,
    PassphraseFallbackMasterKeyStore, PlatformError, RecoveryEnvelope, RecoveryEnvelopeEntry,
    RecoveryKdfToml, UnavailableLocalUserVerifier, decode_key, encode_key, load_recovery_envelope,
    load_recovery_kdf_toml, master_key_account, save_recovery_envelope, save_recovery_kdf_toml,
};

const PROJECT_ID: &str = "lk_proj_test";
const MASTER_KEY: [u8; KEY_LEN] = [42; KEY_LEN];

#[test]
fn encodes_master_key_without_padding() -> Result<(), PlatformError> {
    let encoded = encode_key(&MASTER_KEY);

    assert!(!encoded.contains('='));
    assert_eq!(&*decode_key(&encoded)?, &MASTER_KEY);
    Ok(())
}

#[test]
fn rejects_invalid_encoded_key_length() {
    assert!(matches!(decode_key("AA"), Err(PlatformError::InvalidMasterKey)));
}

#[test]
fn rejects_invalid_encoded_key_alphabet() {
    assert!(matches!(decode_key("not valid base64"), Err(PlatformError::InvalidMasterKey)));
}

#[test]
fn memory_store_round_trips_and_deletes_master_key() -> Result<(), PlatformError> {
    let store = MemoryMasterKeyStore::default();

    store.store_master_key(PROJECT_ID, &MASTER_KEY)?;
    assert_eq!(&*store.load_master_key(PROJECT_ID)?, &MASTER_KEY);

    store.delete_master_key(PROJECT_ID)?;
    assert!(matches!(store.load_master_key(PROJECT_ID), Err(PlatformError::MasterKeyNotFound)));
    Ok(())
}

#[test]
fn memory_store_is_project_scoped() -> Result<(), PlatformError> {
    let store = MemoryMasterKeyStore::default();

    store.store_master_key(PROJECT_ID, &MASTER_KEY)?;

    assert!(matches!(
        store.load_master_key("lk_proj_other"),
        Err(PlatformError::MasterKeyNotFound)
    ));
    Ok(())
}

#[test]
fn memory_store_replaces_existing_project_key() -> Result<(), PlatformError> {
    let store = MemoryMasterKeyStore::default();
    let replacement = [7; KEY_LEN];

    store.store_master_key(PROJECT_ID, &MASTER_KEY)?;
    store.store_master_key("lk_proj_other", &replacement)?;

    assert!(matches!(store.load_master_key(PROJECT_ID), Err(PlatformError::MasterKeyNotFound)));
    assert_eq!(&*store.load_master_key("lk_proj_other")?, &replacement);
    Ok(())
}

#[test]
fn keyring_account_is_project_scoped() {
    assert_eq!(master_key_account(PROJECT_ID), "master:lk_proj_test");
}

#[test]
fn unavailable_user_verifier_fails_closed() {
    let verifier = UnavailableLocalUserVerifier;
    let request = LocalUserVerificationRequest::new("reveal", "Reveal DATABASE_URL");

    let result = verifier.verify_user(&request);

    assert!(matches!(result, Err(PlatformError::LocalUserVerificationUnavailable)));
}

#[test]
fn memory_user_verifier_supports_success_and_failure() -> Result<(), PlatformError> {
    let request = LocalUserVerificationRequest::new("unlock", "Unlock local vault");
    let success = MemoryLocalUserVerifier::allowing().verify_user(&request)?;

    assert_eq!(success.method, LocalUserVerificationMethod::Test);
    assert_eq!(success.platform, super::platform_name());
    assert!(matches!(
        MemoryLocalUserVerifier::denying().verify_user(&request),
        Err(PlatformError::LocalUserVerificationFailed)
    ));
    Ok(())
}

#[test]
fn passphrase_fallback_round_trips_master_key() -> Result<(), PlatformError> {
    let directory = tempfile::tempdir()?;
    let store = PassphraseFallbackMasterKeyStore::new(directory.path());

    store.store_master_key(PROJECT_ID, &MASTER_KEY, b"fallback passphrase", 123)?;

    assert!(store.contains_project(PROJECT_ID)?);
    let loaded = store.load_master_key(PROJECT_ID, b"fallback passphrase")?;
    assert_eq!(&*loaded, &MASTER_KEY);

    let envelope = std::fs::read_to_string(directory.path().join(format!("{PROJECT_ID}.toml")))?;
    assert!(!envelope.contains("fallback passphrase"));
    assert!(!envelope.contains(&encode_key(&MASTER_KEY)));
    assert!(envelope.contains("algorithm = \"argon2id\""));
    assert!(envelope.contains("m_cost = 32768"));
    Ok(())
}

#[test]
fn passphrase_fallback_rejects_wrong_passphrase() -> Result<(), PlatformError> {
    let directory = tempfile::tempdir()?;
    let store = PassphraseFallbackMasterKeyStore::new(directory.path());

    store.store_master_key(PROJECT_ID, &MASTER_KEY, b"fallback passphrase", 123)?;
    let result = store.load_master_key(PROJECT_ID, b"wrong passphrase");

    assert!(matches!(result, Err(PlatformError::InvalidPassphrase)));
    Ok(())
}

#[test]
fn passphrase_fallback_rejects_tampered_kdf_params() -> Result<(), PlatformError> {
    let cases = [
        ("m_cost", "m_cost = 32768", "m_cost = 1048576"),
        ("t_cost", "t_cost = 2", "t_cost = 100"),
        ("p_cost", "p_cost = 4", "p_cost = 128"),
        ("output_len", "output_len = 32", "output_len = 64"),
        ("salt", "salt = ", "salt = \"AA\""),
        ("wrapped_master_key", "wrapped_master_key = ", "wrapped_master_key = \"AA\""),
    ];

    for (case, from, to) in cases {
        let directory = tempfile::tempdir()?;
        let store = PassphraseFallbackMasterKeyStore::new(directory.path());

        store.store_master_key(PROJECT_ID, &MASTER_KEY, b"fallback passphrase", 123)?;
        let envelope_path = directory.path().join(format!("{PROJECT_ID}.toml"));
        let envelope = std::fs::read_to_string(&envelope_path)?;
        let tampered = if from.ends_with("= ") {
            replace_toml_assignment(&envelope, from, to)
        } else {
            envelope.replace(from, to)
        };
        assert_ne!(tampered, envelope, "case {case} did not tamper the envelope");
        std::fs::write(&envelope_path, tampered)?;

        let result = store.load_master_key(PROJECT_ID, b"fallback passphrase");

        assert!(
            matches!(result, Err(PlatformError::InvalidPassphraseFallback)),
            "case {case} should reject before derivation/decrypt"
        );
    }
    Ok(())
}

fn replace_toml_assignment(text: &str, prefix: &str, replacement: &str) -> String {
    text.lines()
        .map(|line| if line.starts_with(prefix) { replacement } else { line })
        .collect::<Vec<_>>()
        .join("\n")
}

#[test]
fn passphrase_fallback_delete_is_idempotent() -> Result<(), PlatformError> {
    let directory = tempfile::tempdir()?;
    let store = PassphraseFallbackMasterKeyStore::new(directory.path());

    store.store_master_key(PROJECT_ID, &MASTER_KEY, b"fallback passphrase", 123)?;
    store.delete_master_key(PROJECT_ID)?;
    store.delete_master_key(PROJECT_ID)?;

    assert!(!store.contains_project(PROJECT_ID)?);
    assert!(matches!(
        store.load_master_key(PROJECT_ID, b"fallback passphrase"),
        Err(PlatformError::MasterKeyNotFound)
    ));
    Ok(())
}

#[cfg(unix)]
#[test]
fn passphrase_fallback_uses_user_only_permissions() -> Result<(), PlatformError> {
    use std::os::unix::fs::PermissionsExt as _;

    let directory = tempfile::tempdir()?;
    let store = PassphraseFallbackMasterKeyStore::new(directory.path());

    store.store_master_key(PROJECT_ID, &MASTER_KEY, b"fallback passphrase", 123)?;

    let dir_mode = std::fs::metadata(directory.path())?.permissions().mode() & 0o777;
    let file_mode = std::fs::metadata(directory.path().join(format!("{PROJECT_ID}.toml")))?
        .permissions()
        .mode()
        & 0o777;
    assert_eq!(dir_mode, 0o700);
    assert_eq!(file_mode, 0o600);
    Ok(())
}

#[test]
fn recovery_kdf_toml_round_trips_and_rejects_tampering() -> Result<(), PlatformError> {
    let directory = tempfile::tempdir()?;
    let salt = [3_u8; locket_crypto::RECOVERY_SALT_LEN];
    let kdf = RecoveryKdfToml::new_v1("lk_kdf_test".to_owned(), &salt, 456);

    save_recovery_kdf_toml(directory.path(), &kdf)?;
    let loaded = load_recovery_kdf_toml(directory.path())?;

    assert_eq!(loaded.kdf_profile_id, "lk_kdf_test");
    assert_eq!(loaded.decode_salt()?, salt);

    let mut tampered = loaded;
    tampered.m_cost = locket_crypto::RECOVERY_M_COST + 1;
    assert!(matches!(
        save_recovery_kdf_toml(directory.path(), &tampered),
        Err(PlatformError::InvalidRecoveryEnvelope(_))
    ));
    Ok(())
}

#[test]
fn recovery_envelope_round_trips_and_rejects_tampering() -> Result<(), PlatformError> {
    let directory = tempfile::tempdir()?;
    let envelope = RecoveryEnvelope {
        kdf_profile_id: "lk_kdf_test".to_owned(),
        created_at_unix_nanos: 123,
        entries: vec![RecoveryEnvelopeEntry {
            entry_kind: "master_key".to_owned(),
            entry_id: PROJECT_ID.to_owned(),
            nonce: [1_u8; NONCE_LEN],
            ciphertext: vec![2_u8; KEY_LEN + locket_crypto::TAG_LEN],
        }],
    };

    save_recovery_envelope(directory.path(), &envelope)?;
    let loaded = load_recovery_envelope(directory.path())?;

    assert_eq!(loaded.kdf_profile_id, envelope.kdf_profile_id);
    assert_eq!(loaded.entries.len(), 1);
    assert_eq!(loaded.entries[0].ciphertext, envelope.entries[0].ciphertext);

    let mut bytes = envelope.serialize()?;
    bytes[0] ^= 0xFF;
    assert!(matches!(
        RecoveryEnvelope::deserialize(&bytes),
        Err(PlatformError::InvalidRecoveryEnvelope(_))
    ));
    Ok(())
}

#[cfg(unix)]
#[test]
fn recovery_files_use_user_only_permissions() -> Result<(), PlatformError> {
    use std::os::unix::fs::PermissionsExt as _;

    let directory = tempfile::tempdir()?;
    let recovery_dir = directory.path().join("recovery");
    let salt = [4_u8; locket_crypto::RECOVERY_SALT_LEN];
    let kdf = RecoveryKdfToml::new_v1("lk_kdf_test".to_owned(), &salt, 456);
    let envelope = RecoveryEnvelope {
        kdf_profile_id: "lk_kdf_test".to_owned(),
        created_at_unix_nanos: 123,
        entries: vec![RecoveryEnvelopeEntry {
            entry_kind: "master_key".to_owned(),
            entry_id: PROJECT_ID.to_owned(),
            nonce: [1_u8; NONCE_LEN],
            ciphertext: vec![2_u8; KEY_LEN + locket_crypto::TAG_LEN],
        }],
    };

    save_recovery_kdf_toml(&recovery_dir, &kdf)?;
    save_recovery_envelope(&recovery_dir, &envelope)?;

    let dir_mode = std::fs::metadata(&recovery_dir)?.permissions().mode() & 0o777;
    let kdf_mode = std::fs::metadata(recovery_dir.join("kdf.toml"))?.permissions().mode() & 0o777;
    let envelope_mode =
        std::fs::metadata(recovery_dir.join("envelope.bin"))?.permissions().mode() & 0o777;
    assert_eq!(dir_mode, 0o700);
    assert_eq!(kdf_mode, 0o600);
    assert_eq!(envelope_mode, 0o600);
    Ok(())
}
