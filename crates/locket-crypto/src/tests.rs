use super::{
    AAD_SCHEMA_V1, CryptoError, HKDF_WRAP_INFO_SCHEMA_V1, HkdfWrapInfo, KEY_LEN,
    KEY_WRAP_SCHEMA_V1, KeyPurpose, KeyWrapAad, KeyWrapPurpose, NONCE_LEN,
    PASSPHRASE_FALLBACK_OUTPUT_LEN, PassphraseKdfParams, RECOVERY_CODE_BYTES,
    RECOVERY_CODE_DATA_CHARS, SecretBlobAad, TAG_LEN, canonical_field, decrypt_secret_value_v1,
    derive_passphrase_fallback_key_v1, derive_wrapping_key_v1, hkdf_wrap_info_v1, key_wrap_aad_v1,
    passphrase_fallback_aad_v1, recovery_code_decode, recovery_code_encode, secret_blob_aad_v1,
    secret_fingerprint_v1, unwrap_dek_v1, unwrap_key_material_v1, wrap_dek_v1,
    wrap_key_material_v1,
};

const PROFILE_SECRET_KEY: [u8; KEY_LEN] = [7; KEY_LEN];
const MASTER_KEY: [u8; KEY_LEN] = [11; KEY_LEN];

#[test]
fn secret_blob_aad_bytes_are_stable() -> Result<(), CryptoError> {
    let metadata = SecretBlobAad::new("lk_proj_123", "lk_prof_dev", "lk_sec_db", "DATABASE_URL", 7);

    let aad = secret_blob_aad_v1(&metadata)?;
    let expected = [
        b"locket-aad-v1".as_slice(),
        &AAD_SCHEMA_V1.to_le_bytes(),
        &[10, 0],
        b"project_id",
        &[11, 0, 0, 0],
        b"lk_proj_123",
        &[10, 0],
        b"profile_id",
        &[11, 0, 0, 0],
        b"lk_prof_dev",
        &[9, 0],
        b"secret_id",
        &[9, 0, 0, 0],
        b"lk_sec_db",
        &[11, 0],
        b"secret_name",
        &[12, 0, 0, 0],
        b"DATABASE_URL",
        &[7, 0, 0, 0],
    ]
    .concat();

    assert_eq!(aad, expected);
    Ok(())
}

#[test]
fn key_wrap_aad_bytes_are_stable() -> Result<(), CryptoError> {
    let metadata = KeyWrapAad::new(
        "lk_proj_123",
        "lk_sec_db",
        Some("lk_prof_dev"),
        7,
        KeyWrapPurpose::SecretDek,
    );

    let aad = key_wrap_aad_v1(&metadata)?;
    let expected = [
        b"locket-key-wrap-v1".as_slice(),
        &[10, 0],
        b"project_id",
        &[11, 0, 0, 0],
        b"lk_proj_123",
        &[6, 0],
        b"key_id",
        &[9, 0, 0, 0],
        b"lk_sec_db",
        &[10, 0],
        b"profile_id",
        &[11, 0, 0, 0],
        b"lk_prof_dev",
        &[7, 0, 0, 0],
        &[7, 0],
        b"purpose",
        &[10, 0, 0, 0],
        b"secret-dek",
        &KEY_WRAP_SCHEMA_V1.to_le_bytes(),
    ]
    .concat();

    assert_eq!(aad, expected);
    Ok(())
}

#[test]
fn hkdf_wrap_info_encodes_missing_profile_as_empty_field() -> Result<(), CryptoError> {
    let info =
        hkdf_wrap_info_v1(&HkdfWrapInfo::new("lk_proj_123", None, KeyPurpose::ProjectMetadata))?;
    let expected = [
        b"locket-wrap-v1".as_slice(),
        &HKDF_WRAP_INFO_SCHEMA_V1.to_le_bytes(),
        &[10, 0],
        b"project_id",
        &[11, 0, 0, 0],
        b"lk_proj_123",
        &[10, 0],
        b"profile_id",
        &[0, 0, 0, 0],
        &[7, 0],
        b"purpose",
        &[16, 0, 0, 0],
        b"project-metadata",
    ]
    .concat();

    assert_eq!(info, expected);
    Ok(())
}

#[test]
fn passphrase_fallback_aad_bytes_are_stable() -> Result<(), CryptoError> {
    let aad = passphrase_fallback_aad_v1("lk_proj_123", "lk_kdf_passphrase_v1")?;
    let expected = [
        b"locket-passphrase-fallback-v1".as_slice(),
        &KEY_WRAP_SCHEMA_V1.to_le_bytes(),
        &[10, 0],
        b"project_id",
        &[11, 0, 0, 0],
        b"lk_proj_123",
        &[14, 0],
        b"kdf_profile_id",
        &[20, 0, 0, 0],
        b"lk_kdf_passphrase_v1",
    ]
    .concat();

    assert_eq!(aad, expected);
    Ok(())
}

#[test]
fn passphrase_fallback_key_derivation_is_salt_and_passphrase_bound() -> Result<(), CryptoError> {
    let params = PassphraseKdfParams {
        m_cost: 32,
        t_cost: 1,
        p_cost: 1,
        output_len: PASSPHRASE_FALLBACK_OUTPUT_LEN,
    };

    let first = derive_passphrase_fallback_key_v1(b"correct horse", b"salt-one", params)?;
    let second = derive_passphrase_fallback_key_v1(b"correct horse", b"salt-one", params)?;
    let changed_passphrase =
        derive_passphrase_fallback_key_v1(b"wrong horse", b"salt-one", params)?;
    let changed_salt = derive_passphrase_fallback_key_v1(b"correct horse", b"salt-two", params)?;

    assert_eq!(&*first, &*second);
    assert_ne!(&*first, &*changed_passphrase);
    assert_ne!(&*first, &*changed_salt);
    Ok(())
}

#[test]
fn passphrase_fallback_rejects_empty_passphrase_or_salt() {
    let params = PassphraseKdfParams::fallback_v1();

    assert!(matches!(
        derive_passphrase_fallback_key_v1(b"", b"salt", params),
        Err(CryptoError::InvalidKdfParameters)
    ));
    assert!(matches!(
        derive_passphrase_fallback_key_v1(b"passphrase", b"", params),
        Err(CryptoError::InvalidKdfParameters)
    ));
}

#[test]
fn canonical_field_rejects_oversized_field_name() {
    let name = "n".repeat(usize::from(u16::MAX) + 1);

    assert!(matches!(canonical_field(&name, "value"), Err(CryptoError::FieldNameTooLong)));
}

#[test]
fn secret_value_uses_separate_value_and_wrap_nonces() -> Result<(), CryptoError> {
    let value_aad = secret_blob_aad_v1(&SecretBlobAad::new(
        "lk_proj_123",
        "lk_prof_dev",
        "lk_sec_db",
        "DATABASE_URL",
        1,
    ))?;
    let wrap_aad = key_wrap_aad_v1(&KeyWrapAad::new(
        "lk_proj_123",
        "lk_sec_db",
        Some("lk_prof_dev"),
        1,
        KeyWrapPurpose::SecretDek,
    ))?;

    let encrypted = super::encrypt_secret_value_v1(
        &PROFILE_SECRET_KEY,
        "postgres://localhost/app",
        &value_aad,
        &wrap_aad,
    )?;

    assert_eq!(encrypted.value_nonce.len(), NONCE_LEN);
    assert_eq!(encrypted.encrypted_dek.len(), NONCE_LEN + KEY_LEN + TAG_LEN);
    assert_ne!(&encrypted.encrypted_dek[..NONCE_LEN], encrypted.value_nonce.as_slice());
    assert_eq!(encrypted.aad_schema_version, AAD_SCHEMA_V1);
    Ok(())
}

#[test]
fn changed_aad_fails_secret_decryption() -> Result<(), CryptoError> {
    let value_aad = secret_blob_aad_v1(&SecretBlobAad::new(
        "lk_proj_123",
        "lk_prof_dev",
        "lk_sec_db",
        "DATABASE_URL",
        1,
    ))?;
    let changed_value_aad = secret_blob_aad_v1(&SecretBlobAad::new(
        "lk_proj_123",
        "lk_prof_prod",
        "lk_sec_db",
        "DATABASE_URL",
        1,
    ))?;
    let wrap_aad = key_wrap_aad_v1(&KeyWrapAad::new(
        "lk_proj_123",
        "lk_sec_db",
        Some("lk_prof_dev"),
        1,
        KeyWrapPurpose::SecretDek,
    ))?;

    let encrypted =
        super::encrypt_secret_value_v1(&PROFILE_SECRET_KEY, "secret-value", &value_aad, &wrap_aad)?;
    let result =
        decrypt_secret_value_v1(&PROFILE_SECRET_KEY, &encrypted, &changed_value_aad, &wrap_aad);

    assert!(matches!(result, Err(CryptoError::DecryptionFailed)));
    Ok(())
}

#[test]
fn changed_dek_wrap_aad_fails_secret_decryption() -> Result<(), CryptoError> {
    let value_aad = secret_blob_aad_v1(&SecretBlobAad::new(
        "lk_proj_123",
        "lk_prof_dev",
        "lk_sec_db",
        "DATABASE_URL",
        1,
    ))?;
    let wrap_aad = key_wrap_aad_v1(&KeyWrapAad::new(
        "lk_proj_123",
        "lk_sec_db",
        Some("lk_prof_dev"),
        1,
        KeyWrapPurpose::SecretDek,
    ))?;
    let changed_wrap_aad = key_wrap_aad_v1(&KeyWrapAad::new(
        "lk_proj_123",
        "lk_sec_db",
        Some("lk_prof_dev"),
        2,
        KeyWrapPurpose::SecretDek,
    ))?;

    let encrypted =
        super::encrypt_secret_value_v1(&PROFILE_SECRET_KEY, "secret", &value_aad, &wrap_aad)?;
    let result =
        decrypt_secret_value_v1(&PROFILE_SECRET_KEY, &encrypted, &value_aad, &changed_wrap_aad);

    assert!(matches!(result, Err(CryptoError::DecryptionFailed)));
    Ok(())
}

#[test]
fn secret_values_reject_nul_bytes_before_encryption_or_fingerprinting() {
    let encrypted =
        super::encrypt_secret_value_v1(&PROFILE_SECRET_KEY, "bad\0value", b"value", b"wrap");
    let fingerprint = secret_fingerprint_v1(&PROFILE_SECRET_KEY, "bad\0value");

    assert!(matches!(encrypted, Err(CryptoError::InvalidSecretValue)));
    assert!(matches!(fingerprint, Err(CryptoError::InvalidSecretValue)));
}

#[test]
fn wrap_and_unwrap_dek_round_trip() -> Result<(), CryptoError> {
    let dek = [19; KEY_LEN];
    let aad = key_wrap_aad_v1(&KeyWrapAad::new(
        "lk_proj_123",
        "lk_sec_db",
        Some("lk_prof_dev"),
        3,
        KeyWrapPurpose::SecretDek,
    ))?;

    let wrapped = wrap_dek_v1(&PROFILE_SECRET_KEY, &dek, &aad)?;
    let unwrapped = unwrap_dek_v1(&PROFILE_SECRET_KEY, &wrapped, &aad)?;

    assert_eq!(&*unwrapped, &dek);
    Ok(())
}

#[test]
fn unwrap_dek_rejects_noncanonical_embedded_nonce_layout() {
    let encrypted_dek = vec![0_u8; NONCE_LEN + KEY_LEN + TAG_LEN - 1];

    assert!(matches!(
        unwrap_dek_v1(&PROFILE_SECRET_KEY, &encrypted_dek, b"aad"),
        Err(CryptoError::InvalidWrappedKey)
    ));
}

#[test]
fn hkdf_wrap_info_uses_canonical_purpose_strings() -> Result<(), CryptoError> {
    let project_key = derive_wrapping_key_v1(
        &MASTER_KEY,
        &HkdfWrapInfo::new("lk_proj_123", None, KeyPurpose::Audit),
    )?;
    let profile_key = derive_wrapping_key_v1(
        &MASTER_KEY,
        &HkdfWrapInfo::new("lk_proj_123", Some("lk_prof_dev"), KeyPurpose::ProfileSecret),
    )?;

    assert_ne!(&*project_key, &*profile_key);
    Ok(())
}

#[test]
fn stored_key_wrap_round_trips_with_separate_nonce() -> Result<(), CryptoError> {
    let key_material = [23; KEY_LEN];
    let aad = key_wrap_aad_v1(&KeyWrapAad::new(
        "lk_proj_123",
        "lk_key_profile",
        Some("lk_prof_dev"),
        0,
        KeyWrapPurpose::ProfileSecret,
    ))?;

    let wrapped = wrap_key_material_v1(&PROFILE_SECRET_KEY, &key_material, &aad)?;
    let unwrapped = unwrap_key_material_v1(&PROFILE_SECRET_KEY, &wrapped, &aad)?;

    assert_eq!(wrapped.nonce.len(), NONCE_LEN);
    assert_eq!(&*unwrapped, &key_material);
    Ok(())
}

#[test]
fn recovery_code_round_trips_with_and_without_checksum() -> Result<(), CryptoError> {
    let code_bytes = [7_u8; RECOVERY_CODE_BYTES];
    let encoded = recovery_code_encode(&code_bytes);
    let encoded = String::from_utf8_lossy(&encoded);
    let grouped =
        format!("{}-{}-{}-{}", &encoded[0..8], &encoded[8..16], &encoded[16..24], &encoded[24..]);

    assert_eq!(recovery_code_decode(&encoded)?, code_bytes);
    assert_eq!(recovery_code_decode(&encoded[..RECOVERY_CODE_DATA_CHARS])?, code_bytes);
    assert_eq!(recovery_code_decode(&grouped)?, code_bytes);
    Ok(())
}

#[test]
fn recovery_code_rejects_malformed_lengths_and_checksum() {
    let code_bytes = [9_u8; RECOVERY_CODE_BYTES];
    let encoded = recovery_code_encode(&code_bytes);
    let encoded = String::from_utf8_lossy(&encoded);
    let mut bad_check = encoded.as_bytes().to_vec();
    bad_check[RECOVERY_CODE_DATA_CHARS] =
        if bad_check[RECOVERY_CODE_DATA_CHARS] == b'0' { b'1' } else { b'0' };
    let bad_check = String::from_utf8_lossy(&bad_check);
    let mut bad_reserved = encoded.as_bytes().to_vec();
    bad_reserved[RECOVERY_CODE_DATA_CHARS + 1] = b'1';
    let bad_reserved = String::from_utf8_lossy(&bad_reserved);

    assert!(matches!(
        recovery_code_decode(&encoded[..=RECOVERY_CODE_DATA_CHARS]),
        Err(CryptoError::InvalidSecretValue)
    ));
    assert!(matches!(
        recovery_code_decode(&format!("{encoded}A")),
        Err(CryptoError::InvalidSecretValue)
    ));
    assert!(matches!(recovery_code_decode(&bad_check), Err(CryptoError::InvalidSecretValue)));
    assert!(matches!(recovery_code_decode(&bad_reserved), Err(CryptoError::InvalidSecretValue)));
}

#[test]
fn secret_fingerprint_is_keyed_and_stable() -> Result<(), CryptoError> {
    let first = secret_fingerprint_v1(&PROFILE_SECRET_KEY, "secret-value")?;
    let second = secret_fingerprint_v1(&PROFILE_SECRET_KEY, "secret-value")?;
    let other_key = secret_fingerprint_v1(&MASTER_KEY, "secret-value")?;

    assert_eq!(first, second);
    assert_ne!(first, other_key);
    Ok(())
}
