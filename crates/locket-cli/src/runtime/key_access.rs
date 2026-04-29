//! Master- and project-key loading helpers used by CLI commands.

use locket_core::{LocketError, ProjectConfig};
use locket_crypto::{
    HkdfWrapInfo, KeyPurpose, KeyWrapAad, KeyWrapPurpose, WrappedKeyMaterial,
    derive_wrapping_key_v1, key_wrap_aad_v1, unwrap_key_material_v1,
};
use locket_store::{ProfileRecord, Store};

use crate::runtime::RuntimeContext;
use crate::runtime::error::{
    CliError, profile_not_found_error, project_not_found_error, typed_cli_error,
};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MasterKeySource {
    OsKeyStore,
    PassphraseFallback,
}

impl MasterKeySource {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::OsKeyStore => "os-key-store",
            Self::PassphraseFallback => "passphrase-fallback",
        }
    }
}

pub fn store_master_key_with_fallback(
    context: &RuntimeContext,
    project_id: &str,
    master_key: &locket_crypto::KeyBytes,
    timestamp: i64,
) -> Result<MasterKeySource, CliError> {
    match context.key_store.store_master_key(project_id, master_key) {
        Ok(()) => Ok(MasterKeySource::OsKeyStore),
        Err(_primary_error) => {
            let passphrase = context.passphrase_reader.new_passphrase()?;
            context.passphrase_store.store_master_key(
                project_id,
                master_key,
                passphrase.as_bytes(),
                timestamp,
            )?;
            Ok(MasterKeySource::PassphraseFallback)
        }
    }
}

pub fn load_master_key(
    context: &RuntimeContext,
    project_id: &str,
) -> Result<(zeroize::Zeroizing<locket_crypto::KeyBytes>, MasterKeySource), CliError> {
    match context.key_store.load_master_key(project_id) {
        Ok(master_key) => Ok((master_key, MasterKeySource::OsKeyStore)),
        Err(primary_error) => {
            if !context.passphrase_store.contains_project(project_id)? {
                return Err(primary_error.into());
            }
            Ok((
                load_fallback_master_key(context, project_id)?,
                MasterKeySource::PassphraseFallback,
            ))
        }
    }
}

pub fn load_fallback_master_key(
    context: &RuntimeContext,
    project_id: &str,
) -> Result<zeroize::Zeroizing<locket_crypto::KeyBytes>, CliError> {
    let passphrase = context.passphrase_reader.existing_passphrase()?;
    Ok(context.passphrase_store.load_master_key(project_id, passphrase.as_bytes())?)
}

pub fn load_master_key_verified_by_project_key(
    context: &RuntimeContext,
    store: &Store,
    project_id: &str,
    purpose: KeyPurpose,
) -> Result<(zeroize::Zeroizing<locket_crypto::KeyBytes>, MasterKeySource), CliError> {
    let (master_key, source) = load_master_key(context, project_id)?;
    match load_project_key_with_master(store, project_id, purpose, &master_key) {
        Ok(_) => Ok((master_key, source)),
        Err(error) if should_try_passphrase_fallback(source, &error) => {
            if !context.passphrase_store.contains_project(project_id)? {
                return Err(error);
            }
            let fallback_master_key = load_fallback_master_key(context, project_id)?;
            load_project_key_with_master(store, project_id, purpose, &fallback_master_key)?;
            Ok((fallback_master_key, MasterKeySource::PassphraseFallback))
        }
        Err(error) => Err(error),
    }
}

pub fn should_try_passphrase_fallback(source: MasterKeySource, error: &CliError) -> bool {
    source == MasterKeySource::OsKeyStore
        && matches!(
            error,
            CliError::Crypto(
                locket_crypto::CryptoError::DecryptionFailed
                    | locket_crypto::CryptoError::InvalidWrappedKey
            )
        )
}

pub fn load_project_key(
    context: &RuntimeContext,
    store: &Store,
    project_id: &str,
    purpose: KeyPurpose,
) -> Result<zeroize::Zeroizing<locket_crypto::KeyBytes>, CliError> {
    load_project_key_with_source(context, store, project_id, purpose).map(|(key, _)| key)
}

pub fn load_project_key_with_source(
    context: &RuntimeContext,
    store: &Store,
    project_id: &str,
    purpose: KeyPurpose,
) -> Result<(zeroize::Zeroizing<locket_crypto::KeyBytes>, MasterKeySource), CliError> {
    let (master_key, source) = load_master_key(context, project_id)?;
    match load_project_key_with_master(store, project_id, purpose, &master_key) {
        Ok(key) => Ok((key, source)),
        Err(error) if should_try_passphrase_fallback(source, &error) => {
            if !context.passphrase_store.contains_project(project_id)? {
                return Err(error);
            }
            let fallback_master_key = load_fallback_master_key(context, project_id)?;
            let key =
                load_project_key_with_master(store, project_id, purpose, &fallback_master_key)?;
            Ok((key, MasterKeySource::PassphraseFallback))
        }
        Err(error) => Err(error),
    }
}

pub fn load_project_key_with_master(
    store: &Store,
    project_id: &str,
    purpose: KeyPurpose,
    master_key: &locket_crypto::KeyBytes,
) -> Result<zeroize::Zeroizing<locket_crypto::KeyBytes>, CliError> {
    let record = store.get_key_by_scope(project_id, None, purpose.as_str())?.ok_or_else(|| {
        typed_cli_error(
            LocketError::AuditIntegrityFailed,
            format!("project {} key is missing", purpose.as_str()),
        )
    })?;
    let wrapping_key =
        derive_wrapping_key_v1(master_key, &HkdfWrapInfo::new(project_id, None, purpose))?;
    let aad = key_wrap_aad_v1(&KeyWrapAad::new(
        project_id,
        &record.id,
        None,
        0,
        KeyWrapPurpose::from(purpose),
    ))?;
    let wrapped = WrappedKeyMaterial { ciphertext: record.wrapped_material, nonce: record.nonce };
    Ok(unwrap_key_material_v1(&wrapping_key, &wrapped, &aad)?)
}

pub fn load_profile_key(
    context: &RuntimeContext,
    store: &Store,
    project_id: &str,
    profile_id: &str,
    purpose: KeyPurpose,
) -> Result<zeroize::Zeroizing<locket_crypto::KeyBytes>, CliError> {
    let (master_key, source) = load_master_key(context, project_id)?;
    match load_profile_key_with_master(store, project_id, profile_id, purpose, &master_key) {
        Ok(key) => Ok(key),
        Err(error) if should_try_passphrase_fallback(source, &error) => {
            if !context.passphrase_store.contains_project(project_id)? {
                return Err(error);
            }
            let fallback_master_key = load_fallback_master_key(context, project_id)?;
            load_profile_key_with_master(
                store,
                project_id,
                profile_id,
                purpose,
                &fallback_master_key,
            )
        }
        Err(error) => Err(error),
    }
}

pub fn load_profile_key_with_master(
    store: &Store,
    project_id: &str,
    profile_id: &str,
    purpose: KeyPurpose,
    master_key: &locket_crypto::KeyBytes,
) -> Result<zeroize::Zeroizing<locket_crypto::KeyBytes>, CliError> {
    let record = store
        .get_key_by_scope(project_id, Some(profile_id), purpose.as_str())?
        .ok_or_else(|| {
            typed_cli_error(
                LocketError::AuditIntegrityFailed,
                format!("profile {} key is missing", purpose.as_str()),
            )
        })?;
    let wrapping_key = derive_wrapping_key_v1(
        master_key,
        &HkdfWrapInfo::new(project_id, Some(profile_id), purpose),
    )?;
    let aad = key_wrap_aad_v1(&KeyWrapAad::new(
        project_id,
        &record.id,
        Some(profile_id),
        0,
        KeyWrapPurpose::from(purpose),
    ))?;
    let wrapped = WrappedKeyMaterial { ciphertext: record.wrapped_material, nonce: record.nonce };
    Ok(unwrap_key_material_v1(&wrapping_key, &wrapped, &aad)?)
}

pub fn ensure_project_exists(store: &Store, project_id: &str) -> Result<(), CliError> {
    if store.get_project(project_id)?.is_some() {
        return Ok(());
    }
    Err(project_not_found_error())
}

pub fn default_profile(store: &Store, config: &ProjectConfig) -> Result<ProfileRecord, CliError> {
    store
        .get_profile_by_name(config.project_id.as_str(), config.default_profile.as_str())?
        .ok_or_else(|| profile_not_found_error("default profile is missing"))
}
