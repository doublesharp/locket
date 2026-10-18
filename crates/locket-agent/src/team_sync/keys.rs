use super::{Result, nanos, reject};
use locket_crypto::{
    HkdfWrapInfo, KeyBytes, KeyPurpose, KeyWrapAad, KeyWrapPurpose, WrappedKeyMaterial,
    derive_wrapping_key_v1, key_wrap_aad_v1, unwrap_key_material_v1, wrap_key_material_v1,
};
use locket_store::{KeyRecord, Store};
/// # Errors
/// Returns an error when trust, scope, cryptography, storage or folder validation fails.
pub fn load_key(
    store: &Store,
    project: &str,
    profile: Option<&str>,
    purpose: KeyPurpose,
    master: &KeyBytes,
) -> Result<zeroize::Zeroizing<KeyBytes>> {
    let key = store
        .get_key_by_scope(project, profile, purpose.as_str())?
        .ok_or_else(|| reject("required wrapping key missing"))?;
    let wrapping = derive_wrapping_key_v1(master, &HkdfWrapInfo::new(project, profile, purpose))?;
    let aad = key_wrap_aad_v1(&KeyWrapAad::new(
        project,
        &key.id,
        profile,
        0,
        KeyWrapPurpose::from(purpose),
    ))?;
    Ok(unwrap_key_material_v1(
        &wrapping,
        &WrappedKeyMaterial { ciphertext: key.wrapped_material, nonce: key.nonce },
        &aad,
    )?)
}
/// # Errors
/// Returns an error when trust, scope, cryptography, storage or folder validation fails.
pub fn store_key(
    store: &Store,
    project: &str,
    profile: Option<&str>,
    purpose: KeyPurpose,
    master: &KeyBytes,
    material: &KeyBytes,
    now: i64,
) -> Result<()> {
    let existing = store.get_key_by_scope(project, profile, purpose.as_str())?;
    let id = if let Some(key) = &existing {
        key.id.clone()
    } else {
        locket_core::KeyId::generate().map_err(|_| reject("clock unavailable"))?.into_string()
    };
    let wrapping = derive_wrapping_key_v1(master, &HkdfWrapInfo::new(project, profile, purpose))?;
    let aad =
        key_wrap_aad_v1(&KeyWrapAad::new(project, &id, profile, 0, KeyWrapPurpose::from(purpose)))?;
    let wrapped = wrap_key_material_v1(&wrapping, material, &aad)?;
    if existing.is_some() {
        store.connection().execute(
            "UPDATE keys SET wrapped_material=?2,nonce=?3 WHERE id=?1",
            rusqlite::params![id, wrapped.ciphertext, wrapped.nonce.as_slice()],
        )?;
    } else {
        store.insert_key(&KeyRecord {
            id,
            project_id: project.into(),
            profile_id: profile.map(str::to_owned),
            purpose: purpose.as_str().into(),
            wrapped_material: wrapped.ciphertext,
            nonce: wrapped.nonce,
            created_at: nanos(now)?,
        })?;
    }
    Ok(())
}
