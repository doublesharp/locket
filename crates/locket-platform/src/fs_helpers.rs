//! Filesystem and base64 encoding helpers shared across platform modules.

use std::fs;
use std::io::Write;
#[cfg(unix)]
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::Path;

use data_encoding::BASE64URL_NOPAD;

use crate::error::PlatformError;

pub fn encode_bytes(bytes: &[u8]) -> String {
    BASE64URL_NOPAD.encode(bytes)
}

pub fn decode_bytes(encoded: &str) -> Result<Vec<u8>, PlatformError> {
    BASE64URL_NOPAD.decode(encoded.as_bytes()).map_err(|_| PlatformError::InvalidPassphraseFallback)
}

pub fn decode_nonce(encoded: &str) -> Result<[u8; 24], PlatformError> {
    let decoded = decode_bytes(encoded)?;
    decoded.try_into().map_err(|_| PlatformError::InvalidPassphraseFallback)
}

pub fn validate_path_component(value: &str) -> Result<(), PlatformError> {
    if value.is_empty()
        || !value.bytes().all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-'))
    {
        return Err(PlatformError::InvalidProjectId);
    }
    Ok(())
}

pub fn secure_directory(path: &Path) -> Result<(), PlatformError> {
    fs::create_dir_all(path)?;
    #[cfg(unix)]
    {
        fs::set_permissions(path, fs::Permissions::from_mode(0o700))?;
    }
    Ok(())
}

pub fn write_user_only_file(path: &Path, contents: &[u8]) -> Result<(), PlatformError> {
    let mut options = fs::OpenOptions::new();
    options.write(true).create(true).truncate(true);
    #[cfg(unix)]
    {
        options.mode(0o600);
    }
    let mut file = options.open(path)?;
    file.write_all(contents)?;
    file.sync_all()?;
    Ok(())
}
