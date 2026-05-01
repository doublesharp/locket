//! Row deserializers shared across `Store` modules.

use rusqlite::types::Type;

use crate::error::{InvalidFixedBytesLength, InvalidNonceLength};

pub fn root_hash_from_row(
    row: &rusqlite::Row<'_>,
    column: usize,
    field: &'static str,
) -> rusqlite::Result<[u8; 32]> {
    let bytes: Vec<u8> = row.get(column)?;
    bytes.try_into().map_err(|bytes: Vec<u8>| {
        rusqlite::Error::FromSqlConversionFailure(
            column,
            Type::Blob,
            Box::new(InvalidFixedBytesLength { field, expected: 32, actual: bytes.len() }),
        )
    })
}

pub fn nonce_from_row(
    row: &rusqlite::Row<'_>,
    column: usize,
    field: &'static str,
) -> rusqlite::Result<[u8; 24]> {
    let bytes: Vec<u8> = row.get(column)?;
    bytes.try_into().map_err(|bytes: Vec<u8>| {
        rusqlite::Error::FromSqlConversionFailure(
            column,
            Type::Blob,
            Box::new(InvalidNonceLength { field, actual: bytes.len() }),
        )
    })
}
