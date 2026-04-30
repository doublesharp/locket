//! Tauri 2 build script: emits the generated context for the desktop shell
//! and writes the placeholder tray icon PNGs into `OUT_DIR`.
//!
//! The tray icons land under `OUT_DIR/tray/{macos,light,dark}/<state>.png`
//! and are baked into the binary via `include_bytes!` from
//! `src/tray.rs`. They are 32x32 fully-transparent RGBA placeholders for
//! now; a later slice swaps in real Lucide-derived assets. We emit them
//! from `build.rs` rather than checking PNG bytes into the worktree so
//! the binaries stay out of `git diff` while the shape is still moving.
#![allow(clippy::print_stderr)]

use std::fs;
use std::io::Write;
use std::path::PathBuf;
use std::process::ExitCode;

const TRAY_STATES: &[&str] =
    &["agent-unlocked", "agent-locked", "agent-stopped", "scan-warning", "error-degraded"];

const TRAY_VARIANTS: &[&str] = &["macos", "light", "dark"];

const PNG_WIDTH: u32 = 32;
const PNG_HEIGHT: u32 = 32;

fn main() -> ExitCode {
    if let Err(err) = emit_tray_placeholder_icons() {
        eprintln!("locket-desktop build script: {err}");
        return ExitCode::FAILURE;
    }
    tauri_build::build();
    ExitCode::SUCCESS
}

fn emit_tray_placeholder_icons() -> std::io::Result<()> {
    let Some(out_dir_os) = std::env::var_os("OUT_DIR") else {
        return Err(std::io::Error::other("OUT_DIR not set; cargo must invoke build.rs"));
    };
    let out_dir = PathBuf::from(out_dir_os);
    let png = transparent_rgba_png(PNG_WIDTH, PNG_HEIGHT);
    for variant in TRAY_VARIANTS {
        let dir = out_dir.join("tray").join(variant);
        fs::create_dir_all(&dir)?;
        for state in TRAY_STATES {
            let path = dir.join(format!("{state}.png"));
            let mut file = fs::File::create(&path)?;
            file.write_all(&png)?;
        }
    }
    Ok(())
}

/// Build a 32x32 fully-transparent RGBA PNG using only stdlib primitives.
///
/// IDAT uses a single zlib stream wrapping a stored (uncompressed) deflate
/// block, so we do not need a compression crate just to emit a placeholder.
fn transparent_rgba_png(width: u32, height: u32) -> Vec<u8> {
    let stride = (width as usize * 4) + 1;
    let raw = vec![0_u8; stride * height as usize];
    let idat_data = zlib_stored(&raw);

    let mut out = Vec::new();
    out.extend_from_slice(b"\x89PNG\r\n\x1a\n");

    let mut ihdr = Vec::with_capacity(13);
    ihdr.extend_from_slice(&width.to_be_bytes());
    ihdr.extend_from_slice(&height.to_be_bytes());
    ihdr.push(8); // bit depth
    ihdr.push(6); // color type: RGBA
    ihdr.push(0); // compression
    ihdr.push(0); // filter
    ihdr.push(0); // interlace
    write_chunk(&mut out, b"IHDR", &ihdr);

    write_chunk(&mut out, b"IDAT", &idat_data);
    write_chunk(&mut out, b"IEND", &[]);
    out
}

fn write_chunk(buf: &mut Vec<u8>, tag: &[u8; 4], data: &[u8]) {
    buf.extend_from_slice(&u32::try_from(data.len()).unwrap_or(u32::MAX).to_be_bytes());
    buf.extend_from_slice(tag);
    buf.extend_from_slice(data);
    let mut crc_input = Vec::with_capacity(4 + data.len());
    crc_input.extend_from_slice(tag);
    crc_input.extend_from_slice(data);
    buf.extend_from_slice(&crc32(&crc_input).to_be_bytes());
}

/// Wrap raw bytes in a zlib stream consisting of one or more deflate
/// stored (uncompressed) blocks. Splits into 65,535-byte windows when
/// needed so the BFINAL flag only lands on the last block.
fn zlib_stored(data: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(data.len() + 16);
    out.extend_from_slice(&[0x78, 0x01]); // zlib header (deflate, default level)

    if data.is_empty() {
        // A single empty stored block with BFINAL=1.
        out.extend_from_slice(&[0x01, 0x00, 0x00, 0xFF, 0xFF]);
    } else {
        let mut offset = 0;
        while offset < data.len() {
            let remaining = data.len() - offset;
            let take = remaining.min(0xFFFF);
            let bfinal: u8 = u8::from(offset + take == data.len());
            out.push(bfinal);
            let len = u16::try_from(take).unwrap_or(u16::MAX);
            out.extend_from_slice(&len.to_le_bytes());
            out.extend_from_slice(&(!len).to_le_bytes());
            out.extend_from_slice(&data[offset..offset + take]);
            offset += take;
        }
    }

    out.extend_from_slice(&adler32(data).to_be_bytes());
    out
}

fn adler32(data: &[u8]) -> u32 {
    const MOD: u32 = 65521;
    let mut a: u32 = 1;
    let mut b: u32 = 0;
    for &byte in data {
        a = (a + u32::from(byte)) % MOD;
        b = (b + a) % MOD;
    }
    (b << 16) | a
}

fn crc32(data: &[u8]) -> u32 {
    let table = crc32_table();
    let mut crc: u32 = 0xFFFF_FFFF;
    for &byte in data {
        let idx = ((crc ^ u32::from(byte)) & 0xFF) as usize;
        crc = (crc >> 8) ^ table[idx];
    }
    crc ^ 0xFFFF_FFFF
}

const fn crc32_table() -> [u32; 256] {
    let mut table = [0_u32; 256];
    let mut n = 0_u32;
    while n < 256 {
        let mut c = n;
        let mut k = 0;
        while k < 8 {
            c = if c & 1 != 0 { 0xEDB8_8320 ^ (c >> 1) } else { c >> 1 };
            k += 1;
        }
        table[n as usize] = c;
        n += 1;
    }
    table
}
