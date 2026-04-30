//! Tauri 2 build script: emits the generated context for the desktop shell
//! and writes the tray icon PNGs into `OUT_DIR`.
//!
//! The tray icons land under `OUT_DIR/tray/{macos,light,dark}/<state>.png`
//! and are baked into the binary via `include_bytes!` from
//! `src/tray.rs`. They are deterministic 32x32 Lucide-derived raster
//! assets emitted from `build.rs` rather than checked in as binary blobs.
#![allow(clippy::print_stderr)]

use std::fs;
use std::io::Write;
use std::path::PathBuf;
use std::process::ExitCode;

const TRAY_STATES: &[(&str, TrayState)] = &[
    ("agent-unlocked", TrayState::AgentUnlocked),
    ("agent-locked", TrayState::AgentLocked),
    ("agent-stopped", TrayState::AgentStopped),
    ("scan-warning", TrayState::ScanWarning),
    ("error-degraded", TrayState::ErrorDegraded),
];

const TRAY_VARIANTS: &[(&str, TrayVariant)] =
    &[("macos", TrayVariant::Macos), ("light", TrayVariant::Light), ("dark", TrayVariant::Dark)];

const PNG_WIDTH: u32 = 32;
const PNG_HEIGHT: u32 = 32;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum TrayState {
    AgentUnlocked,
    AgentLocked,
    AgentStopped,
    ScanWarning,
    ErrorDegraded,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum TrayVariant {
    Macos,
    Light,
    Dark,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct Rgba {
    red: u8,
    green: u8,
    blue: u8,
    alpha: u8,
}

impl Rgba {
    const fn new(red: u8, green: u8, blue: u8, alpha: u8) -> Self {
        Self { red, green, blue, alpha }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct Palette {
    foreground: Rgba,
    accent: Rgba,
    secondary: Rgba,
}

struct Canvas {
    width: u32,
    height: u32,
    pixels: Vec<u8>,
}

fn main() -> ExitCode {
    if let Err(err) = emit_tray_icons() {
        eprintln!("locket-desktop build script: {err}");
        return ExitCode::FAILURE;
    }
    tauri_build::build();
    ExitCode::SUCCESS
}

fn emit_tray_icons() -> std::io::Result<()> {
    let Some(out_dir_os) = std::env::var_os("OUT_DIR") else {
        return Err(std::io::Error::other("OUT_DIR not set; cargo must invoke build.rs"));
    };
    let out_dir = PathBuf::from(out_dir_os);
    for (variant_slug, variant) in TRAY_VARIANTS {
        let dir = out_dir.join("tray").join(variant_slug);
        fs::create_dir_all(&dir)?;
        for (state_slug, state) in TRAY_STATES {
            let png = tray_icon_png(*state, *variant);
            let path = dir.join(format!("{state_slug}.png"));
            let mut file = fs::File::create(&path)?;
            file.write_all(&png)?;
        }
    }
    Ok(())
}

fn tray_icon_png(state: TrayState, variant: TrayVariant) -> Vec<u8> {
    let mut canvas = Canvas::new(PNG_WIDTH, PNG_HEIGHT);
    let palette = palette_for(state, variant);
    match state {
        TrayState::AgentUnlocked => draw_lock(&mut canvas, palette, LockStyle::OpenFilled),
        TrayState::AgentLocked => draw_lock(&mut canvas, palette, LockStyle::LockedFilled),
        TrayState::AgentStopped => draw_lock(&mut canvas, palette, LockStyle::LockedOutline),
        TrayState::ScanWarning => draw_shield_alert(&mut canvas, palette),
        TrayState::ErrorDegraded => draw_alert_triangle(&mut canvas, palette),
    }
    rgba_png(PNG_WIDTH, PNG_HEIGHT, &canvas.pixels)
}

fn palette_for(state: TrayState, variant: TrayVariant) -> Palette {
    match variant {
        TrayVariant::Macos => {
            let black = Rgba::new(0, 0, 0, 255);
            Palette { foreground: black, accent: black, secondary: black }
        }
        TrayVariant::Light => match state {
            TrayState::AgentUnlocked => Palette {
                foreground: Rgba::new(20, 83, 45, 255),
                accent: Rgba::new(34, 197, 94, 255),
                secondary: Rgba::new(187, 247, 208, 255),
            },
            TrayState::AgentLocked => Palette {
                foreground: Rgba::new(30, 41, 59, 255),
                accent: Rgba::new(96, 116, 139, 255),
                secondary: Rgba::new(203, 213, 225, 255),
            },
            TrayState::AgentStopped => Palette {
                foreground: Rgba::new(71, 85, 105, 255),
                accent: Rgba::new(148, 163, 184, 255),
                secondary: Rgba::new(226, 232, 240, 255),
            },
            TrayState::ScanWarning => Palette {
                foreground: Rgba::new(120, 53, 15, 255),
                accent: Rgba::new(245, 158, 11, 255),
                secondary: Rgba::new(254, 243, 199, 255),
            },
            TrayState::ErrorDegraded => Palette {
                foreground: Rgba::new(127, 29, 29, 255),
                accent: Rgba::new(239, 68, 68, 255),
                secondary: Rgba::new(254, 226, 226, 255),
            },
        },
        TrayVariant::Dark => match state {
            TrayState::AgentUnlocked => Palette {
                foreground: Rgba::new(187, 247, 208, 255),
                accent: Rgba::new(34, 197, 94, 255),
                secondary: Rgba::new(22, 101, 52, 255),
            },
            TrayState::AgentLocked => Palette {
                foreground: Rgba::new(226, 232, 240, 255),
                accent: Rgba::new(148, 163, 184, 255),
                secondary: Rgba::new(51, 65, 85, 255),
            },
            TrayState::AgentStopped => Palette {
                foreground: Rgba::new(203, 213, 225, 255),
                accent: Rgba::new(100, 116, 139, 255),
                secondary: Rgba::new(30, 41, 59, 255),
            },
            TrayState::ScanWarning => Palette {
                foreground: Rgba::new(254, 243, 199, 255),
                accent: Rgba::new(245, 158, 11, 255),
                secondary: Rgba::new(146, 64, 14, 255),
            },
            TrayState::ErrorDegraded => Palette {
                foreground: Rgba::new(254, 226, 226, 255),
                accent: Rgba::new(248, 113, 113, 255),
                secondary: Rgba::new(153, 27, 27, 255),
            },
        },
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum LockStyle {
    OpenFilled,
    LockedFilled,
    LockedOutline,
}

fn draw_lock(canvas: &mut Canvas, palette: Palette, style: LockStyle) {
    match style {
        LockStyle::OpenFilled => {
            canvas.fill_rect(9, 15, 24, 26, palette.accent);
            canvas.stroke_rect(9, 15, 24, 26, 2.0, palette.foreground);
            canvas.draw_line((11.0, 15.0), (11.0, 12.0), 2.8, palette.foreground);
            canvas.draw_line((11.0, 12.0), (15.0, 8.0), 2.8, palette.foreground);
            canvas.draw_line((15.0, 8.0), (21.0, 10.0), 2.8, palette.foreground);
            canvas.draw_line((21.0, 10.0), (23.5, 8.0), 2.8, palette.foreground);
            canvas.fill_rect(15, 19, 18, 23, palette.secondary);
        }
        LockStyle::LockedFilled => {
            canvas.draw_line((11.0, 15.0), (11.0, 12.0), 3.0, palette.foreground);
            canvas.draw_line((11.0, 12.0), (16.0, 7.0), 3.0, palette.foreground);
            canvas.draw_line((16.0, 7.0), (21.0, 12.0), 3.0, palette.foreground);
            canvas.draw_line((21.0, 12.0), (21.0, 15.0), 3.0, palette.foreground);
            canvas.fill_rect(9, 15, 24, 26, palette.accent);
            canvas.stroke_rect(9, 15, 24, 26, 2.0, palette.foreground);
            canvas.fill_rect(15, 19, 18, 23, palette.secondary);
        }
        LockStyle::LockedOutline => {
            canvas.draw_line((11.0, 15.0), (11.0, 12.0), 2.4, palette.foreground);
            canvas.draw_line((11.0, 12.0), (16.0, 7.0), 2.4, palette.foreground);
            canvas.draw_line((16.0, 7.0), (21.0, 12.0), 2.4, palette.foreground);
            canvas.draw_line((21.0, 12.0), (21.0, 15.0), 2.4, palette.foreground);
            canvas.stroke_rect(9, 15, 24, 26, 2.4, palette.foreground);
            canvas.draw_line((13.0, 20.0), (20.0, 20.0), 2.0, palette.accent);
        }
    }
}

fn draw_shield_alert(canvas: &mut Canvas, palette: Palette) {
    let shield = &[(16.0, 4.0), (25.0, 8.0), (23.0, 20.0), (16.0, 28.0), (9.0, 20.0), (7.0, 8.0)];
    canvas.fill_polygon(shield, palette.secondary);
    canvas.draw_polyline(shield, 2.6, palette.foreground, true);
    canvas.draw_line((16.0, 11.0), (16.0, 18.0), 2.6, palette.accent);
    canvas.fill_rect(15, 22, 18, 25, palette.accent);
}

fn draw_alert_triangle(canvas: &mut Canvas, palette: Palette) {
    let triangle = &[(16.0, 4.0), (28.0, 27.0), (4.0, 27.0)];
    canvas.fill_polygon(triangle, palette.secondary);
    canvas.draw_polyline(triangle, 2.8, palette.foreground, true);
    canvas.draw_line((16.0, 12.0), (16.0, 19.0), 2.6, palette.accent);
    canvas.fill_rect(15, 23, 18, 26, palette.accent);
}

impl Canvas {
    fn new(width: u32, height: u32) -> Self {
        Self { width, height, pixels: vec![0_u8; width as usize * height as usize * 4] }
    }

    fn set_pixel(&mut self, x: i32, y: i32, color: Rgba) {
        if x < 0 || y < 0 || x >= self.width as i32 || y >= self.height as i32 {
            return;
        }
        let offset = ((y as u32 * self.width + x as u32) * 4) as usize;
        self.pixels[offset] = color.red;
        self.pixels[offset + 1] = color.green;
        self.pixels[offset + 2] = color.blue;
        self.pixels[offset + 3] = color.alpha;
    }

    fn fill_rect(&mut self, left: i32, top: i32, right: i32, bottom: i32, color: Rgba) {
        for y in top..bottom {
            for x in left..right {
                self.set_pixel(x, y, color);
            }
        }
    }

    fn stroke_rect(
        &mut self,
        left: i32,
        top: i32,
        right: i32,
        bottom: i32,
        thickness: f32,
        color: Rgba,
    ) {
        self.draw_line((left as f32, top as f32), (right as f32, top as f32), thickness, color);
        self.draw_line((right as f32, top as f32), (right as f32, bottom as f32), thickness, color);
        self.draw_line(
            (right as f32, bottom as f32),
            (left as f32, bottom as f32),
            thickness,
            color,
        );
        self.draw_line((left as f32, bottom as f32), (left as f32, top as f32), thickness, color);
    }

    fn draw_polyline(&mut self, points: &[(f32, f32)], thickness: f32, color: Rgba, closed: bool) {
        for pair in points.windows(2) {
            self.draw_line(pair[0], pair[1], thickness, color);
        }
        if closed && points.len() > 1 {
            self.draw_line(points[points.len() - 1], points[0], thickness, color);
        }
    }

    fn draw_line(&mut self, from: (f32, f32), to: (f32, f32), thickness: f32, color: Rgba) {
        let radius = thickness / 2.0;
        let min_x = (from.0.min(to.0) - radius - 1.0).floor() as i32;
        let max_x = (from.0.max(to.0) + radius + 1.0).ceil() as i32;
        let min_y = (from.1.min(to.1) - radius - 1.0).floor() as i32;
        let max_y = (from.1.max(to.1) + radius + 1.0).ceil() as i32;
        let radius_sq = radius * radius;
        for y in min_y..=max_y {
            for x in min_x..=max_x {
                let px = x as f32 + 0.5;
                let py = y as f32 + 0.5;
                if distance_sq_to_segment((px, py), from, to) <= radius_sq {
                    self.set_pixel(x, y, color);
                }
            }
        }
    }

    fn fill_polygon(&mut self, points: &[(f32, f32)], color: Rgba) {
        let min_y = points.iter().map(|(_, y)| *y).fold(f32::INFINITY, f32::min).floor() as i32;
        let max_y = points.iter().map(|(_, y)| *y).fold(f32::NEG_INFINITY, f32::max).ceil() as i32;
        let min_x = points.iter().map(|(x, _)| *x).fold(f32::INFINITY, f32::min).floor() as i32;
        let max_x = points.iter().map(|(x, _)| *x).fold(f32::NEG_INFINITY, f32::max).ceil() as i32;
        for y in min_y..=max_y {
            for x in min_x..=max_x {
                if point_in_polygon((x as f32 + 0.5, y as f32 + 0.5), points) {
                    self.set_pixel(x, y, color);
                }
            }
        }
    }
}

fn distance_sq_to_segment(point: (f32, f32), from: (f32, f32), to: (f32, f32)) -> f32 {
    let dx = to.0 - from.0;
    let dy = to.1 - from.1;
    let len_sq = dx * dx + dy * dy;
    if len_sq == 0.0 {
        return distance_sq(point, from);
    }
    let t = (((point.0 - from.0) * dx) + ((point.1 - from.1) * dy)) / len_sq;
    let t = t.clamp(0.0, 1.0);
    distance_sq(point, (from.0 + (t * dx), from.1 + (t * dy)))
}

fn distance_sq(a: (f32, f32), b: (f32, f32)) -> f32 {
    let dx = a.0 - b.0;
    let dy = a.1 - b.1;
    dx * dx + dy * dy
}

fn point_in_polygon(point: (f32, f32), points: &[(f32, f32)]) -> bool {
    let mut inside = false;
    let mut previous = points.len() - 1;
    for current in 0..points.len() {
        let (current_x, current_y) = points[current];
        let (previous_x, previous_y) = points[previous];
        let crosses_y = (current_y > point.1) != (previous_y > point.1);
        if crosses_y {
            let x_at_y = (previous_x - current_x) * (point.1 - current_y)
                / (previous_y - current_y)
                + current_x;
            if point.0 < x_at_y {
                inside = !inside;
            }
        }
        previous = current;
    }
    inside
}

/// Build an RGBA PNG using only stdlib primitives.
///
/// IDAT uses a single zlib stream wrapping a stored (uncompressed) deflate
/// block, so we do not need a compression crate for tiny tray assets.
fn rgba_png(width: u32, height: u32, pixels: &[u8]) -> Vec<u8> {
    let stride = (width as usize * 4) + 1;
    let mut raw = Vec::with_capacity(stride * height as usize);
    for row in 0..height as usize {
        raw.push(0);
        let start = row * width as usize * 4;
        let end = start + width as usize * 4;
        raw.extend_from_slice(&pixels[start..end]);
    }
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
