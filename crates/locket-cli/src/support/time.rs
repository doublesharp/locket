//! Pure date/time and ISO 8601 helpers shared across CLI commands.

use std::path::Path;

use crate::CliError;
use crate::commands::scan::scanner;
use crate::runtime::error::metadata_invalid_error;

pub const NANOS_PER_SECOND: i64 = 1_000_000_000;

pub fn resolve_diff_since(project_root: &Path, value: &str) -> Result<i64, CliError> {
    if let Some(timestamp) = parse_iso8601_utc_nanos(value)? {
        return Ok(timestamp);
    }

    let output = scanner::git_output(project_root, ["log", "-1", "--format=%ct", value]).map_err(|error| {
        CliError::Config(format!(
            "could not resolve diff --since value {value:?} as an ISO date/time or Git revision: {error}"
        ))
    })?;
    let seconds = String::from_utf8_lossy(&output)
        .trim()
        .parse::<i64>()
        .map_err(|_| CliError::Config("git revision timestamp was not an integer".to_owned()))?;
    seconds.checked_mul(NANOS_PER_SECOND).ok_or(CliError::Time)
}

pub fn parse_iso8601_utc_nanos(value: &str) -> Result<Option<i64>, CliError> {
    let value = value.trim();
    if value.len() < 10 || !value.as_bytes().get(0..10).is_some_and(is_iso_date_prefix) {
        return Ok(None);
    }

    let year = parse_i32_digits(&value[0..4])?;
    let month = parse_u32_digits(&value[5..7])?;
    let day = parse_u32_digits(&value[8..10])?;
    validate_ymd(year, month, day)?;

    if value.len() == 10 {
        return unix_nanos_from_iso_parts((year, month, day), (0, 0, 0, 0), 0).map(Some);
    }

    let separator = value.as_bytes()[10];
    if !matches!(separator, b'T' | b't' | b' ') {
        return Ok(None);
    }

    let (time_part, offset_seconds) = split_iso_time_and_offset(&value[11..])?;
    let (hour, minute, second, fractional_nanos) = parse_iso_time(time_part)?;
    unix_nanos_from_iso_parts(
        (year, month, day),
        (hour, minute, second, fractional_nanos),
        offset_seconds,
    )
    .map(Some)
}

fn is_iso_date_prefix(bytes: &[u8]) -> bool {
    bytes.len() == 10
        && bytes[0..4].iter().all(u8::is_ascii_digit)
        && bytes[4] == b'-'
        && bytes[5..7].iter().all(u8::is_ascii_digit)
        && bytes[7] == b'-'
        && bytes[8..10].iter().all(u8::is_ascii_digit)
}

fn split_iso_time_and_offset(value: &str) -> Result<(&str, i64), CliError> {
    if let Some(time) = value.strip_suffix('Z').or_else(|| value.strip_suffix('z')) {
        return Ok((time, 0));
    }
    if let Some(index) = value
        .as_bytes()
        .iter()
        .enumerate()
        .skip(1)
        .find_map(|(index, byte)| matches!(byte, b'+' | b'-').then_some(index))
    {
        let offset = parse_iso_offset_seconds(&value[index..])?;
        return Ok((&value[..index], offset));
    }
    Ok((value, 0))
}

fn parse_iso_time(value: &str) -> Result<(u32, u32, u32, u32), CliError> {
    if value.len() < 8 || &value[2..3] != ":" || &value[5..6] != ":" {
        return Err(metadata_invalid_error("invalid ISO date/time for diff --since"));
    }
    let hour = parse_u32_digits(&value[0..2])?;
    let minute = parse_u32_digits(&value[3..5])?;
    let second = parse_u32_digits(&value[6..8])?;
    if hour > 23 || minute > 59 || second > 59 {
        return Err(metadata_invalid_error("invalid ISO date/time for diff --since"));
    }
    let fractional_nanos = if value.len() == 8 {
        0
    } else {
        if value.as_bytes().get(8) != Some(&b'.') {
            return Err(metadata_invalid_error("invalid ISO date/time for diff --since"));
        }
        parse_fractional_nanos(&value[9..])?
    };
    Ok((hour, minute, second, fractional_nanos))
}

fn parse_fractional_nanos(value: &str) -> Result<u32, CliError> {
    if value.is_empty() || !value.as_bytes().iter().all(u8::is_ascii_digit) {
        return Err(metadata_invalid_error("invalid ISO date/time for diff --since"));
    }
    let mut nanos = 0_u32;
    let mut scale = 100_000_000_u32;
    for byte in value.as_bytes().iter().take(9) {
        nanos += u32::from(byte - b'0') * scale;
        scale /= 10;
    }
    Ok(nanos)
}

fn parse_iso_offset_seconds(value: &str) -> Result<i64, CliError> {
    let sign = match value.as_bytes().first() {
        Some(b'+') => 1_i64,
        Some(b'-') => -1_i64,
        _ => return Err(metadata_invalid_error("invalid ISO date/time for diff --since")),
    };
    let offset = &value[1..];
    let (hours, minutes) = if offset.len() == 5 && &offset[2..3] == ":" {
        (parse_u32_digits(&offset[0..2])?, parse_u32_digits(&offset[3..5])?)
    } else if offset.len() == 4 {
        (parse_u32_digits(&offset[0..2])?, parse_u32_digits(&offset[2..4])?)
    } else {
        return Err(metadata_invalid_error("invalid ISO date/time for diff --since"));
    };
    if hours > 23 || minutes > 59 {
        return Err(metadata_invalid_error("invalid ISO date/time for diff --since"));
    }
    Ok(sign * i64::from(hours * 3600 + minutes * 60))
}

fn parse_i32_digits(value: &str) -> Result<i32, CliError> {
    if value.is_empty() || !value.as_bytes().iter().all(u8::is_ascii_digit) {
        return Err(metadata_invalid_error("invalid ISO date/time for diff --since"));
    }
    value
        .parse::<i32>()
        .map_err(|_| metadata_invalid_error("invalid ISO date/time for diff --since"))
}

fn parse_u32_digits(value: &str) -> Result<u32, CliError> {
    if value.is_empty() || !value.as_bytes().iter().all(u8::is_ascii_digit) {
        return Err(metadata_invalid_error("invalid ISO date/time for diff --since"));
    }
    value
        .parse::<u32>()
        .map_err(|_| metadata_invalid_error("invalid ISO date/time for diff --since"))
}

fn validate_ymd(year: i32, month: u32, day: u32) -> Result<(), CliError> {
    if !(1..=12).contains(&month) || day == 0 || day > days_in_month(year, month) {
        return Err(metadata_invalid_error("invalid ISO date/time for diff --since"));
    }
    Ok(())
}

const fn days_in_month(year: i32, month: u32) -> u32 {
    match month {
        1 | 3 | 5 | 7 | 8 | 10 | 12 => 31,
        4 | 6 | 9 | 11 => 30,
        2 if is_leap_year(year) => 29,
        2 => 28,
        _ => 0,
    }
}

const fn is_leap_year(year: i32) -> bool {
    (year % 4 == 0 && year % 100 != 0) || year % 400 == 0
}

fn unix_nanos_from_iso_parts(
    date: (i32, u32, u32),
    time: (u32, u32, u32, u32),
    offset_seconds: i64,
) -> Result<i64, CliError> {
    let (year, month, day) = date;
    let (hour, minute, second, fractional_nanos) = time;
    let days = days_from_civil(year, month, day);
    let seconds = days
        .checked_mul(86_400)
        .and_then(|seconds| seconds.checked_add(i64::from(hour * 3_600 + minute * 60 + second)))
        .and_then(|seconds| seconds.checked_sub(offset_seconds))
        .ok_or(CliError::Time)?;
    seconds
        .checked_mul(NANOS_PER_SECOND)
        .and_then(|nanos| nanos.checked_add(i64::from(fractional_nanos)))
        .ok_or(CliError::Time)
}

fn days_from_civil(year: i32, month: u32, day: u32) -> i64 {
    let year = i64::from(year) - i64::from(month <= 2);
    let era = if year >= 0 { year } else { year - 399 } / 400;
    let year_of_era = year - era * 400;
    let month = i64::from(month);
    let day = i64::from(day);
    let day_of_year = (153 * (month + if month > 2 { -3 } else { 9 }) + 2) / 5 + day - 1;
    let day_of_era = year_of_era * 365 + year_of_era / 4 - year_of_era / 100 + day_of_year;
    era * 146_097 + day_of_era - 719_468
}

pub fn optional_i64(value: Option<i64>) -> String {
    value.map_or_else(|| "-".to_owned(), |value| value.to_string())
}

/// Renders a Unix nanosecond timestamp as `<nanos>(<rfc3339>)`.
///
/// The numeric form preserves byte-for-byte parity with prior history output that
/// downstream tooling parses, while the parenthesised RFC 3339 form gives humans
/// a readable rendering. Negative or out-of-range values fall back to the numeric
/// form alone so we never mask the underlying database value.
pub fn format_unix_nanos(nanos: i64) -> String {
    unix_nanos_to_rfc3339(nanos)
        .map_or_else(|| nanos.to_string(), |rendered| format!("{nanos}({rendered})"))
}

pub fn format_optional_unix_nanos(value: Option<i64>) -> String {
    value.map_or_else(|| "-".to_owned(), format_unix_nanos)
}

pub const fn format_optional_str(value: Option<&str>) -> &str {
    match value {
        Some(value) => value,
        None => "-",
    }
}

/// Renders Unix nanosecond timestamps as RFC 3339 in UTC.
///
/// Returns `None` when the timestamp is negative or would overflow our calendar
/// arithmetic; the caller is expected to fall back to the raw integer form.
pub fn unix_nanos_to_rfc3339(nanos: i64) -> Option<String> {
    let nanos = u64::try_from(nanos).ok()?;
    let secs = nanos / 1_000_000_000;
    let sub_nanos = u32::try_from(nanos % 1_000_000_000).ok()?;
    let days = secs / 86_400;
    let time_of_day = secs % 86_400;
    let hour = u32::try_from(time_of_day / 3_600).ok()?;
    let minute = u32::try_from((time_of_day % 3_600) / 60).ok()?;
    let second = u32::try_from(time_of_day % 60).ok()?;
    let (year, month, day) = days_to_ymd(days)?;
    Some(format!("{year:04}-{month:02}-{day:02}T{hour:02}:{minute:02}:{second:02}.{sub_nanos:09}Z"))
}

/// Converts whole days since the Unix epoch into a `(year, month, day)` triple.
///
/// Uses the civil-from-days algorithm so the conversion stays self-contained and
/// avoids pulling a date dependency into the workspace just for history rendering.
pub fn days_to_ymd(days: u64) -> Option<(i32, u32, u32)> {
    let z = days.checked_add(719_468)?;
    let era = z / 146_097;
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1_460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = u32::try_from(doy - (153 * mp + 2) / 5 + 1).ok()?;
    let month_u64 = if mp < 10 { mp + 3 } else { mp - 9 };
    let month = u32::try_from(month_u64).ok()?;
    let year = if month <= 2 { y + 1 } else { y };
    let year = i32::try_from(year).ok()?;
    Some((year, month, day))
}
