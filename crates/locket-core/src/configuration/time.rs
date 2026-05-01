//! Timestamp and duration primitives.

use std::fmt::{self, Display};
use std::str::FromStr;
use std::time::Duration as StdDuration;

use thiserror::Error;

/// UTC Unix nanoseconds.
///
/// Negative values represent pre-epoch instants.
#[derive(Debug, Clone, Copy, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub struct Timestamp(i64);

impl Timestamp {
    /// Creates a timestamp from signed UTC Unix nanoseconds.
    #[must_use]
    pub const fn from_unix_nanos(value: i64) -> Self {
        Self(value)
    }

    /// Returns signed UTC Unix nanoseconds.
    #[must_use]
    pub const fn unix_nanos(self) -> i64 {
        self.0
    }

    /// Returns the audit HMAC `i128_le` representation.
    #[must_use]
    pub fn audit_i128_le_bytes(self) -> [u8; 16] {
        i128::from(self.0).to_le_bytes()
    }
}

impl Display for Timestamp {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(formatter)
    }
}

/// A normalized single-unit Locket duration.
///
/// Parsed strings must match `^[1-9][0-9]*(s|m|h|d|w)$`. Rendering preserves
/// the original parsed string when present; otherwise it renders the largest
/// exact unit.
#[derive(Debug, Clone, Eq, PartialEq, Hash)]
pub struct Duration {
    value: StdDuration,
    original: Option<String>,
}

impl Duration {
    /// Creates a normalized duration from seconds.
    #[must_use]
    pub const fn from_secs(seconds: u64) -> Self {
        Self { value: StdDuration::from_secs(seconds), original: None }
    }

    /// Returns the normalized duration as [`std::time::Duration`].
    #[must_use]
    pub const fn as_std(&self) -> StdDuration {
        self.value
    }

    /// Returns the normalized duration in seconds.
    #[must_use]
    pub const fn as_secs(&self) -> u64 {
        self.value.as_secs()
    }

    /// Consumes the value and returns the normalized [`std::time::Duration`].
    #[must_use]
    pub fn into_std(self) -> StdDuration {
        self.value
    }
}

impl Display for Duration {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        if let Some(original) = &self.original {
            return formatter.write_str(original);
        }

        let seconds = self.value.as_secs();
        let (value, unit) = if seconds != 0 && seconds.is_multiple_of(WEEK_SECONDS) {
            (seconds / WEEK_SECONDS, "w")
        } else if seconds != 0 && seconds.is_multiple_of(DAY_SECONDS) {
            (seconds / DAY_SECONDS, "d")
        } else if seconds != 0 && seconds.is_multiple_of(HOUR_SECONDS) {
            (seconds / HOUR_SECONDS, "h")
        } else if seconds != 0 && seconds.is_multiple_of(MINUTE_SECONDS) {
            (seconds / MINUTE_SECONDS, "m")
        } else {
            (seconds, "s")
        };

        write!(formatter, "{value}{unit}")
    }
}

impl FromStr for Duration {
    type Err = InvalidDuration;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        parse_duration(value)
    }
}

/// Error returned when a duration string is invalid.
#[derive(Debug, Clone, Eq, Error, PartialEq)]
#[error("invalid duration")]
pub struct InvalidDuration;

const MINUTE_SECONDS: u64 = 60;
const HOUR_SECONDS: u64 = 60 * MINUTE_SECONDS;
const DAY_SECONDS: u64 = 24 * HOUR_SECONDS;
const WEEK_SECONDS: u64 = 7 * DAY_SECONDS;

fn parse_duration(value: &str) -> Result<Duration, InvalidDuration> {
    let (number, unit) = value.split_at(value.len().checked_sub(1).ok_or(InvalidDuration)?);
    if number.is_empty()
        || number.starts_with('0')
        || !number.bytes().all(|byte| byte.is_ascii_digit())
    {
        return Err(InvalidDuration);
    }

    let amount = number.parse::<u64>().map_err(|_| InvalidDuration)?;
    let multiplier = match unit {
        "s" => 1,
        "m" => MINUTE_SECONDS,
        "h" => HOUR_SECONDS,
        "d" => DAY_SECONDS,
        "w" => WEEK_SECONDS,
        _ => return Err(InvalidDuration),
    };
    let seconds = amount.checked_mul(multiplier).ok_or(InvalidDuration)?;

    Ok(Duration { value: StdDuration::from_secs(seconds), original: Some(value.to_owned()) })
}

#[cfg(test)]
mod tests {
    use std::str::FromStr;

    use super::{Duration, Timestamp};

    #[test]
    fn timestamps_render_as_signed_unix_nanoseconds_and_audit_i128() {
        let timestamp = Timestamp::from_unix_nanos(-1);

        assert_eq!(timestamp.unix_nanos(), -1);
        assert_eq!(timestamp.to_string(), "-1");
        assert_eq!(timestamp.audit_i128_le_bytes(), (-1_i128).to_le_bytes());
    }

    #[test]
    fn accepts_single_unit_durations() {
        let cases = [("1s", 1), ("10m", 600), ("2h", 7_200), ("3d", 259_200), ("4w", 2_419_200)];

        for (input, seconds) in cases {
            let parsed = Duration::from_str(input);
            assert_eq!(parsed.as_ref().map(Duration::as_secs), Ok(seconds), "{input}");
            assert_eq!(parsed.map(|duration| duration.to_string()), Ok(input.to_owned()));
        }
    }

    #[test]
    fn rejects_invalid_duration_syntax() {
        for input in [
            "", "0s", "01s", "-1s", "+1s", "1.5h", "1h30m", "1H", "1M", "1 h", " 1h", "1h ",
            "\t1h", "1",
        ] {
            assert!(Duration::from_str(input).is_err(), "{input} should be invalid");
        }
    }

    #[test]
    fn rejects_duration_overflow_after_unit_scaling() {
        assert!(Duration::from_str("18446744073709551616s").is_err());
        assert!(Duration::from_str("307445734561825861m").is_err());
    }

    #[test]
    fn renders_largest_exact_unit_without_original() {
        assert_eq!(Duration::from_secs(0).to_string(), "0s");
        assert_eq!(Duration::from_secs(120).to_string(), "2m");
        assert_eq!(Duration::from_secs(7_200).to_string(), "2h");
        assert_eq!(Duration::from_secs(172_800).to_string(), "2d");
        assert_eq!(Duration::from_secs(1_209_600).to_string(), "2w");
        assert_eq!(Duration::from_secs(90).to_string(), "90s");
    }

    #[test]
    fn exposes_std_duration_and_consumes_into_std() {
        let duration = Duration::from_secs(42);

        assert_eq!(duration.as_std().as_secs(), 42);
        assert_eq!(duration.into_std().as_secs(), 42);
    }
}
