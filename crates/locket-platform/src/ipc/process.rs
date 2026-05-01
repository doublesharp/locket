//! Process identity helpers used for live grant binding.

#[cfg(target_os = "linux")]
use std::fs;
#[cfg(any(target_os = "macos", target_os = "windows"))]
use std::process::Command;

use serde::{Deserialize, Serialize};

use crate::PlatformError;

/// Process identity captured when a live grant is issued.
///
/// The start-time token is intentionally opaque. Callers compare it for exact
/// equality instead of interpreting platform-specific clock or tick units.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ProcessBinding {
    /// Operating-system process id.
    pub pid: u32,
    /// Platform-specific process start metadata.
    pub process_start_time: String,
}

impl ProcessBinding {
    /// Creates a process binding from already captured metadata.
    #[must_use]
    pub fn new(pid: u32, process_start_time: impl Into<String>) -> Self {
        Self { pid, process_start_time: process_start_time.into() }
    }
}

/// Capture a binding for the current process.
///
/// # Errors
///
/// Returns [`PlatformError::ProcessStartTimeUnavailable`] when the platform
/// cannot report stable start metadata for the process.
pub fn current_process_binding() -> Result<ProcessBinding, PlatformError> {
    process_binding_for_pid(std::process::id())
}

/// Capture a binding for an arbitrary process id.
///
/// # Errors
///
/// Returns [`PlatformError::ProcessStartTimeUnavailable`] if the process is not
/// live or if the platform metadata source is unavailable.
pub fn process_binding_for_pid(pid: u32) -> Result<ProcessBinding, PlatformError> {
    Ok(ProcessBinding::new(pid, process_start_time_for_pid(pid)?))
}

/// Validate that the binding still refers to the same live process.
///
/// This returns `Ok(false)` when the PID is gone or its start-time token no
/// longer matches. I/O and parser failures from a live metadata source are
/// surfaced so callers can fail closed instead of trusting the PID alone.
///
/// # Errors
///
/// Returns platform I/O errors other than "not found", plus
/// [`PlatformError::ProcessStartTimeUnavailable`] for malformed metadata.
pub fn process_binding_matches_live_process(
    binding: &ProcessBinding,
) -> Result<bool, PlatformError> {
    match process_start_time_for_pid(binding.pid) {
        Ok(current) => Ok(current == binding.process_start_time),
        Err(PlatformError::Io(error)) if error.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(PlatformError::ProcessStartTimeUnavailable) => Ok(false),
        Err(error) => Err(error),
    }
}

#[cfg(target_os = "linux")]
fn process_start_time_for_pid(pid: u32) -> Result<String, PlatformError> {
    let stat = fs::read_to_string(format!("/proc/{pid}/stat"))?;
    let after_name = stat.rsplit_once(") ").ok_or(PlatformError::ProcessStartTimeUnavailable)?.1;
    let fields = after_name.split_whitespace().collect::<Vec<_>>();
    let start_time = fields.get(19).ok_or(PlatformError::ProcessStartTimeUnavailable)?;
    if start_time.bytes().all(|byte| byte.is_ascii_digit()) {
        Ok((*start_time).to_owned())
    } else {
        Err(PlatformError::ProcessStartTimeUnavailable)
    }
}

#[cfg(target_os = "macos")]
fn process_start_time_for_pid(pid: u32) -> Result<String, PlatformError> {
    let output = Command::new("ps")
        .args(["-o", "lstart=", "-p", &pid.to_string()])
        .output()
        .map_err(PlatformError::Io)?;
    if !output.status.success() {
        return Err(PlatformError::ProcessStartTimeUnavailable);
    }
    let text =
        String::from_utf8(output.stdout).map_err(|_| PlatformError::ProcessStartTimeUnavailable)?;
    let rendered = text.trim();
    if rendered.is_empty() {
        return Err(PlatformError::ProcessStartTimeUnavailable);
    }
    parse_macos_lstart(rendered)?;
    Ok(rendered.to_owned())
}

#[cfg(target_os = "macos")]
fn parse_macos_lstart(value: &str) -> Result<(), PlatformError> {
    let fields = value.split_whitespace().collect::<Vec<_>>();
    let [weekday, month, day, time, year] = fields.as_slice() else {
        return Err(PlatformError::ProcessStartTimeUnavailable);
    };
    let known_weekday = matches!(*weekday, "Mon" | "Tue" | "Wed" | "Thu" | "Fri" | "Sat" | "Sun");
    let known_month = matches!(
        *month,
        "Jan"
            | "Feb"
            | "Mar"
            | "Apr"
            | "May"
            | "Jun"
            | "Jul"
            | "Aug"
            | "Sep"
            | "Oct"
            | "Nov"
            | "Dec"
    );
    let day_ok = day.parse::<u8>().is_ok_and(|value| (1..=31).contains(&value));
    let year_ok = year.parse::<u16>().is_ok_and(|value| value >= 1970);
    let time_fields = time.split(':').collect::<Vec<_>>();
    let clock_ok = match time_fields.as_slice() {
        [hour, minute, second] => {
            hour.parse::<u8>().is_ok_and(|value| value <= 23)
                && minute.parse::<u8>().is_ok_and(|value| value <= 59)
                && second.parse::<u8>().is_ok_and(|value| value <= 60)
        }
        _ => false,
    };
    if known_weekday && known_month && day_ok && clock_ok && year_ok {
        Ok(())
    } else {
        Err(PlatformError::ProcessStartTimeUnavailable)
    }
}

#[cfg(target_os = "windows")]
fn process_start_time_for_pid(pid: u32) -> Result<String, PlatformError> {
    let output = Command::new("powershell")
        .args([
            "-NoProfile",
            "-NonInteractive",
            "-Command",
            &format!(
                "(Get-CimInstance Win32_Process -Filter \"ProcessId = {pid}\").CreationDate.ToUniversalTime().ToString('o')"
            ),
        ])
        .output()
        .map_err(PlatformError::Io)?;
    if !output.status.success() {
        return Err(PlatformError::ProcessStartTimeUnavailable);
    }
    let text =
        String::from_utf8(output.stdout).map_err(|_| PlatformError::ProcessStartTimeUnavailable)?;
    let rendered = text.trim();
    if rendered.is_empty() {
        return Err(PlatformError::ProcessStartTimeUnavailable);
    }
    Ok(rendered.to_owned())
}

#[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))]
fn process_start_time_for_pid(_pid: u32) -> Result<String, PlatformError> {
    Err(PlatformError::ProcessStartTimeUnavailable)
}
