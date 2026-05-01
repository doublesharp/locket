//! Windows named-pipe path and ACL helpers for the local agent.
//!
//! The full Windows transport is owned by `locket-agent`, but the path
//! and security descriptor rules live here so CLI, desktop, and tests
//! can share one contract.

use std::borrow::Cow;

use crate::PlatformError;

/// Windows named-pipe prefix for the local agent endpoint.
pub const AGENT_PIPE_PREFIX: &str = r"\\.\pipe\locket-agent-";

/// Returns the spec-mandated Windows named-pipe path for a user SID.
///
/// # Errors
///
/// Returns [`PlatformError::InvalidWindowsSid`] when `sid` is empty,
/// malformed, or would produce an overlong pipe path.
pub fn agent_pipe_name_for_sid(sid: &str) -> Result<String, PlatformError> {
    let sid = validate_sid_fragment(sid)?;
    let pipe_name = format!("{AGENT_PIPE_PREFIX}{sid}");
    if pipe_name.len() > 256 {
        return Err(PlatformError::InvalidWindowsSid);
    }
    Ok(pipe_name)
}

/// Returns the protected DACL SDDL used when creating the agent pipe.
///
/// The descriptor grants generic-all to the current user's SID and
/// marks the DACL protected (`D:P`) so inherited ACEs are not added by
/// the object manager.
///
/// # Errors
///
/// Returns [`PlatformError::InvalidWindowsSid`] when `sid` is empty or malformed.
pub fn agent_pipe_dacl_sddl_for_sid(sid: &str) -> Result<String, PlatformError> {
    let sid = validate_sid_fragment(sid)?;
    Ok(format!("D:P(A;;GA;;;{sid})"))
}

fn validate_sid_fragment(sid: &str) -> Result<Cow<'_, str>, PlatformError> {
    let sid = sid.trim();
    if !sid.starts_with("S-") {
        return Err(PlatformError::InvalidWindowsSid);
    }
    if !sid.bytes().all(|byte| byte.is_ascii_alphanumeric() || byte == b'-') {
        return Err(PlatformError::InvalidWindowsSid);
    }
    Ok(Cow::Borrowed(sid))
}

/// Resolves the current user's SID as a string.
///
/// # Errors
///
/// Returns [`PlatformError::WindowsSidUnavailable`] when Windows token
/// APIs fail or return malformed data.
#[cfg(target_os = "windows")]
pub fn current_user_sid_string() -> Result<String, PlatformError> {
    windows_impl::current_user_sid_string()
}

/// Resolves the current user's default agent pipe path.
///
/// # Errors
///
/// Returns [`PlatformError::WindowsSidUnavailable`] when the current
/// user's SID cannot be read.
#[cfg(target_os = "windows")]
pub fn default_agent_pipe_name() -> Result<String, PlatformError> {
    agent_pipe_name_for_sid(&current_user_sid_string()?)
}

#[cfg(target_os = "windows")]
mod windows_impl {
    #![allow(unsafe_code)]

    use std::ptr::{null, null_mut};

    use windows_sys::Win32::Foundation::{CloseHandle, GetLastError, HANDLE, HLOCAL};
    use windows_sys::Win32::Security::{
        ConvertSidToStringSidW, GetTokenInformation, OpenProcessToken, TOKEN_QUERY, TOKEN_USER,
        TokenUser,
    };
    use windows_sys::Win32::System::Memory::LocalFree;
    use windows_sys::Win32::System::Threading::GetCurrentProcess;

    use crate::PlatformError;

    struct Handle(HANDLE);

    impl Drop for Handle {
        fn drop(&mut self) {
            if !self.0.is_null() {
                // SAFETY: `self.0` is a live handle returned by `OpenProcessToken`.
                unsafe {
                    CloseHandle(self.0);
                }
            }
        }
    }

    pub(super) fn current_user_sid_string() -> Result<String, PlatformError> {
        let mut token: HANDLE = null_mut();
        // SAFETY: `GetCurrentProcess` is a pseudo-handle and `token`
        // points to writable storage for the opened token handle.
        let opened = unsafe { OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token) };
        if opened == 0 {
            return Err(PlatformError::WindowsSidUnavailable(last_os_error_code()));
        }
        let token = Handle(token);

        let mut needed = 0_u32;
        // SAFETY: The first call intentionally passes a null buffer to
        // query the required size per `GetTokenInformation` contract.
        unsafe {
            GetTokenInformation(token.0, TokenUser, null_mut(), 0, &mut needed);
        }
        if needed == 0 {
            return Err(PlatformError::WindowsSidUnavailable(last_os_error_code()));
        }

        let mut buffer = vec![0_u8; needed as usize];
        // SAFETY: `buffer` has the size Windows just requested, and
        // `needed` points to writable storage for the returned size.
        let read = unsafe {
            GetTokenInformation(token.0, TokenUser, buffer.as_mut_ptr().cast(), needed, &mut needed)
        };
        if read == 0 {
            return Err(PlatformError::WindowsSidUnavailable(last_os_error_code()));
        }

        // SAFETY: `buffer` contains a TOKEN_USER structure written by
        // `GetTokenInformation(TokenUser, ...)`.
        let token_user = unsafe { &*(buffer.as_ptr().cast::<TOKEN_USER>()) };
        let mut sid_text = null_mut();
        // SAFETY: `token_user.User.Sid` is owned by the token-info
        // buffer and valid for this call; Windows allocates `sid_text`.
        let converted = unsafe { ConvertSidToStringSidW(token_user.User.Sid, &mut sid_text) };
        if converted == 0 || sid_text.is_null() {
            return Err(PlatformError::WindowsSidUnavailable(last_os_error_code()));
        }

        let text = wide_ptr_to_string(sid_text)?;
        // SAFETY: `sid_text` was allocated by `ConvertSidToStringSidW`
        // and must be released with `LocalFree`.
        unsafe {
            LocalFree(sid_text.cast::<core::ffi::c_void>() as HLOCAL);
        }
        Ok(text)
    }

    fn wide_ptr_to_string(ptr: *const u16) -> Result<String, PlatformError> {
        if ptr.is_null() {
            return Err(PlatformError::WindowsSidUnavailable(0));
        }
        let mut len = 0_usize;
        // SAFETY: `ptr` is a NUL-terminated UTF-16 string allocated by
        // Windows. The loop stops at the first terminator.
        unsafe {
            while *ptr.add(len) != 0 {
                len += 1;
            }
            String::from_utf16(std::slice::from_raw_parts(ptr, len))
                .map_err(|_| PlatformError::WindowsSidUnavailable(0))
        }
    }

    fn last_os_error_code() -> u32 {
        // SAFETY: `GetLastError` has no preconditions.
        unsafe { GetLastError() }
    }
}

#[cfg(test)]
mod tests {
    use super::{agent_pipe_dacl_sddl_for_sid, agent_pipe_name_for_sid};

    #[test]
    fn agent_pipe_name_uses_sid_suffix() -> Result<(), Box<dyn std::error::Error>> {
        assert_eq!(
            agent_pipe_name_for_sid("S-1-5-21-1000")?,
            r"\\.\pipe\locket-agent-S-1-5-21-1000"
        );
        Ok(())
    }

    #[test]
    fn agent_pipe_dacl_sddl_is_current_user_only_and_protected()
    -> Result<(), Box<dyn std::error::Error>> {
        assert_eq!(agent_pipe_dacl_sddl_for_sid("S-1-5-21-1000")?, "D:P(A;;GA;;;S-1-5-21-1000)");
        Ok(())
    }

    #[test]
    fn agent_pipe_helpers_reject_malformed_sid_text() {
        assert!(agent_pipe_name_for_sid("").is_err());
        assert!(agent_pipe_name_for_sid("user name").is_err());
        assert!(agent_pipe_dacl_sddl_for_sid("S-1-5-21/1000").is_err());
    }
}
