#[cfg(unix)]
pub(crate) mod peer_cred;
#[cfg(any(unix, target_os = "windows"))]
pub(crate) mod server;
#[cfg(target_os = "windows")]
pub(crate) mod windows_pipe;
