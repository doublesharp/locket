//! Shared CLI runtime infrastructure: context, errors, prompts, key access.

pub mod context;
pub mod degraded_audit;
pub mod error;
pub mod key_access;
pub mod prompts;
pub mod user_verification;

pub use context::RuntimeContext;
