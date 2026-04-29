//! Shared CLI runtime infrastructure: context, errors, prompts, key access.

pub mod context;
pub mod error;
pub mod key_access;
pub mod prompts;

pub use context::RuntimeContext;
