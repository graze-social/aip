//! In-memory storage implementations
//!
//! This module provides in-memory implementations of all storage traits.
//! These implementations are suitable for development and testing.

mod atprotocol;
mod nonce;
mod oauth;

pub use atprotocol::{MemoryAtpOAuthSessionStorage, MemoryAuthorizationRequestStorage};
pub use nonce::MemoryNonceStorage;
pub use oauth::MemoryOAuthStorage;

// Backward compatibility re-exports (deprecated)
#[deprecated(since = "0.1.0", note = "Use `MemoryOAuthStorage` instead")]
pub use oauth::MemoryOAuthStorage as InMemoryOAuthStorage;

#[deprecated(since = "0.1.0", note = "Use `MemoryAtpOAuthSessionStorage` instead")]
pub use atprotocol::MemoryAtpOAuthSessionStorage as InMemoryAtpOAuthSessionStorage;

#[deprecated(
    since = "0.1.0",
    note = "Use `MemoryAuthorizationRequestStorage` instead"
)]
pub use atprotocol::MemoryAuthorizationRequestStorage as InMemoryAuthorizationRequestStorage;

#[deprecated(since = "0.1.0", note = "Use `MemoryNonceStorage` instead")]
pub use nonce::MemoryNonceStorage as InMemoryNonceStore;
