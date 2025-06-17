//! OAuth client management and registration.
//!
//! Manages OAuth client storage and dynamic client registration per RFC 7591.

pub mod registration;

// Re-export main types and services
pub use registration::ClientRegistrationService;
