//! ATProtocol Identity Provider (AIP) library crate.
//!
//! Provides OAuth 2.1 authorization server functionality with ATProtocol integration
//! for managing access tokens and authentication sessions.

pub mod config;
pub mod errors;
pub mod http;
pub mod oauth;
pub mod storage;
pub mod templates;
