//! OAuth 2.1 authorization and resource server implementation.
//!
//! Provides complete OAuth flows with DPoP support, client registration,
//! and ATProtocol integration for identity-backed authentication.

pub mod atprotocol_bridge;
pub mod auth_server;
pub mod clients;
pub mod dpop;
pub mod dpop_nonce;
pub mod resource_server;
pub mod types;

#[cfg(test)]
pub mod time_tests;

// Re-export frequently used items from each module
pub use crate::storage::{
    inmemory::MemoryOAuthStorage,
    traits::{
        AccessTokenStore, AuthorizationCodeStore, OAuthClientStore, OAuthStorage, RefreshTokenStore,
    },
};
pub use atprotocol_bridge::{
    AtpBackedAuthorizationServer, AtpOAuthSessionStorage, MemoryAtpOAuthSessionStorage,
    UnifiedAtpOAuthSessionStorageAdapter, UnifiedAuthorizationRequestStorageAdapter,
};
pub use auth_server::{AuthorizationServer, AuthorizeQuery, AuthorizeResponse, TokenForm};
pub use clients::ClientRegistrationService;
pub use dpop::{DPoPClaims, DPoPProof, DPoPValidator};
pub use dpop_nonce::{DPoPNonceGenerator, DPoPNonceProvider};
pub use resource_server::{ResourceServer, TokenValidationResult};
pub use types::{
    AccessToken, AuthorizationCode, AuthorizationRequest, ClientAuthMethod,
    ClientRegistrationRequest, ClientRegistrationResponse, ClientType, GrantType, OAuthClient,
    OAuthErrorResponse, RefreshToken, ResponseType, TokenRequest, TokenResponse, TokenType,
    parse_scope,
};
