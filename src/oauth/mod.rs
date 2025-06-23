//! OAuth 2.1 authorization and resource server with DPoP support and ATProtocol identity integration.

pub mod atprotocol_bridge;
pub mod auth_server;
pub mod clients;
pub mod dpop;
pub mod dpop_nonce;
pub mod openid;
pub mod resource_server;
pub mod types;
pub mod utils_atprotocol_oauth;

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
    AtpBackedAuthorizationServer, AtpOAuthSessionStorage, UnifiedAtpOAuthSessionStorageAdapter,
    UnifiedAuthorizationRequestStorageAdapter,
};
pub use auth_server::{AuthorizationServer, AuthorizeQuery, AuthorizeResponse, TokenForm};
pub use clients::ClientRegistrationService;
pub use dpop::{DPoPClaims, DPoPProof, DPoPValidator};
pub use dpop_nonce::{DPoPNonceGenerator, DPoPNonceProvider};
pub use openid::OpenIDClaims;
pub use resource_server::{ResourceServer, TokenValidationResult};
pub use types::{
    AccessToken, AuthorizationCode, AuthorizationRequest, ClientAuthMethod,
    ClientRegistrationRequest, ClientRegistrationResponse, ClientType, GrantType, OAuthClient,
    OAuthErrorResponse, RefreshToken, ResponseType, TokenRequest, TokenResponse, TokenType,
    parse_scope,
};
