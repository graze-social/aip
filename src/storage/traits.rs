//! Storage trait definitions for OAuth and ATProtocol data.
//!
//! Defines async storage interfaces for clients, tokens, keys, sessions,
//! and nonces that can be implemented by various backend providers.

use crate::errors::{DPoPError, StorageError};
use crate::oauth::types::*;
use async_trait::async_trait;
use atproto_identity::key::KeyData;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use time::OffsetDateTime;

pub type Result<T> = std::result::Result<T, StorageError>;

// ===== OAuth Core Storage Traits =====

/// Trait for storing and retrieving OAuth clients
#[async_trait]
pub trait OAuthClientStore {
    /// Store a new OAuth client
    async fn store_client(&self, client: &OAuthClient) -> Result<()>;

    /// Retrieve a client by ID
    async fn get_client(&self, client_id: &str) -> Result<Option<OAuthClient>>;

    /// Update an existing client
    async fn update_client(&self, client: &OAuthClient) -> Result<()>;

    /// Delete a client
    async fn delete_client(&self, client_id: &str) -> Result<()>;

    /// List all clients (for admin purposes)
    async fn list_clients(&self, limit: Option<usize>) -> Result<Vec<OAuthClient>>;
}

/// Trait for storing and retrieving authorization codes
#[async_trait]
pub trait AuthorizationCodeStore {
    /// Store a new authorization code
    async fn store_code(&self, code: &AuthorizationCode) -> Result<()>;

    /// Retrieve and consume an authorization code
    async fn consume_code(&self, code: &str) -> Result<Option<AuthorizationCode>>;

    /// Clean up expired codes
    async fn cleanup_expired_codes(&self) -> Result<usize>;
}

/// Trait for storing and retrieving access tokens
#[async_trait]
pub trait AccessTokenStore {
    /// Store a new access token
    async fn store_token(&self, token: &AccessToken) -> Result<()>;

    /// Retrieve an access token
    async fn get_token(&self, token: &str) -> Result<Option<AccessToken>>;

    /// Revoke a token
    async fn revoke_token(&self, token: &str) -> Result<()>;

    /// Clean up expired tokens
    async fn cleanup_expired_tokens(&self) -> Result<usize>;

    /// Get all tokens for a user
    async fn get_user_tokens(&self, user_id: &str) -> Result<Vec<AccessToken>>;

    /// Get all tokens for a client
    async fn get_client_tokens(&self, client_id: &str) -> Result<Vec<AccessToken>>;
}

/// Trait for storing and retrieving refresh tokens
#[async_trait]
pub trait RefreshTokenStore {
    /// Store a new refresh token
    async fn store_refresh_token(&self, token: &RefreshToken) -> Result<()>;

    /// Retrieve and consume a refresh token
    async fn consume_refresh_token(&self, token: &str) -> Result<Option<RefreshToken>>;

    /// Cleanup expired refresh tokens
    async fn cleanup_expired_refresh_tokens(&self) -> Result<usize>;
}

/// Trait for storing and retrieving cryptographic keys
#[async_trait]
pub trait KeyStore {
    /// Store a signing key for JWT generation
    async fn store_signing_key(&self, key: &KeyData) -> Result<()>;

    /// Retrieve the signing key
    async fn get_signing_key(&self) -> Result<Option<KeyData>>;

    /// Store a key with a specific ID
    async fn store_key(&self, key_id: &str, key: &KeyData) -> Result<()>;

    /// Retrieve a key by ID
    async fn get_key(&self, key_id: &str) -> Result<Option<KeyData>>;

    /// List all key IDs
    async fn list_key_ids(&self) -> Result<Vec<String>>;
}

/// Stored PAR request
#[derive(Clone, Serialize, Deserialize)]
pub struct StoredPushedRequest {
    pub request_uri: String,
    pub authorization_request: AuthorizationRequest,
    pub client_id: String,
    pub created_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
    pub subject: Option<String>, // ATProtocol subject if provided (legacy)
}

/// Trait for storing and retrieving PAR (Pushed Authorization Request) data
#[async_trait]
pub trait PARStorage {
    /// Store a new PAR request
    async fn store_par_request(&self, request: &StoredPushedRequest) -> Result<()>;

    /// Retrieve a PAR request by request URI
    async fn get_par_request(&self, request_uri: &str) -> Result<Option<StoredPushedRequest>>;

    /// Remove a PAR request after use (one-time use)
    async fn consume_par_request(&self, request_uri: &str) -> Result<Option<StoredPushedRequest>>;

    /// Clean up expired PAR requests
    async fn cleanup_expired_par_requests(&self) -> Result<usize>;
}

// ===== ATProtocol Bridge Storage Traits =====

/// Session linking OAuth authorization requests to ATProtocol OAuth flows
#[derive(Clone, Serialize, Deserialize)]
#[cfg_attr(any(debug_assertions, test), derive(Debug))]
pub struct AtpOAuthSession {
    /// Unique session ID
    pub session_id: String,
    /// DID being authenticated (nullable until token exchange)
    pub did: Option<String>,
    /// Session creation time (UTC)
    pub session_created_at: DateTime<Utc>,
    /// ATProtocol OAuth state for tracking
    pub atp_oauth_state: String,
    /// JWK thumbprint of the signing key used to create the session
    pub signing_key_jkt: String,
    /// String serialized KeyData p256 private key provided to oauth_init
    pub dpop_key: String,
    /// Access token from token exchange process
    pub access_token: Option<String>,
    /// Refresh token from token exchange process
    pub refresh_token: Option<String>,
    /// Timestamp when the access token was created
    pub access_token_created_at: Option<DateTime<Utc>>,
    /// Timestamp when the access token expires
    pub access_token_expires_at: Option<DateTime<Utc>>,
    /// Scopes associated with the access token
    pub access_token_scopes: Option<Vec<String>>,
    /// Timestamp when the oauth_callback method was invoked
    pub session_exchanged_at: Option<DateTime<Utc>>,
    /// Exchange error if oauth_callback returns an error
    pub exchange_error: Option<String>,
    /// Session iteration (for refresh flows)
    pub iteration: u32,
}

/// Trait for storing ATProtocol OAuth sessions
#[async_trait]
pub trait AtpOAuthSessionStorage: Send + Sync {
    /// Store a new ATProtocol OAuth session
    async fn store_session(&self, session: &AtpOAuthSession) -> Result<()>;

    /// Get sessions by DID and session ID, ordered by iteration (highest to lowest)
    async fn get_sessions(&self, did: &str, session_id: &str) -> Result<Vec<AtpOAuthSession>>;

    /// Get specific session by DID, session ID, and iteration
    async fn get_session(
        &self,
        did: &str,
        session_id: &str,
        iteration: u32,
    ) -> Result<Option<AtpOAuthSession>>;

    /// Get the latest session by DID and session ID
    async fn get_latest_session(
        &self,
        did: &str,
        session_id: &str,
    ) -> Result<Option<AtpOAuthSession>>;

    /// Get session by ATProtocol OAuth state
    async fn get_session_by_atp_state(&self, atp_state: &str) -> Result<Option<AtpOAuthSession>>;

    /// Update existing session
    async fn update_session(&self, session: &AtpOAuthSession) -> Result<()>;

    /// Update session with access and refresh tokens
    async fn update_session_tokens(
        &self,
        did: &str,
        session_id: &str,
        iteration: u32,
        access_token: Option<String>,
        refresh_token: Option<String>,
        access_token_created_at: Option<DateTime<Utc>>,
        access_token_expires_at: Option<DateTime<Utc>>,
        access_token_scopes: Option<Vec<String>>,
    ) -> Result<()>;

    /// Remove session by DID, session ID, and iteration
    async fn remove_session(&self, did: &str, session_id: &str, iteration: u32) -> Result<()>;

    /// Delete sessions older than the specified date
    async fn cleanup_old_sessions(&self, older_than: DateTime<Utc>) -> Result<usize>;
}

/// Trait for storing authorization requests
#[async_trait]
pub trait AuthorizationRequestStorage: Send + Sync {
    /// Store an authorization request by session ID
    async fn store_authorization_request(
        &self,
        session_id: &str,
        request: &AuthorizationRequest,
    ) -> Result<()>;

    /// Get authorization request by session ID
    async fn get_authorization_request(
        &self,
        session_id: &str,
    ) -> Result<Option<AuthorizationRequest>>;

    /// Remove authorization request by session ID
    async fn remove_authorization_request(&self, session_id: &str) -> Result<()>;
}

/// Trait for storing and checking nonces to prevent replay attacks
#[async_trait]
pub trait NonceStorage: Send + Sync {
    /// Check if a nonce has been used and mark it as used
    async fn check_and_use_nonce(
        &self,
        nonce: &str,
        expiry: OffsetDateTime,
    ) -> std::result::Result<bool, DPoPError>;

    /// Clean up expired nonces
    async fn cleanup_expired(&self) -> std::result::Result<(), DPoPError>;
}

// ===== App Password Storage Traits =====

/// Stored app password
#[derive(Clone, Serialize, Deserialize)]
#[cfg_attr(any(debug_assertions, test), derive(Debug))]
pub struct AppPassword {
    /// OAuth client ID
    pub client_id: String,
    /// ATProtocol DID
    pub did: String,
    /// The app password (stored as clear text)
    pub app_password: String,
    /// When this password was created
    pub created_at: DateTime<Utc>,
    /// When this password was last updated
    pub updated_at: DateTime<Utc>,
}

/// App password session
#[derive(Clone, Serialize, Deserialize)]
#[cfg_attr(any(debug_assertions, test), derive(Debug))]
pub struct AppPasswordSession {
    /// OAuth client ID
    pub client_id: String,
    /// ATProtocol DID
    pub did: String,
    /// Access token from the session
    pub access_token: String,
    /// Refresh token from the session
    pub refresh_token: Option<String>,
    /// When the access token was created
    pub access_token_created_at: DateTime<Utc>,
    /// When the access token expires
    pub access_token_expires_at: DateTime<Utc>,
    /// Session iteration
    pub iteration: u32,
    /// When the session was exchanged (authenticated)
    pub session_exchanged_at: Option<DateTime<Utc>>,
    /// Any exchange error
    pub exchange_error: Option<String>,
}

/// Trait for storing and retrieving app passwords
#[async_trait]
pub trait AppPasswordStore: Send + Sync {
    /// Store or update an app password
    async fn store_app_password(&self, app_password: &AppPassword) -> Result<()>;

    /// Get an app password by client ID and DID
    async fn get_app_password(&self, client_id: &str, did: &str) -> Result<Option<AppPassword>>;

    /// Delete an app password by client ID and DID
    async fn delete_app_password(&self, client_id: &str, did: &str) -> Result<()>;

    /// List all app passwords for a DID
    async fn list_app_passwords_by_did(&self, did: &str) -> Result<Vec<AppPassword>>;

    /// List all app passwords for a client ID
    async fn list_app_passwords_by_client(&self, client_id: &str) -> Result<Vec<AppPassword>>;
}

/// Trait for storing and retrieving app password sessions
#[async_trait]
pub trait AppPasswordSessionStore: Send + Sync {
    /// Store a new app password session
    async fn store_app_password_session(&self, session: &AppPasswordSession) -> Result<()>;

    /// Get an app password session by client ID and DID
    async fn get_app_password_session(
        &self,
        client_id: &str,
        did: &str,
    ) -> Result<Option<AppPasswordSession>>;

    /// Update an app password session
    async fn update_app_password_session(&self, session: &AppPasswordSession) -> Result<()>;

    /// Delete app password sessions by client ID and DID
    async fn delete_app_password_sessions(&self, client_id: &str, did: &str) -> Result<()>;

    /// List all app password sessions for a DID
    async fn list_app_password_sessions_by_did(&self, did: &str)
    -> Result<Vec<AppPasswordSession>>;

    /// List all app password sessions for a client ID
    async fn list_app_password_sessions_by_client(
        &self,
        client_id: &str,
    ) -> Result<Vec<AppPasswordSession>>;
}

// ===== Combined Storage Trait =====

/// Combined OAuth storage trait
pub trait OAuthStorage:
    OAuthClientStore
    + AuthorizationCodeStore
    + AccessTokenStore
    + RefreshTokenStore
    + KeyStore
    + PARStorage
    + AtpOAuthSessionStorage
    + AuthorizationRequestStorage
    + AppPasswordStore
    + AppPasswordSessionStore
    + Send
    + Sync
{
}
