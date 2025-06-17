//! OAuth 2.1 core types and data structures.
//!
//! Defines enums, structs, and traits for OAuth grants, tokens, clients, and requests.

use base64::prelude::*;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use uuid::Uuid;

/// OAuth 2.1 Grant Types
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum GrantType {
    AuthorizationCode,
    ClientCredentials,
    RefreshToken,
}

/// OAuth 2.1 Response Types
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ResponseType {
    Code,
}

/// OAuth 2.1 Token Types
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TokenType {
    Bearer,
    #[serde(rename = "DPoP")]
    DPoP,
}

/// OAuth 2.1 Client Authentication Methods
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ClientAuthMethod {
    ClientSecretBasic,
    ClientSecretPost,
    None,
    PrivateKeyJwt,
}

/// OAuth Client Registration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OAuthClient {
    /// Unique client identifier
    pub client_id: String,
    /// Client secret (optional for public clients)
    pub client_secret: Option<String>,
    /// Client name
    pub client_name: Option<String>,
    /// Redirect URIs
    pub redirect_uris: Vec<String>,
    /// Grant types allowed for this client
    pub grant_types: Vec<GrantType>,
    /// Response types allowed for this client
    pub response_types: Vec<ResponseType>,
    /// Scopes that can be requested by this client
    pub scope: Option<String>,
    /// Client authentication method
    pub token_endpoint_auth_method: ClientAuthMethod,
    /// Client type (public or confidential)
    pub client_type: ClientType,
    /// Registration timestamp
    pub created_at: DateTime<Utc>,
    /// Last updated timestamp
    pub updated_at: DateTime<Utc>,
    /// Client metadata
    pub metadata: serde_json::Value,
}

/// Client Type
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ClientType {
    Public,
    Confidential,
}

/// OAuth Authorization Request
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthorizationRequest {
    /// Response type
    pub response_type: ResponseType,
    /// Client ID
    pub client_id: String,
    /// Redirect URI
    pub redirect_uri: String,
    /// Requested scope
    pub scope: Option<String>,
    /// State parameter
    pub state: Option<String>,
    /// Code challenge for PKCE
    pub code_challenge: Option<String>,
    /// Code challenge method for PKCE
    pub code_challenge_method: Option<String>,
    /// Login hint for ATProtocol subject
    pub login_hint: Option<String>,
}

/// OAuth Authorization Code
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthorizationCode {
    /// The authorization code
    pub code: String,
    /// Client ID that requested this code
    pub client_id: String,
    /// User ID that authorized this code
    pub user_id: String,

    pub session_id: Option<String>,

    /// Redirect URI used in the authorization request
    pub redirect_uri: String,
    /// Granted scope
    pub scope: Option<String>,
    /// Code challenge for PKCE
    pub code_challenge: Option<String>,
    /// Code challenge method for PKCE
    pub code_challenge_method: Option<String>,
    /// Creation timestamp
    pub created_at: DateTime<Utc>,
    /// Expiration timestamp
    pub expires_at: DateTime<Utc>,
    /// Whether this code has been used
    pub used: bool,
}

/// OAuth Access Token
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AccessToken {
    /// The access token
    pub token: String,
    /// Token type
    pub token_type: TokenType,
    /// Client ID
    pub client_id: String,
    /// User ID (optional for client credentials)
    pub user_id: Option<String>,

    pub session_id: Option<String>,

    /// Session iteration (for ATProtocol OAuth sessions)
    pub session_iteration: Option<u32>,

    /// Granted scope
    pub scope: Option<String>,
    /// Creation timestamp
    pub created_at: DateTime<Utc>,
    /// Expiration timestamp
    pub expires_at: DateTime<Utc>,
    /// DPoP key thumbprint (for DPoP tokens)
    pub dpop_jkt: Option<String>,
}

/// OAuth Refresh Token
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RefreshToken {
    /// The refresh token
    pub token: String,
    /// Associated access token
    pub access_token: String,
    /// Client ID
    pub client_id: String,
    /// User ID
    pub user_id: String,

    pub session_id: Option<String>,

    /// Granted scope
    pub scope: Option<String>,
    /// Creation timestamp
    pub created_at: DateTime<Utc>,
    /// Expiration timestamp (optional, can be long-lived)
    pub expires_at: Option<DateTime<Utc>>,
}

/// Token Exchange Request
#[derive(Debug, Deserialize)]
pub struct TokenRequest {
    /// Grant type
    pub grant_type: GrantType,
    /// Authorization code (for authorization_code grant)
    pub code: Option<String>,
    /// Redirect URI (for authorization_code grant)
    pub redirect_uri: Option<String>,
    /// Code verifier (for PKCE)
    pub code_verifier: Option<String>,
    /// Refresh token (for refresh_token grant)
    pub refresh_token: Option<String>,
    /// Client ID
    pub client_id: Option<String>,
    /// Client secret
    pub client_secret: Option<String>,
    /// Requested scope
    pub scope: Option<String>,
}

/// Token Response
#[derive(Debug, Serialize)]
pub struct TokenResponse {
    /// Access token
    pub access_token: String,
    /// Token type
    pub token_type: TokenType,
    /// Expires in seconds
    pub expires_in: u64,
    /// Refresh token (optional)
    pub refresh_token: Option<String>,
    /// Granted scope
    pub scope: Option<String>,
}

/// OAuth Error Response
#[derive(Debug, Serialize, Deserialize)]
pub struct OAuthErrorResponse {
    /// Error code
    pub error: String,
    /// Error description
    pub error_description: Option<String>,
    /// Error URI
    pub error_uri: Option<String>,
    /// State parameter (for authorization errors)
    pub state: Option<String>,
}

/// Client Registration Request (RFC 7591)
#[derive(Debug, Deserialize)]
pub struct ClientRegistrationRequest {
    /// Client name
    pub client_name: Option<String>,
    /// Redirect URIs
    pub redirect_uris: Option<Vec<String>>,
    /// Grant types
    pub grant_types: Option<Vec<GrantType>>,
    /// Response types
    pub response_types: Option<Vec<ResponseType>>,
    /// Scope
    pub scope: Option<String>,
    /// Token endpoint authentication method
    pub token_endpoint_auth_method: Option<ClientAuthMethod>,
    /// Additional metadata
    #[serde(flatten)]
    pub metadata: serde_json::Value,
}

/// Client Registration Response (RFC 7591)
#[derive(Debug, Serialize)]
pub struct ClientRegistrationResponse {
    /// Client ID
    pub client_id: String,
    /// Client secret (for confidential clients)
    pub client_secret: Option<String>,
    /// Client name
    pub client_name: Option<String>,
    /// Redirect URIs
    pub redirect_uris: Vec<String>,
    /// Grant types
    pub grant_types: Vec<GrantType>,
    /// Response types
    pub response_types: Vec<ResponseType>,
    /// Scope
    pub scope: Option<String>,
    /// Token endpoint authentication method
    pub token_endpoint_auth_method: ClientAuthMethod,
    /// Registration access token
    pub registration_access_token: String,
    /// Registration client URI
    pub registration_client_uri: String,
    /// Client ID issued at
    pub client_id_issued_at: i64,
    /// Client secret expires at (optional)
    pub client_secret_expires_at: Option<i64>,
}

/// DPoP Token Claims
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DPoPTokenClaims {
    /// Token type
    pub typ: String,
    /// Algorithm
    pub alg: String,
    /// JSON Web Key
    pub jwk: serde_json::Value,
    /// HTTP method
    pub htm: String,
    /// HTTP URI
    pub htu: String,
    /// Unique identifier
    pub jti: String,
    /// Issued at
    pub iat: i64,
    /// Access token hash (for bound tokens)
    pub ath: Option<String>,
}

/// Standard OAuth 2.1 scopes
pub const STANDARD_SCOPES: &[&str] = &["openid", "profile", "email", "offline_access"];

/// Generate a secure random token
pub fn generate_token() -> String {
    use rand::Rng;
    let mut rng = rand::thread_rng();
    let bytes: [u8; 32] = rng.gen();
    base64::prelude::BASE64_URL_SAFE_NO_PAD.encode(bytes)
}

/// Generate a client ID
pub fn generate_client_id() -> String {
    Uuid::new_v4().to_string()
}

/// Validate scope string
pub fn validate_scope(scope: &str) -> bool {
    // Basic scope validation - contains only valid characters
    scope.split_whitespace().all(|s| {
        s.chars()
            .all(|c| c.is_alphanumeric() || c == '_' || c == '-' || c == ':')
    })
}

/// Parse scope string into a set
pub fn parse_scope(scope: &str) -> HashSet<String> {
    scope.split_whitespace().map(|s| s.to_string()).collect()
}

/// Join scopes into a space-separated string
pub fn join_scopes(scopes: &HashSet<String>) -> String {
    let mut scopes: Vec<_> = scopes.iter().collect();
    scopes.sort();
    scopes.into_iter().cloned().collect::<Vec<_>>().join(" ")
}
