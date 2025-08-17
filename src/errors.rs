//! Standardized error types following the `error-aip-<domain>-<number>` format.

use axum::response::{IntoResponse, Response};
use http::StatusCode;
use thiserror::Error;

/// Configuration errors that occur during application startup
#[derive(Debug, Error)]
pub enum ConfigError {
    /// Error when a required environment variable is not set
    #[error("error-aip-config-1 {0} must be set")]
    EnvVarRequired(String),

    /// Error when PORT cannot be parsed
    #[error("error-aip-config-2 Parsing PORT into u16 failed: {0:?}")]
    PortParsingFailed(std::num::ParseIntError),

    /// Error when version information is not available
    #[error("error-aip-config-3 One of GIT_HASH or CARGO_PKG_VERSION must be set")]
    VersionNotSet,

    /// Error when a DNS nameserver IP cannot be parsed
    #[error("error-aip-config-4 Unable to parse nameserver IP '{0}': {1}")]
    NameserverParsingFailed(String, std::net::AddrParseError),

    /// Error when HTTP client timeout cannot be parsed
    #[error("error-aip-config-5 Failed to parse HTTP client timeout: {0}")]
    TimeoutParsingFailed(std::num::ParseIntError),

    /// Error when duration string cannot be parsed
    #[error("error-aip-config-6 Failed to parse duration '{0}': {1}")]
    DurationParsingFailed(String, String),

    /// Error when boolean string cannot be parsed
    #[error(
        "error-aip-config-7 Failed to parse boolean '{0}': expected true/false/1/0/yes/no/on/off"
    )]
    BoolParsingFailed(String),
}

/// HTTP server errors
#[derive(Debug, Error)]
pub enum HttpError {
    /// Error when template rendering fails
    #[error("error-aip-http-1 Template rendering failed: {0}")]
    TemplateRenderingFailed(String),

    /// Error when static file not found
    #[error("error-aip-http-2 Static file not found: {0}")]
    StaticFileNotFound(String),

    /// Error when request processing fails
    #[error("error-aip-http-3 Request processing failed: {0}")]
    RequestProcessingFailed(String),
}

/// OAuth-related errors
#[derive(Debug, Error)]
pub enum OAuthError {
    /// Error when OAuth authorization fails
    #[error("error-aip-oauth-1 Authorization failed: {0}")]
    AuthorizationFailed(String),

    /// Error when OAuth token exchange fails
    #[error("error-aip-oauth-2 Token exchange failed: {0}")]
    TokenExchangeFailed(String),

    /// Error when OAuth state is invalid
    #[error("error-aip-oauth-3 Invalid OAuth state: {0}")]
    InvalidState(String),

    /// Invalid client credentials
    #[error("error-aip-oauth-4 Invalid client credentials: {0}")]
    InvalidClient(String),

    /// Invalid authorization code
    #[error("error-aip-oauth-5 Invalid authorization code: {0}")]
    InvalidGrant(String),

    /// Unsupported grant type
    #[error("error-aip-oauth-6 Unsupported grant type: {0}")]
    UnsupportedGrantType(String),

    /// Invalid scope
    #[error("error-aip-oauth-7 Invalid scope: {0}")]
    InvalidScope(String),

    /// Invalid request
    #[error("error-aip-oauth-8 Invalid request: {0}")]
    InvalidRequest(String),

    /// Unauthorized client
    #[error("error-aip-oauth-9 Unauthorized client: {0}")]
    UnauthorizedClient(String),

    /// Unsupported response type
    #[error("error-aip-oauth-10 Unsupported response type: {0}")]
    UnsupportedResponseType(String),

    /// Access denied
    #[error("error-aip-oauth-11 Access denied: {0}")]
    AccessDenied(String),

    /// Server error
    #[error("error-aip-oauth-12 Server error: {0}")]
    ServerError(String),

    /// Temporarily unavailable
    #[error("error-aip-oauth-13 Temporarily unavailable: {0}")]
    TemporarilyUnavailable(String),

    /// Authorization pending (RFC 8628 device flow)
    #[error("error-aip-oauth-14 Authorization pending: {0}")]
    AuthorizationPending(String),
}

/// Identity resolution errors
#[derive(Debug, Error)]
pub enum ResolveError {
    /// Multiple DIDs resolved for method
    #[error("error-aip-resolve-1 Multiple DIDs resolved for method: {0}")]
    MultipleDidsResolved(String),
}

/// DPoP-related errors
#[derive(Debug, Error)]
pub enum DPoPError {
    /// Invalid DPoP proof
    #[error("error-aip-dpop-1 Invalid DPoP proof: {0}")]
    InvalidProof(String),

    /// Missing DPoP header
    #[error("error-aip-dpop-2 Missing DPoP header")]
    MissingHeader,

    /// DPoP key mismatch
    #[error("error-aip-dpop-3 DPoP key mismatch: {0}")]
    KeyMismatch(String),

    /// DPoP replay attack detected
    #[error("error-aip-dpop-4 DPoP replay attack detected: {0}")]
    ReplayAttack(String),

    /// DPoP token expired
    #[error("error-aip-dpop-5 DPoP token expired: {0}")]
    TokenExpired(String),

    /// Invalid DPoP algorithm
    #[error("error-aip-dpop-6 Invalid DPoP algorithm: {0}")]
    InvalidAlgorithm(String),

    /// JWT processing error
    #[error("error-aip-dpop-7 JWT processing error: {0}")]
    JwtError(String),

    /// JWT thumbprint error
    #[error("error-aip-dpop-8 JWT thumbprint error: {0}")]
    Thumbprint(String),
}

/// Client registration errors
#[derive(Debug, Error)]
pub enum ClientRegistrationError {
    /// Invalid client metadata
    #[error("error-aip-client-1 Invalid client metadata: {0}")]
    InvalidClientMetadata(String),

    /// Invalid redirect URI
    #[error("error-aip-client-2 Invalid redirect URI: {0}")]
    InvalidRedirectUri(String),

    /// Client not found
    #[error("error-aip-client-3 Client not found: {0}")]
    ClientNotFound(String),

    /// Registration access token invalid
    #[error("error-aip-client-4 Registration access token invalid: {0}")]
    InvalidRegistrationToken(String),

    /// Client registration disabled
    #[error("error-aip-client-5 Client registration disabled")]
    RegistrationDisabled,
}

/// Database/storage errors
#[derive(Debug, Error)]
pub enum StorageError {
    /// Error when database connection fails
    #[error("error-aip-storage-1 Database connection failed: {0}")]
    ConnectionFailed(String),

    /// Error when query execution fails
    #[error("error-aip-storage-2 Query execution failed: {0}")]
    QueryFailed(String),

    /// Error when data serialization fails
    #[error("error-aip-storage-3 Data serialization failed: {0}")]
    SerializationFailed(String),

    /// Error when database operation fails
    #[error("error-aip-storage-4 Database error: {0}")]
    DatabaseError(String),

    /// Error when data validation fails
    #[error("error-aip-storage-5 Invalid data: {0}")]
    InvalidData(String),

    /// Error when data serialization fails (alias for SerializationFailed)
    #[error("error-aip-storage-6 Serialization error: {0}")]
    SerializationError(String),

    /// Error when requested resource is not found
    #[error("error-aip-storage-7 Not found: {0}")]
    NotFound(String),
}

pub type Result<T> = std::result::Result<T, HttpError>;

impl IntoResponse for HttpError {
    fn into_response(self) -> Response {
        tracing::error!(error = ?self, "internal server error");
        (StatusCode::INTERNAL_SERVER_ERROR).into_response()
    }
}
