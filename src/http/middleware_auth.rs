//! JWT authentication middleware.
//!
//! Validates Bearer and DPoP tokens for OAuth-protected endpoints with automatic
//! subject extraction for request handlers.

use std::sync::Arc;

use crate::http::AppState;
use crate::oauth::{DPoPNonceProvider, types::*};
use atproto_oauth::dpop::{DpopValidationConfig, validate_dpop_jwt};
use atproto_oauth::pkce::challenge;
use axum::extract::{FromRef, FromRequestParts, OriginalUri, State};
use axum::http::{HeaderMap, HeaderValue, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::{Extension, RequestPartsExt};
use chrono;
use http::request::Parts;
use serde_json::json;

/// Authenticated subject extractor for protected endpoints
///
/// Validates OAuth 2.0 access tokens (Bearer or DPoP) and extracts the
/// authenticated user or client subject. Automatically handles token validation,
/// expiry checks, and DPoP proof verification when applicable.
///
/// # Example
///
/// ```ignore
/// use axum::{routing::get, Json, Router};
/// use serde_json::json;
/// use aip::http::middleware_auth::ExtractedAuth;
///
/// async fn protected_handler(
///     ExtractedAuth(token): ExtractedAuth,
/// ) -> Json<serde_json::Value> {
///     Json(json!({
///         "message": format!("Hello, user {}", token.user_id.as_deref().unwrap_or("client")),
///         "authenticated_as": token.user_id.as_deref().unwrap_or(&token.client_id),
///         "scope": token.scope.as_deref().unwrap_or(""),
///     }))
/// }
///
/// // Register as a protected route
/// let app = Router::new()
///     .route("/api/protected", get(protected_handler));
/// ```
///
/// # Token Types
///
/// - **Bearer**: Standard OAuth 2.0 bearer tokens via `Authorization: Bearer <token>`
/// - **DPoP**: Proof-of-possession tokens via `Authorization: DPoP <token>` with
///   additional `DPoP` header containing the proof JWT
///
/// # Security
///
/// - Validates token exists in storage and hasn't expired
/// - Enforces token type consistency (Bearer vs DPoP)
/// - For DPoP: validates proof JWT, nonce, access token binding, and key thumbprint
/// - Returns appropriate OAuth 2.0 error responses on failure
#[derive(Clone, Debug)]
pub struct ExtractedAuth(pub AccessToken);

/// Create a standard OAuth 2.0 error response
fn create_oauth_error_response(
    status: StatusCode,
    error: &str,
    error_description: &str,
) -> Response {
    let body = json!({
        "error": error,
        "error_description": error_description
    });

    (status, axum::Json(body)).into_response()
}

/// Create a DPoP error response with WWW-Authenticate header
fn create_dpop_error_response(
    status: StatusCode,
    error: &str,
    error_description: &str,
) -> Response {
    let body = json!({
        "error": error,
        "error_description": error_description
    });

    let header_value = format!(
        "error=\"{}\", error_description=\"{}\"",
        error, error_description
    );

    let mut headers = HeaderMap::new();
    headers.insert(
        "WWW-Authenticate",
        HeaderValue::from_str(&header_value).unwrap(),
    );

    (status, headers, axum::Json(body)).into_response()
}

impl<S> FromRequestParts<S> for ExtractedAuth
where
    AppState: FromRef<S>,
    // OriginalUri: FromRef<S>,
    S: Send + Sync,
{
    type Rejection = Response;

    /// Extract and validate authentication from request
    ///
    /// Performs comprehensive validation of OAuth 2.0 access tokens:
    /// 1. Parses Authorization header for token type and value
    /// 2. Validates token exists and hasn't expired
    /// 3. For DPoP tokens: validates proof JWT and bindings
    /// 4. Returns authenticated subject on success
    async fn from_request_parts(parts: &mut Parts, state: &S) -> Result<Self, Self::Rejection> {
        // let original_uri = OriginalUri::from_ref(state);
        let app_state = AppState::from_ref(state);

        // Step 1: Extract Authorization header
        // Format: "Bearer <token>" or "DPoP <token>"
        let auth_header = parts
            .headers
            .get("authorization")
            .and_then(|h| h.to_str().ok())
            .ok_or_else(|| {
                create_oauth_error_response(
                    StatusCode::UNAUTHORIZED,
                    "invalid_request",
                    "Missing Authorization header",
                )
            })?;

        // Step 2: Parse token type and value
        // Split only on first space to handle tokens that may contain spaces
        let parts_iter: Vec<String> = auth_header.splitn(2, ' ').map(|v| v.to_string()).collect();
        if parts_iter.len() != 2 {
            return Err(create_oauth_error_response(
                StatusCode::UNAUTHORIZED,
                "invalid_request",
                "Invalid Authorization header format",
            ));
        }

        // Normalize token type to lowercase for consistent comparison
        let token_type = parts_iter[0].to_lowercase();
        let access_token = parts_iter[1].clone();

        // Step 3: Validate token exists and hasn't expired
        // Storage layer handles expiry checking automatically
        let stored_token = app_state
            .oauth_storage
            .get_token(&access_token)
            .await
            .map_err(|e| {
                create_oauth_error_response(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "server_error",
                    &format!("Storage error: {}", e),
                )
            })?
            .ok_or_else(|| {
                create_oauth_error_response(
                    StatusCode::UNAUTHORIZED,
                    "invalid_token",
                    "Access token not found or expired",
                )
            })?;

        // Step 4: Handle DPoP token validation
        if token_type == "dpop" {
            // Ensure stored token was issued as DPoP type
            // This prevents token downgrade attacks
            if stored_token.token_type != TokenType::DPoP {
                return Err(create_oauth_error_response(
                    StatusCode::UNAUTHORIZED,
                    "invalid_token",
                    "Token type mismatch - expected DPoP token",
                ));
            }

            // Step 4a: Extract DPoP proof JWT from header
            // RFC 9449 requires DPoP header for DPoP-bound tokens
            let dpop_header = parts
                .headers
                .get("dpop")
                .and_then(|h| h.to_str().ok())
                .map(|value| value.to_string())
                .ok_or_else(|| {
                    create_dpop_error_response(
                        StatusCode::UNAUTHORIZED,
                        "invalid_dpop_proof",
                        "Missing DPoP header",
                    )
                })?;

            // Step 4b: Prepare validation parameters
            // URI and method must match the current request exactly

            let uri_str = match parts.extract::<Extension<OriginalUri>>().await {
                Ok(Extension(value)) => {
                    let path_and_query = value
                        .0
                        .path_and_query()
                        .map(|v| v.as_str().to_string())
                        .to_owned();
                    match path_and_query {
                        Some(inner_value) => {
                            format!("{}{}", app_state.config.external_base, inner_value)
                        }
                        None => {
                            format!(
                                "{}{}",
                                app_state.config.external_base,
                                value.0.path().to_owned()
                            )
                        }
                    }
                }
                Err(err) => {
                    tracing::warn!(?err, "unable to get OriginalUri from request parts");
                    format!("{}{}", app_state.config.external_base, parts.uri)
                }
            };

            let http_method = parts.method.to_string();

            // Step 4c: Get valid nonces for replay protection
            // Server maintains rolling window of valid nonces
            let expected_nonce_values = app_state.dpop_nonce_provider.generate_nonces().await;

            // Step 4d: Configure comprehensive DPoP validation
            let config = DpopValidationConfig {
                expected_http_method: Some(http_method.clone()),
                expected_http_uri: Some(uri_str.clone()),
                expected_access_token_hash: Some(challenge(&access_token)),
                max_age_seconds: 300,    // 5 minutes max age for DPoP proofs
                allow_future_iat: false, // Reject proofs with future timestamps
                clock_skew_tolerance_seconds: 30, // Allow 30s clock skew
                now: chrono::Utc::now().timestamp(),
                expected_nonce_values,
            };

            // Step 4e: Validate DPoP JWT cryptographically and semantically
            // Returns the JWK thumbprint if validation succeeds
            let jwk_thumbprint = validate_dpop_jwt(&dpop_header, &config).map_err(|e| {
                // TODO: The error should be "use_dpop_nonce" when the nonce is expected but does not match.
                create_dpop_error_response(
                    StatusCode::UNAUTHORIZED,
                    "invalid_dpop_proof",
                    &format!("DPoP validation failed: {}", e),
                )
            })?;

            // Step 4f: Verify key binding between token and DPoP proof
            // Ensures the same key that created the proof was bound to the token
            if stored_token.dpop_jkt.as_ref() != Some(&jwk_thumbprint) {
                return Err(create_dpop_error_response(
                    StatusCode::UNAUTHORIZED,
                    "invalid_dpop_proof",
                    "DPoP key thumbprint does not match token binding",
                ));
            }

            Ok(ExtractedAuth(stored_token))
        } else if token_type == "bearer" {
            // Step 4 (Bearer): Validate token type consistency
            // Prevent using DPoP-bound tokens as Bearer tokens (security downgrade)
            if stored_token.token_type == TokenType::DPoP {
                return Err(create_oauth_error_response(
                    StatusCode::UNAUTHORIZED,
                    "invalid_token",
                    "DPoP-bound token cannot be used with Bearer authentication",
                ));
            }

            Ok(ExtractedAuth(stored_token))
        } else {
            // Reject unsupported token types
            // Only "Bearer" and "DPoP" are valid per OAuth 2.0 and RFC 9449
            Err(create_oauth_error_response(
                StatusCode::UNAUTHORIZED,
                "invalid_request",
                "Unsupported token type",
            ))
        }
    }
}

pub async fn set_dpop_headers<B>(
    dpop_generator: State<Arc<dyn DPoPNonceProvider>>,
    mut response: Response<B>,
) -> Response<B> {
    let nonces = dpop_generator.as_ref().generate_nonces().await;
    response.headers_mut().insert(
        "DPoP-Nonce",
        nonces
            .first()
            .cloned()
            .unwrap_or("nonce".to_string())
            .parse()
            .unwrap(),
    );
    response
}
