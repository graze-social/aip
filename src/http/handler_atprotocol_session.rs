//! Handles GET /api/atprotocol/session - Retrieves ATProtocol OAuth session information including access tokens and DPoP keys

use atproto_oauth::jwk::WrappedJsonWebKey;
use axum::{
    extract::{Query, State},
    http::StatusCode,
    response::Json,
};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

use super::context::AppState;
use crate::{
    http::middleware_auth::ExtractedAuth,
    oauth::utils_app_password::get_app_password_session_with_refresh,
    oauth::utils_atprotocol_oauth::get_atprotocol_session_with_refresh,
};
use atproto_identity::key::identify_key;
use atproto_oauth::jwk::generate as generate_jwk;

/// Query parameters for session endpoint
#[derive(Deserialize)]
pub struct SessionQuery {
    /// Access token type - "oauth_session" (default) or "app_password_session"
    #[serde(default = "default_access_token_type")]
    pub access_token_type: String,
    /// Subject DID for app password session lookup (optional)
    pub sub: Option<String>,
}

fn default_access_token_type() -> String {
    "oauth_session".to_string()
}

/// ATProtocol session information response
#[derive(Serialize)]
pub struct AtpSessionResponse {
    /// ATProtocol DID
    pub did: String,
    /// ATProtocol handle (if available)
    pub handle: String,
    /// ATProtocol access token
    pub access_token: String,
    /// ATProtocol token type (usually "Bearer")
    pub token_type: String,
    /// ATProtocol scopes
    pub scopes: Vec<String>,
    /// PDS endpoint (if available)
    pub pds_endpoint: String,
    /// DPoP key thumbprint (if DPoP-bound)
    pub dpop_key: Option<String>,
    /// DPoP key as JWK (if DPoP-bound)
    pub dpop_jwk: Option<WrappedJsonWebKey>,
    /// Session expiration timestamp (Unix timestamp)
    pub expires_at: i64,
}

/// Get ATProtocol session information
/// GET /api/atprotocol/session
///
/// Retrieves ATProtocol session information. Can retrieve OAuth session (default) or app-password session
/// based on the `access_token_type` query parameter.
pub async fn get_atprotocol_session_handler(
    State(state): State<AppState>,
    Query(query): Query<SessionQuery>,
    ExtractedAuth(access_token): ExtractedAuth,
) -> Result<Json<AtpSessionResponse>, (StatusCode, Json<Value>)> {
    // For app_password_session, handle sub parameter logic
    let did = if query.access_token_type == "app_password_session" {
        match (&access_token.user_id, &query.sub) {
            // Both user_id and sub are set - they must match
            (Some(user_id), Some(sub)) => {
                if user_id != sub {
                    let error_response = json!({
                        "error": "invalid_request",
                        "error_description": "Token user_id and sub parameter do not match"
                    });
                    return Err((StatusCode::BAD_REQUEST, Json(error_response)));
                }
                user_id
            }
            // user_id is set but sub is not - use user_id
            (Some(user_id), None) => user_id,
            // user_id is not set but sub is - use sub
            (None, Some(sub)) => sub,
            // Neither user_id nor sub are set - error
            (None, None) => {
                let error_response = json!({
                    "error": "invalid_token",
                    "error_description": "Token missing user_id (DID) and no sub parameter provided"
                });
                return Err((StatusCode::UNAUTHORIZED, Json(error_response)));
            }
        }
    } else {
        // For non-app_password_session types, require user_id in token
        access_token.user_id.as_ref().ok_or_else(|| {
            let error_response = json!({
                "error": "invalid_token",
                "error_description": "Token missing user_id (DID)"
            });
            (StatusCode::UNAUTHORIZED, Json(error_response))
        })?
    };

    // Retrieve the DID document from DocumentStorage
    let document = match state.document_storage.get_document_by_did(did).await {
        Ok(Some(doc)) => doc,
        Ok(None) => {
            let error_response = json!({
                "error": "not_found",
                "error_description": "DID document not found"
            });
            return Err((StatusCode::NOT_FOUND, Json(error_response)));
        }
        Err(e) => {
            let error_response = json!({
                "error": "server_error",
                "error_description": format!("Failed to retrieve DID document: {}", e)
            });
            return Err((StatusCode::INTERNAL_SERVER_ERROR, Json(error_response)));
        }
    };

    // Branch based on access token type
    match query.access_token_type.as_str() {
        "app_password_session" => {
            // Use app-password session helper
            let current_session =
                get_app_password_session_with_refresh(&state, &access_token.client_id, &document)
                    .await
                    .map_err(|e| {
                        let error_msg = e.to_string();
                        let (status, error_type, error_desc) =
                            if error_msg.contains("No app-password session found") {
                                (
                                    StatusCode::NOT_FOUND,
                                    "session_not_found",
                                    "App-password session not found",
                                )
                            } else if error_msg.contains("Session has exchange error") {
                                (StatusCode::BAD_REQUEST, "session_error", error_msg.as_str())
                            } else if error_msg.contains("refresh") {
                                (
                                    StatusCode::INTERNAL_SERVER_ERROR,
                                    "refresh_failed",
                                    error_msg.as_str(),
                                )
                            } else {
                                (
                                    StatusCode::INTERNAL_SERVER_ERROR,
                                    "server_error",
                                    error_msg.as_str(),
                                )
                            };

                        let error_response = json!({
                            "error": error_type,
                            "error_description": error_desc
                        });
                        (status, Json(error_response))
                    })?;

            // Build response for app-password session
            let response = AtpSessionResponse {
                did: document.id.clone(),
                handle: document.handles().unwrap_or("unknown.unknown").to_string(),
                access_token: current_session.access_token,
                token_type: "Bearer".to_string(),
                scopes: vec!["atproto".to_string()], // App-password sessions have basic atproto scope
                pds_endpoint: document
                    .pds_endpoints()
                    .first()
                    .map_or("", |v| v)
                    .to_string(),
                dpop_key: None, // App-password sessions don't use DPoP
                dpop_jwk: None,
                expires_at: current_session.access_token_expires_at.timestamp(),
            };
            Ok(Json(response))
        }
        _ => {
            // Default to OAuth session behavior
            let session_id = match access_token.session_id {
                Some(value) => value,
                None => {
                    let error_response = json!({
                        "error": "invalid_token",
                        "error_description": "OAuth session requires session_id in token",
                    });
                    return Err((StatusCode::UNAUTHORIZED, Json(error_response)));
                }
            };

            // Use the helper function for OAuth session flow with automatic refresh
            let current_session =
                get_atprotocol_session_with_refresh(&state, &document, &session_id)
                    .await
                    .map_err(|e| {
                        let error_msg = e.to_string();
                        let (status, error_type, error_desc) =
                            if error_msg.contains("No sessions found") {
                                (
                                    StatusCode::NOT_FOUND,
                                    "session_not_found",
                                    "Session not found or expired",
                                )
                            } else if error_msg.contains("DID document not found") {
                                (
                                    StatusCode::INTERNAL_SERVER_ERROR,
                                    "session_incomplete",
                                    "Session found but ATProtocol identity not yet established",
                                )
                            } else if error_msg.contains("Session has exchange error") {
                                (StatusCode::BAD_REQUEST, "session_error", error_msg.as_str())
                            } else if error_msg.contains("refresh") {
                                (
                                    StatusCode::INTERNAL_SERVER_ERROR,
                                    "refresh_failed",
                                    error_msg.as_str(),
                                )
                            } else {
                                (
                                    StatusCode::INTERNAL_SERVER_ERROR,
                                    "server_error",
                                    error_msg.as_str(),
                                )
                            };

                        let error_response = json!({
                            "error": error_type,
                            "error_description": error_desc
                        });
                        (status, Json(error_response))
                    })?;

            let (access_token, expires_at, scopes) = match (
                current_session.access_token.clone(),
                current_session.access_token_expires_at,
                current_session.access_token_scopes.clone(),
            ) {
                (
                    Some(access_token_value),
                    Some(access_token_expires_at_value),
                    Some(access_token_scopes_value),
                ) => (
                    access_token_value,
                    access_token_expires_at_value.timestamp(),
                    access_token_scopes_value,
                ),
                _ => {
                    let error_response = json!({
                        "error": "session_incomplete",
                        "error_description": "Session found it is not valid"
                    });
                    return Err((StatusCode::INTERNAL_SERVER_ERROR, Json(error_response)));
                }
            };

            // Generate DPoP JWK from the session's DPoP key
            let (dpop_key, dpop_jwk) = match identify_key(&current_session.dpop_key) {
                Ok(private_key_data) => {
                    let dpop_key_str = current_session.dpop_key.clone();
                    match generate_jwk(&private_key_data) {
                        Ok(jwk) => (Some(dpop_key_str), Some(jwk)),
                        Err(_) => (Some(dpop_key_str), None),
                    }
                }
                Err(_) => (Some(current_session.dpop_key.clone()), None),
            };

            let response = AtpSessionResponse {
                did: document.id.clone(),
                handle: document.handles().unwrap_or("unknown.unknown").to_string(),
                access_token,
                token_type: "DPOP".to_string(), // Proper DPoP token type - BFF will handle DPoP signing
                scopes,
                pds_endpoint: document
                    .pds_endpoints()
                    .first()
                    .map_or("", |v| v)
                    .to_string(),
                dpop_key,
                dpop_jwk,
                expires_at,
            };
            Ok(Json(response))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_atp_session_response_structure() {
        let response = AtpSessionResponse {
            did: "did:plc:test123".to_string(),
            handle: "test.bsky.social".to_string(),
            access_token: "test-token".to_string(),
            token_type: "Bearer".to_string(),
            scopes: vec!["atproto".to_string()],
            pds_endpoint: "https://bsky.social".to_string(),
            dpop_key: Some("test-dpop-key".to_string()),
            dpop_jwk: None,
            expires_at: 1234567890,
        };

        assert_eq!(response.did, "did:plc:test123");
        assert_eq!(response.handle, "test.bsky.social".to_string());
        assert_eq!(response.token_type, "Bearer");
        assert!(response.scopes.contains(&"atproto".to_string()));
        assert_eq!(response.dpop_key, Some("test-dpop-key".to_string()));
        assert_eq!(response.dpop_jwk, None);
    }
}
