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
    /// Access token type - "oauth_session" (default), "app_password_session", or "best" (tries app-password first, then oauth)
    #[serde(default = "default_access_token_type")]
    pub access_token_type: String,
    /// Subject DID for app password session lookup (optional)
    pub sub: Option<String>,
    /// DID of the account owner to act on behalf of (delegate access)
    pub delegate_for: Option<String>,
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
/// Retrieves ATProtocol session information. Can retrieve OAuth session (default), app-password session,
/// or the best available session (tries app-password first, falls back to OAuth) based on the
/// `access_token_type` query parameter.
pub async fn get_atprotocol_session_handler(
    State(state): State<AppState>,
    Query(query): Query<SessionQuery>,
    ExtractedAuth(access_token): ExtractedAuth,
) -> Result<Json<AtpSessionResponse>, (StatusCode, Json<Value>)> {
    // For app_password_session, handle sub parameter logic
    let did = if query.access_token_type == "app_password_session" || query.access_token_type == "best" {
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

    // Handle delegate_for: if present, verify caller is a delegate and switch to owner's DID
    let did = if let Some(ref owner_did) = query.delegate_for {
        // Validate the DID format
        if let Err(e) = super::utils_oauth::validate_did(owner_did) {
            let error_response = json!({
                "error": "invalid_request",
                "error_description": format!("Invalid delegate_for DID: {}", e)
            });
            return Err((StatusCode::BAD_REQUEST, Json(error_response)));
        }

        // Verify the caller is a delegate for the requested owner
        let is_delegate = state
            .oauth_storage
            .is_delegate(owner_did, did)
            .await
            .map_err(|e| {
                let error_response = json!({
                    "error": "server_error",
                    "error_description": format!("Failed to check delegate access: {}", e)
                });
                (StatusCode::INTERNAL_SERVER_ERROR, Json(error_response))
            })?;

        if !is_delegate {
            let error_response = json!({
                "error": "forbidden",
                "error_description": "You are not a delegate for this account"
            });
            return Err((StatusCode::FORBIDDEN, Json(error_response)));
        }

        // Use the owner's DID for session lookup
        owner_did
    } else {
        did
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

    // Try app-password session if requested or if "best" mode
    if query.access_token_type == "app_password_session" || query.access_token_type == "best" {
        match get_app_password_session_with_refresh(&state, &access_token.client_id, &document)
            .await
        {
            Ok(current_session) => {
                // Build response for app-password session
                let response = AtpSessionResponse {
                    did: document.id.clone(),
                    handle: document.handles().unwrap_or("unknown.unknown").to_string(),
                    access_token: current_session.access_token,
                    token_type: "bearer".to_string(),
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
                return Ok(Json(response));
            }
            Err(e) if query.access_token_type == "app_password_session" => {
                // For explicit app-password request, return error
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
                return Err((status, Json(error_response)));
            }
            Err(err) => {
                tracing::warn!(?err, "no app-password session found");
                // For "best" mode, continue to OAuth session below
            }
        }
    }

    // If delegate_for is set and we haven't returned yet, look up the owner's sessions by DID
    if query.delegate_for.is_some() {
        // For delegation, find the owner's latest session by DID
        let owner_sessions = state
            .oauth_storage
            .get_sessions_by_did(did)
            .await
            .map_err(|e| {
                let error_response = json!({
                    "error": "server_error",
                    "error_description": format!("Failed to look up owner sessions: {}", e)
                });
                (StatusCode::INTERNAL_SERVER_ERROR, Json(error_response))
            })?;

        // Find the best session: prefer one with a valid access token
        let best_session = owner_sessions
            .iter()
            .filter(|s| s.access_token.is_some() && s.session_exchanged_at.is_some() && s.exchange_error.is_none())
            .max_by_key(|s| s.access_token_expires_at);

        match best_session {
            Some(session) => {
                let (access_token_val, expires_at, scopes) = match (
                    session.access_token.clone(),
                    session.access_token_expires_at,
                    session.access_token_scopes.clone(),
                ) {
                    (Some(at), Some(exp), Some(sc)) => (at, exp.timestamp(), sc),
                    _ => {
                        let error_response = json!({
                            "error": "session_incomplete",
                            "error_description": "Owner session found but is not valid"
                        });
                        return Err((StatusCode::INTERNAL_SERVER_ERROR, Json(error_response)));
                    }
                };

                // Never return private key for delegated sessions — delegates must use
                // the /api/atprotocol/dpop-proof endpoint for per-request signing
                let dpop_key = None;
                let dpop_jwk = None;

                let response = AtpSessionResponse {
                    did: document.id.clone(),
                    handle: document.handles().unwrap_or("unknown.unknown").to_string(),
                    access_token: access_token_val,
                    token_type: "dpop".to_string(),
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
                return Ok(Json(response));
            }
            None => {
                let error_response = json!({
                    "error": "session_not_found",
                    "error_description": "No valid session found for the delegated account"
                });
                return Err((StatusCode::NOT_FOUND, Json(error_response)));
            }
        }
    }

    // OAuth session logic (for default, or "best" fallback)
    if query.access_token_type != "app_password_session" {
        let session_id = match access_token.session_id {
            Some(value) => value,
            None => {
                let error_response = if query.access_token_type == "best" {
                    json!({
                        "error": "no_session_found",
                        "error_description": "No app-password or OAuth session found"
                    })
                } else {
                    json!({
                        "error": "invalid_token",
                        "error_description": "OAuth session requires session_id in token",
                    })
                };
                let status = if query.access_token_type == "best" {
                    StatusCode::NOT_FOUND
                } else {
                    StatusCode::UNAUTHORIZED
                };
                return Err((status, Json(error_response)));
            }
        };

        // Use the helper function for OAuth session flow with automatic refresh
        let current_session = get_atprotocol_session_with_refresh(&state, &document, &session_id)
            .await
            .map_err(|e| {
                let error_msg = e.to_string();
                let (status, error_type, error_desc) = if query.access_token_type == "best" {
                    // For "best" mode, we tried both and both failed
                    (
                        StatusCode::NOT_FOUND,
                        "no_session_found",
                        "No valid app-password or OAuth session found",
                    )
                } else if error_msg.contains("No sessions found") {
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
            token_type: "dpop".to_string(), // Proper DPoP token type - BFF will handle DPoP signing
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
    } else {
        // This should be unreachable - app_password_session always returns above
        unreachable!("app_password_session should have returned above")
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
