//! Handles GET /api/atprotocol/session - Retrieves ATProtocol OAuth session information including access tokens and DPoP keys

use atproto_oauth::jwk::WrappedJsonWebKey;
use axum::{
    extract::{Query, State},
    http::StatusCode,
    response::Json,
};
use chrono::Utc;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use super::{context::AppState, utils_atprotocol_oauth::create_atp_backed_server};
use crate::http::middleware_auth::ExtractedAuth;
use atproto_identity::key::identify_key;
use atproto_oauth::jwk::generate as generate_jwk;

/// Query parameters for the session endpoint
#[derive(Debug, Deserialize)]
pub struct SessionQuery {
    /// Force refresh of the session even if not expired
    #[serde(default)]
    pub force_refresh: Option<String>,
}

/// ATProtocol session information response
#[derive(Debug, Serialize)]
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
/// Retrieves ATProtocol OAuth session information using either:
/// 1. Session ID from query parameters, or
/// 2. Session ID extracted from JWT bearer token
pub async fn get_atprotocol_session_handler(
    State(state): State<AppState>,
    Query(query): Query<SessionQuery>,
    ExtractedAuth(access_token): ExtractedAuth,
) -> Result<Json<AtpSessionResponse>, (StatusCode, Json<Value>)> {
    tracing::info!(?access_token, ?query, "get_atprotocol_session_handler");

    // Create ATProtocol-backed authorization server
    let atp_auth_server = create_atp_backed_server(&state).await.map_err(|e| {
        let error_response = json!({
            "error": "server_error",
            "error_description": format!("Failed to create ATProtocol authorization server: {}", e)
        });
        (StatusCode::INTERNAL_SERVER_ERROR, Json(error_response))
    })?;

    let session_id = match access_token.session_id {
        Some(value) => value,
        None => {
            let error_response = json!({
                "error": "invalid_token",
                "error_description": "something went horribly wrong",
            });
            return Err((StatusCode::UNAUTHORIZED, Json(error_response)));
        }
    };

    let did = access_token.user_id.as_ref().ok_or_else(|| {
        let error_response = json!({
            "error": "invalid_token",
            "error_description": "Token missing user_id (DID)"
        });
        (StatusCode::UNAUTHORIZED, Json(error_response))
    })?;

    let sessions = match atp_auth_server
        .session_storage()
        .get_sessions(did, &session_id)
        .await
    {
        Ok(sessions) if !sessions.is_empty() => sessions,
        Ok(_) => {
            let error_response = json!({
                "error": "session_not_found",
                "error_description": "Session not found or expired"
            });
            return Err((StatusCode::NOT_FOUND, Json(error_response)));
        }
        Err(e) => {
            let error_response = json!({
                "error": "storage_error",
                "error_description": format!("Failed to retrieve session: {}", e)
            });
            return Err((StatusCode::INTERNAL_SERVER_ERROR, Json(error_response)));
        }
    };

    tracing::info!(?sessions, "sessions found");

    // Use the most recent session (highest iteration)
    let session = &sessions[0];

    tracing::info!(?session, "session found");

    // Check if session has an exchange error
    if let Some(ref exchange_error) = session.exchange_error {
        let error_response = json!({
            "error": "session_error",
            "error_description": exchange_error
        });
        return Err((StatusCode::BAD_REQUEST, Json(error_response)));
    }

    // Check if token needs refreshing (expired or force refresh requested)
    let now = chrono::Utc::now();
    let should_refresh = query.force_refresh.is_some_and(|v| &v == "force_refresh")
        || session
            .access_token_expires_at
            .map(|expires_at| expires_at <= now)
            .unwrap_or(false);

    tracing::info!(?should_refresh, "should refresh");

    let current_session = if should_refresh {
        // Perform session refresh
        match refresh_session(&state, session, &atp_auth_server).await {
            Ok(new_session) => new_session,
            Err(e) => {
                let error_response = json!({
                    "error": "refresh_failed",
                    "error_description": format!("Failed to refresh session: {}", e)
                });
                return Err((StatusCode::INTERNAL_SERVER_ERROR, Json(error_response)));
            }
        }
    } else {
        session.clone()
    };

    let document = match state
        .document_storage
        .get_document_by_did(&current_session.did)
        .await
    {
        Ok(Some(value)) => value,
        Ok(None) => {
            let error_response = json!({
                "error": "session_incomplete",
                "error_description": "Session found but ATProtocol identity not yet established"
            });
            return Err((StatusCode::INTERNAL_SERVER_ERROR, Json(error_response)));
        }
        Err(e) => {
            let error_response = json!({
                "error": "session_incomplete",
                "error_description": format!("Session found but ATProtocol identity not yet established: {e}")
            });
            return Err((StatusCode::INTERNAL_SERVER_ERROR, Json(error_response)));
        }
    };

    tracing::info!(?document, "document found");

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

/// Refresh an ATProtocol OAuth session using oauth_refresh workflow
async fn refresh_session(
    _state: &AppState,
    session: &crate::oauth::atprotocol_bridge::AtpOAuthSession,
    atp_auth_server: &crate::oauth::AtpBackedAuthorizationServer,
) -> Result<
    crate::oauth::atprotocol_bridge::AtpOAuthSession,
    Box<dyn std::error::Error + Send + Sync>,
> {
    use atproto_identity::key::identify_key;
    use atproto_oauth::workflow::oauth_refresh;

    let now = Utc::now();
    let new_iteration = session.iteration + 1;

    // Parse the DPoP key from the session
    let dpop_key =
        identify_key(&session.dpop_key).map_err(|e| format!("Failed to parse DPoP key: {}", e))?;

    // Create new session with incremented iteration
    let mut new_session = crate::oauth::atprotocol_bridge::AtpOAuthSession {
        session_id: session.session_id.clone(),
        did: session.did.clone(),
        session_created_at: session.session_created_at,
        atp_oauth_state: session.atp_oauth_state.clone(),
        signing_key_jkt: session.signing_key_jkt.clone(),
        dpop_key: session.dpop_key.clone(),
        access_token: None,
        refresh_token: None,
        access_token_created_at: None,
        access_token_expires_at: None,
        access_token_scopes: None,
        session_exchanged_at: Some(now),
        exchange_error: None,
        iteration: new_iteration,
    };

    // Get the document for the DID
    let document = match atp_auth_server
        .document_storage()
        .get_document_by_did(&session.did)
        .await
    {
        Ok(Some(doc)) => doc,
        Ok(None) => {
            new_session.exchange_error = Some("DID document not found".to_string());
            atp_auth_server
                .session_storage()
                .store_session(&new_session)
                .await
                .map_err(|e| format!("Failed to store session with error: {}", e))?;
            return Err("DID document not found".into());
        }
        Err(e) => {
            new_session.exchange_error = Some(format!("Failed to get DID document: {}", e));
            atp_auth_server
                .session_storage()
                .store_session(&new_session)
                .await
                .map_err(|e| format!("Failed to store session with error: {}", e))?;
            return Err(format!("Failed to get DID document: {}", e).into());
        }
    };

    // Create OAuth client
    let oauth_client = atp_auth_server.create_oauth_client();

    // Attempt to refresh the session
    match session.refresh_token.as_ref() {
        Some(refresh_token) => {
            match oauth_refresh(
                atp_auth_server.http_client(),
                &oauth_client,
                &dpop_key,
                refresh_token,
                &document,
            )
            .await
            {
                Ok(token_response) => {
                    // Update session with new tokens
                    new_session.access_token = Some(token_response.access_token);
                    new_session.refresh_token = Some(token_response.refresh_token);
                    new_session.access_token_created_at = Some(now);
                    new_session.access_token_expires_at =
                        Some(now + chrono::Duration::seconds(token_response.expires_in as i64));
                    new_session.access_token_scopes = Some(
                        token_response
                            .scope
                            .split_whitespace()
                            .map(|s| s.to_string())
                            .collect(),
                    );
                }
                Err(e) => {
                    // Store the refresh error in the new session
                    new_session.exchange_error = Some(format!("Refresh failed: {}", e));
                }
            }
        }
        None => {
            new_session.exchange_error = Some("No refresh token available".to_string());
        }
    }

    // Store the new session
    atp_auth_server
        .session_storage()
        .store_session(&new_session)
        .await
        .map_err(|e| format!("Failed to store refreshed session: {}", e))?;

    // Return error if refresh failed
    if let Some(ref error) = new_session.exchange_error {
        return Err(error.clone().into());
    }

    Ok(new_session)
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
