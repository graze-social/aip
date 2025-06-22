//! Handles GET /oauth/userinfo - OpenID Connect UserInfo endpoint

use atproto_client::client::{DPoPAuth, get_dpop_json_with_headers};
use atproto_identity::key::identify_key;
use axum::{extract::State, http::StatusCode, response::Json};
use reqwest::header::HeaderMap;
use serde::Deserialize;
use serde_json::{Value, json};

use super::{context::AppState, utils_atprotocol_oauth::create_atp_backed_server};
use crate::http::middleware_auth::ExtractedAuth;
use crate::oauth::openid::OpenIDClaims;
use crate::oauth::types::parse_scope;

/// ATProtocol getSession response
#[derive(Debug, Deserialize)]
struct AtpGetSessionResponse {
    #[allow(dead_code)]
    handle: String,
    #[allow(dead_code)]
    did: String,
    email: Option<String>,
    #[allow(dead_code)]
    #[serde(rename = "emailConfirmed")]
    email_confirmed: Option<bool>,
}

/// Get OpenID Connect UserInfo
/// GET /oauth/userinfo
///
/// Returns claims about the authenticated End-User as authorized by the access token.
/// The response is a JSON object containing claims about the End-User.
pub async fn get_userinfo_handler(
    State(state): State<AppState>,
    ExtractedAuth(access_token): ExtractedAuth,
) -> Result<Json<OpenIDClaims>, (StatusCode, Json<Value>)> {
    tracing::info!(?access_token, "get_userinfo_handler");

    // Get the user ID (DID) from the access token
    let user_id = match access_token.user_id {
        Some(ref uid) => uid.clone(),
        None => {
            let error_response = json!({
                "error": "invalid_token",
                "error_description": "Access token missing user_id (subject)"
            });
            return Err((StatusCode::UNAUTHORIZED, Json(error_response)));
        }
    };

    // Parse the access token scopes
    let scopes = match access_token.scope {
        Some(ref scope_str) => parse_scope(scope_str),
        None => std::collections::HashSet::new(),
    };

    // Check for standard OAuth scopes
    let has_profile_scope = scopes.contains("profile");
    let has_email_scope = scopes.contains("email");

    // Check if ATProtocol scopes are present (for accessing ATProtocol-specific data)
    let has_atproto_scopes =
        scopes.contains("atproto:atproto") && scopes.contains("atproto:transition:generic");

    // If ATProtocol scopes are not present, we can only return DID and basic profile info (no email)
    if !has_atproto_scopes {
        let mut claims = OpenIDClaims::new_userinfo(user_id.clone()).with_did(user_id.clone());

        // If profile scope is present, try to get basic profile info from DID document
        if has_profile_scope {
            if let Ok(Some(document)) = state.document_storage.get_document_by_did(&user_id).await {
                claims = claims
                    .with_name(document.handles().map(|h| h.to_string()))
                    .with_pds_endpoint(document.pds_endpoints().first().map(|v| v.to_string()));
            }
        }

        return Ok(Json(claims));
    }

    // Retrieve the DID document from DocumentStorage
    let document = match state.document_storage.get_document_by_did(&user_id).await {
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

    // Get the handle from the DID document
    let handle = document.handles().map(|h| h.to_string());
    let pds_endpoint = document.pds_endpoints().first().map(|v| v.to_string());

    // If email scope is not present, return DID and optionally profile information
    if !has_email_scope {
        let mut claims = OpenIDClaims::new_userinfo(user_id).with_did(document.id);

        // Only set name, pds_endpoint, and profile fields if profile scope is present
        if has_profile_scope {
            claims = claims.with_name(handle).with_pds_endpoint(pds_endpoint);
        }

        return Ok(Json(claims));
    }

    // Get ATProtocol session information to fetch email
    if scopes.iter().any(|s| s.starts_with("atproto")) {
        if let Some(session_id) = access_token.session_id {
            // Create ATProtocol-backed authorization server to get session info
            let atp_auth_server = create_atp_backed_server(&state).await.map_err(|e| {
                let error_response = json!({
                    "error": "server_error",
                    "error_description": format!("Failed to create ATProtocol authorization server: {}", e)
                });
                (StatusCode::INTERNAL_SERVER_ERROR, Json(error_response))
            })?;

            // Get the ATProtocol session
            match atp_auth_server
                .session_storage()
                .get_sessions(&user_id, &session_id)
                .await
            {
                Ok(sessions) if !sessions.is_empty() => {
                    let session = &sessions[0];

                    // Check if we have a valid ATProtocol access token
                    if let (Some(atp_access_token), Some(pds_endpoint)) =
                        (&session.access_token, document.pds_endpoints().first())
                    {
                        // Make DPoP request to get session with email
                        let email = fetch_email_from_pds(
                            &state,
                            atp_access_token,
                            &session.dpop_key,
                            pds_endpoint,
                        )
                        .await?;

                        let mut claims =
                            OpenIDClaims::new_userinfo(user_id).with_did(document.id.clone());

                        // Only set name, pds_endpoint, and profile fields if profile scope is present
                        if has_profile_scope {
                            claims = claims
                                .with_name(handle)
                                .with_pds_endpoint(Some(pds_endpoint.to_string()));
                        }

                        // Set email since email scope is present
                        claims = claims.with_email(email);

                        return Ok(Json(claims));
                    }
                }
                Ok(_) => {
                    tracing::warn!("No ATProtocol sessions found for user: {}", user_id);
                }
                Err(e) => {
                    tracing::warn!("Failed to get sessions for user {}: {}", user_id, e);
                }
            }
        }
    }

    // Fallback response if we couldn't get email
    let mut claims = OpenIDClaims::new_userinfo(user_id).with_did(document.id.clone());

    // Only set name, pds_endpoint, and profile fields if profile scope is present
    if has_profile_scope {
        claims = claims.with_name(handle).with_pds_endpoint(pds_endpoint);
    }

    Ok(Json(claims))
}

/// Fetch email from ATProtocol PDS using DPoP
async fn fetch_email_from_pds(
    state: &AppState,
    atp_access_token: &str,
    dpop_key: &str,
    pds_endpoint: &str,
) -> Result<Option<String>, (StatusCode, Json<Value>)> {
    // Parse the DPoP key
    let dpop_private_key = identify_key(dpop_key).map_err(|e| {
        let error_response = json!({
            "error": "server_error",
            "error_description": format!("Failed to parse DPoP key: {}", e)
        });
        (StatusCode::INTERNAL_SERVER_ERROR, Json(error_response))
    })?;

    // Create DPoP authentication
    let dpop_auth = DPoPAuth {
        dpop_private_key_data: dpop_private_key,
        oauth_access_token: atp_access_token.to_string(),
    };

    // Construct the getSession endpoint URL
    let get_session_url = format!("{}/xrpc/com.atproto.server.getSession", pds_endpoint);

    // Make DPoP GET request to the PDS
    let session_response = get_dpop_json_with_headers(
        &state.identity_resolver.0.http_client,
        &dpop_auth,
        &get_session_url,
        &HeaderMap::new(),
    )
    .await
    .map_err(|e| {
        tracing::warn!("Failed to fetch session from PDS: {}", e);
        let error_response = json!({
            "error": "upstream_error",
            "error_description": format!("Failed to fetch session from PDS: {}", e)
        });
        (StatusCode::BAD_GATEWAY, Json(error_response))
    })?;

    // Parse the response
    let atp_session: AtpGetSessionResponse =
        serde_json::from_value(session_response).map_err(|e| {
            tracing::warn!("Failed to parse ATProtocol session response: {}", e);
            let error_response = json!({
                "error": "server_error",
                "error_description": format!("Failed to parse session response: {}", e)
            });
            (StatusCode::INTERNAL_SERVER_ERROR, Json(error_response))
        })?;

    Ok(atp_session.email)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::oauth::DPoPNonceGenerator;
    use crate::oauth::resource_server::ResourceServer;
    use crate::storage::SimpleKeyProvider;
    use crate::storage::inmemory::MemoryOAuthStorage;
    use atproto_identity::{resolve::create_resolver, storage_lru::LruDidDocumentStorage};
    use atproto_oauth::storage_lru::LruOAuthRequestStorage;
    use std::{num::NonZeroUsize, sync::Arc};

    fn create_test_app_state() -> AppState {
        let oauth_storage = Arc::new(MemoryOAuthStorage::new());
        let resource_server = Arc::new(ResourceServer::new(
            oauth_storage.clone(),
            "https://localhost".to_string(),
        ));

        let http_client = reqwest::Client::new();
        let dns_nameservers = vec![];
        let dns_resolver = create_resolver(&dns_nameservers);
        let identity_resolver = atproto_identity::resolve::IdentityResolver(Arc::new(
            atproto_identity::resolve::InnerIdentityResolver {
                http_client,
                dns_resolver,
                plc_hostname: "plc.directory".to_string(),
            },
        ));

        let key_provider = Arc::new(SimpleKeyProvider::new());
        let oauth_request_storage =
            Arc::new(LruOAuthRequestStorage::new(NonZeroUsize::new(256).unwrap()));
        let document_storage =
            Arc::new(LruDidDocumentStorage::new(NonZeroUsize::new(100).unwrap()));

        #[cfg(feature = "reload")]
        let template_env = {
            use minijinja_autoreload::AutoReloader;
            axum_template::engine::Engine::new(AutoReloader::new(|_| {
                Ok(minijinja::Environment::new())
            }))
        };

        #[cfg(not(feature = "reload"))]
        let template_env = axum_template::engine::Engine::new(minijinja::Environment::new());

        let config = Arc::new(crate::config::Config {
            version: "test".to_string(),
            http_port: "3000".to_string().try_into().unwrap(),
            http_static_path: "static".to_string(),
            http_templates_path: "templates".to_string(),
            external_base: "https://localhost".to_string(),
            certificate_bundles: "".to_string().try_into().unwrap(),
            user_agent: "test-user-agent".to_string(),
            plc_hostname: "plc.directory".to_string(),
            dns_nameservers: "".to_string().try_into().unwrap(),
            http_client_timeout: "10s".to_string().try_into().unwrap(),
            atproto_oauth_signing_keys: Default::default(),
            oauth_signing_keys: Default::default(),
            oauth_supported_scopes: crate::config::OAuthSupportedScopes::try_from(
                "openid read write atproto:atproto".to_string(),
            )
            .unwrap(),
            dpop_nonce_seed: "seed".to_string(),
            storage_backend: "memory".to_string(),
            database_url: None,
            redis_url: None,
            enable_client_api: false,
        });

        let atp_session_storage =
            Arc::new(crate::oauth::atprotocol_bridge::MemoryAtpOAuthSessionStorage::new());
        let authorization_request_storage =
            Arc::new(crate::oauth::atprotocol_bridge::MemoryAuthorizationRequestStorage::new());
        let client_registration_service = Arc::new(crate::oauth::ClientRegistrationService::new(
            oauth_storage.clone(),
        ));

        AppState {
            config: config.clone(),
            template_env,
            identity_resolver,
            key_provider,
            oauth_request_storage,
            document_storage,
            oauth_storage,
            resource_server,
            client_registration_service,
            atp_session_storage,
            authorization_request_storage,
            atproto_oauth_signing_keys: vec![],
            dpop_nonce_provider: Arc::new(DPoPNonceGenerator::new(
                config.dpop_nonce_seed.clone(),
                1,
            )),
        }
    }

    #[test]
    fn test_userinfo_response_structure() {
        let response = OpenIDClaims::new_userinfo("did:plc:test123".to_string())
            .with_name(Some("test.bsky.social".to_string()))
            .with_email(Some("test@example.com".to_string()));

        assert_eq!(response.sub, "did:plc:test123");
        assert_eq!(response.name, Some("test.bsky.social".to_string()));
        assert_eq!(response.email, Some("test@example.com".to_string()));
    }

    #[test]
    fn test_userinfo_response_minimal() {
        let response = OpenIDClaims::new_userinfo("did:plc:user123".to_string());

        assert_eq!(response.sub, "did:plc:user123");
        assert_eq!(response.name, None);
        assert_eq!(response.email, None);
    }

    #[tokio::test]
    async fn test_userinfo_handler_without_atproto_scopes() {
        use crate::oauth::types::{AccessToken, TokenType};
        use chrono::Utc;

        let app_state = create_test_app_state();

        // Create an access token without ATProtocol scopes
        let access_token = AccessToken {
            token: "test-token".to_string(),
            token_type: TokenType::Bearer,
            client_id: "test-client".to_string(),
            user_id: Some("did:plc:test123".to_string()),
            session_id: Some("test-session".to_string()),
            session_iteration: Some(1),
            scope: Some("read write".to_string()), // No ATProtocol scopes
            created_at: Utc::now(),
            expires_at: Utc::now() + chrono::Duration::hours(1),
            dpop_jkt: None,
        };

        let extracted_auth = crate::http::middleware_auth::ExtractedAuth(access_token);

        let result = get_userinfo_handler(axum::extract::State(app_state), extracted_auth).await;

        assert!(result.is_ok());
        let response = result.unwrap().0;

        // Should return just the DID
        assert_eq!(response.sub, "did:plc:test123");
        assert_eq!(response.did, Some("did:plc:test123".to_string()));
        assert_eq!(response.email, None);
    }

    #[tokio::test]
    async fn test_userinfo_handler_missing_user_id() {
        use crate::oauth::types::{AccessToken, TokenType};
        use chrono::Utc;

        let app_state = create_test_app_state();

        // Create an access token without user_id
        let access_token = AccessToken {
            token: "test-token".to_string(),
            token_type: TokenType::Bearer,
            client_id: "test-client".to_string(),
            user_id: None, // Missing user_id
            session_id: Some("test-session".to_string()),
            session_iteration: Some(1),
            scope: Some("openid".to_string()),
            created_at: Utc::now(),
            expires_at: Utc::now() + chrono::Duration::hours(1),
            dpop_jkt: None,
        };

        let extracted_auth = crate::http::middleware_auth::ExtractedAuth(access_token);

        let result = get_userinfo_handler(axum::extract::State(app_state), extracted_auth).await;

        assert!(result.is_err());
        let (status, json_response) = result.unwrap_err();
        assert_eq!(status, StatusCode::UNAUTHORIZED);

        let error = json_response.0;
        assert_eq!(error["error"], "invalid_token");
    }

    #[tokio::test]
    async fn test_userinfo_handler_without_atproto_scopes_minimal() {
        use crate::oauth::types::{AccessToken, TokenType};
        use chrono::Utc;

        let app_state = create_test_app_state();

        // Create an access token with non-ATProtocol scopes
        let access_token = AccessToken {
            token: "test-token".to_string(),
            token_type: TokenType::Bearer,
            client_id: "test-client".to_string(),
            user_id: Some("did:plc:user123".to_string()),
            session_id: Some("test-session".to_string()),
            session_iteration: Some(1),
            scope: Some("openid".to_string()),
            created_at: Utc::now(),
            expires_at: Utc::now() + chrono::Duration::hours(1),
            dpop_jkt: None,
        };

        let extracted_auth = crate::http::middleware_auth::ExtractedAuth(access_token);

        let result = get_userinfo_handler(axum::extract::State(app_state), extracted_auth).await;

        assert!(result.is_ok());
        let response = result.unwrap().0;

        assert_eq!(response.sub, "did:plc:user123");
        assert_eq!(response.did, Some("did:plc:user123".to_string()));
        assert_eq!(response.email, None);
    }
}
