//! Handles GET /oauth/userinfo - OpenID Connect UserInfo endpoint

use axum::{extract::State, http::StatusCode, response::Json};
use serde_json::{Value, json};

use super::context::AppState;
use crate::http::middleware_auth::ExtractedAuth;
use crate::oauth::openid::OpenIDClaims;
use crate::oauth::types::parse_scope;
use crate::oauth::utils_atprotocol_oauth::{
    build_openid_claims_with_document_info, get_atprotocol_session_with_refresh,
};

/// Get OpenID Connect UserInfo
/// GET /oauth/userinfo
///
/// Returns claims about the authenticated End-User as authorized by the access token.
/// The response is a JSON object containing claims about the End-User.
pub async fn get_userinfo_handler(
    State(state): State<AppState>,
    ExtractedAuth(access_token): ExtractedAuth,
) -> Result<Json<OpenIDClaims>, (StatusCode, Json<Value>)> {
    tracing::debug!(?access_token, "get_userinfo_handler access_token");

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

    // Retrieve the DID document from DocumentStorage
    let document = match state.document_storage.get_document_by_did(&user_id).await {
        Ok(Some(value)) => value,
        _ => {
            tracing::warn!("no document found for user id");
            let error_response = json!({
                "error": "internal_error",
                "error_description": "Internal error generating response"
            });
            return Err((StatusCode::INTERNAL_SERVER_ERROR, Json(error_response)));
        }
    };

    // Parse the access token scopes
    let scopes = match access_token.scope {
        Some(ref scope_str) => parse_scope(scope_str),
        None => std::collections::HashSet::new(),
    };

    // Create initial UserInfo claims
    let initial_claims = OpenIDClaims::new_userinfo(user_id.clone());

    let session_id = match access_token.session_id {
        Some(value) => value,
        _ => {
            tracing::warn!("no session_id associated with access token");
            let error_response = json!({
                "error": "internal_error",
                "error_description": "Internal error generating response"
            });
            return Err((StatusCode::INTERNAL_SERVER_ERROR, Json(error_response)));
        }
    };

    let session = match get_atprotocol_session_with_refresh(&state, &document, &session_id).await {
        Ok(value) => value,
        Err(_) => {
            let error_response = json!({
                "error": "internal_error",
                "error_description": "Internal error generating response"
            });
            return Err((StatusCode::INTERNAL_SERVER_ERROR, Json(error_response)));
        }
    };

    // Use the helper function to build claims with document information
    let mut claims = build_openid_claims_with_document_info(
        &state.http_client,
        initial_claims,
        &document,
        &scopes,
        Some(&session),
    )
    .await
    .map_err(|e| {
        let error_msg = e.to_string();
        let (status, error_type, error_desc) = if error_msg.contains("DID document not found") {
            (StatusCode::NOT_FOUND, "not_found", "DID document not found")
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

    claims = claims.with_nonce(access_token.nonce);

    Ok(Json(claims))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::oauth::DPoPNonceGenerator;
    use crate::storage::SimpleKeyProvider;
    use crate::storage::inmemory::MemoryOAuthStorage;
    use atproto_identity::{resolve::create_resolver, storage_lru::LruDidDocumentStorage};
    use atproto_oauth::storage_lru::LruOAuthRequestStorage;
    use std::{num::NonZeroUsize, sync::Arc};

    fn create_test_app_state() -> AppState {
        let oauth_storage = Arc::new(MemoryOAuthStorage::new());

        let http_client = reqwest::Client::new();
        let dns_nameservers = vec![];
        let dns_resolver = create_resolver(&dns_nameservers);
        let identity_resolver = atproto_identity::resolve::IdentityResolver(Arc::new(
            atproto_identity::resolve::InnerIdentityResolver {
                http_client: http_client.clone(),
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
            client_default_access_token_expiration: "1d".to_string().try_into().unwrap(),
            client_default_refresh_token_expiration: "14d".to_string().try_into().unwrap(),
            admin_dids: "".to_string().try_into().unwrap(),
            client_default_redirect_exact: "true".to_string().try_into().unwrap(),
            atproto_client_name: "AIP OAuth Server".to_string().try_into().unwrap(),
            atproto_client_logo: None::<String>.try_into().unwrap(),
            atproto_client_tos: None::<String>.try_into().unwrap(),
            atproto_client_policy: None::<String>.try_into().unwrap(),
        });

        let atp_session_storage = Arc::new(
            crate::oauth::UnifiedAtpOAuthSessionStorageAdapter::new(oauth_storage.clone()),
        );
        let authorization_request_storage = Arc::new(
            crate::oauth::UnifiedAuthorizationRequestStorageAdapter::new(oauth_storage.clone()),
        );
        let client_registration_service = Arc::new(crate::oauth::ClientRegistrationService::new(
            oauth_storage.clone(),
            chrono::Duration::days(1),
            chrono::Duration::days(14),
            true,
        ));

        AppState {
            http_client: http_client.clone(),
            config: config.clone(),
            template_env,
            identity_resolver,
            key_provider,
            oauth_request_storage,
            document_storage,
            oauth_storage,
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
        use crate::storage::traits::AtpOAuthSession;
        use atproto_identity::key::{KeyType, generate_key};
        use chrono::Utc;

        let app_state = create_test_app_state();

        // Create and store a test DID document
        let test_document = serde_json::from_value(serde_json::json!({
            "id": "did:plc:test123",
            "alsoKnownAs": [],
            "service": [{
                "id": "#atproto_pds",
                "type": "AtprotoPersonalDataServer",
                "serviceEndpoint": "https://bsky.social"
            }],
            "verificationMethod": []
        }))
        .unwrap();
        app_state
            .document_storage
            .store_document(test_document)
            .await
            .unwrap();

        // Generate a test DPoP key
        let dpop_key = generate_key(KeyType::P256Private).unwrap();
        let dpop_key_data = dpop_key.to_string();

        // Create and store a test ATProtocol OAuth session
        let test_session = AtpOAuthSession {
            session_id: "test-session".to_string(),
            did: Some("did:plc:test123".to_string()),
            session_created_at: Utc::now(),
            atp_oauth_state: "test-atp-state".to_string(),
            signing_key_jkt: "test-jkt".to_string(),
            dpop_key: dpop_key_data,
            access_token: Some("test-atp-access-token".to_string()),
            refresh_token: Some("test-atp-refresh-token".to_string()),
            access_token_created_at: Some(Utc::now()),
            access_token_expires_at: Some(Utc::now() + chrono::Duration::hours(1)),
            access_token_scopes: Some(vec!["atproto:atproto".to_string()]),
            session_exchanged_at: Some(Utc::now()),
            exchange_error: None,
            iteration: 1,
        };
        app_state
            .atp_session_storage
            .store_session(&test_session)
            .await
            .unwrap();

        // Create an access token without ATProtocol scopes
        let access_token = AccessToken {
            token: "test-token".to_string(),
            token_type: TokenType::Bearer,
            client_id: "test-client".to_string(),
            user_id: Some("did:plc:test123".to_string()),
            session_id: Some("test-session".to_string()),
            session_iteration: Some(1),
            scope: Some("read write".to_string()), // No ATProtocol scopes
            nonce: None,
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
            nonce: None,
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
        use crate::storage::traits::AtpOAuthSession;
        use atproto_identity::key::{KeyType, generate_key};
        use chrono::Utc;

        let app_state = create_test_app_state();

        // Create and store a test DID document
        let test_document = serde_json::from_value(serde_json::json!({
            "id": "did:plc:user123",
            "alsoKnownAs": [],
            "service": [{
                "id": "#atproto_pds",
                "type": "AtprotoPersonalDataServer",
                "serviceEndpoint": "https://bsky.social"
            }],
            "verificationMethod": []
        }))
        .unwrap();
        app_state
            .document_storage
            .store_document(test_document)
            .await
            .unwrap();

        // Generate a test DPoP key
        let dpop_key = generate_key(KeyType::P256Private).unwrap();
        let dpop_key_data = dpop_key.to_string();

        // Create and store a test ATProtocol OAuth session
        let test_session = AtpOAuthSession {
            session_id: "test-session".to_string(),
            did: Some("did:plc:user123".to_string()),
            session_created_at: Utc::now(),
            atp_oauth_state: "test-atp-state".to_string(),
            signing_key_jkt: "test-jkt".to_string(),
            dpop_key: dpop_key_data,
            access_token: Some("test-atp-access-token".to_string()),
            refresh_token: Some("test-atp-refresh-token".to_string()),
            access_token_created_at: Some(Utc::now()),
            access_token_expires_at: Some(Utc::now() + chrono::Duration::hours(1)),
            access_token_scopes: Some(vec!["atproto:atproto".to_string()]),
            session_exchanged_at: Some(Utc::now()),
            exchange_error: None,
            iteration: 1,
        };
        app_state
            .atp_session_storage
            .store_session(&test_session)
            .await
            .unwrap();

        // Create an access token with non-ATProtocol scopes
        let access_token = AccessToken {
            token: "test-token".to_string(),
            token_type: TokenType::Bearer,
            client_id: "test-client".to_string(),
            user_id: Some("did:plc:user123".to_string()),
            session_id: Some("test-session".to_string()),
            session_iteration: Some(1),
            scope: Some("openid".to_string()),
            nonce: None,
            created_at: Utc::now(),
            expires_at: Utc::now() + chrono::Duration::hours(1),
            dpop_jkt: None,
        };

        let extracted_auth = crate::http::middleware_auth::ExtractedAuth(access_token);

        let result = get_userinfo_handler(axum::extract::State(app_state), extracted_auth).await;

        assert!(result.is_ok());
        let response = result.unwrap();

        assert_eq!(response.sub, "did:plc:user123");
        assert_eq!(response.did, Some("did:plc:user123".to_string()));
        assert_eq!(response.email, None);
    }
}
