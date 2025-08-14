//! Handles POST /oauth/token - Exchanges authorization codes for JWT access tokens with ATProtocol identity

use anyhow::Result;
use atproto_oauth::jwt::{Header, mint};
use axum::{
    Form, Json,
    extract::State,
    http::{HeaderMap, StatusCode},
};
use chrono::Utc;
use serde_json::{Value, json};

use super::{context::AppState, utils_oauth::create_base_auth_server};
use crate::oauth::{
    OpenIDClaims,
    auth_server::{TokenForm, extract_client_auth},
    types::TokenRequest,
};
use crate::{errors::OAuthError, oauth::TokenResponse};

/// Handle ATProtocol-backed OAuth token requests
/// POST /oauth/token - Exchanges authorization code for JWT with ATProtocol identity
#[axum::debug_handler]
pub async fn handle_oauth_token(
    State(state): State<AppState>,
    headers: HeaderMap,
    Form(form): Form<TokenForm>,
) -> Result<Json<TokenResponse>, (StatusCode, Json<Value>)> {
    // Extract client authentication from Authorization header or form
    let client_auth = extract_client_auth(&headers, &form);

    let now = Utc::now();

    let request = match TokenRequest::try_from(form) {
        Ok(req) => req,
        Err(e) => {
            let error_response = json!({
                "error": "invalid_request",
                "error_description": e.to_string()
            });
            return Err((StatusCode::BAD_REQUEST, Json(error_response)));
        }
    };

    // Create base authorization server for token exchange
    let base_auth_server = create_base_auth_server(&state).await.map_err(|e| {
        let error_response = json!({
            "error": "server_error",
            "error_description": format!("Failed to create authorization server: {}", e)
        });
        (StatusCode::INTERNAL_SERVER_ERROR, Json(error_response))
    })?;

    match base_auth_server
        .token(request.clone(), &headers, client_auth)
        .await
    {
        Ok(mut value) => {
            // For device code grants, link the access token to an existing ATProtocol session
            if matches!(request.grant_type, crate::oauth::types::GrantType::DeviceCode) {
                match state.oauth_storage.get_token(&value.access_token).await {
                    Ok(Some(mut access_token)) => {
                        if let Some(ref user_did) = access_token.user_id {
                            match state.atp_session_storage.get_sessions_by_did(user_did).await {
                                Ok(sessions) => {
                                    if let Some(latest_session) = sessions.into_iter()
                                        .max_by_key(|s| s.session_created_at) {
                                        // Update the access token with the session_id
                                        access_token.session_id = Some(latest_session.session_id.clone());
                                        access_token.session_iteration = Some(latest_session.iteration);

                                        // Store the updated access token
                                        if let Err(e) = state.oauth_storage.store_token(&access_token).await {
                                            tracing::error!(
                                                error = %e,
                                                "Failed to store updated access token"
                                            );
                                        }
                                    }
                                }
                                Err(e) => {
                                    tracing::error!(
                                        error = %e,
                                        user_did = %user_did,
                                        "Failed to get sessions for user"
                                    );
                                }
                            }
                        }
                    }
                    Ok(None) => {
                        tracing::error!(
                            access_token = %value.access_token,
                            "Access token not found in storage"
                        );
                    }
                    Err(e) => {
                        tracing::error!(
                            error = %e,
                            access_token = %value.access_token,
                            "Failed to retrieve access token"
                        );
                    }
                }
            }

            if value.scope.clone().is_some_and(|v| v.contains("openid")) {
                let access_token = state
                    .oauth_storage
                    .get_token(value.access_token.as_ref())
                    .await
                    .unwrap();
                let access_token: crate::oauth::AccessToken = access_token.unwrap();

                let did = access_token.user_id.unwrap();

                let claims = OpenIDClaims::new_id_token(
                    state.config.external_base.clone(),
                    did.clone(),
                    access_token.client_id.clone(),
                    now,
                )
                .with_did(did.clone())
                .with_c_hash(request.code.unwrap().as_str())
                .with_at_hash(&access_token.token)
                .with_nonce(access_token.nonce);

                let vague_claims = serde_json::to_value(claims).unwrap();
                let real_claims: atproto_oauth::jwt::Claims =
                    serde_json::from_value(vague_claims).unwrap();

                let private_signing_key_data = state.atproto_oauth_signing_keys.first().unwrap();
                let header: Header = private_signing_key_data.clone().try_into().unwrap();
                let id_token = mint(private_signing_key_data, &header, &real_claims).unwrap();

                value = value.with_id_token(id_token);
            }

            Ok(Json(value))
        }
        Err(e) => {
            let (status, error_code) = match e {
                OAuthError::InvalidClient(_) => (StatusCode::UNAUTHORIZED, "invalid_client"),
                OAuthError::InvalidGrant(_) => (StatusCode::BAD_REQUEST, "invalid_grant"),
                OAuthError::UnsupportedGrantType(_) => {
                    (StatusCode::BAD_REQUEST, "unsupported_grant_type")
                }
                OAuthError::InvalidScope(_) => (StatusCode::BAD_REQUEST, "invalid_scope"),
                OAuthError::InvalidRequest(_) => (StatusCode::BAD_REQUEST, "invalid_request"),
                _ => (StatusCode::INTERNAL_SERVER_ERROR, "server_error"),
            };

            let error_response = json!({
                "error": error_code,
                "error_description": e.to_string()
            });
            Err((status, Json(error_response)))
        }
    }
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
                "read write atproto:atproto".to_string(),
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

    #[tokio::test]
    async fn test_token_form_validation() {
        // Test that token request forms can be created properly
        // This is a placeholder test since we don't expose the TokenForm directly
        let app_state = create_test_app_state();
        assert!(!app_state.config.external_base.is_empty());
    }
}
