//! Handles POST /oauth/token - Exchanges authorization codes for JWT access tokens with ATProtocol identity

use anyhow::Result;
use atproto_oauth::jwt::{Claims, Header, mint};
use axum::{
    Form, Json,
    extract::State,
    http::{HeaderMap, StatusCode},
};
use chrono::Utc;
use serde_json::{Value, json};
use ulid::Ulid;

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

    // {
    //     Ok(response) => Ok(response),
    //     //     // Generate ID token if OpenID scope is requested
    //     //     let id_token = if has_openid_scope(&response.scope) {
    //     //         // Get first signing key for ID token generation
    //     //         if let Some(signing_key) = state.config.oauth_signing_keys.as_ref().first() {
    //     //             // Extract information from the token request and response
    //     //             match generate_id_token_with_claims(&state, &request, &response, &session_id, signing_key)
    //     //                 .await
    //     //             {
    //     //                 Ok(token) => Some(token),
    //     //                 Err(e) => {
    //     //                     tracing::warn!("Failed to generate ID token: {}", e);
    //     //                     None
    //     //                 }
    //     //             }
    //     //         } else {
    //     //             tracing::warn!("No signing key available for ID token generation");
    //     //             None
    //     //         }
    //     //     } else {
    //     //         None
    //     //     };

    //     //     let mut response_json = json!({
    //     //         "access_token": response.access_token,
    //     //         "token_type": response.token_type,
    //     //         "expires_in": response.expires_in,
    //     //         "refresh_token": response.refresh_token,
    //     //         "scope": response.scope
    //     //     });

    //     //     if let Some(id_token) = id_token {
    //     //         response_json["id_token"] = serde_json::Value::String(id_token);
    //     //     }

    //     //     Ok(Json(response_json))
    //     Err(e) => {
    //         let (status, error_code) = match e {
    //             OAuthError::InvalidClient(_) => (StatusCode::UNAUTHORIZED, "invalid_client"),
    //             OAuthError::InvalidGrant(_) => (StatusCode::BAD_REQUEST, "invalid_grant"),
    //             OAuthError::UnsupportedGrantType(_) => {
    //                 (StatusCode::BAD_REQUEST, "unsupported_grant_type")
    //             }
    //             OAuthError::InvalidScope(_) => (StatusCode::BAD_REQUEST, "invalid_scope"),
    //             OAuthError::InvalidRequest(_) => (StatusCode::BAD_REQUEST, "invalid_request"),
    //             _ => (StatusCode::INTERNAL_SERVER_ERROR, "server_error"),
    //         };

    //         let error_response = json!({
    //             "error": error_code,
    //             "error_description": e.to_string()
    //         });
    //         Err((status, Json(error_response)))
    //     } // _ => {
    //       //     let error_response = json!({
    //       //         "error": "server_error",
    //       //         "error_description": "server_error"
    //       //     });
    //       //     Err((StatusCode::INTERNAL_SERVER_ERROR, Json(error_response)))
    //       // }
    // }
}

// /// Generate ID token with all required claims
// async fn generate_id_token_with_claims(
//     state: &AppState,
//     request: &crate::oauth::types::TokenRequest,
//     response: &crate::oauth::types::TokenResponse,
//     session_id :&str,
//     signing_key: &atproto_identity::key::KeyData,
// ) -> Result<String, crate::errors::OAuthError> {
//     use chrono::Utc;

//     // // Get the authorization code details to extract session info
//     // let (user_id, client_id, code_value, auth_time) = if let Some(code) = &request.code {
//     //     // Get the authorization code from storage
//     //     match state.oauth_storage.consume_code(code).await {
//     //         Ok(Some(auth_code)) => {
//     //             let user_id = auth_code.user_id.clone();
//     //             let client_id = auth_code.client_id.clone();
//     //             let auth_time = auth_code.created_at;
//     //             (user_id, client_id, Some(code.clone()), auth_time)
//     //         }
//     //         _ => {
//     //             // Fallback values if we can't find the auth code
//     //             let user_id = "unknown_user".to_string();
//     //             let client_id = request
//     //                 .client_id
//     //                 .clone()
//     //                 .unwrap_or_else(|| "unknown_client".to_string());
//     //             let auth_time = Utc::now();
//     //             (user_id, client_id, None, auth_time)
//     //         }
//     //     }
//     // } else {
//     //     // For refresh token grants, extract from the refresh token
//     //     let user_id = "unknown_user".to_string();
//     //     let client_id = request
//     //         .client_id
//     //         .clone()
//     //         .unwrap_or_else(|| "unknown_client".to_string());
//     //     let auth_time = Utc::now();
//     //     (user_id, client_id, None, auth_time)
//     // };

//     let client_id = request.client_id.unwrap_or_default();

//     // Create OpenID claims for the ID token
//     let mut claims = OpenIDClaims::new_id_token(
//         state.config.external_base.clone(),
//         user_id.clone(),
//         client_id,
//         auth_time,
//     );

//     // Set the access token hash
//     claims = claims.with_at_hash(&response.access_token);

//     // Set the code hash if we have the authorization code
//     if let Some(code) = &code_value {
//         claims = claims.with_c_hash(code);
//     }

//     // Parse the scopes from the token response
//     let scopes = if let Some(ref scope_str) = response.scope {
//         parse_scope(scope_str)
//     } else {
//         std::collections::HashSet::new()
//     };

//     // Try to enhance claims with document information
//     claims = build_openid_claims_with_document_info(
//         state,
//         claims.clone(),
//         &user_id,
//         &scopes,
//         Some(session_id),
//     )
//     .await
//     .unwrap_or(claims); // Fall back to original claims if enhancement fails

//     // TODO: Extract nonce from the original authorization request if present
//     // This would require storing the nonce with the authorization code

//     // // Convert OpenIDClaims to atproto_oauth::jwt::Claims
//     // let jose_claims = atproto_oauth::jwt::JoseClaims {
//     //     issuer: claims.iss.clone(),
//     //     subject: Some(claims.sub.clone()),
//     //     audience: claims.aud.clone(),
//     //     expiration: claims.exp.map(|e| e as u64),
//     //     issued_at: claims.iat.map(|i| i as u64),
//     //     nonce: claims.nonce.clone(),
//     //     ..Default::default()
//     // };

//     // // Convert additional claims to private claims
//     // let mut private_claims = std::collections::BTreeMap::new();
//     // if let Some(auth_time) = claims.auth_time {
//     //     private_claims.insert("auth_time".to_string(), serde_json::Value::Number(auth_time.into()));
//     // }
//     // if let Some(at_hash) = &claims.at_hash {
//     //     private_claims.insert("at_hash".to_string(), serde_json::Value::String(at_hash.clone()));
//     // }
//     // if let Some(c_hash) = &claims.c_hash {
//     //     private_claims.insert("c_hash".to_string(), serde_json::Value::String(c_hash.clone()));
//     // }
//     // if let Some(did) = &claims.did {
//     //     private_claims.insert("did".to_string(), serde_json::Value::String(did.clone()));
//     // }
//     // if let Some(name) = &claims.name {
//     //     private_claims.insert("name".to_string(), serde_json::Value::String(name.clone()));
//     // }
//     // if let Some(profile) = &claims.profile {
//     //     private_claims.insert("profile".to_string(), serde_json::Value::String(profile.clone()));
//     // }
//     // if let Some(pds_endpoint) = &claims.pds_endpoint {
//     //     private_claims.insert("pds_endpoint".to_string(), serde_json::Value::String(pds_endpoint.clone()));
//     // }
//     // if let Some(email) = &claims.email {
//     //     private_claims.insert("email".to_string(), serde_json::Value::String(email.clone()));
//     // }
//     // // Add any additional claims from the original OpenIDClaims
//     // for (key, value) in &claims.additional_claims {
//     //     private_claims.insert(key.clone(), value.clone());
//     // }

//     let jwt_claims = atproto_oauth::jwt::Claims {
//         jose: jose_claims,
//         private: private_claims,
//     };

//     // Create JWT header from the signing key
//     let header = atproto_oauth::jwt::Header::try_from(signing_key.clone())
//         .map_err(|e| OAuthError::InvalidRequest(format!("Failed to create JWT header: {}", e)))?;

//     // Generate the JWT using atproto_oauth::jwt::mint
//     atproto_oauth::jwt::mint(signing_key, &header, &jwt_claims)
//         .map_err(|e| OAuthError::InvalidRequest(format!("Failed to mint JWT: {}", e)))
// }

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
        });

        let atp_session_storage =
            Arc::new(crate::oauth::atprotocol_bridge::MemoryAtpOAuthSessionStorage::new());
        let authorization_request_storage =
            Arc::new(crate::oauth::atprotocol_bridge::MemoryAuthorizationRequestStorage::new());
        let client_registration_service = Arc::new(crate::oauth::ClientRegistrationService::new(
            oauth_storage.clone(),
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

    #[tokio::test]
    async fn test_token_form_validation() {
        // Test that token request forms can be created properly
        // This is a placeholder test since we don't expose the TokenForm directly
        let app_state = create_test_app_state();
        assert!(!app_state.config.external_base.is_empty());
    }
}
