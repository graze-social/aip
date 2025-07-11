//! Handles POST /oauth/par - Pushed Authorization Request endpoint per RFC 9126

use axum::{
    Form,
    extract::State,
    http::{HeaderMap, StatusCode},
    response::Json,
};
use base64::Engine;
use chrono::{Duration, Utc};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::sync::Arc;
use ulid::Ulid;

use super::context::AppState;
use super::utils_oauth::normalize_login_hint;
use crate::errors::OAuthError;
use crate::oauth::{
    auth_server::{AuthorizationServer, ClientAuthentication},
    types::*,
};

/// PAR request parameters
#[derive(Deserialize)]
pub(super) struct PushedAuthorizationRequest {
    pub response_type: String,
    pub client_id: String,
    pub redirect_uri: String,
    pub scope: Option<String>,
    pub state: Option<String>,
    pub code_challenge: Option<String>,
    pub code_challenge_method: Option<String>,
    pub request: Option<String>,
    pub request_uri: Option<String>,
    pub login_hint: Option<String>,
    pub nonce: Option<String>,

    // ATProtocol-specific parameter (legacy, prefer login_hint)
    pub subject: Option<String>,
}

/// PAR response
#[derive(Debug, Serialize)]
pub(super) struct PushedAuthorizationResponse {
    pub request_uri: String,
    pub expires_in: u64,
}

/// OAuth 2.0 Pushed Authorization Request endpoint handler
/// POST /oauth/par
///
/// Processes pushed authorization requests and returns a request URI for use in authorization flow.
pub async fn pushed_authorization_request_handler(
    State(state): State<AppState>,
    headers: HeaderMap,
    Form(request): Form<PushedAuthorizationRequest>,
) -> Result<Json<PushedAuthorizationResponse>, (StatusCode, Json<Value>)> {
    // Create authorization server from AppState
    let auth_server = Arc::new(AuthorizationServer::new(
        state.oauth_storage.clone(),
        state.config.external_base.clone(),
    ));
    // Validate client authentication
    let client_auth = extract_client_auth_from_headers(&headers);
    let client_id = client_auth
        .as_ref()
        .map(|auth| auth.client_id.as_str())
        .unwrap_or(&request.client_id);

    // Get and validate client
    let client = match auth_server.storage.get_client(client_id).await {
        Ok(Some(client)) => client,
        Ok(None) => {
            let error_response = json!({
                "error": "invalid_client",
                "error_description": "Client not found"
            });
            return Err((StatusCode::UNAUTHORIZED, Json(error_response)));
        }
        Err(e) => {
            let error_response = json!({
                "error": "server_error",
                "error_description": format!("Storage error: {:?}", e)
            });
            return Err((StatusCode::INTERNAL_SERVER_ERROR, Json(error_response)));
        }
    };

    // Authenticate client if credentials provided
    if let Some(auth) = client_auth {
        if let Err(e) = authenticate_client(&client, &auth) {
            let error_response = json!({
                "error": "invalid_client",
                "error_description": e.to_string()
            });
            return Err((StatusCode::UNAUTHORIZED, Json(error_response)));
        }
    }

    // Validate authorization request parameters
    let auth_request = match validate_and_convert_par_request(&request, &client, &state.config) {
        Ok(req) => req,
        Err(e) => {
            let (status, error_code) = match e {
                OAuthError::InvalidRequest(_) => (StatusCode::BAD_REQUEST, "invalid_request"),
                OAuthError::InvalidClient(_) => (StatusCode::BAD_REQUEST, "invalid_client"),
                OAuthError::InvalidScope(_) => (StatusCode::BAD_REQUEST, "invalid_scope"),
                OAuthError::UnsupportedResponseType(_) => {
                    (StatusCode::BAD_REQUEST, "unsupported_response_type")
                }
                _ => (StatusCode::INTERNAL_SERVER_ERROR, "server_error"),
            };

            let error_response = json!({
                "error": error_code,
                "error_description": e.to_string()
            });
            return Err((status, Json(error_response)));
        }
    };

    // Generate request URI
    let request_uri = format!("urn:ietf:params:oauth:request_uri:{}", Ulid::new());
    let expires_in = 600; // 10 minutes as per RFC recommendation
    let now = Utc::now();

    // Store the pushed request
    let stored_request = crate::storage::traits::StoredPushedRequest {
        request_uri: request_uri.clone(),
        authorization_request: auth_request.clone(),
        client_id: client.client_id,
        created_at: now,
        expires_at: now + Duration::seconds(expires_in as i64),
        subject: auth_request.login_hint, // Use login_hint instead of legacy subject
    };

    // Store in the authorization server's storage using the new PAR storage trait
    if let Err(e) = auth_server.storage.store_par_request(&stored_request).await {
        let error_response = json!({
            "error": "server_error",
            "error_description": format!("Failed to store pushed request: {:?}", e)
        });
        return Err((StatusCode::INTERNAL_SERVER_ERROR, Json(error_response)));
    }

    let response = PushedAuthorizationResponse {
        request_uri,
        expires_in: expires_in as u64,
    };

    Ok(Json(response))
}

/// Validate and convert PAR request to authorization request
fn validate_and_convert_par_request(
    request: &PushedAuthorizationRequest,
    client: &OAuthClient,
    config: &crate::config::Config,
) -> Result<AuthorizationRequest, OAuthError> {
    // Validate response type - parse space-separated response types
    let response_types = match crate::oauth::types::parse_response_type(&request.response_type) {
        Ok(types) => types,
        Err(e) => {
            return Err(OAuthError::UnsupportedResponseType(format!(
                "Invalid response type: {}",
                e
            )));
        }
    };

    // Check if any requested response type is supported by client
    let has_supported_response_type = response_types
        .iter()
        .any(|rt| client.response_types.contains(rt));
    if !has_supported_response_type {
        return Err(OAuthError::UnsupportedResponseType(
            "Response type not allowed for this client".to_string(),
        ));
    }

    // Validate redirect URI
    let redirect_uri_valid = if client.require_redirect_exact {
        // Exact matching
        client.redirect_uris.contains(&request.redirect_uri)
    } else {
        // Prefix matching
        client
            .redirect_uris
            .iter()
            .any(|registered_uri| request.redirect_uri.starts_with(registered_uri))
    };

    if !redirect_uri_valid {
        return Err(OAuthError::InvalidRequest(
            "Invalid redirect URI".to_string(),
        ));
    }

    // Validate scope
    if let Some(ref requested_scope) = request.scope {
        let requested_scopes = crate::oauth::types::parse_scope(requested_scope);
        let supported_scopes =
            crate::oauth::types::parse_scope(&config.oauth_supported_scopes.as_ref().join(" "));

        // First, validate against server's supported scopes
        if !requested_scopes.is_subset(&supported_scopes) {
            return Err(OAuthError::InvalidScope(
                "One or more requested scopes are not supported by this server".to_string(),
            ));
        }

        // Then, validate against client's allowed scopes
        if let Some(ref client_scope) = client.scope {
            let allowed_scopes = crate::oauth::types::parse_scope(client_scope);

            if !requested_scopes.is_subset(&allowed_scopes) {
                return Err(OAuthError::InvalidScope(
                    "Requested scope exceeds allowed scope".to_string(),
                ));
            }
        }
    }

    // TODO: Validate request/request_uri if provided (RFC 9101)
    if request.request.is_some() || request.request_uri.is_some() {
        return Err(OAuthError::InvalidRequest(
            "Request objects not yet supported".to_string(),
        ));
    }

    // Normalize login_hint if present and not empty
    let normalized_login_hint = if let Some(ref hint) = request.login_hint {
        if !hint.trim().is_empty() {
            Some(normalize_login_hint(hint)?)
        } else {
            request.subject.clone()
        }
    } else {
        request.subject.clone()
    };

    Ok(AuthorizationRequest {
        response_type: response_types,
        client_id: request.client_id.clone(),
        redirect_uri: request.redirect_uri.clone(),
        scope: request.scope.clone(),
        state: request.state.clone(),
        code_challenge: request.code_challenge.clone(),
        code_challenge_method: request.code_challenge_method.clone(),
        login_hint: normalized_login_hint,
        nonce: request.nonce.clone(),
    })
}

/// Extract client authentication from Authorization header
fn extract_client_auth_from_headers(headers: &HeaderMap) -> Option<ClientAuthentication> {
    if let Some(auth_header) = headers.get("Authorization") {
        if let Ok(auth_str) = auth_header.to_str() {
            if let Some(encoded) = auth_str.strip_prefix("Basic ") {
                if let Ok(decoded) = base64::prelude::BASE64_STANDARD.decode(encoded) {
                    if let Ok(credentials) = String::from_utf8(decoded) {
                        let parts: Vec<&str> = credentials.splitn(2, ':').collect();
                        if parts.len() == 2 {
                            return Some(ClientAuthentication {
                                client_id: parts[0].to_string(),
                                client_secret: Some(parts[1].to_string()),
                            });
                        }
                    }
                }
            }
        }
    }
    None
}

/// Authenticate client using provided authentication
fn authenticate_client(
    client: &OAuthClient,
    client_auth: &ClientAuthentication,
) -> Result<(), OAuthError> {
    match &client.token_endpoint_auth_method {
        ClientAuthMethod::None => Ok(()),
        ClientAuthMethod::ClientSecretBasic | ClientAuthMethod::ClientSecretPost => {
            let provided_secret = client_auth
                .client_secret
                .as_ref()
                .ok_or_else(|| OAuthError::InvalidClient("Missing client secret".to_string()))?;

            let expected_secret = client.client_secret.as_ref().ok_or_else(|| {
                OAuthError::InvalidClient("Client has no secret configured".to_string())
            })?;

            if provided_secret != expected_secret {
                return Err(OAuthError::InvalidClient(
                    "Invalid client secret".to_string(),
                ));
            }

            Ok(())
        }
        ClientAuthMethod::PrivateKeyJwt => Err(OAuthError::UnsupportedGrantType(
            "private_key_jwt not implemented for PAR".to_string(),
        )),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::storage::inmemory::MemoryOAuthStorage;
    use chrono::Utc;

    fn create_test_auth_server() -> Arc<AuthorizationServer> {
        let storage = Arc::new(MemoryOAuthStorage::new());
        Arc::new(AuthorizationServer::new(
            storage,
            "https://localhost".to_string(),
        ))
    }

    async fn create_test_client(auth_server: &Arc<AuthorizationServer>) -> OAuthClient {
        let client = OAuthClient {
            client_id: "test-client".to_string(),
            client_secret: Some("test-secret".to_string()),
            client_name: Some("Test Client".to_string()),
            redirect_uris: vec!["https://example.com/callback".to_string()],
            grant_types: vec![GrantType::AuthorizationCode],
            response_types: vec![ResponseType::Code],
            scope: Some("read write atproto".to_string()),
            token_endpoint_auth_method: ClientAuthMethod::ClientSecretBasic,
            client_type: ClientType::Confidential,
            created_at: Utc::now(),
            updated_at: Utc::now(),
            metadata: serde_json::Value::Null,
            access_token_expiration: chrono::Duration::days(1),
            refresh_token_expiration: chrono::Duration::days(14),
            require_redirect_exact: true,
            registration_access_token: Some("test-registration-token".to_string()),
        };

        auth_server.storage.store_client(&client).await.unwrap();
        client
    }

    #[tokio::test]
    async fn test_par_request_validation() {
        let auth_server = create_test_auth_server();
        let client = create_test_client(&auth_server).await;

        let par_request = PushedAuthorizationRequest {
            response_type: "code".to_string(),
            client_id: client.client_id.clone(),
            redirect_uri: "https://example.com/callback".to_string(),
            scope: Some("read".to_string()),
            state: Some("test-state".to_string()),
            code_challenge: Some("test-challenge".to_string()),
            code_challenge_method: Some("S256".to_string()),
            request: None,
            request_uri: None,
            login_hint: None,
            nonce: None,
            subject: Some("alice.bsky.social".to_string()),
        };

        let test_config = crate::config::Config {
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
        };

        let auth_request =
            validate_and_convert_par_request(&par_request, &client, &test_config).unwrap();

        assert_eq!(auth_request.response_type, vec![ResponseType::Code]);
        assert_eq!(auth_request.client_id, client.client_id);
        assert_eq!(auth_request.scope, Some("read".to_string()));
        assert_eq!(auth_request.state, Some("test-state".to_string()));
    }

    #[test]
    fn test_par_request_invalid_redirect_uri() {
        let client = OAuthClient {
            client_id: "test-client".to_string(),
            client_secret: Some("test-secret".to_string()),
            client_name: Some("Test Client".to_string()),
            redirect_uris: vec!["https://example.com/callback".to_string()],
            grant_types: vec![GrantType::AuthorizationCode],
            response_types: vec![ResponseType::Code],
            scope: Some("read write".to_string()),
            token_endpoint_auth_method: ClientAuthMethod::ClientSecretBasic,
            client_type: ClientType::Confidential,
            created_at: Utc::now(),
            updated_at: Utc::now(),
            metadata: serde_json::Value::Null,
            access_token_expiration: chrono::Duration::days(1),
            refresh_token_expiration: chrono::Duration::days(14),
            require_redirect_exact: true,
            registration_access_token: Some("test-registration-token".to_string()),
        };

        let par_request = PushedAuthorizationRequest {
            response_type: "code".to_string(),
            client_id: client.client_id.clone(),
            redirect_uri: "https://evil.com/callback".to_string(), // Invalid redirect URI
            scope: Some("read".to_string()),
            state: Some("test-state".to_string()),
            code_challenge: None,
            code_challenge_method: None,
            request: None,
            request_uri: None,
            login_hint: None,
            nonce: None,
            subject: None,
        };

        let test_config = crate::config::Config {
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
                "read write".to_string(),
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
        };

        let result = validate_and_convert_par_request(&par_request, &client, &test_config);
        assert!(result.is_err());
        if let Err(error) = result {
            assert!(matches!(error, OAuthError::InvalidRequest(_)));
        }
    }

    #[test]
    fn test_par_request_invalid_scope() {
        let client = OAuthClient {
            client_id: "test-client".to_string(),
            client_secret: Some("test-secret".to_string()),
            client_name: Some("Test Client".to_string()),
            redirect_uris: vec!["https://example.com/callback".to_string()],
            grant_types: vec![GrantType::AuthorizationCode],
            response_types: vec![ResponseType::Code],
            scope: Some("read".to_string()), // Only 'read' allowed
            token_endpoint_auth_method: ClientAuthMethod::ClientSecretBasic,
            client_type: ClientType::Confidential,
            created_at: Utc::now(),
            updated_at: Utc::now(),
            metadata: serde_json::Value::Null,
            access_token_expiration: chrono::Duration::days(1),
            refresh_token_expiration: chrono::Duration::days(14),
            require_redirect_exact: true,
            registration_access_token: Some("test-registration-token".to_string()),
        };

        let par_request = PushedAuthorizationRequest {
            response_type: "code".to_string(),
            client_id: client.client_id.clone(),
            redirect_uri: "https://example.com/callback".to_string(),
            scope: Some("read write admin".to_string()), // Requesting more than allowed
            state: Some("test-state".to_string()),
            code_challenge: None,
            code_challenge_method: None,
            request: None,
            request_uri: None,
            login_hint: None,
            nonce: None,
            subject: None,
        };

        let test_config = crate::config::Config {
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
                "read write admin".to_string(),
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
        };

        let result = validate_and_convert_par_request(&par_request, &client, &test_config);
        assert!(result.is_err());
        if let Err(error) = result {
            assert!(matches!(error, OAuthError::InvalidScope(_)));
        }
    }

    #[test]
    fn test_client_authentication_basic_auth() {
        let mut headers = HeaderMap::new();
        let credentials = base64::prelude::BASE64_STANDARD.encode("test-client:test-secret");
        headers.insert(
            "Authorization",
            format!("Basic {}", credentials).parse().unwrap(),
        );

        let auth = extract_client_auth_from_headers(&headers).unwrap();
        assert_eq!(auth.client_id, "test-client");
        assert_eq!(auth.client_secret, Some("test-secret".to_string()));
    }

    #[test]
    fn test_client_authentication_no_auth() {
        let headers = HeaderMap::new();
        let auth = extract_client_auth_from_headers(&headers);
        assert!(auth.is_none());
    }

    #[test]
    fn test_request_uri_format() {
        let request_uri = format!("urn:ietf:params:oauth:request_uri:{}", Ulid::new());
        assert!(request_uri.starts_with("urn:ietf:params:oauth:request_uri:"));
        assert!(request_uri.len() > 40); // ULID is 26 characters, plus prefix
    }

    #[test]
    fn test_par_response_structure() {
        let response = PushedAuthorizationResponse {
            request_uri: "urn:ietf:params:oauth:request_uri:test123".to_string(),
            expires_in: 600,
        };

        assert_eq!(response.expires_in, 600);
        assert!(
            response
                .request_uri
                .contains("urn:ietf:params:oauth:request_uri:")
        );
    }
}
