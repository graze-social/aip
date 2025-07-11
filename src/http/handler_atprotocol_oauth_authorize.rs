//! Handles GET /oauth/authorize - ATProtocol-backed OAuth authorization endpoint that redirects to ATProtocol OAuth or shows login form

use axum::{
    Json,
    extract::{Query, State},
    http::StatusCode,
    response::{Html, IntoResponse, Redirect, Response},
};
use axum_template::TemplateEngine;
use chrono::Utc;
use serde_json::{Value, json};
use std::sync::Arc;

use super::context::AppState;
use super::utils_oauth::normalize_login_hint;
use crate::oauth::{
    auth_server::AuthorizeQuery, types::AuthorizationRequest,
    utils_atprotocol_oauth::create_atp_backed_server,
};

/// Handle ATProtocol-backed OAuth authorization requests
/// GET /oauth/authorize - Redirects to ATProtocol OAuth for authentication or shows login form
pub async fn handle_oauth_authorize(
    State(state): State<AppState>,
    Query(query): Query<AuthorizeQuery>,
) -> std::result::Result<Response, (StatusCode, Json<Value>)> {
    // Validate and process authorization request
    let (request, original_query) =
        match process_authorization_query(query, &state.oauth_storage, &state.config).await {
            Ok(req) => req,
            Err(error_response) => {
                return Err((StatusCode::BAD_REQUEST, Json(error_response)));
            }
        };

    let login_hint = {
        if let Some(value) = request
            .login_hint
            .as_ref()
            .filter(|value| !value.trim().is_empty())
            .cloned()
        {
            Some(value.clone())
        } else {
            original_query
                .login_hint
                .as_ref()
                .filter(|value| !value.trim().is_empty())
                .cloned()
        }
    };

    // Check if login_hint is missing - if so, render login form
    if login_hint.is_none() {
        return render_login_form(state, &original_query, &request).await;
    }

    // Create ATProtocol-backed authorization server
    let atp_auth_server = create_atp_backed_server(&state).await.map_err(|e| {
        let error_response = json!({
            "error": "server_error",
            "error_description": format!("Failed to create ATProtocol authorization server: {}", e)
        });
        (StatusCode::INTERNAL_SERVER_ERROR, Json(error_response))
    })?;

    match atp_auth_server
        .authorize_with_atprotocol(request, login_hint.unwrap())
        .await
    {
        Ok(redirect_url) => Ok(Redirect::to(&redirect_url).into_response()),
        Err(e) => {
            let error_response = json!({
                "error": "server_error",
                "error_description": e.to_string()
            });
            Err((StatusCode::INTERNAL_SERVER_ERROR, Json(error_response)))
        }
    }
}

/// Process authorization query parameters, handling both PAR and traditional OAuth
async fn process_authorization_query(
    query: AuthorizeQuery,
    storage: &Arc<dyn crate::storage::traits::OAuthStorage + Send + Sync>,
    config: &crate::config::Config,
) -> Result<(AuthorizationRequest, AuthorizeQuery), Value> {
    // Handle PAR request (request_uri present)
    if let Some(request_uri) = &query.request_uri {
        // Retrieve PAR request from storage
        match storage.get_par_request(request_uri).await {
            Ok(Some(stored_request)) => {
                // Check if PAR request has expired
                if stored_request.expires_at < Utc::now() {
                    return Err(json!({
                        "error": "invalid_request",
                        "error_description": "PAR request has expired"
                    }));
                }

                // Validate that client_id matches if provided in query
                if !query.client_id.is_empty() && query.client_id != stored_request.client_id {
                    return Err(json!({
                        "error": "invalid_client",
                        "error_description": "client_id does not match PAR request"
                    }));
                }

                // Return the authorization request from the stored PAR request
                return Ok((stored_request.authorization_request, query));
            }
            Ok(None) => {
                return Err(json!({
                    "error": "invalid_request",
                    "error_description": "Invalid or expired request_uri"
                }));
            }
            Err(e) => {
                return Err(json!({
                    "error": "server_error",
                    "error_description": format!("Failed to retrieve PAR request: {:?}", e)
                }));
            }
        }
    }

    // Handle traditional OAuth request
    // Validate required parameters for traditional OAuth
    if query.client_id.is_empty() {
        return Err(json!({
            "error": "invalid_request",
            "error_description": "Missing required parameter: client_id"
        }));
    }

    let redirect_uri = match &query.redirect_uri {
        Some(uri) if !uri.is_empty() => uri.clone(),
        _ => {
            return Err(json!({
                "error": "invalid_request",
                "error_description": "Missing required parameter: redirect_uri"
            }));
        }
    };

    // Use default response_type if not provided
    let response_type = query
        .response_type
        .clone()
        .unwrap_or_else(|| "code".to_string());
    if response_type != "code" {
        return Err(json!({
            "error": "unsupported_response_type",
            "error_description": format!("Unsupported response_type: {}. Only 'code' is supported.", response_type)
        }));
    }

    // Normalize login_hint if present and not empty
    let normalized_login_hint = if let Some(ref hint) = query.login_hint {
        if !hint.trim().is_empty() {
            match normalize_login_hint(hint) {
                Ok(normalized) => Some(normalized),
                Err(e) => {
                    return Err(json!({
                        "error": "invalid_request",
                        "error_description": e.to_string()
                    }));
                }
            }
        } else {
            None
        }
    } else {
        None
    };

    let request = AuthorizationRequest {
        response_type: vec![crate::oauth::types::ResponseType::Code],
        client_id: query.client_id.clone(),
        redirect_uri,
        scope: query.scope.clone(),
        state: query.state.clone(),
        code_challenge: query.code_challenge.clone(),
        code_challenge_method: query.code_challenge_method.clone(),
        login_hint: normalized_login_hint,
        nonce: query.nonce.clone(),
    };

    // Validate scope against server's supported scopes for traditional OAuth requests
    if let Some(ref requested_scope) = request.scope {
        let requested_scopes = crate::oauth::types::parse_scope(requested_scope);
        let supported_scopes =
            crate::oauth::types::parse_scope(&config.oauth_supported_scopes.as_ref().join(" "));

        if !requested_scopes.is_subset(&supported_scopes) {
            return Err(serde_json::json!({
                "error": "invalid_scope",
                "error_description": "One or more requested scopes are not supported by this server"
            }));
        }
    }

    Ok((request, query))
}

/// Render the login form when no login_hint is provided
async fn render_login_form(
    state: AppState,
    query: &AuthorizeQuery,
    request: &AuthorizationRequest,
) -> std::result::Result<Response, (StatusCode, Json<Value>)> {
    use std::collections::HashMap;

    let mut query_params = HashMap::new();

    // Preserve all query parameters except login_hint
    query_params.insert("client_id".to_string(), query.client_id.clone());
    if let Some(ref redirect_uri) = query.redirect_uri {
        query_params.insert("redirect_uri".to_string(), redirect_uri.clone());
    }
    if let Some(ref response_type) = query.response_type {
        query_params.insert("response_type".to_string(), response_type.clone());
    }
    if let Some(ref scope) = query.scope {
        query_params.insert("scope".to_string(), scope.clone());
    }
    if let Some(ref state) = query.state {
        query_params.insert("state".to_string(), state.clone());
    }
    if let Some(ref code_challenge) = query.code_challenge {
        query_params.insert("code_challenge".to_string(), code_challenge.clone());
    }
    if let Some(ref code_challenge_method) = query.code_challenge_method {
        query_params.insert(
            "code_challenge_method".to_string(),
            code_challenge_method.clone(),
        );
    }
    if let Some(ref request_uri) = query.request_uri {
        query_params.insert("request_uri".to_string(), request_uri.clone());
    }
    if let Some(ref nonce) = query.nonce {
        query_params.insert("nonce".to_string(), nonce.clone());
    }

    let template_data = json!({
        "title": "AIP - ATProtocol Identity Provider",
        "version": state.config.version,
        "query_params": query_params,
        "client_name": query.client_id, // TODO: Look up actual client name from storage
        "scope": request.scope,
        "redirect_uri": request.redirect_uri,
    });

    match state.template_env.render("login.html", &template_data) {
        Ok(html) => Ok(Html(html).into_response()),
        Err(e) => {
            let error_response = json!({
                "error": "server_error",
                "error_description": format!("Template rendering failed: {}", e)
            });
            Err((StatusCode::INTERNAL_SERVER_ERROR, Json(error_response)))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::oauth::auth_server::AuthorizeQuery;

    fn create_test_config() -> crate::config::Config {
        crate::config::Config {
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
        }
    }

    #[tokio::test]
    async fn test_authorize_query_validation() {
        let storage = Arc::new(crate::storage::inmemory::MemoryOAuthStorage::new());

        // Test valid authorize query
        let query = AuthorizeQuery {
            client_id: "test-client".to_string(),
            redirect_uri: Some("https://example.com/callback".to_string()),
            response_type: Some("code".to_string()),
            scope: Some("read write".to_string()),
            state: Some("test-state".to_string()),
            code_challenge: None,
            code_challenge_method: None,
            request_uri: None,
            login_hint: None,
            nonce: None,
        };

        let config = create_test_config();
        let (request, _) = process_authorization_query(
            query,
            &(storage as Arc<dyn crate::storage::traits::OAuthStorage + Send + Sync>),
            &config,
        )
        .await
        .unwrap();
        assert_eq!(request.client_id, "test-client");
        assert_eq!(request.redirect_uri, "https://example.com/callback");
        assert_eq!(
            request.response_type,
            vec![crate::oauth::types::ResponseType::Code]
        );
    }

    #[tokio::test]
    async fn test_authorize_query_with_pkce() {
        let storage = Arc::new(crate::storage::inmemory::MemoryOAuthStorage::new());

        // Test authorize query with PKCE parameters
        let query = AuthorizeQuery {
            client_id: "test-client".to_string(),
            redirect_uri: Some("https://example.com/callback".to_string()),
            response_type: Some("code".to_string()),
            scope: Some("read".to_string()),
            state: Some("test-state".to_string()),
            code_challenge: Some("test-challenge".to_string()),
            code_challenge_method: Some("S256".to_string()),
            request_uri: None,
            login_hint: None,
            nonce: None,
        };

        let config = create_test_config();
        let (request, _) = process_authorization_query(
            query,
            &(storage as Arc<dyn crate::storage::traits::OAuthStorage + Send + Sync>),
            &config,
        )
        .await
        .unwrap();
        assert_eq!(request.client_id, "test-client");
        assert_eq!(request.code_challenge, Some("test-challenge".to_string()));
        assert_eq!(request.code_challenge_method, Some("S256".to_string()));
    }

    #[tokio::test]
    async fn test_authorize_query_minimal() {
        let storage = Arc::new(crate::storage::inmemory::MemoryOAuthStorage::new());

        // Test minimal required parameters
        let query = AuthorizeQuery {
            client_id: "minimal-client".to_string(),
            redirect_uri: Some("https://minimal.example.com/callback".to_string()),
            response_type: None, // Should default to "code"
            scope: None,
            state: None,
            code_challenge: None,
            code_challenge_method: None,
            request_uri: None,
            login_hint: None,
            nonce: None,
        };

        let config = create_test_config();
        let (request, _) = process_authorization_query(
            query,
            &(storage as Arc<dyn crate::storage::traits::OAuthStorage + Send + Sync>),
            &config,
        )
        .await
        .unwrap();
        assert_eq!(request.client_id, "minimal-client");
        assert_eq!(request.redirect_uri, "https://minimal.example.com/callback");
        assert_eq!(
            request.response_type,
            vec![crate::oauth::types::ResponseType::Code]
        );
        assert!(request.scope.is_none());
        assert!(request.state.is_none());
    }

    #[tokio::test]
    async fn test_authorize_query_par_invalid_request_uri() {
        let storage = Arc::new(crate::storage::inmemory::MemoryOAuthStorage::new());

        // Test PAR request with invalid request_uri
        let query = AuthorizeQuery {
            client_id: "test-client".to_string(),
            redirect_uri: None,
            response_type: None,
            scope: None,
            state: None,
            code_challenge: None,
            code_challenge_method: None,
            request_uri: Some("urn:ietf:params:oauth:request_uri:invalid123".to_string()),
            login_hint: None,
            nonce: None,
        };

        let config = create_test_config();
        let result = process_authorization_query(
            query,
            &(storage as Arc<dyn crate::storage::traits::OAuthStorage + Send + Sync>),
            &config,
        )
        .await;
        assert!(result.is_err());
        if let Err(error) = result {
            assert_eq!(error["error"], "invalid_request");
        }
    }

    #[tokio::test]
    async fn test_authorize_query_missing_client_id() {
        let storage = Arc::new(crate::storage::inmemory::MemoryOAuthStorage::new());

        // Test missing client_id
        let query = AuthorizeQuery {
            client_id: "".to_string(),
            redirect_uri: Some("https://example.com/callback".to_string()),
            response_type: Some("code".to_string()),
            scope: None,
            state: None,
            code_challenge: None,
            code_challenge_method: None,
            request_uri: None,
            login_hint: None,
            nonce: None,
        };

        let config = create_test_config();
        let result = process_authorization_query(
            query,
            &(storage as Arc<dyn crate::storage::traits::OAuthStorage + Send + Sync>),
            &config,
        )
        .await;
        assert!(result.is_err());
        if let Err(error) = result {
            assert_eq!(error["error"], "invalid_request");
        }
    }

    #[tokio::test]
    async fn test_authorize_query_missing_redirect_uri() {
        let storage = Arc::new(crate::storage::inmemory::MemoryOAuthStorage::new());

        // Test missing redirect_uri
        let query = AuthorizeQuery {
            client_id: "test-client".to_string(),
            redirect_uri: None,
            response_type: Some("code".to_string()),
            scope: None,
            state: None,
            code_challenge: None,
            code_challenge_method: None,
            request_uri: None,
            login_hint: None,
            nonce: None,
        };

        let config = create_test_config();
        let result = process_authorization_query(
            query,
            &(storage as Arc<dyn crate::storage::traits::OAuthStorage + Send + Sync>),
            &config,
        )
        .await;
        assert!(result.is_err());
        if let Err(error) = result {
            assert_eq!(error["error"], "invalid_request");
        }
    }
}
