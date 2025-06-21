//! OAuth 2.1 resource server implementation.
//!
//! Protects API endpoints with access token validation, including DPoP-bound tokens.

use crate::errors::OAuthError;
use crate::oauth::{dpop::*, types::*};
use crate::storage::traits::OAuthStorage;
use axum::extract::OriginalUri;
use axum::{
    extract::{Request, State},
    http::{HeaderMap, StatusCode},
    middleware::Next,
    response::Response,
};
use chrono::Utc;
use serde_json::{Value, json};
use std::{future::Future, pin::Pin, sync::Arc};

/// OAuth Resource Server for protecting APIs
pub struct ResourceServer {
    storage: Arc<dyn OAuthStorage>,
    dpop_validator: DPoPValidator,
    /// External base URL for constructing full URLs
    external_base: String,
    /// Whether to require DPoP for all tokens
    require_dpop: bool,
    /// Allowed scopes for different endpoints
    scope_requirements: std::collections::HashMap<String, Vec<String>>,
}

impl ResourceServer {
    /// Create a new resource server
    pub fn new(storage: Arc<dyn OAuthStorage>, external_base: String) -> Self {
        let nonce_store = Box::new(crate::storage::MemoryNonceStorage::new());
        let dpop_validator = DPoPValidator::new(nonce_store);

        Self {
            storage,
            dpop_validator,
            external_base,
            require_dpop: false,
            scope_requirements: std::collections::HashMap::new(),
        }
    }

    /// Enable DPoP requirement for all tokens
    pub fn require_dpop(mut self) -> Self {
        self.require_dpop = true;
        self
    }

    /// Add scope requirement for a specific path pattern
    pub fn require_scope<P: Into<String>, S: Into<String>>(
        mut self,
        path_pattern: P,
        scopes: Vec<S>,
    ) -> Self {
        let scopes: Vec<String> = scopes.into_iter().map(|s| s.into()).collect();
        self.scope_requirements.insert(path_pattern.into(), scopes);
        self
    }

    /// Validate an access token from a request
    pub async fn validate_token(
        &self,
        headers: &HeaderMap,
        http_method: &str,
        http_uri: &str,
        required_scopes: Option<&[String]>,
    ) -> Result<TokenValidationResult, OAuthError> {
        tracing::info!(
            ?http_method,
            ?http_uri,
            ?required_scopes,
            ?headers,
            "validate_token"
        );

        // Extract access token from Authorization header
        let (token, token_type) = self.extract_access_token(headers)?;

        // Retrieve token from storage
        let access_token = self
            .storage
            .get_token(&token)
            .await
            .map_err(|e| OAuthError::ServerError(format!("Storage error: {:?}", e)))?
            .ok_or_else(|| {
                OAuthError::InvalidGrant("Invalid or expired access token".to_string())
            })?;

        // Check if token is expired
        if access_token.expires_at < Utc::now() {
            return Err(OAuthError::InvalidGrant("Access token expired".to_string()));
        }

        // Validate DPoP if token is DPoP-bound or DPoP is required
        if access_token.token_type == TokenType::DPoP
            || (self.require_dpop && token_type == TokenType::DPoP)
        {
            self.validate_dpop_binding(&access_token, headers, http_method, http_uri, &token)
                .await?;
        }

        // Validate scopes
        if let Some(required_scopes) = required_scopes {
            self.validate_scopes(&access_token, required_scopes)?;
        }

        Ok(TokenValidationResult {
            client_id: access_token.client_id.clone(),
            user_id: access_token.user_id.clone(),
            scopes: access_token
                .scope
                .as_ref()
                .map(|s| parse_scope(s))
                .unwrap_or_default(),
            access_token,
        })
    }

    /// Extract access token from Authorization header
    fn extract_access_token(&self, headers: &HeaderMap) -> Result<(String, TokenType), OAuthError> {
        let auth_header = headers.get("Authorization").ok_or_else(|| {
            OAuthError::InvalidRequest("Missing Authorization header".to_string())
        })?;

        tracing::info!(?auth_header, "Authorization header");

        let auth_str = auth_header.to_str().map_err(|e| {
            OAuthError::InvalidRequest(format!("Invalid Authorization header: {}", e))
        })?;

        tracing::info!(?auth_str, "Authorization header value");

        if let Some(token) = auth_str.strip_prefix("Bearer ") {
            Ok((token.to_string(), TokenType::Bearer))
        } else if let Some(token) = auth_str.strip_prefix("DPoP ") {
            Ok((token.to_string(), TokenType::DPoP))
        } else {
            Err(OAuthError::InvalidRequest(
                "Invalid Authorization header format".to_string(),
            ))
        }
    }

    /// Validate DPoP binding
    async fn validate_dpop_binding(
        &self,
        access_token: &AccessToken,
        headers: &HeaderMap,
        http_method: &str,
        http_uri: &str,
        token: &str,
    ) -> Result<(), OAuthError> {
        // Get DPoP header
        let dpop_header = headers.get("DPoP").ok_or_else(|| {
            OAuthError::InvalidRequest("Missing DPoP header for DPoP-bound token".to_string())
        })?;

        tracing::info!(?dpop_header, "DPoP header");

        let dpop_str = dpop_header
            .to_str()
            .map_err(|e| OAuthError::InvalidRequest(format!("Invalid DPoP header: {}", e)))?;

        tracing::info!(?dpop_str, "DPoP header value");

        // Construct full URL for DPoP validation using external base
        let full_url = if http_uri.starts_with("http://") || http_uri.starts_with("https://") {
            // Already a full URL
            http_uri.to_string()
        } else {
            // Relative URL, construct full URL
            format!("{}{}", self.external_base.trim_end_matches('/'), http_uri)
        };

        // Validate DPoP proof
        let dpop_proof = self
            .dpop_validator
            .validate_proof(dpop_str, http_method, &full_url, Some(token))
            .await
            .map_err(|e| OAuthError::InvalidRequest(format!("DPoP validation failed: {:?}", e)))?;

        tracing::info!(?dpop_proof, "dpop_proof");

        // Verify JWK thumbprint matches the token binding
        if let Some(ref bound_jkt) = access_token.dpop_jkt {
            let proof_jkt = compute_jwk_thumbprint(&dpop_proof.header.jwk)
                .map_err(|e| OAuthError::ServerError(format!("JWK thumbprint error: {:?}", e)))?;

            if bound_jkt != &proof_jkt {
                return Err(OAuthError::InvalidRequest("DPoP key mismatch".to_string()));
            }
        }

        Ok(())
    }

    /// Validate that the token has required scopes
    fn validate_scopes(
        &self,
        access_token: &AccessToken,
        required_scopes: &[String],
    ) -> Result<(), OAuthError> {
        let token_scopes = if let Some(ref scope) = access_token.scope {
            parse_scope(scope)
        } else {
            std::collections::HashSet::new()
        };

        for required_scope in required_scopes {
            if !token_scopes.contains(required_scope) {
                return Err(OAuthError::InvalidScope(format!(
                    "Missing required scope: {}",
                    required_scope
                )));
            }
        }

        Ok(())
    }

    /// Get scope requirements for a path
    pub fn get_required_scopes(&self, path: &str) -> Option<&[String]> {
        // Simple exact match for now
        // In production, you might want pattern matching
        self.scope_requirements.get(path).map(|v| v.as_slice())
    }
}

/// Result of token validation
#[derive(Debug, Clone)]
pub struct TokenValidationResult {
    /// The validated access token
    pub access_token: AccessToken,
    /// Client ID that owns this token
    pub client_id: String,
    /// User ID associated with this token (if any)
    pub user_id: Option<String>,
    /// Scopes granted to this token
    pub scopes: std::collections::HashSet<String>,
}

/// OAuth middleware for Axum
pub async fn oauth_middleware(
    State(resource_server): State<Arc<ResourceServer>>,
    mut request: Request,
    next: Next,
) -> Result<Response, (StatusCode, axum::Json<Value>)> {
    tracing::info!("oauth_middleware");

    let headers = request.headers().clone();
    let method = request.method().to_string();

    let uri = if let Some(path) = request.extensions().get::<OriginalUri>() {
        path.0.path().to_owned()
    } else {
        request.uri().path().to_owned()
    };

    // let uri = request.uri().to_string();

    // Get required scopes for this path
    let required_scopes = resource_server.get_required_scopes(&uri);

    match resource_server
        .validate_token(&headers, &method, &uri, required_scopes)
        .await
    {
        Ok(validation_result) => {
            tracing::info!(?validation_result, "validation_result");
            // Add token info to request extensions for handlers to access
            request.extensions_mut().insert(validation_result);
            Ok(next.run(request).await)
        }
        Err(e) => {
            let (status, error_code) = match e {
                OAuthError::InvalidRequest(_) => (StatusCode::BAD_REQUEST, "invalid_request"),
                OAuthError::InvalidGrant(_) => (StatusCode::UNAUTHORIZED, "invalid_token"),
                OAuthError::InvalidScope(_) => (StatusCode::FORBIDDEN, "insufficient_scope"),
                _ => (StatusCode::INTERNAL_SERVER_ERROR, "server_error"),
            };

            let error_response = json!({
                "error": error_code,
                "error_description": e.to_string()
            });

            Err((status, axum::Json(error_response)))
        }
    }
}

/// Create OAuth middleware with scope requirements
#[allow(clippy::type_complexity)]
pub fn oauth_middleware_with_scopes(
    resource_server: Arc<ResourceServer>,
    required_scopes: Vec<String>,
) -> impl Fn(
    Request,
    Next,
) -> Pin<Box<dyn Future<Output = Result<Response, (StatusCode, axum::Json<Value>)>> + Send>>
+ Clone {
    move |request: Request, next: Next| {
        let resource_server = resource_server.clone();
        let required_scopes = required_scopes.clone();

        Box::pin(async move {
            let headers = request.headers().clone();
            let method = request.method().to_string();
            let uri = request.uri().to_string();

            match resource_server
                .validate_token(&headers, &method, &uri, Some(&required_scopes))
                .await
            {
                Ok(validation_result) => {
                    let mut request = request;
                    request.extensions_mut().insert(validation_result);
                    Ok(next.run(request).await)
                }
                Err(e) => {
                    let (status, error_code) = match e {
                        OAuthError::InvalidRequest(_) => {
                            (StatusCode::BAD_REQUEST, "invalid_request")
                        }
                        OAuthError::InvalidGrant(_) => (StatusCode::UNAUTHORIZED, "invalid_token"),
                        OAuthError::InvalidScope(_) => {
                            (StatusCode::FORBIDDEN, "insufficient_scope")
                        }
                        _ => (StatusCode::INTERNAL_SERVER_ERROR, "server_error"),
                    };

                    let error_response = json!({
                        "error": error_code,
                        "error_description": e.to_string()
                    });

                    Err((status, axum::Json(error_response)))
                }
            }
        })
    }
}

/// Token introspection endpoint (RFC 7662)
pub async fn introspect_token(
    State(resource_server): State<Arc<ResourceServer>>,
    _headers: HeaderMap,
    axum::Form(form): axum::Form<std::collections::HashMap<String, String>>,
) -> Result<axum::Json<Value>, (StatusCode, axum::Json<Value>)> {
    // Extract token from form
    let token = form.get("token").ok_or_else(|| {
        let error = json!({
            "error": "invalid_request",
            "error_description": "Missing token parameter"
        });
        (StatusCode::BAD_REQUEST, axum::Json(error))
    })?;

    // For introspection, we need to authenticate the client making the request
    // This is simplified - in production you'd validate client credentials

    match resource_server.storage.get_token(token).await {
        Ok(Some(access_token)) => {
            let now = Utc::now();
            let active = access_token.expires_at > now;

            let response = if active {
                json!({
                    "active": true,
                    "client_id": access_token.client_id,
                    "username": access_token.user_id,
                    "scope": access_token.scope,
                    "exp": access_token.expires_at.timestamp(),
                    "iat": access_token.created_at.timestamp(),
                    "token_type": access_token.token_type
                })
            } else {
                json!({ "active": false })
            };

            Ok(axum::Json(response))
        }
        Ok(None) => {
            // Token not found - return inactive
            Ok(axum::Json(json!({ "active": false })))
        }
        Err(e) => {
            let error = json!({
                "error": "server_error",
                "error_description": format!("Storage error: {:?}", e)
            });
            Err((StatusCode::INTERNAL_SERVER_ERROR, axum::Json(error)))
        }
    }
}

/// Token revocation endpoint (RFC 7009)
pub async fn revoke_token(
    State(resource_server): State<Arc<ResourceServer>>,
    _headers: HeaderMap,
    axum::Form(form): axum::Form<std::collections::HashMap<String, String>>,
) -> Result<StatusCode, (StatusCode, axum::Json<Value>)> {
    // Extract token from form
    let token = form.get("token").ok_or_else(|| {
        let error = json!({
            "error": "invalid_request",
            "error_description": "Missing token parameter"
        });
        (StatusCode::BAD_REQUEST, axum::Json(error))
    })?;

    // For revocation, we need to authenticate the client making the request
    // This is simplified - in production you'd validate client credentials

    match resource_server.storage.revoke_token(token).await {
        Ok(_) => Ok(StatusCode::OK),
        Err(e) => {
            let error = json!({
                "error": "server_error",
                "error_description": format!("Storage error: {:?}", e)
            });
            Err((StatusCode::INTERNAL_SERVER_ERROR, axum::Json(error)))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::storage::inmemory::MemoryOAuthStorage;
    use crate::storage::traits::AccessTokenStore;
    use chrono::Duration;

    #[tokio::test]
    async fn test_bearer_token_validation() {
        let storage = Arc::new(MemoryOAuthStorage::new());
        let resource_server = ResourceServer::new(storage.clone(), "https://localhost".to_string());

        // Create a test access token
        let now = Utc::now();
        let access_token = AccessToken {
            token: "test-token".to_string(),
            token_type: TokenType::Bearer,
            client_id: "test-client".to_string(),
            user_id: Some("test-user".to_string()),
            session_id: None,
            session_iteration: None,
            scope: Some("read write".to_string()),
            created_at: now,
            expires_at: now + Duration::hours(1),
            dpop_jkt: None,
        };

        storage.store_token(&access_token).await.unwrap();

        // Create headers with Bearer token
        let mut headers = HeaderMap::new();
        headers.insert("Authorization", "Bearer test-token".parse().unwrap());

        // Validate token
        let result = resource_server
            .validate_token(
                &headers,
                "GET",
                "/api/resource",
                Some(&["read".to_string()]),
            )
            .await
            .unwrap();

        assert_eq!(result.client_id, "test-client");
        assert_eq!(result.user_id, Some("test-user".to_string()));
        assert!(result.scopes.contains("read"));
        assert!(result.scopes.contains("write"));
    }

    #[tokio::test]
    async fn test_insufficient_scope() {
        let storage = Arc::new(MemoryOAuthStorage::new());
        let resource_server = ResourceServer::new(storage.clone(), "https://localhost".to_string());

        // Create a test access token with limited scope
        let now = Utc::now();
        let access_token = AccessToken {
            token: "test-token".to_string(),
            token_type: TokenType::Bearer,
            client_id: "test-client".to_string(),
            user_id: Some("test-user".to_string()),
            session_id: None,
            session_iteration: None,
            scope: Some("read".to_string()),
            created_at: now,
            expires_at: now + Duration::hours(1),
            dpop_jkt: None,
        };

        storage.store_token(&access_token).await.unwrap();

        // Create headers with Bearer token
        let mut headers = HeaderMap::new();
        headers.insert("Authorization", "Bearer test-token".parse().unwrap());

        // Try to validate token with insufficient scope
        let result = resource_server
            .validate_token(
                &headers,
                "POST",
                "/api/resource",
                Some(&["write".to_string()]),
            )
            .await;

        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), OAuthError::InvalidScope(_)));
    }

    #[tokio::test]
    async fn test_expired_token() {
        let storage = Arc::new(MemoryOAuthStorage::new());
        let resource_server = ResourceServer::new(storage.clone(), "https://localhost".to_string());

        // Create an expired access token
        let now = Utc::now();
        let access_token = AccessToken {
            token: "expired-token".to_string(),
            token_type: TokenType::Bearer,
            client_id: "test-client".to_string(),
            user_id: Some("test-user".to_string()),
            session_id: None,
            session_iteration: None,
            scope: Some("read".to_string()),
            created_at: now - Duration::hours(2),
            expires_at: now - Duration::hours(1), // Expired
            dpop_jkt: None,
        };

        storage.store_token(&access_token).await.unwrap();

        // Create headers with Bearer token
        let mut headers = HeaderMap::new();
        headers.insert("Authorization", "Bearer expired-token".parse().unwrap());

        // Try to validate expired token
        let result = resource_server
            .validate_token(&headers, "GET", "/api/resource", None)
            .await;

        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), OAuthError::InvalidGrant(_)));
    }
}
