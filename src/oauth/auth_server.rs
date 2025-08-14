//! Core OAuth 2.1 authorization server handling authorization, token, and PKCE flows.

use crate::errors::OAuthError;
use crate::oauth::{dpop::*, types::*};
use crate::storage::traits::OAuthStorage;
use axum::{
    Form,
    extract::{Query, State},
    http::{HeaderMap, StatusCode},
    response::{Json, Redirect},
};
use base64::{Engine, prelude::*};
use chrono::{Duration, Utc};
use serde::Deserialize;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::sync::Arc;
use url::Url;

/// OAuth 2.1 Authorization Server
pub struct AuthorizationServer {
    pub storage: Arc<dyn OAuthStorage>,
    dpop_validator: DPoPValidator,
    /// Authorization code lifetime
    auth_code_lifetime: Duration,
    /// Server issuer URL (external base)
    issuer: String,
    /// Whether PKCE is required for public clients
    require_pkce: bool,
}

impl AuthorizationServer {
    /// Create a new authorization server
    pub fn new(storage: Arc<dyn OAuthStorage>, issuer: String) -> Self {
        let nonce_store = Box::new(crate::storage::MemoryNonceStorage::new());
        let dpop_validator = DPoPValidator::new(nonce_store);

        Self {
            storage,
            dpop_validator,
            auth_code_lifetime: Duration::minutes(10),
            issuer,
            require_pkce: true,
        }
    }

    /// Handle authorization requests (RFC 6749 Section 4.1.1)
    pub async fn authorize(
        &self,
        request: AuthorizationRequest,
        user_id: String, // Assume user is already authenticated
        session_id: Option<String>,
    ) -> Result<AuthorizeResponse, OAuthError> {
        // Validate client
        let client = self
            .storage
            .get_client(&request.client_id)
            .await
            .map_err(|e| OAuthError::ServerError(format!("Storage error: {:?}", e)))?
            .ok_or_else(|| OAuthError::InvalidClient("Client not found".to_string()))?;

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

        // Validate response type - check if any requested response type is supported by client
        let has_supported_response_type = request
            .response_type
            .iter()
            .any(|rt| client.response_types.contains(rt));
        if !has_supported_response_type {
            return Err(OAuthError::UnsupportedResponseType(format!(
                "{:?}",
                request.response_type
            )));
        }

        // Validate scope
        if let Some(ref requested_scope) = request.scope {
            if let Some(ref client_scope) = client.scope {
                let requested_scopes = parse_scope(requested_scope);
                let allowed_scopes = parse_scope(client_scope);

                if !requested_scopes.is_subset(&allowed_scopes) {
                    return Err(OAuthError::InvalidScope(
                        "Requested scope exceeds allowed scope".to_string(),
                    ));
                }
            }
        }

        // For public clients, require PKCE
        if self.require_pkce
            && client.client_type == ClientType::Public
            && request.code_challenge.is_none()
        {
            return Err(OAuthError::InvalidRequest(
                "PKCE required for public clients".to_string(),
            ));
        }

        // Generate authorization code
        let code = generate_token();
        let now = Utc::now();

        let auth_code = AuthorizationCode {
            code: code.clone(),
            client_id: request.client_id,
            user_id,
            redirect_uri: request.redirect_uri.clone(),
            scope: request.scope,
            code_challenge: request.code_challenge,
            code_challenge_method: request.code_challenge_method,
            nonce: request.nonce,
            created_at: now,
            expires_at: now + self.auth_code_lifetime,
            used: false,
            session_id,
        };

        // Store the authorization code
        self.storage
            .store_code(&auth_code)
            .await
            .map_err(|e| OAuthError::ServerError(format!("Failed to store auth code: {:?}", e)))?;

        // Build redirect URL
        let mut redirect_url = Url::parse(&request.redirect_uri)
            .map_err(|e| OAuthError::InvalidRequest(format!("Invalid redirect URI: {}", e)))?;

        redirect_url.query_pairs_mut().append_pair("code", &code);

        if let Some(state) = request.state {
            redirect_url.query_pairs_mut().append_pair("state", &state);
        }

        Ok(AuthorizeResponse::Redirect(redirect_url.to_string()))
    }

    /// Handle token requests (RFC 6749 Section 4.1.3)
    pub async fn token(
        &self,
        request: TokenRequest,
        headers: &HeaderMap,
        client_auth: Option<ClientAuthentication>,
    ) -> Result<TokenResponse, OAuthError> {
        match request.grant_type {
            GrantType::AuthorizationCode => {
                self.handle_authorization_code_grant(request, headers, client_auth)
                    .await
            }
            GrantType::ClientCredentials => {
                self.handle_client_credentials_grant(request, client_auth)
                    .await
            }
            GrantType::RefreshToken => {
                self.handle_refresh_token_grant(request, headers, client_auth)
                    .await
            }
            GrantType::DeviceCode => {
                self.handle_device_code_grant(request, headers, client_auth).await
            }
        }
    }

    /// Handle authorization code grant
    async fn handle_authorization_code_grant(
        &self,
        request: TokenRequest,
        headers: &HeaderMap,
        client_auth: Option<ClientAuthentication>,
    ) -> Result<TokenResponse, OAuthError> {
        let code = request
            .code
            .as_ref()
            .ok_or_else(|| OAuthError::InvalidRequest("Missing authorization code".to_string()))?;

        let redirect_uri = request
            .redirect_uri
            .as_ref()
            .ok_or_else(|| OAuthError::InvalidRequest("Missing redirect URI".to_string()))?;

        // Consume authorization code
        let auth_code: AuthorizationCode = self
            .storage
            .consume_code(code)
            .await
            .map_err(|e| OAuthError::ServerError(format!("Storage error: {:?}", e)))?
            .ok_or_else(|| OAuthError::InvalidGrant("Invalid authorization code".to_string()))?;

        // Verify redirect URI matches
        if auth_code.redirect_uri != *redirect_uri {
            return Err(OAuthError::InvalidGrant(
                "Redirect URI mismatch".to_string(),
            ));
        }

        // Get client
        let client = self
            .storage
            .get_client(&auth_code.client_id)
            .await
            .map_err(|e| OAuthError::ServerError(format!("Storage error: {:?}", e)))?
            .ok_or_else(|| OAuthError::InvalidClient("Client not found".to_string()))?;

        // Authenticate client
        self.authenticate_client(&client, client_auth, &request)?;

        // Verify PKCE if present
        if let Some(ref code_challenge) = auth_code.code_challenge {
            let code_verifier = request
                .code_verifier
                .as_ref()
                .ok_or_else(|| OAuthError::InvalidRequest("Missing code verifier".to_string()))?;

            let method = auth_code
                .code_challenge_method
                .as_deref()
                .unwrap_or("plain");

            if !self.verify_pkce(code_verifier, code_challenge, method)? {
                return Err(OAuthError::InvalidGrant(
                    "PKCE verification failed".to_string(),
                ));
            }
        }

        // Check for DPoP
        let (token_type, dpop_jkt) = if let Some(dpop_header) = headers.get("DPoP") {
            let dpop_str = dpop_header
                .to_str()
                .map_err(|e| OAuthError::InvalidRequest(format!("Invalid DPoP header: {}", e)))?;

            // Construct full URL for DPoP validation using external base
            let full_token_url = format!("{}/oauth/token", self.issuer.trim_end_matches('/'));

            // For token endpoint, we don't have an access token yet, so ath should be None
            let dpop_proof = self
                .dpop_validator
                .validate_proof(dpop_str, "POST", &full_token_url, None)
                .await
                .map_err(|e| {
                    OAuthError::InvalidRequest(format!("DPoP validation failed: {:?}", e))
                })?;

            (TokenType::DPoP, Some(dpop_proof.thumbprint))
        } else {
            (TokenType::Bearer, None)
        };

        // Generate tokens
        let access_token = generate_token();
        let refresh_token = generate_token();
        let now = Utc::now();

        // Store access token
        let access_token_record = AccessToken {
            token: access_token.clone(),
            token_type: token_type.clone(),
            client_id: client.client_id.clone(),
            user_id: Some(auth_code.user_id.clone()),
            session_id: auth_code.session_id.clone(),
            session_iteration: Some(1),
            scope: auth_code.scope.clone(),
            nonce: auth_code.nonce.clone(),
            created_at: now,
            expires_at: now + client.access_token_expiration,
            dpop_jkt,
        };

        self.storage
            .store_token(&access_token_record)
            .await
            .map_err(|e| {
                OAuthError::ServerError(format!("Failed to store access token: {:?}", e))
            })?;

        // Store refresh token
        let refresh_token_record = RefreshToken {
            token: refresh_token.clone(),
            access_token: access_token.clone(),
            client_id: client.client_id,
            user_id: auth_code.user_id,
            session_id: auth_code.session_id.clone(),
            scope: auth_code.scope.clone(),
            nonce: auth_code.nonce.clone(),
            created_at: now,
            expires_at: Some(now + client.refresh_token_expiration),
        };

        self.storage
            .store_refresh_token(&refresh_token_record)
            .await
            .map_err(|e| {
                OAuthError::ServerError(format!("Failed to store refresh token: {:?}", e))
            })?;

        Ok(TokenResponse::new(
            access_token,
            token_type,
            client.access_token_expiration.num_seconds() as u64,
            Some(refresh_token),
            auth_code.scope,
        ))
    }

    /// Handle client credentials grant
    async fn handle_client_credentials_grant(
        &self,
        request: TokenRequest,
        client_auth: Option<ClientAuthentication>,
    ) -> Result<TokenResponse, OAuthError> {
        // Client credentials grant requires client authentication
        let client_id = client_auth
            .as_ref()
            .map(|auth| auth.client_id.as_str())
            .or(request.client_id.as_deref())
            .ok_or_else(|| OAuthError::InvalidClient("Missing client credentials".to_string()))?;

        let client = self
            .storage
            .get_client(client_id)
            .await
            .map_err(|e| OAuthError::ServerError(format!("Storage error: {:?}", e)))?
            .ok_or_else(|| OAuthError::InvalidClient("Client not found".to_string()))?;

        // Authenticate client
        self.authenticate_client(&client, client_auth, &request)?;

        // Verify client can use client credentials grant
        if !client.grant_types.contains(&GrantType::ClientCredentials) {
            return Err(OAuthError::UnauthorizedClient(
                "Client not authorized for client credentials grant".to_string(),
            ));
        }

        // Validate scope
        let granted_scope = if let Some(ref requested_scope) = request.scope {
            if let Some(ref client_scope) = client.scope {
                let requested_scopes = parse_scope(requested_scope);
                let allowed_scopes = parse_scope(client_scope);

                if !requested_scopes.is_subset(&allowed_scopes) {
                    return Err(OAuthError::InvalidScope(
                        "Requested scope exceeds allowed scope".to_string(),
                    ));
                }

                Some(requested_scope.clone())
            } else {
                return Err(OAuthError::InvalidScope(
                    "Client has no allowed scope".to_string(),
                ));
            }
        } else {
            client.scope.clone()
        };

        // Generate access token
        let access_token = generate_token();
        let now = Utc::now();

        let access_token_record = AccessToken {
            token: access_token.clone(),
            token_type: TokenType::Bearer, // Client credentials doesn't use DPoP typically
            client_id: client.client_id.clone(),
            user_id: None, // No user for client credentials
            session_id: None,
            session_iteration: None, // No session for client credentials
            scope: granted_scope.clone(),
            nonce: None, // No nonce for client credentials grant
            created_at: now,
            expires_at: now + client.access_token_expiration,
            dpop_jkt: None,
        };

        self.storage
            .store_token(&access_token_record)
            .await
            .map_err(|e| {
                OAuthError::ServerError(format!("Failed to store access token: {:?}", e))
            })?;

        Ok(TokenResponse::new(
            access_token,
            TokenType::Bearer,
            client.access_token_expiration.num_seconds() as u64,
            None, // No refresh token for client credentials
            granted_scope,
        ))
    }

    /// Handle refresh token grant
    async fn handle_refresh_token_grant(
        &self,
        request: TokenRequest,
        _headers: &HeaderMap,
        client_auth: Option<ClientAuthentication>,
    ) -> Result<TokenResponse, OAuthError> {
        let refresh_token = request
            .refresh_token
            .as_ref()
            .ok_or_else(|| OAuthError::InvalidRequest("Missing refresh token".to_string()))?;

        // Consume refresh token
        let refresh_token_record: RefreshToken = self
            .storage
            .consume_refresh_token(refresh_token)
            .await
            .map_err(|e| OAuthError::ServerError(format!("Storage error: {:?}", e)))?
            .ok_or_else(|| OAuthError::InvalidGrant("Invalid refresh token".to_string()))?;

        // Get client
        let client = self
            .storage
            .get_client(&refresh_token_record.client_id)
            .await
            .map_err(|e| OAuthError::ServerError(format!("Storage error: {:?}", e)))?
            .ok_or_else(|| OAuthError::InvalidClient("Client not found".to_string()))?;

        // Authenticate client
        self.authenticate_client(&client, client_auth, &request)?;

        let old_access_token = self
            .storage
            .get_token(&refresh_token_record.access_token)
            .await
            .map_err(|e| OAuthError::ServerError(format!("Storage error: {:?}", e)))?
            .ok_or_else(|| OAuthError::InvalidGrant("Invalid refresh token".to_string()))?;

        let session_iteration = old_access_token
            .session_iteration
            .ok_or_else(|| OAuthError::InvalidGrant("Invalid refresh token".to_string()))?;

        // Generate new tokens
        let new_access_token = generate_token();
        let new_refresh_token = generate_token();
        let now = Utc::now();

        // Store new access token
        let access_token_record = AccessToken {
            token: new_access_token.clone(),
            token_type: old_access_token.token_type,
            client_id: client.client_id.clone(),
            user_id: Some(refresh_token_record.user_id.clone()),
            session_id: refresh_token_record.session_id.clone(),
            session_iteration: Some(session_iteration + 1),
            scope: refresh_token_record.scope.clone(),
            nonce: refresh_token_record.nonce.clone(),
            created_at: now,
            expires_at: now + client.access_token_expiration,
            dpop_jkt: old_access_token.dpop_jkt,
        };

        self.storage
            .store_token(&access_token_record)
            .await
            .map_err(|e| {
                OAuthError::ServerError(format!("Failed to store access token: {:?}", e))
            })?;

        // Store new refresh token
        let new_refresh_token_record = RefreshToken {
            token: new_refresh_token.clone(),
            access_token: new_access_token.clone(),
            client_id: client.client_id,
            user_id: refresh_token_record.user_id,
            session_id: refresh_token_record.session_id,
            scope: refresh_token_record.scope.clone(),
            nonce: refresh_token_record.nonce.clone(),
            created_at: now,
            expires_at: Some(now + client.refresh_token_expiration),
        };

        self.storage
            .store_refresh_token(&new_refresh_token_record)
            .await
            .map_err(|e| {
                OAuthError::ServerError(format!("Failed to store refresh token: {:?}", e))
            })?;

        Ok(TokenResponse::new(
            new_access_token,
            TokenType::Bearer,
            client.access_token_expiration.num_seconds() as u64,
            Some(new_refresh_token),
            refresh_token_record.scope,
        ))
    }

    /// Handle device code grant (RFC 8628)
    async fn handle_device_code_grant(
        &self,
        request: TokenRequest,
        _headers: &HeaderMap,
        client_auth: Option<ClientAuthentication>,
    ) -> Result<TokenResponse, OAuthError> {
        let device_code = request
            .device_code
            .as_ref()
            .ok_or_else(|| OAuthError::InvalidRequest("Missing device_code".to_string()))?;

        // Get device code entry (don't consume yet)
        let device_entry = self
            .storage
            .get_device_code(device_code)
            .await
            .map_err(|e| OAuthError::ServerError(format!("Storage error: {:?}", e)))?
            .ok_or_else(|| OAuthError::InvalidGrant("Invalid or expired device code".to_string()))?;

        // Check if device code is expired
        if device_entry.expires_at <= chrono::Utc::now() {
            return Err(OAuthError::InvalidGrant("Expired device code".to_string()));
        }

        // Check if device code is authorized
        let _authorized_user = match device_entry.authorized_user {
            Some(user) => user,
            None => return Err(OAuthError::AuthorizationPending("Device code not yet authorized".to_string())),
        };

        // Use the client_id from the device code entry
        let client_id = device_entry.client_id.clone();

        // Get client
        let client = self
            .storage
            .get_client(&client_id)
            .await
            .map_err(|e| OAuthError::ServerError(format!("Storage error: {:?}", e)))?
            .ok_or_else(|| OAuthError::InvalidClient("Client not found".to_string()))?;

        // Authenticate client
        self.authenticate_client(&client, client_auth, &request)?;

        // Now consume the device code since we're going to issue tokens
        // Only consume after successful authentication to avoid consuming on auth failures
        let consumed_authorized_user = self.storage
            .consume_device_code(device_code)
            .await
            .map_err(|e| OAuthError::ServerError(format!("Storage error: {:?}", e)))?
            .ok_or_else(|| OAuthError::InvalidGrant("Device code no longer valid".to_string()))?;

        // Generate access token
        let access_token = generate_token();
        let now = Utc::now();

        // Store access token - session linking will happen in handler_oauth.rs
        let access_token_record = AccessToken {
            token: access_token.clone(),
            token_type: TokenType::Bearer,
            client_id: client.client_id.clone(),
            user_id: Some(consumed_authorized_user.clone()),
            session_id: None, // Will be linked in handler_oauth.rs
            session_iteration: None,
            scope: device_entry.scope.clone(),
            nonce: None,
            created_at: now,
            expires_at: now + client.access_token_expiration,
            dpop_jkt: None, // Device flow typically doesn't use DPoP
        };

        self.storage
            .store_token(&access_token_record)
            .await
            .map_err(|e| {
                OAuthError::ServerError(format!("Failed to store access token: {:?}", e))
            })?;

        // Generate refresh token if supported
        let refresh_token = if client.grant_types.contains(&GrantType::RefreshToken) {
            let refresh_token = generate_token();
            let now = Utc::now();
            let refresh_token_record = RefreshToken {
                token: refresh_token.clone(),
                access_token: access_token_record.token.clone(),
                client_id: client.client_id.clone(),
                user_id: consumed_authorized_user.clone(),
                session_id: access_token_record.session_id.clone(),
                scope: device_entry.scope.clone(),
                nonce: None,
                created_at: now,
                expires_at: Some(now + client.refresh_token_expiration),
            };

            self.storage
                .store_refresh_token(&refresh_token_record)
                .await
                .map_err(|e| {
                    OAuthError::ServerError(format!("Failed to store refresh token: {:?}", e))
                })?;

            Some(refresh_token)
        } else {
            None
        };

        Ok(TokenResponse::new(
            access_token_record.token,
            TokenType::Bearer,
            client.access_token_expiration.num_seconds() as u64,
            refresh_token,
            device_entry.scope,
        ))
    }

    /// Authenticate a client
    fn authenticate_client(
        &self,
        client: &OAuthClient,
        client_auth: Option<ClientAuthentication>,
        request: &TokenRequest,
    ) -> Result<(), OAuthError> {
        match &client.token_endpoint_auth_method {
            ClientAuthMethod::None => {
                // Public client - no authentication required
                Ok(())
            }
            ClientAuthMethod::ClientSecretBasic | ClientAuthMethod::ClientSecretPost => {
                // Require client secret
                let provided_secret = client_auth
                    .as_ref()
                    .and_then(|auth| auth.client_secret.as_ref())
                    .or(request.client_secret.as_ref())
                    .ok_or_else(|| {
                        OAuthError::InvalidClient("Missing client secret".to_string())
                    })?;

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
            ClientAuthMethod::PrivateKeyJwt => {
                // TODO: Implement JWT client authentication
                Err(OAuthError::UnsupportedGrantType(
                    "private_key_jwt not implemented".to_string(),
                ))
            }
        }
    }

    /// Verify PKCE code challenge
    fn verify_pkce(
        &self,
        code_verifier: &str,
        code_challenge: &str,
        method: &str,
    ) -> Result<bool, OAuthError> {
        let computed_challenge = match method {
            "plain" => code_verifier.to_string(),
            "S256" => {
                let mut hasher = Sha256::new();
                hasher.update(code_verifier.as_bytes());
                let hash = hasher.finalize();
                BASE64_URL_SAFE_NO_PAD.encode(hash)
            }
            _ => {
                return Err(OAuthError::InvalidRequest(format!(
                    "Unsupported PKCE method: {}",
                    method
                )));
            }
        };

        Ok(computed_challenge == code_challenge)
    }
}

/// Client Authentication extracted from request
#[derive(Clone)]
pub struct ClientAuthentication {
    pub client_id: String,
    pub client_secret: Option<String>,
}

/// Authorization response
#[derive(Debug)]
pub enum AuthorizeResponse {
    Redirect(String),
    Error { error: String, description: String },
}

/// Query parameters for authorization endpoint
#[derive(Deserialize)]
#[cfg_attr(any(debug_assertions, test), derive(Debug))]
pub struct AuthorizeQuery {
    pub response_type: Option<String>,
    pub client_id: String,
    pub redirect_uri: Option<String>,
    pub scope: Option<String>,
    pub state: Option<String>,
    pub code_challenge: Option<String>,
    pub code_challenge_method: Option<String>,
    pub request_uri: Option<String>, // For PAR (RFC 9126)
    pub login_hint: Option<String>,
    pub nonce: Option<String>,
}

impl From<AuthorizeQuery> for AuthorizationRequest {
    fn from(query: AuthorizeQuery) -> Self {
        Self {
            response_type: vec![ResponseType::Code], // Always code, regardless of input
            client_id: query.client_id,
            redirect_uri: query.redirect_uri.unwrap_or_default(), // Default to empty for PAR
            scope: query.scope,
            state: query.state,
            code_challenge: query.code_challenge,
            code_challenge_method: query.code_challenge_method,
            login_hint: query.login_hint,
            nonce: query.nonce,
        }
    }
}

/// Form data for token endpoint
#[derive(Debug, Deserialize)]
pub struct TokenForm {
    pub grant_type: String,
    pub code: Option<String>,
    pub redirect_uri: Option<String>,
    pub code_verifier: Option<String>,
    pub refresh_token: Option<String>,
    pub device_code: Option<String>,
    pub client_id: Option<String>,
    pub client_secret: Option<String>,
    pub scope: Option<String>,
}

impl TryFrom<TokenForm> for TokenRequest {
    type Error = OAuthError;

    fn try_from(form: TokenForm) -> Result<Self, Self::Error> {
        let grant_type = match form.grant_type.as_str() {
            "authorization_code" => GrantType::AuthorizationCode,
            "client_credentials" => GrantType::ClientCredentials,
            "refresh_token" => GrantType::RefreshToken,
            "urn:ietf:params:oauth:grant-type:device_code" => GrantType::DeviceCode,
            _ => return Err(OAuthError::UnsupportedGrantType(form.grant_type)),
        };

        Ok(Self {
            grant_type,
            code: form.code,
            redirect_uri: form.redirect_uri,
            code_verifier: form.code_verifier,
            refresh_token: form.refresh_token,
            device_code: form.device_code,
            client_id: form.client_id,
            client_secret: form.client_secret,
            scope: form.scope,
        })
    }
}

/// Axum handler for authorization endpoint
pub async fn authorize_handler(
    State(auth_server): State<Arc<AuthorizationServer>>,
    Query(query): Query<AuthorizeQuery>,
) -> Result<Redirect, (StatusCode, Json<Value>)> {
    // For now, assume user is authenticated with a dummy user ID
    let user_id = "dummy-user".to_string();

    let request = AuthorizationRequest::from(query);

    match auth_server.authorize(request, user_id, None).await {
        Ok(AuthorizeResponse::Redirect(url)) => Ok(Redirect::to(&url)),
        Ok(AuthorizeResponse::Error { error, description }) => {
            let error_response = json!({
                "error": error,
                "error_description": description
            });
            Err((StatusCode::INTERNAL_SERVER_ERROR, Json(error_response)))
        }
        Err(e) => {
            let error_response = json!({
                "error": "server_error",
                "error_description": e.to_string()
            });
            Err((StatusCode::INTERNAL_SERVER_ERROR, Json(error_response)))
        }
    }
}

/// Axum handler for token endpoint
pub async fn token_handler(
    State(auth_server): State<Arc<AuthorizationServer>>,
    headers: HeaderMap,
    Form(form): Form<TokenForm>,
) -> Result<Json<TokenResponse>, (StatusCode, Json<Value>)> {
    // Extract client authentication from Authorization header or form
    let client_auth = extract_client_auth(&headers, &form);

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

    match auth_server.token(request, &headers, client_auth).await {
        Ok(response) => Ok(Json(response)),
        Err(e) => {
            let (status, error_code) = match e {
                OAuthError::InvalidClient(_) => (StatusCode::UNAUTHORIZED, "invalid_client"),
                OAuthError::InvalidGrant(_) => (StatusCode::BAD_REQUEST, "invalid_grant"),
                OAuthError::UnsupportedGrantType(_) => {
                    (StatusCode::BAD_REQUEST, "unsupported_grant_type")
                }
                OAuthError::InvalidScope(_) => (StatusCode::BAD_REQUEST, "invalid_scope"),
                OAuthError::InvalidRequest(_) => (StatusCode::BAD_REQUEST, "invalid_request"),
                OAuthError::AuthorizationPending(_) => (StatusCode::ACCEPTED, "authorization_pending"),
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

/// Extract client authentication from headers and form
pub fn extract_client_auth(headers: &HeaderMap, form: &TokenForm) -> Option<ClientAuthentication> {
    // Try Authorization header first (HTTP Basic)
    if let Some(auth_header) = headers.get("Authorization") {
        if let Ok(auth_str) = auth_header.to_str() {
            if let Some(encoded) = auth_str.strip_prefix("Basic ") {
                if let Ok(decoded) = BASE64_STANDARD.decode(encoded) {
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

    // Fall back to form parameters
    if let Some(client_id) = &form.client_id {
        return Some(ClientAuthentication {
            client_id: client_id.clone(),
            client_secret: form.client_secret.clone(),
        });
    }

    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::storage::inmemory::MemoryOAuthStorage;
    use crate::storage::traits::{OAuthClientStore, AccessTokenStore, DeviceCodeStore, AtpOAuthSessionStorage};

    #[tokio::test]
    async fn test_authorization_code_flow() {
        let storage = Arc::new(MemoryOAuthStorage::new());
        let auth_server =
            AuthorizationServer::new(storage.clone(), "https://localhost".to_string());

        // Register a test client
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
            application_type: None,
            software_id: None,
            software_version: None,
            created_at: Utc::now(),
            updated_at: Utc::now(),
            metadata: serde_json::Value::Null,
            access_token_expiration: chrono::Duration::days(1),
            refresh_token_expiration: chrono::Duration::days(14),
            require_redirect_exact: true,
            registration_access_token: Some("test-registration-token".to_string()),
        };

        storage.store_client(&client).await.unwrap();

        // Step 1: Authorization request
        let auth_request = AuthorizationRequest {
            response_type: vec![ResponseType::Code],
            client_id: "test-client".to_string(),
            redirect_uri: "https://example.com/callback".to_string(),
            scope: Some("read".to_string()),
            state: Some("test-state".to_string()),
            code_challenge: None,
            code_challenge_method: None,
            login_hint: None,
            nonce: None,
        };

        let auth_response = auth_server
            .authorize(auth_request, "test-user".to_string(), None)
            .await
            .unwrap();

        // Extract code from redirect URL
        let redirect_url = match auth_response {
            AuthorizeResponse::Redirect(url) => url,
            _ => panic!("Expected redirect response"),
        };

        let parsed_url = Url::parse(&redirect_url).unwrap();
        let code = parsed_url
            .query_pairs()
            .find(|(key, _)| key == "code")
            .map(|(_, value)| value.to_string())
            .unwrap();

        // Step 2: Token request
        let token_request = TokenRequest {
            grant_type: GrantType::AuthorizationCode,
            code: Some(code),
            redirect_uri: Some("https://example.com/callback".to_string()),
            code_verifier: None,
            refresh_token: None,
            device_code: None,
            client_id: Some("test-client".to_string()),
            client_secret: Some("test-secret".to_string()),
            scope: None,
        };

        let headers = HeaderMap::new();
        let client_auth = Some(ClientAuthentication {
            client_id: "test-client".to_string(),
            client_secret: Some("test-secret".to_string()),
        });

        let token_response = auth_server
            .token(token_request, &headers, client_auth)
            .await
            .unwrap();

        assert!(!token_response.access_token.is_empty());
        assert!(token_response.refresh_token.is_some());
        assert_eq!(token_response.scope, Some("read".to_string()));
    }

    #[tokio::test]
    async fn test_device_code_flow() {
        let storage = Arc::new(MemoryOAuthStorage::new());
        let auth_server =
            AuthorizationServer::new(storage.clone(), "https://localhost".to_string());

        // Register a test device client with proper native app configuration
        let client = OAuthClient {
            client_id: "test-device-client".to_string(),
            client_secret: None, // Public client for device flow
            client_name: Some("Test Device Client".to_string()),
            redirect_uris: vec![], // Device flow doesn't use redirect URIs
            grant_types: vec![GrantType::DeviceCode, GrantType::RefreshToken],
            response_types: vec![], // Device flow uses device_code response type (not standard ResponseType enum)
            scope: Some("atproto:atproto atproto:transition:generic".to_string()),
            token_endpoint_auth_method: ClientAuthMethod::None, // Public client
            client_type: ClientType::Public,
            application_type: Some(crate::oauth::types::ApplicationType::Native),
            software_id: Some("test-software-id".to_string()),
            software_version: Some("1.0.0".to_string()),
            created_at: Utc::now(),
            updated_at: Utc::now(),
            metadata: serde_json::Value::Null,
            access_token_expiration: chrono::Duration::hours(1),
            refresh_token_expiration: chrono::Duration::days(14),
            require_redirect_exact: true,
            registration_access_token: Some("test-registration-token".to_string()),
        };
        storage.store_client(&client).await.unwrap();

        // Step 1: Store a device code
        let device_code = "device_test123";
        let user_code = "ABCD-EFGH";
        storage.store_device_code(
            device_code,
            user_code,
            "test-device-client",
            Some("atproto:atproto atproto:transition:generic"),
            1800, // 30 minutes
        ).await.unwrap();

        // Step 2: Authorize the device code (simulate user authorization)
        let user_did = "did:plc:test123";
        storage.authorize_device_code(user_code, user_did).await.unwrap();

        // Step 3: Exchange device code for token
        let token_request = TokenRequest {
            grant_type: GrantType::DeviceCode,
            code: None,
            redirect_uri: None,
            code_verifier: None,
            refresh_token: None,
            client_id: Some("test-device-client".to_string()),
            client_secret: None, // Public client
            device_code: Some(device_code.to_string()),
            scope: None,
        };

        let headers = HeaderMap::new();
        let client_auth = Some(ClientAuthentication {
            client_id: "test-device-client".to_string(),
            client_secret: None, // Public client
        });

        let token_response = auth_server
            .token(token_request, &headers, client_auth)
            .await
            .unwrap();

        // Verify token response
        assert!(!token_response.access_token.is_empty());
        assert!(token_response.refresh_token.is_some());
        assert_eq!(token_response.scope, Some("atproto:atproto atproto:transition:generic".to_string()));

        // Verify token is stored with correct user_id
        let stored_token = storage.get_token(&token_response.access_token).await.unwrap().unwrap();
        assert_eq!(stored_token.user_id, Some(user_did.to_string()));
        assert_eq!(stored_token.client_id, "test-device-client");
        assert_eq!(stored_token.scope, Some("atproto:atproto atproto:transition:generic".to_string()));
        
        // Initially token should not be linked to a session (session_id should be None)
        assert_eq!(stored_token.session_id, None);
        assert_eq!(stored_token.session_iteration, None);
    }

}
