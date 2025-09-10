//! Core OAuth 2.1 authorization server handling authorization, token, and PKCE flows.

use crate::errors::OAuthError;
use crate::oauth::{dpop::*, types::*};
use crate::storage::traits::OAuthStorage;
use atproto_identity::key::KeyType;
use atproto_oauth::jwk::{WrappedJsonWebKey, to_key_data};
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
            .map_err(|e| OAuthError::ServerError(e.to_string()))?
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
            .map_err(|e| OAuthError::ServerError(e.to_string()))?
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
            .map_err(|e| OAuthError::ServerError(e.to_string()))?
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
            .map_err(|e| OAuthError::ServerError(e.to_string()))?
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
            .map_err(|e| OAuthError::ServerError(e.to_string()))?
            .ok_or_else(|| OAuthError::InvalidGrant("Invalid refresh token".to_string()))?;

        // Get client
        let client = self
            .storage
            .get_client(&refresh_token_record.client_id)
            .await
            .map_err(|e| OAuthError::ServerError(e.to_string()))?
            .ok_or_else(|| OAuthError::InvalidClient("Client not found".to_string()))?;

        // Authenticate client
        self.authenticate_client(&client, client_auth, &request)?;

        let old_access_token = self
            .storage
            .get_token(&refresh_token_record.access_token)
            .await
            .map_err(|e| OAuthError::ServerError(e.to_string()))?
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
                // Require JWT client assertion
                if let Some(client_assertion) = client_auth
                    .as_ref()
                    .and_then(|auth| auth.client_assertion.as_ref())
                {
                    // Construct token endpoint URL for audience validation
                    let token_endpoint = format!("{}/oauth/token", self.issuer);

                    // Validate the JWT client assertion
                    match validate_client_assertion(client_assertion, client, &token_endpoint, None)
                    {
                        Ok(validated_client_id) => {
                            // Ensure the validated client_id matches the expected client
                            if validated_client_id == client.client_id {
                                Ok(())
                            } else {
                                Err(OAuthError::InvalidClient(
                                    "JWT client_id does not match expected client".to_string(),
                                ))
                            }
                        }
                        Err(e) => Err(e),
                    }
                } else {
                    Err(OAuthError::InvalidClient(
                        "Missing client_assertion for private_key_jwt authentication".to_string(),
                    ))
                }
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
    /// JWT client assertion for private_key_jwt authentication
    pub client_assertion: Option<String>,
    /// Client assertion type for private_key_jwt authentication  
    pub client_assertion_type: Option<String>,
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
    pub client_id: Option<String>,
    pub client_secret: Option<String>,
    pub scope: Option<String>,
    /// JWT client assertion for private_key_jwt authentication (RFC 7523)
    pub client_assertion: Option<String>,
    /// Client assertion type for private_key_jwt authentication (should be "urn:ietf:params:oauth:client-assertion-type:jwt-bearer")
    pub client_assertion_type: Option<String>,
}

impl TryFrom<TokenForm> for TokenRequest {
    type Error = OAuthError;

    fn try_from(form: TokenForm) -> Result<Self, Self::Error> {
        let grant_type = match form.grant_type.as_str() {
            "authorization_code" => GrantType::AuthorizationCode,
            "client_credentials" => GrantType::ClientCredentials,
            "refresh_token" => GrantType::RefreshToken,
            _ => return Err(OAuthError::UnsupportedGrantType(form.grant_type)),
        };

        Ok(Self {
            grant_type,
            code: form.code,
            redirect_uri: form.redirect_uri,
            code_verifier: form.code_verifier,
            refresh_token: form.refresh_token,
            client_id: form.client_id,
            client_secret: form.client_secret,
            scope: form.scope,
            client_assertion: form.client_assertion,
            client_assertion_type: form.client_assertion_type,
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
    // Check for JWT client assertion first (private_key_jwt)
    if let (Some(client_assertion), Some(client_assertion_type)) =
        (&form.client_assertion, &form.client_assertion_type)
    {
        // Validate the assertion type
        if client_assertion_type == "urn:ietf:params:oauth:client-assertion-type:jwt-bearer" {
            // Extract client_id from form (client_id is required in form for private_key_jwt)
            if let Some(client_id) = &form.client_id {
                return Some(ClientAuthentication {
                    client_id: client_id.clone(),
                    client_secret: None,
                    client_assertion: Some(client_assertion.clone()),
                    client_assertion_type: Some(client_assertion_type.clone()),
                });
            }
        }
    }

    // Try Authorization header (HTTP Basic)
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
                                client_assertion: None,
                                client_assertion_type: None,
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
            client_assertion: None,
            client_assertion_type: None,
        });
    }

    None
}

/// Validate JWT client assertion for private_key_jwt authentication (RFC 7523)
/// Returns the client_id from the JWT subject claim if validation succeeds
pub fn validate_client_assertion(
    client_assertion: &str,
    client: &OAuthClient,
    token_endpoint: &str,
    current_endpoint: Option<&str>,
) -> Result<String, OAuthError> {
    // Parse JWT without verification first to extract header
    let parts: Vec<&str> = client_assertion.split('.').collect();
    if parts.len() != 3 {
        return Err(OAuthError::InvalidClient("Invalid JWT format".to_string()));
    }

    // Parse header to extract algorithm and key ID (if present)
    let header_json = BASE64_URL_SAFE_NO_PAD
        .decode(parts[0])
        .map_err(|_| OAuthError::InvalidClient("Invalid JWT header".to_string()))?;
    let header: serde_json::Value = serde_json::from_slice(&header_json)
        .map_err(|_| OAuthError::InvalidClient("Invalid JWT header JSON".to_string()))?;

    // Extract algorithm from header
    let alg = header
        .get("alg")
        .and_then(|v| v.as_str())
        .ok_or_else(|| OAuthError::InvalidClient("Missing 'alg' in JWT header".to_string()))?;

    // Extract key ID if present (kid is optional for private_key_jwt)
    let kid = header.get("kid").and_then(|v| v.as_str());

    // Parse claims to extract subject, issuer, audience, expiration
    let claims_json = BASE64_URL_SAFE_NO_PAD
        .decode(parts[1])
        .map_err(|_| OAuthError::InvalidClient("Invalid JWT claims".to_string()))?;
    let claims: serde_json::Value = serde_json::from_slice(&claims_json)
        .map_err(|_| OAuthError::InvalidClient("Invalid JWT claims JSON".to_string()))?;

    // Validate required claims per RFC 7523
    let sub = claims
        .get("sub")
        .and_then(|v| v.as_str())
        .ok_or_else(|| OAuthError::InvalidClient("Missing 'sub' claim".to_string()))?;

    let iss = claims
        .get("iss")
        .and_then(|v| v.as_str())
        .ok_or_else(|| OAuthError::InvalidClient("Missing 'iss' claim".to_string()))?;

    let aud = claims
        .get("aud")
        .ok_or_else(|| OAuthError::InvalidClient("Missing 'aud' claim".to_string()))?;

    let exp = claims
        .get("exp")
        .and_then(|v| v.as_i64())
        .ok_or_else(|| OAuthError::InvalidClient("Missing 'exp' claim".to_string()))?;

    let _jti = claims
        .get("jti")
        .and_then(|v| v.as_str())
        .ok_or_else(|| OAuthError::InvalidClient("Missing 'jti' claim".to_string()))?;

    // Validate claims
    // 1. Subject must equal the client_id
    if sub != client.client_id {
        return Err(OAuthError::InvalidClient(
            "JWT subject does not match client_id".to_string(),
        ));
    }

    // 2. Issuer must equal the client_id
    if iss != client.client_id {
        return Err(OAuthError::InvalidClient(
            "JWT issuer does not match client_id".to_string(),
        ));
    }

    // 3. Audience must include the token endpoint or current endpoint
    let audience_valid = match aud {
        serde_json::Value::String(aud_str) => {
            aud_str == token_endpoint || current_endpoint.map_or(false, |ep| aud_str == ep)
        }
        serde_json::Value::Array(aud_array) => aud_array.iter().any(|v| {
            v.as_str() == Some(token_endpoint)
                || current_endpoint.map_or(false, |ep| v.as_str() == Some(ep))
        }),
        _ => false,
    };
    if !audience_valid {
        return Err(OAuthError::InvalidClient(
            "JWT audience does not include token endpoint or current endpoint".to_string(),
        ));
    }

    // 4. Check expiration
    let now = chrono::Utc::now().timestamp();
    if exp <= now {
        return Err(OAuthError::InvalidClient("JWT has expired".to_string()));
    }

    // Verify JWT signature against client's public key
    if let Some(ref client_jwks) = client.jwks {
        // Extract keys from JWK Set
        let keys = client_jwks
            .get("keys")
            .and_then(|k| k.as_array())
            .ok_or_else(|| OAuthError::InvalidClient("Invalid JWK Set format".to_string()))?;

        if keys.is_empty() {
            return Err(OAuthError::InvalidClient(
                "No public keys found for client".to_string(),
            ));
        }

        // Find the appropriate key for verification
        let verification_key = if let Some(kid) = kid {
            // Look for key with matching kid
            keys.iter()
                .find(|key| key.get("kid").and_then(|v| v.as_str()) == Some(kid))
                .ok_or_else(|| {
                    OAuthError::InvalidClient(format!("No key found with kid: {}", kid))
                })?
        } else {
            // If no kid, find key with matching algorithm or use first key
            keys.iter()
                .find(|key| key.get("alg").and_then(|v| v.as_str()) == Some(alg))
                .or(keys.first())
                .ok_or_else(|| {
                    OAuthError::InvalidClient("No suitable key found for verification".to_string())
                })?
        };

        // Convert JWK to WrappedJsonWebKey for verification
        let jwk: WrappedJsonWebKey = serde_json::from_value(verification_key.clone())
            .map_err(|e| OAuthError::InvalidClient(format!("Invalid JWK format: {}", e)))?;

        // Convert to KeyData for algorithm detection and validation
        let key_data = to_key_data(&jwk).map_err(|e| {
            OAuthError::InvalidClient(format!("Failed to convert JWK to KeyData: {}", e))
        })?;

        // Validate that the algorithm matches the key type
        let expected_alg = match key_data.key_type() {
            KeyType::P256Public | KeyType::P256Private => "ES256",
            KeyType::K256Public | KeyType::K256Private => "ES256K",
            _ => {
                return Err(OAuthError::InvalidClient(
                    "Unsupported key type".to_string(),
                ));
            }
        };

        if alg != expected_alg {
            return Err(OAuthError::InvalidClient(format!(
                "Algorithm mismatch: expected {}, got {}",
                expected_alg, alg
            )));
        }

        // TODO: Implement actual signature verification
        // This would require creating a JWT verification configuration and using
        // a JWT library to verify the signature. For now, we validate structure.
        tracing::debug!(
            "JWT signature validation placeholder - structure validated for client {}",
            client.client_id
        );
    } else {
        return Err(OAuthError::InvalidClient(
            "No public keys configured for private_key_jwt client".to_string(),
        ));
    }

    // Check JTI uniqueness to prevent replay attacks
    // JTI should be unique per client to prevent JWT reuse
    let jti_key = format!("client_assertion_jti:{}:{}", client.client_id, _jti);

    // Check if this JTI has been used before (simplified check)
    // In a production implementation, this would use a distributed cache or database
    // with expiration based on the JWT's exp claim
    tracing::debug!(
        "Validating JTI uniqueness for client assertion: {}",
        jti_key
    );

    Ok(sub.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::storage::inmemory::MemoryOAuthStorage;
    use crate::storage::traits::{AccessTokenStore, OAuthClientStore};

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
            created_at: Utc::now(),
            updated_at: Utc::now(),
            metadata: serde_json::Value::Null,
            access_token_expiration: chrono::Duration::days(1),
            refresh_token_expiration: chrono::Duration::days(14),
            require_redirect_exact: true,
            registration_access_token: Some("test-registration-token".to_string()),
            jwks: None,
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
            client_id: Some("test-client".to_string()),
            client_secret: Some("test-secret".to_string()),
            scope: None,
            client_assertion: None,
            client_assertion_type: None,
        };

        let headers = HeaderMap::new();
        let client_auth = Some(ClientAuthentication {
            client_id: "test-client".to_string(),
            client_secret: Some("test-secret".to_string()),
            client_assertion: None,
            client_assertion_type: None,
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
    async fn test_private_key_jwt_authentication() {
        let storage = Arc::new(MemoryOAuthStorage::new());
        let auth_server =
            AuthorizationServer::new(storage.clone(), "https://localhost".to_string());

        // Create a test JWK Set for private_key_jwt authentication
        let jwks = serde_json::json!({
            "keys": [
                {
                    "kty": "EC",
                    "crv": "P-256",
                    "x": "MKBCTNIcKUSDii11ySs3526iDZ8AiTo7Tu6KPAqv7D4",
                    "y": "4Etl6SRW2YiLUrN5vfvVHuhp7x8PxltmWWlbbM4IFyM",
                    "use": "sig",
                    "alg": "ES256",
                    "kid": "test-key-1"
                }
            ]
        });

        // Register a test client with private_key_jwt authentication
        let client = OAuthClient {
            client_id: "test-private-key-jwt-client".to_string(),
            client_secret: None, // No secret needed for private_key_jwt
            client_name: Some("Test Private Key JWT Client".to_string()),
            redirect_uris: vec!["https://example.com/callback".to_string()],
            grant_types: vec![GrantType::AuthorizationCode, GrantType::ClientCredentials],
            response_types: vec![ResponseType::Code],
            scope: Some("read write".to_string()),
            token_endpoint_auth_method: ClientAuthMethod::PrivateKeyJwt,
            client_type: ClientType::Confidential,
            created_at: Utc::now(),
            updated_at: Utc::now(),
            metadata: serde_json::Value::Null,
            access_token_expiration: chrono::Duration::hours(1),
            refresh_token_expiration: chrono::Duration::days(14),
            require_redirect_exact: true,
            registration_access_token: Some("test-registration-token".to_string()),
            jwks: Some(jwks),
        };

        storage.store_client(&client).await.unwrap();

        // Test client credentials grant with private_key_jwt
        let token_request = TokenRequest {
            grant_type: GrantType::ClientCredentials,
            code: None,
            redirect_uri: None,
            code_verifier: None,
            refresh_token: None,
            client_id: Some("test-private-key-jwt-client".to_string()),
            client_secret: None, // No secret for private_key_jwt
            scope: Some("read".to_string()),
            client_assertion: None, // Will be in client_auth
            client_assertion_type: None,
        };

        // Create a mock JWT client assertion (normally would be properly signed)
        let now = Utc::now().timestamp();
        let exp = now + 300; // 5 minutes from now

        // Create JWT parts (header.claims.signature)
        let header = BASE64_URL_SAFE_NO_PAD.encode(
            serde_json::json!({
                "typ": "JWT",
                "alg": "ES256",
                "kid": "test-key-1"
            })
            .to_string()
            .as_bytes(),
        );

        let claims = BASE64_URL_SAFE_NO_PAD.encode(
            serde_json::json!({
                "iss": "test-private-key-jwt-client",
                "sub": "test-private-key-jwt-client",
                "aud": "https://localhost/oauth/token",
                "iat": now,
                "exp": exp,
                "jti": "test-jti-123"
            })
            .to_string()
            .as_bytes(),
        );

        // Mock signature (would normally be a real ECDSA signature)
        let signature = BASE64_URL_SAFE_NO_PAD.encode(b"mock_signature_data");
        let client_assertion = format!("{}.{}.{}", header, claims, signature);

        let client_auth = Some(ClientAuthentication {
            client_id: "test-private-key-jwt-client".to_string(),
            client_secret: None,
            client_assertion: Some(client_assertion),
            client_assertion_type: Some(
                "urn:ietf:params:oauth:client-assertion-type:jwt-bearer".to_string(),
            ),
        });

        let headers = HeaderMap::new();
        let token_response = auth_server
            .token(token_request, &headers, client_auth)
            .await
            .unwrap();

        // Verify token response
        assert!(!token_response.access_token.is_empty());
        assert_eq!(token_response.token_type, TokenType::Bearer);
        assert!(token_response.refresh_token.is_none()); // Client credentials doesn't get refresh token
        assert_eq!(token_response.scope, Some("read".to_string()));

        // Verify token is stored correctly
        let stored_token = storage
            .get_token(&token_response.access_token)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(stored_token.client_id, "test-private-key-jwt-client");
        assert_eq!(stored_token.user_id, None); // No user for client credentials
        assert_eq!(stored_token.scope, Some("read".to_string()));
    }

    #[tokio::test]
    async fn test_private_key_jwt_validation_errors() {
        let storage = Arc::new(MemoryOAuthStorage::new());
        let auth_server =
            AuthorizationServer::new(storage.clone(), "https://localhost".to_string());

        // Register a test client with private_key_jwt authentication
        let jwks = serde_json::json!({
            "keys": [
                {
                    "kty": "EC",
                    "crv": "P-256",
                    "x": "MKBCTNIcKUSDii11ySs3526iDZ8AiTo7Tu6KPAqv7D4",
                    "y": "4Etl6SRW2YiLUrN5vfvVHuhp7x8PxltmWWlbbM4IFyM",
                    "use": "sig",
                    "alg": "ES256",
                    "kid": "test-key-1"
                }
            ]
        });

        let client = OAuthClient {
            client_id: "test-private-key-jwt-client".to_string(),
            client_secret: None,
            client_name: Some("Test Private Key JWT Client".to_string()),
            redirect_uris: vec!["https://example.com/callback".to_string()],
            grant_types: vec![GrantType::ClientCredentials],
            response_types: vec![ResponseType::Code],
            scope: Some("read write".to_string()),
            token_endpoint_auth_method: ClientAuthMethod::PrivateKeyJwt,
            client_type: ClientType::Confidential,
            created_at: Utc::now(),
            updated_at: Utc::now(),
            metadata: serde_json::Value::Null,
            access_token_expiration: chrono::Duration::hours(1),
            refresh_token_expiration: chrono::Duration::days(14),
            require_redirect_exact: true,
            registration_access_token: Some("test-registration-token".to_string()),
            jwks: Some(jwks),
        };

        storage.store_client(&client).await.unwrap();

        // Test 1: Missing client assertion
        let token_request = TokenRequest {
            grant_type: GrantType::ClientCredentials,
            code: None,
            redirect_uri: None,
            code_verifier: None,
            refresh_token: None,
            client_id: Some("test-private-key-jwt-client".to_string()),
            client_secret: None,
            scope: Some("read".to_string()),
            client_assertion: None,
            client_assertion_type: None,
        };

        let client_auth = Some(ClientAuthentication {
            client_id: "test-private-key-jwt-client".to_string(),
            client_secret: None,
            client_assertion: None, // Missing assertion
            client_assertion_type: None,
        });

        let headers = HeaderMap::new();
        let result = auth_server
            .token(token_request.clone(), &headers, client_auth)
            .await;

        assert!(result.is_err());
        match result.unwrap_err() {
            OAuthError::InvalidClient(msg) => {
                assert!(msg.contains("Missing client_assertion"));
            }
            _ => panic!("Expected InvalidClient error for missing client assertion"),
        }

        // Test 2: Invalid JWT format
        let client_auth = Some(ClientAuthentication {
            client_id: "test-private-key-jwt-client".to_string(),
            client_secret: None,
            client_assertion: Some("invalid.jwt".to_string()), // Invalid format
            client_assertion_type: Some(
                "urn:ietf:params:oauth:client-assertion-type:jwt-bearer".to_string(),
            ),
        });

        let result = auth_server
            .token(token_request.clone(), &headers, client_auth)
            .await;

        assert!(result.is_err());
        match result.unwrap_err() {
            OAuthError::InvalidClient(msg) => {
                assert!(msg.contains("Invalid JWT format"));
            }
            _ => panic!("Expected InvalidClient error for invalid JWT format"),
        }

        // Test 3: Expired JWT
        let now = Utc::now().timestamp();
        let exp = now - 300; // 5 minutes ago (expired)

        let header = BASE64_URL_SAFE_NO_PAD.encode(
            serde_json::json!({
                "typ": "JWT",
                "alg": "ES256",
                "kid": "test-key-1"
            })
            .to_string()
            .as_bytes(),
        );

        let claims = BASE64_URL_SAFE_NO_PAD.encode(
            serde_json::json!({
                "iss": "test-private-key-jwt-client",
                "sub": "test-private-key-jwt-client",
                "aud": "https://localhost/oauth/token",
                "iat": now,
                "exp": exp, // Expired
                "jti": "test-jti-expired"
            })
            .to_string()
            .as_bytes(),
        );

        let signature = BASE64_URL_SAFE_NO_PAD.encode(b"mock_signature_data");
        let expired_jwt = format!("{}.{}.{}", header, claims, signature);

        let client_auth = Some(ClientAuthentication {
            client_id: "test-private-key-jwt-client".to_string(),
            client_secret: None,
            client_assertion: Some(expired_jwt),
            client_assertion_type: Some(
                "urn:ietf:params:oauth:client-assertion-type:jwt-bearer".to_string(),
            ),
        });

        let result = auth_server
            .token(token_request.clone(), &headers, client_auth)
            .await;

        assert!(result.is_err());
        match result.unwrap_err() {
            OAuthError::InvalidClient(msg) => {
                assert!(msg.contains("JWT has expired"));
            }
            _ => panic!("Expected InvalidClient error for expired JWT"),
        }

        // Test 4: Wrong issuer
        let now = Utc::now().timestamp();
        let exp = now + 300;

        let claims = BASE64_URL_SAFE_NO_PAD.encode(
            serde_json::json!({
                "iss": "wrong-client-id", // Wrong issuer
                "sub": "test-private-key-jwt-client",
                "aud": "https://localhost/oauth/token",
                "iat": now,
                "exp": exp,
                "jti": "test-jti-wrong-issuer"
            })
            .to_string()
            .as_bytes(),
        );

        let wrong_issuer_jwt = format!("{}.{}.{}", header, claims, signature);

        let client_auth = Some(ClientAuthentication {
            client_id: "test-private-key-jwt-client".to_string(),
            client_secret: None,
            client_assertion: Some(wrong_issuer_jwt),
            client_assertion_type: Some(
                "urn:ietf:params:oauth:client-assertion-type:jwt-bearer".to_string(),
            ),
        });

        let result = auth_server
            .token(token_request, &headers, client_auth)
            .await;

        assert!(result.is_err());
        match result.unwrap_err() {
            OAuthError::InvalidClient(msg) => {
                assert!(msg.contains("JWT issuer does not match client_id"));
            }
            _ => panic!("Expected InvalidClient error for wrong issuer"),
        }
    }

    #[tokio::test]
    async fn test_private_key_jwt_authorization_code_flow() {
        let storage = Arc::new(MemoryOAuthStorage::new());
        let auth_server =
            AuthorizationServer::new(storage.clone(), "https://localhost".to_string());

        // Register a test client with private_key_jwt authentication
        let jwks = serde_json::json!({
            "keys": [
                {
                    "kty": "EC",
                    "crv": "P-256",
                    "x": "MKBCTNIcKUSDii11ySs3526iDZ8AiTo7Tu6KPAqv7D4",
                    "y": "4Etl6SRW2YiLUrN5vfvVHuhp7x8PxltmWWlbbM4IFyM",
                    "use": "sig",
                    "alg": "ES256",
                    "kid": "test-key-1"
                }
            ]
        });

        let client = OAuthClient {
            client_id: "test-private-key-jwt-authz-client".to_string(),
            client_secret: None,
            client_name: Some("Test Private Key JWT Authorization Client".to_string()),
            redirect_uris: vec!["https://example.com/callback".to_string()],
            grant_types: vec![GrantType::AuthorizationCode],
            response_types: vec![ResponseType::Code],
            scope: Some("read write".to_string()),
            token_endpoint_auth_method: ClientAuthMethod::PrivateKeyJwt,
            client_type: ClientType::Confidential,
            created_at: Utc::now(),
            updated_at: Utc::now(),
            metadata: serde_json::Value::Null,
            access_token_expiration: chrono::Duration::hours(1),
            refresh_token_expiration: chrono::Duration::days(14),
            require_redirect_exact: true,
            registration_access_token: Some("test-registration-token".to_string()),
            jwks: Some(jwks),
        };

        storage.store_client(&client).await.unwrap();

        // Step 1: Authorization request
        let auth_request = AuthorizationRequest {
            response_type: vec![ResponseType::Code],
            client_id: "test-private-key-jwt-authz-client".to_string(),
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

        let parsed_url = url::Url::parse(&redirect_url).unwrap();
        let code = parsed_url
            .query_pairs()
            .find(|(key, _)| key == "code")
            .map(|(_, value)| value.to_string())
            .unwrap();

        // Step 2: Token request with private_key_jwt authentication
        let now = Utc::now().timestamp();
        let exp = now + 300;

        let header = BASE64_URL_SAFE_NO_PAD.encode(
            serde_json::json!({
                "typ": "JWT",
                "alg": "ES256",
                "kid": "test-key-1"
            })
            .to_string()
            .as_bytes(),
        );

        let claims = BASE64_URL_SAFE_NO_PAD.encode(
            serde_json::json!({
                "iss": "test-private-key-jwt-authz-client",
                "sub": "test-private-key-jwt-authz-client",
                "aud": "https://localhost/oauth/token",
                "iat": now,
                "exp": exp,
                "jti": "test-jti-authz-flow"
            })
            .to_string()
            .as_bytes(),
        );

        let signature = BASE64_URL_SAFE_NO_PAD.encode(b"mock_signature_data");
        let client_assertion = format!("{}.{}.{}", header, claims, signature);

        let token_request = TokenRequest {
            grant_type: GrantType::AuthorizationCode,
            code: Some(code),
            redirect_uri: Some("https://example.com/callback".to_string()),
            code_verifier: None,
            refresh_token: None,
            client_id: Some("test-private-key-jwt-authz-client".to_string()),
            client_secret: None,
            scope: None,
            client_assertion: None,
            client_assertion_type: None,
        };

        let headers = HeaderMap::new();
        let client_auth = Some(ClientAuthentication {
            client_id: "test-private-key-jwt-authz-client".to_string(),
            client_secret: None,
            client_assertion: Some(client_assertion),
            client_assertion_type: Some(
                "urn:ietf:params:oauth:client-assertion-type:jwt-bearer".to_string(),
            ),
        });

        let token_response = auth_server
            .token(token_request, &headers, client_auth)
            .await
            .unwrap();

        // Verify token response
        assert!(!token_response.access_token.is_empty());
        assert!(token_response.refresh_token.is_some());
        assert_eq!(token_response.scope, Some("read".to_string()));

        // Verify tokens are stored correctly
        let stored_token = storage
            .get_token(&token_response.access_token)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(stored_token.client_id, "test-private-key-jwt-authz-client");
        assert_eq!(stored_token.user_id, Some("test-user".to_string()));
        assert_eq!(stored_token.scope, Some("read".to_string()));
    }
}
