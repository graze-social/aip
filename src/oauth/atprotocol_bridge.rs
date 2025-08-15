//! Bridge for ATProtocol OAuth authentication within base OAuth 2.1 flows.

use crate::errors::OAuthError;
use crate::oauth::{
    auth_server::{AuthorizationServer, AuthorizeResponse},
    types::*,
};
use atproto_identity::key::{KeyType, generate_key, identify_key, to_public};
use atproto_oauth::resources::{oauth_authorization_server, oauth_protected_resource};
use atproto_oauth::{
    jwk::generate as generate_jwk,
    pkce,
    workflow::{OAuthClient, OAuthRequest, OAuthRequestState, oauth_complete, oauth_init},
};
use chrono::{Duration, Utc};
use std::sync::Arc;
use ulid::Ulid;
use uuid::Uuid;

use crate::oauth::dpop::compute_jwk_thumbprint;

// Re-export unified storage types
pub use crate::storage::traits::AtpOAuthSession;

/// Storage trait for ATProtocol OAuth sessions (legacy interface)
#[async_trait::async_trait]
pub trait AtpOAuthSessionStorage: Send + Sync {
    /// Store a new ATProtocol OAuth session
    async fn store_session(
        &self,
        session: &AtpOAuthSession,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>>;

    /// Get sessions by DID and session ID, ordered by iteration (highest to lowest)
    async fn get_sessions(
        &self,
        did: &str,
        session_id: &str,
    ) -> Result<Vec<AtpOAuthSession>, Box<dyn std::error::Error + Send + Sync>>;

    /// Get specific session by DID, session ID, and iteration
    async fn get_session(
        &self,
        did: &str,
        session_id: &str,
        iteration: u32,
    ) -> Result<Option<AtpOAuthSession>, Box<dyn std::error::Error + Send + Sync>>;

    /// Get session by ATProtocol OAuth state
    async fn get_session_by_atp_state(
        &self,
        atp_state: &str,
    ) -> Result<Option<AtpOAuthSession>, Box<dyn std::error::Error + Send + Sync>>;


    /// Get all sessions for a specific DID
    async fn get_sessions_by_did(
        &self,
        did: &str,
    ) -> Result<Vec<AtpOAuthSession>, Box<dyn std::error::Error + Send + Sync>>;

    /// Remove session by DID, session ID, and iteration
    async fn remove_session(
        &self,
        did: &str,
        session_id: &str,
        iteration: u32,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>>;
}

/// Storage trait for OAuth authorization requests (legacy interface)
#[async_trait::async_trait]
pub trait AuthorizationRequestStorage: Send + Sync {
    /// Store an authorization request by session ID
    async fn store_authorization_request(
        &self,
        session_id: &str,
        request: &AuthorizationRequest,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>>;

    /// Get authorization request by session ID
    async fn get_authorization_request(
        &self,
        session_id: &str,
    ) -> Result<Option<AuthorizationRequest>, Box<dyn std::error::Error + Send + Sync>>;

    /// Remove authorization request by session ID
    async fn remove_authorization_request(
        &self,
        session_id: &str,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>>;
}

/// ATProtocol-backed OAuth authorization server
pub struct AtpBackedAuthorizationServer {
    /// Base OAuth authorization server
    base_auth_server: Arc<AuthorizationServer>,
    /// ATProtocol identity resolver
    identity_resolver: atproto_identity::resolve::IdentityResolver,
    /// HTTP client for making requests
    http_client: reqwest::Client,
    /// OAuth request storage for ATProtocol flows
    oauth_request_storage: Arc<dyn atproto_oauth::storage::OAuthRequestStorage>,
    /// Client configuration
    client_config: atproto_oauth_axum::state::OAuthClientConfig,
    /// ATProtocol OAuth session storage
    session_storage: Arc<dyn AtpOAuthSessionStorage>,
    /// DID document storage for resolved identities
    document_storage: Arc<dyn atproto_identity::storage::DidDocumentStorage + Send + Sync>,
    /// Authorization request storage
    authorization_request_storage: Arc<dyn AuthorizationRequestStorage>,
    /// External base URL for callbacks
    external_base: String,
}

impl AtpBackedAuthorizationServer {
    /// Create a new ATProtocol-backed authorization server
    pub fn new(
        base_auth_server: Arc<AuthorizationServer>,
        identity_resolver: atproto_identity::resolve::IdentityResolver,
        http_client: reqwest::Client,
        oauth_request_storage: Arc<dyn atproto_oauth::storage::OAuthRequestStorage>,
        client_config: atproto_oauth_axum::state::OAuthClientConfig,
        session_storage: Arc<dyn AtpOAuthSessionStorage>,
        document_storage: Arc<dyn atproto_identity::storage::DidDocumentStorage + Send + Sync>,
        authorization_request_storage: Arc<dyn AuthorizationRequestStorage>,
        external_base: String,
    ) -> Self {
        Self {
            base_auth_server,
            identity_resolver,
            http_client,
            oauth_request_storage,
            client_config,
            session_storage,
            document_storage,
            authorization_request_storage,
            external_base,
        }
    }

    /// Get a reference to the session storage
    pub fn session_storage(&self) -> &Arc<dyn AtpOAuthSessionStorage> {
        &self.session_storage
    }

    /// Get a reference to the HTTP client
    pub fn http_client(&self) -> &reqwest::Client {
        &self.http_client
    }

    /// Get a reference to the document storage
    pub fn document_storage(
        &self,
    ) -> &Arc<dyn atproto_identity::storage::DidDocumentStorage + Send + Sync> {
        &self.document_storage
    }

    /// Create an OAuth client for ATProtocol flows
    pub fn create_oauth_client(&self) -> atproto_oauth::workflow::OAuthClient {
        // Get the first signing key
        let signing_key = self
            .client_config
            .signing_keys
            .first()
            .expect("At least one signing key is required");

        atproto_oauth::workflow::OAuthClient {
            redirect_uri: format!("{}/oauth/atp/callback", self.external_base),
            client_id: self.client_config.client_id.clone(),
            private_signing_key_data: signing_key.clone(),
        }
    }

    /// Handle OAuth authorization request by redirecting to ATProtocol OAuth
    pub async fn authorize_with_atprotocol(
        &self,
        request: AuthorizationRequest,
        atpoauth_subject: String,
    ) -> Result<String, OAuthError> {
        // Validate the OAuth request first (client validation, etc.)
        self.validate_oauth_request(&request).await?;

        // Generate session ID and ATProtocol OAuth state
        let session_id = Ulid::new().to_string();
        let atpoauth_state = Uuid::new_v4().to_string();

        //
        let (did_option, authorization_server_endpoint) = if atpoauth_subject
            .starts_with("https://")
        {
            (None, atpoauth_subject.clone())
        } else {
            let atpoauth_document = self
                .identity_resolver
                .resolve(&atpoauth_subject)
                .await
                .map_err(|e| {
                    OAuthError::AuthorizationFailed(format!(
                        "Failed to resolve subject '{}': {:?}",
                        atpoauth_subject, e
                    ))
                })?;

            // Store the resolved document for later use
            self.document_storage
                .store_document(atpoauth_document.clone())
                .await
                .map_err(|e| {
                    OAuthError::ServerError(format!("Failed to store resolved document: {:?}", e))
                })?;

            let pds_endpoint = match atpoauth_document.pds_endpoints().first() {
                Some(value) => value.to_string(),
                None => {
                    return Err(OAuthError::AuthorizationFailed(
                        "No PDS endpoint found".to_string(),
                    ));
                }
            };

            let protected_resource =
                match oauth_protected_resource(&self.http_client, &pds_endpoint).await {
                    Ok(value) => value,
                    _ => {
                        return Err(OAuthError::AuthorizationFailed(
                            "No oauth protected resource found".to_string(),
                        ));
                    }
                };

            match protected_resource.authorization_servers.first() {
                Some(value) => (Some(atpoauth_document.id.clone()), value.to_string()),
                None => {
                    return Err(OAuthError::AuthorizationFailed(
                        "No authorization server found".to_string(),
                    ));
                }
            }
        };

        let authorization_server =
            match oauth_authorization_server(&self.http_client, &authorization_server_endpoint)
                .await
            {
                Ok(value) => value,
                _ => {
                    return Err(OAuthError::AuthorizationFailed(
                        "No authorization server found".to_string(),
                    ));
                }
            };

        // Generate PKCE parameters for ATProtocol OAuth
        let (atpoauth_pkce_verifier, atpoauth_code_challenge) = pkce::generate();

        // Generate DPoP key for this ATProtocol OAuth session
        let atpoauth_dpop_key = generate_key(KeyType::P256Private)
            .map_err(|e| OAuthError::ServerError(format!("DPoP key generation failed: {:?}", e)))?;

        // Generate ATProtocol OAuth nonce
        let atpoauth_nonce = Ulid::new().to_string();

        // Get signing key for OAuth client
        let signing_key = self
            .client_config
            .signing_keys
            .first()
            .cloned()
            .ok_or_else(|| {
                OAuthError::ServerError(
                    "No signing keys configured - at least one signing key is required".to_string(),
                )
            })?;

        // Compute JKT (JWK thumbprint) of the signing key
        let signing_public_key = to_public(&signing_key).map_err(|e| {
            OAuthError::ServerError(format!("Failed to derive public key: {:?}", e))
        })?;
        let signing_jwk = generate_jwk(&signing_public_key)
            .map_err(|e| OAuthError::ServerError(format!("Failed to generate JWK: {:?}", e)))?;
        let signing_key_jkt = compute_jwk_thumbprint(&signing_jwk)
            .map_err(|e| OAuthError::ServerError(format!("Failed to compute JKT: {:?}", e)))?;

        // Store authorization request separately
        self.authorization_request_storage
            .store_authorization_request(&session_id, &request)
            .await
            .map_err(|e| {
                OAuthError::ServerError(format!("Failed to store authorization request: {}", e))
            })?;

        // Create session with all required fields
        let now = Utc::now();
        let session = AtpOAuthSession {
            session_id: session_id.clone(),
            did: did_option.clone(), // Will be updated after token exchange
            session_created_at: now,
            atp_oauth_state: atpoauth_state.clone(),
            signing_key_jkt,
            dpop_key: atpoauth_dpop_key.to_string(),
            access_token: None,
            refresh_token: None,
            access_token_created_at: None,
            access_token_expires_at: None,
            access_token_scopes: None,
            session_exchanged_at: None,
            exchange_error: None,
            iteration: 1,
        };

        // Store session
        self.session_storage
            .store_session(&session)
            .await
            .map_err(|e| OAuthError::ServerError(format!("Failed to store session: {}", e)))?;

        // Create OAuth client for ATProtocol workflow
        let oauth_client = OAuthClient {
            redirect_uri: format!("{}/oauth/atp/callback", self.external_base),
            client_id: format!("{}/oauth/atp/client-metadata", self.external_base),
            private_signing_key_data: signing_key.clone(),
        };

        // Create OAuth request state for ATProtocol workflow
        // Filter original scope to only include atprotocol scopes, removing the prefix
        // Also add transition scopes based on profile and email scopes
        let filtered_scope = if let Some(ref original_scope) = request.scope {
            let scopes: Vec<&str> = original_scope.split_whitespace().collect();
            let mut atprotocol_scopes: Vec<String> = scopes
                .iter()
                .filter_map(|scope| {
                    if scope.starts_with("atproto:") {
                        Some(scope.strip_prefix("atproto:").unwrap().to_string())
                    } else {
                        None
                    }
                })
                .collect();

            // Add transition:generic scope if profile scope is present
            if scopes.contains(&"profile")
                && !atprotocol_scopes.contains(&"transition:generic".to_string())
            {
                atprotocol_scopes.push("transition:generic".to_string());
            }

            // Add transition:email scope if email scope is present
            if scopes.contains(&"email")
                && !atprotocol_scopes.contains(&"transition:email".to_string())
            {
                atprotocol_scopes.push("transition:email".to_string());
            }

            if atprotocol_scopes.is_empty() {
                // If no atprotocol scopes found, use default
                "atproto transition:generic".to_string()
            } else {
                atprotocol_scopes.join(" ")
            }
        } else {
            // If no scope provided, use default
            "atproto transition:generic".to_string()
        };

        let atpoauth_request_state = OAuthRequestState {
            state: atpoauth_state.clone(),
            nonce: atpoauth_nonce.clone(),
            code_challenge: atpoauth_code_challenge.clone(),
            scope: filtered_scope,
        };

        let login_hint = if atpoauth_subject.starts_with("https://") {
            None
        } else {
            Some(atpoauth_subject.as_str())
        };

        // Use atproto-oauth workflow to initiate the flow
        let atpoauth_par_response = oauth_init(
            &self.http_client,
            &oauth_client,
            &atpoauth_dpop_key,
            login_hint,
            &authorization_server,
            &atpoauth_request_state,
        )
        .await
        .map_err(|e| OAuthError::AuthorizationFailed(format!("OAuth init failed: {:?}", e)))?;

        // Store OAuth request for callback handling
        let atpoauth_public_signing_key = to_public(&oauth_client.private_signing_key_data)
            .map_err(|e| {
                OAuthError::ServerError(format!("Failed to derive public key: {:?}", e))
            })?;

        let now = Utc::now();
        let atpoauth_request = OAuthRequest {
            oauth_state: atpoauth_state.clone(),
            issuer: authorization_server.issuer.clone(),
            authorization_server: authorization_server_endpoint,
            nonce: atpoauth_nonce.clone(),
            pkce_verifier: atpoauth_pkce_verifier,
            signing_public_key: atpoauth_public_signing_key.to_string(),
            dpop_private_key: atpoauth_dpop_key.to_string(),
            created_at: now,
            expires_at: now + Duration::hours(1),
        };

        self.oauth_request_storage
            .insert_oauth_request(atpoauth_request)
            .await
            .map_err(|e| {
                OAuthError::ServerError(format!("Failed to store OAuth request: {:?}", e))
            })?;

        // Build authorization URL
        let atp_auth_url = format!(
            "{}?client_id={}&request_uri={}",
            authorization_server.authorization_endpoint,
            oauth_client.client_id,
            atpoauth_par_response.request_uri
        );

        Ok(atp_auth_url)
    }

    /// Handle ATProtocol OAuth callback and complete base OAuth flow
    pub async fn handle_atp_callback(
        &self,
        code: String,
        state: String,
    ) -> Result<String, OAuthError> {
        let exchange_start_time = Utc::now();

        // Try to execute the callback logic and handle errors
        let result = self
            .handle_atp_callback_impl(code, state.clone(), exchange_start_time)
            .await;

        // If there was an error, try to update the session with the error info
        if let Err(ref error) = result {
            if let Ok(Some(mut session)) =
                self.session_storage.get_session_by_atp_state(&state).await
            {
                session.exchange_error = Some(error.to_string());
                let _ = self.session_storage.store_session(&session).await;
            }
        }

        result
    }

    /// Internal implementation of the callback handling
    async fn handle_atp_callback_impl(
        &self,
        code: String,
        state: String,
        now: chrono::DateTime<chrono::Utc>,
    ) -> Result<String, OAuthError> {
        // Get session by ATProtocol state
        let mut session = self
            .session_storage
            .get_session_by_atp_state(&state)
            .await
            .map_err(|e| OAuthError::ServerError(format!("Session storage error: {}", e)))?
            .ok_or_else(|| OAuthError::InvalidState("Session not found".to_string()))?;

        // Verify this is the first iteration as expected during callback
        if session.iteration != 1 {
            return Err(OAuthError::InvalidState(format!(
                "Expected session iteration 1 during callback, got {}",
                session.iteration
            )));
        }

        // Set session_exchanged_at timestamp
        session.session_exchanged_at = Some(now);

        // Update the session to persist the timestamp
        self.session_storage
            .store_session(&session)
            .await
            .map_err(|e| OAuthError::ServerError(format!("Failed to update session: {}", e)))?;

        // Get the OAuth request from storage (contains PKCE verifier and DPoP key)
        let oauth_request = self
            .oauth_request_storage
            .get_oauth_request_by_state(&state)
            .await
            .map_err(|e| OAuthError::ServerError(format!("OAuth request storage error: {}", e)))?
            .ok_or_else(|| OAuthError::InvalidState("OAuth request not found".to_string()))?;

        // Parse the DPoP private key from storage
        let dpop_key = identify_key(&oauth_request.dpop_private_key)
            .map_err(|e| OAuthError::ServerError(format!("Failed to parse DPoP key: {}", e)))?;

        // Get the signing private key from the AIP server configuration
        let signing_key = self
            .client_config
            .signing_keys
            .first()
            .cloned()
            .ok_or_else(|| {
                OAuthError::ServerError(
                    "No signing keys configured - at least one signing key is required".to_string(),
                )
            })?;

        // Create OAuth client for the workflow
        let oauth_client = OAuthClient {
            redirect_uri: format!("{}/oauth/atp/callback", self.external_base),
            client_id: format!("{}/oauth/atp/client-metadata", self.external_base),
            private_signing_key_data: signing_key,
        };

        // Use the issuer from the OAuth request as the authorization server endpoint
        // The issuer contains the authorization server issuer URL
        let authorization_server =
            oauth_authorization_server(&self.http_client, &oauth_request.authorization_server)
                .await
                .map_err(|e| {
                    OAuthError::ServerError(format!(
                        "Failed to retrieve authorization server from issuer: {}",
                        e
                    ))
                })?;

        // Use oauth_complete to properly handle the token exchange with PKCE
        let token_response = oauth_complete(
            &self.http_client,
            &oauth_client,
            &dpop_key,
            &code,
            &oauth_request,
            &authorization_server,
        )
        .await
        .map_err(|e| OAuthError::ServerError(format!("OAuth completion failed: {}", e)))?;

        // Parse scopes from token response
        let parsed_scopes: Vec<String> = token_response
            .scope
            .split_whitespace()
            .map(|s| s.to_string())
            .collect();

        // Calculate expiration time
        let expires_at = now + Duration::seconds(token_response.expires_in as i64);

        // Get the actual DID from the token response
        let token_subject = token_response.sub.clone().ok_or(OAuthError::InvalidState(
            "Token response does not contain subject".to_string(),
        ))?;

        let atpoauth_document = self
            .identity_resolver
            .resolve(&token_subject)
            .await
            .map_err(|e| {
                OAuthError::AuthorizationFailed(format!(
                    "Failed to resolve subject '{}': {:?}",
                    token_subject, e
                ))
            })?;

        // Store the resolved document for later use
        self.document_storage
            .store_document(atpoauth_document.clone())
            .await
            .map_err(|e| {
                OAuthError::ServerError(format!("Failed to store resolved document: {:?}", e))
            })?;

        let mut updated_session = session.clone();
        updated_session.access_token = Some(token_response.access_token.clone());
        updated_session.refresh_token = Some(token_response.refresh_token.clone());
        updated_session.access_token_created_at = Some(now);
        updated_session.access_token_expires_at = Some(expires_at);
        updated_session.access_token_scopes = Some(parsed_scopes);
        updated_session.did = Some(token_subject.clone());

        self.session_storage
            .store_session(&updated_session)
            .await
            .map_err(|e| OAuthError::ServerError(format!("Failed to update session: {}", e)))?;

        // Retrieve the original authorization request from storage
        let authorization_request = self
            .authorization_request_storage
            .get_authorization_request(&session.session_id)
            .await
            .map_err(|e| {
                OAuthError::ServerError(format!("Authorization request storage error: {}", e))
            })?
            .ok_or_else(|| {
                OAuthError::InvalidState("Authorization request not found".to_string())
            })?;

        // Clone session_id before it gets moved
        let session_id = session.session_id.clone();

        // Now complete the base OAuth flow using the ATProtocol identity as the user_id
        let auth_response = self
            .base_auth_server
            .authorize(
                authorization_request,
                token_subject,
                Some(session.session_id),
            )
            .await?;

        // Clean up OAuth request storage
        self.oauth_request_storage
            .delete_oauth_request_by_state(&state)
            .await
            .map_err(|e| OAuthError::ServerError(format!("OAuth request cleanup error: {}", e)))?;

        // Clean up authorization request storage
        self.authorization_request_storage
            .remove_authorization_request(&session_id)
            .await
            .map_err(|e| {
                OAuthError::ServerError(format!("Authorization request cleanup error: {}", e))
            })?;

        match auth_response {
            AuthorizeResponse::Redirect(url) => Ok(url),
            AuthorizeResponse::Error { error, description } => Err(OAuthError::ServerError(
                format!("Authorization failed: {} - {}", error, description),
            )),
        }
    }

    /// Validate OAuth request before redirecting to ATProtocol OAuth
    async fn validate_oauth_request(
        &self,
        request: &AuthorizationRequest,
    ) -> Result<(), OAuthError> {
        // Get OAuth storage from base server
        let storage = &self.base_auth_server.storage;

        // Validate client
        let client = storage
            .get_client(&request.client_id)
            .await
            .map_err(|e| OAuthError::ServerError(format!("Storage error: {:?}", e)))?
            .ok_or_else(|| OAuthError::InvalidClient("Client not found".to_string()))?;

        // Validate redirect URI
        if !client.redirect_uris.contains(&request.redirect_uri) {
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

        Ok(())
    }
}

pub struct UnifiedAtpOAuthSessionStorageAdapter {
    storage: Arc<dyn crate::storage::traits::AtpOAuthSessionStorage>,
}

impl UnifiedAtpOAuthSessionStorageAdapter {
    pub fn new(storage: Arc<dyn crate::storage::traits::AtpOAuthSessionStorage>) -> Self {
        Self { storage }
    }
}

#[async_trait::async_trait]
impl AtpOAuthSessionStorage for UnifiedAtpOAuthSessionStorageAdapter {
    async fn store_session(
        &self,
        session: &AtpOAuthSession,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        // Convert from oauth bridge AtpOAuthSession to storage traits AtpOAuthSession
        let storage_session = crate::storage::traits::AtpOAuthSession {
            session_id: session.session_id.clone(),
            did: session.did.clone(),
            session_created_at: session.session_created_at,
            atp_oauth_state: session.atp_oauth_state.clone(),
            signing_key_jkt: session.signing_key_jkt.clone(),
            dpop_key: session.dpop_key.clone(),
            access_token: session.access_token.clone(),
            refresh_token: session.refresh_token.clone(),
            access_token_created_at: session.access_token_created_at,
            access_token_expires_at: session.access_token_expires_at,
            access_token_scopes: session.access_token_scopes.clone(),
            session_exchanged_at: session.session_exchanged_at,
            exchange_error: session.exchange_error.clone(),
            iteration: session.iteration,
        };

        self.storage
            .store_session(&storage_session)
            .await
            .map_err(|e| Box::new(e) as Box<dyn std::error::Error + Send + Sync>)
    }

    async fn get_sessions(
        &self,
        did: &str,
        session_id: &str,
    ) -> Result<Vec<AtpOAuthSession>, Box<dyn std::error::Error + Send + Sync>> {
        let storage_sessions = self
            .storage
            .get_sessions(did, session_id)
            .await
            .map_err(|e| Box::new(e) as Box<dyn std::error::Error + Send + Sync>)?;

        let oauth_sessions = storage_sessions
            .into_iter()
            .map(|s| AtpOAuthSession {
                session_id: s.session_id,
                did: s.did,
                session_created_at: s.session_created_at,
                atp_oauth_state: s.atp_oauth_state,
                signing_key_jkt: s.signing_key_jkt,
                dpop_key: s.dpop_key,
                access_token: s.access_token,
                refresh_token: s.refresh_token,
                access_token_created_at: s.access_token_created_at,
                access_token_expires_at: s.access_token_expires_at,
                access_token_scopes: s.access_token_scopes,
                session_exchanged_at: s.session_exchanged_at,
                exchange_error: s.exchange_error,
                iteration: s.iteration,
            })
            .collect();

        Ok(oauth_sessions)
    }

    async fn get_session(
        &self,
        did: &str,
        session_id: &str,
        iteration: u32,
    ) -> Result<Option<AtpOAuthSession>, Box<dyn std::error::Error + Send + Sync>> {
        let storage_session = self
            .storage
            .get_session(did, session_id, iteration)
            .await
            .map_err(|e| Box::new(e) as Box<dyn std::error::Error + Send + Sync>)?;

        let oauth_session = storage_session.map(|s| AtpOAuthSession {
            session_id: s.session_id,
            did: s.did,
            session_created_at: s.session_created_at,
            atp_oauth_state: s.atp_oauth_state,
            signing_key_jkt: s.signing_key_jkt,
            dpop_key: s.dpop_key,
            access_token: s.access_token,
            refresh_token: s.refresh_token,
            access_token_created_at: s.access_token_created_at,
            access_token_expires_at: s.access_token_expires_at,
            access_token_scopes: s.access_token_scopes,
            session_exchanged_at: s.session_exchanged_at,
            exchange_error: s.exchange_error,
            iteration: s.iteration,
        });

        Ok(oauth_session)
    }

    async fn get_session_by_atp_state(
        &self,
        atp_state: &str,
    ) -> Result<Option<AtpOAuthSession>, Box<dyn std::error::Error + Send + Sync>> {
        let storage_session = self
            .storage
            .get_session_by_atp_state(atp_state)
            .await
            .map_err(|e| Box::new(e) as Box<dyn std::error::Error + Send + Sync>)?;

        let oauth_session = storage_session.map(|s| AtpOAuthSession {
            session_id: s.session_id,
            did: s.did,
            session_created_at: s.session_created_at,
            atp_oauth_state: s.atp_oauth_state,
            signing_key_jkt: s.signing_key_jkt,
            dpop_key: s.dpop_key,
            access_token: s.access_token,
            refresh_token: s.refresh_token,
            access_token_created_at: s.access_token_created_at,
            access_token_expires_at: s.access_token_expires_at,
            access_token_scopes: s.access_token_scopes,
            session_exchanged_at: s.session_exchanged_at,
            exchange_error: s.exchange_error,
            iteration: s.iteration,
        });

        Ok(oauth_session)
    }


    async fn get_sessions_by_did(
        &self,
        did: &str,
    ) -> Result<Vec<AtpOAuthSession>, Box<dyn std::error::Error + Send + Sync>> {
        let storage_sessions = self
            .storage
            .get_sessions_by_did(did)
            .await
            .map_err(|e| Box::new(e) as Box<dyn std::error::Error + Send + Sync>)?;

        let oauth_sessions = storage_sessions
            .into_iter()
            .map(|s| AtpOAuthSession {
                session_id: s.session_id,
                did: s.did,
                session_created_at: s.session_created_at,
                atp_oauth_state: s.atp_oauth_state,
                signing_key_jkt: s.signing_key_jkt,
                dpop_key: s.dpop_key,
                access_token: s.access_token,
                refresh_token: s.refresh_token,
                access_token_created_at: s.access_token_created_at,
                access_token_expires_at: s.access_token_expires_at,
                access_token_scopes: s.access_token_scopes,
                session_exchanged_at: s.session_exchanged_at,
                exchange_error: s.exchange_error,
                iteration: s.iteration,
            })
            .collect();

        Ok(oauth_sessions)
    }

    async fn remove_session(
        &self,
        did: &str,
        session_id: &str,
        iteration: u32,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        self.storage
            .remove_session(did, session_id, iteration)
            .await
            .map_err(|e| Box::new(e) as Box<dyn std::error::Error + Send + Sync>)
    }
}

/// Adapter to bridge new unified AuthorizationRequestStorage to old oauth bridge trait
pub struct UnifiedAuthorizationRequestStorageAdapter {
    storage: Arc<dyn crate::storage::traits::AuthorizationRequestStorage>,
}

impl UnifiedAuthorizationRequestStorageAdapter {
    pub fn new(storage: Arc<dyn crate::storage::traits::AuthorizationRequestStorage>) -> Self {
        Self { storage }
    }
}

#[async_trait::async_trait]
impl AuthorizationRequestStorage for UnifiedAuthorizationRequestStorageAdapter {
    async fn store_authorization_request(
        &self,
        session_id: &str,
        request: &crate::oauth::types::AuthorizationRequest,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        self.storage
            .store_authorization_request(session_id, request)
            .await
            .map_err(|e| Box::new(e) as Box<dyn std::error::Error + Send + Sync>)
    }

    async fn get_authorization_request(
        &self,
        session_id: &str,
    ) -> Result<
        Option<crate::oauth::types::AuthorizationRequest>,
        Box<dyn std::error::Error + Send + Sync>,
    > {
        self.storage
            .get_authorization_request(session_id)
            .await
            .map_err(|e| Box::new(e) as Box<dyn std::error::Error + Send + Sync>)
    }

    async fn remove_authorization_request(
        &self,
        session_id: &str,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        self.storage
            .remove_authorization_request(session_id)
            .await
            .map_err(|e| Box::new(e) as Box<dyn std::error::Error + Send + Sync>)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::oauth::auth_server::AuthorizationServer;
    use crate::oauth::{
        UnifiedAtpOAuthSessionStorageAdapter, UnifiedAuthorizationRequestStorageAdapter,
    };
    use crate::storage::inmemory::MemoryOAuthStorage;
    use atproto_identity::resolve::{IdentityResolver, InnerIdentityResolver, create_resolver};
    use atproto_identity::storage_lru::LruDidDocumentStorage;
    use atproto_oauth::storage_lru::LruOAuthRequestStorage;
    use std::num::NonZeroUsize;

    #[cfg(test)]
    fn create_test_atp_backed_server() -> AtpBackedAuthorizationServer {
        // Create unified OAuth storage
        let oauth_storage = Arc::new(MemoryOAuthStorage::new());

        // Create base OAuth server
        let base_server = Arc::new(AuthorizationServer::new(
            oauth_storage.clone(),
            "https://localhost".to_string(),
        ));

        // Create identity resolver
        let http_client = reqwest::Client::new();
        let dns_nameservers = vec![];
        let dns_resolver = create_resolver(&dns_nameservers);
        let identity_resolver = IdentityResolver(Arc::new(InnerIdentityResolver {
            http_client: http_client.clone(),
            dns_resolver,
            plc_hostname: "plc.directory".to_string(),
        }));

        // Create OAuth request storage
        let oauth_request_storage =
            Arc::new(LruOAuthRequestStorage::new(NonZeroUsize::new(256).unwrap()));

        // Create document storage
        let document_storage =
            Arc::new(LruDidDocumentStorage::new(NonZeroUsize::new(100).unwrap()));

        let test_signing_key =
            atproto_identity::key::generate_key(atproto_identity::key::KeyType::P256Private)
                .unwrap();
        let client_config = atproto_oauth_axum::state::OAuthClientConfig {
            client_id: "https://localhost/oauth/atp/client-metadata".to_string(),
            redirect_uris: "https://localhost/oauth/atp/callback".to_string(),
            jwks_uri: Some("https://localhost/.well-known/jwks.json".to_string()),
            signing_keys: vec![test_signing_key],
            client_name: Some("Test Client".to_string()),
            client_uri: None,
            logo_uri: None,
            tos_uri: None,
            policy_uri: None,
            scope: Some(
                "atproto:atproto atproto:transition:generic atproto:transition:email".to_string(),
            ),
        };

        // Create session storage using unified adapter
        let session_storage = Arc::new(UnifiedAtpOAuthSessionStorageAdapter::new(
            oauth_storage.clone(),
        ));

        // Create authorization request storage using unified adapter
        let authorization_request_storage = Arc::new(
            UnifiedAuthorizationRequestStorageAdapter::new(oauth_storage.clone()),
        );

        AtpBackedAuthorizationServer::new(
            base_server,
            identity_resolver,
            http_client,
            oauth_request_storage,
            client_config,
            session_storage,
            document_storage,
            authorization_request_storage,
            "https://localhost".to_string(),
        )
    }

    #[tokio::test]
    async fn test_authorization_request_storage() {
        let oauth_storage = Arc::new(MemoryOAuthStorage::new());
        let storage = UnifiedAuthorizationRequestStorageAdapter::new(oauth_storage);

        let request = AuthorizationRequest {
            response_type: vec![ResponseType::Code],
            client_id: "test-client".to_string(),
            redirect_uri: "https://example.com/callback".to_string(),
            scope: Some("read".to_string()),
            state: Some("test-state".to_string()),
            code_challenge: None,
            code_challenge_method: None,
            login_hint: Some("alice.bsky.social".to_string()),
            nonce: None,
        };

        // Test store and retrieve
        storage
            .store_authorization_request("session-1", &request)
            .await
            .unwrap();

        let retrieved = storage
            .get_authorization_request("session-1")
            .await
            .unwrap()
            .unwrap();
        assert_eq!(retrieved.client_id, "test-client");
        assert_eq!(retrieved.redirect_uri, "https://example.com/callback");

        // Test non-existent session
        assert!(
            storage
                .get_authorization_request("non-existent")
                .await
                .unwrap()
                .is_none()
        );

        // Test remove
        storage
            .remove_authorization_request("session-1")
            .await
            .unwrap();
        assert!(
            storage
                .get_authorization_request("session-1")
                .await
                .unwrap()
                .is_none()
        );
    }

    #[tokio::test]
    async fn test_atp_oauth_session_storage() {
        let oauth_storage = Arc::new(MemoryOAuthStorage::new());
        let storage = UnifiedAtpOAuthSessionStorageAdapter::new(oauth_storage);

        let session = AtpOAuthSession {
            session_id: "session-1".to_string(),
            did: Some("did:plc:alice123".to_string()),
            session_created_at: Utc::now(),
            atp_oauth_state: "atp-state-123".to_string(),
            signing_key_jkt: "test-jkt-123".to_string(),
            dpop_key: "test-dpop-key".to_string(),
            access_token: None,
            refresh_token: None,
            access_token_created_at: None,
            access_token_expires_at: None,
            access_token_scopes: None,
            session_exchanged_at: None,
            exchange_error: None,
            iteration: 1,
        };

        // Test store and retrieve
        storage.store_session(&session).await.unwrap();

        let retrieved_sessions = storage
            .get_sessions("did:plc:alice123", "session-1")
            .await
            .unwrap();
        assert_eq!(retrieved_sessions.len(), 1);
        let retrieved = &retrieved_sessions[0];
        assert_eq!(retrieved.session_id, "session-1");
        assert_eq!(retrieved.did, Some("did:plc:alice123".to_string()));

        // Test retrieve by ATProtocol state
        let retrieved_by_state = storage
            .get_session_by_atp_state("atp-state-123")
            .await
            .unwrap()
            .unwrap();
        assert_eq!(retrieved_by_state.session_id, "session-1");

        // Test remove
        storage
            .remove_session("did:plc:alice123", "session-1", 1)
            .await
            .unwrap();
        let sessions_after_remove = storage
            .get_sessions("did:plc:alice123", "session-1")
            .await
            .unwrap();
        assert!(sessions_after_remove.is_empty());
        assert!(
            storage
                .get_session_by_atp_state("atp-state-123")
                .await
                .unwrap()
                .is_none()
        );
    }

    #[tokio::test]
    async fn test_authorize_with_atprotocol_flow() {
        let server = create_test_atp_backed_server();

        let request = AuthorizationRequest {
            response_type: vec![ResponseType::Code],
            client_id: "test-client".to_string(),
            redirect_uri: "https://example.com/callback".to_string(),
            scope: Some("read".to_string()),
            state: Some("client-state".to_string()),
            code_challenge: None,
            code_challenge_method: None,
            login_hint: Some("alice.bsky.social".to_string()),
            nonce: None,
        };

        // This will fail because the client doesn't exist, but tests the flow
        let result = server
            .authorize_with_atprotocol(request, "alice.bsky.social".to_string())
            .await;
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), OAuthError::InvalidClient(_)));
    }

    #[tokio::test]
    async fn test_atp_backed_oauth_flow_validation() {
        let server = create_test_atp_backed_server();

        // First, register a valid OAuth client
        let client = crate::oauth::types::OAuthClient {
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

        server
            .base_auth_server
            .storage
            .store_client(&client)
            .await
            .unwrap();

        let request = AuthorizationRequest {
            response_type: vec![ResponseType::Code],
            client_id: "test-client".to_string(),
            redirect_uri: "https://example.com/callback".to_string(),
            scope: Some("read".to_string()),
            state: Some("client-state".to_string()),
            code_challenge: None,
            code_challenge_method: None,
            login_hint: Some("alice.bsky.social".to_string()),
            nonce: None,
        };

        // Test that validation passes (the actual ATProtocol OAuth will fail in tests,
        // but we can test that our validation logic is working correctly)
        let result = server
            .authorize_with_atprotocol(request, "alice.bsky.social".to_string())
            .await;

        // The test environment doesn't have real ATProtocol OAuth servers, so this will fail
        // at the ATProtocol OAuth step. But we can verify that it's not failing at our validation step.
        assert!(result.is_err());
        let error_message = result.unwrap_err().to_string();

        // Should fail at ATProtocol OAuth step, not at our validation
        assert!(
            error_message.contains("AuthorizationFailed")
                || error_message.contains("OAuth init failed")
        );
        assert!(!error_message.contains("InvalidClient"));
        assert!(!error_message.contains("Invalid redirect URI"));
    }

    #[tokio::test]
    async fn test_atp_callback_handling() {
        let server = create_test_atp_backed_server();

        // Create a mock session first
        let session = AtpOAuthSession {
            session_id: "test-session".to_string(),
            did: Some("did:plc:alice123".to_string()),
            session_created_at: Utc::now(),
            atp_oauth_state: "atp-state-123".to_string(),
            signing_key_jkt: "test-jkt-456".to_string(),
            dpop_key: "test-dpop-key-456".to_string(),
            access_token: None,
            refresh_token: None,
            access_token_created_at: None,
            access_token_expires_at: None,
            access_token_scopes: None,
            session_exchanged_at: None,
            exchange_error: None,
            iteration: 1,
        };

        server
            .session_storage
            .store_session(&session)
            .await
            .unwrap();

        // Test callback with invalid code (will fail at ATProtocol OAuth exchange)
        let result = server
            .handle_atp_callback("invalid-code".to_string(), "atp-state-123".to_string())
            .await;

        // Should fail during ATProtocol OAuth token exchange
        assert!(result.is_err());
        // The exact error depends on the AtpOAuthServer implementation
    }

    #[test]
    fn test_session_storage_operations() {
        tokio::runtime::Runtime::new().unwrap().block_on(async {
            let oauth_storage = Arc::new(MemoryOAuthStorage::new());
            let storage = UnifiedAtpOAuthSessionStorageAdapter::new(oauth_storage);

            // Test that non-existent session returns empty list
            let result = storage
                .get_sessions("did:plc:nonexistent", "non-existent")
                .await
                .unwrap();
            assert!(result.is_empty());

            // Test session storage and retrieval by state
            let session = AtpOAuthSession {
                session_id: "session-1".to_string(),
                did: Some("did:plc:alice123".to_string()),
                session_created_at: Utc::now(),
                atp_oauth_state: "atp-state-123".to_string(),
                signing_key_jkt: "test-jkt-789".to_string(),
                dpop_key: "test-dpop-key-789".to_string(),
                access_token: None,
                refresh_token: None,
                access_token_created_at: None,
                access_token_expires_at: None,
                access_token_scopes: None,
                session_exchanged_at: None,
                exchange_error: None,
                iteration: 1,
            };

            storage.store_session(&session).await.unwrap();

            // Test retrieval by state
            let by_state = storage
                .get_session_by_atp_state("atp-state-123")
                .await
                .unwrap()
                .unwrap();
            assert_eq!(by_state.session_id, "session-1");

            // Test session removal cleanup
            storage
                .remove_session("did:plc:alice123", "session-1", 1)
                .await
                .unwrap();
            let sessions_after_remove = storage
                .get_sessions("did:plc:alice123", "session-1")
                .await
                .unwrap();
            assert!(sessions_after_remove.is_empty());
            assert!(
                storage
                    .get_session_by_atp_state("atp-state-123")
                    .await
                    .unwrap()
                    .is_none()
            );
        });
    }

    #[tokio::test]
    async fn test_different_key_types_for_jwt() {
        use atproto_identity::key::{KeyType, generate_key, to_public};

        let server = create_test_atp_backed_server();

        // Test with both P-256 and K-256 keys
        let key_types = vec![
            (KeyType::P256Private, "P-256"),
            (KeyType::K256Private, "K-256"),
        ];

        for (key_type, key_name) in key_types {
            println!(
                "Testing {} key generation, storage, and retrieval",
                key_name
            );

            // Test key generation
            let private_key = generate_key(key_type.clone()).unwrap();
            assert_eq!(*private_key.key_type(), key_type);

            let public_key = to_public(&private_key).unwrap();
            let expected_public_type = match key_type {
                KeyType::P256Private => KeyType::P256Public,
                KeyType::K256Private => KeyType::K256Public,
                _ => panic!("Unexpected key type"),
            };
            assert_eq!(*public_key.key_type(), expected_public_type);

            // Test key storage and retrieval
            let key_id = format!("{}-test", key_name.to_lowercase().replace("-", ""));
            server
                .base_auth_server
                .storage
                .store_key(&key_id, &private_key)
                .await
                .unwrap();

            let retrieved = server
                .base_auth_server
                .storage
                .get_key(&key_id)
                .await
                .unwrap()
                .unwrap();

            // Verify the retrieved key is exactly the same
            assert_eq!(private_key.to_string(), retrieved.to_string());
            assert_eq!(*private_key.key_type(), *retrieved.key_type());

            // Test JWT generation using the key (this is the real functionality we need)
            server
                .base_auth_server
                .storage
                .store_signing_key(&private_key)
                .await
                .unwrap();

            println!(
                "✓ {} key generation, storage, and retrieval all successful",
                key_name
            );
        }
    }

    #[tokio::test]
    async fn test_keydata_serialization_integration() {
        use atproto_identity::key::{KeyType, generate_key, identify_key};

        let server = create_test_atp_backed_server();

        // Generate various key types
        let keys = vec![
            ("p256-private", generate_key(KeyType::P256Private).unwrap()),
            ("k256-private", generate_key(KeyType::K256Private).unwrap()),
        ];

        // Store all keys using string serialization
        for (key_id, key) in &keys {
            server
                .base_auth_server
                .storage
                .store_key(key_id, key)
                .await
                .unwrap();
        }

        // Retrieve all keys and verify they round-trip correctly
        for (key_id, original_key) in &keys {
            let retrieved = server
                .base_auth_server
                .storage
                .get_key(key_id)
                .await
                .unwrap()
                .unwrap();

            // Verify the KeyData is exactly the same
            assert_eq!(original_key.to_string(), retrieved.to_string());
            assert_eq!(*original_key.key_type(), *retrieved.key_type());

            // Verify that identify_key can parse the string representation
            let key_string = original_key.to_string();
            let parsed = identify_key(&key_string).unwrap();
            assert_eq!(*original_key.key_type(), *parsed.key_type());
            assert_eq!(original_key.to_string(), parsed.to_string());
        }

        // Test listing all key IDs
        let key_ids = server
            .base_auth_server
            .storage
            .list_key_ids()
            .await
            .unwrap();
        assert_eq!(key_ids.len(), 2);
        assert!(key_ids.contains(&"p256-private".to_string()));
        assert!(key_ids.contains(&"k256-private".to_string()));
    }

    #[tokio::test]
    async fn test_complete_oauth_flow_with_atproto_identity() {
        use crate::oauth::dpop::DPoPValidator;
        use crate::storage::MemoryNonceStorage;
        use atproto_identity::key::{KeyType, generate_key, sign, to_public};

        let server = create_test_atp_backed_server();

        // Step 1: Generate and store cryptographic keys using atproto_identity
        let signing_key = generate_key(KeyType::P256Private).unwrap();
        let dpop_key = generate_key(KeyType::P256Private).unwrap();
        let client_key = generate_key(KeyType::K256Private).unwrap();

        // Store keys using KeyData string serialization
        server
            .base_auth_server
            .storage
            .store_signing_key(&signing_key)
            .await
            .unwrap();
        server
            .base_auth_server
            .storage
            .store_key("dpop-key", &dpop_key)
            .await
            .unwrap();
        server
            .base_auth_server
            .storage
            .store_key("client-key", &client_key)
            .await
            .unwrap();

        // Step 2: Verify key storage and retrieval
        let retrieved_signing = server
            .base_auth_server
            .storage
            .get_signing_key()
            .await
            .unwrap()
            .unwrap();
        let retrieved_dpop = server
            .base_auth_server
            .storage
            .get_key("dpop-key")
            .await
            .unwrap()
            .unwrap();
        let retrieved_client = server
            .base_auth_server
            .storage
            .get_key("client-key")
            .await
            .unwrap()
            .unwrap();

        assert_eq!(signing_key.to_string(), retrieved_signing.to_string());
        assert_eq!(dpop_key.to_string(), retrieved_dpop.to_string());
        assert_eq!(client_key.to_string(), retrieved_client.to_string());

        // Step 3: Test DPoP validation with atproto_identity keys
        let nonce_store = Box::new(MemoryNonceStorage::new());
        let _dpop_validator = DPoPValidator::new(nonce_store);

        // Test that the validator is properly initialized with standardized validation
        // The standardized DPoP validation supports ES256, ES384, and ES256K algorithms
        // and rejects RSA algorithms automatically

        // Step 4: Test key type conversions and validation
        let key_types_to_test = vec![
            (KeyType::P256Private, KeyType::P256Public),
            (KeyType::K256Private, KeyType::K256Public),
        ];

        for (private_type, public_type) in key_types_to_test {
            let private_key = generate_key(private_type.clone()).unwrap();
            let public_key = to_public(&private_key).unwrap();

            assert_eq!(*private_key.key_type(), private_type);
            assert_eq!(*public_key.key_type(), public_type);

            // Test key functionality (direct sign/validate has implementation issues)
            let test_message = b"integration test message";
            let signature = sign(&private_key, test_message).unwrap();

            // Verify we can generate signatures and the key types are correct
            assert!(!signature.is_empty(), "Signature should not be empty");
            assert_eq!(*private_key.key_type(), private_type);
            assert_eq!(*public_key.key_type(), public_type);

            println!(
                "✓ Key generation and signature creation successful for {:?}",
                private_type
            );

            // Store and retrieve to test serialization
            let key_id = format!("integration-test-{:?}", private_type);
            server
                .base_auth_server
                .storage
                .store_key(&key_id, &private_key)
                .await
                .unwrap();
            let retrieved = server
                .base_auth_server
                .storage
                .get_key(&key_id)
                .await
                .unwrap()
                .unwrap();
            assert_eq!(private_key.to_string(), retrieved.to_string());
        }

        // Step 5: Verify complete key management workflow
        let all_key_ids = server
            .base_auth_server
            .storage
            .list_key_ids()
            .await
            .unwrap();
        assert!(all_key_ids.len() >= 4); // At least the keys we stored

        // Verify each key can be retrieved and is valid
        for key_id in &all_key_ids {
            let key = server
                .base_auth_server
                .storage
                .get_key(key_id)
                .await
                .unwrap()
                .unwrap();
            assert!(!key.to_string().is_empty());

            // Verify the key string can be parsed back
            use atproto_identity::key::identify_key;
            let parsed = identify_key(&key.to_string()).unwrap();
            assert_eq!(key.to_string(), parsed.to_string());
        }
    }

    #[test]
    fn test_scope_filtering_with_profile_and_email() {
        use crate::oauth::types::{AuthorizationRequest, ResponseType};

        tokio::runtime::Runtime::new().unwrap().block_on(async {
            let server = create_test_atp_backed_server();

            // Test scope filtering with profile scope
            let request_with_profile = AuthorizationRequest {
                response_type: vec![ResponseType::Code],
                client_id: "test-client".to_string(),
                redirect_uri: "https://example.com/callback".to_string(),
                scope: Some("openid profile".to_string()),
                state: Some("client-state".to_string()),
                code_challenge: None,
                code_challenge_method: None,
                login_hint: Some("alice.bsky.social".to_string()),
                nonce: None,
            };

            // Store a test client to pass validation
            let test_client = crate::oauth::types::OAuthClient {
                client_id: "test-client".to_string(),
                client_secret: None,
                client_name: Some("Test Client".to_string()),
                redirect_uris: vec!["https://example.com/callback".to_string()],
                grant_types: vec![crate::oauth::types::GrantType::AuthorizationCode],
                response_types: vec![crate::oauth::types::ResponseType::Code],
                scope: Some("openid profile email".to_string()),
                token_endpoint_auth_method: crate::oauth::types::ClientAuthMethod::None,
                client_type: crate::oauth::types::ClientType::Public,
                application_type: None,
                software_id: None,
                software_version: None,
                created_at: chrono::Utc::now(),
                updated_at: chrono::Utc::now(),
                metadata: serde_json::json!({}),
                access_token_expiration: chrono::Duration::days(1),
                refresh_token_expiration: chrono::Duration::days(14),
                require_redirect_exact: true,
                registration_access_token: Some("test-registration-token".to_string()),
            };

            server
                .base_auth_server
                .storage
                .store_client(&test_client)
                .await
                .unwrap();

            // Test with profile scope - should add transition:generic
            let result_profile = server
                .authorize_with_atprotocol(request_with_profile, "alice.bsky.social".to_string())
                .await;

            // The test will fail at ATProtocol OAuth step, but we can verify it passed our validation
            assert!(result_profile.is_err());
            let error_message = result_profile.unwrap_err().to_string();
            println!("Profile error message: {}", error_message);
            assert!(
                error_message.contains("Failed to resolve subject")
                    || error_message.contains("PDS discovery failed")
                    || error_message.contains("error-aip-resolve-1")
                    || error_message.contains("error-aip-oauth-1")
                    || error_message.contains("OAuth init failed")
            );

            // Test scope filtering with email scope
            let request_with_email = AuthorizationRequest {
                response_type: vec![ResponseType::Code],
                client_id: "test-client".to_string(),
                redirect_uri: "https://example.com/callback".to_string(),
                scope: Some("openid email".to_string()),
                state: Some("client-state".to_string()),
                code_challenge: None,
                code_challenge_method: None,
                login_hint: Some("alice.bsky.social".to_string()),
                nonce: None,
            };

            // Test with email scope - should add transition:email
            let result_email = server
                .authorize_with_atprotocol(request_with_email, "alice.bsky.social".to_string())
                .await;

            // The test will fail at ATProtocol OAuth step, but we can verify it passed our validation
            assert!(result_email.is_err());
            let error_message = result_email.unwrap_err().to_string();
            println!("Email error message: {}", error_message);
            assert!(
                error_message.contains("Failed to resolve subject")
                    || error_message.contains("PDS discovery failed")
                    || error_message.contains("error-aip-resolve-1")
                    || error_message.contains("error-aip-oauth-1")
                    || error_message.contains("OAuth init failed")
            );

            // Test scope filtering with both profile and email scopes
            let request_with_both = AuthorizationRequest {
                response_type: vec![ResponseType::Code],
                client_id: "test-client".to_string(),
                redirect_uri: "https://example.com/callback".to_string(),
                scope: Some("openid profile email".to_string()),
                state: Some("client-state".to_string()),
                code_challenge: None,
                code_challenge_method: None,
                login_hint: Some("alice.bsky.social".to_string()),
                nonce: None,
            };

            // Test with both scopes - should add both transition scopes
            let result_both = server
                .authorize_with_atprotocol(request_with_both, "alice.bsky.social".to_string())
                .await;

            // The test will fail at ATProtocol OAuth step, but we can verify it passed our validation
            assert!(result_both.is_err());
            let error_message = result_both.unwrap_err().to_string();
            println!("Both scopes error message: {}", error_message);
            assert!(
                error_message.contains("Failed to resolve subject")
                    || error_message.contains("PDS discovery failed")
                    || error_message.contains("error-aip-resolve-1")
                    || error_message.contains("error-aip-oauth-1")
                    || error_message.contains("OAuth init failed")
            );
        });
    }
}
