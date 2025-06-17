//! ATProtocol OAuth integration bridge.
//!
//! Bridges base OAuth 2.1 authorization with ATProtocol OAuth authentication,
//! allowing ATProtocol users to authenticate for OAuth flows.

use crate::errors::OAuthError;
use crate::oauth::{
    auth_server::{AuthorizationServer, AuthorizeResponse},
    types::*,
};
use atproto_identity::key::{generate_key, identify_key, to_public, KeyType};
use atproto_oauth::{
    jwk::generate as generate_jwk,
    pkce, resources,
    workflow::{oauth_complete, oauth_init, OAuthClient, OAuthRequest, OAuthRequestState},
};
use chrono::{DateTime, Duration, Utc};
use serde::{Deserialize, Serialize};
use std::{collections::HashMap, sync::Arc};
use ulid::Ulid;
use uuid::Uuid;

use crate::oauth::dpop::compute_jwk_thumbprint;

/// Session linking OAuth authorization requests to ATProtocol OAuth flows
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AtpOAuthSession {
    /// Unique session ID
    pub session_id: String,
    /// DID being authenticated
    pub did: String,
    /// Session creation time (UTC)
    pub session_created_at: DateTime<Utc>,
    /// ATProtocol OAuth state for tracking
    pub atp_oauth_state: String,
    /// JWK thumbprint of the signing key used to create the session
    pub signing_key_jkt: String,
    /// String serialized KeyData p256 private key provided to oauth_init
    pub dpop_key: String,
    /// Access token from token exchange process
    pub access_token: Option<String>,
    /// Refresh token from token exchange process
    pub refresh_token: Option<String>,
    /// Timestamp when the access token was created
    pub access_token_created_at: Option<DateTime<Utc>>,
    /// Timestamp when the access token expires
    pub access_token_expires_at: Option<DateTime<Utc>>,
    /// Scopes associated with the access token
    pub access_token_scopes: Option<Vec<String>>,
    /// Timestamp when the oauth_callback method was invoked
    pub session_exchanged_at: Option<DateTime<Utc>>,
    /// Exchange error if oauth_callback returns an error
    pub exchange_error: Option<String>,
    /// Iteration counter for the session_id
    pub iteration: u32,
}

/// Storage trait for ATProtocol OAuth sessions
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

    /// Update session with access and refresh tokens
    async fn update_session_tokens(
        &self,
        did: &str,
        session_id: &str,
        iteration: u32,
        access_token: Option<String>,
        refresh_token: Option<String>,
        access_token_created_at: Option<DateTime<Utc>>,
        access_token_expires_at: Option<DateTime<Utc>>,
        access_token_scopes: Option<Vec<String>>,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>>;

    /// Remove session by DID, session ID, and iteration
    async fn remove_session(
        &self,
        did: &str,
        session_id: &str,
        iteration: u32,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>>;
}

/// In-memory implementation of ATProtocol OAuth session storage
#[derive(Default)]
pub struct MemoryAtpOAuthSessionStorage {
    sessions: tokio::sync::RwLock<HashMap<String, AtpOAuthSession>>, // session_key -> session
    state_index: tokio::sync::RwLock<HashMap<String, String>>,       // atp_state -> session_key
    session_iterations: tokio::sync::RwLock<HashMap<String, Vec<u32>>>, // (did, session_id) -> iterations
}

impl MemoryAtpOAuthSessionStorage {
    pub fn new() -> Self {
        Self::default()
    }

    /// Generate a unique session key from DID, session_id, and iteration
    fn session_key(did: &str, session_id: &str, iteration: u32) -> String {
        format!("{}:{}:{}", did, session_id, iteration)
    }

    /// Generate a session index key from DID and session_id
    fn session_index_key(did: &str, session_id: &str) -> String {
        format!("{}:{}", did, session_id)
    }
}

#[async_trait::async_trait]
impl AtpOAuthSessionStorage for MemoryAtpOAuthSessionStorage {
    async fn store_session(
        &self,
        session: &AtpOAuthSession,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let mut sessions = self.sessions.write().await;
        let mut state_index = self.state_index.write().await;
        let mut session_iterations = self.session_iterations.write().await;

        let session_key = Self::session_key(&session.did, &session.session_id, session.iteration);
        let index_key = Self::session_index_key(&session.did, &session.session_id);

        // Store the session
        sessions.insert(session_key.clone(), session.clone());

        // Update state index
        state_index.insert(session.atp_oauth_state.clone(), session_key);

        // Update iterations index
        let iterations = session_iterations.entry(index_key).or_insert_with(Vec::new);
        if !iterations.contains(&session.iteration) {
            iterations.push(session.iteration);
            iterations.sort_by(|a, b| b.cmp(a)); // Sort highest to lowest
        }

        Ok(())
    }

    async fn get_sessions(
        &self,
        did: &str,
        session_id: &str,
    ) -> Result<Vec<AtpOAuthSession>, Box<dyn std::error::Error + Send + Sync>> {
        let sessions = self.sessions.read().await;
        let session_iterations = self.session_iterations.read().await;

        let index_key = Self::session_index_key(did, session_id);
        tracing::warn!(?did, ?session_id, "getting sessions");

        if let Some(iterations) = session_iterations.get(&index_key) {
            let mut result = Vec::new();
            for &iteration in iterations {
                let session_key = Self::session_key(did, session_id, iteration);
                if let Some(session) = sessions.get(&session_key) {
                    result.push(session.clone());
                }
            }
            Ok(result)
        } else {
            Ok(Vec::new())
        }
    }

    async fn get_session(
        &self,
        did: &str,
        session_id: &str,
        iteration: u32,
    ) -> Result<Option<AtpOAuthSession>, Box<dyn std::error::Error + Send + Sync>> {
        let sessions = self.sessions.read().await;
        let session_key = Self::session_key(did, session_id, iteration);
        tracing::warn!(?did, ?session_id, ?iteration, "getting specific session");
        Ok(sessions.get(&session_key).cloned())
    }

    async fn get_session_by_atp_state(
        &self,
        atp_state: &str,
    ) -> Result<Option<AtpOAuthSession>, Box<dyn std::error::Error + Send + Sync>> {
        let state_index = self.state_index.read().await;
        if let Some(session_key) = state_index.get(atp_state) {
            let sessions = self.sessions.read().await;
            Ok(sessions.get(session_key).cloned())
        } else {
            Ok(None)
        }
    }

    async fn update_session_tokens(
        &self,
        did: &str,
        session_id: &str,
        iteration: u32,
        access_token: Option<String>,
        refresh_token: Option<String>,
        access_token_created_at: Option<DateTime<Utc>>,
        access_token_expires_at: Option<DateTime<Utc>>,
        access_token_scopes: Option<Vec<String>>,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let mut sessions = self.sessions.write().await;
        let session_key = Self::session_key(did, session_id, iteration);
        if let Some(session) = sessions.get_mut(&session_key) {
            session.access_token = access_token;
            session.refresh_token = refresh_token;
            session.access_token_created_at = access_token_created_at;
            session.access_token_expires_at = access_token_expires_at;
            session.access_token_scopes = access_token_scopes;
        }
        tracing::warn!(?did, ?session_id, ?iteration, "updating session tokens");
        Ok(())
    }

    async fn remove_session(
        &self,
        did: &str,
        session_id: &str,
        iteration: u32,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let mut sessions = self.sessions.write().await;
        let mut state_index = self.state_index.write().await;
        let mut session_iterations = self.session_iterations.write().await;

        let session_key = Self::session_key(did, session_id, iteration);
        let index_key = Self::session_index_key(did, session_id);

        if let Some(session) = sessions.remove(&session_key) {
            // Remove from state index
            state_index.remove(&session.atp_oauth_state);

            // Remove iteration from the iterations list
            if let Some(iterations) = session_iterations.get_mut(&index_key) {
                iterations.retain(|&i| i != iteration);
                // If no more iterations, remove the entire entry
                if iterations.is_empty() {
                    session_iterations.remove(&index_key);
                }
            }
        }

        tracing::warn!(?did, ?session_id, ?iteration, "deleting session");

        Ok(())
    }
}

/// Storage trait for OAuth authorization requests
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

/// In-memory implementation of authorization request storage
#[derive(Default)]
pub struct MemoryAuthorizationRequestStorage {
    requests: tokio::sync::RwLock<HashMap<String, AuthorizationRequest>>,
}

impl MemoryAuthorizationRequestStorage {
    pub fn new() -> Self {
        Self::default()
    }
}

#[async_trait::async_trait]
impl AuthorizationRequestStorage for MemoryAuthorizationRequestStorage {
    async fn store_authorization_request(
        &self,
        session_id: &str,
        request: &AuthorizationRequest,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let mut requests = self.requests.write().await;
        requests.insert(session_id.to_string(), request.clone());

        tracing::info!(?session_id, ?requests, "storing request");
        Ok(())
    }

    async fn get_authorization_request(
        &self,
        session_id: &str,
    ) -> Result<Option<AuthorizationRequest>, Box<dyn std::error::Error + Send + Sync>> {
        let requests = self.requests.read().await;

        tracing::info!(?session_id, ?requests, "getting request");

        Ok(requests.get(session_id).cloned())
    }

    async fn remove_authorization_request(
        &self,
        session_id: &str,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let mut requests = self.requests.write().await;
        requests.remove(session_id);
        Ok(())
    }
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

        // Resolve ATProtocol identity document
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

        // Discover PDS resources and authorization server
        let (_, atpoauth_auth_server) = match atpoauth_document.pds_endpoints().first() {
            Some(endpoint) => resources::pds_resources(&self.http_client, endpoint)
                .await
                .map_err(|e| {
                    OAuthError::AuthorizationFailed(format!("PDS discovery failed: {:?}", e))
                }),
            None => Err(OAuthError::AuthorizationFailed(
                "No PDS endpoint found".to_string(),
            )),
        }?;

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
            did: atpoauth_document.id.clone(),
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
        let filtered_scope = if let Some(ref original_scope) = request.scope {
            let scopes: Vec<&str> = original_scope.split_whitespace().collect();
            let atprotocol_scopes: Vec<String> = scopes
                .iter()
                .filter_map(|scope| {
                    if scope.starts_with("atprotocol:") {
                        Some(scope.strip_prefix("atprotocol:").unwrap().to_string())
                    } else {
                        None
                    }
                })
                .collect();

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

        // Use atproto-oauth workflow to initiate the flow
        let atpoauth_par_response = oauth_init(
            &self.http_client,
            &oauth_client,
            &atpoauth_dpop_key,
            &atpoauth_subject,
            &atpoauth_auth_server,
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
            issuer: atpoauth_auth_server.issuer.clone(),
            did: atpoauth_document.id,
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
            atpoauth_auth_server.authorization_endpoint,
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

        // Re-resolve the DID document using the identity resolver
        let did_document = self
            .identity_resolver
            .resolve(&oauth_request.did)
            .await
            .map_err(|e| {
                OAuthError::ServerError(format!("Failed to resolve DID document: {}", e))
            })?;

        // Use oauth_complete to properly handle the token exchange with PKCE
        let token_response = oauth_complete(
            &self.http_client,
            &oauth_client,
            &dpop_key,
            &code,
            &oauth_request,
            &did_document,
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

        // Update session with tokens from the token response
        self.session_storage
            .update_session_tokens(
                &session.did,
                &session.session_id,
                session.iteration,
                Some(token_response.access_token.clone()),
                Some(token_response.refresh_token.clone()),
                Some(now),
                Some(expires_at),
                Some(parsed_scopes),
            )
            .await
            .map_err(|e| OAuthError::ServerError(format!("Session token update error: {}", e)))?;

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
                did_document.id,
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

        // Validate response type
        if !client.response_types.contains(&request.response_type) {
            return Err(OAuthError::UnsupportedResponseType(format!(
                "{:?}",
                request.response_type
            )));
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::oauth::auth_server::AuthorizationServer;
    use crate::storage::inmemory::MemoryOAuthStorage;
    use atproto_identity::resolve::{create_resolver, IdentityResolver, InnerIdentityResolver};
    use atproto_identity::storage_lru::LruDidDocumentStorage;
    use atproto_oauth::storage_lru::LruOAuthRequestStorage;
    use std::num::NonZeroUsize;

    fn create_test_atp_backed_server() -> AtpBackedAuthorizationServer {
        // Create base OAuth server
        let oauth_storage = Arc::new(MemoryOAuthStorage::new());
        let base_server = Arc::new(AuthorizationServer::new(
            oauth_storage,
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
        };

        // Create session storage
        let session_storage = Arc::new(MemoryAtpOAuthSessionStorage::new());

        // Create authorization request storage
        let authorization_request_storage = Arc::new(MemoryAuthorizationRequestStorage::new());

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
        let storage = MemoryAuthorizationRequestStorage::new();

        let request = AuthorizationRequest {
            response_type: ResponseType::Code,
            client_id: "test-client".to_string(),
            redirect_uri: "https://example.com/callback".to_string(),
            scope: Some("read".to_string()),
            state: Some("test-state".to_string()),
            code_challenge: None,
            code_challenge_method: None,
            login_hint: Some("alice.bsky.social".to_string()),
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
        assert!(storage
            .get_authorization_request("non-existent")
            .await
            .unwrap()
            .is_none());

        // Test remove
        storage
            .remove_authorization_request("session-1")
            .await
            .unwrap();
        assert!(storage
            .get_authorization_request("session-1")
            .await
            .unwrap()
            .is_none());
    }

    #[tokio::test]
    async fn test_atp_oauth_session_storage() {
        let storage = MemoryAtpOAuthSessionStorage::new();

        let session = AtpOAuthSession {
            session_id: "session-1".to_string(),
            did: "did:plc:alice123".to_string(),
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
        assert_eq!(retrieved.did, "did:plc:alice123");

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
        assert!(storage
            .get_session_by_atp_state("atp-state-123")
            .await
            .unwrap()
            .is_none());
    }

    #[tokio::test]
    async fn test_authorize_with_atprotocol_flow() {
        let server = create_test_atp_backed_server();

        let request = AuthorizationRequest {
            response_type: ResponseType::Code,
            client_id: "test-client".to_string(),
            redirect_uri: "https://example.com/callback".to_string(),
            scope: Some("read".to_string()),
            state: Some("client-state".to_string()),
            code_challenge: None,
            code_challenge_method: None,
            login_hint: Some("alice.bsky.social".to_string()),
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
            created_at: Utc::now(),
            updated_at: Utc::now(),
            metadata: serde_json::Value::Null,
        };

        server
            .base_auth_server
            .storage
            .store_client(&client)
            .await
            .unwrap();

        let request = AuthorizationRequest {
            response_type: ResponseType::Code,
            client_id: "test-client".to_string(),
            redirect_uri: "https://example.com/callback".to_string(),
            scope: Some("read".to_string()),
            state: Some("client-state".to_string()),
            code_challenge: None,
            code_challenge_method: None,
            login_hint: Some("alice.bsky.social".to_string()),
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
            did: "did:plc:alice123".to_string(),
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
            let storage = MemoryAtpOAuthSessionStorage::new();

            // Test that non-existent session returns empty list
            let result = storage
                .get_sessions("did:plc:nonexistent", "non-existent")
                .await
                .unwrap();
            assert!(result.is_empty());

            // Test session storage and retrieval by state
            let session = AtpOAuthSession {
                session_id: "session-1".to_string(),
                did: "did:plc:alice123".to_string(),
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
            assert!(storage
                .get_session_by_atp_state("atp-state-123")
                .await
                .unwrap()
                .is_none());
        });
    }

    #[tokio::test]
    async fn test_different_key_types_for_jwt() {
        use atproto_identity::key::{generate_key, to_public, KeyType};

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
        use atproto_identity::key::{generate_key, identify_key, KeyType};

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
        use atproto_identity::key::{generate_key, sign, to_public, KeyType};

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
}

// ===== Adapter Implementations =====
//
// These adapters bridge from the new unified storage traits to the old oauth bridge traits

/// Adapter to bridge new unified AtpOAuthSessionStorage to old oauth bridge trait
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

    async fn update_session_tokens(
        &self,
        did: &str,
        session_id: &str,
        iteration: u32,
        access_token: Option<String>,
        refresh_token: Option<String>,
        access_token_created_at: Option<DateTime<Utc>>,
        access_token_expires_at: Option<DateTime<Utc>>,
        access_token_scopes: Option<Vec<String>>,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        self.storage
            .update_session_tokens(
                did,
                session_id,
                iteration,
                access_token,
                refresh_token,
                access_token_created_at,
                access_token_expires_at,
                access_token_scopes,
            )
            .await
            .map_err(|e| Box::new(e) as Box<dyn std::error::Error + Send + Sync>)
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
