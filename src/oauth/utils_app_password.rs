//! App-password session management utilities.

use crate::http::AppState;
use crate::storage::traits::AppPasswordSession;
use atproto_identity::model::Document;
use chrono::{Duration, Utc};
use serde::{Deserialize, Serialize};

/// Request for com.atproto.server.createSession
#[derive(Debug, Serialize)]
struct CreateSessionRequest {
    identifier: String,
    password: String,
}

/// Response from com.atproto.server.createSession
#[derive(Debug, Deserialize)]
struct CreateSessionResponse {
    #[serde(rename = "accessJwt")]
    access_jwt: String,
    #[serde(rename = "refreshJwt")]
    refresh_jwt: String,
}

/// Request for com.atproto.server.refreshSession
#[derive(Debug, Serialize)]
struct RefreshSessionRequest {
    #[serde(rename = "refreshJwt")]
    refresh_jwt: String,
}

/// Response from com.atproto.server.refreshSession
#[derive(Debug, Deserialize)]
struct RefreshSessionResponse {
    #[serde(rename = "accessJwt")]
    access_jwt: String,
    #[serde(rename = "refreshJwt")]
    refresh_jwt: String,
}

/// Create a new app-password session using ATProtocol createSession XRPC
///
/// This function authenticates with a PDS using an app-password and creates
/// a new session with access and refresh tokens.
///
/// # Arguments
/// * `state` - The application state
/// * `client_id` - The OAuth client ID
/// * `did` - The DID (identifier) of the identity
/// * `handle_or_did` - The handle or DID for authentication
/// * `app_password` - The app-password for authentication
/// * `pds_endpoint` - The PDS endpoint URL
///
/// # Returns
/// A new `AppPasswordSession` with access and refresh tokens
pub async fn create_app_password_session(
    state: &AppState,
    client_id: &str,
    did: &str,
    handle_or_did: &str,
    app_password: &str,
    pds_endpoint: &str,
) -> Result<AppPasswordSession, Box<dyn std::error::Error + Send + Sync>> {
    let create_session_url = format!("{}/xrpc/com.atproto.server.createSession", pds_endpoint);

    let request_body = CreateSessionRequest {
        identifier: handle_or_did.to_string(),
        password: app_password.to_string(),
    };

    // Make POST request to createSession endpoint
    let response = state
        .http_client
        .post(&create_session_url)
        .json(&request_body)
        .send()
        .await
        .map_err(|e| format!("Failed to send createSession request: {}", e))?;

    if !response.status().is_success() {
        let status = response.status();
        let body = response.text().await.unwrap_or_default();
        return Err(format!("createSession failed with status {}: {}", status, body).into());
    }

    let session_response: CreateSessionResponse = response
        .json()
        .await
        .map_err(|e| format!("Failed to parse createSession response: {}", e))?;

    let now = Utc::now();

    // Calculate token expiration (PDS typically returns tokens valid for 2 hours)
    let expires_at = now + Duration::hours(2);

    // Create app-password session
    let app_password_session = AppPasswordSession {
        client_id: client_id.to_string(),
        did: did.to_string(),
        access_token: session_response.access_jwt,
        refresh_token: Some(session_response.refresh_jwt),
        access_token_created_at: now,
        access_token_expires_at: expires_at,
        iteration: 1,
        session_exchanged_at: Some(now),
        exchange_error: None,
    };

    // Store the session
    state
        .oauth_storage
        .store_app_password_session(&app_password_session)
        .await
        .map_err(|e| format!("Failed to store app-password session: {}", e))?;

    Ok(app_password_session)
}

/// Refresh an app-password session using ATProtocol refreshSession XRPC
///
/// This function uses a refresh token to obtain new access and refresh tokens.
///
/// # Arguments
/// * `state` - The application state
/// * `session` - The current app-password session to refresh
/// * `pds_endpoint` - The PDS endpoint URL
///
/// # Returns
/// An updated `AppPasswordSession` with new tokens
pub async fn refresh_app_password_session(
    state: &AppState,
    session: &AppPasswordSession,
    pds_endpoint: &str,
) -> Result<AppPasswordSession, Box<dyn std::error::Error + Send + Sync>> {
    let refresh_session_url = format!("{}/xrpc/com.atproto.server.refreshSession", pds_endpoint);

    let now = Utc::now();
    let new_iteration = session.iteration + 1;

    // Create new session with incremented iteration
    let mut new_session = AppPasswordSession {
        client_id: session.client_id.clone(),
        did: session.did.clone(),
        access_token: session.access_token.clone(),
        refresh_token: session.refresh_token.clone(),
        access_token_created_at: session.access_token_created_at,
        access_token_expires_at: session.access_token_expires_at,
        iteration: new_iteration,
        session_exchanged_at: Some(now),
        exchange_error: None,
    };

    // Check if we have a refresh token
    let refresh_token = match &session.refresh_token {
        Some(token) => token,
        None => {
            new_session.exchange_error = Some("No refresh token available".to_string());
            state
                .oauth_storage
                .store_app_password_session(&new_session)
                .await
                .map_err(|e| format!("Failed to store session with error: {}", e))?;
            return Err("No refresh token available".into());
        }
    };

    let request_body = RefreshSessionRequest {
        refresh_jwt: refresh_token.clone(),
    };

    // Attempt to refresh the session
    match state
        .http_client
        .post(&refresh_session_url)
        .header("Authorization", format!("Bearer {}", refresh_token))
        .json(&request_body)
        .send()
        .await
    {
        Ok(response) => {
            if response.status().is_success() {
                match response.json::<RefreshSessionResponse>().await {
                    Ok(token_response) => {
                        // Update session with new tokens
                        new_session.access_token = token_response.access_jwt;
                        new_session.refresh_token = Some(token_response.refresh_jwt);
                        new_session.access_token_created_at = now;

                        // Calculate new expiration (typically 2 hours)
                        new_session.access_token_expires_at = now + Duration::hours(2);
                    }
                    Err(e) => {
                        new_session.exchange_error =
                            Some(format!("Failed to parse refresh response: {}", e));
                    }
                }
            } else {
                let status = response.status();
                let body = response.text().await.unwrap_or_default();
                new_session.exchange_error =
                    Some(format!("Refresh failed with status {}: {}", status, body));
            }
        }
        Err(e) => {
            // Store the refresh error in the new session
            new_session.exchange_error = Some(format!("Refresh request failed: {}", e));
        }
    }

    // Store the new session
    state
        .oauth_storage
        .store_app_password_session(&new_session)
        .await
        .map_err(|e| format!("Failed to store refreshed app-password session: {}", e))?;

    // Return error if refresh failed
    if let Some(ref error) = new_session.exchange_error {
        return Err(error.clone().into());
    }

    Ok(new_session)
}

/// Retrieve app-password session with automatic refresh if needed
///
/// This function retrieves the app-password session for a given client and document.
/// If the access token is within 60 seconds of expiration or has already expired,
/// it will automatically refresh the token.
///
/// # Arguments
/// * `state` - The application state
/// * `client_id` - The OAuth client ID
/// * `document` - The ATProtocol identity document (contains DID and PDS endpoint)
///
/// # Returns
/// An `AppPasswordSession` (potentially refreshed)
pub async fn get_app_password_session_with_refresh(
    state: &AppState,
    client_id: &str,
    document: &Document,
) -> Result<AppPasswordSession, Box<dyn std::error::Error + Send + Sync>> {
    // Get existing session
    let session = state
        .oauth_storage
        .get_app_password_session(client_id, &document.id)
        .await
        .map_err(|e| format!("Failed to get app-password session: {}", e))?
        .ok_or("No app-password session found")?;

    // Check if session has an exchange error
    if let Some(ref exchange_error) = session.exchange_error {
        return Err(format!("Session has exchange error: {}", exchange_error).into());
    }

    // Check if token needs refreshing
    let now = Utc::now();
    let needs_refresh = {
        // Refresh if expired or within 60 seconds of expiration
        session.access_token_expires_at <= now
            || session.access_token_expires_at <= now + Duration::seconds(60)
    };

    let current_session = if needs_refresh {
        // Get PDS endpoint from document
        let pds_endpoints: Vec<String> = document
            .pds_endpoints()
            .into_iter()
            .map(|s| s.to_string())
            .collect();
        let pds_endpoint = pds_endpoints
            .first()
            .ok_or("No PDS endpoint found in document")?;

        // Perform session refresh
        refresh_app_password_session(state, &session, pds_endpoint).await?
    } else {
        session
    };

    Ok(current_session)
}

/// Authenticate and create app-password session for a given client and DID
///
/// This function combines app-password retrieval, DID resolution, and session creation
/// into a single convenient function.
///
/// # Arguments
/// * `state` - The application state
/// * `client_id` - The OAuth client ID
/// * `did` - The DID (identifier) of the identity
///
/// # Returns
/// A new `AppPasswordSession` with access and refresh tokens
pub async fn authenticate_with_app_password(
    state: &AppState,
    client_id: &str,
    did: &str,
) -> Result<AppPasswordSession, Box<dyn std::error::Error + Send + Sync>> {
    // Get the stored app-password
    let app_password_entry = state
        .oauth_storage
        .get_app_password(client_id, did)
        .await
        .map_err(|e| format!("Failed to get app-password: {}", e))?
        .ok_or("No app-password found for client and DID")?;

    // Get the DID document from document storage
    let document = state
        .document_storage
        .get_document_by_did(did)
        .await
        .map_err(|e| format!("Failed to get DID document: {}", e))?
        .ok_or("DID document not found")?;

    // Get PDS endpoint from document
    let pds_endpoints: Vec<String> = document
        .pds_endpoints()
        .into_iter()
        .map(|s| s.to_string())
        .collect();
    let pds_endpoint = pds_endpoints
        .first()
        .ok_or("No PDS endpoint found in document")?;

    // Create session using the app-password
    create_app_password_session(
        state,
        client_id,
        did,
        did, // Use DID as identifier for authentication
        &app_password_entry.app_password,
        pds_endpoint,
    )
    .await
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::oauth::DPoPNonceGenerator;
    use crate::storage::SimpleKeyProvider;
    use crate::storage::inmemory::MemoryOAuthStorage;
    use crate::storage::traits::AppPassword;
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

    #[test]
    fn test_app_password_session_creation() {
        let session = AppPasswordSession {
            client_id: "test-client".to_string(),
            did: "did:plc:test123".to_string(),
            access_token: "access-token-123".to_string(),
            refresh_token: Some("refresh-token-123".to_string()),
            access_token_created_at: Utc::now(),
            access_token_expires_at: Utc::now() + Duration::hours(2),
            iteration: 1,
            session_exchanged_at: Some(Utc::now()),
            exchange_error: None,
        };

        assert_eq!(session.client_id, "test-client");
        assert_eq!(session.did, "did:plc:test123");
        assert_eq!(session.iteration, 1);
        assert!(session.exchange_error.is_none());
    }

    #[tokio::test]
    async fn test_app_password_session_storage() {
        let app_state = create_test_app_state();

        // Create test app-password
        let app_password = AppPassword {
            client_id: "test-client".to_string(),
            did: "did:plc:test123".to_string(),
            app_password: "test-password-123".to_string(),
            created_at: Utc::now(),
            updated_at: Utc::now(),
        };

        // Store app-password
        app_state
            .oauth_storage
            .store_app_password(&app_password)
            .await
            .unwrap();

        // Verify app-password was stored
        let retrieved = app_state
            .oauth_storage
            .get_app_password("test-client", "did:plc:test123")
            .await
            .unwrap();

        assert!(retrieved.is_some());
        assert_eq!(retrieved.unwrap().app_password, "test-password-123");
    }
}
