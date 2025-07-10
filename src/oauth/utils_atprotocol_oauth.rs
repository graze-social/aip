//! ATProtocol OAuth server configuration utilities.

use std::sync::Arc;

use crate::http::AppState;
use crate::oauth::atprotocol_bridge::AtpOAuthSession;
use crate::oauth::openid::OpenIDClaims;
use crate::oauth::{AtpBackedAuthorizationServer, auth_server::AuthorizationServer};
use atproto_client::client::{DPoPAuth, get_dpop_json_with_headers};
use atproto_identity::key::identify_key;
use atproto_identity::model::Document;
use atproto_oauth_axum::state::OAuthClientConfig;
use chrono::{Duration, Utc};
use reqwest::header::HeaderMap;
use serde::Deserialize;
use std::collections::HashSet;

/// Create ATProtocol-backed authorization server
pub async fn create_atp_backed_server(
    state: &AppState,
) -> std::result::Result<AtpBackedAuthorizationServer, Box<dyn std::error::Error + Send + Sync>> {
    // Create base OAuth authorization server
    let base_auth_server = Arc::new(AuthorizationServer::new(
        state.oauth_storage.clone(),
        state.config.external_base.clone(),
    ));

    // Use the identity resolver from state and create HTTP client for AtpOAuthServer
    let identity_resolver = state.identity_resolver.clone();
    let http_client = reqwest::Client::new();

    let client_config = OAuthClientConfig {
        client_id: format!("{}/oauth/atp/client-metadata", state.config.external_base),
        redirect_uris: format!("{}/oauth/atp/callback", state.config.external_base),
        jwks_uri: Some(format!(
            "{}/.well-known/jwks.json",
            state.config.external_base
        )),
        signing_keys: state.atproto_oauth_signing_keys.clone(),
        client_name: Some("AIP OAuth Server".to_string()),
        client_uri: Some(state.config.external_base.clone()),
        logo_uri: None,
        tos_uri: None,
        policy_uri: None,
        scope: Some(state.config.oauth_supported_scopes.as_ref().join(" ")),
    };

    Ok(AtpBackedAuthorizationServer::new(
        base_auth_server,
        identity_resolver,
        http_client,
        state.oauth_request_storage.clone(),
        client_config,
        state.atp_session_storage.clone(),
        state.document_storage.clone(),
        state.authorization_request_storage.clone(),
        state.config.external_base.clone(),
    ))
}

/// Retrieve ATProtocol OAuth session with automatic refresh if needed
///
/// This function retrieves the ATProtocol OAuth session for a given DID and session_id.
/// If the access token is within 60 seconds of expiration or has already expired,
/// it will automatically refresh the token.
///
/// # Arguments
/// * `state` - The application state
/// * `did` - The DID (identifier) of the identity
/// * `session_id` - The session ID to retrieve
///
/// # Returns
/// A tuple containing:
/// * `Document` - The ATProtocol identity document
/// * `AtpOAuthSession` - The ATProtocol OAuth session (potentially refreshed)
pub async fn get_atprotocol_session_with_refresh(
    state: &AppState,
    document: &Document,
    session_id: &str,
) -> Result<
    crate::oauth::atprotocol_bridge::AtpOAuthSession,
    Box<dyn std::error::Error + Send + Sync>,
> {
    // Create ATProtocol-backed authorization server
    let atp_auth_server = create_atp_backed_server(state).await?;

    // Get sessions for the DID and session_id
    let sessions = atp_auth_server
        .session_storage()
        .get_sessions(&document.id, session_id)
        .await?;

    if sessions.is_empty() {
        return Err("No sessions found for the given DID and session_id".into());
    }

    // Use the most recent session (highest iteration)
    let session = &sessions[0];

    // Check if session has an exchange error
    if let Some(ref exchange_error) = session.exchange_error {
        return Err(format!("Session has exchange error: {}", exchange_error).into());
    }

    // Check if token needs refreshing
    let now = Utc::now();
    let needs_refresh = session
        .access_token_expires_at
        .map(|expires_at| {
            // Refresh if expired or within 60 seconds of expiration
            expires_at <= now || expires_at <= now + Duration::seconds(60)
        })
        .unwrap_or(false);

    let current_session = if needs_refresh {
        // Perform session refresh
        refresh_session(state, session, &atp_auth_server).await?
    } else {
        session.clone()
    };

    Ok(current_session)
}

/// Refresh an ATProtocol OAuth session using oauth_refresh workflow
pub async fn refresh_session(
    _state: &AppState,
    session: &crate::oauth::atprotocol_bridge::AtpOAuthSession,
    atp_auth_server: &crate::oauth::AtpBackedAuthorizationServer,
) -> Result<
    crate::oauth::atprotocol_bridge::AtpOAuthSession,
    Box<dyn std::error::Error + Send + Sync>,
> {
    use atproto_identity::key::identify_key;
    use atproto_oauth::workflow::oauth_refresh;

    let now = Utc::now();
    let new_iteration = session.iteration + 1;

    // Parse the DPoP key from the session
    let dpop_key =
        identify_key(&session.dpop_key).map_err(|e| format!("Failed to parse DPoP key: {}", e))?;

    // Create new session with incremented iteration
    let mut new_session = crate::oauth::atprotocol_bridge::AtpOAuthSession {
        session_id: session.session_id.clone(),
        did: session.did.clone(),
        session_created_at: session.session_created_at,
        atp_oauth_state: session.atp_oauth_state.clone(),
        signing_key_jkt: session.signing_key_jkt.clone(),
        dpop_key: session.dpop_key.clone(),
        access_token: None,
        refresh_token: None,
        access_token_created_at: None,
        access_token_expires_at: None,
        access_token_scopes: None,
        session_exchanged_at: Some(now),
        exchange_error: None,
        iteration: new_iteration,
    };

    // TODO: Re-resolve the DID when refreshing tokens.
    let did = session.did.as_ref().ok_or("Session does not have a DID")?;
    let document = match atp_auth_server
        .document_storage()
        .get_document_by_did(did)
        .await
    {
        Ok(Some(doc)) => doc,
        Ok(None) => {
            new_session.exchange_error = Some("DID document not found".to_string());
            atp_auth_server
                .session_storage()
                .store_session(&new_session)
                .await
                .map_err(|e| format!("Failed to store session with error: {}", e))?;
            return Err("DID document not found".into());
        }
        Err(e) => {
            new_session.exchange_error = Some(format!("Failed to get DID document: {}", e));
            atp_auth_server
                .session_storage()
                .store_session(&new_session)
                .await
                .map_err(|e| format!("Failed to store session with error: {}", e))?;
            return Err(format!("Failed to get DID document: {}", e).into());
        }
    };

    // Create OAuth client
    let oauth_client = atp_auth_server.create_oauth_client();

    // Attempt to refresh the session
    match session.refresh_token.as_ref() {
        Some(refresh_token) => {
            match oauth_refresh(
                atp_auth_server.http_client(),
                &oauth_client,
                &dpop_key,
                refresh_token,
                &document,
            )
            .await
            {
                Ok(token_response) => {
                    // Update session with new tokens
                    new_session.access_token = Some(token_response.access_token.clone());
                    new_session.refresh_token = Some(token_response.refresh_token.clone());
                    new_session.access_token_created_at = Some(now);
                    new_session.access_token_expires_at =
                        Some(now + Duration::seconds(token_response.expires_in as i64));
                    new_session.access_token_scopes = Some(
                        token_response
                            .scope
                            .split_whitespace()
                            .map(|s| s.to_string())
                            .collect(),
                    );
                }
                Err(e) => {
                    // Store the refresh error in the new session
                    new_session.exchange_error = Some(format!("Refresh failed: {}", e));
                }
            }
        }
        None => {
            new_session.exchange_error = Some("No refresh token available".to_string());
        }
    }

    // Store the new session
    atp_auth_server
        .session_storage()
        .store_session(&new_session)
        .await
        .map_err(|e| format!("Failed to store refreshed session: {}", e))?;

    // Return error if refresh failed
    if let Some(ref error) = new_session.exchange_error {
        return Err(error.clone().into());
    }

    Ok(new_session)
}

/// Configuration options for building OpenID claims
#[derive(Debug, Clone)]
pub struct ClaimsOptions {
    /// Whether ATProtocol scopes are required for profile information
    pub require_atproto_for_profile: bool,
    /// Whether ATProtocol email scope is required for email
    pub require_atproto_for_email: bool,
    /// Whether to attempt fetching email from PDS
    pub enable_email_fetching: bool,
}

impl Default for ClaimsOptions {
    fn default() -> Self {
        Self {
            require_atproto_for_profile: false,
            require_atproto_for_email: false,
            enable_email_fetching: true,
        }
    }
}

/// Build OpenID claims with document information based on scopes
///
/// This function enhances the provided OpenID claims with ATProtocol identity information
/// based on the requested scopes. It handles:
/// - DID resolution and document retrieval
/// - Profile information (name, PDS endpoint) based on profile scope
/// - Email fetching from ATProtocol PDS based on email scope
///
/// # Arguments
/// * `state` - The application state
/// * `claims` - Initial OpenID claims to enhance
/// * `user_id` - The DID of the user
/// * `scopes` - The OAuth scopes to check
/// * `session_id` - Optional session ID for email fetching
/// * `options` - Configuration options for claim building
pub async fn build_openid_claims_with_document_info(
    http_client: &reqwest::Client,
    mut claims: OpenIDClaims,
    document: &Document,
    scopes: &HashSet<String>,
    session: Option<&AtpOAuthSession>,
) -> Result<OpenIDClaims, Box<dyn std::error::Error + Send + Sync>> {
    // Check for standard OAuth scopes
    let has_profile_scope = scopes.contains("profile");
    let has_email_scope = scopes.contains("email");

    // Check for ATProtocol-specific scopes
    let has_atproto_scopes =
        scopes.contains("atproto:atproto") && scopes.contains("atproto:transition:generic");
    let has_atproto_email = scopes.contains("atproto:transition:email");

    // Always set the DID from the document
    claims = claims.with_did(document.id.clone());

    // Early return if no relevant scopes are present
    if !has_profile_scope && !has_email_scope {
        return Ok(claims);
    }

    // Check if we should proceed based on ATProtocol scope requirements
    if !has_atproto_scopes {
        return Ok(claims);
    }

    // Add profile information if profile scope is present and requirements are met
    let should_add_profile = has_profile_scope && has_atproto_scopes;

    if should_add_profile {
        let handle = document.handles().map(|h| h.to_string());
        let pds_endpoint = document.pds_endpoints().first().map(|v| v.to_string());

        claims = claims.with_name(handle).with_pds_endpoint(pds_endpoint);
    }

    // Add email information if email scope is present and requirements are met
    let should_add_email = has_email_scope && has_atproto_email;

    if let (true, Some(session)) = (should_add_email, session) {
        let email = if let (Some(atp_access_token), Some(pds_endpoint)) =
            (&session.access_token, document.pds_endpoints().first())
        {
            fetch_email_from_pds(
                http_client,
                atp_access_token,
                &session.dpop_key,
                pds_endpoint,
            )
            .await?
        } else {
            None
        };
        if email.is_some() {
            claims = claims.with_email(email);
        }
    }

    Ok(claims)
}

/// ATProtocol getSession response
#[derive(Debug, Deserialize)]
struct AtpGetSessionResponse {
    #[allow(dead_code)]
    handle: String,
    #[allow(dead_code)]
    did: String,
    email: Option<String>,
    #[allow(dead_code)]
    #[serde(rename = "emailConfirmed")]
    email_confirmed: Option<bool>,
}

/// Fetch email from ATProtocol PDS using DPoP
async fn fetch_email_from_pds(
    http_client: &reqwest::Client,
    atp_access_token: &str,
    dpop_key: &str,
    pds_endpoint: &str,
) -> Result<Option<String>, Box<dyn std::error::Error + Send + Sync>> {
    // Parse the DPoP key
    let dpop_private_key =
        identify_key(dpop_key).map_err(|e| format!("Failed to parse DPoP key: {}", e))?;

    // Create DPoP authentication
    let dpop_auth = DPoPAuth {
        dpop_private_key_data: dpop_private_key,
        oauth_access_token: atp_access_token.to_string(),
    };

    // Construct the getSession endpoint URL
    let get_session_url = format!("{}/xrpc/com.atproto.server.getSession", pds_endpoint);

    // Make DPoP GET request to the PDS
    let session_response =
        get_dpop_json_with_headers(http_client, &dpop_auth, &get_session_url, &HeaderMap::new())
            .await
            .map_err(|e| format!("Failed to fetch session from PDS: {}", e))?;

    // Parse the response
    let atp_session: AtpGetSessionResponse = serde_json::from_value(session_response)
        .map_err(|e| format!("Failed to parse ATProtocol session response: {}", e))?;

    Ok(atp_session.email)
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
    async fn test_create_atp_backed_server() {
        let app_state = create_test_app_state();
        let result = create_atp_backed_server(&app_state).await;
        assert!(result.is_ok());

        let _atp_server = result.unwrap();
        // Verify that the server was created successfully
        // The AtpBackedAuthorizationServer should be properly constructed
        // with all the required components
    }

    #[tokio::test]
    async fn test_create_atp_backed_server_with_custom_config() {
        let mut app_state = create_test_app_state();

        // Test with custom external base and PLC hostname
        let custom_config = Arc::new(crate::config::Config {
            version: "test".to_string(),
            http_port: "3000".to_string().try_into().unwrap(),
            http_static_path: "static".to_string(),
            http_templates_path: "templates".to_string(),
            external_base: "https://custom.oauth.example.com".to_string(),
            certificate_bundles: "".to_string().try_into().unwrap(),
            user_agent: "custom-user-agent".to_string(),
            plc_hostname: "custom.plc.example.com".to_string(),
            dns_nameservers: "".to_string().try_into().unwrap(),
            http_client_timeout: "30s".to_string().try_into().unwrap(),
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

        app_state.config = custom_config;

        let result = create_atp_backed_server(&app_state).await;
        assert!(result.is_ok());
    }

    #[test]
    fn test_atp_oauth_client_config_construction() {
        let external_base = "https://test.example.com";
        let expected_client_id = format!("{}/oauth/atp/client-metadata", external_base);
        let expected_redirect_uri = format!("{}/oauth/atp/callback", external_base);
        let expected_jwks_uri = format!("{}/.well-known/jwks.json", external_base);

        let client_config = OAuthClientConfig {
            client_id: expected_client_id.clone(),
            redirect_uris: expected_redirect_uri.clone(),
            jwks_uri: Some(expected_jwks_uri.clone()),
            signing_keys: vec![],
            client_name: Some("AIP OAuth Server".to_string()),
            client_uri: Some(external_base.to_string()),
            logo_uri: None,
            tos_uri: None,
            policy_uri: None,
            scope: Some(
                "atproto:atproto atproto:transition:generic atproto:transition:email".to_string(),
            ),
        };

        assert_eq!(client_config.client_id, expected_client_id);
        assert_eq!(
            client_config.client_name,
            Some("AIP OAuth Server".to_string())
        );
        assert_eq!(client_config.client_uri, Some(external_base.to_string()));
        assert_eq!(client_config.redirect_uris, expected_redirect_uri);
        assert_eq!(client_config.jwks_uri, Some(expected_jwks_uri));
        assert!(client_config.logo_uri.is_none());
        assert!(client_config.tos_uri.is_none());
        assert!(client_config.policy_uri.is_none());
        assert!(client_config.signing_keys.is_empty());
    }
}
