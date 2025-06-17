//! ATProtocol OAuth server configuration utilities.

use std::sync::Arc;

use super::context::AppState;
use crate::oauth::{auth_server::AuthorizationServer, AtpBackedAuthorizationServer};
use atproto_oauth_axum::state::OAuthClientConfig;

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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::oauth::resource_server::ResourceServer;
    use crate::oauth::DPoPNonceGenerator;
    use crate::storage::inmemory::MemoryOAuthStorage;
    use crate::storage::SimpleKeyProvider;
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
                http_client,
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
