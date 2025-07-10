//! Handles GET / - Renders the main index page of the application

use axum::{extract::State, response::IntoResponse};
use axum_template::RenderHtml;
use minijinja::context;

use super::context::AppState;
use crate::errors::Result;

/// Handle requests to the index page
pub async fn handle_index(State(state): State<AppState>) -> Result<impl IntoResponse> {
    Ok(RenderHtml(
        "index.html",
        state.template_env.clone(),
        context! {
            title => "Hello World",
        },
    ))
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
    async fn test_handle_index() {
        let app_state = create_test_app_state();
        let result = handle_index(State(app_state)).await;
        assert!(result.is_ok());
    }
}
