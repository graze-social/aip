//! Main router configuration assembling all OAuth and ATProtocol endpoints.

use axum::{
    Router, middleware,
    routing::{get, post},
};
use tower_http::{cors::CorsLayer, services::ServeDir, trace::TraceLayer};

use super::{
    context::AppState,
    handler_app_password::create_app_password_handler,
    handler_atprotocol_client_metadata::handle_atpoauth_client_metadata,
    handler_atprotocol_oauth_authorize::handle_oauth_authorize,
    handler_atprotocol_oauth_callback::handle_atpoauth_callback,
    handler_atprotocol_session::get_atprotocol_session_handler,
    handler_index::handle_index,
    handler_oauth::handle_oauth_token,
    handler_oauth_clients::{
        app_delete_client_handler, app_get_client_handler, app_register_client_handler,
        app_update_client_handler,
    },
    handler_par::pushed_authorization_request_handler,
    handler_userinfo::get_userinfo_handler,
    handler_well_known::{
        jwks_handler, oauth_authorization_server_handler, oauth_protected_resource_handler,
        openid_configuration_handler,
    },
    handler_xrpc_clients::xrpc_clients_update_handler,
};
use crate::http::middleware_auth::set_dpop_headers;

/// Build the application router
pub fn build_router(ctx: AppState) -> Router {
    // Create protected API routes with OAuth middleware
    let protected_api_routes = Router::new()
        .route("/atprotocol/session", get(get_atprotocol_session_handler))
        .route(
            "/atprotocol/app-password",
            post(create_app_password_handler),
        )
        .layer(middleware::map_response_with_state(
            ctx.clone(),
            set_dpop_headers,
        ));

    // Create OAuth routes for ATProtocol-backed authentication
    let mut oauth_routes = Router::new()
        .route("/authorize", get(handle_oauth_authorize))
        .route("/token", post(handle_oauth_token))
        .route("/userinfo", get(get_userinfo_handler))
        .route("/userinfo", post(get_userinfo_handler))
        .route("/par", post(pushed_authorization_request_handler))
        .route("/atp/callback", get(handle_atpoauth_callback))
        .route("/atp/client-metadata", get(handle_atpoauth_client_metadata));

    // Conditionally add client API endpoints
    if ctx.config.enable_client_api {
        oauth_routes = oauth_routes
            .route("/clients/register", post(app_register_client_handler))
            .route(
                "/clients/{client_id}",
                get(app_get_client_handler)
                    .put(app_update_client_handler)
                    .delete(app_delete_client_handler),
            );
    }

    oauth_routes = oauth_routes.layer(middleware::map_response_with_state(
        ctx.clone(),
        set_dpop_headers,
    ));

    // Create well-known discovery routes
    let well_known_routes = Router::new()
        .route(
            "/oauth-protected-resource",
            get(oauth_protected_resource_handler),
        )
        .route(
            "/oauth-authorization-server",
            get(oauth_authorization_server_handler),
        )
        .route("/openid-configuration", get(openid_configuration_handler))
        .route("/jwks.json", get(jwks_handler));

    // Configure CORS to allow React frontend access
    let cors = CorsLayer::new()
        .allow_origin([
            "http://localhost:3001"
                .parse::<axum::http::HeaderValue>()
                .unwrap(),
            "http://localhost:3002"
                .parse::<axum::http::HeaderValue>()
                .unwrap(),
            "https://psteniusubi.github.io"
                .parse::<axum::http::HeaderValue>()
                .unwrap(),
        ])
        .allow_methods([
            axum::http::Method::GET,
            axum::http::Method::POST,
            axum::http::Method::PUT,
            axum::http::Method::DELETE,
            axum::http::Method::OPTIONS,
        ])
        .allow_headers([
            axum::http::header::CONTENT_TYPE,
            axum::http::header::AUTHORIZATION,
            axum::http::header::ACCEPT,
        ]);

    // Build the main router
    Router::new()
        .route("/", get(handle_index))
        .nest("/api", protected_api_routes)
        .nest("/oauth", oauth_routes)
        .nest("/.well-known", well_known_routes)
        .route(
            "/xrpc/tools.graze.aip.clients.Update",
            post(xrpc_clients_update_handler),
        )
        .nest_service("/static", ServeDir::new(&ctx.config.http_static_path))
        .layer(cors)
        .layer(TraceLayer::new_for_http())
        .with_state(ctx)
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
        let client_registration_service = Arc::new(crate::oauth::ClientRegistrationService::new(
            oauth_storage.clone(),
            chrono::Duration::days(1),
            chrono::Duration::days(14),
            true,
        ));

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

        AppState {
            http_client,
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
    fn test_build_router_structure() {
        let app_state = create_test_app_state();
        let _router = build_router(app_state);
        // Just verify that the router builds without panicking
        // This tests the middleware setup and route configuration
    }
}
