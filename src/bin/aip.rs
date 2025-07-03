//! ATProtocol Identity Provider server binary.
//!
//! Main application entry point that configures OAuth 2.1 authorization server
//! with ATProtocol integration and starts the HTTP server with graceful shutdown.

use aip::{
    config::Config,
    errors::StorageError,
    http::{AppEngine, AppState, build_router},
    oauth::{
        DPoPNonceGenerator, UnifiedAtpOAuthSessionStorageAdapter,
        UnifiedAuthorizationRequestStorageAdapter,
        atprotocol_bridge::{AtpOAuthSessionStorage, AuthorizationRequestStorage},
        clients::registration::ClientRegistrationService,
    },
    storage::{
        StorageBackend, create_storage_backend, key_provider::SimpleKeyProvider,
        parse_storage_backend,
    },
};
use anyhow::Result;
use atproto_identity::{
    resolve::{IdentityResolver, InnerIdentityResolver, create_resolver},
    storage::DidDocumentStorage,
    storage_lru::LruDidDocumentStorage,
};
use atproto_oauth::{storage::OAuthRequestStorage, storage_lru::LruOAuthRequestStorage};
use std::{env, num::NonZeroUsize, sync::Arc};

#[cfg(feature = "postgres")]
use aip::storage::{PostgresOAuthRequestStorage, postgres::PostgresDidDocumentStorage};

use tokio::net::TcpListener;
use tokio::signal;
use tokio_util::{sync::CancellationToken, task::TaskTracker};
use tracing_subscriber::prelude::*;

// Type alias to simplify the complex storage tuple type
type StorageTuple = (
    Arc<dyn aip::storage::traits::OAuthStorage>,
    Arc<dyn OAuthRequestStorage>,
    Arc<dyn DidDocumentStorage>,
    Arc<dyn AtpOAuthSessionStorage>,
    Arc<dyn AuthorizationRequestStorage>,
);

#[cfg(feature = "embed")]
use aip::templates::build_env;

#[cfg(feature = "reload")]
use aip::templates::build_env;

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::registry()
        .with(tracing_subscriber::EnvFilter::new(
            std::env::var("RUST_LOG").unwrap_or_else(|_| "aip=debug,info".into()),
        ))
        .with(tracing_subscriber::fmt::layer().pretty())
        .init();

    let version = aip::config::version()?;

    env::args().for_each(|arg| {
        if arg == "--version" {
            println!("{version}");
            std::process::exit(0);
        }
    });

    tracing::info!(?version, "Starting AIP");

    let config = Config::new()?;

    // Build HTTP client with certificate bundles
    let mut client_builder = reqwest::Client::builder();
    for ca_certificate in config.certificate_bundles.as_ref() {
        tracing::info!("Loading CA certificate: {:?}", ca_certificate);
        let cert = std::fs::read(ca_certificate)?;
        let cert = reqwest::Certificate::from_pem(&cert)?;
        client_builder = client_builder.add_root_certificate(cert);
    }

    client_builder = client_builder
        .user_agent(config.user_agent.clone())
        .timeout(*config.http_client_timeout.as_ref());
    let http_client = client_builder.build()?;

    // Initialize template engine
    // Setup template engine
    let template_env = {
        #[cfg(feature = "embed")]
        {
            AppEngine::from(build_env(
                config.external_base.clone(),
                env!("CARGO_PKG_VERSION").to_string(),
            ))
        }

        #[cfg(feature = "reload")]
        {
            AppEngine::from(build_env())
        }

        #[cfg(not(any(feature = "reload", feature = "embed")))]
        {
            use minijinja::Environment;
            let mut env = Environment::new();
            // Add a simple template for the minimal case
            env.add_template(
                "index.html",
                "<!DOCTYPE html><html><body>Showcase</body></html>",
            )
            .unwrap();
            env.add_template(
                "identity.html",
                "<!DOCTYPE html><html><body>Identity</body></html>",
            )
            .unwrap();
            AppEngine::from(env)
        }
    };

    // Initialize the DNS resolver
    let dns_resolver = create_resolver(config.dns_nameservers.as_ref());

    // Initialize the identity resolver
    let identity_resolver = IdentityResolver(Arc::new(InnerIdentityResolver {
        dns_resolver,
        http_client: http_client.clone(),
        plc_hostname: config.plc_hostname.clone(),
    }));

    // Initialize OAuth storage components
    let key_provider = Arc::new(SimpleKeyProvider::new());

    // Parse storage backend configuration
    let storage_backend =
        parse_storage_backend(&config.storage_backend, config.database_url.as_deref())?;

    // Create storage backends based on configuration
    let (
        oauth_storage,
        oauth_request_storage,
        document_storage,
        atp_session_storage,
        authorization_request_storage,
    ): StorageTuple = match &storage_backend {
        StorageBackend::Memory => {
            let oauth_storage = create_storage_backend(storage_backend.clone())
                .await
                .map_err(|e| {
                    StorageError::DatabaseError(format!("Storage backend creation failed: {}", e))
                })?;
            let oauth_request_storage =
                Arc::new(LruOAuthRequestStorage::new(NonZeroUsize::new(256).unwrap()));
            let document_storage =
                Arc::new(LruDidDocumentStorage::new(NonZeroUsize::new(255).unwrap()));

            // Use adapters to bridge from unified storage to oauth bridge traits
            let atp_session_storage: Arc<dyn AtpOAuthSessionStorage> = Arc::new(
                UnifiedAtpOAuthSessionStorageAdapter::new(oauth_storage.clone()),
            );
            let authorization_request_storage: Arc<dyn AuthorizationRequestStorage> = Arc::new(
                UnifiedAuthorizationRequestStorageAdapter::new(oauth_storage.clone()),
            );

            (
                oauth_storage,
                oauth_request_storage,
                document_storage,
                atp_session_storage,
                authorization_request_storage,
            )
        }
        #[cfg(feature = "postgres")]
        StorageBackend::Postgres(database_url) => {
            // Create PostgreSQL connection pool
            let pool = sqlx::postgres::PgPool::connect(database_url)
                .await
                .map_err(|e| {
                    StorageError::ConnectionFailed(format!("PostgreSQL connection failed: {}", e))
                })?;

            // Create PostgreSQL storage implementations
            let postgres_oauth_storage =
                aip::storage::postgres::PostgresOAuthStorage::new(pool.clone());

            // Run migrations
            postgres_oauth_storage
                .migrate()
                .await
                .map_err(|e| StorageError::DatabaseError(format!("Migration failed: {}", e)))?;

            let oauth_request_storage = Arc::new(PostgresOAuthRequestStorage::new(pool.clone()));
            let document_storage = Arc::new(PostgresDidDocumentStorage::new(pool));

            let oauth_storage_arc = Arc::new(postgres_oauth_storage);

            // Use adapters to bridge from unified storage to oauth bridge traits
            let atp_session_storage: Arc<dyn AtpOAuthSessionStorage> = Arc::new(
                UnifiedAtpOAuthSessionStorageAdapter::new(oauth_storage_arc.clone()),
            );
            let authorization_request_storage: Arc<dyn AuthorizationRequestStorage> = Arc::new(
                UnifiedAuthorizationRequestStorageAdapter::new(oauth_storage_arc.clone()),
            );

            (
                oauth_storage_arc,
                oauth_request_storage,
                document_storage,
                atp_session_storage,
                authorization_request_storage,
            )
        }
        #[cfg(feature = "sqlite")]
        StorageBackend::Sqlite(_) => {
            let oauth_storage = create_storage_backend(storage_backend.clone())
                .await
                .map_err(|e| {
                    StorageError::DatabaseError(format!("Storage backend creation failed: {}", e))
                })?;
            let oauth_request_storage =
                Arc::new(LruOAuthRequestStorage::new(NonZeroUsize::new(256).unwrap()));
            let document_storage =
                Arc::new(LruDidDocumentStorage::new(NonZeroUsize::new(255).unwrap()));

            // Use adapters to bridge from unified storage to oauth bridge traits
            let atp_session_storage: Arc<dyn AtpOAuthSessionStorage> = Arc::new(
                UnifiedAtpOAuthSessionStorageAdapter::new(oauth_storage.clone()),
            );
            let authorization_request_storage: Arc<dyn AuthorizationRequestStorage> = Arc::new(
                UnifiedAuthorizationRequestStorageAdapter::new(oauth_storage.clone()),
            );

            (
                oauth_storage,
                oauth_request_storage,
                document_storage,
                atp_session_storage,
                authorization_request_storage,
            )
        }
    };

    // Create client registration service for dynamic client registration
    let client_registration_service = Arc::new(ClientRegistrationService::new(
        oauth_storage.clone(),
        *config.client_default_access_token_expiration.as_ref(),
        *config.client_default_refresh_token_expiration.as_ref(),
        *config.client_default_redirect_exact.as_ref(),
    ));

    // Create application context
    let app_context = AppState {
        http_client: http_client.clone(),
        config: Arc::new(config.clone()),
        template_env,
        identity_resolver,
        key_provider,
        oauth_request_storage,
        document_storage,
        oauth_storage,
        client_registration_service,
        atp_session_storage,
        authorization_request_storage,
        atproto_oauth_signing_keys: config.atproto_oauth_signing_keys.as_ref().clone(),
        dpop_nonce_provider: Arc::new(DPoPNonceGenerator::new(config.dpop_nonce_seed.clone(), 2)),
    };

    // Build the router
    let app = build_router(app_context);

    // Setup graceful shutdown
    let tracker = TaskTracker::new();
    let token = CancellationToken::new();

    {
        let tracker = tracker.clone();
        let inner_token = token.clone();

        let ctrl_c = async {
            signal::ctrl_c()
                .await
                .expect("failed to install Ctrl+C handler");
        };

        #[cfg(unix)]
        let terminate = async {
            signal::unix::signal(signal::unix::SignalKind::terminate())
                .expect("failed to install signal handler")
                .recv()
                .await;
        };

        #[cfg(not(unix))]
        let terminate = std::future::pending::<()>();

        tokio::spawn(async move {
            tokio::select! {
                () = inner_token.cancelled() => { },
                _ = terminate => {},
                _ = ctrl_c => {},
            }

            tracker.close();
            inner_token.cancel();
        });
    }

    // Start HTTP server
    {
        let inner_config = config.clone();
        let http_port = *inner_config.http_port.as_ref();
        let inner_token = token.clone();
        tracker.spawn(async move {
            let bind_address = format!("0.0.0.0:{http_port}");
            tracing::info!("Starting server on {bind_address}");
            let listener = TcpListener::bind(&bind_address).await.unwrap();

            let shutdown_token = inner_token.clone();
            let result = axum::serve(listener, app)
                .with_graceful_shutdown(async move {
                    tokio::select! {
                        () = shutdown_token.cancelled() => { }
                    }
                    tracing::info!("axum graceful shutdown complete");
                })
                .await;
            if let Err(err) = result {
                tracing::error!("axum task failed: {}", err);
            }

            inner_token.cancel();
        });
    }

    tracker.wait().await;

    Ok(())
}
