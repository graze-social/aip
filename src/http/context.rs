//! Application state and request context management.

use atproto_identity::{
    axum::state::DidDocumentStorageExtractor,
    key::{KeyData, KeyProvider},
    resolve::IdentityResolver,
    storage::DidDocumentStorage,
};
use atproto_oauth::storage::OAuthRequestStorage;
use axum::extract::FromRef;
use axum_template::engine::Engine;
use std::sync::Arc;

use crate::oauth::{
    atprotocol_bridge::{AtpOAuthSessionStorage, AuthorizationRequestStorage},
    clients::registration::ClientRegistrationService,
};
use crate::storage::traits::OAuthStorage;
use crate::{config::Config, oauth::DPoPNonceProvider};

#[cfg(feature = "reload")]
use minijinja_autoreload::AutoReloader;

#[cfg(feature = "reload")]
/// Template engine with auto-reloading support for development.
pub type AppEngine = Engine<AutoReloader>;

#[cfg(feature = "embed")]
use minijinja::Environment;

#[cfg(feature = "embed")]
pub type AppEngine = Engine<Environment<'static>>;

#[cfg(not(any(feature = "reload", feature = "embed")))]
pub type AppEngine = Engine<minijinja::Environment<'static>>;

#[derive(Clone)]
pub struct AppState {
    pub http_client: reqwest::Client,
    pub config: Arc<Config>,
    /// Template engine for rendering HTML responses.
    pub template_env: AppEngine,
    /// Identity resolver for ATProtocol DIDs
    pub identity_resolver: IdentityResolver,
    /// Key provider for OAuth signing keys
    pub key_provider: Arc<dyn KeyProvider + Send + Sync>,
    /// OAuth request storage for ATProtocol flows
    pub oauth_request_storage: Arc<dyn OAuthRequestStorage + Send + Sync>,
    /// DID document storage
    pub document_storage: Arc<dyn DidDocumentStorage + Send + Sync>,
    /// OAuth storage for tokens, clients, and codes
    pub oauth_storage: Arc<dyn OAuthStorage + Send + Sync>,

    /// Client registration service for dynamic client registration
    pub client_registration_service: Arc<ClientRegistrationService>,
    /// ATP OAuth session storage
    pub atp_session_storage: Arc<dyn AtpOAuthSessionStorage + Send + Sync>,
    /// Authorization request storage for ATProtocol OAuth flows
    pub authorization_request_storage: Arc<dyn AuthorizationRequestStorage + Send + Sync>,
    /// ATProtocol OAuth signing keys for client metadata
    pub atproto_oauth_signing_keys: Vec<KeyData>,

    pub dpop_nonce_provider: Arc<dyn DPoPNonceProvider>,
}

impl FromRef<AppState> for Arc<dyn DPoPNonceProvider> {
    fn from_ref(app_state: &AppState) -> Self {
        app_state.dpop_nonce_provider.clone()
    }
}

impl FromRef<AppState> for DidDocumentStorageExtractor {
    fn from_ref(app_state: &AppState) -> Self {
        atproto_identity::axum::state::DidDocumentStorageExtractor(
            app_state.document_storage.clone(),
        )
    }
}
