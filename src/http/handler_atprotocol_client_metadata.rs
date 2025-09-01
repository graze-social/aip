//! Handles GET /oauth-client-metadata.json - Provides ATProtocol OAuth client metadata per RFC 7591

use atproto_oauth_axum::{handler_metadata::handle_oauth_metadata, state::OAuthClientConfig};
use axum::{extract::State, response::IntoResponse};

use super::context::AppState;
use crate::config::ATPROTO_CLIENT_METADATA_PATH;

/// Handles requests for ATProtocol OAuth client metadata.
///
/// This endpoint provides client metadata required for ATProtocol OAuth flows,
/// conforming to RFC 7591 client metadata specification.
pub async fn handle_atpoauth_client_metadata(
    State(app_state): State<AppState>,
) -> impl IntoResponse {
    // Convert AppState configuration to OAuthClientConfig
    // Use configured server scopes
    let scopes = app_state
        .config
        .oauth_supported_scopes
        .as_strings()
        .join(" ");

    let oauth_client_config = OAuthClientConfig {
        client_id: format!(
            "{}{}",
            app_state.config.external_base, ATPROTO_CLIENT_METADATA_PATH
        ),
        redirect_uris: format!("{}/oauth/atp/callback", app_state.config.external_base),
        jwks_uri: None, // Use inline JWKS instead of external URI
        signing_keys: app_state.atproto_oauth_signing_keys.clone(),
        client_name: Some(app_state.config.atproto_client_name.as_ref().clone()),
        client_uri: Some(app_state.config.external_base.clone()),
        logo_uri: app_state.config.atproto_client_logo.as_ref().clone(),
        tos_uri: app_state.config.atproto_client_tos.as_ref().clone(),
        policy_uri: app_state.config.atproto_client_policy.as_ref().clone(),
        scope: Some(scopes),
    };

    // Use the atproto-oauth-axum handler
    handle_oauth_metadata(oauth_client_config).await
}
