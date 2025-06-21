//! Handles GET /oauth/atp/client-metadata - Provides ATProtocol OAuth client metadata per RFC 7591

use atproto_oauth_axum::{handler_metadata::handle_oauth_metadata, state::OAuthClientConfig};
use axum::{extract::State, response::IntoResponse};

use super::context::AppState;

/// Handles requests for ATProtocol OAuth client metadata.
///
/// This endpoint provides client metadata required for ATProtocol OAuth flows,
/// conforming to RFC 7591 client metadata specification.
pub async fn handle_atpoauth_client_metadata(
    State(app_state): State<AppState>,
) -> impl IntoResponse {
    // Convert AppState configuration to OAuthClientConfig
    let oauth_client_config = OAuthClientConfig {
        client_id: format!(
            "{}/oauth/atp/client-metadata",
            app_state.config.external_base
        ),
        redirect_uris: format!("{}/oauth/atp/callback", app_state.config.external_base),
        jwks_uri: None, // Use inline JWKS instead of external URI
        signing_keys: app_state.atproto_oauth_signing_keys.clone(),
        client_name: Some("AIP OAuth Server".to_string()),
        client_uri: Some(app_state.config.external_base.clone()),
        logo_uri: None,
        tos_uri: None,
        policy_uri: None,
        scope: Some(app_state.config.oauth_supported_scopes.as_ref().join(" ")),
    };

    // Use the atproto-oauth-axum handler
    handle_oauth_metadata(oauth_client_config).await
}
