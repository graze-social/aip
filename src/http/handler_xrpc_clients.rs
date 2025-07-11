//! Handles XRPC requests to /xrpc/tools.graze.aip.clients.Update

use atproto_xrpcs::authorization::Authorization;
use axum::{
    extract::{Json, State},
    http::StatusCode,
    response::Json as ResponseJson,
};
use serde_json::{Value, json};

use crate::{
    errors::ClientRegistrationError,
    http::context::AppState,
    oauth::{clients::registration::ClientServiceAuth, types::UpdateClientRequest},
};

pub(crate) fn match_lxm(authorization: &Authorization, lxm: &str) -> bool {
    authorization
        .1
        .private
        .get("lxm")
        .and_then(|value| value.as_str())
        .is_some_and(|value| value == lxm)
}

#[allow(dead_code)]
pub(crate) fn match_issuer(authorization: &Authorization, issuer: &str) -> bool {
    authorization
        .1
        .private
        .get("iss")
        .and_then(|value| value.as_str())
        .is_some_and(|value| value == issuer)
}

pub(crate) fn match_any_issuer(authorization: &Authorization, issuers: &Vec<String>) -> bool {
    authorization
        .1
        .private
        .get("iss")
        .and_then(|value| value.as_str())
        .is_some_and(|value| issuers.iter().any(|issuer| *issuer == value))
}

pub async fn xrpc_clients_update_handler(
    State(state): State<AppState>,
    authorization: Option<Authorization>,
    Json(request): Json<UpdateClientRequest>,
) -> Result<ResponseJson<Value>, (StatusCode, ResponseJson<Value>)> {
    // Extract Authorization header
    if authorization.is_none() {
        return Err((
            StatusCode::UNAUTHORIZED,
            ResponseJson(json!({
                "error": "missing_authorization",
                "error_description": "Missing Authorization header"
            })),
        ));
    }
    let authorization = authorization.unwrap();

    if !match_lxm(&authorization, "tools.graze.aip.clients.Update") {
        return Err((
            StatusCode::UNAUTHORIZED,
            ResponseJson(json!({
                "error": "unauthorized",
                "error_description": "invalid lxm claim"
            })),
        ));
    }
    if !match_any_issuer(&authorization, state.config.admin_dids.as_ref()) {
        return Err((
            StatusCode::UNAUTHORIZED,
            ResponseJson(json!({
                "error": "unauthorized",
                "error_description": "invalid iss claim"
            })),
        ));
    }

    // Convert UpdateClientRequest to ClientRegistrationRequest for reuse
    let client_registration_request = crate::oauth::types::ClientRegistrationRequest {
        client_name: request.client_name,
        redirect_uris: request.redirect_uris,
        grant_types: request.grant_types,
        response_types: request.response_types,
        scope: request.scope,
        token_endpoint_auth_method: request.token_endpoint_auth_method,
        metadata: request.metadata,
    };

    // Use the existing client registration service to update the client
    let service = state.client_registration_service.clone();
    match service
        .update_client_with_supported_scopes(
            &request.client_id,
            &ClientServiceAuth::DID,
            client_registration_request,
            Some(&state.config.oauth_supported_scopes),
        )
        .await
    {
        Ok(response) => {
            // Fetch the full client data to get all fields
            match state.oauth_storage.get_client(&request.client_id).await {
                Ok(Some(client)) => Ok(ResponseJson(json!({
                    // All OAuthClient fields
                    "client_id": client.client_id,
                    "client_secret": client.client_secret,
                    "client_name": client.client_name,
                    "redirect_uris": client.redirect_uris,
                    "grant_types": client.grant_types,
                    "response_types": client.response_types,
                    "scope": client.scope,
                    "token_endpoint_auth_method": client.token_endpoint_auth_method,
                    "client_type": client.client_type,
                    "created_at": client.created_at,
                    "updated_at": client.updated_at,
                    "metadata": client.metadata,
                    "access_token_expiration": client.access_token_expiration.num_seconds(),
                    "refresh_token_expiration": client.refresh_token_expiration.num_seconds(),
                    "require_redirect_exact": client.require_redirect_exact,
                    "registration_access_token": client.registration_access_token,
                    // Additional fields from the response
                    "registration_client_uri": response.registration_client_uri,
                    "client_id_issued_at": response.client_id_issued_at,
                    "client_secret_expires_at": response.client_secret_expires_at,
                }))),
                Ok(None) => Err((
                    StatusCode::NOT_FOUND,
                    ResponseJson(json!({
                        "error": "client_not_found",
                        "error_description": "Client not found after update"
                    })),
                )),
                Err(e) => Err((
                    StatusCode::INTERNAL_SERVER_ERROR,
                    ResponseJson(json!({
                        "error": "server_error",
                        "error_description": format!("Failed to fetch client after update: {:?}", e)
                    })),
                )),
            }
        }
        Err(e) => {
            let (status, error_code, description) = match &e {
                ClientRegistrationError::InvalidClientMetadata(_) => (
                    StatusCode::BAD_REQUEST,
                    "invalid_client_metadata",
                    e.to_string(),
                ),
                ClientRegistrationError::InvalidRedirectUri(_) => (
                    StatusCode::BAD_REQUEST,
                    "invalid_redirect_uri",
                    e.to_string(),
                ),
                ClientRegistrationError::ClientNotFound(_) => {
                    (StatusCode::NOT_FOUND, "client_not_found", e.to_string())
                }
                _ => (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "server_error",
                    "Internal server error".to_string(),
                ),
            };

            Err((
                status,
                ResponseJson(json!({
                    "error": error_code,
                    "error_description": description
                })),
            ))
        }
    }
}
