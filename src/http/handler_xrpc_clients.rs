//! Handles XRPC requests to /xrpc/tools.graze.aip.clients.Update

use axum::{
    extract::{Json, State},
    http::{HeaderMap, StatusCode},
    response::Json as ResponseJson,
};
use serde_json::{Value, json};

use crate::{
    errors::ClientRegistrationError,
    http::context::AppState,
    oauth::types::UpdateClientRequest,
};

pub async fn xrpc_clients_update_handler(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(request): Json<UpdateClientRequest>,
) -> Result<ResponseJson<Value>, (StatusCode, ResponseJson<Value>)> {
    // Extract Authorization header
    let auth_header = headers.get("authorization")
        .and_then(|h| h.to_str().ok())
        .ok_or_else(|| (
            StatusCode::UNAUTHORIZED,
            ResponseJson(json!({
                "error": "missing_authorization",
                "error_description": "Missing Authorization header"
            })),
        ))?;

    // For now, implement a basic check - in a real implementation, 
    // you would need to properly parse and validate the XRPC authorization
    // This is a simplified version that expects the Authorization header to contain a DID
    let issuer_did = if auth_header.starts_with("Bearer ") {
        &auth_header[7..] // Remove "Bearer " prefix
    } else {
        auth_header
    };

    // Verify the issuer is in the admin DIDs list
    let admin_dids = state.config.admin_dids.as_ref();
    if !admin_dids.contains(&issuer_did.to_string()) {
        return Err((
            StatusCode::FORBIDDEN,
            ResponseJson(json!({
                "error": "unauthorized_issuer", 
                "error_description": "Issuer is not authorized to perform this action"
            })),
        ));
    }

    // Look up the client
    let _client = match state.oauth_storage.get_client(&request.client_id).await {
        Ok(Some(client)) => client,
        Ok(None) => {
            return Err((
                StatusCode::NOT_FOUND,
                ResponseJson(json!({
                    "error": "client_not_found",
                    "error_description": format!("Client with ID '{}' not found", request.client_id)
                })),
            ));
        }
        Err(e) => {
            return Err((
                StatusCode::INTERNAL_SERVER_ERROR,
                ResponseJson(json!({
                    "error": "storage_error",
                    "error_description": format!("Storage error: {:?}", e)
                })),
            ));
        }
    };

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
            "admin", // Placeholder token since we're using admin authorization
            client_registration_request,
            Some(&state.config.oauth_supported_scopes),
        )
        .await
    {
        Ok(response) => Ok(ResponseJson(json!({
            "client_id": response.client_id,
            "client_name": response.client_name,
            "redirect_uris": response.redirect_uris,
            "grant_types": response.grant_types,
            "response_types": response.response_types,
            "scope": response.scope,
            "token_endpoint_auth_method": response.token_endpoint_auth_method,
            "updated": true
        }))),
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
                ClientRegistrationError::ClientNotFound(_) => (
                    StatusCode::NOT_FOUND,
                    "client_not_found",
                    e.to_string(),
                ),
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