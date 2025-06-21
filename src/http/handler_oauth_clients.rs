//! Handles POST /oauth/clients/register - Dynamic OAuth client registration per RFC 7591

use axum::{
    extract::{Json, Path, State},
    http::StatusCode,
    response::Json as ResponseJson,
};
use serde_json::{Value, json};

use crate::{
    errors::ClientRegistrationError,
    http::context::AppState,
    oauth::types::{ClientRegistrationRequest, ClientRegistrationResponse},
};

pub async fn app_register_client_handler(
    State(state): State<AppState>,
    Json(request): Json<ClientRegistrationRequest>,
) -> Result<ResponseJson<ClientRegistrationResponse>, (StatusCode, ResponseJson<Value>)> {
    let service = state.client_registration_service.clone();

    match service
        .register_client_with_supported_scopes(request, Some(&state.config.oauth_supported_scopes))
        .await
    {
        Ok(response) => Ok(ResponseJson(response)),
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
                ClientRegistrationError::RegistrationDisabled => (
                    StatusCode::FORBIDDEN,
                    "registration_not_supported",
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

pub async fn app_get_client_handler(
    State(state): State<AppState>,
    Path(client_id): Path<String>,
) -> Result<ResponseJson<ClientRegistrationResponse>, (StatusCode, ResponseJson<Value>)> {
    let service = state.client_registration_service.clone();

    match service.get_client(&client_id, "placeholder").await {
        Ok(response) => Ok(ResponseJson(response)),
        Err(e) => {
            let (status, error_code, description) = match &e {
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

pub async fn app_update_client_handler(
    State(state): State<AppState>,
    Path(client_id): Path<String>,
    Json(request): Json<ClientRegistrationRequest>,
) -> Result<ResponseJson<ClientRegistrationResponse>, (StatusCode, ResponseJson<Value>)> {
    let service = state.client_registration_service.clone();

    match service
        .update_client_with_supported_scopes(
            &client_id,
            "placeholder",
            request,
            Some(&state.config.oauth_supported_scopes),
        )
        .await
    {
        Ok(response) => Ok(ResponseJson(response)),
        Err(e) => {
            let (status, error_code, description) = match &e {
                ClientRegistrationError::ClientNotFound(_) => {
                    (StatusCode::NOT_FOUND, "client_not_found", e.to_string())
                }
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

pub async fn app_delete_client_handler(
    State(state): State<AppState>,
    Path(client_id): Path<String>,
) -> Result<StatusCode, (StatusCode, ResponseJson<Value>)> {
    let service = state.client_registration_service.clone();

    match service.delete_client(&client_id, "placeholder").await {
        Ok(()) => Ok(StatusCode::NO_CONTENT),
        Err(e) => {
            let (status, error_code, description) = match &e {
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
