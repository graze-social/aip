//! Handles POST /oauth/clients/register - Dynamic OAuth client registration per RFC 7591

use axum::{
    extract::{Json, Path, State},
    http::{HeaderMap, StatusCode},
    response::Json as ResponseJson,
};
use serde_json::{Value, json};

use crate::{
    errors::ClientRegistrationError,
    http::context::AppState,
    oauth::{
        clients::registration::ClientServiceAuth,
        types::{
            ClientRegistrationRequest, ClientRegistrationResponse,
            FilteredClientRegistrationResponse,
        },
    },
};

/// Extract bearer token from Authorization header
fn extract_bearer_token(headers: &HeaderMap) -> Result<String, (StatusCode, ResponseJson<Value>)> {
    let auth_header = headers
        .get("authorization")
        .and_then(|h| h.to_str().ok())
        .ok_or_else(|| {
            (
                StatusCode::UNAUTHORIZED,
                ResponseJson(json!({
                    "error": "invalid_token",
                    "error_description": "Missing Authorization header"
                })),
            )
        })?;

    if !auth_header.starts_with("Bearer ") {
        return Err((
            StatusCode::UNAUTHORIZED,
            ResponseJson(json!({
                "error": "invalid_token",
                "error_description": "Authorization header must use Bearer token"
            })),
        ));
    }

    let token = &auth_header[7..]; // Remove "Bearer " prefix
    if token.is_empty() {
        return Err((
            StatusCode::UNAUTHORIZED,
            ResponseJson(json!({
                "error": "invalid_token",
                "error_description": "Bearer token cannot be empty"
            })),
        ));
    }

    Ok(token.to_string())
}

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
    headers: HeaderMap,
) -> Result<ResponseJson<FilteredClientRegistrationResponse>, (StatusCode, ResponseJson<Value>)> {
    let service = state.client_registration_service.clone();
    let registration_token = extract_bearer_token(&headers)?;

    let client_service_auth = ClientServiceAuth::RegistrationToken(registration_token);
    match service.get_client(&client_id, &client_service_auth).await {
        Ok(response) => {
            let filtered_response = FilteredClientRegistrationResponse::from(response);
            Ok(ResponseJson(filtered_response))
        }
        Err(e) => {
            let (status, error_code, description) = match &e {
                ClientRegistrationError::ClientNotFound(_) => {
                    (StatusCode::NOT_FOUND, "client_not_found", e.to_string())
                }
                ClientRegistrationError::InvalidRegistrationToken(_) => {
                    (StatusCode::UNAUTHORIZED, "invalid_token", e.to_string())
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
    headers: HeaderMap,
    Json(request): Json<ClientRegistrationRequest>,
) -> Result<ResponseJson<FilteredClientRegistrationResponse>, (StatusCode, ResponseJson<Value>)> {
    let service = state.client_registration_service.clone();
    let registration_token = extract_bearer_token(&headers)?;

    let client_service_auth = ClientServiceAuth::RegistrationToken(registration_token);
    match service
        .update_client_with_supported_scopes(
            &client_id,
            &client_service_auth,
            request,
            Some(&state.config.oauth_supported_scopes),
        )
        .await
    {
        Ok(response) => {
            let filtered_response = FilteredClientRegistrationResponse::from(response);
            Ok(ResponseJson(filtered_response))
        }
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
                ClientRegistrationError::InvalidRegistrationToken(_) => {
                    (StatusCode::UNAUTHORIZED, "invalid_token", e.to_string())
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

pub async fn app_delete_client_handler(
    State(state): State<AppState>,
    Path(client_id): Path<String>,
    headers: HeaderMap,
) -> Result<StatusCode, (StatusCode, ResponseJson<Value>)> {
    let service = state.client_registration_service.clone();
    let registration_token = extract_bearer_token(&headers)?;

    let client_service_auth = ClientServiceAuth::RegistrationToken(registration_token);
    match service
        .delete_client(&client_id, &client_service_auth)
        .await
    {
        Ok(()) => Ok(StatusCode::NO_CONTENT),
        Err(e) => {
            let (status, error_code, description) = match &e {
                ClientRegistrationError::ClientNotFound(_) => {
                    (StatusCode::NOT_FOUND, "client_not_found", e.to_string())
                }
                ClientRegistrationError::InvalidRegistrationToken(_) => {
                    (StatusCode::UNAUTHORIZED, "invalid_token", e.to_string())
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
