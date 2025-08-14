//! RFC 8628 Device Authorization Grant endpoints

use axum::{
    extract::State,
    http::StatusCode,
    response::Json as ResponseJson,
    Form,
};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use uuid::Uuid;

use crate::http::context::AppState;

/// Device Authorization Request (RFC 8628 Section 3.1)
#[derive(Debug, Deserialize)]
pub struct DeviceAuthorizationRequest {
    /// Client identifier
    pub client_id: String,
    /// Scope (optional)
    pub scope: Option<String>,
}

/// Device Authorization Response (RFC 8628 Section 3.2)
#[derive(Debug, Serialize)]
pub struct DeviceAuthorizationResponse {
    /// Device verification code
    pub device_code: String,
    /// User verification code
    pub user_code: String,
    /// End-user verification URI
    pub verification_uri: String,
    /// Complete verification URI (optional)
    pub verification_uri_complete: Option<String>,
    /// Device code expires in seconds
    pub expires_in: u64,
    /// Minimum polling interval
    pub interval: Option<u64>,
}

/// Handle device authorization requests
/// POST /oauth/device
pub async fn device_authorization_handler(
    State(state): State<AppState>,
    Form(request): Form<DeviceAuthorizationRequest>,
) -> Result<ResponseJson<DeviceAuthorizationResponse>, (StatusCode, ResponseJson<Value>)> {
    // TODO: Implement device authorization logic
    // For now, return a placeholder implementation
    
    // Validate client_id exists by checking storage directly
    let client = state
        .oauth_storage
        .get_client(&request.client_id)
        .await
        .map_err(|_| {
            (
                StatusCode::BAD_REQUEST,
                ResponseJson(json!({
                    "error": "invalid_client",
                    "error_description": "Invalid client_id"
                })),
            )
        })?
        .ok_or_else(|| {
            (
                StatusCode::BAD_REQUEST,
                ResponseJson(json!({
                    "error": "invalid_client",
                    "error_description": "Client not found"
                })),
            )
        })?;

    // Check if client supports device_code grant
    if !client.grant_types.contains(&crate::oauth::types::GrantType::DeviceCode) {
        return Err((
            StatusCode::BAD_REQUEST,
            ResponseJson(json!({
                "error": "unauthorized_client",
                "error_description": "Client not authorized for device_code grant"
            })),
        ));
    }

    // Generate device code and user code
    let device_code = format!("device_{}", Uuid::new_v4().to_string().replace('-', ""));
    let user_code = generate_user_code();
    
    // Store device code in storage
    state
        .oauth_storage
        .store_device_code(
            &device_code,
            &user_code,
            &request.client_id,
            request.scope.as_deref(),
            1800, // 30 minutes
        )
        .await
        .map_err(|e| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                ResponseJson(json!({
                    "error": "server_error",
                    "error_description": format!("Failed to store device code: {}", e)
                })),
            )
        })?;
    
    let verification_uri = format!("{}/device", state.config.external_base);
    let verification_uri_complete = Some(format!("{}?user_code={}", verification_uri, user_code));
    
    let response = DeviceAuthorizationResponse {
        device_code,
        user_code,
        verification_uri,
        verification_uri_complete,
        expires_in: 1800, // 30 minutes
        interval: Some(5), // 5 seconds
    };

    Ok(ResponseJson(response))
}

/// Generate a user-friendly verification code
fn generate_user_code() -> String {
    use rand::Rng;
    let mut rng = rand::thread_rng();
    
    // Generate 8-character alphanumeric code in format XXXX-XXXX
    let chars = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789"; // Excluding confusing chars
    let code: String = (0..8)
        .map(|i| {
            if i == 4 {
                '-'
            } else {
                chars.chars().nth(rng.gen_range(0..chars.len())).unwrap()
            }
        })
        .collect();
    
    code
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_generate_user_code() {
        let code = generate_user_code();
        assert_eq!(code.len(), 9); // XXXX-XXXX
        assert_eq!(code.chars().nth(4).unwrap(), '-');
        
        // Should only contain valid characters
        let valid_chars = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789-";
        for c in code.chars() {
            assert!(valid_chars.contains(c));
        }
    }
}