//! Handles POST /api/atprotocol/app-password - Creates or updates app passwords for authenticated users

use axum::{
    extract::{Form, State},
    http::StatusCode,
    response::Json,
};
use chrono::Utc;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

use super::context::AppState;
use crate::{
    http::middleware_auth::ExtractedAuth, oauth::utils_app_password::create_app_password_session,
    storage::traits::AppPassword,
};

/// App password form submission
#[derive(Debug, Deserialize)]
pub struct AppPasswordForm {
    /// The app password to store
    #[serde(rename = "app-password")]
    pub app_password: String,
}

/// App password response
#[derive(Debug, Serialize)]
pub struct AppPasswordResponse {
    /// OAuth client ID
    pub client_id: String,
    /// ATProtocol DID
    pub did: String,
    /// Success message
    pub message: String,
    /// When the password was created/updated
    pub timestamp: String,
}

/// Create or update app password
/// POST /api/atprotocol/app-password
///
/// Accepts a form submission with an "app-password" field and stores it
/// for the authenticated user. If a password already exists for this
/// client/user combination, it will be replaced.
pub async fn create_app_password_handler(
    State(state): State<AppState>,
    ExtractedAuth(access_token): ExtractedAuth,
    Form(form): Form<AppPasswordForm>,
) -> Result<Json<AppPasswordResponse>, (StatusCode, Json<Value>)> {
    // Extract DID from the access token
    let did = access_token.user_id.as_ref().ok_or_else(|| {
        let error_response = json!({
            "error": "invalid_token",
            "error_description": "Token missing user_id (DID)"
        });
        (StatusCode::UNAUTHORIZED, Json(error_response))
    })?;

    // Validate app password is not empty
    if form.app_password.trim().is_empty() {
        let error_response = json!({
            "error": "invalid_request",
            "error_description": "App password cannot be empty"
        });
        return Err((StatusCode::BAD_REQUEST, Json(error_response)));
    }

    // Store the app password as clear text
    let app_password = form.app_password;

    let now = Utc::now();

    // Check if app password already exists
    let existing = state
        .oauth_storage
        .get_app_password(&access_token.client_id, did)
        .await
        .map_err(|e| {
            let error_response = json!({
                "error": "server_error",
                "error_description": format!("Failed to check existing password: {}", e)
            });
            (StatusCode::INTERNAL_SERVER_ERROR, Json(error_response))
        })?;

    let is_update = existing.is_some();

    // Get the DID document to extract PDS endpoint for session creation
    let document = state
        .document_storage
        .get_document_by_did(did)
        .await
        .map_err(|e| {
            let error_response = json!({
                "error": "server_error",
                "error_description": format!("Failed to get DID document: {}", e)
            });
            (StatusCode::INTERNAL_SERVER_ERROR, Json(error_response))
        })?
        .ok_or_else(|| {
            let error_response = json!({
                "error": "not_found",
                "error_description": "DID document not found"
            });
            (StatusCode::NOT_FOUND, Json(error_response))
        })?;

    // Get PDS endpoint from document
    let pds_endpoints: Vec<String> = document
        .pds_endpoints()
        .into_iter()
        .map(|s| s.to_string())
        .collect();
    let pds_endpoint = pds_endpoints.first().ok_or_else(|| {
        let error_response = json!({
            "error": "invalid_configuration",
            "error_description": "No PDS endpoint found in DID document"
        });
        (StatusCode::BAD_REQUEST, Json(error_response))
    })?;

    // Create app-password session before storing the password
    create_app_password_session(
        &state,
        &access_token.client_id,
        did,
        did, // Use DID as identifier for authentication
        &app_password,
        pds_endpoint,
    )
    .await
    .map_err(|e| {
        let error_response = json!({
            "error": "authentication_failed",
            "error_description": format!("Failed to create app-password session: {}", e)
        });
        (StatusCode::UNAUTHORIZED, Json(error_response))
    })?;

    // Create app password entry
    let app_password_entry = AppPassword {
        client_id: access_token.client_id.clone(),
        did: did.clone(),
        app_password,
        created_at: existing.as_ref().map(|e| e.created_at).unwrap_or(now),
        updated_at: now,
    };

    // Store the app password
    state
        .oauth_storage
        .store_app_password(&app_password_entry)
        .await
        .map_err(|e| {
            let error_response = json!({
                "error": "server_error",
                "error_description": format!("Failed to store app password: {}", e)
            });
            (StatusCode::INTERNAL_SERVER_ERROR, Json(error_response))
        })?;

    // If this was an update, delete all associated sessions
    if is_update {
        state
            .oauth_storage
            .delete_app_password_sessions(&access_token.client_id, did)
            .await
            .map_err(|e| {
                let error_response = json!({
                    "error": "server_error",
                    "error_description": format!("Failed to delete existing sessions: {}", e)
                });
                (StatusCode::INTERNAL_SERVER_ERROR, Json(error_response))
            })?;
    }

    let response = AppPasswordResponse {
        client_id: access_token.client_id,
        did: did.clone(),
        message: if is_update {
            "App password updated successfully".to_string()
        } else {
            "App password created successfully".to_string()
        },
        timestamp: now.to_rfc3339(),
    };

    Ok(Json(response))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_app_password_form_deserialization() {
        let json = r#"{"app-password": "test-password-123"}"#;
        let form: AppPasswordForm = serde_json::from_str(json).unwrap();
        assert_eq!(form.app_password, "test-password-123");
    }

    #[test]
    fn test_app_password_response_serialization() {
        let response = AppPasswordResponse {
            client_id: "test-client".to_string(),
            did: "did:plc:test123".to_string(),
            message: "App password created successfully".to_string(),
            timestamp: "2024-01-01T00:00:00Z".to_string(),
        };

        let json = serde_json::to_string(&response).unwrap();
        assert!(json.contains("test-client"));
        assert!(json.contains("did:plc:test123"));
        assert!(json.contains("App password created successfully"));
    }
}
