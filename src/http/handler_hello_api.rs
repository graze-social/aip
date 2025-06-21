//! Handles GET /api/hello - OAuth-protected demo endpoint that returns a simple JSON message

use axum::{Json, extract::Extension, http::StatusCode};
use serde_json::{Value, json};

use crate::oauth::resource_server::TokenValidationResult;

/// Handle OAuth-protected hello API endpoint
/// GET /api/hello - Returns a simple JSON message with valid OAuth token
pub async fn handle_hello_api(
    Extension(token_info): Extension<TokenValidationResult>,
) -> std::result::Result<Json<Value>, (StatusCode, Json<Value>)> {
    // Log some information about the validated token (optional)
    tracing::debug!(
        "Hello API accessed by client_id: {}, user_id: {:?}, scopes: {:?}",
        token_info.client_id,
        token_info.user_id,
        token_info.scopes
    );

    // Return the required JSON response
    let response = json!({
        "message": "Hello world"
    });

    Ok(Json(response))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::oauth::{
        resource_server::TokenValidationResult,
        types::{AccessToken, TokenType},
    };
    use axum::extract::Extension;
    use chrono::{Duration, Utc};
    use std::collections::HashSet;

    #[tokio::test]
    async fn test_handle_hello_api_with_valid_token() {
        // Create a valid token validation result
        let token_info = TokenValidationResult {
            client_id: "test-client".to_string(),
            user_id: Some("test-user".to_string()),
            scopes: HashSet::from_iter(vec!["read".to_string(), "write".to_string()]),
            access_token: AccessToken {
                token: "test-token".to_string(),
                token_type: TokenType::Bearer,
                client_id: "test-client".to_string(),
                user_id: Some("test-user".to_string()),
                session_id: None,
                session_iteration: None,
                scope: Some("read write".to_string()),
                created_at: Utc::now(),
                expires_at: Utc::now() + Duration::hours(1),
                dpop_jkt: None,
            },
        };

        // Call the handler directly
        let result = handle_hello_api(Extension(token_info)).await;

        // Verify successful response
        assert!(result.is_ok());
        let response = result.unwrap();
        assert_eq!(response.0["message"], "Hello world");
    }

    #[tokio::test]
    async fn test_handle_hello_api_with_minimal_token() {
        // Create a minimal token validation result
        let token_info = TokenValidationResult {
            client_id: "minimal-client".to_string(),
            user_id: None,
            scopes: HashSet::new(),
            access_token: AccessToken {
                token: "minimal-token".to_string(),
                token_type: TokenType::Bearer,
                client_id: "minimal-client".to_string(),
                user_id: None,
                session_id: None,
                session_iteration: None,
                scope: None,
                created_at: Utc::now(),
                expires_at: Utc::now() + Duration::hours(1),
                dpop_jkt: None,
            },
        };

        // Call the handler directly
        let result = handle_hello_api(Extension(token_info)).await;

        // Verify successful response
        assert!(result.is_ok());
        let response = result.unwrap();
        assert_eq!(response.0["message"], "Hello world");
    }
}
