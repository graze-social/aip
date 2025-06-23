//! Handles GET /oauth/atp/callback - Processes ATProtocol OAuth callback with authorization code

use axum::{
    Json,
    extract::{Query, State},
    http::StatusCode,
    response::Redirect,
};
use serde::Deserialize;
use serde_json::{Value, json};

use crate::oauth::utils_atprotocol_oauth::create_atp_backed_server;

use super::context::AppState;

/// Query parameters for ATProtocol OAuth callback
#[derive(Debug, Deserialize)]
pub struct AtpCallbackQuery {
    pub code: String,
    pub state: String,
    pub error: Option<String>,
    pub error_description: Option<String>,
}

/// Handle ATProtocol OAuth callback
/// GET /oauth/atp/callback - Completes the ATProtocol OAuth flow and returns to client
pub async fn handle_atpoauth_callback(
    State(state): State<AppState>,
    Query(query): Query<AtpCallbackQuery>,
) -> std::result::Result<Redirect, (StatusCode, Json<Value>)> {
    // Check for OAuth errors first
    if let Some(error) = query.error {
        let description = query
            .error_description
            .unwrap_or_else(|| "OAuth error".to_string());
        let error_response = json!({
            "error": error,
            "error_description": description
        });
        return Err((StatusCode::BAD_REQUEST, Json(error_response)));
    }

    // Create ATProtocol-backed authorization server
    let atp_auth_server = create_atp_backed_server(&state).await.map_err(|e| {
        let error_response = json!({
            "error": "server_error",
            "error_description": format!("Failed to create ATProtocol authorization server: {}", e)
        });
        (StatusCode::INTERNAL_SERVER_ERROR, Json(error_response))
    })?;

    match atp_auth_server
        .handle_atp_callback(query.code, query.state)
        .await
    {
        Ok(redirect_url) => Ok(Redirect::to(&redirect_url)),
        Err(e) => {
            let error_response = json!({
                "error": "server_error",
                "error_description": e.to_string()
            });
            Err((StatusCode::INTERNAL_SERVER_ERROR, Json(error_response)))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_atp_callback_query_parsing() {
        let query = AtpCallbackQuery {
            code: "test-code".to_string(),
            state: "test-state".to_string(),
            error: None,
            error_description: None,
        };

        assert_eq!(query.code, "test-code");
        assert_eq!(query.state, "test-state");
        assert!(query.error.is_none());
        assert!(query.error_description.is_none());
    }

    #[tokio::test]
    async fn test_atp_callback_query_with_error() {
        let query = AtpCallbackQuery {
            code: "".to_string(),
            state: "test-state".to_string(),
            error: Some("access_denied".to_string()),
            error_description: Some("User denied access".to_string()),
        };

        assert_eq!(query.error, Some("access_denied".to_string()));
        assert_eq!(
            query.error_description,
            Some("User denied access".to_string())
        );
    }

    #[tokio::test]
    async fn test_atp_callback_query_with_error_but_no_description() {
        let query = AtpCallbackQuery {
            code: "".to_string(),
            state: "test-state".to_string(),
            error: Some("server_error".to_string()),
            error_description: None,
        };

        assert_eq!(query.error, Some("server_error".to_string()));
        assert!(query.error_description.is_none());
    }

    #[tokio::test]
    async fn test_atp_callback_query_validation() {
        // Test that required fields are present
        let query = AtpCallbackQuery {
            code: "valid-code-123".to_string(),
            state: "valid-state-456".to_string(),
            error: None,
            error_description: None,
        };

        assert!(!query.code.is_empty());
        assert!(!query.state.is_empty());
        assert!(query.error.is_none());
    }

    #[tokio::test]
    async fn test_atp_callback_query_with_special_characters() {
        // Test handling of special characters in parameters
        let query = AtpCallbackQuery {
            code: "code-with-special-chars_123".to_string(),
            state: "state-with-dashes-and_underscores".to_string(),
            error: None,
            error_description: None,
        };

        assert_eq!(query.code, "code-with-special-chars_123");
        assert_eq!(query.state, "state-with-dashes-and_underscores");
    }
}
