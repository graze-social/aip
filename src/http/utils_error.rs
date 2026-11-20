//! Error handling utilities for HTTP handlers.
//!
//! Provides extension traits for converting storage errors to HTTP responses
//! with standardized error formats.

use axum::{Json, http::StatusCode};
use serde_json::{Value, json};

use crate::errors::{OAuthError, StorageError};

/// Standard HTTP error response type used across handlers
pub type HttpErrorResponse = (StatusCode, Json<Value>);

/// Builds the error body returned to callers when an ATProtocol OAuth step
/// fails.
///
/// Errors about the caller's own request keep their message. Every other
/// error can carry text from remote servers (transport failures, response
/// bodies, parser output) that would let a caller probe what AIP can reach, so
/// the caller gets a fixed message and the detail goes to the log.
pub fn atprotocol_oauth_error_body(error: &OAuthError, step: &'static str) -> Value {
    let description = match error {
        OAuthError::InvalidClient(_)
        | OAuthError::InvalidRequest(_)
        | OAuthError::InvalidScope(_)
        | OAuthError::UnauthorizedClient(_)
        | OAuthError::UnsupportedResponseType(_)
        | OAuthError::AccessDenied(_) => error.to_string(),
        _ => {
            tracing::warn!(error = %error, step, "ATProtocol OAuth step failed");
            format!("ATProtocol OAuth {step} failed")
        }
    };
    json!({
        "error": "server_error",
        "error_description": description
    })
}

/// Extension trait for converting storage Results to HTTP error responses
pub trait StorageResultExt<T> {
    /// Convert storage error to HTTP 500 response with standard format
    ///
    /// # Example
    /// ```ignore
    /// state.oauth_storage
    ///     .get_client(&client_id)
    ///     .await
    ///     .to_http_error("Failed to retrieve client")?;
    /// ```
    fn to_http_error(self, operation: &str) -> Result<T, HttpErrorResponse>;

    /// Convert storage error to HTTP 500 response, logging at error level
    fn to_http_error_logged(self, operation: &str) -> Result<T, HttpErrorResponse>;
}

impl<T> StorageResultExt<T> for Result<T, StorageError> {
    fn to_http_error(self, operation: &str) -> Result<T, HttpErrorResponse> {
        self.map_err(|e| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({
                    "error": "server_error",
                    "error_description": format!("{}: {}", operation, e)
                })),
            )
        })
    }

    fn to_http_error_logged(self, operation: &str) -> Result<T, HttpErrorResponse> {
        self.map_err(|e| {
            tracing::error!(error = %e, operation = %operation, "Storage operation failed");
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({
                    "error": "server_error",
                    "error_description": format!("{}: {}", operation, e)
                })),
            )
        })
    }
}

/// Extension trait for Option results from storage that may not find a resource
pub trait StorageOptionExt<T> {
    /// Require the option to have a value, returning 404 if None
    ///
    /// # Example
    /// ```ignore
    /// let client = state.oauth_storage
    ///     .get_client(&client_id)
    ///     .await
    ///     .to_http_error("Failed to retrieve client")?
    ///     .require("Client")?;
    /// ```
    fn require(self, resource_name: &str) -> Result<T, HttpErrorResponse>;

    /// Require the option to have a value with custom error code
    fn require_with_error(
        self,
        resource_name: &str,
        error_code: &str,
    ) -> Result<T, HttpErrorResponse>;
}

impl<T> StorageOptionExt<T> for Option<T> {
    fn require(self, resource_name: &str) -> Result<T, HttpErrorResponse> {
        self.ok_or_else(|| {
            (
                StatusCode::NOT_FOUND,
                Json(json!({
                    "error": "not_found",
                    "error_description": format!("{} not found", resource_name)
                })),
            )
        })
    }

    fn require_with_error(
        self,
        resource_name: &str,
        error_code: &str,
    ) -> Result<T, HttpErrorResponse> {
        self.ok_or_else(|| {
            (
                StatusCode::NOT_FOUND,
                Json(json!({
                    "error": error_code,
                    "error_description": format!("{} not found", resource_name)
                })),
            )
        })
    }
}

/// Extension trait combining storage result and option handling
pub trait StorageResultOptionExt<T> {
    /// Get value or return 500 on storage error, 404 if not found
    ///
    /// # Example
    /// ```ignore
    /// let client = state.oauth_storage
    ///     .get_client(&client_id)
    ///     .await
    ///     .require_or_error("Client", "Failed to retrieve client")?;
    /// ```
    fn require_or_error(
        self,
        resource_name: &str,
        operation: &str,
    ) -> Result<T, HttpErrorResponse>;
}

impl<T> StorageResultOptionExt<T> for Result<Option<T>, StorageError> {
    fn require_or_error(
        self,
        resource_name: &str,
        operation: &str,
    ) -> Result<T, HttpErrorResponse> {
        self.to_http_error(operation)?.require(resource_name)
    }
}

/// Helper to create a standard server error response
pub fn server_error(description: impl Into<String>) -> HttpErrorResponse {
    (
        StatusCode::INTERNAL_SERVER_ERROR,
        Json(json!({
            "error": "server_error",
            "error_description": description.into()
        })),
    )
}

/// Helper to create a standard bad request error response
pub fn bad_request(description: impl Into<String>) -> HttpErrorResponse {
    (
        StatusCode::BAD_REQUEST,
        Json(json!({
            "error": "invalid_request",
            "error_description": description.into()
        })),
    )
}

/// Helper to create a standard unauthorized error response
pub fn unauthorized(description: impl Into<String>) -> HttpErrorResponse {
    (
        StatusCode::UNAUTHORIZED,
        Json(json!({
            "error": "invalid_token",
            "error_description": description.into()
        })),
    )
}

/// Helper to create a standard not found error response
pub fn not_found(resource: impl Into<String>) -> HttpErrorResponse {
    (
        StatusCode::NOT_FOUND,
        Json(json!({
            "error": "not_found",
            "error_description": format!("{} not found", resource.into())
        })),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_storage_result_to_http_error() {
        let err: Result<(), StorageError> =
            Err(StorageError::QueryFailed("test error".to_string()));
        let result = err.to_http_error("Test operation");

        assert!(result.is_err());
        let (status, json) = result.unwrap_err();
        assert_eq!(status, StatusCode::INTERNAL_SERVER_ERROR);
        assert_eq!(json.0["error"], "server_error");
        assert!(json.0["error_description"]
            .as_str()
            .unwrap()
            .contains("Test operation"));
    }

    #[test]
    fn test_option_require() {
        let none: Option<String> = None;
        let result = none.require("User");

        assert!(result.is_err());
        let (status, json) = result.unwrap_err();
        assert_eq!(status, StatusCode::NOT_FOUND);
        assert_eq!(json.0["error"], "not_found");
        assert!(json.0["error_description"]
            .as_str()
            .unwrap()
            .contains("User not found"));
    }

    #[test]
    fn test_option_require_success() {
        let some: Option<String> = Some("value".to_string());
        let result = some.require("User");

        assert!(result.is_ok());
        assert_eq!(result.unwrap(), "value");
    }

    #[test]
    fn test_require_or_error() {
        let storage_result: Result<Option<String>, StorageError> = Ok(None);
        let result = storage_result.require_or_error("Client", "Failed to get client");

        assert!(result.is_err());
        let (status, _) = result.unwrap_err();
        assert_eq!(status, StatusCode::NOT_FOUND);
    }

    #[test]
    fn test_require_or_error_storage_failure() {
        let storage_result: Result<Option<String>, StorageError> =
            Err(StorageError::ConnectionFailed("db down".to_string()));
        let result = storage_result.require_or_error("Client", "Failed to get client");

        assert!(result.is_err());
        let (status, _) = result.unwrap_err();
        assert_eq!(status, StatusCode::INTERNAL_SERVER_ERROR);
    }

    #[test]
    fn test_helper_functions() {
        let (status, json) = server_error("Something went wrong");
        assert_eq!(status, StatusCode::INTERNAL_SERVER_ERROR);
        assert_eq!(json.0["error"], "server_error");

        let (status, json) = bad_request("Missing field");
        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert_eq!(json.0["error"], "invalid_request");

        let (status, json) = unauthorized("Token expired");
        assert_eq!(status, StatusCode::UNAUTHORIZED);
        assert_eq!(json.0["error"], "invalid_token");

        let (status, json) = not_found("User");
        assert_eq!(status, StatusCode::NOT_FOUND);
        assert_eq!(json.0["error"], "not_found");
    }
}
