//! OAuth 2.0 Dynamic Client Registration implementation (RFC 7591).
//!
//! Handles client registration requests, validation, and credential generation.

use crate::errors::ClientRegistrationError;
use crate::oauth::types::*;
use crate::storage::traits::OAuthStorage;
use chrono::Utc;
use std::sync::Arc;
use url::Url;

/// Client Registration Service
pub struct ClientRegistrationService {
    storage: Arc<dyn OAuthStorage>,
    /// Whether client registration is enabled
    registration_enabled: bool,
    /// Default token endpoint auth method
    default_auth_method: ClientAuthMethod,
    /// Maximum number of redirect URIs per client
    max_redirect_uris: usize,
    /// Default access token expiration duration
    default_access_token_expiration: chrono::Duration,
    /// Default refresh token expiration duration
    default_refresh_token_expiration: chrono::Duration,
    /// Default redirect URI exact matching requirement
    default_require_redirect_exact: bool,
}

pub(crate) enum ClientServiceAuth {
    DID,
    RegistrationToken(String),
}

impl ClientRegistrationService {
    /// Create a new client registration service
    pub fn new(
        storage: Arc<dyn OAuthStorage>,
        default_access_token_expiration: chrono::Duration,
        default_refresh_token_expiration: chrono::Duration,
        default_require_redirect_exact: bool,
    ) -> Self {
        Self {
            storage,
            registration_enabled: true,
            default_auth_method: ClientAuthMethod::ClientSecretBasic,
            max_redirect_uris: 10,
            default_access_token_expiration,
            default_refresh_token_expiration,
            default_require_redirect_exact,
        }
    }

    /// Disable client registration
    pub fn disable_registration(mut self) -> Self {
        self.registration_enabled = false;
        self
    }

    /// Register a new OAuth client
    pub async fn register_client(
        &self,
        request: ClientRegistrationRequest,
    ) -> Result<ClientRegistrationResponse, ClientRegistrationError> {
        self.register_client_with_supported_scopes(request, None)
            .await
    }

    /// Register a new OAuth client with supported scopes validation
    pub async fn register_client_with_supported_scopes(
        &self,
        request: ClientRegistrationRequest,
        supported_scopes: Option<&crate::config::OAuthSupportedScopes>,
    ) -> Result<ClientRegistrationResponse, ClientRegistrationError> {
        if !self.registration_enabled {
            return Err(ClientRegistrationError::RegistrationDisabled);
        }

        // Validate the registration request
        self.validate_registration_request_with_supported_scopes(&request, supported_scopes)?;

        // Generate client credentials
        let client_id = generate_client_id();
        let client_id_for_uri = client_id.clone(); // Clone for later use
        let client_secret = if self.requires_client_secret(&request) {
            Some(generate_token())
        } else {
            None
        };

        // Determine client type
        let client_type = if client_secret.is_some() {
            ClientType::Confidential
        } else {
            ClientType::Public
        };

        // Set defaults
        let redirect_uris = request.redirect_uris.unwrap_or_default();
        let grant_types = request
            .grant_types
            .unwrap_or_else(|| vec![GrantType::AuthorizationCode]);
        let response_types = request
            .response_types
            .unwrap_or_else(|| vec![ResponseType::Code]);
        let auth_method = request
            .token_endpoint_auth_method
            .unwrap_or(self.default_auth_method.clone());

        let now = Utc::now();

        // Generate registration access token
        let registration_access_token = generate_token();

        // Create the OAuth client
        let client = OAuthClient {
            client_id: client_id.clone(),
            client_secret: client_secret.clone(),
            client_name: request.client_name.clone(),
            redirect_uris: redirect_uris.clone(),
            grant_types: grant_types.clone(),
            response_types: response_types.clone(),
            scope: request.scope.clone(),
            token_endpoint_auth_method: auth_method.clone(),
            client_type,
            created_at: now,
            updated_at: now,
            metadata: request.metadata,
            access_token_expiration: self.default_access_token_expiration,
            refresh_token_expiration: self.default_refresh_token_expiration,
            require_redirect_exact: self.default_require_redirect_exact,
            registration_access_token: Some(registration_access_token.clone()),
        };

        // Store the client
        self.storage.store_client(&client).await.map_err(|e| {
            ClientRegistrationError::InvalidClientMetadata(format!(
                "Failed to store client: {:?}",
                e
            ))
        })?;

        // Build registration client URI
        let registration_client_uri = format!("/oauth/clients/{}", client_id_for_uri);

        // Create response
        let response = ClientRegistrationResponse {
            client_id: client.client_id.clone(),
            client_secret,
            client_name: request.client_name,
            redirect_uris,
            grant_types,
            response_types,
            scope: request.scope,
            token_endpoint_auth_method: auth_method,
            registration_access_token,
            registration_client_uri,
            client_id_issued_at: now.timestamp(),
            client_secret_expires_at: None, // Non-expiring for now
        };

        Ok(response)
    }

    /// Get client configuration
    pub(crate) async fn get_client(
        &self,
        client_id: &str,
        client_service_auth: &ClientServiceAuth,
    ) -> Result<ClientRegistrationResponse, ClientRegistrationError> {
        let client = self
            .storage
            .get_client(client_id)
            .await
            .map_err(|e| {
                ClientRegistrationError::InvalidClientMetadata(format!("Storage error: {:?}", e))
            })?
            .ok_or_else(|| ClientRegistrationError::ClientNotFound(client_id.to_string()))?;

        if let ClientServiceAuth::RegistrationToken(registration_token) = client_service_auth {
            match &client.registration_access_token {
                Some(stored_token) if stored_token == registration_token => {
                    // Token matches, continue
                }
                Some(_) => {
                    return Err(ClientRegistrationError::InvalidRegistrationToken(
                        "Registration access token does not match".to_string(),
                    ));
                }
                None => {
                    return Err(ClientRegistrationError::InvalidRegistrationToken(
                        "Client has no registration access token".to_string(),
                    ));
                }
            }
        }

        // Convert to response format
        let client_id_for_uri = client.client_id.clone();
        let response = ClientRegistrationResponse {
            client_id: client.client_id,
            client_secret: client.client_secret,
            client_name: client.client_name,
            redirect_uris: client.redirect_uris,
            grant_types: client.grant_types,
            response_types: client.response_types,
            scope: client.scope,
            token_endpoint_auth_method: client.token_endpoint_auth_method,
            registration_access_token: "redacted".to_string(), // Don't return the actual token
            registration_client_uri: format!("/oauth/clients/{}", client_id_for_uri),
            client_id_issued_at: client.created_at.timestamp(),
            client_secret_expires_at: None,
        };

        Ok(response)
    }

    /// Update client configuration with supported scopes validation
    pub(crate) async fn update_client_with_supported_scopes(
        &self,
        client_id: &str,
        client_service_auth: &ClientServiceAuth,
        request: ClientRegistrationRequest,
        supported_scopes: Option<&crate::config::OAuthSupportedScopes>,
    ) -> Result<ClientRegistrationResponse, ClientRegistrationError> {
        // Get existing client
        let mut client = self
            .storage
            .get_client(client_id)
            .await
            .map_err(|e| {
                ClientRegistrationError::InvalidClientMetadata(format!("Storage error: {:?}", e))
            })?
            .ok_or_else(|| ClientRegistrationError::ClientNotFound(client_id.to_string()))?;

        if let ClientServiceAuth::RegistrationToken(registration_token) = client_service_auth {
            match &client.registration_access_token {
                Some(stored_token) if stored_token == registration_token => {
                    // Token matches, continue
                }
                Some(_) => {
                    return Err(ClientRegistrationError::InvalidRegistrationToken(
                        "Registration access token does not match".to_string(),
                    ));
                }
                None => {
                    return Err(ClientRegistrationError::InvalidRegistrationToken(
                        "Client has no registration access token".to_string(),
                    ));
                }
            }
        }

        // Validate the update request
        self.validate_registration_request_with_supported_scopes(&request, supported_scopes)?;

        // Update fields if provided
        if request.client_name.is_some() {
            client.client_name = request.client_name.clone();
        }
        if let Some(redirect_uris) = request.redirect_uris {
            client.redirect_uris = redirect_uris;
        }
        if let Some(grant_types) = request.grant_types {
            client.grant_types = grant_types;
        }
        if let Some(response_types) = request.response_types {
            client.response_types = response_types;
        }
        if request.scope.is_some() {
            client.scope = request.scope.clone();
        }
        if let Some(auth_method) = request.token_endpoint_auth_method {
            client.token_endpoint_auth_method = auth_method;
        }

        client.updated_at = Utc::now();
        client.metadata = request.metadata;

        // Store updated client
        self.storage.update_client(&client).await.map_err(|e| {
            ClientRegistrationError::InvalidClientMetadata(format!(
                "Failed to update client: {:?}",
                e
            ))
        })?;

        // Return updated configuration
        self.get_client(client_id, client_service_auth).await
    }

    /// Delete client registration
    pub(crate) async fn delete_client(
        &self,
        client_id: &str,
        client_service_auth: &ClientServiceAuth,
    ) -> Result<(), ClientRegistrationError> {
        // Verify client exists
        let client = self
            .storage
            .get_client(client_id)
            .await
            .map_err(|e| {
                ClientRegistrationError::InvalidClientMetadata(format!("Storage error: {:?}", e))
            })?
            .ok_or_else(|| ClientRegistrationError::ClientNotFound(client_id.to_string()))?;

        if let ClientServiceAuth::RegistrationToken(registration_token) = client_service_auth {
            match &client.registration_access_token {
                Some(stored_token) if stored_token == registration_token => {
                    // Token matches, continue
                }
                Some(_) => {
                    return Err(ClientRegistrationError::InvalidRegistrationToken(
                        "Registration access token does not match".to_string(),
                    ));
                }
                None => {
                    return Err(ClientRegistrationError::InvalidRegistrationToken(
                        "Client has no registration access token".to_string(),
                    ));
                }
            }
        }

        // Delete the client
        self.storage.delete_client(client_id).await.map_err(|e| {
            ClientRegistrationError::InvalidClientMetadata(format!(
                "Failed to delete client: {:?}",
                e
            ))
        })?;

        Ok(())
    }

    /// Validate a client registration request with supported scopes
    fn validate_registration_request_with_supported_scopes(
        &self,
        request: &ClientRegistrationRequest,
        supported_scopes: Option<&crate::config::OAuthSupportedScopes>,
    ) -> Result<(), ClientRegistrationError> {
        // Validate redirect URIs
        if let Some(ref redirect_uris) = request.redirect_uris {
            if redirect_uris.len() > self.max_redirect_uris {
                return Err(ClientRegistrationError::InvalidRedirectUri(format!(
                    "Too many redirect URIs: {} (max: {})",
                    redirect_uris.len(),
                    self.max_redirect_uris
                )));
            }

            for uri in redirect_uris {
                self.validate_redirect_uri(uri)?;
            }
        }

        // Validate grant types and response types are compatible
        if let (Some(grant_types), Some(response_types)) =
            (&request.grant_types, &request.response_types)
        {
            if grant_types.contains(&GrantType::AuthorizationCode)
                && !response_types.contains(&ResponseType::Code)
            {
                return Err(ClientRegistrationError::InvalidClientMetadata(
                    "authorization_code grant requires code response type".to_string(),
                ));
            }
        }

        // Validate scope
        if let Some(ref scope) = request.scope {
            if !validate_scope(scope) {
                return Err(ClientRegistrationError::InvalidClientMetadata(format!(
                    "Invalid scope: {}",
                    scope
                )));
            }

            // Validate against server's supported scopes if provided
            if let Some(supported_scopes) = supported_scopes {
                let requested_scopes = parse_scope(scope);
                let server_supported_scopes = parse_scope(&supported_scopes.as_ref().join(" "));

                if !requested_scopes.is_subset(&server_supported_scopes) {
                    return Err(ClientRegistrationError::InvalidClientMetadata(format!(
                        "Requested scope '{}' contains unsupported scopes. Supported scopes: {}",
                        scope,
                        supported_scopes.as_ref().join(" ")
                    )));
                }
            }
        }

        Ok(())
    }

    /// Validate a redirect URI
    fn validate_redirect_uri(&self, uri: &str) -> Result<(), ClientRegistrationError> {
        let parsed = Url::parse(uri).map_err(|e| {
            ClientRegistrationError::InvalidRedirectUri(format!("Invalid URI format: {}", e))
        })?;

        // Must use HTTPS (except for localhost for development)
        match parsed.scheme() {
            "https" => {} // Always allowed
            "http" => {
                // Only allow http for localhost
                if let Some(host) = parsed.host_str() {
                    if !host.starts_with("localhost") && !host.starts_with("127.0.0.1") {
                        return Err(ClientRegistrationError::InvalidRedirectUri(
                            "HTTP redirect URIs only allowed for localhost".to_string(),
                        ));
                    }
                } else {
                    return Err(ClientRegistrationError::InvalidRedirectUri(
                        "Invalid redirect URI host".to_string(),
                    ));
                }
            }
            _ => {
                return Err(ClientRegistrationError::InvalidRedirectUri(
                    "Redirect URI must use HTTP or HTTPS".to_string(),
                ));
            }
        }

        // Must not contain fragment
        if parsed.fragment().is_some() {
            return Err(ClientRegistrationError::InvalidRedirectUri(
                "Redirect URI must not contain fragment".to_string(),
            ));
        }

        Ok(())
    }

    /// Check if client secret is required based on auth method
    fn requires_client_secret(&self, request: &ClientRegistrationRequest) -> bool {
        !matches!(
            request
                .token_endpoint_auth_method
                .as_ref()
                .unwrap_or(&self.default_auth_method),
            ClientAuthMethod::None
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::storage::inmemory::MemoryOAuthStorage;

    #[tokio::test]
    async fn test_client_registration() {
        let storage = Arc::new(MemoryOAuthStorage::new());
        let service = ClientRegistrationService::new(
            storage,
            chrono::Duration::days(1),
            chrono::Duration::days(14),
            true,
        );

        let request = ClientRegistrationRequest {
            client_name: Some("Test Client".to_string()),
            redirect_uris: Some(vec!["https://example.com/callback".to_string()]),
            grant_types: Some(vec![GrantType::AuthorizationCode]),
            response_types: Some(vec![ResponseType::Code]),
            scope: Some("read write".to_string()),
            token_endpoint_auth_method: Some(ClientAuthMethod::ClientSecretBasic),
            metadata: serde_json::Value::Null,
        };

        let response = service.register_client(request).await.unwrap();

        assert!(!response.client_id.is_empty());
        assert!(response.client_secret.is_some());
        assert_eq!(response.client_name, Some("Test Client".to_string()));
        assert_eq!(response.redirect_uris, vec!["https://example.com/callback"]);
    }

    #[tokio::test]
    async fn test_invalid_redirect_uri() {
        let storage = Arc::new(MemoryOAuthStorage::new());
        let service = ClientRegistrationService::new(
            storage,
            chrono::Duration::days(1),
            chrono::Duration::days(14),
            true,
        );

        let request = ClientRegistrationRequest {
            client_name: Some("Test Client".to_string()),
            redirect_uris: Some(vec!["http://example.com/callback".to_string()]), // Invalid - not HTTPS
            grant_types: None,
            response_types: None,
            scope: None,
            token_endpoint_auth_method: None,
            metadata: serde_json::Value::Null,
        };

        let result = service.register_client(request).await;
        assert!(result.is_err());
        if let Err(error) = result {
            assert!(matches!(
                error,
                ClientRegistrationError::InvalidRedirectUri(_)
            ));
        }
    }

    #[tokio::test]
    async fn test_disabled_registration() {
        let storage = Arc::new(MemoryOAuthStorage::new());
        let service = ClientRegistrationService::new(
            storage,
            chrono::Duration::days(1),
            chrono::Duration::days(14),
            true,
        )
        .disable_registration();

        let request = ClientRegistrationRequest {
            client_name: Some("Test Client".to_string()),
            redirect_uris: Some(vec!["https://example.com/callback".to_string()]),
            grant_types: None,
            response_types: None,
            scope: None,
            token_endpoint_auth_method: None,
            metadata: serde_json::Value::Null,
        };

        let result = service.register_client(request).await;
        assert!(result.is_err());
        if let Err(error) = result {
            assert!(matches!(
                error,
                ClientRegistrationError::RegistrationDisabled
            ));
        }
    }

    #[tokio::test]
    async fn test_scope_validation_with_supported_scopes() {
        let storage = Arc::new(MemoryOAuthStorage::new());
        let service = ClientRegistrationService::new(
            storage,
            chrono::Duration::days(1),
            chrono::Duration::days(14),
            true,
        );

        // Test with supported scopes
        let supported_scopes =
            crate::config::OAuthSupportedScopes::try_from("read write atproto:atproto".to_string())
                .unwrap();

        // Test valid scope within supported scopes
        let valid_request = ClientRegistrationRequest {
            client_name: Some("Test Client".to_string()),
            redirect_uris: Some(vec!["https://example.com/callback".to_string()]),
            grant_types: None,
            response_types: None,
            scope: Some("read write".to_string()),
            token_endpoint_auth_method: None,
            metadata: serde_json::Value::Null,
        };

        let result = service
            .register_client_with_supported_scopes(valid_request, Some(&supported_scopes))
            .await;
        assert!(result.is_ok());

        // Test invalid scope not in supported scopes
        let invalid_request = ClientRegistrationRequest {
            client_name: Some("Test Client".to_string()),
            redirect_uris: Some(vec!["https://example.com/callback".to_string()]),
            grant_types: None,
            response_types: None,
            scope: Some("read write admin".to_string()), // 'admin' not in supported scopes
            token_endpoint_auth_method: None,
            metadata: serde_json::Value::Null,
        };

        let result = service
            .register_client_with_supported_scopes(invalid_request, Some(&supported_scopes))
            .await;
        assert!(result.is_err());
        if let Err(error) = result {
            assert!(matches!(
                error,
                ClientRegistrationError::InvalidClientMetadata(_)
            ));
        }
    }
}
