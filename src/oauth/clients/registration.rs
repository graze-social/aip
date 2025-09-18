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
        // Confidential clients are those with client secrets OR using private_key_jwt auth
        let client_type = if client_secret.is_some()
            || request.token_endpoint_auth_method.as_ref() == Some(&ClientAuthMethod::PrivateKeyJwt)
        {
            ClientType::Confidential
        } else {
            ClientType::Public
        };

        // Set defaults based on application type
        let redirect_uris = request.redirect_uris.clone().unwrap_or_default();
        
        // For native applications, default to device code flow
        let grant_types = request.grant_types.clone().unwrap_or_else(|| {
            match &request.application_type {
                Some(crate::oauth::types::ApplicationType::Native) => {
                    vec![GrantType::DeviceCode, GrantType::RefreshToken]
                }
                _ => vec![GrantType::AuthorizationCode]
            }
        });
        
        let response_types = request.response_types.clone().unwrap_or_else(|| {
            if grant_types.contains(&GrantType::DeviceCode) {
                vec![ResponseType::DeviceCode]
            } else {
                vec![ResponseType::Code]
            }
        });
        
        // For device flow, default to no authentication
        let auth_method = request.token_endpoint_auth_method.clone().unwrap_or_else(|| {
            if grant_types.contains(&GrantType::DeviceCode) {
                crate::oauth::types::ClientAuthMethod::None
            } else {
                self.default_auth_method.clone()
            }
        });

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
            application_type: request.application_type.clone(),
            software_id: request.software_id.clone(),
            software_version: request.software_version.clone(),
            created_at: now,
            updated_at: now,
            metadata: request.metadata.clone(),
            access_token_expiration: self.default_access_token_expiration,
            refresh_token_expiration: self.default_refresh_token_expiration,
            require_redirect_exact: self.default_require_redirect_exact,
            registration_access_token: Some(registration_access_token.clone()),
            jwks: extract_client_jwks(&request, &auth_method)?,
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
            application_type: request.application_type,
            software_id: request.software_id,
            software_version: request.software_version,
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
                ClientRegistrationError::InvalidClientMetadata(e.to_string())
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
            application_type: client.application_type,
            software_id: client.software_id,
            software_version: client.software_version,
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
                ClientRegistrationError::InvalidClientMetadata(e.to_string())
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
        if request.application_type.is_some() {
            client.application_type = request.application_type.clone();
        }
        if request.software_id.is_some() {
            client.software_id = request.software_id.clone();
        }
        if request.software_version.is_some() {
            client.software_version = request.software_version.clone();
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
                ClientRegistrationError::InvalidClientMetadata(e.to_string())
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
            
            // Validate device code grant type requirements
            if grant_types.contains(&GrantType::DeviceCode) {
                if !response_types.contains(&ResponseType::DeviceCode) {
                    return Err(ClientRegistrationError::InvalidClientMetadata(
                        "device_code grant requires device_code response type".to_string(),
                    ));
                }
                
                // Device flow clients should be native applications
                if let Some(app_type) = &request.application_type {
                    if *app_type != crate::oauth::types::ApplicationType::Native {
                        return Err(ClientRegistrationError::InvalidClientMetadata(
                            "device_code grant is typically used with native applications".to_string(),
                        ));
                    }
                }
                
                // Device flow clients should use no authentication by default
                if let Some(auth_method) = &request.token_endpoint_auth_method {
                    if *auth_method != crate::oauth::types::ClientAuthMethod::None {
                        return Err(ClientRegistrationError::InvalidClientMetadata(
                            "device_code grant typically uses 'none' authentication method".to_string(),
                        ));
                    }
                }
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

            let requested_scopes = parse_scope(scope);

            // Parse the scope string into Scope instances for validation
            let parsed_scopes = atproto_oauth::scopes::Scope::parse_multiple_reduced(scope)
                .map_err(|e| {
                    ClientRegistrationError::InvalidClientMetadata(format!(
                        "Invalid scope format: {}",
                        e
                    ))
                })?;

            // Validate scope requirements (openid and email scopes must have required AT Protocol scopes)
            crate::config::OAuthSupportedScopes::validate_scope_requirements(&parsed_scopes)
                .map_err(|e| ClientRegistrationError::InvalidClientMetadata(e.to_string()))?;

            // Validate against server's supported scopes if provided
            if let Some(supported_scopes) = supported_scopes {
                let supported_scope_strings = supported_scopes.as_strings();
                let server_supported_scopes = parse_scope(&supported_scope_strings.join(" "));

                // Check if all requested scopes are either directly supported or match repo:* wildcard
                for requested in &requested_scopes {
                    let is_supported = server_supported_scopes.contains(requested) ||
                        // Support the special repo:* wildcard for any repo scope
                        (supported_scope_strings.contains(&"repo:*".to_string()) && requested.starts_with("repo:"));

                    if !is_supported {
                        return Err(ClientRegistrationError::InvalidClientMetadata(format!(
                            "Requested scope '{}' is not supported. Supported scopes: {}",
                            requested,
                            supported_scope_strings.join(" ")
                        )));
                    }
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

        // Must use HTTPS (except for localhost for development) or custom scheme for native apps
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
            scheme => {
                // Allow custom schemes for native applications (RFC 8252)
                // Custom schemes should not be "http" or "https" and should be unique to the application
                if scheme.len() < 3 || !scheme.chars().all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '.' || c == '+') {
                    return Err(ClientRegistrationError::InvalidRedirectUri(
                        "Custom scheme must be at least 3 characters and contain only alphanumeric characters, hyphens, dots, or plus signs".to_string(),
                    ));
                }
                // Allow custom schemes for native apps - these are typically used for device/CLI applications
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
            ClientAuthMethod::None | ClientAuthMethod::PrivateKeyJwt
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
            scope: Some("atproto transition:generic transition:email".to_string()),
            token_endpoint_auth_method: Some(ClientAuthMethod::ClientSecretBasic),
            jwks: None,
            jwks_uri: None,
            application_type: None,
            software_id: None,
            software_version: None,
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
            jwks: None,
            jwks_uri: None,
            application_type: None,
            software_id: None,
            software_version: None,
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
            jwks: None,
            jwks_uri: None,
            application_type: None,
            software_id: None,
            software_version: None,
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
        let supported_scopes = crate::config::OAuthSupportedScopes::try_from(
            "atproto transition:generic transition:email".to_string(),
        )
        .unwrap();

        // Test valid scope within supported scopes
        let valid_request = ClientRegistrationRequest {
            client_name: Some("Test Client".to_string()),
            redirect_uris: Some(vec!["https://example.com/callback".to_string()]),
            grant_types: None,
            response_types: None,
            scope: Some("atproto transition:generic".to_string()),
            token_endpoint_auth_method: None,
            jwks: None,
            jwks_uri: None,
            application_type: None,
            software_id: None,
            software_version: None,
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
            scope: Some("atproto transition:generic admin".to_string()), // 'admin' not in supported scopes
            token_endpoint_auth_method: None,
            jwks: None,
            jwks_uri: None,
            application_type: None,
            software_id: None,
            software_version: None,
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

    #[tokio::test]
    async fn test_openid_scope_validation() {
        let storage = Arc::new(MemoryOAuthStorage::new());
        let service = ClientRegistrationService::new(
            storage,
            chrono::Duration::days(1),
            chrono::Duration::days(14),
            true,
        );

        // Test with supported scopes including required AT Protocol scopes
        let supported_scopes = crate::config::OAuthSupportedScopes::try_from(
            "openid email atproto transition:generic transition:email".to_string(),
        )
        .unwrap();

        // Test 1: openid scope with transition:generic should succeed
        let valid_request1 = ClientRegistrationRequest {
            client_name: Some("Test Client".to_string()),
            redirect_uris: Some(vec!["https://example.com/callback".to_string()]),
            grant_types: None,
            response_types: None,
            scope: Some("openid atproto transition:generic".to_string()),
            token_endpoint_auth_method: None,
            jwks: None,
            jwks_uri: None,
            application_type: None,
            software_id: None,
            software_version: None,
            metadata: serde_json::Value::Null,
        };

        let result = service
            .register_client_with_supported_scopes(valid_request1, Some(&supported_scopes))
            .await;
        assert!(
            result.is_ok(),
            "openid with atproto transition:generic should succeed"
        );

        // Test 2: openid scope with atproto but no transition:generic should fail
        let invalid_request2 = ClientRegistrationRequest {
            client_name: Some("Test Client".to_string()),
            redirect_uris: Some(vec!["https://example.com/callback".to_string()]),
            grant_types: None,
            response_types: None,
            scope: Some("openid atproto".to_string()),
            token_endpoint_auth_method: None,
            jwks: None,
            jwks_uri: None,
            application_type: None,
            software_id: None,
            software_version: None,
            metadata: serde_json::Value::Null,
        };

        let result = service
            .register_client_with_supported_scopes(invalid_request2, Some(&supported_scopes))
            .await;
        assert!(
            result.is_ok(),
            "openid with only atproto should succeed (no transition:generic required)"
        );

        // Test 3: openid scope without required AT Protocol scopes should fail
        let invalid_request = ClientRegistrationRequest {
            client_name: Some("Test Client".to_string()),
            redirect_uris: Some(vec!["https://example.com/callback".to_string()]),
            grant_types: None,
            response_types: None,
            scope: Some("openid".to_string()),
            token_endpoint_auth_method: None,
            jwks: None,
            jwks_uri: None,
            application_type: None,
            software_id: None,
            software_version: None,
            metadata: serde_json::Value::Null,
        };

        let result = service
            .register_client_with_supported_scopes(invalid_request, Some(&supported_scopes))
            .await;
        assert!(
            result.is_err(),
            "openid without required AT Protocol scopes should fail"
        );
        if let Err(error) = result {
            let error_msg = error.to_string();
            assert!(
                error_msg.contains("atproto") && error_msg.contains("required"),
                "Error should mention atproto scope requirement. Got: {}",
                error_msg
            );
        }
    }

    #[tokio::test]
    async fn test_repo_wildcard_scope_validation() {
        let storage = Arc::new(MemoryOAuthStorage::new());
        let service = ClientRegistrationService::new(
            storage,
            chrono::Duration::days(1),
            chrono::Duration::days(14),
            true,
        );

        // Test with supported scopes including repo:* wildcard
        let supported_scopes = crate::config::OAuthSupportedScopes::try_from(
            "atproto repo:*".to_string(),
        )
        .unwrap();

        // Test 1: Specific repo collection scope should succeed when repo:* is supported
        let valid_request1 = ClientRegistrationRequest {
            client_name: Some("Test Client".to_string()),
            redirect_uris: Some(vec!["https://example.com/callback".to_string()]),
            grant_types: None,
            response_types: None,
            scope: Some("atproto repo:app.bsky.feed.post".to_string()),
            token_endpoint_auth_method: None,
            jwks: None,
            jwks_uri: None,
            application_type: None,
            software_id: None,
            software_version: None,
            metadata: serde_json::Value::Null,
        };

        let result = service
            .register_client_with_supported_scopes(valid_request1, Some(&supported_scopes))
            .await;
        assert!(
            result.is_ok(),
            "repo:app.bsky.feed.post should succeed when repo:* is supported"
        );

        // Test 2: Multiple repo collection scopes should succeed
        let valid_request2 = ClientRegistrationRequest {
            client_name: Some("Test Client".to_string()),
            redirect_uris: Some(vec!["https://example.com/callback".to_string()]),
            grant_types: None,
            response_types: None,
            scope: Some("atproto repo:app.bsky.feed.post repo:app.bsky.feed.like:create".to_string()),
            token_endpoint_auth_method: None,
            jwks: None,
            jwks_uri: None,
            application_type: None,
            software_id: None,
            software_version: None,
            metadata: serde_json::Value::Null,
        };

        let result = service
            .register_client_with_supported_scopes(valid_request2, Some(&supported_scopes))
            .await;
        assert!(
            result.is_ok(),
            "Multiple repo scopes should succeed when repo:* is supported"
        );

        // Test 3: Requesting repo:* itself should succeed when repo:* is supported
        let wildcard_request = ClientRegistrationRequest {
            client_name: Some("Test Client".to_string()),
            redirect_uris: Some(vec!["https://example.com/callback".to_string()]),
            grant_types: None,
            response_types: None,
            scope: Some("atproto repo:*".to_string()),
            token_endpoint_auth_method: None,
            jwks: None,
            jwks_uri: None,
            application_type: None,
            software_id: None,
            software_version: None,
            metadata: serde_json::Value::Null,
        };

        let result = service
            .register_client_with_supported_scopes(wildcard_request, Some(&supported_scopes))
            .await;
        assert!(
            result.is_ok(),
            "repo:* should succeed when repo:* is supported"
        );

        // Test 4: Non-repo scope should still be validated normally
        let invalid_request = ClientRegistrationRequest {
            client_name: Some("Test Client".to_string()),
            redirect_uris: Some(vec!["https://example.com/callback".to_string()]),
            grant_types: None,
            response_types: None,
            scope: Some("atproto transition:email".to_string()), // 'transition:email' not in supported scopes
            token_endpoint_auth_method: None,
            jwks: None,
            jwks_uri: None,
            application_type: None,
            software_id: None,
            software_version: None,
            metadata: serde_json::Value::Null,
        };

        let result = service
            .register_client_with_supported_scopes(invalid_request, Some(&supported_scopes))
            .await;
        assert!(
            result.is_err(),
            "Non-repo unsupported scope should fail even when repo:* is supported"
        );
        if let Err(error) = result {
            let error_msg = error.to_string();
            assert!(
                error_msg.contains("transition:email") && error_msg.contains("not supported"),
                "Error should mention unsupported scope. Got: {}",
                error_msg
            );
        }

        // Test 5: Without repo:* wildcard, specific repo scopes should fail
        let limited_scopes = crate::config::OAuthSupportedScopes::try_from(
            "atproto repo:app.bsky.feed.post repo:app.bsky.feed.like".to_string(),
        )
        .unwrap();

        let should_fail_request = ClientRegistrationRequest {
            client_name: Some("Test Client".to_string()),
            redirect_uris: Some(vec!["https://example.com/callback".to_string()]),
            grant_types: None,
            response_types: None,
            scope: Some("atproto repo:app.bsky.actor.profile".to_string()),
            token_endpoint_auth_method: None,
            jwks: None,
            jwks_uri: None,
            application_type: None,
            software_id: None,
            software_version: None,
            metadata: serde_json::Value::Null,
        };

        let result = service
            .register_client_with_supported_scopes(should_fail_request, Some(&limited_scopes))
            .await;
        assert!(
            result.is_err(),
            "repo:app.bsky.actor.profile should fail when only specific repo scopes are allowed"
        );
    }

    #[tokio::test]
    async fn test_email_scope_validation() {
        let storage = Arc::new(MemoryOAuthStorage::new());
        let service = ClientRegistrationService::new(
            storage,
            chrono::Duration::days(1),
            chrono::Duration::days(14),
            true,
        );

        // Test with supported scopes including required AT Protocol scopes
        let supported_scopes = crate::config::OAuthSupportedScopes::try_from(
            "openid email atproto transition:generic transition:email account:email?action=read".to_string(),
        )
        .unwrap();

        // Test 1: email scope with openid and transition:email should succeed
        let valid_request1 = ClientRegistrationRequest {
            client_name: Some("Test Client".to_string()),
            redirect_uris: Some(vec!["https://example.com/callback".to_string()]),
            grant_types: None,
            response_types: None,
            scope: Some("openid email atproto transition:email".to_string()),
            token_endpoint_auth_method: None,
            jwks: None,
            jwks_uri: None,
            application_type: None,
            software_id: None,
            software_version: None,
            metadata: serde_json::Value::Null,
        };

        let result = service
            .register_client_with_supported_scopes(valid_request1, Some(&supported_scopes))
            .await;
        assert!(
            result.is_ok(),
            "email with openid and transition:email should succeed"
        );

        // Test 2: email scope with account:email (parsed from account:email?action=read) should succeed
        let valid_request2 = ClientRegistrationRequest {
            client_name: Some("Test Client".to_string()),
            redirect_uris: Some(vec!["https://example.com/callback".to_string()]),
            grant_types: None,
            response_types: None,
            scope: Some("openid email atproto account:email".to_string()),
            token_endpoint_auth_method: None,
            jwks: None,
            jwks_uri: None,
            application_type: None,
            software_id: None,
            software_version: None,
            metadata: serde_json::Value::Null,
        };

        let result = service
            .register_client_with_supported_scopes(valid_request2, Some(&supported_scopes))
            .await;
        assert!(
            result.is_ok(),
            "email with openid and account:email should succeed. Got error: {:?}",
            result.as_ref().err()
        );

        // Test 3: email scope without required AT Protocol scopes should fail
        let invalid_request = ClientRegistrationRequest {
            client_name: Some("Test Client".to_string()),
            redirect_uris: Some(vec!["https://example.com/callback".to_string()]),
            grant_types: None,
            response_types: None,
            scope: Some("email".to_string()),
            token_endpoint_auth_method: None,
            jwks: None,
            jwks_uri: None,
            application_type: None,
            software_id: None,
            software_version: None,
            metadata: serde_json::Value::Null,
        };

        let result = service
            .register_client_with_supported_scopes(invalid_request, Some(&supported_scopes))
            .await;
        assert!(
            result.is_err(),
            "email without required AT Protocol scopes should fail"
        );
        if let Err(error) = result {
            let error_msg = error.to_string();
            assert!(
                error_msg.contains("atproto") && error_msg.contains("required"),
                "Error should mention atproto scope requirement. Got: {}",
                error_msg
            );
        }
    }

    #[tokio::test]
    async fn test_combined_openid_email_scope_validation() {
        let storage = Arc::new(MemoryOAuthStorage::new());
        let service = ClientRegistrationService::new(
            storage,
            chrono::Duration::days(1),
            chrono::Duration::days(14),
            true,
        );

        // Test with supported scopes including required AT Protocol scopes
        let supported_scopes = crate::config::OAuthSupportedScopes::try_from(
            "openid email atproto transition:generic transition:email".to_string(),
        )
        .unwrap();

        // Test: both openid and email with all required scopes should succeed
        let valid_request = ClientRegistrationRequest {
            client_name: Some("Test Client".to_string()),
            redirect_uris: Some(vec!["https://example.com/callback".to_string()]),
            grant_types: None,
            response_types: None,
            scope: Some("openid email atproto transition:generic transition:email".to_string()),
            token_endpoint_auth_method: None,
            jwks: None,
            jwks_uri: None,
            application_type: None,
            software_id: None,
            software_version: None,
            metadata: serde_json::Value::Null,
        };

        let result = service
            .register_client_with_supported_scopes(valid_request, Some(&supported_scopes))
            .await;
        assert!(
            result.is_ok(),
            "openid and email with all required scopes should succeed"
        );

        // Test: openid and email with transition:generic should fail (doesn't grant email)
        let invalid_request2 = ClientRegistrationRequest {
            client_name: Some("Test Client".to_string()),
            redirect_uris: Some(vec!["https://example.com/callback".to_string()]),
            grant_types: None,
            response_types: None,
            scope: Some("openid email atproto transition:generic".to_string()),
            token_endpoint_auth_method: None,
            jwks: None,
            jwks_uri: None,
            application_type: None,
            software_id: None,
            software_version: None,
            metadata: serde_json::Value::Null,
        };

        let result = service
            .register_client_with_supported_scopes(invalid_request2, Some(&supported_scopes))
            .await;
        assert!(
            result.is_err(),
            "openid and email with only transition:generic should fail (doesn't grant email)"
        );
        if let Err(error) = result {
            let error_msg = error.to_string();
            assert!(
                error_msg.contains("email") && error_msg.contains("requires"),
                "Error should mention email requirements. Got: {}",
                error_msg
            );
        }
        
        // Test: openid and email without any transition scopes should fail
        let invalid_request = ClientRegistrationRequest {
            client_name: Some("Test Client".to_string()),
            redirect_uris: Some(vec!["https://example.com/callback".to_string()]),
            grant_types: None,
            response_types: None,
            scope: Some("openid email atproto".to_string()),
            token_endpoint_auth_method: None,
            jwks: None,
            jwks_uri: None,
            application_type: None,
            software_id: None,
            software_version: None,
            metadata: serde_json::Value::Null,
        };

        let result = service
            .register_client_with_supported_scopes(invalid_request, Some(&supported_scopes))
            .await;
        assert!(
            result.is_err(),
            "openid and email without transition scopes should fail"
        );
        if let Err(error) = result {
            let error_msg = error.to_string();
            assert!(
                error_msg.contains("email") && (error_msg.contains("read access") || error_msg.contains("transition:email")),
                "Error should mention email requires read access capability. Got: {}",
                error_msg
            );
        }
    }
}

/// Extract and validate client JWKs from registration request
fn extract_client_jwks(
    request: &ClientRegistrationRequest,
    auth_method: &ClientAuthMethod,
) -> Result<Option<serde_json::Value>, ClientRegistrationError> {
    // Only extract JWKs for private_key_jwt authentication
    if *auth_method != ClientAuthMethod::PrivateKeyJwt {
        return Ok(None);
    }

    // Client must provide either jwks or jwks_uri for private_key_jwt
    match (&request.jwks, &request.jwks_uri) {
        (Some(jwks), None) => {
            // Validate JWK Set format
            validate_jwk_set(jwks)?;
            Ok(Some(jwks.clone()))
        }
        (None, Some(_jwks_uri)) => {
            // TODO: Implement JWK Set fetching from URI
            // For now, require inline JWKs
            Err(ClientRegistrationError::InvalidClientMetadata(
                "jwks_uri not yet supported, please provide jwks inline".to_string(),
            ))
        }
        (Some(_), Some(_)) => Err(ClientRegistrationError::InvalidClientMetadata(
            "Cannot specify both jwks and jwks_uri".to_string(),
        )),
        (None, None) => Err(ClientRegistrationError::InvalidClientMetadata(
            "private_key_jwt requires jwks or jwks_uri".to_string(),
        )),
    }
}

/// Validate JWK Set format and keys
fn validate_jwk_set(jwks: &serde_json::Value) -> Result<(), ClientRegistrationError> {
    // Check basic JWK Set structure
    let keys = jwks.get("keys").and_then(|k| k.as_array()).ok_or_else(|| {
        ClientRegistrationError::InvalidClientMetadata(
            "Invalid JWK Set: missing 'keys' array".to_string(),
        )
    })?;

    if keys.is_empty() {
        return Err(ClientRegistrationError::InvalidClientMetadata(
            "JWK Set cannot be empty".to_string(),
        ));
    }

    // Validate each key
    for (i, key) in keys.iter().enumerate() {
        validate_jwk(key, i)?;
    }

    Ok(())
}

/// Validate individual JWK
fn validate_jwk(jwk: &serde_json::Value, index: usize) -> Result<(), ClientRegistrationError> {
    let error_prefix = format!("Invalid JWK at index {}", index);

    // Check required fields
    let kty = jwk.get("kty").and_then(|v| v.as_str()).ok_or_else(|| {
        ClientRegistrationError::InvalidClientMetadata(format!(
            "{}: missing 'kty' field",
            error_prefix
        ))
    })?;

    let alg = jwk.get("alg").and_then(|v| v.as_str());

    // Validate key type and algorithm
    match kty {
        "EC" => {
            let crv = jwk.get("crv").and_then(|v| v.as_str()).ok_or_else(|| {
                ClientRegistrationError::InvalidClientMetadata(format!(
                    "{}: EC key missing 'crv' field",
                    error_prefix
                ))
            })?;

            // Validate curve and algorithm compatibility
            match (crv, alg) {
                ("P-256", Some("ES256")) | ("P-256", None) => {}
                ("secp256k1", Some("ES256K")) | ("secp256k1", None) => {}
                _ => {
                    return Err(ClientRegistrationError::InvalidClientMetadata(format!(
                        "{}: unsupported curve/algorithm combination",
                        error_prefix
                    )));
                }
            }

            // Check required EC key components
            if jwk.get("x").is_none() || jwk.get("y").is_none() {
                return Err(ClientRegistrationError::InvalidClientMetadata(format!(
                    "{}: EC key missing x/y coordinates",
                    error_prefix
                )));
            }
        }
        "RSA" => {
            return Err(ClientRegistrationError::InvalidClientMetadata(format!(
                "{}: RSA keys not supported for private_key_jwt",
                error_prefix
            )));
        }
        _ => {
            return Err(ClientRegistrationError::InvalidClientMetadata(format!(
                "{}: unsupported key type '{}'",
                error_prefix, kty
            )));
        }
    }

    // Key usage should be 'sig' for signing
    if let Some(use_val) = jwk.get("use").and_then(|v| v.as_str()) {
        if use_val != "sig" {
            return Err(ClientRegistrationError::InvalidClientMetadata(format!(
                "{}: key use must be 'sig' for JWT signing",
                error_prefix
            )));
        }
    }

    Ok(())
}
