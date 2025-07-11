//! OAuth authorization server factory functions.

use std::sync::Arc;

use atproto_identity::validation::{
    is_valid_did_method_plc, is_valid_did_method_web, is_valid_hostname, strip_handle_prefixes,
};

use super::context::AppState;
use crate::errors::OAuthError;
use crate::oauth::auth_server::AuthorizationServer;

/// Normalize login_hint values to ensure consistent format
///
/// Accepts handle, DID, or HTTPS URL values and normalizes them:
/// - Handle inputs may have `@` or `at://` prefix which will be stripped
/// - DID inputs may have `at://` prefix which will be stripped
/// - HTTPS URLs must only contain protocol, hostname, and optional port
///
/// # Examples
/// ```ignore
/// normalize_login_hint("ngerakines.me") -> Ok("ngerakines.me")
/// normalize_login_hint("@ngerakines.me") -> Ok("ngerakines.me")
/// normalize_login_hint("at://ngerakines.me") -> Ok("ngerakines.me")
/// normalize_login_hint("did:plc:7iza6de2dwap2sbkpav7c6c6") -> Ok("did:plc:7iza6de2dwap2sbkpav7c6c6")
/// normalize_login_hint("at://did:plc:7iza6de2dwap2sbkpav7c6c6") -> Ok("did:plc:7iza6de2dwap2sbkpav7c6c6")
/// normalize_login_hint("https://example.com") -> Ok("https://example.com")
/// ```
pub fn normalize_login_hint(login_hint: &str) -> Result<String, OAuthError> {
    let trimmed = login_hint.trim();

    if trimmed.is_empty() {
        return Err(OAuthError::InvalidRequest(
            "Login hint cannot be empty".to_string(),
        ));
    }

    let trimmed = strip_handle_prefixes(trimmed);

    // Check if it's an HTTPS URL
    if trimmed.starts_with("https://") {
        // Parse URL to ensure it's valid and extract only protocol + hostname + port
        match url::Url::parse(trimmed) {
            Ok(url) => {
                if url.scheme() != "https" {
                    return Err(OAuthError::InvalidRequest(
                        "Only HTTPS URLs are allowed".to_string(),
                    ));
                }

                // Build URL with only scheme, host, and optional port
                let mut normalized = String::from("https://");
                if let Some(host) = url.host_str() {
                    normalized.push_str(host);
                    if let Some(port) = url.port() {
                        normalized.push(':');
                        normalized.push_str(&port.to_string());
                    }
                    Ok(normalized)
                } else {
                    Err(OAuthError::InvalidRequest(
                        "Invalid HTTPS URL: missing host".to_string(),
                    ))
                }
            }
            Err(_) => Err(OAuthError::InvalidRequest(
                "Invalid HTTPS URL format".to_string(),
            )),
        }
    }
    // Check if it's a DID
    else if trimmed.starts_with("did:") {
        // Validate DIDs using atproto_identity validation functions
        if trimmed.starts_with("did:plc:") {
            if !is_valid_did_method_plc(trimmed) {
                return Err(OAuthError::InvalidRequest(
                    "Invalid DID PLC format".to_string(),
                ));
            }
        } else if trimmed.starts_with("did:web:") {
            if !is_valid_did_method_web(trimmed, true) {
                return Err(OAuthError::InvalidRequest(
                    "Invalid DID Web format".to_string(),
                ));
            }
        } else {
            return Err(OAuthError::InvalidRequest(
                "Unsupported DID method".to_string(),
            ));
        }

        Ok(trimmed.to_string())
    }
    // Otherwise, treat it as a handle
    else {
        if !(is_valid_hostname(trimmed) && trimmed.contains('.')) {
            return Err(OAuthError::InvalidRequest(
                "Invalid handle format".to_string(),
            ));
        }

        Ok(trimmed.to_string())
    }
}

/// Create base authorization server
pub async fn create_base_auth_server(
    state: &AppState,
) -> std::result::Result<Arc<AuthorizationServer>, Box<dyn std::error::Error + Send + Sync>> {
    Ok(Arc::new(AuthorizationServer::new(
        state.oauth_storage.clone(),
        state.config.external_base.clone(),
    )))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::oauth::DPoPNonceGenerator;
    use crate::storage::SimpleKeyProvider;
    use crate::storage::inmemory::MemoryOAuthStorage;
    use atproto_identity::{resolve::create_resolver, storage_lru::LruDidDocumentStorage};
    use atproto_oauth::storage_lru::LruOAuthRequestStorage;
    use std::{num::NonZeroUsize, sync::Arc};

    fn create_test_app_state() -> AppState {
        let oauth_storage = Arc::new(MemoryOAuthStorage::new());

        let http_client = reqwest::Client::new();
        let dns_nameservers = vec![];
        let dns_resolver = create_resolver(&dns_nameservers);
        let identity_resolver = atproto_identity::resolve::IdentityResolver(Arc::new(
            atproto_identity::resolve::InnerIdentityResolver {
                http_client: http_client.clone(),
                dns_resolver,
                plc_hostname: "plc.directory".to_string(),
            },
        ));

        let key_provider = Arc::new(SimpleKeyProvider::new());
        let oauth_request_storage =
            Arc::new(LruOAuthRequestStorage::new(NonZeroUsize::new(256).unwrap()));
        let document_storage =
            Arc::new(LruDidDocumentStorage::new(NonZeroUsize::new(100).unwrap()));

        #[cfg(feature = "reload")]
        let template_env = {
            use minijinja_autoreload::AutoReloader;
            axum_template::engine::Engine::new(AutoReloader::new(|_| {
                Ok(minijinja::Environment::new())
            }))
        };

        #[cfg(not(feature = "reload"))]
        let template_env = axum_template::engine::Engine::new(minijinja::Environment::new());

        let config = Arc::new(crate::config::Config {
            version: "test".to_string(),
            http_port: "3000".to_string().try_into().unwrap(),
            http_static_path: "static".to_string(),
            http_templates_path: "templates".to_string(),
            external_base: "https://localhost".to_string(),
            certificate_bundles: "".to_string().try_into().unwrap(),
            user_agent: "test-user-agent".to_string(),
            plc_hostname: "plc.directory".to_string(),
            dns_nameservers: "".to_string().try_into().unwrap(),
            http_client_timeout: "10s".to_string().try_into().unwrap(),
            atproto_oauth_signing_keys: Default::default(),
            oauth_signing_keys: Default::default(),
            oauth_supported_scopes: crate::config::OAuthSupportedScopes::try_from(
                "read write atproto:atproto".to_string(),
            )
            .unwrap(),
            dpop_nonce_seed: "seed".to_string(),
            storage_backend: "memory".to_string(),
            database_url: None,
            redis_url: None,
            enable_client_api: false,
            client_default_access_token_expiration: "1d".to_string().try_into().unwrap(),
            client_default_refresh_token_expiration: "14d".to_string().try_into().unwrap(),
            admin_dids: "".to_string().try_into().unwrap(),
            client_default_redirect_exact: "true".to_string().try_into().unwrap(),
            atproto_client_name: "AIP OAuth Server".to_string().try_into().unwrap(),
            atproto_client_logo: None::<String>.try_into().unwrap(),
            atproto_client_tos: None::<String>.try_into().unwrap(),
            atproto_client_policy: None::<String>.try_into().unwrap(),
        });

        let atp_session_storage = Arc::new(
            crate::oauth::UnifiedAtpOAuthSessionStorageAdapter::new(oauth_storage.clone()),
        );
        let authorization_request_storage = Arc::new(
            crate::oauth::UnifiedAuthorizationRequestStorageAdapter::new(oauth_storage.clone()),
        );
        let client_registration_service = Arc::new(crate::oauth::ClientRegistrationService::new(
            oauth_storage.clone(),
            chrono::Duration::days(1),
            chrono::Duration::days(14),
            true,
        ));

        AppState {
            http_client: http_client.clone(),
            config: config.clone(),
            template_env,
            identity_resolver,
            key_provider,
            oauth_request_storage,
            document_storage,
            oauth_storage,
            client_registration_service,
            atp_session_storage,
            authorization_request_storage,
            atproto_oauth_signing_keys: vec![],
            dpop_nonce_provider: Arc::new(DPoPNonceGenerator::new(
                config.dpop_nonce_seed.clone(),
                1,
            )),
        }
    }

    #[tokio::test]
    async fn test_create_base_auth_server() {
        let app_state = create_test_app_state();
        let result = create_base_auth_server(&app_state).await;
        assert!(result.is_ok());

        let auth_server = result.unwrap();
        // Verify that the server was created successfully
        // Since the AuthorizationServer doesn't expose much for testing,
        // we just verify that it was created without panicking
        assert!(Arc::strong_count(&auth_server) > 0);
    }

    #[tokio::test]
    async fn test_create_base_auth_server_with_different_config() {
        let mut app_state = create_test_app_state();

        // Modify the config to test different external_base
        let custom_config = Arc::new(crate::config::Config {
            version: "test".to_string(),
            http_port: "3000".to_string().try_into().unwrap(),
            http_static_path: "static".to_string(),
            http_templates_path: "templates".to_string(),
            external_base: "https://custom.example.com".to_string(),
            certificate_bundles: "".to_string().try_into().unwrap(),
            user_agent: "custom-user-agent".to_string(),
            plc_hostname: "custom.plc.directory".to_string(),
            dns_nameservers: "".to_string().try_into().unwrap(),
            http_client_timeout: "30s".to_string().try_into().unwrap(),
            atproto_oauth_signing_keys: Default::default(),
            oauth_signing_keys: Default::default(),
            oauth_supported_scopes: crate::config::OAuthSupportedScopes::try_from(
                "read write atproto:atproto".to_string(),
            )
            .unwrap(),
            dpop_nonce_seed: "seed".to_string(),
            storage_backend: "memory".to_string(),
            database_url: None,
            redis_url: None,
            enable_client_api: false,
            client_default_access_token_expiration: "1d".to_string().try_into().unwrap(),
            client_default_refresh_token_expiration: "14d".to_string().try_into().unwrap(),
            admin_dids: "".to_string().try_into().unwrap(),
            client_default_redirect_exact: "true".to_string().try_into().unwrap(),
            atproto_client_name: "AIP OAuth Server".to_string().try_into().unwrap(),
            atproto_client_logo: None::<String>.try_into().unwrap(),
            atproto_client_tos: None::<String>.try_into().unwrap(),
            atproto_client_policy: None::<String>.try_into().unwrap(),
        });

        app_state.config = custom_config;

        let result = create_base_auth_server(&app_state).await;
        assert!(result.is_ok());
    }

    #[test]
    fn test_normalize_login_hint_handle() {
        // Basic handle without prefix
        assert_eq!(
            normalize_login_hint("ngerakines.me").unwrap(),
            "ngerakines.me"
        );

        // Handle with @ prefix
        assert_eq!(
            normalize_login_hint("@ngerakines.me").unwrap(),
            "ngerakines.me"
        );

        // Handle with at:// prefix
        assert_eq!(
            normalize_login_hint("at://ngerakines.me").unwrap(),
            "ngerakines.me"
        );

        // Handle with multiple dots
        assert_eq!(
            normalize_login_hint("sub.domain.example.com").unwrap(),
            "sub.domain.example.com"
        );

        // Handle with @ and spaces (trimmed)
        assert_eq!(
            normalize_login_hint("  @example.com  ").unwrap(),
            "example.com"
        );
    }

    #[test]
    fn test_normalize_login_hint_did() {
        // Valid DID PLC without prefix
        assert_eq!(
            normalize_login_hint("did:plc:7iza6de2dwap2sbkpav7c6c6").unwrap(),
            "did:plc:7iza6de2dwap2sbkpav7c6c6"
        );

        // Valid DID PLC with at:// prefix
        assert_eq!(
            normalize_login_hint("at://did:plc:7iza6de2dwap2sbkpav7c6c6").unwrap(),
            "did:plc:7iza6de2dwap2sbkpav7c6c6"
        );

        // Valid DID Web
        assert_eq!(
            normalize_login_hint("did:web:example.com").unwrap(),
            "did:web:example.com"
        );

        // DID with spaces (trimmed)
        assert_eq!(
            normalize_login_hint("  did:plc:7iza6de2dwap2sbkpav7c6c6  ").unwrap(),
            "did:plc:7iza6de2dwap2sbkpav7c6c6"
        );
    }

    #[test]
    fn test_normalize_login_hint_https_url() {
        // Basic HTTPS URL
        assert_eq!(
            normalize_login_hint("https://example.com").unwrap(),
            "https://example.com"
        );

        // HTTPS URL with port
        assert_eq!(
            normalize_login_hint("https://example.com:8080").unwrap(),
            "https://example.com:8080"
        );

        // HTTPS URL with path (should be stripped)
        assert_eq!(
            normalize_login_hint("https://example.com/path/to/resource").unwrap(),
            "https://example.com"
        );

        // HTTPS URL with query parameters (should be stripped)
        assert_eq!(
            normalize_login_hint("https://example.com?foo=bar").unwrap(),
            "https://example.com"
        );

        // HTTPS URL with fragment (should be stripped)
        assert_eq!(
            normalize_login_hint("https://example.com#section").unwrap(),
            "https://example.com"
        );

        // HTTPS URL with everything (port 443 is default for HTTPS so won't be included)
        assert_eq!(
            normalize_login_hint("https://example.com:443/path?query=value#fragment").unwrap(),
            "https://example.com"
        );
    }

    #[test]
    fn test_normalize_login_hint_errors() {
        // Empty string
        assert!(normalize_login_hint("").is_err());

        // Only whitespace
        assert!(normalize_login_hint("   ").is_err());

        // Invalid handle (no dot) - ATProtocol validation will catch these
        assert!(normalize_login_hint("invalid").is_err());
        assert!(normalize_login_hint("@invalid").is_err());
        assert!(normalize_login_hint("at://invalid").is_err());

        // Invalid DID PLC (wrong format)
        assert!(normalize_login_hint("did:plc:invalid").is_err());
        assert!(normalize_login_hint("did:plc:").is_err());
        assert!(normalize_login_hint("at://did:plc:invalid").is_err());

        // Invalid DID Web (wrong format)
        assert!(normalize_login_hint("did:web:").is_err());
        assert!(normalize_login_hint("did:web:invalid..domain").is_err());

        // Invalid DID (too short or malformed)
        assert!(normalize_login_hint("did:").is_err());
        assert!(normalize_login_hint("did:x").is_err());
        assert!(normalize_login_hint("at://did:").is_err());

        // Non-HTTPS URLs
        assert!(normalize_login_hint("http://example.com").is_err());
        assert!(normalize_login_hint("ftp://example.com").is_err());

        // Invalid URL format
        assert!(normalize_login_hint("https://").is_err());
        assert!(normalize_login_hint("https://[invalid").is_err());
    }
}
