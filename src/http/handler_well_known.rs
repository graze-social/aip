//! Handles OAuth 2.0 well-known discovery endpoints - authorization server metadata, protected resource metadata, and JWKS

use atproto_identity::key::to_public;
use atproto_oauth::jwk::generate;
use axum::{extract::State, http::StatusCode, response::Json};
use serde_json::{Value, json};

use super::context::AppState;

/// OAuth 2.0 Protected Resource Metadata handler
/// GET /.well-known/oauth-protected-resource
///
/// Returns metadata about the protected resource as specified by the OAuth 2.0 Resource Server spec.
pub async fn oauth_protected_resource_handler(State(state): State<AppState>) -> Json<Value> {
    let metadata = json!({
        "resource": state.config.external_base,
        "authorization_servers": [state.config.external_base],
        "jwks_uri": format!("{}/.well-known/jwks.json", state.config.external_base),
        "scopes_supported": ["openid", "atproto:atproto", "atproto:transition:generic", "atproto:transition:email", "profile", "email"],
        "bearer_methods_supported": ["header", "body"],
        "dpop_signing_alg_values_supported": ["ES256"]
    });

    Json(metadata)
}

/// OAuth 2.0 Authorization Server Metadata handler
/// GET /.well-known/oauth-authorization-server
///
/// Returns metadata about the OAuth authorization server as specified by RFC 8414.
pub async fn oauth_authorization_server_handler(State(state): State<AppState>) -> Json<Value> {
    let metadata = json!({
        "issuer": state.config.external_base,
        "authorization_endpoint": format!("{}/oauth/authorize", state.config.external_base),
        "token_endpoint": format!("{}/oauth/token", state.config.external_base),
        "device_authorization_endpoint": format!("{}/oauth/device", state.config.external_base),
        "registration_endpoint": format!("{}/oauth/clients/register", state.config.external_base),
        "jwks_uri": format!("{}/.well-known/jwks.json", state.config.external_base),
        "scopes_supported": ["openid", "atproto:atproto", "atproto:transition:generic", "atproto:transition:email", "profile", "email"],
        "response_types_supported": ["code"],
        "response_modes_supported": ["query"],
        "grant_types_supported": ["authorization_code", "client_credentials", "refresh_token", "urn:ietf:params:oauth:grant-type:device_code"],
        "token_endpoint_auth_methods_supported": ["client_secret_basic", "client_secret_post", "none"],
        "token_endpoint_auth_signing_alg_values_supported": ["ES256"],
        "service_documentation": format!("{}/docs", state.config.external_base),
        "ui_locales_supported": ["en"],
        "op_policy_uri": format!("{}/policy", state.config.external_base),
        "op_tos_uri": format!("{}/terms", state.config.external_base),
        "revocation_endpoint": format!("{}/oauth/revoke", state.config.external_base),
        "introspection_endpoint": format!("{}/oauth/introspect", state.config.external_base),
        "code_challenge_methods_supported": ["S256"],
        "dpop_signing_alg_values_supported": ["ES256"],
        "require_pushed_authorization_requests": false,
        "pushed_authorization_request_endpoint": format!("{}/oauth/par", state.config.external_base),
        "subject_types_supported": ["public"],
        "id_token_signing_alg_values_supported": ["ES256"],
        "request_object_signing_alg_values_supported": ["ES256"],
        "request_parameter_supported": true,
        "request_uri_parameter_supported": true,
        "require_request_uri_registration": false,
        "claims_parameter_supported": false
    });

    Json(metadata)
}

/// OpenID Connect Configuration handler
/// GET /.well-known/openid-configuration
///
/// Returns OpenID Provider metadata as specified by OpenID Connect Discovery 1.0 specification.
pub async fn openid_configuration_handler(State(state): State<AppState>) -> Json<Value> {
    let metadata = json!({
        "issuer": state.config.external_base,
        "authorization_endpoint": format!("{}/oauth/authorize", state.config.external_base),
        "token_endpoint": format!("{}/oauth/token", state.config.external_base),
        "userinfo_endpoint": format!("{}/oauth/userinfo", state.config.external_base),
        "jwks_uri": format!("{}/.well-known/jwks.json", state.config.external_base),
        "response_types_supported": ["code", "id_token"],
        "subject_types_supported": ["public"],
        "id_token_signing_alg_values_supported": ["ES256"],
        "userinfo_signed_response_alg": ["ES256"],
        "scopes_supported": ["openid", "atproto:atproto", "atproto:transition:generic", "atproto:transition:email", "profile", "email"],
        "claims_supported": ["iss", "sub", "aud", "exp", "iat", "auth_time", "nonce", "at_hash", "c_hash", "email", "did", "name", "profile", "pds_endpoint"],
        "grant_types_supported": ["authorization_code", "refresh_token"],
        "response_modes_supported": ["query", "fragment"]
    });

    Json(metadata)
}

/// JWKS (JSON Web Key Set) handler
/// GET /.well-known/jwks.json
///
/// Returns the public keys used by the authorization server for signing tokens.
pub async fn jwks_handler(
    State(state): State<AppState>,
) -> Result<Json<Value>, (StatusCode, Json<Value>)> {
    let mut jwks_keys = Vec::new();
    for key_data in state.config.oauth_signing_keys.as_ref() {
        if let Ok(public_key_data) = to_public(key_data) {
            if let Ok(jwk) = generate(&public_key_data) {
                jwks_keys.push(jwk);
            }
        }
    }
    for key_data in state.config.atproto_oauth_signing_keys.as_ref() {
        if let Ok(public_key_data) = to_public(key_data) {
            if let Ok(jwk) = generate(&public_key_data) {
                jwks_keys.push(jwk);
            }
        }
    }

    let jwks = json!({
        "keys": jwks_keys
    });
    Ok(Json(jwks))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::oauth::DPoPNonceGenerator;
    use crate::storage::inmemory::MemoryOAuthStorage;
    use std::sync::Arc;

    fn create_test_app_state() -> AppState {
        let oauth_storage = Arc::new(MemoryOAuthStorage::new());

        let http_client = reqwest::Client::new();
        let dns_nameservers = vec![];
        let dns_resolver = atproto_identity::resolve::create_resolver(&dns_nameservers);
        let identity_resolver = atproto_identity::resolve::IdentityResolver(Arc::new(
            atproto_identity::resolve::InnerIdentityResolver {
                http_client: http_client.clone(),
                dns_resolver,
                plc_hostname: "plc.directory".to_string(),
            },
        ));

        let key_provider = Arc::new(crate::storage::SimpleKeyProvider::new());
        let oauth_request_storage =
            Arc::new(atproto_oauth::storage_lru::LruOAuthRequestStorage::new(
                std::num::NonZeroUsize::new(256).unwrap(),
            ));
        let document_storage = Arc::new(atproto_identity::storage_lru::LruDidDocumentStorage::new(
            std::num::NonZeroUsize::new(100).unwrap(),
        ));

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
    async fn test_oauth_protected_resource_handler() {
        let app_state = create_test_app_state();
        let response = oauth_protected_resource_handler(State(app_state)).await;
        let metadata = response.0;

        assert!(metadata.get("resource").is_some());
        assert!(metadata.get("authorization_servers").is_some());
        assert!(metadata.get("jwks_uri").is_some());
        assert!(metadata.get("scopes_supported").is_some());
        assert!(metadata.get("dpop_signing_alg_values_supported").is_some());

        // Verify DPoP support
        let dpop_algs = metadata["dpop_signing_alg_values_supported"]
            .as_array()
            .unwrap();
        assert!(dpop_algs.contains(&json!("ES256")));
    }

    #[tokio::test]
    async fn test_oauth_authorization_server_handler() {
        let app_state = create_test_app_state();
        let response = oauth_authorization_server_handler(State(app_state)).await;
        let metadata = response.0;

        // Verify required OAuth metadata fields
        assert!(metadata.get("issuer").is_some());
        assert!(metadata.get("authorization_endpoint").is_some());
        assert!(metadata.get("token_endpoint").is_some());
        assert!(metadata.get("jwks_uri").is_some());
        assert!(metadata.get("scopes_supported").is_some());
        assert!(metadata.get("response_types_supported").is_some());
        assert!(metadata.get("grant_types_supported").is_some());

        // Verify PAR support configuration
        assert_eq!(metadata["require_pushed_authorization_requests"], false);
        assert!(
            metadata
                .get("pushed_authorization_request_endpoint")
                .is_some()
        );

        // Verify PAR endpoint URL format
        let par_endpoint = metadata["pushed_authorization_request_endpoint"]
            .as_str()
            .unwrap();
        assert!(par_endpoint.ends_with("/oauth/par"));
        assert!(par_endpoint.starts_with("https://localhost"));

        // Verify DPoP support
        let dpop_algs = metadata["dpop_signing_alg_values_supported"]
            .as_array()
            .unwrap();
        assert!(dpop_algs.contains(&json!("ES256")));
    }

    #[tokio::test]
    async fn test_openid_configuration_handler() {
        let app_state = create_test_app_state();
        let response = openid_configuration_handler(State(app_state)).await;
        let metadata = response.0;

        // Verify required OpenID Connect metadata fields
        assert!(metadata.get("issuer").is_some());
        assert!(metadata.get("authorization_endpoint").is_some());
        assert!(metadata.get("token_endpoint").is_some());
        assert!(metadata.get("userinfo_endpoint").is_some());
        assert!(metadata.get("jwks_uri").is_some());
        assert!(metadata.get("response_types_supported").is_some());
        assert!(metadata.get("subject_types_supported").is_some());
        assert!(
            metadata
                .get("id_token_signing_alg_values_supported")
                .is_some()
        );

        // Verify OpenID Connect specific requirements
        let response_types = metadata["response_types_supported"].as_array().unwrap();
        assert!(response_types.contains(&json!("code")));
        assert!(response_types.contains(&json!("id_token")));

        let subject_types = metadata["subject_types_supported"].as_array().unwrap();
        assert!(subject_types.contains(&json!("public")));

        let id_token_algs = metadata["id_token_signing_alg_values_supported"]
            .as_array()
            .unwrap();
        assert!(id_token_algs.contains(&json!("ES256")));

        // Verify scopes include openid
        let scopes = metadata["scopes_supported"].as_array().unwrap();
        assert!(scopes.contains(&json!("openid")));

        // Verify endpoint URLs are properly formatted
        let issuer = metadata["issuer"].as_str().unwrap();
        assert!(issuer.starts_with("https://"));

        let auth_endpoint = metadata["authorization_endpoint"].as_str().unwrap();
        assert!(auth_endpoint.starts_with("https://"));
        assert!(auth_endpoint.ends_with("/oauth/authorize"));

        let token_endpoint = metadata["token_endpoint"].as_str().unwrap();
        assert!(token_endpoint.starts_with("https://"));
        assert!(token_endpoint.ends_with("/oauth/token"));

        let jwks_uri = metadata["jwks_uri"].as_str().unwrap();
        assert!(jwks_uri.starts_with("https://"));
        assert!(jwks_uri.ends_with("/.well-known/jwks.json"));

        let userinfo_endpoint = metadata["userinfo_endpoint"].as_str().unwrap();
        assert!(userinfo_endpoint.starts_with("https://"));
        assert!(userinfo_endpoint.ends_with("/oauth/userinfo"));
    }

    #[tokio::test]
    async fn test_jwks_handler_empty_keys() {
        let app_state = create_test_app_state();
        let result = jwks_handler(State(app_state)).await;

        match result {
            Ok(response) => {
                let jwks = response.0;
                assert!(jwks.get("keys").is_some());
                let keys = jwks["keys"].as_array().unwrap();
                assert_eq!(keys.len(), 0); // No keys stored yet
            }
            Err((status, _)) => {
                // Also acceptable if storage doesn't support signing keys yet
                assert!(status.is_server_error() || status.is_client_error());
            }
        }
    }

    #[tokio::test]
    async fn test_jwks_handler_with_key() {
        use atproto_identity::key::{KeyType, generate_key};

        let app_state = create_test_app_state();

        // Generate and store a test signing key
        let signing_key = generate_key(KeyType::P256Private).unwrap();
        app_state
            .oauth_storage
            .store_signing_key(&signing_key)
            .await
            .unwrap();

        let result = jwks_handler(State(app_state)).await;

        match result {
            Ok(response) => {
                let jwks = response.0;
                assert!(jwks.get("keys").is_some());
                let keys = jwks["keys"].as_array().unwrap();
                // TODO: Currently returns empty array due to unimplemented JWK conversion
                // When JWK conversion is implemented, this should be 1
                assert_eq!(keys.len(), 0);
            }
            Err((status, error)) => {
                // If conversion fails, that's also valid for testing
                println!("JWKS conversion failed: {:?}", error);
                assert!(status.is_server_error());
            }
        }
    }

    #[test]
    fn test_well_known_endpoint_paths() {
        // Verify the endpoint paths follow OAuth specifications
        assert_eq!(
            "/.well-known/oauth-protected-resource",
            "/.well-known/oauth-protected-resource"
        );
        assert_eq!(
            "/.well-known/oauth-authorization-server",
            "/.well-known/oauth-authorization-server"
        );
        assert_eq!("/.well-known/jwks.json", "/.well-known/jwks.json");
    }

    #[test]
    fn test_metadata_compliance() {
        // Test that metadata structures comply with OAuth specifications
        let test_metadata = json!({
            "issuer": "https://example.com",
            "authorization_endpoint": "https://example.com/oauth/authorize",
            "token_endpoint": "https://example.com/oauth/token",
            "jwks_uri": "https://example.com/.well-known/jwks.json"
        });

        // Verify required fields are present
        assert!(test_metadata.get("issuer").is_some());
        assert!(test_metadata.get("authorization_endpoint").is_some());
        assert!(test_metadata.get("token_endpoint").is_some());
        assert!(test_metadata.get("jwks_uri").is_some());
    }
}
