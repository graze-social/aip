//! OAuth 2.1 Integration Tests
//!
//! These tests verify the complete OAuth 2.1 flows including authorization code grant,
//! client credentials grant, dynamic client registration, and DPoP support.

use aip::oauth::{
    OAuthClientStore, auth_server::*, clients::registration::*, resource_server::*, types::*,
};
use aip::storage::{inmemory::MemoryOAuthStorage, traits::AccessTokenStore};
use axum::http::HeaderMap;
use chrono::{Duration, Utc};
use std::sync::Arc;

#[tokio::test]
async fn test_complete_authorization_code_flow() {
    // Setup
    let storage = Arc::new(MemoryOAuthStorage::new());
    let auth_server = Arc::new(AuthorizationServer::new(
        storage.clone(),
        "https://localhost".to_string(),
    ));
    let resource_server = Arc::new(ResourceServer::new(
        storage.clone(),
        "https://localhost".to_string(),
    ));
    let client_registration = Arc::new(ClientRegistrationService::new(storage.clone()));

    // Step 1: Dynamic Client Registration
    let registration_request = ClientRegistrationRequest {
        client_name: Some("Test Application".to_string()),
        redirect_uris: Some(vec!["https://app.example.com/callback".to_string()]),
        grant_types: Some(vec![GrantType::AuthorizationCode]),
        response_types: Some(vec![ResponseType::Code]),
        scope: Some("read write profile".to_string()),
        token_endpoint_auth_method: Some(ClientAuthMethod::ClientSecretBasic),
        metadata: serde_json::Value::Null,
    };

    let registration_response = client_registration
        .register_client(registration_request)
        .await
        .unwrap();
    let client_id = registration_response.client_id;
    let client_secret = registration_response.client_secret.unwrap();

    // Step 2: Authorization Request
    let auth_request = AuthorizationRequest {
        response_type: vec![ResponseType::Code],
        client_id: client_id.clone(),
        redirect_uri: "https://app.example.com/callback".to_string(),
        scope: Some("read profile".to_string()),
        state: Some("random-state-string".to_string()),
        code_challenge: None,
        code_challenge_method: None,
        login_hint: None,
        nonce: None,
    };

    let auth_response = auth_server
        .authorize(auth_request, "user123".to_string(), None)
        .await
        .unwrap();

    // Extract authorization code from redirect
    let redirect_url = match auth_response {
        AuthorizeResponse::Redirect(url) => url,
        _ => panic!("Expected redirect response"),
    };

    let parsed_url = url::Url::parse(&redirect_url).unwrap();
    let code = parsed_url
        .query_pairs()
        .find(|(key, _)| key == "code")
        .map(|(_, value)| value.to_string())
        .expect("Authorization code not found in redirect URL");

    // Step 3: Token Exchange
    let token_request = TokenRequest {
        grant_type: GrantType::AuthorizationCode,
        code: Some(code),
        redirect_uri: Some("https://app.example.com/callback".to_string()),
        code_verifier: None,
        refresh_token: None,
        client_id: Some(client_id.clone()),
        client_secret: Some(client_secret.clone()),
        scope: None,
    };

    let headers = HeaderMap::new();
    let client_auth = Some(ClientAuthentication {
        client_id: client_id.clone(),
        client_secret: Some(client_secret.clone()),
    });

    let token_response = auth_server
        .token(token_request, &headers, client_auth)
        .await
        .unwrap();

    assert!(!token_response.access_token.is_empty());
    assert!(token_response.refresh_token.is_some());
    assert_eq!(token_response.token_type, TokenType::Bearer);
    assert_eq!(token_response.scope, Some("read profile".to_string()));

    // Step 4: Resource Access
    let mut resource_headers = HeaderMap::new();
    resource_headers.insert(
        "Authorization",
        format!("Bearer {}", token_response.access_token)
            .parse()
            .unwrap(),
    );

    let validation_result = resource_server
        .validate_token(
            &resource_headers,
            "GET",
            "/api/profile",
            Some(&["read".to_string()]),
        )
        .await
        .unwrap();

    assert_eq!(validation_result.client_id, client_id);
    assert_eq!(validation_result.user_id, Some("user123".to_string()));
    assert!(validation_result.scopes.contains("read"));
    assert!(validation_result.scopes.contains("profile"));

    // Step 5: Token Refresh
    let refresh_request = TokenRequest {
        grant_type: GrantType::RefreshToken,
        code: None,
        redirect_uri: None,
        code_verifier: None,
        refresh_token: token_response.refresh_token,
        client_id: Some(client_id.clone()),
        client_secret: None,
        scope: None,
    };

    let refresh_headers = HeaderMap::new();
    let refresh_auth = Some(ClientAuthentication {
        client_id,
        client_secret: Some(client_secret),
    });

    let new_token_response = auth_server
        .token(refresh_request, &refresh_headers, refresh_auth)
        .await
        .unwrap();

    assert!(!new_token_response.access_token.is_empty());
    assert!(new_token_response.refresh_token.is_some());
    assert_ne!(new_token_response.access_token, token_response.access_token);
}

#[tokio::test]
async fn test_client_credentials_flow() {
    // Setup
    let storage = Arc::new(MemoryOAuthStorage::new());
    let auth_server = Arc::new(AuthorizationServer::new(
        storage.clone(),
        "https://localhost".to_string(),
    ));
    let resource_server = Arc::new(ResourceServer::new(
        storage.clone(),
        "https://localhost".to_string(),
    ));

    // Create a confidential client for client credentials flow
    let client = OAuthClient {
        client_id: "service-client".to_string(),
        client_secret: Some("service-secret".to_string()),
        client_name: Some("Service Client".to_string()),
        redirect_uris: vec![], // No redirect URIs needed for client credentials
        grant_types: vec![GrantType::ClientCredentials],
        response_types: vec![], // No response types needed for client credentials
        scope: Some("api:read api:write".to_string()),
        token_endpoint_auth_method: ClientAuthMethod::ClientSecretBasic,
        client_type: ClientType::Confidential,
        created_at: Utc::now(),
        updated_at: Utc::now(),
        metadata: serde_json::Value::Null,
    };

    storage.store_client(&client).await.unwrap();

    // Token Request
    let token_request = TokenRequest {
        grant_type: GrantType::ClientCredentials,
        code: None,
        redirect_uri: None,
        code_verifier: None,
        refresh_token: None,
        client_id: Some("service-client".to_string()),
        client_secret: Some("service-secret".to_string()),
        scope: Some("api:read".to_string()),
    };

    let headers = HeaderMap::new();
    let client_auth = Some(ClientAuthentication {
        client_id: "service-client".to_string(),
        client_secret: Some("service-secret".to_string()),
    });

    let token_response = auth_server
        .token(token_request, &headers, client_auth)
        .await
        .unwrap();

    assert!(!token_response.access_token.is_empty());
    assert!(token_response.refresh_token.is_none()); // No refresh token for client credentials
    assert_eq!(token_response.token_type, TokenType::Bearer);
    assert_eq!(token_response.scope, Some("api:read".to_string()));

    // Resource Access
    let mut resource_headers = HeaderMap::new();
    resource_headers.insert(
        "Authorization",
        format!("Bearer {}", token_response.access_token)
            .parse()
            .unwrap(),
    );

    let validation_result = resource_server
        .validate_token(
            &resource_headers,
            "GET",
            "/api/data",
            Some(&["api:read".to_string()]),
        )
        .await
        .unwrap();

    assert_eq!(validation_result.client_id, "service-client");
    assert_eq!(validation_result.user_id, None); // No user for client credentials
    assert!(validation_result.scopes.contains("api:read"));
}

#[tokio::test]
async fn test_token_expiry_and_cleanup() {
    let storage = Arc::new(MemoryOAuthStorage::new());
    let resource_server = Arc::new(ResourceServer::new(
        storage.clone(),
        "https://localhost".to_string(),
    ));

    // Create an expired token
    let expired_token = AccessToken {
        token: "expired-token".to_string(),
        token_type: TokenType::Bearer,
        client_id: "test-client".to_string(),
        user_id: Some("test-user".to_string()),
        session_id: None,
        session_iteration: None,
        scope: Some("read".to_string()),
        created_at: Utc::now() - Duration::hours(2),
        expires_at: Utc::now() - Duration::hours(1), // Expired 1 hour ago
        dpop_jkt: None,
        nonce: None,
    };

    storage.store_token(&expired_token).await.unwrap();

    // Try to validate expired token
    let mut headers = HeaderMap::new();
    headers.insert("Authorization", "Bearer expired-token".parse().unwrap());

    let result = resource_server
        .validate_token(&headers, "GET", "/api/resource", None)
        .await;

    // Should fail with invalid token error
    assert!(result.is_err());
    match result.unwrap_err() {
        aip::errors::OAuthError::InvalidGrant(msg) => {
            assert!(msg.contains("expired"));
        }
        _ => panic!("Expected InvalidGrant error for expired token"),
    }
}

#[tokio::test]
async fn test_scope_validation() {
    let storage = Arc::new(MemoryOAuthStorage::new());
    let resource_server = Arc::new(ResourceServer::new(
        storage.clone(),
        "https://localhost".to_string(),
    ));

    // Create a token with limited scope
    let token = AccessToken {
        token: "limited-token".to_string(),
        token_type: TokenType::Bearer,
        client_id: "test-client".to_string(),
        user_id: Some("test-user".to_string()),
        session_id: None,
        session_iteration: None,
        scope: Some("read".to_string()), // Only read scope
        created_at: Utc::now(),
        expires_at: Utc::now() + Duration::hours(1),
        dpop_jkt: None,
        nonce: None,
    };

    storage.store_token(&token).await.unwrap();

    let mut headers = HeaderMap::new();
    headers.insert("Authorization", "Bearer limited-token".parse().unwrap());

    // Should succeed with read scope requirement
    let result = resource_server
        .validate_token(&headers, "GET", "/api/data", Some(&["read".to_string()]))
        .await;
    assert!(result.is_ok());

    // Should fail with write scope requirement
    let result = resource_server
        .validate_token(&headers, "POST", "/api/data", Some(&["write".to_string()]))
        .await;

    assert!(result.is_err());
    match result.unwrap_err() {
        aip::errors::OAuthError::InvalidScope(msg) => {
            assert!(msg.contains("write"));
        }
        _ => panic!("Expected InvalidScope error"),
    }
}

#[tokio::test]
async fn test_invalid_client_registration() {
    let storage = Arc::new(MemoryOAuthStorage::new());
    let client_registration = Arc::new(ClientRegistrationService::new(storage));

    // Test invalid redirect URI (HTTP without localhost)
    let invalid_request = ClientRegistrationRequest {
        client_name: Some("Invalid Client".to_string()),
        redirect_uris: Some(vec!["http://malicious.example.com/callback".to_string()]),
        grant_types: Some(vec![GrantType::AuthorizationCode]),
        response_types: Some(vec![ResponseType::Code]),
        scope: Some("read".to_string()),
        token_endpoint_auth_method: Some(ClientAuthMethod::ClientSecretBasic),
        metadata: serde_json::Value::Null,
    };

    let result = client_registration.register_client(invalid_request).await;
    assert!(result.is_err());
    match result.unwrap_err() {
        aip::errors::ClientRegistrationError::InvalidRedirectUri(msg) => {
            assert!(msg.contains("HTTP redirect URIs only allowed for localhost"));
        }
        _ => panic!("Expected InvalidRedirectUri error"),
    }
}
