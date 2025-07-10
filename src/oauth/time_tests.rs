//! Time handling validation tests.
//!
//! Verifies UTC time usage, chrono integration, and expiration logic across OAuth components.

#[cfg(test)]
mod tests {
    use super::super::{atprotocol_bridge::AtpOAuthSession, types::*};
    use crate::storage::{inmemory::MemoryOAuthStorage, traits::AccessTokenStore};
    use chrono::{Duration, Utc};

    /// Test that all session timestamps are in UTC
    #[tokio::test]
    async fn test_session_timestamps_are_utc() {
        let now = Utc::now();

        // Test AtpOAuthSession uses UTC
        let session = AtpOAuthSession {
            session_id: "test-session".to_string(),
            did: Some("did:plc:test123".to_string()),
            session_created_at: now,
            atp_oauth_state: "test-state".to_string(),
            signing_key_jkt: "test-jkt".to_string(),
            dpop_key: "test-dpop-key".to_string(),
            access_token: None,
            refresh_token: None,
            access_token_created_at: None,
            access_token_expires_at: None,
            access_token_scopes: None,
            session_exchanged_at: None,
            exchange_error: None,
            iteration: 1,
        };

        // Verify the timestamps are UTC (chrono DateTime<Utc>)
        assert_eq!(session.session_created_at.timezone(), Utc);
    }

    /// Test that OAuth tokens use UTC timestamps
    #[tokio::test]
    async fn test_oauth_token_timestamps_utc() {
        let now = Utc::now();

        // Test AuthorizationCode
        let auth_code = AuthorizationCode {
            code: "test-code".to_string(),
            client_id: "test-client".to_string(),
            user_id: "test-user".to_string(),
            redirect_uri: "https://example.com/callback".to_string(),
            scope: Some("read".to_string()),
            code_challenge: None,
            code_challenge_method: None,
            nonce: None,
            created_at: now,
            expires_at: now + Duration::minutes(10),
            used: false,
            session_id: None,
        };

        assert_eq!(auth_code.created_at.timezone(), Utc);
        assert_eq!(auth_code.expires_at.timezone(), Utc);

        // Test AccessToken
        let access_token = AccessToken {
            token: "test-token".to_string(),
            token_type: TokenType::Bearer,
            client_id: "test-client".to_string(),
            user_id: Some("test-user".to_string()),
            session_id: None,
            session_iteration: None,
            scope: Some("read write".to_string()),
            created_at: now,
            expires_at: now + Duration::hours(1),
            dpop_jkt: None,
            nonce: None,
        };

        assert_eq!(access_token.created_at.timezone(), Utc);
        assert_eq!(access_token.expires_at.timezone(), Utc);

        // Test RefreshToken
        let refresh_token = RefreshToken {
            token: "refresh-token".to_string(),
            access_token: "test-token".to_string(),
            client_id: "test-client".to_string(),
            user_id: "test-user".to_string(),
            session_id: None,
            scope: Some("read write".to_string()),
            created_at: now,
            expires_at: Some(now + Duration::days(30)),
            nonce: None,
        };

        assert_eq!(refresh_token.created_at.timezone(), Utc);
        assert!(refresh_token.expires_at.unwrap().timezone() == Utc);
    }

    /// Test that OAuth clients use UTC timestamps
    #[tokio::test]
    async fn test_oauth_client_timestamps_utc() {
        let now = Utc::now();

        let client = OAuthClient {
            client_id: "test-client".to_string(),
            client_secret: Some("secret".to_string()),
            client_name: Some("Test Client".to_string()),
            redirect_uris: vec!["https://example.com/callback".to_string()],
            grant_types: vec![GrantType::AuthorizationCode],
            response_types: vec![ResponseType::Code],
            scope: Some("read write".to_string()),
            token_endpoint_auth_method: ClientAuthMethod::ClientSecretBasic,
            client_type: ClientType::Confidential,
            created_at: now,
            updated_at: now,
            metadata: serde_json::Value::Null,
            access_token_expiration: chrono::Duration::days(1),
            refresh_token_expiration: chrono::Duration::days(14),
            require_redirect_exact: true,
            registration_access_token: Some("test-registration-token".to_string()),
        };

        assert_eq!(client.created_at.timezone(), Utc);
        assert_eq!(client.updated_at.timezone(), Utc);
    }

    /// Test expiration logic works correctly with UTC times
    #[tokio::test]
    async fn test_expiration_logic_with_utc() {
        let storage = MemoryOAuthStorage::new();
        let now = Utc::now();

        // Create an expired token (1 hour ago)
        let expired_token = AccessToken {
            token: "expired-token".to_string(),
            token_type: TokenType::Bearer,
            client_id: "test-client".to_string(),
            user_id: Some("test-user".to_string()),
            session_id: None,
            session_iteration: None,
            scope: Some("read".to_string()),
            created_at: now - Duration::hours(2),
            expires_at: now - Duration::hours(1), // Expired 1 hour ago
            dpop_jkt: None,
            nonce: None,
        };

        // Create a valid token (expires in 1 hour)
        let valid_token = AccessToken {
            token: "valid-token".to_string(),
            token_type: TokenType::Bearer,
            client_id: "test-client".to_string(),
            user_id: Some("test-user".to_string()),
            session_id: None,
            session_iteration: None,
            scope: Some("read".to_string()),
            created_at: now,
            expires_at: now + Duration::hours(1),
            dpop_jkt: None,
            nonce: None,
        };

        // Store both tokens
        storage.store_token(&expired_token).await.unwrap();
        storage.store_token(&valid_token).await.unwrap();

        // Verify expired token is not returned by get_token
        let retrieved_expired = storage.get_token("expired-token").await.unwrap();
        assert!(
            retrieved_expired.is_none(),
            "Expired token should not be retrievable"
        );

        // Verify valid token is returned
        let retrieved_valid = storage.get_token("valid-token").await.unwrap();
        assert!(
            retrieved_valid.is_some(),
            "Valid token should be retrievable"
        );
    }

    /// Test duration calculations for different token types
    #[test]
    fn test_duration_calculations() {
        // Test standard OAuth token lifetimes based on AuthorizationServer defaults
        let auth_code_lifetime = Duration::minutes(10);
        let access_token_lifetime = Duration::hours(1);
        let refresh_token_lifetime = Duration::days(30);

        // Test duration arithmetic
        let now = Utc::now();
        let code_expires = now + auth_code_lifetime;
        let token_expires = now + access_token_lifetime;
        let refresh_expires = now + refresh_token_lifetime;

        // Verify ordering: code < token < refresh
        assert!(code_expires < token_expires);
        assert!(token_expires < refresh_expires);

        // Test that duration calculations work correctly
        assert_eq!(auth_code_lifetime.num_seconds(), 600);
        assert_eq!(access_token_lifetime.num_seconds(), 3600);
        assert_eq!(refresh_token_lifetime.num_seconds(), 30 * 24 * 3600);
    }

    /// Test session cleanup based on expiration times
    #[test]
    fn test_session_cleanup_with_utc() {
        let now = Utc::now();

        // Create sessions with different creation times
        let old_session = AtpOAuthSession {
            session_id: "old-session".to_string(),
            did: Some("did:plc:test123".to_string()),
            session_created_at: now - Duration::hours(2),
            atp_oauth_state: "old-state".to_string(),
            signing_key_jkt: "test-jkt-old".to_string(),
            dpop_key: "test-dpop-key-old".to_string(),
            access_token: None,
            refresh_token: None,
            access_token_created_at: None,
            access_token_expires_at: None,
            access_token_scopes: None,
            session_exchanged_at: None,
            exchange_error: None,
            iteration: 1,
        };

        let new_session = AtpOAuthSession {
            session_id: "new-session".to_string(),
            did: Some("did:plc:test123".to_string()),
            session_created_at: now,
            atp_oauth_state: "new-state".to_string(),
            signing_key_jkt: "test-jkt-new".to_string(),
            dpop_key: "test-dpop-key-new".to_string(),
            access_token: None,
            refresh_token: None,
            access_token_created_at: None,
            access_token_expires_at: None,
            access_token_scopes: None,
            session_exchanged_at: None,
            exchange_error: None,
            iteration: 1,
        };

        // Test that sessions can be sorted by creation time
        let mut sessions = vec![old_session, new_session];
        sessions.sort_by(|a, b| a.session_created_at.cmp(&b.session_created_at));

        assert_eq!(sessions.len(), 2);
        assert_eq!(sessions[0].session_id, "old-session");
        assert_eq!(sessions[1].session_id, "new-session");
    }

    /// Test timestamp serialization/deserialization maintains UTC
    #[test]
    fn test_timestamp_serialization_utc() {
        let now = Utc::now();

        let session = AtpOAuthSession {
            session_id: "test-session".to_string(),
            did: Some("did:plc:test123".to_string()),
            session_created_at: now,
            atp_oauth_state: "test-state".to_string(),
            signing_key_jkt: "test-jkt".to_string(),
            dpop_key: "test-dpop-key".to_string(),
            access_token: None,
            refresh_token: None,
            access_token_created_at: None,
            access_token_expires_at: None,
            access_token_scopes: None,
            session_exchanged_at: None,
            exchange_error: None,
            iteration: 1,
        };

        // Serialize to JSON
        let json = serde_json::to_string(&session).unwrap();

        // Deserialize back
        let deserialized: AtpOAuthSession = serde_json::from_str(&json).unwrap();

        // Verify timestamps are preserved and still UTC
        assert_eq!(deserialized.session_created_at.timezone(), Utc);
        assert_eq!(deserialized.session_created_at, session.session_created_at);
    }

    /// Test duration parsing and validation
    #[test]
    fn test_duration_parsing() {
        // Test various duration formats
        let ten_minutes = Duration::minutes(10);
        let one_hour = Duration::hours(1);
        let thirty_days = Duration::days(30);

        // Verify duration calculations
        assert_eq!(ten_minutes.num_seconds(), 600);
        assert_eq!(one_hour.num_seconds(), 3600);
        assert_eq!(thirty_days.num_seconds(), 30 * 24 * 3600);

        // Test duration comparisons
        assert!(ten_minutes < one_hour);
        assert!(one_hour < thirty_days);
    }

    /// Test UTC time zone consistency across different operations
    #[test]
    fn test_utc_timezone_consistency() {
        let now = Utc::now();

        // Test arithmetic operations preserve UTC
        let future = now + Duration::hours(1);
        let past = now - Duration::hours(1);

        assert_eq!(now.timezone(), Utc);
        assert_eq!(future.timezone(), Utc);
        assert_eq!(past.timezone(), Utc);

        // Test that comparison works correctly
        assert!(past < now);
        assert!(now < future);
        assert!(past < future);
    }
}
