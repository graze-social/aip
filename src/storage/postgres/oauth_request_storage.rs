//! PostgreSQL implementation of OAuthRequestStorage trait
//!
//! This module provides PostgreSQL-based storage for ATProtocol OAuth authorization
//! requests, handling the complete OAuth flow lifecycle with proper expiration and cleanup.

use anyhow::Result;
use async_trait::async_trait;
use atproto_oauth::{storage::OAuthRequestStorage, workflow::OAuthRequest};
use chrono::{DateTime, Utc};
use sqlx::Row;
use sqlx::postgres::{PgPool, PgRow};

/// PostgreSQL implementation of OAuthRequestStorage
pub struct PostgresOAuthRequestStorage {
    pool: PgPool,
}

impl PostgresOAuthRequestStorage {
    /// Create a new PostgreSQL OAuth request storage instance
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }
}

#[async_trait]
impl OAuthRequestStorage for PostgresOAuthRequestStorage {
    async fn get_oauth_request_by_state(&self, state: &str) -> Result<Option<OAuthRequest>> {
        let query = "
            SELECT 
                oauth_state,
                issuer,
                authorization_server,
                nonce,
                pkce_verifier,
                signing_public_key,
                dpop_private_key,
                created_at,
                expires_at
            FROM oauth_requests 
            WHERE oauth_state = $1 AND expires_at > $2
        ";

        let row: Option<PgRow> = sqlx::query(query)
            .bind(state)
            .bind(Utc::now())
            .fetch_optional(&self.pool)
            .await?;

        Ok(row.map(|r| OAuthRequestRow::from_row(&r).into_oauth_request()))
    }

    async fn insert_oauth_request(&self, request: OAuthRequest) -> Result<()> {
        let query = "
            INSERT INTO oauth_requests (
                oauth_state, 
                issuer, 
                authorization_server,
                nonce, 
                pkce_verifier, 
                signing_public_key,
                dpop_private_key, 
                created_at, 
                expires_at
            )
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
            ON CONFLICT (oauth_state) 
            DO UPDATE SET
                issuer = EXCLUDED.issuer,
                authorization_server = EXCLUDED.authorization_server,
                nonce = EXCLUDED.nonce,
                pkce_verifier = EXCLUDED.pkce_verifier,
                signing_public_key = EXCLUDED.signing_public_key,
                dpop_private_key = EXCLUDED.dpop_private_key,
                created_at = EXCLUDED.created_at,
                expires_at = EXCLUDED.expires_at
        ";

        sqlx::query(query)
            .bind(&request.oauth_state)
            .bind(&request.issuer)
            .bind(&request.authorization_server)
            .bind(&request.nonce)
            .bind(&request.pkce_verifier)
            .bind(&request.signing_public_key)
            .bind(&request.dpop_private_key)
            .bind(request.created_at)
            .bind(request.expires_at)
            .execute(&self.pool)
            .await?;

        Ok(())
    }

    async fn delete_oauth_request_by_state(&self, state: &str) -> Result<()> {
        sqlx::query("DELETE FROM oauth_requests WHERE oauth_state = $1")
            .bind(state)
            .execute(&self.pool)
            .await?;

        Ok(())
    }

    async fn clear_expired_oauth_requests(&self) -> Result<u64> {
        let result = sqlx::query("DELETE FROM oauth_requests WHERE expires_at <= $1")
            .bind(Utc::now())
            .execute(&self.pool)
            .await?;

        Ok(result.rows_affected())
    }
}

/// Database row representation of an OAuth request
#[derive(Debug)]
struct OAuthRequestRow {
    oauth_state: String,
    issuer: String,
    authorization_server: String,
    nonce: String,
    pkce_verifier: String,
    signing_public_key: String,
    dpop_private_key: String,
    created_at: DateTime<Utc>,
    expires_at: DateTime<Utc>,
}

impl OAuthRequestRow {
    /// Create OAuthRequestRow from database row
    fn from_row(row: &PgRow) -> Self {
        Self {
            oauth_state: row.get("oauth_state"),
            issuer: row.get("issuer"),
            authorization_server: row.get("authorization_server"),
            nonce: row.get("nonce"),
            pkce_verifier: row.get("pkce_verifier"),
            signing_public_key: row.get("signing_public_key"),
            dpop_private_key: row.get("dpop_private_key"),
            created_at: row.get("created_at"),
            expires_at: row.get("expires_at"),
        }
    }

    /// Convert database row to OAuthRequest struct
    fn into_oauth_request(self) -> OAuthRequest {
        OAuthRequest {
            oauth_state: self.oauth_state,
            issuer: self.issuer,
            authorization_server: self.authorization_server,
            nonce: self.nonce,
            pkce_verifier: self.pkce_verifier,
            signing_public_key: self.signing_public_key,
            dpop_private_key: self.dpop_private_key,
            created_at: self.created_at,
            expires_at: self.expires_at,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Duration;
    use sqlx::PgPool;

    async fn setup_test_pool() -> PgPool {
        // This would be used for integration tests with a test database
        // For now, we'll just show the structure
        todo!("Setup test database pool")
    }

    #[tokio::test]
    #[ignore] // Requires test database setup
    async fn test_insert_and_retrieve_oauth_request() {
        let pool = setup_test_pool().await;
        let storage = PostgresOAuthRequestStorage::new(pool);

        let now = Utc::now();
        let request = OAuthRequest {
            oauth_state: "test-state-123".to_string(),
            issuer: "https://pds.example.com".to_string(),
            authorization_server: "https://pds.example.com".to_string(),
            nonce: "test-nonce".to_string(),
            pkce_verifier: "test-verifier".to_string(),
            signing_public_key: "test-public-key".to_string(),
            dpop_private_key: "test-private-key".to_string(),
            created_at: now,
            expires_at: now + Duration::minutes(10),
        };

        // Insert request
        storage.insert_oauth_request(request.clone()).await.unwrap();

        // Retrieve request
        let retrieved = storage
            .get_oauth_request_by_state("test-state-123")
            .await
            .unwrap();
        assert_eq!(
            retrieved.as_ref().map(|r| &r.oauth_state),
            Some(&request.oauth_state)
        );

        // Delete request
        storage
            .delete_oauth_request_by_state("test-state-123")
            .await
            .unwrap();
        let deleted = storage
            .get_oauth_request_by_state("test-state-123")
            .await
            .unwrap();
        assert_eq!(deleted, None);
    }

    #[tokio::test]
    #[ignore] // Requires test database setup
    async fn test_expired_request_not_returned() {
        let pool = setup_test_pool().await;
        let storage = PostgresOAuthRequestStorage::new(pool);

        let now = Utc::now();
        let expired_request = OAuthRequest {
            oauth_state: "expired-state-456".to_string(),
            issuer: "https://pds.example.com".to_string(),
            authorization_server: "https://pds.example.com".to_string(),
            nonce: "expired-nonce".to_string(),
            pkce_verifier: "expired-verifier".to_string(),
            signing_public_key: "expired-public-key".to_string(),
            dpop_private_key: "expired-private-key".to_string(),
            created_at: now - Duration::minutes(20),
            expires_at: now - Duration::minutes(10), // Expired 10 minutes ago
        };

        // Insert expired request
        storage.insert_oauth_request(expired_request).await.unwrap();

        // Try to retrieve expired request (should return None)
        let retrieved = storage
            .get_oauth_request_by_state("expired-state-456")
            .await
            .unwrap();
        assert_eq!(retrieved, None);
    }

    #[tokio::test]
    #[ignore] // Requires test database setup
    async fn test_clear_expired_requests() {
        let pool = setup_test_pool().await;
        let storage = PostgresOAuthRequestStorage::new(pool);

        let now = Utc::now();

        // Insert expired request
        let expired_request = OAuthRequest {
            oauth_state: "expired-clear-test".to_string(),
            issuer: "https://pds.example.com".to_string(),
            authorization_server: "https://pds.example.com".to_string(),
            nonce: "expired-nonce".to_string(),
            pkce_verifier: "expired-verifier".to_string(),
            signing_public_key: "expired-public-key".to_string(),
            dpop_private_key: "expired-private-key".to_string(),
            created_at: now - Duration::minutes(20),
            expires_at: now - Duration::minutes(10),
        };

        // Insert valid request
        let valid_request = OAuthRequest {
            oauth_state: "valid-clear-test".to_string(),
            issuer: "https://pds.example.com".to_string(),
            authorization_server: "https://pds.example.com".to_string(),
            nonce: "valid-nonce".to_string(),
            pkce_verifier: "valid-verifier".to_string(),
            signing_public_key: "valid-public-key".to_string(),
            dpop_private_key: "valid-private-key".to_string(),
            created_at: now,
            expires_at: now + Duration::minutes(10),
        };

        storage.insert_oauth_request(expired_request).await.unwrap();
        storage.insert_oauth_request(valid_request).await.unwrap();

        // Clear expired requests
        let cleared_count = storage.clear_expired_oauth_requests().await.unwrap();
        assert_eq!(cleared_count, 1);

        // Valid request should still exist
        let valid_retrieved = storage
            .get_oauth_request_by_state("valid-clear-test")
            .await
            .unwrap();
        assert!(valid_retrieved.is_some());

        // Expired request should be gone
        let expired_retrieved = storage
            .get_oauth_request_by_state("expired-clear-test")
            .await
            .unwrap();
        assert_eq!(expired_retrieved, None);
    }
}
