//! SQLite implementation of OAuthRequestStorage trait
//!
//! This module provides SQLite-based storage for ATProtocol OAuth authorization
//! requests, handling the complete OAuth flow lifecycle with proper expiration and cleanup.

use anyhow::Result;
use async_trait::async_trait;
use atproto_oauth::{storage::OAuthRequestStorage, workflow::OAuthRequest};
use chrono::Utc;
use sqlx::Row;
use sqlx::sqlite::{SqlitePool, SqliteRow};

/// SQLite implementation of OAuthRequestStorage
pub struct SqliteOAuthRequestStorage {
    pool: SqlitePool,
}

impl SqliteOAuthRequestStorage {
    /// Create a new SQLite OAuth request storage instance
    pub fn new(pool: SqlitePool) -> Self {
        Self { pool }
    }
}

#[async_trait]
impl OAuthRequestStorage for SqliteOAuthRequestStorage {
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
            WHERE oauth_state = ? AND expires_at > ?
        ";

        let now = Utc::now().to_rfc3339();
        let row: Option<SqliteRow> = sqlx::query(query)
            .bind(state)
            .bind(&now)
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
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(oauth_state) 
            DO UPDATE SET
                issuer = excluded.issuer,
                authorization_server = excluded.authorization_server,
                nonce = excluded.nonce,
                pkce_verifier = excluded.pkce_verifier,
                signing_public_key = excluded.signing_public_key,
                dpop_private_key = excluded.dpop_private_key,
                created_at = excluded.created_at,
                expires_at = excluded.expires_at
        ";

        // Use the issuer as the authorization server endpoint
        // This is a temporary solution until we can properly pass the authorization_server_endpoint
        let authorization_server = &request.issuer;

        sqlx::query(query)
            .bind(&request.oauth_state)
            .bind(&request.issuer)
            .bind(authorization_server)
            .bind(&request.nonce)
            .bind(&request.pkce_verifier)
            .bind(&request.signing_public_key)
            .bind(&request.dpop_private_key)
            .bind(request.created_at.to_rfc3339())
            .bind(request.expires_at.to_rfc3339())
            .execute(&self.pool)
            .await?;

        Ok(())
    }

    async fn delete_oauth_request_by_state(&self, state: &str) -> Result<()> {
        sqlx::query("DELETE FROM oauth_requests WHERE oauth_state = ?")
            .bind(state)
            .execute(&self.pool)
            .await?;

        Ok(())
    }

    async fn clear_expired_oauth_requests(&self) -> Result<u64> {
        let now = Utc::now().to_rfc3339();
        let result = sqlx::query("DELETE FROM oauth_requests WHERE expires_at <= ?")
            .bind(&now)
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
    created_at: String,
    expires_at: String,
}

impl OAuthRequestRow {
    /// Create OAuthRequestRow from database row
    fn from_row(row: &SqliteRow) -> Self {
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
        let created_at = chrono::DateTime::parse_from_rfc3339(&self.created_at)
            .expect("Invalid created_at timestamp")
            .with_timezone(&Utc);
        let expires_at = chrono::DateTime::parse_from_rfc3339(&self.expires_at)
            .expect("Invalid expires_at timestamp")
            .with_timezone(&Utc);

        OAuthRequest {
            oauth_state: self.oauth_state,
            issuer: self.issuer,
            authorization_server: self.authorization_server,
            nonce: self.nonce,
            pkce_verifier: self.pkce_verifier,
            signing_public_key: self.signing_public_key,
            dpop_private_key: self.dpop_private_key,
            created_at,
            expires_at,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Duration;
    use sqlx::SqlitePool;

    async fn setup_test_pool() -> SqlitePool {
        // This would be used for integration tests with a test database
        // For now, we'll just show the structure
        todo!("Setup test database pool")
    }

    #[tokio::test]
    #[ignore] // Requires test database setup
    async fn test_insert_and_retrieve_oauth_request() {
        let pool = setup_test_pool().await;
        let storage = SqliteOAuthRequestStorage::new(pool);

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
    }
}
