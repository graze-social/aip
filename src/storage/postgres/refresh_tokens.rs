//! PostgreSQL implementation for refresh token storage

use crate::errors::StorageError;
use crate::oauth::types::RefreshToken;
use crate::storage::traits::{RefreshTokenStore, Result};
use async_trait::async_trait;
use chrono::Utc;
use sqlx::Row;
use sqlx::postgres::{PgPool, PgRow};

/// PostgreSQL implementation of refresh token storage
pub struct PostgresRefreshTokenStore {
    pool: PgPool,
}

impl PostgresRefreshTokenStore {
    /// Create a new PostgreSQL refresh token store
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }

    /// Convert PostgreSQL row to RefreshToken
    fn row_to_refresh_token(row: &PgRow) -> Result<RefreshToken> {
        let created_at: chrono::DateTime<chrono::Utc> = row
            .try_get("created_at")
            .map_err(|e| StorageError::DatabaseError(format!("Failed to get created_at: {}", e)))?;

        let expires_at: Option<chrono::DateTime<chrono::Utc>> = row
            .try_get("expires_at")
            .map_err(|e| StorageError::DatabaseError(format!("Failed to get expires_at: {}", e)))?;

        Ok(RefreshToken {
            token: row
                .try_get("token")
                .map_err(|e| StorageError::DatabaseError(format!("Failed to get token: {}", e)))?,
            access_token: row.try_get("access_token").map_err(|e| {
                StorageError::DatabaseError(format!("Failed to get access_token: {}", e))
            })?,
            client_id: row.try_get("client_id").map_err(|e| {
                StorageError::DatabaseError(format!("Failed to get client_id: {}", e))
            })?,
            user_id: row.try_get("user_id").map_err(|e| {
                StorageError::DatabaseError(format!("Failed to get user_id: {}", e))
            })?,
            session_id: row.try_get("session_id").map_err(|e| {
                StorageError::DatabaseError(format!("Failed to get session_id: {}", e))
            })?,
            scope: row
                .try_get("scope")
                .map_err(|e| StorageError::DatabaseError(format!("Failed to get scope: {}", e)))?,
            nonce: row
                .try_get("nonce")
                .map_err(|e| StorageError::DatabaseError(format!("Failed to get nonce: {}", e)))?,
            created_at,
            expires_at,
        })
    }
}

#[async_trait]
impl RefreshTokenStore for PostgresRefreshTokenStore {
    async fn store_refresh_token(&self, token: &RefreshToken) -> Result<()> {
        sqlx::query(
            r#"
            INSERT INTO refresh_tokens (
                token, access_token, client_id, user_id, session_id, scope, nonce, created_at, expires_at
            ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
            "#,
        )
        .bind(&token.token)
        .bind(&token.access_token)
        .bind(&token.client_id)
        .bind(&token.user_id)
        .bind(&token.session_id)
        .bind(&token.scope)
        .bind(&token.nonce)
        .bind(token.created_at)
        .bind(token.expires_at)
        .execute(&self.pool)
        .await
        .map_err(|e| StorageError::DatabaseError(e.to_string()))?;

        Ok(())
    }

    async fn consume_refresh_token(&self, token: &str) -> Result<Option<RefreshToken>> {
        // Start a transaction to ensure atomicity
        let mut tx = self
            .pool
            .begin()
            .await
            .map_err(|e| StorageError::DatabaseError(e.to_string()))?;

        // First, get the token if it exists
        let row = sqlx::query("SELECT * FROM refresh_tokens WHERE token = $1")
            .bind(token)
            .fetch_optional(&mut *tx)
            .await
            .map_err(|e| StorageError::DatabaseError(e.to_string()))?;

        match row {
            Some(row) => {
                let refresh_token = Self::row_to_refresh_token(&row)?;

                // Check if the token has expired (if it has an expiration)
                if let Some(expires_at) = refresh_token.expires_at {
                    let now = Utc::now();
                    if expires_at <= now {
                        // Clean up expired token and return None
                        sqlx::query("DELETE FROM refresh_tokens WHERE token = $1")
                            .bind(token)
                            .execute(&mut *tx)
                            .await
                            .map_err(|e| StorageError::DatabaseError(e.to_string()))?;

                        tx.commit()
                            .await
                            .map_err(|e| StorageError::DatabaseError(e.to_string()))?;
                        return Ok(None);
                    }
                }

                // Delete the token (refresh tokens are typically one-time use)
                sqlx::query("DELETE FROM refresh_tokens WHERE token = $1")
                    .bind(token)
                    .execute(&mut *tx)
                    .await
                    .map_err(|e| StorageError::DatabaseError(e.to_string()))?;

                tx.commit()
                    .await
                    .map_err(|e| StorageError::DatabaseError(e.to_string()))?;

                Ok(Some(refresh_token))
            }
            None => Ok(None),
        }
    }

    async fn cleanup_expired_refresh_tokens(&self) -> Result<usize> {
        let now = Utc::now();

        let result = sqlx::query(
            "DELETE FROM refresh_tokens WHERE expires_at IS NOT NULL AND expires_at <= $1",
        )
        .bind(now)
        .execute(&self.pool)
        .await
        .map_err(|e| StorageError::DatabaseError(e.to_string()))?;

        Ok(result.rows_affected() as usize)
    }
}
