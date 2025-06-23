//! SQLite implementation for refresh token storage

use crate::errors::StorageError;
use crate::oauth::types::*;
use crate::storage::traits::{RefreshTokenStore, Result};
use async_trait::async_trait;
use chrono::Utc;
use sqlx::Row;
use sqlx::sqlite::{SqlitePool, SqliteRow};

/// SQLite implementation of refresh token storage
pub struct SqliteRefreshTokenStore {
    pool: SqlitePool,
}

impl SqliteRefreshTokenStore {
    /// Create a new SQLite refresh token store
    pub fn new(pool: SqlitePool) -> Self {
        Self { pool }
    }

    /// Convert SQLite row to RefreshToken
    fn row_to_refresh_token(row: &SqliteRow) -> Result<RefreshToken> {
        let created_at_str: String = row
            .try_get("created_at")
            .map_err(|e| StorageError::DatabaseError(format!("Failed to get created_at: {}", e)))?;
        let created_at = chrono::DateTime::parse_from_rfc3339(&created_at_str)
            .map_err(|e| StorageError::InvalidData(format!("Invalid created_at timestamp: {}", e)))?
            .with_timezone(&Utc);

        let expires_at = if let Ok(expires_at_str) = row.try_get::<Option<String>, _>("expires_at")
        {
            if let Some(expires_at_str) = expires_at_str {
                Some(
                    chrono::DateTime::parse_from_rfc3339(&expires_at_str)
                        .map_err(|e| {
                            StorageError::InvalidData(format!(
                                "Invalid expires_at timestamp: {}",
                                e
                            ))
                        })?
                        .with_timezone(&Utc),
                )
            } else {
                None
            }
        } else {
            None
        };

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
impl RefreshTokenStore for SqliteRefreshTokenStore {
    async fn store_refresh_token(&self, token: &RefreshToken) -> Result<()> {
        let created_at_str = token.created_at.to_rfc3339();
        let expires_at_str = token.expires_at.as_ref().map(|dt| dt.to_rfc3339());

        sqlx::query(
            r#"
            INSERT INTO refresh_tokens (
                token, access_token, client_id, user_id, session_id,
                scope, nonce, created_at, expires_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            "#,
        )
        .bind(&token.token)
        .bind(&token.access_token)
        .bind(&token.client_id)
        .bind(&token.user_id)
        .bind(&token.session_id)
        .bind(&token.scope)
        .bind(&token.nonce)
        .bind(created_at_str)
        .bind(expires_at_str)
        .execute(&self.pool)
        .await
        .map_err(|e| StorageError::DatabaseError(e.to_string()))?;

        Ok(())
    }

    async fn consume_refresh_token(&self, token_value: &str) -> Result<Option<RefreshToken>> {
        // Start a transaction to ensure atomicity
        let mut tx = self
            .pool
            .begin()
            .await
            .map_err(|e| StorageError::DatabaseError(e.to_string()))?;

        // First, get the token if it exists
        let row = sqlx::query("SELECT * FROM refresh_tokens WHERE token = ?")
            .bind(token_value)
            .fetch_optional(&mut *tx)
            .await
            .map_err(|e| StorageError::DatabaseError(e.to_string()))?;

        match row {
            Some(row) => {
                let refresh_token = Self::row_to_refresh_token(&row)?;

                // Check if the token has expired (if it has an expiration date)
                if let Some(expires_at) = refresh_token.expires_at {
                    let now = Utc::now();
                    if expires_at <= now {
                        // Clean up expired token and return None
                        sqlx::query("DELETE FROM refresh_tokens WHERE token = ?")
                            .bind(token_value)
                            .execute(&mut *tx)
                            .await
                            .map_err(|e| StorageError::DatabaseError(e.to_string()))?;

                        tx.commit()
                            .await
                            .map_err(|e| StorageError::DatabaseError(e.to_string()))?;
                        return Ok(None);
                    }
                }

                // Delete the refresh token (one-time use)
                sqlx::query("DELETE FROM refresh_tokens WHERE token = ?")
                    .bind(token_value)
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
        let now_str = now.to_rfc3339();

        // Only delete tokens that have an explicit expiration date and are expired
        let result = sqlx::query(
            "DELETE FROM refresh_tokens WHERE expires_at IS NOT NULL AND expires_at <= ?",
        )
        .bind(now_str)
        .execute(&self.pool)
        .await
        .map_err(|e| StorageError::DatabaseError(e.to_string()))?;

        Ok(result.rows_affected() as usize)
    }
}
