//! SQLite implementation for authorization code storage

use crate::errors::StorageError;
use crate::oauth::types::*;
use crate::storage::traits::{AuthorizationCodeStore, Result};
use async_trait::async_trait;
use chrono::Utc;
use sqlx::Row;
use sqlx::sqlite::{SqlitePool, SqliteRow};

/// SQLite implementation of authorization code storage
pub struct SqliteAuthorizationCodeStore {
    pool: SqlitePool,
}

impl SqliteAuthorizationCodeStore {
    /// Create a new SQLite authorization code store
    pub fn new(pool: SqlitePool) -> Self {
        Self { pool }
    }

    /// Convert SQLite row to AuthorizationCode
    fn row_to_authorization_code(row: &SqliteRow) -> Result<AuthorizationCode> {
        let created_at_str: String = row
            .try_get("created_at")
            .map_err(|e| StorageError::DatabaseError(format!("Failed to get created_at: {}", e)))?;
        let created_at = chrono::DateTime::parse_from_rfc3339(&created_at_str)
            .map_err(|e| StorageError::InvalidData(format!("Invalid created_at timestamp: {}", e)))?
            .with_timezone(&Utc);

        let expires_at_str: String = row
            .try_get("expires_at")
            .map_err(|e| StorageError::DatabaseError(format!("Failed to get expires_at: {}", e)))?;
        let expires_at = chrono::DateTime::parse_from_rfc3339(&expires_at_str)
            .map_err(|e| StorageError::InvalidData(format!("Invalid expires_at timestamp: {}", e)))?
            .with_timezone(&Utc);

        let used_int: i64 = row
            .try_get("used")
            .map_err(|e| StorageError::DatabaseError(format!("Failed to get used: {}", e)))?;
        let used = used_int != 0;

        Ok(AuthorizationCode {
            code: row
                .try_get("code")
                .map_err(|e| StorageError::DatabaseError(format!("Failed to get code: {}", e)))?,
            client_id: row.try_get("client_id").map_err(|e| {
                StorageError::DatabaseError(format!("Failed to get client_id: {}", e))
            })?,
            user_id: row.try_get("user_id").map_err(|e| {
                StorageError::DatabaseError(format!("Failed to get user_id: {}", e))
            })?,
            session_id: row.try_get("session_id").map_err(|e| {
                StorageError::DatabaseError(format!("Failed to get session_id: {}", e))
            })?,
            redirect_uri: row.try_get("redirect_uri").map_err(|e| {
                StorageError::DatabaseError(format!("Failed to get redirect_uri: {}", e))
            })?,
            scope: row
                .try_get("scope")
                .map_err(|e| StorageError::DatabaseError(format!("Failed to get scope: {}", e)))?,
            code_challenge: row.try_get("code_challenge").map_err(|e| {
                StorageError::DatabaseError(format!("Failed to get code_challenge: {}", e))
            })?,
            code_challenge_method: row.try_get("code_challenge_method").map_err(|e| {
                StorageError::DatabaseError(format!("Failed to get code_challenge_method: {}", e))
            })?,
            nonce: row
                .try_get("nonce")
                .map_err(|e| StorageError::DatabaseError(format!("Failed to get nonce: {}", e)))?,
            created_at,
            expires_at,
            used,
        })
    }
}

#[async_trait]
impl AuthorizationCodeStore for SqliteAuthorizationCodeStore {
    async fn store_code(&self, code: &AuthorizationCode) -> Result<()> {
        let created_at_str = code.created_at.to_rfc3339();
        let expires_at_str = code.expires_at.to_rfc3339();
        let used_int = if code.used { 1i64 } else { 0i64 };

        sqlx::query(
            r#"
            INSERT INTO authorization_codes (
                code, client_id, user_id, session_id, redirect_uri, scope,
                code_challenge, code_challenge_method, nonce, created_at, expires_at, used
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            "#,
        )
        .bind(&code.code)
        .bind(&code.client_id)
        .bind(&code.user_id)
        .bind(&code.session_id)
        .bind(&code.redirect_uri)
        .bind(&code.scope)
        .bind(&code.code_challenge)
        .bind(&code.code_challenge_method)
        .bind(&code.nonce)
        .bind(created_at_str)
        .bind(expires_at_str)
        .bind(used_int)
        .execute(&self.pool)
        .await
        .map_err(|e| StorageError::DatabaseError(e.to_string()))?;

        Ok(())
    }

    async fn consume_code(&self, code_value: &str) -> Result<Option<AuthorizationCode>> {
        // Start a transaction to ensure atomicity
        let mut tx = self
            .pool
            .begin()
            .await
            .map_err(|e| StorageError::DatabaseError(e.to_string()))?;

        // First, get the code if it exists and is not used
        let row = sqlx::query("SELECT * FROM authorization_codes WHERE code = ? AND used = 0")
            .bind(code_value)
            .fetch_optional(&mut *tx)
            .await
            .map_err(|e| StorageError::DatabaseError(e.to_string()))?;

        match row {
            Some(row) => {
                let authorization_code = Self::row_to_authorization_code(&row)?;

                // Check if the code has expired
                let now = Utc::now();
                if authorization_code.expires_at <= now {
                    // Clean up expired code and return None
                    sqlx::query("DELETE FROM authorization_codes WHERE code = ?")
                        .bind(code_value)
                        .execute(&mut *tx)
                        .await
                        .map_err(|e| StorageError::DatabaseError(e.to_string()))?;

                    tx.commit()
                        .await
                        .map_err(|e| StorageError::DatabaseError(e.to_string()))?;
                    return Ok(None);
                }

                // Mark the code as used
                sqlx::query("UPDATE authorization_codes SET used = 1 WHERE code = ?")
                    .bind(code_value)
                    .execute(&mut *tx)
                    .await
                    .map_err(|e| StorageError::DatabaseError(e.to_string()))?;

                tx.commit()
                    .await
                    .map_err(|e| StorageError::DatabaseError(e.to_string()))?;

                Ok(Some(authorization_code))
            }
            None => Ok(None),
        }
    }

    async fn cleanup_expired_codes(&self) -> Result<usize> {
        let now = Utc::now();
        let now_str = now.to_rfc3339();

        let result = sqlx::query("DELETE FROM authorization_codes WHERE expires_at <= ?")
            .bind(now_str)
            .execute(&self.pool)
            .await
            .map_err(|e| StorageError::DatabaseError(e.to_string()))?;

        Ok(result.rows_affected() as usize)
    }
}
