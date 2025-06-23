//! PostgreSQL implementation for authorization code storage

use crate::errors::StorageError;
use crate::oauth::types::AuthorizationCode;
use crate::storage::traits::{AuthorizationCodeStore, Result};
use async_trait::async_trait;
use chrono::Utc;
use sqlx::Row;
use sqlx::postgres::{PgPool, PgRow};

/// PostgreSQL implementation of authorization code storage
pub struct PostgresAuthorizationCodeStore {
    pool: PgPool,
}

impl PostgresAuthorizationCodeStore {
    /// Create a new PostgreSQL authorization code store
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }

    /// Convert PostgreSQL row to AuthorizationCode
    fn row_to_authorization_code(row: &PgRow) -> Result<AuthorizationCode> {
        let created_at: chrono::DateTime<chrono::Utc> = row
            .try_get("created_at")
            .map_err(|e| StorageError::DatabaseError(format!("Failed to get created_at: {}", e)))?;

        let expires_at: chrono::DateTime<chrono::Utc> = row
            .try_get("expires_at")
            .map_err(|e| StorageError::DatabaseError(format!("Failed to get expires_at: {}", e)))?;

        let used: bool = row
            .try_get("used")
            .map_err(|e| StorageError::DatabaseError(format!("Failed to get used: {}", e)))?;

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
impl AuthorizationCodeStore for PostgresAuthorizationCodeStore {
    async fn store_code(&self, code: &AuthorizationCode) -> Result<()> {
        sqlx::query(
            r#"
            INSERT INTO authorization_codes (
                code, client_id, user_id, session_id, redirect_uri, scope, code_challenge, 
                code_challenge_method, nonce, created_at, expires_at, used
            ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12)
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
        .bind(code.created_at)
        .bind(code.expires_at)
        .bind(code.used)
        .execute(&self.pool)
        .await
        .map_err(|e| StorageError::DatabaseError(e.to_string()))?;

        Ok(())
    }

    async fn consume_code(&self, code: &str) -> Result<Option<AuthorizationCode>> {
        // Start a transaction to ensure atomicity
        let mut tx = self
            .pool
            .begin()
            .await
            .map_err(|e| StorageError::DatabaseError(e.to_string()))?;

        // First, get the code if it exists
        let row = sqlx::query("SELECT * FROM authorization_codes WHERE code = $1")
            .bind(code)
            .fetch_optional(&mut *tx)
            .await
            .map_err(|e| StorageError::DatabaseError(e.to_string()))?;

        match row {
            Some(row) => {
                let auth_code = Self::row_to_authorization_code(&row)?;

                // Check if the code has expired
                let now = Utc::now();
                if auth_code.expires_at <= now {
                    // Clean up expired code and return None
                    sqlx::query("DELETE FROM authorization_codes WHERE code = $1")
                        .bind(code)
                        .execute(&mut *tx)
                        .await
                        .map_err(|e| StorageError::DatabaseError(e.to_string()))?;

                    tx.commit()
                        .await
                        .map_err(|e| StorageError::DatabaseError(e.to_string()))?;
                    return Ok(None);
                }

                // Delete the code (one-time use)
                sqlx::query("DELETE FROM authorization_codes WHERE code = $1")
                    .bind(code)
                    .execute(&mut *tx)
                    .await
                    .map_err(|e| StorageError::DatabaseError(e.to_string()))?;

                tx.commit()
                    .await
                    .map_err(|e| StorageError::DatabaseError(e.to_string()))?;

                Ok(Some(auth_code))
            }
            None => Ok(None),
        }
    }

    async fn cleanup_expired_codes(&self) -> Result<usize> {
        let now = Utc::now();

        let result = sqlx::query("DELETE FROM authorization_codes WHERE expires_at <= $1")
            .bind(now)
            .execute(&self.pool)
            .await
            .map_err(|e| StorageError::DatabaseError(e.to_string()))?;

        Ok(result.rows_affected() as usize)
    }
}
