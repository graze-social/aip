//! SQLite implementation for access token storage

use crate::errors::StorageError;
use crate::oauth::types::*;
use crate::storage::traits::{AccessTokenStore, Result};
use async_trait::async_trait;
use chrono::Utc;
use sqlx::Row;
use sqlx::sqlite::{SqlitePool, SqliteRow};

/// SQLite implementation of access token storage
pub struct SqliteAccessTokenStore {
    pool: SqlitePool,
}

impl SqliteAccessTokenStore {
    /// Create a new SQLite access token store
    pub fn new(pool: SqlitePool) -> Self {
        Self { pool }
    }

    /// Convert TokenType enum to string representation
    fn token_type_to_string(token_type: &TokenType) -> &'static str {
        match token_type {
            TokenType::Bearer => "bearer",
            TokenType::DPoP => "dpop",
        }
    }

    /// Convert string to TokenType enum
    fn string_to_token_type(s: &str) -> Result<TokenType> {
        match s {
            "bearer" => Ok(TokenType::Bearer),
            "dpop" => Ok(TokenType::DPoP),
            _ => Err(StorageError::InvalidData(format!(
                "Unknown token type: {}",
                s
            ))),
        }
    }

    /// Convert SQLite row to AccessToken
    fn row_to_access_token(row: &SqliteRow) -> Result<AccessToken> {
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

        let token_type_str: String = row
            .try_get("token_type")
            .map_err(|e| StorageError::DatabaseError(format!("Failed to get token_type: {}", e)))?;
        let token_type = Self::string_to_token_type(&token_type_str)?;

        let session_iteration: Option<i64> = row.try_get("session_iteration").map_err(|e| {
            StorageError::DatabaseError(format!("Failed to get session_iteration: {}", e))
        })?;
        let session_iteration = session_iteration.map(|i| i as u32);

        Ok(AccessToken {
            token: row
                .try_get("token")
                .map_err(|e| StorageError::DatabaseError(format!("Failed to get token: {}", e)))?,
            token_type,
            client_id: row.try_get("client_id").map_err(|e| {
                StorageError::DatabaseError(format!("Failed to get client_id: {}", e))
            })?,
            user_id: row.try_get("user_id").map_err(|e| {
                StorageError::DatabaseError(format!("Failed to get user_id: {}", e))
            })?,
            session_id: row.try_get("session_id").map_err(|e| {
                StorageError::DatabaseError(format!("Failed to get session_id: {}", e))
            })?,
            session_iteration,
            scope: row
                .try_get("scope")
                .map_err(|e| StorageError::DatabaseError(format!("Failed to get scope: {}", e)))?,
            nonce: row
                .try_get("nonce")
                .map_err(|e| StorageError::DatabaseError(format!("Failed to get nonce: {}", e)))?,
            created_at,
            expires_at,
            dpop_jkt: row.try_get("dpop_jkt").map_err(|e| {
                StorageError::DatabaseError(format!("Failed to get dpop_jkt: {}", e))
            })?,
        })
    }
}

#[async_trait]
impl AccessTokenStore for SqliteAccessTokenStore {
    async fn store_token(&self, token: &AccessToken) -> Result<()> {
        let created_at_str = token.created_at.to_rfc3339();
        let expires_at_str = token.expires_at.to_rfc3339();
        let token_type_str = Self::token_type_to_string(&token.token_type);
        let session_iteration = token.session_iteration.map(|i| i as i64);

        sqlx::query(
            r#"
            INSERT INTO access_tokens (
                token, token_type, client_id, user_id, session_id, session_iteration,
                scope, nonce, created_at, expires_at, dpop_jkt
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            "#,
        )
        .bind(&token.token)
        .bind(token_type_str)
        .bind(&token.client_id)
        .bind(&token.user_id)
        .bind(&token.session_id)
        .bind(session_iteration)
        .bind(&token.scope)
        .bind(&token.nonce)
        .bind(created_at_str)
        .bind(expires_at_str)
        .bind(&token.dpop_jkt)
        .execute(&self.pool)
        .await
        .map_err(|e| StorageError::DatabaseError(e.to_string()))?;

        Ok(())
    }

    async fn get_token(&self, token_value: &str) -> Result<Option<AccessToken>> {
        let row = sqlx::query("SELECT * FROM access_tokens WHERE token = ?")
            .bind(token_value)
            .fetch_optional(&self.pool)
            .await
            .map_err(|e| StorageError::DatabaseError(e.to_string()))?;

        match row {
            Some(row) => {
                let access_token = Self::row_to_access_token(&row)?;

                // Check if the token has expired
                let now = Utc::now();
                if access_token.expires_at <= now {
                    // Clean up expired token and return None
                    sqlx::query("DELETE FROM access_tokens WHERE token = ?")
                        .bind(token_value)
                        .execute(&self.pool)
                        .await
                        .map_err(|e| StorageError::DatabaseError(e.to_string()))?;
                    return Ok(None);
                }

                Ok(Some(access_token))
            }
            None => Ok(None),
        }
    }

    async fn revoke_token(&self, token_value: &str) -> Result<()> {
        let result = sqlx::query("DELETE FROM access_tokens WHERE token = ?")
            .bind(token_value)
            .execute(&self.pool)
            .await
            .map_err(|e| StorageError::DatabaseError(e.to_string()))?;

        if result.rows_affected() == 0 {
            return Err(StorageError::NotFound(format!(
                "Token not found: {}",
                token_value
            )));
        }

        Ok(())
    }

    async fn cleanup_expired_tokens(&self) -> Result<usize> {
        let now = Utc::now();
        let now_str = now.to_rfc3339();

        let result = sqlx::query("DELETE FROM access_tokens WHERE expires_at <= ?")
            .bind(now_str)
            .execute(&self.pool)
            .await
            .map_err(|e| StorageError::DatabaseError(e.to_string()))?;

        Ok(result.rows_affected() as usize)
    }

    async fn get_user_tokens(&self, user_id: &str) -> Result<Vec<AccessToken>> {
        let rows =
            sqlx::query("SELECT * FROM access_tokens WHERE user_id = ? ORDER BY created_at DESC")
                .bind(user_id)
                .fetch_all(&self.pool)
                .await
                .map_err(|e| StorageError::DatabaseError(e.to_string()))?;

        let mut tokens = Vec::new();
        for row in rows {
            let token = Self::row_to_access_token(&row)?;

            // Only include non-expired tokens
            let now = Utc::now();
            if token.expires_at > now {
                tokens.push(token);
            }
        }

        Ok(tokens)
    }

    async fn get_client_tokens(&self, client_id: &str) -> Result<Vec<AccessToken>> {
        let rows =
            sqlx::query("SELECT * FROM access_tokens WHERE client_id = ? ORDER BY created_at DESC")
                .bind(client_id)
                .fetch_all(&self.pool)
                .await
                .map_err(|e| StorageError::DatabaseError(e.to_string()))?;

        let mut tokens = Vec::new();
        for row in rows {
            let token = Self::row_to_access_token(&row)?;

            // Only include non-expired tokens
            let now = Utc::now();
            if token.expires_at > now {
                tokens.push(token);
            }
        }

        Ok(tokens)
    }
}
