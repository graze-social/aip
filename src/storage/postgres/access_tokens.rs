//! PostgreSQL implementation for access token storage

use crate::errors::StorageError;
use crate::oauth::types::{AccessToken, TokenType};
use crate::storage::traits::{AccessTokenStore, Result};
use async_trait::async_trait;
use chrono::Utc;
use sqlx::Row;
use sqlx::postgres::{PgPool, PgRow};

/// PostgreSQL implementation of access token storage
pub struct PostgresAccessTokenStore {
    pool: PgPool,
}

impl PostgresAccessTokenStore {
    /// Create a new PostgreSQL access token store
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }

    /// Convert TokenType enum to string representation
    fn token_type_to_string(token_type: &TokenType) -> &'static str {
        match token_type {
            TokenType::Bearer => "Bearer",
            TokenType::DPoP => "DPoP",
        }
    }

    /// Convert string to TokenType enum
    fn string_to_token_type(s: &str) -> Result<TokenType> {
        match s {
            "Bearer" => Ok(TokenType::Bearer),
            "DPoP" => Ok(TokenType::DPoP),
            _ => Err(StorageError::InvalidData(format!(
                "Unknown token type: {}",
                s
            ))),
        }
    }

    /// Convert PostgreSQL row to AccessToken
    fn row_to_access_token(row: &PgRow) -> Result<AccessToken> {
        let created_at: chrono::DateTime<chrono::Utc> = row
            .try_get("created_at")
            .map_err(|e| StorageError::DatabaseError(format!("Failed to get created_at: {}", e)))?;

        let expires_at: chrono::DateTime<chrono::Utc> = row
            .try_get("expires_at")
            .map_err(|e| StorageError::DatabaseError(format!("Failed to get expires_at: {}", e)))?;

        let token_type_str: String = row
            .try_get("token_type")
            .map_err(|e| StorageError::DatabaseError(format!("Failed to get token_type: {}", e)))?;
        let token_type = Self::string_to_token_type(&token_type_str)?;

        let session_iteration: Option<i32> = row.try_get("session_iteration").map_err(|e| {
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
impl AccessTokenStore for PostgresAccessTokenStore {
    async fn store_token(&self, token: &AccessToken) -> Result<()> {
        let token_type_str = Self::token_type_to_string(&token.token_type);

        sqlx::query(
            r#"
            INSERT INTO access_tokens (
                token, token_type, client_id, user_id, session_id, session_iteration,
                scope, nonce, created_at, expires_at, dpop_jkt
            ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)
            "#,
        )
        .bind(&token.token)
        .bind(token_type_str)
        .bind(&token.client_id)
        .bind(&token.user_id)
        .bind(&token.session_id)
        .bind(token.session_iteration.map(|i| i as i32))
        .bind(&token.scope)
        .bind(&token.nonce)
        .bind(token.created_at)
        .bind(token.expires_at)
        .bind(&token.dpop_jkt)
        .execute(&self.pool)
        .await
        .map_err(|e| StorageError::DatabaseError(e.to_string()))?;

        Ok(())
    }

    async fn get_token(&self, token: &str) -> Result<Option<AccessToken>> {
        let row = sqlx::query("SELECT * FROM access_tokens WHERE token = $1")
            .bind(token)
            .fetch_optional(&self.pool)
            .await
            .map_err(|e| StorageError::DatabaseError(e.to_string()))?;

        match row {
            Some(row) => {
                let access_token = Self::row_to_access_token(&row)?;

                // Check if the token has expired
                let now = Utc::now();
                if access_token.expires_at <= now {
                    return Ok(None);
                }

                Ok(Some(access_token))
            }
            None => Ok(None),
        }
    }

    async fn revoke_token(&self, token: &str) -> Result<()> {
        let result = sqlx::query("DELETE FROM access_tokens WHERE token = $1")
            .bind(token)
            .execute(&self.pool)
            .await
            .map_err(|e| StorageError::DatabaseError(e.to_string()))?;

        if result.rows_affected() == 0 {
            return Err(StorageError::NotFound(format!(
                "Token not found: {}",
                token
            )));
        }

        Ok(())
    }

    async fn cleanup_expired_tokens(&self) -> Result<usize> {
        let now = Utc::now();

        let result = sqlx::query("DELETE FROM access_tokens WHERE expires_at <= $1")
            .bind(now)
            .execute(&self.pool)
            .await
            .map_err(|e| StorageError::DatabaseError(e.to_string()))?;

        Ok(result.rows_affected() as usize)
    }

    async fn get_user_tokens(&self, user_id: &str) -> Result<Vec<AccessToken>> {
        let rows =
            sqlx::query("SELECT * FROM access_tokens WHERE user_id = $1 ORDER BY created_at DESC")
                .bind(user_id)
                .fetch_all(&self.pool)
                .await
                .map_err(|e| StorageError::DatabaseError(e.to_string()))?;

        let mut tokens = Vec::new();
        let now = Utc::now();

        for row in rows {
            let token = Self::row_to_access_token(&row)?;
            // Only include non-expired tokens
            if token.expires_at > now {
                tokens.push(token);
            }
        }

        Ok(tokens)
    }

    async fn get_client_tokens(&self, client_id: &str) -> Result<Vec<AccessToken>> {
        let rows = sqlx::query(
            "SELECT * FROM access_tokens WHERE client_id = $1 ORDER BY created_at DESC",
        )
        .bind(client_id)
        .fetch_all(&self.pool)
        .await
        .map_err(|e| StorageError::DatabaseError(e.to_string()))?;

        let mut tokens = Vec::new();
        let now = Utc::now();

        for row in rows {
            let token = Self::row_to_access_token(&row)?;
            // Only include non-expired tokens
            if token.expires_at > now {
                tokens.push(token);
            }
        }

        Ok(tokens)
    }
}
