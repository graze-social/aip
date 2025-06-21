//! PostgreSQL implementation for authorization request storage

use crate::errors::StorageError;
use crate::oauth::types::AuthorizationRequest;
use crate::storage::traits::{AuthorizationRequestStorage, Result};
use async_trait::async_trait;
use chrono::Utc;
use sqlx::Row;
use sqlx::postgres::{PgPool, PgRow};

/// PostgreSQL implementation of authorization request storage
pub struct PostgresAuthorizationRequestStorage {
    pool: PgPool,
}

impl PostgresAuthorizationRequestStorage {
    /// Create a new PostgreSQL authorization request storage
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }

    /// Convert PostgreSQL row to AuthorizationRequest
    fn row_to_authorization_request(row: &PgRow) -> Result<AuthorizationRequest> {
        let request_data_json: serde_json::Value = row.try_get("request_data").map_err(|e| {
            StorageError::DatabaseError(format!("Failed to get request_data: {}", e))
        })?;

        let authorization_request: AuthorizationRequest = serde_json::from_value(request_data_json)
            .map_err(|e| StorageError::SerializationError(e.to_string()))?;

        Ok(authorization_request)
    }
}

#[async_trait]
impl AuthorizationRequestStorage for PostgresAuthorizationRequestStorage {
    async fn store_authorization_request(
        &self,
        session_id: &str,
        request: &AuthorizationRequest,
    ) -> Result<()> {
        let request_data_json = serde_json::to_value(request)
            .map_err(|e| StorageError::SerializationError(e.to_string()))?;
        let created_at = Utc::now();

        sqlx::query(
            r#"
            INSERT INTO authorization_requests (session_id, request_data, created_at)
            VALUES ($1, $2, $3)
            ON CONFLICT (session_id) DO UPDATE SET
                request_data = EXCLUDED.request_data,
                created_at = EXCLUDED.created_at
            "#,
        )
        .bind(session_id)
        .bind(&request_data_json)
        .bind(created_at)
        .execute(&self.pool)
        .await
        .map_err(|e| StorageError::DatabaseError(e.to_string()))?;

        Ok(())
    }

    async fn get_authorization_request(
        &self,
        session_id: &str,
    ) -> Result<Option<AuthorizationRequest>> {
        let row = sqlx::query("SELECT * FROM authorization_requests WHERE session_id = $1")
            .bind(session_id)
            .fetch_optional(&self.pool)
            .await
            .map_err(|e| StorageError::DatabaseError(e.to_string()))?;

        match row {
            Some(row) => {
                let authorization_request = Self::row_to_authorization_request(&row)?;
                Ok(Some(authorization_request))
            }
            None => Ok(None),
        }
    }

    async fn remove_authorization_request(&self, session_id: &str) -> Result<()> {
        let result = sqlx::query("DELETE FROM authorization_requests WHERE session_id = $1")
            .bind(session_id)
            .execute(&self.pool)
            .await
            .map_err(|e| StorageError::DatabaseError(e.to_string()))?;

        if result.rows_affected() == 0 {
            return Err(StorageError::NotFound(format!(
                "Authorization request not found for session: {}",
                session_id
            )));
        }

        Ok(())
    }
}
