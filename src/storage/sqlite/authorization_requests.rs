//! SQLite implementation for authorization request storage

use crate::errors::StorageError;
use crate::oauth::types::AuthorizationRequest;
use crate::storage::traits::{AuthorizationRequestStorage, Result};
use async_trait::async_trait;
use chrono::Utc;
use sqlx::Row;
use sqlx::sqlite::{SqlitePool, SqliteRow};

/// SQLite implementation of authorization request storage
pub struct SqliteAuthorizationRequestStorage {
    pool: SqlitePool,
}

impl SqliteAuthorizationRequestStorage {
    /// Create a new SQLite authorization request storage
    pub fn new(pool: SqlitePool) -> Self {
        Self { pool }
    }

    /// Convert SQLite row to AuthorizationRequest
    fn row_to_authorization_request(row: &SqliteRow) -> Result<AuthorizationRequest> {
        let request_data_json: String = row.try_get("request_data").map_err(|e| {
            StorageError::DatabaseError(format!("Failed to get request_data: {}", e))
        })?;

        let authorization_request: AuthorizationRequest = serde_json::from_str(&request_data_json)
            .map_err(|e| StorageError::SerializationError(e.to_string()))?;

        Ok(authorization_request)
    }
}

#[async_trait]
impl AuthorizationRequestStorage for SqliteAuthorizationRequestStorage {
    async fn store_authorization_request(
        &self,
        session_id: &str,
        request: &AuthorizationRequest,
    ) -> Result<()> {
        let request_data_json = serde_json::to_string(request)
            .map_err(|e| StorageError::SerializationError(e.to_string()))?;
        let created_at_str = Utc::now().to_rfc3339();

        sqlx::query(
            r#"
            INSERT OR REPLACE INTO authorization_requests (session_id, request_data, created_at)
            VALUES (?, ?, ?)
            "#,
        )
        .bind(session_id)
        .bind(&request_data_json)
        .bind(&created_at_str)
        .execute(&self.pool)
        .await
        .map_err(|e| StorageError::DatabaseError(e.to_string()))?;

        Ok(())
    }

    async fn get_authorization_request(
        &self,
        session_id: &str,
    ) -> Result<Option<AuthorizationRequest>> {
        let row = sqlx::query("SELECT * FROM authorization_requests WHERE session_id = ?")
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
        let result = sqlx::query("DELETE FROM authorization_requests WHERE session_id = ?")
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
