//! PostgreSQL implementation for PAR (Pushed Authorization Request) storage

use crate::errors::StorageError;
use crate::oauth::types::AuthorizationRequest;
use crate::storage::traits::{PARStorage, Result, StoredPushedRequest};
use async_trait::async_trait;
use chrono::Utc;
use sqlx::Row;
use sqlx::postgres::{PgPool, PgRow};

/// PostgreSQL implementation of PAR storage
pub struct PostgresPARStorage {
    pool: PgPool,
}

impl PostgresPARStorage {
    /// Create a new PostgreSQL PAR storage
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }

    /// Convert PostgreSQL row to StoredPushedRequest
    fn row_to_stored_pushed_request(row: &PgRow) -> Result<StoredPushedRequest> {
        let created_at: chrono::DateTime<chrono::Utc> = row
            .try_get("created_at")
            .map_err(|e| StorageError::DatabaseError(format!("Failed to get created_at: {}", e)))?;

        let expires_at: chrono::DateTime<chrono::Utc> = row
            .try_get("expires_at")
            .map_err(|e| StorageError::DatabaseError(format!("Failed to get expires_at: {}", e)))?;

        let authorization_request_json: serde_json::Value =
            row.try_get("authorization_request").map_err(|e| {
                StorageError::DatabaseError(format!("Failed to get authorization_request: {}", e))
            })?;
        let authorization_request: AuthorizationRequest =
            serde_json::from_value(authorization_request_json)
                .map_err(|e| StorageError::SerializationError(e.to_string()))?;

        Ok(StoredPushedRequest {
            request_uri: row.try_get("request_uri").map_err(|e| {
                StorageError::DatabaseError(format!("Failed to get request_uri: {}", e))
            })?,
            authorization_request,
            client_id: row.try_get("client_id").map_err(|e| {
                StorageError::DatabaseError(format!("Failed to get client_id: {}", e))
            })?,
            created_at,
            expires_at,
            subject: row.try_get("subject").map_err(|e| {
                StorageError::DatabaseError(format!("Failed to get subject: {}", e))
            })?,
        })
    }
}

#[async_trait]
impl PARStorage for PostgresPARStorage {
    async fn store_par_request(&self, request: &StoredPushedRequest) -> Result<()> {
        let authorization_request_json = serde_json::to_value(&request.authorization_request)
            .map_err(|e| StorageError::SerializationError(e.to_string()))?;

        sqlx::query(
            r#"
            INSERT INTO par_requests (
                request_uri, authorization_request, client_id, created_at, expires_at, subject
            ) VALUES ($1, $2, $3, $4, $5, $6)
            "#,
        )
        .bind(&request.request_uri)
        .bind(&authorization_request_json)
        .bind(&request.client_id)
        .bind(request.created_at)
        .bind(request.expires_at)
        .bind(&request.subject)
        .execute(&self.pool)
        .await
        .map_err(|e| StorageError::DatabaseError(e.to_string()))?;

        Ok(())
    }

    async fn get_par_request(&self, request_uri: &str) -> Result<Option<StoredPushedRequest>> {
        let row = sqlx::query("SELECT * FROM par_requests WHERE request_uri = $1")
            .bind(request_uri)
            .fetch_optional(&self.pool)
            .await
            .map_err(|e| StorageError::DatabaseError(e.to_string()))?;

        match row {
            Some(row) => {
                let par_request = Self::row_to_stored_pushed_request(&row)?;

                // Check if the request has expired
                let now = Utc::now();
                if par_request.expires_at <= now {
                    // Clean up expired request and return None
                    sqlx::query("DELETE FROM par_requests WHERE request_uri = $1")
                        .bind(request_uri)
                        .execute(&self.pool)
                        .await
                        .map_err(|e| StorageError::DatabaseError(e.to_string()))?;
                    return Ok(None);
                }

                Ok(Some(par_request))
            }
            None => Ok(None),
        }
    }

    async fn consume_par_request(&self, request_uri: &str) -> Result<Option<StoredPushedRequest>> {
        // Start a transaction to ensure atomicity
        let mut tx = self
            .pool
            .begin()
            .await
            .map_err(|e| StorageError::DatabaseError(e.to_string()))?;

        // First, get the request if it exists
        let row = sqlx::query("SELECT * FROM par_requests WHERE request_uri = $1")
            .bind(request_uri)
            .fetch_optional(&mut *tx)
            .await
            .map_err(|e| StorageError::DatabaseError(e.to_string()))?;

        match row {
            Some(row) => {
                let par_request = Self::row_to_stored_pushed_request(&row)?;

                // Check if the request has expired
                let now = Utc::now();
                if par_request.expires_at <= now {
                    // Clean up expired request and return None
                    sqlx::query("DELETE FROM par_requests WHERE request_uri = $1")
                        .bind(request_uri)
                        .execute(&mut *tx)
                        .await
                        .map_err(|e| StorageError::DatabaseError(e.to_string()))?;

                    tx.commit()
                        .await
                        .map_err(|e| StorageError::DatabaseError(e.to_string()))?;
                    return Ok(None);
                }

                // Delete the request (one-time use)
                sqlx::query("DELETE FROM par_requests WHERE request_uri = $1")
                    .bind(request_uri)
                    .execute(&mut *tx)
                    .await
                    .map_err(|e| StorageError::DatabaseError(e.to_string()))?;

                tx.commit()
                    .await
                    .map_err(|e| StorageError::DatabaseError(e.to_string()))?;

                Ok(Some(par_request))
            }
            None => Ok(None),
        }
    }

    async fn cleanup_expired_par_requests(&self) -> Result<usize> {
        let now = Utc::now();

        let result = sqlx::query("DELETE FROM par_requests WHERE expires_at <= $1")
            .bind(now)
            .execute(&self.pool)
            .await
            .map_err(|e| StorageError::DatabaseError(e.to_string()))?;

        Ok(result.rows_affected() as usize)
    }
}
