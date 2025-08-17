//! SQLite implementation of DeviceCodeStore

use crate::errors::StorageError;
use crate::storage::traits::{DeviceCodeEntry, DeviceCodeStore, Result};
use async_trait::async_trait;
use chrono::{DateTime, Utc};
use sqlx::sqlite::SqlitePool;

/// SQLite implementation of device code storage
pub struct SqliteDeviceCodeStore {
    pool: SqlitePool,
}

impl SqliteDeviceCodeStore {
    pub fn new(pool: SqlitePool) -> Self {
        Self { pool }
    }
}

#[async_trait]
impl DeviceCodeStore for SqliteDeviceCodeStore {
    async fn store_device_code(
        &self,
        device_code: &str,
        user_code: &str,
        client_id: &str,
        scope: Option<&str>,
        expires_in: u64,
    ) -> Result<()> {
        let now = Utc::now();
        let expires_at = now + chrono::Duration::seconds(expires_in as i64);
        let expires_at_timestamp = expires_at.timestamp();
        let now_timestamp = now.timestamp();

        sqlx::query!(
            r#"
            INSERT INTO device_codes (device_code, user_code, client_id, scope, expires_at, created_at)
            VALUES (?, ?, ?, ?, ?, ?)
            "#,
            device_code,
            user_code,
            client_id,
            scope,
            expires_at_timestamp,
            now_timestamp
        )
        .execute(&self.pool)
        .await
        .map_err(|e| StorageError::DatabaseError(format!("Failed to store device code: {}", e)))?;

        Ok(())
    }

    async fn get_device_code(&self, device_code: &str) -> Result<Option<DeviceCodeEntry>> {
        let row = sqlx::query!(
            r#"
            SELECT device_code, user_code, client_id, scope, authorized_user, expires_at, created_at
            FROM device_codes 
            WHERE device_code = ?
            "#,
            device_code
        )
        .fetch_optional(&self.pool)
        .await
        .map_err(|e| StorageError::DatabaseError(format!("Failed to get device code: {}", e)))?;

        if let Some(row) = row {
            Ok(Some(DeviceCodeEntry {
                device_code: row.device_code.unwrap_or_default(),
                user_code: row.user_code,
                client_id: row.client_id,
                scope: row.scope,
                authorized_user: row.authorized_user,
                expires_at: DateTime::from_timestamp(row.expires_at, 0)
                    .unwrap_or_else(|| Utc::now()),
                created_at: DateTime::from_timestamp(row.created_at, 0)
                    .unwrap_or_else(|| Utc::now()),
            }))
        } else {
            Ok(None)
        }
    }

    async fn get_device_code_by_user_code(&self, user_code: &str) -> Result<Option<DeviceCodeEntry>> {
        let row = sqlx::query!(
            r#"
            SELECT device_code, user_code, client_id, scope, authorized_user, expires_at, created_at
            FROM device_codes 
            WHERE user_code = ?
            "#,
            user_code
        )
        .fetch_optional(&self.pool)
        .await
        .map_err(|e| StorageError::DatabaseError(format!("Failed to get device code by user code: {}", e)))?;

        if let Some(row) = row {
            Ok(Some(DeviceCodeEntry {
                device_code: row.device_code.unwrap_or_default(),
                user_code: row.user_code,
                client_id: row.client_id,
                scope: row.scope,
                authorized_user: row.authorized_user,
                expires_at: DateTime::from_timestamp(row.expires_at, 0)
                    .unwrap_or_else(|| Utc::now()),
                created_at: DateTime::from_timestamp(row.created_at, 0)
                    .unwrap_or_else(|| Utc::now()),
            }))
        } else {
            Ok(None)
        }
    }

    async fn authorize_device_code(&self, user_code: &str, user_id: &str) -> Result<()> {
        let now_timestamp = Utc::now().timestamp();
        let rows_affected = sqlx::query!(
            r#"
            UPDATE device_codes 
            SET authorized_user = ?
            WHERE user_code = ? AND expires_at > ?
            "#,
            user_id,
            user_code,
            now_timestamp
        )
        .execute(&self.pool)
        .await
        .map_err(|e| StorageError::DatabaseError(format!("Failed to authorize device code: {}", e)))?
        .rows_affected();

        if rows_affected == 0 {
            return Err(StorageError::NotFound("Device code not found or expired".to_string()));
        }

        Ok(())
    }

    async fn consume_device_code(&self, device_code: &str) -> Result<Option<String>> {
        let mut transaction = self.pool.begin().await
            .map_err(|e| StorageError::DatabaseError(format!("Failed to start transaction: {}", e)))?;

        // Get the device code entry
        let row = sqlx::query!(
            r#"
            SELECT authorized_user, expires_at
            FROM device_codes 
            WHERE device_code = ?
            "#,
            device_code
        )
        .fetch_optional(&mut *transaction)
        .await
        .map_err(|e| StorageError::DatabaseError(format!("Failed to get device code: {}", e)))?;

        if let Some(row) = row {
            // Check if expired
            let expires_at = DateTime::from_timestamp(row.expires_at, 0)
                .unwrap_or_else(|| Utc::now());
            if expires_at <= Utc::now() {
                // Clean up expired code
                sqlx::query!("DELETE FROM device_codes WHERE device_code = ?", device_code)
                    .execute(&mut *transaction)
                    .await
                    .map_err(|e| StorageError::DatabaseError(format!("Failed to delete expired device code: {}", e)))?;
                
                transaction.commit().await
                    .map_err(|e| StorageError::DatabaseError(format!("Failed to commit transaction: {}", e)))?;
                return Ok(None);
            }

            // Delete the device code (consume it)
            sqlx::query!("DELETE FROM device_codes WHERE device_code = ?", device_code)
                .execute(&mut *transaction)
                .await
                .map_err(|e| StorageError::DatabaseError(format!("Failed to delete device code: {}", e)))?;

            transaction.commit().await
                .map_err(|e| StorageError::DatabaseError(format!("Failed to commit transaction: {}", e)))?;

            Ok(row.authorized_user)
        } else {
            transaction.rollback().await
                .map_err(|e| StorageError::DatabaseError(format!("Failed to rollback transaction: {}", e)))?;
            Ok(None)
        }
    }

    async fn cleanup_expired_device_codes(&self) -> Result<usize> {
        let now_timestamp = Utc::now().timestamp();
        let result = sqlx::query!(
            "DELETE FROM device_codes WHERE expires_at <= ?",
            now_timestamp
        )
        .execute(&self.pool)
        .await
        .map_err(|e| StorageError::DatabaseError(format!("Failed to cleanup expired device codes: {}", e)))?;

        Ok(result.rows_affected() as usize)
    }
}