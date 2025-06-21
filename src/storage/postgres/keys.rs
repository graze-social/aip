//! PostgreSQL implementation for cryptographic key storage

use crate::errors::StorageError;
use crate::storage::traits::{KeyStore, Result};
use async_trait::async_trait;
use atproto_identity::key::KeyData;
use chrono::Utc;
use sqlx::Row;
use sqlx::postgres::{PgPool, PgRow};

/// PostgreSQL implementation of key storage
pub struct PostgresKeyStore {
    pool: PgPool,
}

impl PostgresKeyStore {
    /// Create a new PostgreSQL key store
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }

    /// Convert PostgreSQL row to KeyData
    fn row_to_key_data(row: &PgRow) -> Result<KeyData> {
        let key_data_str: String = row
            .try_get("key_data")
            .map_err(|e| StorageError::DatabaseError(format!("Failed to get key_data: {}", e)))?;

        // Parse the KeyData from its string representation
        atproto_identity::key::identify_key(&key_data_str)
            .map_err(|e| StorageError::InvalidData(format!("Failed to parse key data: {}", e)))
    }

    /// Generate a unique key ID if one is not provided
    fn generate_key_id() -> String {
        format!("key_{}", uuid::Uuid::new_v4())
    }
}

#[async_trait]
impl KeyStore for PostgresKeyStore {
    async fn store_signing_key(&self, key: &KeyData) -> Result<()> {
        let key_data_str = key.to_string();
        let key_id = Self::generate_key_id();
        let now = Utc::now();

        // Start a transaction to ensure only one default signing key exists
        let mut tx = self
            .pool
            .begin()
            .await
            .map_err(|e| StorageError::DatabaseError(e.to_string()))?;

        // Remove the default flag from any existing default signing keys
        sqlx::query("UPDATE keys SET is_default_signing = FALSE WHERE is_default_signing = TRUE")
            .execute(&mut *tx)
            .await
            .map_err(|e| StorageError::DatabaseError(e.to_string()))?;

        // Insert the new default signing key
        sqlx::query(
            r#"
            INSERT INTO keys (key_id, key_data, key_type, created_at, is_default_signing)
            VALUES ($1, $2, 'signing', $3, TRUE)
            "#,
        )
        .bind(&key_id)
        .bind(&key_data_str)
        .bind(now)
        .bind(true)
        .execute(&mut *tx)
        .await
        .map_err(|e| StorageError::DatabaseError(e.to_string()))?;

        tx.commit()
            .await
            .map_err(|e| StorageError::DatabaseError(e.to_string()))?;

        Ok(())
    }

    async fn get_signing_key(&self) -> Result<Option<KeyData>> {
        let row = sqlx::query(
            "SELECT * FROM keys WHERE is_default_signing = TRUE ORDER BY created_at DESC LIMIT 1",
        )
        .fetch_optional(&self.pool)
        .await
        .map_err(|e| StorageError::DatabaseError(e.to_string()))?;

        match row {
            Some(row) => {
                let key_data = Self::row_to_key_data(&row)?;
                Ok(Some(key_data))
            }
            None => Ok(None),
        }
    }

    async fn store_key(&self, key_id: &str, key: &KeyData) -> Result<()> {
        let key_data_str = key.to_string();
        let now = Utc::now();

        sqlx::query(
            r#"
            INSERT INTO keys (key_id, key_data, key_type, created_at, is_default_signing)
            VALUES ($1, $2, 'signing', $3, FALSE)
            ON CONFLICT (key_id) DO UPDATE SET
                key_data = EXCLUDED.key_data,
                created_at = EXCLUDED.created_at
            "#,
        )
        .bind(key_id)
        .bind(&key_data_str)
        .bind(now)
        .bind(false)
        .execute(&self.pool)
        .await
        .map_err(|e| StorageError::DatabaseError(e.to_string()))?;

        Ok(())
    }

    async fn get_key(&self, key_id: &str) -> Result<Option<KeyData>> {
        let row = sqlx::query("SELECT * FROM keys WHERE key_id = $1")
            .bind(key_id)
            .fetch_optional(&self.pool)
            .await
            .map_err(|e| StorageError::DatabaseError(e.to_string()))?;

        match row {
            Some(row) => {
                let key_data = Self::row_to_key_data(&row)?;
                Ok(Some(key_data))
            }
            None => Ok(None),
        }
    }

    async fn list_key_ids(&self) -> Result<Vec<String>> {
        let rows = sqlx::query("SELECT key_id FROM keys ORDER BY created_at DESC")
            .fetch_all(&self.pool)
            .await
            .map_err(|e| StorageError::DatabaseError(e.to_string()))?;

        let mut key_ids = Vec::new();
        for row in rows {
            let key_id: String = row
                .try_get("key_id")
                .map_err(|e| StorageError::DatabaseError(format!("Failed to get key_id: {}", e)))?;
            key_ids.push(key_id);
        }

        Ok(key_ids)
    }
}
