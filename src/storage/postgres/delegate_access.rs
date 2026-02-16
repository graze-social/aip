//! PostgreSQL implementation for delegate access storage

use crate::errors::StorageError;
use crate::storage::traits::{DelegateAccessStore, DelegateGrant};
use async_trait::async_trait;
use chrono::Utc;
use sqlx::Row;
use sqlx::postgres::{PgPool, PgRow};

pub type Result<T> = std::result::Result<T, StorageError>;

/// PostgreSQL implementation for delegate access storage
pub struct PostgresDelegateAccessStore {
    pool: PgPool,
}

impl PostgresDelegateAccessStore {
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }

    /// Convert PostgreSQL row to DelegateGrant
    fn row_to_delegate_grant(row: &PgRow) -> Result<DelegateGrant> {
        Ok(DelegateGrant {
            owner_did: row.try_get("owner_did").map_err(|e| {
                StorageError::DatabaseError(format!("Failed to get owner_did: {}", e))
            })?,
            delegate_did: row.try_get("delegate_did").map_err(|e| {
                StorageError::DatabaseError(format!("Failed to get delegate_did: {}", e))
            })?,
            granted_at: row.try_get("granted_at").map_err(|e| {
                StorageError::DatabaseError(format!("Failed to get granted_at: {}", e))
            })?,
        })
    }
}

#[async_trait]
impl DelegateAccessStore for PostgresDelegateAccessStore {
    async fn grant_delegate(&self, owner_did: &str, delegate_did: &str) -> Result<()> {
        let now = Utc::now();
        sqlx::query(
            r#"
            INSERT INTO delegate_access (owner_did, delegate_did, granted_at)
            VALUES ($1, $2, $3)
            ON CONFLICT (owner_did, delegate_did) DO NOTHING
            "#,
        )
        .bind(owner_did)
        .bind(delegate_did)
        .bind(now)
        .execute(&self.pool)
        .await
        .map_err(|e| StorageError::DatabaseError(format!("Failed to grant delegate: {}", e)))?;

        Ok(())
    }

    async fn revoke_delegate(&self, owner_did: &str, delegate_did: &str) -> Result<()> {
        sqlx::query(
            r#"
            DELETE FROM delegate_access
            WHERE owner_did = $1 AND delegate_did = $2
            "#,
        )
        .bind(owner_did)
        .bind(delegate_did)
        .execute(&self.pool)
        .await
        .map_err(|e| StorageError::DatabaseError(format!("Failed to revoke delegate: {}", e)))?;

        Ok(())
    }

    async fn is_delegate(&self, owner_did: &str, delegate_did: &str) -> Result<bool> {
        let row = sqlx::query(
            r#"
            SELECT 1 FROM delegate_access
            WHERE owner_did = $1 AND delegate_did = $2
            "#,
        )
        .bind(owner_did)
        .bind(delegate_did)
        .fetch_optional(&self.pool)
        .await
        .map_err(|e| {
            StorageError::DatabaseError(format!("Failed to check delegate: {}", e))
        })?;

        Ok(row.is_some())
    }

    async fn list_delegates(&self, owner_did: &str) -> Result<Vec<DelegateGrant>> {
        let rows = sqlx::query(
            r#"
            SELECT owner_did, delegate_did, granted_at
            FROM delegate_access
            WHERE owner_did = $1
            ORDER BY granted_at DESC
            "#,
        )
        .bind(owner_did)
        .fetch_all(&self.pool)
        .await
        .map_err(|e| {
            StorageError::DatabaseError(format!("Failed to list delegates: {}", e))
        })?;

        let mut grants = Vec::new();
        for row in rows {
            grants.push(Self::row_to_delegate_grant(&row)?);
        }

        Ok(grants)
    }

    async fn list_owners(&self, delegate_did: &str) -> Result<Vec<DelegateGrant>> {
        let rows = sqlx::query(
            r#"
            SELECT owner_did, delegate_did, granted_at
            FROM delegate_access
            WHERE delegate_did = $1
            ORDER BY granted_at DESC
            "#,
        )
        .bind(delegate_did)
        .fetch_all(&self.pool)
        .await
        .map_err(|e| {
            StorageError::DatabaseError(format!("Failed to list owners: {}", e))
        })?;

        let mut grants = Vec::new();
        for row in rows {
            grants.push(Self::row_to_delegate_grant(&row)?);
        }

        Ok(grants)
    }
}
