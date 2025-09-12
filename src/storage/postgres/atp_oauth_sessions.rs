//! PostgreSQL implementation for ATProtocol OAuth session storage

use crate::errors::StorageError;
use crate::storage::traits::{AtpOAuthSession, AtpOAuthSessionStorage, Result};
use async_trait::async_trait;
use chrono::{DateTime, Utc};
use sqlx::Row;
use sqlx::postgres::{PgPool, PgRow};

/// PostgreSQL implementation of ATProtocol OAuth session storage
pub struct PostgresAtpOAuthSessionStorage {
    pool: PgPool,
}

impl PostgresAtpOAuthSessionStorage {
    /// Create a new PostgreSQL ATP OAuth session storage
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }

    /// Convert PostgreSQL row to AtpOAuthSession
    fn row_to_atp_oauth_session(row: &PgRow) -> Result<AtpOAuthSession> {
        let session_created_at: chrono::DateTime<chrono::Utc> =
            row.try_get("session_created_at").map_err(|e| {
                StorageError::DatabaseError(format!("Failed to get session_created_at: {}", e))
            })?;

        let access_token_created_at: Option<chrono::DateTime<chrono::Utc>> =
            row.try_get("access_token_created_at").map_err(|e| {
                StorageError::DatabaseError(format!("Failed to get access_token_created_at: {}", e))
            })?;

        let access_token_expires_at: Option<chrono::DateTime<chrono::Utc>> =
            row.try_get("access_token_expires_at").map_err(|e| {
                StorageError::DatabaseError(format!("Failed to get access_token_expires_at: {}", e))
            })?;

        let access_token_scopes: Option<serde_json::Value> =
            row.try_get("access_token_scopes").map_err(|e| {
                StorageError::DatabaseError(format!("Failed to get access_token_scopes: {}", e))
            })?;

        let access_token_scopes = if let Some(scopes_json) = access_token_scopes {
            Some(
                serde_json::from_value(scopes_json)
                    .map_err(|e| StorageError::SerializationError(e.to_string()))?,
            )
        } else {
            None
        };

        let iteration: i32 = row
            .try_get("iteration")
            .map_err(|e| StorageError::DatabaseError(format!("Failed to get iteration: {}", e)))?;

        // Extract additional fields from metadata if available
        let metadata: Option<serde_json::Value> = row.try_get("metadata").ok();
        let session_exchanged_at = metadata
            .as_ref()
            .and_then(|m| m.get("session_exchanged_at"))
            .and_then(|v| v.as_str())
            .and_then(|s| chrono::DateTime::parse_from_rfc3339(s).ok())
            .map(|dt| dt.with_timezone(&Utc));

        let exchange_error = metadata
            .as_ref()
            .and_then(|m| m.get("exchange_error"))
            .and_then(|v| v.as_str())
            .map(|s| s.to_string());

        Ok(AtpOAuthSession {
            session_id: row.try_get("session_id").map_err(|e| {
                StorageError::DatabaseError(format!("Failed to get session_id: {}", e))
            })?,
            did: row.try_get("did").ok(),
            session_created_at,
            atp_oauth_state: row.try_get("atp_oauth_state").map_err(|e| {
                StorageError::DatabaseError(format!("Failed to get atp_oauth_state: {}", e))
            })?,
            signing_key_jkt: row.try_get("signing_key_jkt").map_err(|e| {
                StorageError::DatabaseError(format!("Failed to get signing_key_jkt: {}", e))
            })?,
            dpop_key: row.try_get("dpop_key").map_err(|e| {
                StorageError::DatabaseError(format!("Failed to get dpop_key: {}", e))
            })?,
            access_token: row.try_get("access_token").map_err(|e| {
                StorageError::DatabaseError(format!("Failed to get access_token: {}", e))
            })?,
            refresh_token: row.try_get("refresh_token").map_err(|e| {
                StorageError::DatabaseError(format!("Failed to get refresh_token: {}", e))
            })?,
            access_token_created_at,
            access_token_expires_at,
            access_token_scopes,
            session_exchanged_at,
            exchange_error,
            iteration: iteration as u32,
        })
    }
}

#[async_trait]
impl AtpOAuthSessionStorage for PostgresAtpOAuthSessionStorage {
    async fn store_session(&self, session: &AtpOAuthSession) -> Result<()> {
        let access_token_scopes_json = session
            .access_token_scopes
            .as_ref()
            .map(serde_json::to_value)
            .transpose()
            .map_err(|e| StorageError::SerializationError(e.to_string()))?;

        let metadata = serde_json::json!({
            "session_exchanged_at": session.session_exchanged_at,
            "exchange_error": session.exchange_error
        });

        sqlx::query(
            r#"
            INSERT INTO atp_oauth_sessions (
                session_id, did, iteration, session_created_at, atp_oauth_state,
                signing_key_jkt, dpop_key, access_token, refresh_token,
                access_token_created_at, access_token_expires_at, access_token_scopes,
                metadata
            ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13)
            ON CONFLICT (session_id, iteration)
            DO UPDATE SET
                did = EXCLUDED.did,
                session_created_at = EXCLUDED.session_created_at,
                atp_oauth_state = EXCLUDED.atp_oauth_state,
                signing_key_jkt = EXCLUDED.signing_key_jkt,
                dpop_key = EXCLUDED.dpop_key,
                access_token = EXCLUDED.access_token,
                refresh_token = EXCLUDED.refresh_token,
                access_token_created_at = EXCLUDED.access_token_created_at,
                access_token_expires_at = EXCLUDED.access_token_expires_at,
                access_token_scopes = EXCLUDED.access_token_scopes,
                metadata = EXCLUDED.metadata
            "#,
        )
        .bind(&session.session_id)
        .bind(&session.did)
        .bind(session.iteration as i32)
        .bind(session.session_created_at)
        .bind(&session.atp_oauth_state)
        .bind(&session.signing_key_jkt)
        .bind(&session.dpop_key)
        .bind(&session.access_token)
        .bind(&session.refresh_token)
        .bind(session.access_token_created_at)
        .bind(session.access_token_expires_at)
        .bind(&access_token_scopes_json)
        .bind(&metadata)
        .execute(&self.pool)
        .await
        .map_err(|e| StorageError::DatabaseError(e.to_string()))?;

        Ok(())
    }

    async fn get_sessions(&self, did: &str, session_id: &str) -> Result<Vec<AtpOAuthSession>> {
        let rows = sqlx::query(
            "SELECT * FROM atp_oauth_sessions WHERE did = $1 AND session_id = $2 ORDER BY iteration DESC",
        )
        .bind(did)
        .bind(session_id)
        .fetch_all(&self.pool)
        .await
        .map_err(|e| StorageError::DatabaseError(e.to_string()))?;

        let mut sessions = Vec::new();
        for row in rows {
            let session = Self::row_to_atp_oauth_session(&row)?;
            sessions.push(session);
        }

        Ok(sessions)
    }

    async fn get_session(
        &self,
        did: &str,
        session_id: &str,
        iteration: u32,
    ) -> Result<Option<AtpOAuthSession>> {
        let row = sqlx::query(
            "SELECT * FROM atp_oauth_sessions WHERE did = $1 AND session_id = $2 AND iteration = $3",
        )
        .bind(did)
        .bind(session_id)
        .bind(iteration as i32)
        .fetch_optional(&self.pool)
        .await
        .map_err(|e| StorageError::DatabaseError(e.to_string()))?;

        match row {
            Some(row) => {
                let session = Self::row_to_atp_oauth_session(&row)?;
                Ok(Some(session))
            }
            None => Ok(None),
        }
    }

    async fn get_latest_session(
        &self,
        did: &str,
        session_id: &str,
    ) -> Result<Option<AtpOAuthSession>> {
        let row = sqlx::query(
            "SELECT * FROM atp_oauth_sessions WHERE did = $1 AND session_id = $2 ORDER BY iteration DESC LIMIT 1",
        )
        .bind(did)
        .bind(session_id)
        .fetch_optional(&self.pool)
        .await
        .map_err(|e| StorageError::DatabaseError(e.to_string()))?;

        match row {
            Some(row) => {
                let session = Self::row_to_atp_oauth_session(&row)?;
                Ok(Some(session))
            }
            None => Ok(None),
        }
    }

    async fn update_session(&self, session: &AtpOAuthSession) -> Result<()> {
        let access_token_scopes_json = session
            .access_token_scopes
            .as_ref()
            .map(serde_json::to_value)
            .transpose()
            .map_err(|e| StorageError::SerializationError(e.to_string()))?;

        let result = sqlx::query(
            r#"
            UPDATE atp_oauth_sessions SET
                did = $1,
                session_created_at = $4, atp_oauth_state = $5, signing_key_jkt = $6,
                dpop_key = $7, access_token = $8, refresh_token = $9,
                access_token_created_at = $10, access_token_expires_at = $11, access_token_scopes = $12
            WHERE session_id = $2 AND iteration = $3
            "#,
        )
        .bind(&session.did)
        .bind(&session.session_id)
        .bind(session.iteration as i32)
        .bind(session.session_created_at)
        .bind(&session.atp_oauth_state)
        .bind(&session.signing_key_jkt)
        .bind(&session.dpop_key)
        .bind(&session.access_token)
        .bind(&session.refresh_token)
        .bind(session.access_token_created_at)
        .bind(session.access_token_expires_at)
        .bind(&access_token_scopes_json)
        .execute(&self.pool)
        .await
        .map_err(|e| StorageError::DatabaseError(e.to_string()))?;

        if result.rows_affected() == 0 {
            return Err(StorageError::NotFound(format!(
                "Session not found: did={:?}, session_id={}, iteration={}",
                session.did, session.session_id, session.iteration
            )));
        }

        Ok(())
    }

    async fn get_session_by_atp_state(&self, atp_state: &str) -> Result<Option<AtpOAuthSession>> {
        let row = sqlx::query("SELECT * FROM atp_oauth_sessions WHERE atp_oauth_state = $1")
            .bind(atp_state)
            .fetch_optional(&self.pool)
            .await
            .map_err(|e| StorageError::DatabaseError(e.to_string()))?;

        match row {
            Some(row) => {
                let session = Self::row_to_atp_oauth_session(&row)?;
                Ok(Some(session))
            }
            None => Ok(None),
        }
    }


    async fn get_sessions_by_did(&self, did: &str) -> Result<Vec<AtpOAuthSession>> {
        let rows = sqlx::query("SELECT * FROM atp_oauth_sessions WHERE did = $1 ORDER BY session_created_at DESC")
            .bind(did)
            .fetch_all(&self.pool)
            .await
            .map_err(|e| StorageError::DatabaseError(e.to_string()))?;

        let mut sessions = Vec::new();
        for row in rows {
            let session = Self::row_to_atp_oauth_session(&row)?;
            sessions.push(session);
        }

        Ok(sessions)
    }

    async fn update_session_tokens(
        &self,
        did: &str,
        session_id: &str,
        iteration: u32,
        access_token: Option<String>,
        refresh_token: Option<String>,
        access_token_created_at: Option<DateTime<Utc>>,
        access_token_expires_at: Option<DateTime<Utc>>,
        access_token_scopes: Option<Vec<String>>,
    ) -> Result<()> {
        let access_token_scopes_json = access_token_scopes
            .as_ref()
            .map(serde_json::to_value)
            .transpose()
            .map_err(|e| StorageError::SerializationError(e.to_string()))?;

        let result = sqlx::query(
            r#"
            UPDATE atp_oauth_sessions SET
                access_token = $4, refresh_token = $5,
                access_token_created_at = $6, access_token_expires_at = $7, access_token_scopes = $8
            WHERE did = $1 AND session_id = $2 AND iteration = $3
            "#,
        )
        .bind(did)
        .bind(session_id)
        .bind(iteration as i32)
        .bind(&access_token)
        .bind(&refresh_token)
        .bind(access_token_created_at)
        .bind(access_token_expires_at)
        .bind(&access_token_scopes_json)
        .execute(&self.pool)
        .await
        .map_err(|e| StorageError::DatabaseError(e.to_string()))?;

        if result.rows_affected() == 0 {
            return Err(StorageError::NotFound(format!(
                "Session not found: did={}, session_id={}, iteration={}",
                did, session_id, iteration
            )));
        }

        Ok(())
    }

    async fn remove_session(&self, did: &str, session_id: &str, iteration: u32) -> Result<()> {
        sqlx::query(
            "DELETE FROM atp_oauth_sessions WHERE did = $1 AND session_id = $2 AND iteration = $3",
        )
        .bind(did)
        .bind(session_id)
        .bind(iteration as i32)
        .execute(&self.pool)
        .await
        .map_err(|e| StorageError::DatabaseError(e.to_string()))?;

        Ok(())
    }

    async fn cleanup_old_sessions(&self, older_than: DateTime<Utc>) -> Result<usize> {
        let result = sqlx::query("DELETE FROM atp_oauth_sessions WHERE session_created_at < $1")
            .bind(older_than)
            .execute(&self.pool)
            .await
            .map_err(|e| StorageError::DatabaseError(e.to_string()))?;

        Ok(result.rows_affected() as usize)
    }
}
