//! SQLite implementation for ATProtocol OAuth session storage

use crate::errors::StorageError;
use crate::storage::traits::{AtpOAuthSession, AtpOAuthSessionStorage, Result};
use async_trait::async_trait;
use chrono::{DateTime, Utc};
use sqlx::Row;
use sqlx::sqlite::{SqlitePool, SqliteRow};

/// SQLite implementation of ATProtocol OAuth session storage
pub struct SqliteAtpOAuthSessionStorage {
    pool: SqlitePool,
}

impl SqliteAtpOAuthSessionStorage {
    /// Create a new SQLite ATP OAuth session storage
    pub fn new(pool: SqlitePool) -> Self {
        Self { pool }
    }

    /// Convert SQLite row to AtpOAuthSession
    fn row_to_atp_oauth_session(row: &SqliteRow) -> Result<AtpOAuthSession> {
        let session_created_at_str: String = row.try_get("session_created_at").map_err(|e| {
            StorageError::DatabaseError(format!("Failed to get session_created_at: {}", e))
        })?;
        let session_created_at = chrono::DateTime::parse_from_rfc3339(&session_created_at_str)
            .map_err(|e| {
                StorageError::InvalidData(format!("Invalid session_created_at timestamp: {}", e))
            })?
            .with_timezone(&Utc);

        let access_token_created_at = if let Ok(Some(created_at_str)) =
            row.try_get::<Option<String>, _>("access_token_created_at")
        {
            Some(
                chrono::DateTime::parse_from_rfc3339(&created_at_str)
                    .map_err(|e| {
                        StorageError::InvalidData(format!(
                            "Invalid access_token_created_at timestamp: {}",
                            e
                        ))
                    })?
                    .with_timezone(&Utc),
            )
        } else {
            None
        };

        let access_token_expires_at = if let Ok(Some(expires_at_str)) =
            row.try_get::<Option<String>, _>("access_token_expires_at")
        {
            Some(
                chrono::DateTime::parse_from_rfc3339(&expires_at_str)
                    .map_err(|e| {
                        StorageError::InvalidData(format!(
                            "Invalid access_token_expires_at timestamp: {}",
                            e
                        ))
                    })?
                    .with_timezone(&Utc),
            )
        } else {
            None
        };

        let access_token_scopes = if let Ok(Some(scopes_json)) =
            row.try_get::<Option<String>, _>("access_token_scopes")
        {
            Some(
                serde_json::from_str(&scopes_json)
                    .map_err(|e| StorageError::SerializationError(e.to_string()))?,
            )
        } else {
            None
        };

        let iteration: i64 = row
            .try_get("iteration")
            .map_err(|e| StorageError::DatabaseError(format!("Failed to get iteration: {}", e)))?;

        // Extract additional fields from metadata if available
        let metadata_str: Option<String> = row.try_get("metadata").ok();
        let metadata: Option<serde_json::Value> = metadata_str
            .as_ref()
            .and_then(|s| serde_json::from_str(s).ok());

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
impl AtpOAuthSessionStorage for SqliteAtpOAuthSessionStorage {
    async fn store_session(&self, session: &AtpOAuthSession) -> Result<()> {
        let session_created_at_str = session.session_created_at.to_rfc3339();
        let access_token_created_at_str = session
            .access_token_created_at
            .as_ref()
            .map(|dt| dt.to_rfc3339());
        let access_token_expires_at_str = session
            .access_token_expires_at
            .as_ref()
            .map(|dt| dt.to_rfc3339());
        let access_token_scopes_json = session
            .access_token_scopes
            .as_ref()
            .map(|scopes| serde_json::to_string(scopes))
            .transpose()
            .map_err(|e| StorageError::SerializationError(e.to_string()))?;

        let metadata = serde_json::json!({
            "session_exchanged_at": session.session_exchanged_at,
            "exchange_error": session.exchange_error
        });
        let metadata_str = serde_json::to_string(&metadata)
            .map_err(|e| StorageError::SerializationError(e.to_string()))?;

        sqlx::query(
            r#"
            INSERT OR REPLACE INTO atp_oauth_sessions (
                session_id, did, iteration, session_created_at, atp_oauth_state,
                signing_key_jkt, dpop_key, access_token, refresh_token,
                access_token_created_at, access_token_expires_at, access_token_scopes,
                metadata
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            "#,
        )
        .bind(&session.session_id)
        .bind(&session.did)
        .bind(session.iteration as i64)
        .bind(&session_created_at_str)
        .bind(&session.atp_oauth_state)
        .bind(&session.signing_key_jkt)
        .bind(&session.dpop_key)
        .bind(&session.access_token)
        .bind(&session.refresh_token)
        .bind(&access_token_created_at_str)
        .bind(&access_token_expires_at_str)
        .bind(&access_token_scopes_json)
        .bind(&metadata_str)
        .execute(&self.pool)
        .await
        .map_err(|e| StorageError::DatabaseError(e.to_string()))?;

        Ok(())
    }

    async fn get_sessions(&self, did: &str, session_id: &str) -> Result<Vec<AtpOAuthSession>> {
        let rows = sqlx::query(
            "SELECT * FROM atp_oauth_sessions WHERE did = ? AND session_id = ? ORDER BY iteration DESC",
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
            "SELECT * FROM atp_oauth_sessions WHERE did = ? AND session_id = ? AND iteration = ?",
        )
        .bind(did)
        .bind(session_id)
        .bind(iteration as i64)
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
            "SELECT * FROM atp_oauth_sessions WHERE did = ? AND session_id = ? ORDER BY iteration DESC LIMIT 1",
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
        let session_created_at_str = session.session_created_at.to_rfc3339();
        let access_token_created_at_str = session
            .access_token_created_at
            .as_ref()
            .map(|dt| dt.to_rfc3339());
        let access_token_expires_at_str = session
            .access_token_expires_at
            .as_ref()
            .map(|dt| dt.to_rfc3339());
        let access_token_scopes_json = session
            .access_token_scopes
            .as_ref()
            .map(|scopes| serde_json::to_string(scopes))
            .transpose()
            .map_err(|e| StorageError::SerializationError(e.to_string()))?;

        let metadata = serde_json::json!({
            "session_exchanged_at": session.session_exchanged_at,
            "exchange_error": session.exchange_error
        });
        let metadata_str = serde_json::to_string(&metadata)
            .map_err(|e| StorageError::SerializationError(e.to_string()))?;

        let result = sqlx::query(
            r#"
            UPDATE atp_oauth_sessions SET
                session_created_at = ?, atp_oauth_state = ?, signing_key_jkt = ?,
                dpop_key = ?, access_token = ?, refresh_token = ?,
                access_token_created_at = ?, access_token_expires_at = ?, access_token_scopes = ?,
                metadata = ?
            WHERE did = ? AND session_id = ? AND iteration = ?
            "#,
        )
        .bind(&session_created_at_str)
        .bind(&session.atp_oauth_state)
        .bind(&session.signing_key_jkt)
        .bind(&session.dpop_key)
        .bind(&session.access_token)
        .bind(&session.refresh_token)
        .bind(&access_token_created_at_str)
        .bind(&access_token_expires_at_str)
        .bind(&access_token_scopes_json)
        .bind(&metadata_str)
        .bind(&session.did)
        .bind(&session.session_id)
        .bind(session.iteration as i64)
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
        let row = sqlx::query("SELECT * FROM atp_oauth_sessions WHERE atp_oauth_state = ?")
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
        let rows = sqlx::query("SELECT * FROM atp_oauth_sessions WHERE did = ? ORDER BY session_created_at DESC")
            .bind(did)
            .fetch_all(&self.pool)
            .await
            .map_err(|e| StorageError::DatabaseError(e.to_string()))?;

        let mut sessions = Vec::new();
        for row in rows {
            sessions.push(Self::row_to_atp_oauth_session(&row)?);
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
        let access_token_created_at_str =
            access_token_created_at.as_ref().map(|dt| dt.to_rfc3339());
        let access_token_expires_at_str =
            access_token_expires_at.as_ref().map(|dt| dt.to_rfc3339());
        let access_token_scopes_json = access_token_scopes
            .as_ref()
            .map(|scopes| serde_json::to_string(scopes))
            .transpose()
            .map_err(|e| StorageError::SerializationError(e.to_string()))?;

        let result = sqlx::query(
            r#"
            UPDATE atp_oauth_sessions SET
                access_token = ?, refresh_token = ?,
                access_token_created_at = ?, access_token_expires_at = ?, access_token_scopes = ?
            WHERE did = ? AND session_id = ? AND iteration = ?
            "#,
        )
        .bind(&access_token)
        .bind(&refresh_token)
        .bind(&access_token_created_at_str)
        .bind(&access_token_expires_at_str)
        .bind(&access_token_scopes_json)
        .bind(did)
        .bind(session_id)
        .bind(iteration as i64)
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
            "DELETE FROM atp_oauth_sessions WHERE did = ? AND session_id = ? AND iteration = ?",
        )
        .bind(did)
        .bind(session_id)
        .bind(iteration as i64)
        .execute(&self.pool)
        .await
        .map_err(|e| StorageError::DatabaseError(e.to_string()))?;

        Ok(())
    }

    async fn cleanup_old_sessions(&self, older_than: DateTime<Utc>) -> Result<usize> {
        let older_than_str = older_than.to_rfc3339();

        let result = sqlx::query("DELETE FROM atp_oauth_sessions WHERE session_created_at < ?")
            .bind(older_than_str)
            .execute(&self.pool)
            .await
            .map_err(|e| StorageError::DatabaseError(e.to_string()))?;

        Ok(result.rows_affected() as usize)
    }
}
