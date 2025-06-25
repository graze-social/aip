//! PostgreSQL implementation for app password storage

use crate::errors::StorageError;
use crate::storage::traits::{
    AppPassword, AppPasswordSession, AppPasswordSessionStore, AppPasswordStore,
};
use async_trait::async_trait;
use sqlx::Row;
use sqlx::postgres::{PgPool, PgRow};

pub type Result<T> = std::result::Result<T, StorageError>;

/// PostgreSQL implementation for app password storage
pub struct PostgresAppPasswordStore {
    pool: PgPool,
}

impl PostgresAppPasswordStore {
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }

    /// Convert PostgreSQL row to AppPassword
    fn row_to_app_password(row: &PgRow) -> Result<AppPassword> {
        Ok(AppPassword {
            client_id: row.try_get("client_id").map_err(|e| {
                StorageError::DatabaseError(format!("Failed to get client_id: {}", e))
            })?,
            did: row
                .try_get("did")
                .map_err(|e| StorageError::DatabaseError(format!("Failed to get did: {}", e)))?,
            app_password: row.try_get("app_password").map_err(|e| {
                StorageError::DatabaseError(format!("Failed to get app_password: {}", e))
            })?,
            created_at: row.try_get("created_at").map_err(|e| {
                StorageError::DatabaseError(format!("Failed to get created_at: {}", e))
            })?,
            updated_at: row.try_get("updated_at").map_err(|e| {
                StorageError::DatabaseError(format!("Failed to get updated_at: {}", e))
            })?,
        })
    }
}

#[async_trait]
impl AppPasswordStore for PostgresAppPasswordStore {
    async fn store_app_password(&self, app_password: &AppPassword) -> Result<()> {
        sqlx::query(
            r#"
            INSERT INTO app_passwords (client_id, did, app_password, created_at, updated_at)
            VALUES ($1, $2, $3, $4, $5)
            ON CONFLICT(client_id, did) DO UPDATE SET
                app_password = EXCLUDED.app_password,
                updated_at = EXCLUDED.updated_at
            "#,
        )
        .bind(&app_password.client_id)
        .bind(&app_password.did)
        .bind(&app_password.app_password)
        .bind(app_password.created_at)
        .bind(app_password.updated_at)
        .execute(&self.pool)
        .await
        .map_err(|e| StorageError::DatabaseError(format!("Failed to store app password: {}", e)))?;

        Ok(())
    }

    async fn get_app_password(&self, client_id: &str, did: &str) -> Result<Option<AppPassword>> {
        let row = sqlx::query(
            r#"
            SELECT client_id, did, app_password, created_at, updated_at
            FROM app_passwords
            WHERE client_id = $1 AND did = $2
            "#,
        )
        .bind(client_id)
        .bind(did)
        .fetch_optional(&self.pool)
        .await
        .map_err(|e| StorageError::DatabaseError(format!("Failed to get app password: {}", e)))?;

        match row {
            Some(row) => {
                let app_password = Self::row_to_app_password(&row)?;
                Ok(Some(app_password))
            }
            None => Ok(None),
        }
    }

    async fn delete_app_password(&self, client_id: &str, did: &str) -> Result<()> {
        sqlx::query(
            r#"
            DELETE FROM app_passwords
            WHERE client_id = $1 AND did = $2
            "#,
        )
        .bind(client_id)
        .bind(did)
        .execute(&self.pool)
        .await
        .map_err(|e| {
            StorageError::DatabaseError(format!("Failed to delete app password: {}", e))
        })?;

        Ok(())
    }

    async fn list_app_passwords_by_did(&self, did: &str) -> Result<Vec<AppPassword>> {
        let rows = sqlx::query(
            r#"
            SELECT client_id, did, app_password, created_at, updated_at
            FROM app_passwords
            WHERE did = $1
            ORDER BY updated_at DESC
            "#,
        )
        .bind(did)
        .fetch_all(&self.pool)
        .await
        .map_err(|e| {
            StorageError::DatabaseError(format!("Failed to list app passwords by DID: {}", e))
        })?;

        let mut passwords = Vec::new();
        for row in rows {
            passwords.push(Self::row_to_app_password(&row)?);
        }

        Ok(passwords)
    }

    async fn list_app_passwords_by_client(&self, client_id: &str) -> Result<Vec<AppPassword>> {
        let rows = sqlx::query(
            r#"
            SELECT client_id, did, app_password, created_at, updated_at
            FROM app_passwords
            WHERE client_id = $1
            ORDER BY updated_at DESC
            "#,
        )
        .bind(client_id)
        .fetch_all(&self.pool)
        .await
        .map_err(|e| {
            StorageError::DatabaseError(format!("Failed to list app passwords by client: {}", e))
        })?;

        let mut passwords = Vec::new();
        for row in rows {
            passwords.push(Self::row_to_app_password(&row)?);
        }

        Ok(passwords)
    }
}

/// PostgreSQL implementation for app password session storage
pub struct PostgresAppPasswordSessionStore {
    pool: PgPool,
}

impl PostgresAppPasswordSessionStore {
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }

    /// Convert PostgreSQL row to AppPasswordSession
    fn row_to_app_password_session(row: &PgRow) -> Result<AppPasswordSession> {
        Ok(AppPasswordSession {
            client_id: row.try_get("client_id").map_err(|e| {
                StorageError::DatabaseError(format!("Failed to get client_id: {}", e))
            })?,
            did: row
                .try_get("did")
                .map_err(|e| StorageError::DatabaseError(format!("Failed to get did: {}", e)))?,
            access_token: row.try_get("access_token").map_err(|e| {
                StorageError::DatabaseError(format!("Failed to get access_token: {}", e))
            })?,
            refresh_token: row.try_get("refresh_token").map_err(|e| {
                StorageError::DatabaseError(format!("Failed to get refresh_token: {}", e))
            })?,
            access_token_created_at: row.try_get("access_token_created_at").map_err(|e| {
                StorageError::DatabaseError(format!("Failed to get access_token_created_at: {}", e))
            })?,
            access_token_expires_at: row.try_get("access_token_expires_at").map_err(|e| {
                StorageError::DatabaseError(format!("Failed to get access_token_expires_at: {}", e))
            })?,
            iteration: {
                let iter: i32 = row.try_get("iteration").map_err(|e| {
                    StorageError::DatabaseError(format!("Failed to get iteration: {}", e))
                })?;
                iter as u32
            },
            session_exchanged_at: row.try_get("session_exchanged_at").map_err(|e| {
                StorageError::DatabaseError(format!("Failed to get session_exchanged_at: {}", e))
            })?,
            exchange_error: row.try_get("exchange_error").map_err(|e| {
                StorageError::DatabaseError(format!("Failed to get exchange_error: {}", e))
            })?,
        })
    }
}

#[async_trait]
impl AppPasswordSessionStore for PostgresAppPasswordSessionStore {
    async fn store_app_password_session(&self, session: &AppPasswordSession) -> Result<()> {
        sqlx::query(
            r#"
            INSERT INTO app_password_sessions (
                client_id, did, access_token, refresh_token,
                access_token_created_at, access_token_expires_at,
                iteration, session_exchanged_at, exchange_error
            )
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
            ON CONFLICT(client_id, did) DO UPDATE SET
                access_token = EXCLUDED.access_token,
                refresh_token = EXCLUDED.refresh_token,
                access_token_created_at = EXCLUDED.access_token_created_at,
                access_token_expires_at = EXCLUDED.access_token_expires_at,
                iteration = EXCLUDED.iteration,
                session_exchanged_at = EXCLUDED.session_exchanged_at,
                exchange_error = EXCLUDED.exchange_error
            "#,
        )
        .bind(&session.client_id)
        .bind(&session.did)
        .bind(&session.access_token)
        .bind(&session.refresh_token)
        .bind(session.access_token_created_at)
        .bind(session.access_token_expires_at)
        .bind(session.iteration as i32)
        .bind(session.session_exchanged_at)
        .bind(&session.exchange_error)
        .execute(&self.pool)
        .await
        .map_err(|e| {
            StorageError::DatabaseError(format!("Failed to store app password session: {}", e))
        })?;

        Ok(())
    }

    async fn get_app_password_session(
        &self,
        client_id: &str,
        did: &str,
    ) -> Result<Option<AppPasswordSession>> {
        let row = sqlx::query(
            r#"
            SELECT client_id, did, access_token, refresh_token,
                   access_token_created_at, access_token_expires_at,
                   iteration, session_exchanged_at, exchange_error
            FROM app_password_sessions
            WHERE client_id = $1 AND did = $2
            "#,
        )
        .bind(client_id)
        .bind(did)
        .fetch_optional(&self.pool)
        .await
        .map_err(|e| {
            StorageError::DatabaseError(format!("Failed to get app password session: {}", e))
        })?;

        match row {
            Some(row) => {
                let session = Self::row_to_app_password_session(&row)?;
                Ok(Some(session))
            }
            None => Ok(None),
        }
    }

    async fn update_app_password_session(&self, session: &AppPasswordSession) -> Result<()> {
        let rows_affected = sqlx::query(
            r#"
            UPDATE app_password_sessions
            SET access_token = $3,
                refresh_token = $4,
                access_token_created_at = $5,
                access_token_expires_at = $6,
                iteration = $7,
                session_exchanged_at = $8,
                exchange_error = $9
            WHERE client_id = $1 AND did = $2
            "#,
        )
        .bind(&session.client_id)
        .bind(&session.did)
        .bind(&session.access_token)
        .bind(&session.refresh_token)
        .bind(session.access_token_created_at)
        .bind(session.access_token_expires_at)
        .bind(session.iteration as i32)
        .bind(session.session_exchanged_at)
        .bind(&session.exchange_error)
        .execute(&self.pool)
        .await
        .map_err(|e| {
            StorageError::DatabaseError(format!("Failed to update app password session: {}", e))
        })?
        .rows_affected();

        if rows_affected == 0 {
            return Err(StorageError::QueryFailed(
                "App password session not found".to_string(),
            ));
        }

        Ok(())
    }

    async fn delete_app_password_sessions(&self, client_id: &str, did: &str) -> Result<()> {
        sqlx::query(
            r#"
            DELETE FROM app_password_sessions
            WHERE client_id = $1 AND did = $2
            "#,
        )
        .bind(client_id)
        .bind(did)
        .execute(&self.pool)
        .await
        .map_err(|e| {
            StorageError::DatabaseError(format!("Failed to delete app password sessions: {}", e))
        })?;

        Ok(())
    }

    async fn list_app_password_sessions_by_did(
        &self,
        did: &str,
    ) -> Result<Vec<AppPasswordSession>> {
        let rows = sqlx::query(
            r#"
            SELECT client_id, did, access_token, refresh_token,
                   access_token_created_at, access_token_expires_at,
                   iteration, session_exchanged_at, exchange_error
            FROM app_password_sessions
            WHERE did = $1
            ORDER BY access_token_expires_at DESC
            "#,
        )
        .bind(did)
        .fetch_all(&self.pool)
        .await
        .map_err(|e| {
            StorageError::DatabaseError(format!(
                "Failed to list app password sessions by DID: {}",
                e
            ))
        })?;

        let mut sessions = Vec::new();
        for row in rows {
            sessions.push(Self::row_to_app_password_session(&row)?);
        }

        Ok(sessions)
    }

    async fn list_app_password_sessions_by_client(
        &self,
        client_id: &str,
    ) -> Result<Vec<AppPasswordSession>> {
        let rows = sqlx::query(
            r#"
            SELECT client_id, did, access_token, refresh_token,
                   access_token_created_at, access_token_expires_at,
                   iteration, session_exchanged_at, exchange_error
            FROM app_password_sessions
            WHERE client_id = $1
            ORDER BY access_token_expires_at DESC
            "#,
        )
        .bind(client_id)
        .fetch_all(&self.pool)
        .await
        .map_err(|e| {
            StorageError::DatabaseError(format!(
                "Failed to list app password sessions by client: {}",
                e
            ))
        })?;

        let mut sessions = Vec::new();
        for row in rows {
            sessions.push(Self::row_to_app_password_session(&row)?);
        }

        Ok(sessions)
    }
}
