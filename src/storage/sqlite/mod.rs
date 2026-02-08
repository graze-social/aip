//! SQLite storage implementations
//!
//! This module provides SQLite-based implementations of all storage traits.
//! SQLite is suitable for single-instance deployments and development.

mod access_tokens;
mod app_passwords;
mod atp_oauth_sessions;
mod authorization_codes;
mod authorization_requests;
mod delegate_access;
mod device_codes;
mod keys;
mod oauth_clients;
mod oauth_request_storage;
mod par_requests;
mod refresh_tokens;

use crate::errors::StorageError;
use crate::storage::traits::*;
use async_trait::async_trait;
use sqlx::sqlite::SqlitePool;
use std::sync::Arc;

pub use access_tokens::SqliteAccessTokenStore;
pub use app_passwords::{SqliteAppPasswordSessionStore, SqliteAppPasswordStore};
pub use atp_oauth_sessions::SqliteAtpOAuthSessionStorage;
pub use authorization_codes::SqliteAuthorizationCodeStore;
pub use authorization_requests::SqliteAuthorizationRequestStorage;
pub use delegate_access::SqliteDelegateAccessStore;
pub use device_codes::SqliteDeviceCodeStore;
pub use keys::SqliteKeyStore;
pub use oauth_clients::SqliteOAuthClientStore;
pub use oauth_request_storage::SqliteOAuthRequestStorage;
pub use par_requests::SqlitePARStorage;
pub use refresh_tokens::SqliteRefreshTokenStore;

pub type Result<T> = std::result::Result<T, StorageError>;

/// Comprehensive SQLite OAuth storage implementation
pub struct SqliteOAuthStorage {
    pool: SqlitePool,
    client_store: Arc<SqliteOAuthClientStore>,
    authorization_code_store: Arc<SqliteAuthorizationCodeStore>,
    access_token_store: Arc<SqliteAccessTokenStore>,
    refresh_token_store: Arc<SqliteRefreshTokenStore>,
    device_code_store: Arc<SqliteDeviceCodeStore>,
    key_store: Arc<SqliteKeyStore>,
    par_storage: Arc<SqlitePARStorage>,
    atp_oauth_session_storage: Arc<SqliteAtpOAuthSessionStorage>,
    authorization_request_storage: Arc<SqliteAuthorizationRequestStorage>,
    app_password_store: Arc<SqliteAppPasswordStore>,
    app_password_session_store: Arc<SqliteAppPasswordSessionStore>,
    delegate_access_store: Arc<SqliteDelegateAccessStore>,
}

impl SqliteOAuthStorage {
    /// Create a new SQLite OAuth storage instance
    pub fn new(pool: SqlitePool) -> Self {
        let client_store = Arc::new(SqliteOAuthClientStore::new(pool.clone()));
        let authorization_code_store = Arc::new(SqliteAuthorizationCodeStore::new(pool.clone()));
        let access_token_store = Arc::new(SqliteAccessTokenStore::new(pool.clone()));
        let refresh_token_store = Arc::new(SqliteRefreshTokenStore::new(pool.clone()));
        let device_code_store = Arc::new(SqliteDeviceCodeStore::new(pool.clone()));
        let key_store = Arc::new(SqliteKeyStore::new(pool.clone()));
        let par_storage = Arc::new(SqlitePARStorage::new(pool.clone()));
        let atp_oauth_session_storage = Arc::new(SqliteAtpOAuthSessionStorage::new(pool.clone()));
        let authorization_request_storage =
            Arc::new(SqliteAuthorizationRequestStorage::new(pool.clone()));
        let app_password_store = Arc::new(SqliteAppPasswordStore::new(pool.clone()));
        let app_password_session_store = Arc::new(SqliteAppPasswordSessionStore::new(pool.clone()));
        let delegate_access_store = Arc::new(SqliteDelegateAccessStore::new(pool.clone()));

        Self {
            pool,
            client_store,
            authorization_code_store,
            access_token_store,
            refresh_token_store,
            device_code_store,
            key_store,
            par_storage,
            atp_oauth_session_storage,
            authorization_request_storage,
            app_password_store,
            app_password_session_store,
            delegate_access_store,
        }
    }

    /// Run database migrations
    pub async fn migrate(&self) -> Result<()> {
        sqlx::migrate!("./migrations/sqlite")
            .run(&self.pool)
            .await
            .map_err(|e| StorageError::DatabaseError(format!("Migration failed: {}", e)))?;
        Ok(())
    }
}

#[async_trait]
impl OAuthClientStore for SqliteOAuthStorage {
    async fn store_client(&self, client: &crate::oauth::types::OAuthClient) -> Result<()> {
        self.client_store.store_client(client).await
    }

    async fn get_client(
        &self,
        client_id: &str,
    ) -> Result<Option<crate::oauth::types::OAuthClient>> {
        self.client_store.get_client(client_id).await
    }

    async fn update_client(&self, client: &crate::oauth::types::OAuthClient) -> Result<()> {
        self.client_store.update_client(client).await
    }

    async fn delete_client(&self, client_id: &str) -> Result<()> {
        self.client_store.delete_client(client_id).await
    }

    async fn list_clients(
        &self,
        limit: Option<usize>,
    ) -> Result<Vec<crate::oauth::types::OAuthClient>> {
        self.client_store.list_clients(limit).await
    }
}

#[async_trait]
impl AuthorizationCodeStore for SqliteOAuthStorage {
    async fn store_code(&self, code: &crate::oauth::types::AuthorizationCode) -> Result<()> {
        self.authorization_code_store.store_code(code).await
    }

    async fn get_code(
        &self,
        code: &str,
    ) -> Result<Option<crate::oauth::types::AuthorizationCode>> {
        self.authorization_code_store.get_code(code).await
    }

    async fn consume_code(
        &self,
        code: &str,
    ) -> Result<Option<crate::oauth::types::AuthorizationCode>> {
        self.authorization_code_store.consume_code(code).await
    }

    async fn cleanup_expired_codes(&self) -> Result<usize> {
        self.authorization_code_store.cleanup_expired_codes().await
    }
}

#[async_trait]
impl AccessTokenStore for SqliteOAuthStorage {
    async fn store_token(&self, token: &crate::oauth::types::AccessToken) -> Result<()> {
        self.access_token_store.store_token(token).await
    }

    async fn get_token(&self, token: &str) -> Result<Option<crate::oauth::types::AccessToken>> {
        self.access_token_store.get_token(token).await
    }

    async fn revoke_token(&self, token: &str) -> Result<()> {
        self.access_token_store.revoke_token(token).await
    }

    async fn cleanup_expired_tokens(&self) -> Result<usize> {
        self.access_token_store.cleanup_expired_tokens().await
    }

    async fn get_user_tokens(
        &self,
        user_id: &str,
    ) -> Result<Vec<crate::oauth::types::AccessToken>> {
        self.access_token_store.get_user_tokens(user_id).await
    }

    async fn get_client_tokens(
        &self,
        client_id: &str,
    ) -> Result<Vec<crate::oauth::types::AccessToken>> {
        self.access_token_store.get_client_tokens(client_id).await
    }
}

#[async_trait]
impl RefreshTokenStore for SqliteOAuthStorage {
    async fn store_refresh_token(&self, token: &crate::oauth::types::RefreshToken) -> Result<()> {
        self.refresh_token_store.store_refresh_token(token).await
    }

    async fn get_refresh_token(
        &self,
        token: &str,
    ) -> Result<Option<crate::oauth::types::RefreshToken>> {
        self.refresh_token_store.get_refresh_token(token).await
    }

    async fn consume_refresh_token(
        &self,
        token: &str,
    ) -> Result<Option<crate::oauth::types::RefreshToken>> {
        self.refresh_token_store.consume_refresh_token(token).await
    }

    async fn cleanup_expired_refresh_tokens(&self) -> Result<usize> {
        self.refresh_token_store
            .cleanup_expired_refresh_tokens()
            .await
    }
}

#[async_trait]
impl DeviceCodeStore for SqliteOAuthStorage {
    async fn store_device_code(
        &self,
        device_code: &str,
        user_code: &str,
        client_id: &str,
        scope: Option<&str>,
        expires_in: u64,
    ) -> Result<()> {
        self.device_code_store
            .store_device_code(device_code, user_code, client_id, scope, expires_in)
            .await
    }

    async fn get_device_code(&self, device_code: &str) -> Result<Option<DeviceCodeEntry>> {
        self.device_code_store.get_device_code(device_code).await
    }

    async fn get_device_code_by_user_code(
        &self,
        user_code: &str,
    ) -> Result<Option<DeviceCodeEntry>> {
        self.device_code_store
            .get_device_code_by_user_code(user_code)
            .await
    }

    async fn authorize_device_code(&self, user_code: &str, user_id: &str) -> Result<()> {
        self.device_code_store
            .authorize_device_code(user_code, user_id)
            .await
    }

    async fn consume_device_code(&self, device_code: &str) -> Result<Option<String>> {
        self.device_code_store
            .consume_device_code(device_code)
            .await
    }

    async fn cleanup_expired_device_codes(&self) -> Result<usize> {
        self.device_code_store.cleanup_expired_device_codes().await
    }
}

#[async_trait]
impl KeyStore for SqliteOAuthStorage {
    async fn store_signing_key(&self, key: &atproto_identity::key::KeyData) -> Result<()> {
        self.key_store.store_signing_key(key).await
    }

    async fn get_signing_key(&self) -> Result<Option<atproto_identity::key::KeyData>> {
        self.key_store.get_signing_key().await
    }

    async fn store_key(&self, key_id: &str, key: &atproto_identity::key::KeyData) -> Result<()> {
        self.key_store.store_key(key_id, key).await
    }

    async fn get_key(&self, key_id: &str) -> Result<Option<atproto_identity::key::KeyData>> {
        self.key_store.get_key(key_id).await
    }

    async fn list_key_ids(&self) -> Result<Vec<String>> {
        self.key_store.list_key_ids().await
    }
}

#[async_trait]
impl PARStorage for SqliteOAuthStorage {
    async fn store_par_request(&self, request: &StoredPushedRequest) -> Result<()> {
        self.par_storage.store_par_request(request).await
    }

    async fn get_par_request(&self, request_uri: &str) -> Result<Option<StoredPushedRequest>> {
        self.par_storage.get_par_request(request_uri).await
    }

    async fn consume_par_request(&self, request_uri: &str) -> Result<Option<StoredPushedRequest>> {
        self.par_storage.consume_par_request(request_uri).await
    }

    async fn cleanup_expired_par_requests(&self) -> Result<usize> {
        self.par_storage.cleanup_expired_par_requests().await
    }
}

#[async_trait]
impl AtpOAuthSessionStorage for SqliteOAuthStorage {
    async fn store_session(&self, session: &AtpOAuthSession) -> Result<()> {
        self.atp_oauth_session_storage.store_session(session).await
    }

    async fn get_sessions(&self, did: &str, session_id: &str) -> Result<Vec<AtpOAuthSession>> {
        self.atp_oauth_session_storage
            .get_sessions(did, session_id)
            .await
    }

    async fn get_session(
        &self,
        did: &str,
        session_id: &str,
        iteration: u32,
    ) -> Result<Option<AtpOAuthSession>> {
        self.atp_oauth_session_storage
            .get_session(did, session_id, iteration)
            .await
    }

    async fn get_latest_session(
        &self,
        did: &str,
        session_id: &str,
    ) -> Result<Option<AtpOAuthSession>> {
        self.atp_oauth_session_storage
            .get_latest_session(did, session_id)
            .await
    }

    async fn update_session(&self, session: &AtpOAuthSession) -> Result<()> {
        self.atp_oauth_session_storage.update_session(session).await
    }

    async fn get_session_by_atp_state(&self, atp_state: &str) -> Result<Option<AtpOAuthSession>> {
        self.atp_oauth_session_storage
            .get_session_by_atp_state(atp_state)
            .await
    }

    async fn get_sessions_by_did(&self, did: &str) -> Result<Vec<AtpOAuthSession>> {
        self.atp_oauth_session_storage
            .get_sessions_by_did(did)
            .await
    }

    async fn update_session_tokens(
        &self,
        did: &str,
        session_id: &str,
        iteration: u32,
        access_token: Option<String>,
        refresh_token: Option<String>,
        access_token_created_at: Option<chrono::DateTime<chrono::Utc>>,
        access_token_expires_at: Option<chrono::DateTime<chrono::Utc>>,
        access_token_scopes: Option<Vec<String>>,
    ) -> Result<()> {
        self.atp_oauth_session_storage
            .update_session_tokens(
                did,
                session_id,
                iteration,
                access_token,
                refresh_token,
                access_token_created_at,
                access_token_expires_at,
                access_token_scopes,
            )
            .await
    }

    async fn remove_session(&self, did: &str, session_id: &str, iteration: u32) -> Result<()> {
        self.atp_oauth_session_storage
            .remove_session(did, session_id, iteration)
            .await
    }

    async fn cleanup_old_sessions(
        &self,
        older_than: chrono::DateTime<chrono::Utc>,
    ) -> Result<usize> {
        self.atp_oauth_session_storage
            .cleanup_old_sessions(older_than)
            .await
    }
}

#[async_trait]
impl AuthorizationRequestStorage for SqliteOAuthStorage {
    async fn store_authorization_request(
        &self,
        session_id: &str,
        request: &crate::oauth::types::AuthorizationRequest,
    ) -> Result<()> {
        self.authorization_request_storage
            .store_authorization_request(session_id, request)
            .await
    }

    async fn get_authorization_request(
        &self,
        session_id: &str,
    ) -> Result<Option<crate::oauth::types::AuthorizationRequest>> {
        self.authorization_request_storage
            .get_authorization_request(session_id)
            .await
    }

    async fn remove_authorization_request(&self, session_id: &str) -> Result<()> {
        self.authorization_request_storage
            .remove_authorization_request(session_id)
            .await
    }
}

#[async_trait]
impl AppPasswordStore for SqliteOAuthStorage {
    async fn store_app_password(&self, app_password: &AppPassword) -> Result<()> {
        self.app_password_store
            .store_app_password(app_password)
            .await
    }

    async fn get_app_password(&self, client_id: &str, did: &str) -> Result<Option<AppPassword>> {
        self.app_password_store
            .get_app_password(client_id, did)
            .await
    }

    async fn delete_app_password(&self, client_id: &str, did: &str) -> Result<()> {
        self.app_password_store
            .delete_app_password(client_id, did)
            .await
    }

    async fn list_app_passwords_by_did(&self, did: &str) -> Result<Vec<AppPassword>> {
        self.app_password_store.list_app_passwords_by_did(did).await
    }

    async fn list_app_passwords_by_client(&self, client_id: &str) -> Result<Vec<AppPassword>> {
        self.app_password_store
            .list_app_passwords_by_client(client_id)
            .await
    }
}

#[async_trait]
impl AppPasswordSessionStore for SqliteOAuthStorage {
    async fn store_app_password_session(&self, session: &AppPasswordSession) -> Result<()> {
        self.app_password_session_store
            .store_app_password_session(session)
            .await
    }

    async fn get_app_password_session(
        &self,
        client_id: &str,
        did: &str,
    ) -> Result<Option<AppPasswordSession>> {
        self.app_password_session_store
            .get_app_password_session(client_id, did)
            .await
    }

    async fn update_app_password_session(&self, session: &AppPasswordSession) -> Result<()> {
        self.app_password_session_store
            .update_app_password_session(session)
            .await
    }

    async fn delete_app_password_sessions(&self, client_id: &str, did: &str) -> Result<()> {
        self.app_password_session_store
            .delete_app_password_sessions(client_id, did)
            .await
    }

    async fn list_app_password_sessions_by_did(
        &self,
        did: &str,
    ) -> Result<Vec<AppPasswordSession>> {
        self.app_password_session_store
            .list_app_password_sessions_by_did(did)
            .await
    }

    async fn list_app_password_sessions_by_client(
        &self,
        client_id: &str,
    ) -> Result<Vec<AppPasswordSession>> {
        self.app_password_session_store
            .list_app_password_sessions_by_client(client_id)
            .await
    }
}

#[async_trait]
impl DelegateAccessStore for SqliteOAuthStorage {
    async fn grant_delegate(&self, owner_did: &str, delegate_did: &str) -> Result<()> {
        self.delegate_access_store
            .grant_delegate(owner_did, delegate_did)
            .await
    }

    async fn revoke_delegate(&self, owner_did: &str, delegate_did: &str) -> Result<()> {
        self.delegate_access_store
            .revoke_delegate(owner_did, delegate_did)
            .await
    }

    async fn is_delegate(&self, owner_did: &str, delegate_did: &str) -> Result<bool> {
        self.delegate_access_store
            .is_delegate(owner_did, delegate_did)
            .await
    }

    async fn list_delegates(&self, owner_did: &str) -> Result<Vec<DelegateGrant>> {
        self.delegate_access_store.list_delegates(owner_did).await
    }

    async fn list_owners(&self, delegate_did: &str) -> Result<Vec<DelegateGrant>> {
        self.delegate_access_store.list_owners(delegate_did).await
    }
}

// Implement the combined OAuthStorage trait
impl OAuthStorage for SqliteOAuthStorage {}

#[async_trait]
impl TransactionalStorage for SqliteOAuthStorage {
    async fn upsert_app_password_with_session(
        &self,
        app_password: &AppPassword,
        session: &AppPasswordSession,
    ) -> Result<()> {
        // Start a transaction to ensure atomicity
        let mut tx = self
            .pool
            .begin()
            .await
            .map_err(|e| StorageError::TransactionFailed(format!("Failed to begin: {}", e)))?;

        // Step 1: Delete existing sessions
        sqlx::query("DELETE FROM app_password_sessions WHERE client_id = ?1 AND did = ?2")
            .bind(&app_password.client_id)
            .bind(&app_password.did)
            .execute(&mut *tx)
            .await
            .map_err(|e| {
                StorageError::TransactionFailed(format!("Failed to delete sessions: {}", e))
            })?;

        // Step 2: Store the app password (upsert)
        let created_at = app_password.created_at.to_rfc3339();
        let updated_at = app_password.updated_at.to_rfc3339();

        sqlx::query(
            r#"
            INSERT INTO app_passwords (client_id, did, app_password, created_at, updated_at)
            VALUES (?1, ?2, ?3, ?4, ?5)
            ON CONFLICT(client_id, did) DO UPDATE SET
                app_password = excluded.app_password,
                updated_at = excluded.updated_at
            "#,
        )
        .bind(&app_password.client_id)
        .bind(&app_password.did)
        .bind(&app_password.app_password)
        .bind(&created_at)
        .bind(&updated_at)
        .execute(&mut *tx)
        .await
        .map_err(|e| {
            StorageError::TransactionFailed(format!("Failed to store app password: {}", e))
        })?;

        // Step 3: Store the new session
        let access_token_created_at = session.access_token_created_at.to_rfc3339();
        let access_token_expires_at = session.access_token_expires_at.to_rfc3339();
        let session_exchanged_at = session.session_exchanged_at.map(|dt| dt.to_rfc3339());

        sqlx::query(
            r#"
            INSERT INTO app_password_sessions (
                client_id, did, access_token, refresh_token,
                access_token_created_at, access_token_expires_at,
                iteration, session_exchanged_at, exchange_error
            )
            VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)
            ON CONFLICT(client_id, did) DO UPDATE SET
                access_token = excluded.access_token,
                refresh_token = excluded.refresh_token,
                access_token_created_at = excluded.access_token_created_at,
                access_token_expires_at = excluded.access_token_expires_at,
                iteration = excluded.iteration,
                session_exchanged_at = excluded.session_exchanged_at,
                exchange_error = excluded.exchange_error
            "#,
        )
        .bind(&session.client_id)
        .bind(&session.did)
        .bind(&session.access_token)
        .bind(&session.refresh_token)
        .bind(&access_token_created_at)
        .bind(&access_token_expires_at)
        .bind(session.iteration as i32)
        .bind(&session_exchanged_at)
        .bind(&session.exchange_error)
        .execute(&mut *tx)
        .await
        .map_err(|e| {
            StorageError::TransactionFailed(format!("Failed to store session: {}", e))
        })?;

        // Commit the transaction
        tx.commit()
            .await
            .map_err(|e| StorageError::TransactionFailed(format!("Failed to commit: {}", e)))?;

        Ok(())
    }

    async fn exchange_code_for_tokens(
        &self,
        code: &str,
        access_token: &crate::oauth::types::AccessToken,
        refresh_token: Option<&crate::oauth::types::RefreshToken>,
    ) -> Result<Option<crate::oauth::types::AuthorizationCode>> {
        use chrono::Utc;
        use sqlx::Row;

        // Start a transaction to ensure atomicity
        let mut tx = self
            .pool
            .begin()
            .await
            .map_err(|e| StorageError::TransactionFailed(format!("Failed to begin: {}", e)))?;

        // Step 1: Get and consume the authorization code
        let row = sqlx::query("SELECT * FROM authorization_codes WHERE code = ? AND used = 0")
            .bind(code)
            .fetch_optional(&mut *tx)
            .await
            .map_err(|e| {
                StorageError::TransactionFailed(format!("Failed to get code: {}", e))
            })?;

        let auth_code = match row {
            Some(row) => {
                // Parse the authorization code
                let created_at_str: String = row
                    .try_get("created_at")
                    .map_err(|e| StorageError::DatabaseError(format!("Failed to get created_at: {}", e)))?;
                let created_at = chrono::DateTime::parse_from_rfc3339(&created_at_str)
                    .map_err(|e| StorageError::InvalidData(format!("Invalid created_at: {}", e)))?
                    .with_timezone(&Utc);

                let expires_at_str: String = row
                    .try_get("expires_at")
                    .map_err(|e| StorageError::DatabaseError(format!("Failed to get expires_at: {}", e)))?;
                let expires_at = chrono::DateTime::parse_from_rfc3339(&expires_at_str)
                    .map_err(|e| StorageError::InvalidData(format!("Invalid expires_at: {}", e)))?
                    .with_timezone(&Utc);

                let used_int: i64 = row
                    .try_get("used")
                    .map_err(|e| StorageError::DatabaseError(format!("Failed to get used: {}", e)))?;
                let used = used_int != 0;

                let auth_code = crate::oauth::types::AuthorizationCode {
                    code: row.try_get("code").map_err(|e| StorageError::DatabaseError(e.to_string()))?,
                    client_id: row.try_get("client_id").map_err(|e| StorageError::DatabaseError(e.to_string()))?,
                    user_id: row.try_get("user_id").map_err(|e| StorageError::DatabaseError(e.to_string()))?,
                    session_id: row.try_get("session_id").map_err(|e| StorageError::DatabaseError(e.to_string()))?,
                    redirect_uri: row.try_get("redirect_uri").map_err(|e| StorageError::DatabaseError(e.to_string()))?,
                    scope: row.try_get("scope").map_err(|e| StorageError::DatabaseError(e.to_string()))?,
                    code_challenge: row.try_get("code_challenge").map_err(|e| StorageError::DatabaseError(e.to_string()))?,
                    code_challenge_method: row.try_get("code_challenge_method").map_err(|e| StorageError::DatabaseError(e.to_string()))?,
                    nonce: row.try_get("nonce").map_err(|e| StorageError::DatabaseError(e.to_string()))?,
                    created_at,
                    expires_at,
                    used,
                };

                // Check if expired
                if auth_code.expires_at <= Utc::now() {
                    sqlx::query("DELETE FROM authorization_codes WHERE code = ?")
                        .bind(code)
                        .execute(&mut *tx)
                        .await
                        .map_err(|e| StorageError::TransactionFailed(e.to_string()))?;
                    tx.commit().await.map_err(|e| StorageError::TransactionFailed(e.to_string()))?;
                    return Ok(None);
                }

                auth_code
            }
            None => {
                tx.rollback().await.ok();
                return Ok(None);
            }
        };

        // Mark code as used
        sqlx::query("UPDATE authorization_codes SET used = 1 WHERE code = ?")
            .bind(code)
            .execute(&mut *tx)
            .await
            .map_err(|e| {
                StorageError::TransactionFailed(format!("Failed to mark code used: {}", e))
            })?;

        // Step 2: Store the access token
        let created_at_str = access_token.created_at.to_rfc3339();
        let expires_at_str = access_token.expires_at.to_rfc3339();
        let token_type_str = match access_token.token_type {
            crate::oauth::types::TokenType::Bearer => "bearer",
            crate::oauth::types::TokenType::DPoP => "dpop",
        };
        let session_iteration = access_token.session_iteration.map(|i| i as i64);

        sqlx::query(
            r#"
            INSERT OR REPLACE INTO access_tokens (
                token, token_type, client_id, user_id, session_id, session_iteration,
                scope, nonce, created_at, expires_at, dpop_jkt
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            "#,
        )
        .bind(&access_token.token)
        .bind(token_type_str)
        .bind(&access_token.client_id)
        .bind(&access_token.user_id)
        .bind(&access_token.session_id)
        .bind(session_iteration)
        .bind(&access_token.scope)
        .bind(&access_token.nonce)
        .bind(&created_at_str)
        .bind(&expires_at_str)
        .bind(&access_token.dpop_jkt)
        .execute(&mut *tx)
        .await
        .map_err(|e| {
            StorageError::TransactionFailed(format!("Failed to store access token: {}", e))
        })?;

        // Step 3: Store the refresh token if provided
        if let Some(rt) = refresh_token {
            let rt_created_at_str = rt.created_at.to_rfc3339();
            let rt_expires_at_str = rt.expires_at.as_ref().map(|dt| dt.to_rfc3339());

            sqlx::query(
                r#"
                INSERT INTO refresh_tokens (
                    token, access_token, client_id, user_id, session_id,
                    scope, nonce, created_at, expires_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                "#,
            )
            .bind(&rt.token)
            .bind(&rt.access_token)
            .bind(&rt.client_id)
            .bind(&rt.user_id)
            .bind(&rt.session_id)
            .bind(&rt.scope)
            .bind(&rt.nonce)
            .bind(&rt_created_at_str)
            .bind(&rt_expires_at_str)
            .execute(&mut *tx)
            .await
            .map_err(|e| {
                StorageError::TransactionFailed(format!("Failed to store refresh token: {}", e))
            })?;
        }

        // Commit the transaction
        tx.commit()
            .await
            .map_err(|e| StorageError::TransactionFailed(format!("Failed to commit: {}", e)))?;

        Ok(Some(auth_code))
    }

    async fn refresh_tokens(
        &self,
        old_refresh_token: &str,
        new_access_token: &crate::oauth::types::AccessToken,
        new_refresh_token: &crate::oauth::types::RefreshToken,
    ) -> Result<Option<crate::oauth::types::RefreshToken>> {
        use chrono::Utc;
        use sqlx::Row;

        // Start a transaction to ensure atomicity
        let mut tx = self
            .pool
            .begin()
            .await
            .map_err(|e| StorageError::TransactionFailed(format!("Failed to begin: {}", e)))?;

        // Step 1: Get and consume the old refresh token
        let row = sqlx::query("SELECT * FROM refresh_tokens WHERE token = ?")
            .bind(old_refresh_token)
            .fetch_optional(&mut *tx)
            .await
            .map_err(|e| {
                StorageError::TransactionFailed(format!("Failed to get refresh token: {}", e))
            })?;

        let consumed_token = match row {
            Some(row) => {
                // Parse the refresh token
                let created_at_str: String = row
                    .try_get("created_at")
                    .map_err(|e| StorageError::DatabaseError(format!("Failed to get created_at: {}", e)))?;
                let created_at = chrono::DateTime::parse_from_rfc3339(&created_at_str)
                    .map_err(|e| StorageError::InvalidData(format!("Invalid created_at: {}", e)))?
                    .with_timezone(&Utc);

                let expires_at = if let Ok(expires_at_str) = row.try_get::<Option<String>, _>("expires_at") {
                    if let Some(expires_at_str) = expires_at_str {
                        Some(
                            chrono::DateTime::parse_from_rfc3339(&expires_at_str)
                                .map_err(|e| StorageError::InvalidData(format!("Invalid expires_at: {}", e)))?
                                .with_timezone(&Utc),
                        )
                    } else {
                        None
                    }
                } else {
                    None
                };

                let refresh_token = crate::oauth::types::RefreshToken {
                    token: row.try_get("token").map_err(|e| StorageError::DatabaseError(e.to_string()))?,
                    access_token: row.try_get("access_token").map_err(|e| StorageError::DatabaseError(e.to_string()))?,
                    client_id: row.try_get("client_id").map_err(|e| StorageError::DatabaseError(e.to_string()))?,
                    user_id: row.try_get("user_id").map_err(|e| StorageError::DatabaseError(e.to_string()))?,
                    session_id: row.try_get("session_id").map_err(|e| StorageError::DatabaseError(e.to_string()))?,
                    scope: row.try_get("scope").map_err(|e| StorageError::DatabaseError(e.to_string()))?,
                    nonce: row.try_get("nonce").map_err(|e| StorageError::DatabaseError(e.to_string()))?,
                    created_at,
                    expires_at,
                };

                // Check if expired
                if let Some(exp) = refresh_token.expires_at {
                    if exp <= Utc::now() {
                        sqlx::query("DELETE FROM refresh_tokens WHERE token = ?")
                            .bind(old_refresh_token)
                            .execute(&mut *tx)
                            .await
                            .map_err(|e| StorageError::TransactionFailed(e.to_string()))?;
                        tx.commit().await.map_err(|e| StorageError::TransactionFailed(e.to_string()))?;
                        return Ok(None);
                    }
                }

                refresh_token
            }
            None => {
                tx.rollback().await.ok();
                return Ok(None);
            }
        };

        // Delete the old refresh token (one-time use)
        sqlx::query("DELETE FROM refresh_tokens WHERE token = ?")
            .bind(old_refresh_token)
            .execute(&mut *tx)
            .await
            .map_err(|e| {
                StorageError::TransactionFailed(format!("Failed to delete old token: {}", e))
            })?;

        // Step 2: Store the new access token
        let created_at_str = new_access_token.created_at.to_rfc3339();
        let expires_at_str = new_access_token.expires_at.to_rfc3339();
        let token_type_str = match new_access_token.token_type {
            crate::oauth::types::TokenType::Bearer => "bearer",
            crate::oauth::types::TokenType::DPoP => "dpop",
        };
        let session_iteration = new_access_token.session_iteration.map(|i| i as i64);

        sqlx::query(
            r#"
            INSERT OR REPLACE INTO access_tokens (
                token, token_type, client_id, user_id, session_id, session_iteration,
                scope, nonce, created_at, expires_at, dpop_jkt
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            "#,
        )
        .bind(&new_access_token.token)
        .bind(token_type_str)
        .bind(&new_access_token.client_id)
        .bind(&new_access_token.user_id)
        .bind(&new_access_token.session_id)
        .bind(session_iteration)
        .bind(&new_access_token.scope)
        .bind(&new_access_token.nonce)
        .bind(&created_at_str)
        .bind(&expires_at_str)
        .bind(&new_access_token.dpop_jkt)
        .execute(&mut *tx)
        .await
        .map_err(|e| {
            StorageError::TransactionFailed(format!("Failed to store access token: {}", e))
        })?;

        // Step 3: Store the new refresh token
        let rt_created_at_str = new_refresh_token.created_at.to_rfc3339();
        let rt_expires_at_str = new_refresh_token.expires_at.as_ref().map(|dt| dt.to_rfc3339());

        sqlx::query(
            r#"
            INSERT INTO refresh_tokens (
                token, access_token, client_id, user_id, session_id,
                scope, nonce, created_at, expires_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            "#,
        )
        .bind(&new_refresh_token.token)
        .bind(&new_refresh_token.access_token)
        .bind(&new_refresh_token.client_id)
        .bind(&new_refresh_token.user_id)
        .bind(&new_refresh_token.session_id)
        .bind(&new_refresh_token.scope)
        .bind(&new_refresh_token.nonce)
        .bind(&rt_created_at_str)
        .bind(&rt_expires_at_str)
        .execute(&mut *tx)
        .await
        .map_err(|e| {
            StorageError::TransactionFailed(format!("Failed to store refresh token: {}", e))
        })?;

        // Commit the transaction
        tx.commit()
            .await
            .map_err(|e| StorageError::TransactionFailed(format!("Failed to commit: {}", e)))?;

        Ok(Some(consumed_token))
    }
}
