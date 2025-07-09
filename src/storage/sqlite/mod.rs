//! SQLite storage implementations
//!
//! This module provides SQLite-based implementations of all storage traits.
//! SQLite is suitable for single-instance deployments and development.

mod access_tokens;
mod app_passwords;
mod atp_oauth_sessions;
mod authorization_codes;
mod authorization_requests;
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
    key_store: Arc<SqliteKeyStore>,
    par_storage: Arc<SqlitePARStorage>,
    atp_oauth_session_storage: Arc<SqliteAtpOAuthSessionStorage>,
    authorization_request_storage: Arc<SqliteAuthorizationRequestStorage>,
    app_password_store: Arc<SqliteAppPasswordStore>,
    app_password_session_store: Arc<SqliteAppPasswordSessionStore>,
}

impl SqliteOAuthStorage {
    /// Create a new SQLite OAuth storage instance
    pub fn new(pool: SqlitePool) -> Self {
        let client_store = Arc::new(SqliteOAuthClientStore::new(pool.clone()));
        let authorization_code_store = Arc::new(SqliteAuthorizationCodeStore::new(pool.clone()));
        let access_token_store = Arc::new(SqliteAccessTokenStore::new(pool.clone()));
        let refresh_token_store = Arc::new(SqliteRefreshTokenStore::new(pool.clone()));
        let key_store = Arc::new(SqliteKeyStore::new(pool.clone()));
        let par_storage = Arc::new(SqlitePARStorage::new(pool.clone()));
        let atp_oauth_session_storage = Arc::new(SqliteAtpOAuthSessionStorage::new(pool.clone()));
        let authorization_request_storage =
            Arc::new(SqliteAuthorizationRequestStorage::new(pool.clone()));
        let app_password_store = Arc::new(SqliteAppPasswordStore::new(pool.clone()));
        let app_password_session_store = Arc::new(SqliteAppPasswordSessionStore::new(pool.clone()));

        Self {
            pool,
            client_store,
            authorization_code_store,
            access_token_store,
            refresh_token_store,
            key_store,
            par_storage,
            atp_oauth_session_storage,
            authorization_request_storage,
            app_password_store,
            app_password_session_store,
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

// Implement the combined OAuthStorage trait
impl OAuthStorage for SqliteOAuthStorage {}
