//! PostgreSQL storage implementations
//!
//! This module provides PostgreSQL-based implementations of all storage traits.
//! PostgreSQL is suitable for production deployments with high availability requirements.

mod access_tokens;
mod app_passwords;
mod atp_oauth_sessions;
mod authorization_codes;
mod authorization_requests;
mod device_codes;
mod did_documents;
mod keys;
mod oauth_clients;
mod oauth_request_storage;
mod par_requests;
mod refresh_tokens;

use crate::errors::StorageError;
use crate::storage::traits::*;
use async_trait::async_trait;
use sqlx::postgres::PgPool;
use std::sync::Arc;

pub use access_tokens::PostgresAccessTokenStore;
pub use app_passwords::{PostgresAppPasswordSessionStore, PostgresAppPasswordStore};
pub use atp_oauth_sessions::PostgresAtpOAuthSessionStorage;
pub use authorization_codes::PostgresAuthorizationCodeStore;
pub use authorization_requests::PostgresAuthorizationRequestStorage;
pub use device_codes::PostgresDeviceCodeStore;
pub use did_documents::PostgresDidDocumentStorage;
pub use keys::PostgresKeyStore;
pub use oauth_clients::PostgresOAuthClientStore;
pub use oauth_request_storage::PostgresOAuthRequestStorage;
pub use par_requests::PostgresPARStorage;
pub use refresh_tokens::PostgresRefreshTokenStore;

pub type Result<T> = std::result::Result<T, StorageError>;

/// Comprehensive PostgreSQL OAuth storage implementation
pub struct PostgresOAuthStorage {
    pool: PgPool,
    client_store: Arc<PostgresOAuthClientStore>,
    authorization_code_store: Arc<PostgresAuthorizationCodeStore>,
    access_token_store: Arc<PostgresAccessTokenStore>,
    refresh_token_store: Arc<PostgresRefreshTokenStore>,
    device_code_store: Arc<PostgresDeviceCodeStore>,
    key_store: Arc<PostgresKeyStore>,
    par_storage: Arc<PostgresPARStorage>,
    atp_oauth_session_storage: Arc<PostgresAtpOAuthSessionStorage>,
    authorization_request_storage: Arc<PostgresAuthorizationRequestStorage>,
    did_document_storage: Arc<PostgresDidDocumentStorage>,
    oauth_request_storage: Arc<PostgresOAuthRequestStorage>,
    app_password_store: Arc<PostgresAppPasswordStore>,
    app_password_session_store: Arc<PostgresAppPasswordSessionStore>,
}

impl PostgresOAuthStorage {
    /// Create a new PostgreSQL OAuth storage instance
    pub fn new(pool: PgPool) -> Self {
        let client_store = Arc::new(PostgresOAuthClientStore::new(pool.clone()));
        let authorization_code_store = Arc::new(PostgresAuthorizationCodeStore::new(pool.clone()));
        let access_token_store = Arc::new(PostgresAccessTokenStore::new(pool.clone()));
        let refresh_token_store = Arc::new(PostgresRefreshTokenStore::new(pool.clone()));
        let device_code_store = Arc::new(PostgresDeviceCodeStore::new(pool.clone()));
        let key_store = Arc::new(PostgresKeyStore::new(pool.clone()));
        let par_storage = Arc::new(PostgresPARStorage::new(pool.clone()));
        let atp_oauth_session_storage = Arc::new(PostgresAtpOAuthSessionStorage::new(pool.clone()));
        let authorization_request_storage =
            Arc::new(PostgresAuthorizationRequestStorage::new(pool.clone()));
        let did_document_storage = Arc::new(PostgresDidDocumentStorage::new(pool.clone()));
        let oauth_request_storage = Arc::new(PostgresOAuthRequestStorage::new(pool.clone()));
        let app_password_store = Arc::new(PostgresAppPasswordStore::new(pool.clone()));
        let app_password_session_store =
            Arc::new(PostgresAppPasswordSessionStore::new(pool.clone()));

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
            did_document_storage,
            oauth_request_storage,
            app_password_store,
            app_password_session_store,
        }
    }

    /// Run database migrations
    pub async fn migrate(&self) -> Result<()> {
        sqlx::migrate!("./migrations/postgres")
            .run(&self.pool)
            .await
            .map_err(|e| StorageError::DatabaseError(format!("Migration failed: {}", e)))?;
        Ok(())
    }

    /// Get the DID document storage component
    pub fn did_document_storage(&self) -> Arc<PostgresDidDocumentStorage> {
        self.did_document_storage.clone()
    }

    /// Get the OAuth request storage component
    pub fn oauth_request_storage(&self) -> Arc<PostgresOAuthRequestStorage> {
        self.oauth_request_storage.clone()
    }
}

#[async_trait]
impl OAuthClientStore for PostgresOAuthStorage {
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
impl AuthorizationCodeStore for PostgresOAuthStorage {
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
impl AccessTokenStore for PostgresOAuthStorage {
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
impl RefreshTokenStore for PostgresOAuthStorage {
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
impl DeviceCodeStore for PostgresOAuthStorage {
    async fn store_device_code(
        &self,
        device_code: &str,
        user_code: &str,
        client_id: &str,
        scope: Option<&str>,
        expires_in: u64,
    ) -> Result<()> {
        self.device_code_store.store_device_code(device_code, user_code, client_id, scope, expires_in).await
    }

    async fn get_device_code(&self, device_code: &str) -> Result<Option<DeviceCodeEntry>> {
        self.device_code_store.get_device_code(device_code).await
    }
    
    async fn get_device_code_by_user_code(&self, user_code: &str) -> Result<Option<DeviceCodeEntry>> {
        self.device_code_store.get_device_code_by_user_code(user_code).await
    }

    async fn authorize_device_code(&self, user_code: &str, user_id: &str) -> Result<()> {
        self.device_code_store.authorize_device_code(user_code, user_id).await
    }

    async fn consume_device_code(&self, device_code: &str) -> Result<Option<String>> {
        self.device_code_store.consume_device_code(device_code).await
    }

    async fn cleanup_expired_device_codes(&self) -> Result<usize> {
        self.device_code_store.cleanup_expired_device_codes().await
    }
}

#[async_trait]
impl KeyStore for PostgresOAuthStorage {
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
impl PARStorage for PostgresOAuthStorage {
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
impl AtpOAuthSessionStorage for PostgresOAuthStorage {
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
impl AuthorizationRequestStorage for PostgresOAuthStorage {
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
impl atproto_identity::storage::DidDocumentStorage for PostgresOAuthStorage {
    async fn get_document_by_did(
        &self,
        did: &str,
    ) -> anyhow::Result<Option<atproto_identity::model::Document>> {
        self.did_document_storage.get_document_by_did(did).await
    }

    async fn store_document(
        &self,
        document: atproto_identity::model::Document,
    ) -> anyhow::Result<()> {
        self.did_document_storage.store_document(document).await
    }

    async fn delete_document_by_did(&self, did: &str) -> anyhow::Result<()> {
        self.did_document_storage.delete_document_by_did(did).await
    }
}

#[async_trait]
impl atproto_oauth::storage::OAuthRequestStorage for PostgresOAuthStorage {
    async fn get_oauth_request_by_state(
        &self,
        state: &str,
    ) -> anyhow::Result<Option<atproto_oauth::workflow::OAuthRequest>> {
        self.oauth_request_storage
            .get_oauth_request_by_state(state)
            .await
    }

    async fn insert_oauth_request(
        &self,
        request: atproto_oauth::workflow::OAuthRequest,
    ) -> anyhow::Result<()> {
        self.oauth_request_storage
            .insert_oauth_request(request)
            .await
    }

    async fn delete_oauth_request_by_state(&self, state: &str) -> anyhow::Result<()> {
        self.oauth_request_storage
            .delete_oauth_request_by_state(state)
            .await
    }

    async fn clear_expired_oauth_requests(&self) -> anyhow::Result<u64> {
        self.oauth_request_storage
            .clear_expired_oauth_requests()
            .await
    }
}

#[async_trait]
impl AppPasswordStore for PostgresOAuthStorage {
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
impl AppPasswordSessionStore for PostgresOAuthStorage {
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
impl OAuthStorage for PostgresOAuthStorage {}
