//! In-memory OAuth storage implementation
//!
//! This module provides in-memory implementations for OAuth-related storage traits.

use crate::errors::StorageError;
use crate::oauth::types::*;
use crate::storage::traits::*;
use async_trait::async_trait;
use atproto_identity::key::KeyData;
use chrono::Utc;
use std::collections::HashMap;
use std::sync::Mutex;

pub type Result<T> = std::result::Result<T, StorageError>;

/// In-memory implementation for OAuth storage
#[derive(Default)]
pub struct MemoryOAuthStorage {
    clients: Mutex<HashMap<String, OAuthClient>>,
    auth_codes: Mutex<HashMap<String, AuthorizationCode>>,
    access_tokens: Mutex<HashMap<String, AccessToken>>,
    refresh_tokens: Mutex<HashMap<String, RefreshToken>>,
    keys: Mutex<HashMap<String, String>>, // Store as KeyData string serialization
    signing_key: Mutex<Option<KeyData>>,
    par_requests: Mutex<HashMap<String, StoredPushedRequest>>,
    // ATProtocol session storage
    atp_sessions: tokio::sync::RwLock<HashMap<String, AtpOAuthSession>>, // session_key -> session
    atp_state_index: tokio::sync::RwLock<HashMap<String, String>>,       // atp_state -> session_key
    atp_session_iterations: tokio::sync::RwLock<HashMap<String, Vec<u32>>>, // (did, session_id) -> iterations
    // Authorization request storage
    auth_requests: tokio::sync::RwLock<HashMap<String, AuthorizationRequest>>,
    // App password storage
    app_passwords: tokio::sync::RwLock<HashMap<String, AppPassword>>, // "client_id:did" -> AppPassword
    app_password_sessions: tokio::sync::RwLock<HashMap<String, AppPasswordSession>>, // "client_id:did" -> AppPasswordSession
}

impl MemoryOAuthStorage {
    pub fn new() -> Self {
        Self::default()
    }

    /// Generate a unique session key from session_id and iteration
    fn session_key(session_id: &str, iteration: u32) -> String {
        format!("{}:{}", session_id, iteration)
    }

    /// Generate a session index key from DID and session_id
    fn session_index_key(did: &str, session_id: &str) -> String {
        format!("{}:{}", did, session_id)
    }

    /// Generate a unique app password key from client_id and DID
    fn app_password_key(client_id: &str, did: &str) -> String {
        format!("{}:{}", client_id, did)
    }
}

#[async_trait]
impl OAuthClientStore for MemoryOAuthStorage {
    async fn store_client(&self, client: &OAuthClient) -> Result<()> {
        let mut clients = self
            .clients
            .lock()
            .map_err(|e| StorageError::SerializationFailed(format!("Lock error: {}", e)))?;
        clients.insert(client.client_id.clone(), client.clone());
        Ok(())
    }

    async fn get_client(&self, client_id: &str) -> Result<Option<OAuthClient>> {
        let clients = self
            .clients
            .lock()
            .map_err(|e| StorageError::SerializationFailed(format!("Lock error: {}", e)))?;
        Ok(clients.get(client_id).cloned())
    }

    async fn update_client(&self, client: &OAuthClient) -> Result<()> {
        let mut clients = self
            .clients
            .lock()
            .map_err(|e| StorageError::SerializationFailed(format!("Lock error: {}", e)))?;
        if clients.contains_key(&client.client_id) {
            clients.insert(client.client_id.clone(), client.clone());
            Ok(())
        } else {
            Err(StorageError::QueryFailed("Client not found".to_string()))
        }
    }

    async fn delete_client(&self, client_id: &str) -> Result<()> {
        let mut clients = self
            .clients
            .lock()
            .map_err(|e| StorageError::SerializationFailed(format!("Lock error: {}", e)))?;
        clients.remove(client_id);
        Ok(())
    }

    async fn list_clients(&self, limit: Option<usize>) -> Result<Vec<OAuthClient>> {
        let clients = self
            .clients
            .lock()
            .map_err(|e| StorageError::SerializationFailed(format!("Lock error: {}", e)))?;
        let mut result: Vec<_> = clients.values().cloned().collect();
        if let Some(limit) = limit {
            result.truncate(limit);
        }
        Ok(result)
    }
}

#[async_trait]
impl AuthorizationCodeStore for MemoryOAuthStorage {
    async fn store_code(&self, code: &AuthorizationCode) -> Result<()> {
        let mut codes = self
            .auth_codes
            .lock()
            .map_err(|e| StorageError::SerializationFailed(format!("Lock error: {}", e)))?;
        codes.insert(code.code.clone(), code.clone());
        Ok(())
    }

    async fn consume_code(&self, code: &str) -> Result<Option<AuthorizationCode>> {
        let mut codes = self
            .auth_codes
            .lock()
            .map_err(|e| StorageError::SerializationFailed(format!("Lock error: {}", e)))?;

        if let Some(mut auth_code) = codes.get(code).cloned() {
            // Check if code is expired
            if auth_code.expires_at < Utc::now() {
                codes.remove(code);
                return Ok(None);
            }

            // Check if code is already used
            if auth_code.used {
                codes.remove(code);
                return Ok(None);
            }

            // Mark as used and update
            auth_code.used = true;
            codes.insert(code.to_string(), auth_code.clone());

            Ok(Some(auth_code))
        } else {
            Ok(None)
        }
    }

    async fn cleanup_expired_codes(&self) -> Result<usize> {
        let mut codes = self
            .auth_codes
            .lock()
            .map_err(|e| StorageError::SerializationFailed(format!("Lock error: {}", e)))?;

        let now = Utc::now();
        let initial_count = codes.len();
        codes.retain(|_, code| code.expires_at > now);

        Ok(initial_count - codes.len())
    }
}

#[async_trait]
impl AccessTokenStore for MemoryOAuthStorage {
    async fn store_token(&self, token: &AccessToken) -> Result<()> {
        let mut tokens = self
            .access_tokens
            .lock()
            .map_err(|e| StorageError::SerializationFailed(format!("Lock error: {}", e)))?;
        tokens.insert(token.token.clone(), token.clone());
        Ok(())
    }

    async fn get_token(&self, token: &str) -> Result<Option<AccessToken>> {
        let tokens = self
            .access_tokens
            .lock()
            .map_err(|e| StorageError::SerializationFailed(format!("Lock error: {}", e)))?;

        if let Some(access_token) = tokens.get(token) {
            // Check if token is expired
            if access_token.expires_at < Utc::now() {
                return Ok(None);
            }
            Ok(Some(access_token.clone()))
        } else {
            Ok(None)
        }
    }

    async fn revoke_token(&self, token: &str) -> Result<()> {
        let mut tokens = self
            .access_tokens
            .lock()
            .map_err(|e| StorageError::SerializationFailed(format!("Lock error: {}", e)))?;
        tokens.remove(token);
        Ok(())
    }

    async fn cleanup_expired_tokens(&self) -> Result<usize> {
        let mut tokens = self
            .access_tokens
            .lock()
            .map_err(|e| StorageError::SerializationFailed(format!("Lock error: {}", e)))?;

        let now = Utc::now();
        let initial_count = tokens.len();
        tokens.retain(|_, token| token.expires_at > now);

        Ok(initial_count - tokens.len())
    }

    async fn get_user_tokens(&self, user_id: &str) -> Result<Vec<AccessToken>> {
        let tokens = self
            .access_tokens
            .lock()
            .map_err(|e| StorageError::SerializationFailed(format!("Lock error: {}", e)))?;

        let now = Utc::now();
        let result: Vec<_> = tokens
            .values()
            .filter(|token| {
                token.user_id.as_ref() == Some(&user_id.to_string()) && token.expires_at > now
            })
            .cloned()
            .collect();

        Ok(result)
    }

    async fn get_client_tokens(&self, client_id: &str) -> Result<Vec<AccessToken>> {
        let tokens = self
            .access_tokens
            .lock()
            .map_err(|e| StorageError::SerializationFailed(format!("Lock error: {}", e)))?;

        let now = Utc::now();
        let result: Vec<_> = tokens
            .values()
            .filter(|token| token.client_id == client_id && token.expires_at > now)
            .cloned()
            .collect();

        Ok(result)
    }
}

#[async_trait]
impl RefreshTokenStore for MemoryOAuthStorage {
    async fn store_refresh_token(&self, token: &RefreshToken) -> Result<()> {
        let mut tokens = self
            .refresh_tokens
            .lock()
            .map_err(|e| StorageError::SerializationFailed(format!("Lock error: {}", e)))?;
        tokens.insert(token.token.clone(), token.clone());
        Ok(())
    }

    async fn consume_refresh_token(&self, token: &str) -> Result<Option<RefreshToken>> {
        let mut tokens = self
            .refresh_tokens
            .lock()
            .map_err(|e| StorageError::SerializationFailed(format!("Lock error: {}", e)))?;

        if let Some(refresh_token) = tokens.remove(token) {
            // Check if token is expired (if it has an expiry)
            if let Some(expires_at) = refresh_token.expires_at {
                if expires_at < Utc::now() {
                    return Ok(None);
                }
            }
            Ok(Some(refresh_token))
        } else {
            Ok(None)
        }
    }

    async fn cleanup_expired_refresh_tokens(&self) -> Result<usize> {
        let mut tokens = self
            .refresh_tokens
            .lock()
            .map_err(|e| StorageError::SerializationFailed(format!("Lock error: {}", e)))?;

        let now = Utc::now();
        let initial_count = tokens.len();
        tokens.retain(|_, token| token.expires_at.is_none_or(|expires_at| expires_at > now));

        Ok(initial_count - tokens.len())
    }
}

#[async_trait]
impl KeyStore for MemoryOAuthStorage {
    async fn store_signing_key(&self, key: &KeyData) -> Result<()> {
        let mut signing_key = self.signing_key.lock().unwrap();
        *signing_key = Some(key.clone());
        Ok(())
    }

    async fn get_signing_key(&self) -> Result<Option<KeyData>> {
        let signing_key = self.signing_key.lock().unwrap();
        Ok(signing_key.clone())
    }

    async fn store_key(&self, key_id: &str, key: &KeyData) -> Result<()> {
        let mut keys = self.keys.lock().unwrap();
        // Use KeyData string serialization for storage
        keys.insert(key_id.to_string(), key.to_string());
        Ok(())
    }

    async fn get_key(&self, key_id: &str) -> Result<Option<KeyData>> {
        use atproto_identity::key::identify_key;

        let keys = self.keys.lock().unwrap();
        if let Some(key_str) = keys.get(key_id) {
            // Deserialize KeyData from string
            match identify_key(key_str) {
                Ok(key_data) => Ok(Some(key_data)),
                Err(e) => Err(StorageError::SerializationFailed(format!(
                    "Failed to deserialize key: {}",
                    e
                ))),
            }
        } else {
            Ok(None)
        }
    }

    async fn list_key_ids(&self) -> Result<Vec<String>> {
        let keys = self.keys.lock().unwrap();
        Ok(keys.keys().cloned().collect())
    }
}

#[async_trait]
impl PARStorage for MemoryOAuthStorage {
    async fn store_par_request(&self, request: &StoredPushedRequest) -> Result<()> {
        let mut par_requests = self
            .par_requests
            .lock()
            .map_err(|e| StorageError::SerializationFailed(format!("Lock error: {}", e)))?;
        par_requests.insert(request.request_uri.clone(), request.clone());
        Ok(())
    }

    async fn get_par_request(&self, request_uri: &str) -> Result<Option<StoredPushedRequest>> {
        let par_requests = self
            .par_requests
            .lock()
            .map_err(|e| StorageError::SerializationFailed(format!("Lock error: {}", e)))?;
        Ok(par_requests.get(request_uri).cloned())
    }

    async fn consume_par_request(&self, request_uri: &str) -> Result<Option<StoredPushedRequest>> {
        let mut par_requests = self
            .par_requests
            .lock()
            .map_err(|e| StorageError::SerializationFailed(format!("Lock error: {}", e)))?;
        Ok(par_requests.remove(request_uri))
    }

    async fn cleanup_expired_par_requests(&self) -> Result<usize> {
        let mut par_requests = self
            .par_requests
            .lock()
            .map_err(|e| StorageError::SerializationFailed(format!("Lock error: {}", e)))?;

        let now = Utc::now();
        let initial_count = par_requests.len();

        par_requests.retain(|_, request| request.expires_at > now);

        Ok(initial_count - par_requests.len())
    }
}

#[async_trait]
impl AtpOAuthSessionStorage for MemoryOAuthStorage {
    async fn store_session(&self, session: &AtpOAuthSession) -> Result<()> {
        let mut sessions = self.atp_sessions.write().await;
        let mut state_index = self.atp_state_index.write().await;
        let mut session_iterations = self.atp_session_iterations.write().await;

        let session_key = Self::session_key(&session.session_id, session.iteration);
        let index_key = session
            .did
            .as_ref()
            .map(|did| Self::session_index_key(did, &session.session_id));

        // Store the session
        sessions.insert(session_key.clone(), session.clone());

        // Update state index
        state_index.insert(session.atp_oauth_state.clone(), session_key);

        // Update iterations index if DID is present
        if let Some(index_key) = index_key {
            let iterations = session_iterations.entry(index_key).or_insert_with(Vec::new);
            if !iterations.contains(&session.iteration) {
                iterations.push(session.iteration);
                iterations.sort_by(|a, b| b.cmp(a)); // Sort highest to lowest
            }
        }

        Ok(())
    }

    async fn get_sessions(&self, did: &str, session_id: &str) -> Result<Vec<AtpOAuthSession>> {
        let sessions = self.atp_sessions.read().await;
        let session_iterations = self.atp_session_iterations.read().await;

        let index_key = Self::session_index_key(did, session_id);

        if let Some(iterations) = session_iterations.get(&index_key) {
            let mut result = Vec::new();
            for &iteration in iterations {
                let session_key = Self::session_key(session_id, iteration);
                if let Some(session) = sessions.get(&session_key) {
                    result.push(session.clone());
                }
            }
            Ok(result)
        } else {
            Ok(Vec::new())
        }
    }

    async fn get_session(
        &self,
        _did: &str,
        session_id: &str,
        iteration: u32,
    ) -> Result<Option<AtpOAuthSession>> {
        let sessions = self.atp_sessions.read().await;
        let session_key = Self::session_key(session_id, iteration);
        Ok(sessions.get(&session_key).cloned())
    }

    async fn get_latest_session(
        &self,
        _did: &str,
        session_id: &str,
    ) -> Result<Option<AtpOAuthSession>> {
        let sessions = self.get_sessions(_did, session_id).await?;
        Ok(sessions.into_iter().next()) // Already sorted highest to lowest
    }

    async fn update_session(&self, session: &AtpOAuthSession) -> Result<()> {
        let mut sessions = self.atp_sessions.write().await;
        let session_key = Self::session_key(&session.session_id, session.iteration);

        if let std::collections::hash_map::Entry::Occupied(mut e) = sessions.entry(session_key) {
            e.insert(session.clone());
            Ok(())
        } else {
            Err(StorageError::QueryFailed("Session not found".to_string()))
        }
    }

    async fn get_session_by_atp_state(&self, atp_state: &str) -> Result<Option<AtpOAuthSession>> {
        let state_index = self.atp_state_index.read().await;
        if let Some(session_key) = state_index.get(atp_state) {
            let sessions = self.atp_sessions.read().await;
            Ok(sessions.get(session_key).cloned())
        } else {
            Ok(None)
        }
    }

    async fn update_session_tokens(
        &self,
        _did: &str,
        session_id: &str,
        iteration: u32,
        access_token: Option<String>,
        refresh_token: Option<String>,
        access_token_created_at: Option<chrono::DateTime<chrono::Utc>>,
        access_token_expires_at: Option<chrono::DateTime<chrono::Utc>>,
        access_token_scopes: Option<Vec<String>>,
    ) -> Result<()> {
        let mut sessions = self.atp_sessions.write().await;
        let session_key = Self::session_key(session_id, iteration);
        if let Some(session) = sessions.get_mut(&session_key) {
            session.access_token = access_token;
            session.refresh_token = refresh_token;
            session.access_token_created_at = access_token_created_at;
            session.access_token_expires_at = access_token_expires_at;
            session.access_token_scopes = access_token_scopes;
            Ok(())
        } else {
            Err(StorageError::QueryFailed("Session not found".to_string()))
        }
    }

    async fn remove_session(&self, did: &str, session_id: &str, iteration: u32) -> Result<()> {
        let mut sessions = self.atp_sessions.write().await;
        let mut state_index = self.atp_state_index.write().await;
        let mut session_iterations = self.atp_session_iterations.write().await;

        let session_key = Self::session_key(session_id, iteration);
        let index_key = Self::session_index_key(did, session_id);

        if let Some(session) = sessions.remove(&session_key) {
            // Remove from state index
            state_index.remove(&session.atp_oauth_state);

            // Remove iteration from the iterations list
            if let Some(iterations) = session_iterations.get_mut(&index_key) {
                iterations.retain(|&i| i != iteration);
                // If no more iterations, remove the entire entry
                if iterations.is_empty() {
                    session_iterations.remove(&index_key);
                }
            }
        }

        Ok(())
    }

    async fn cleanup_old_sessions(
        &self,
        older_than: chrono::DateTime<chrono::Utc>,
    ) -> Result<usize> {
        let mut sessions = self.atp_sessions.write().await;
        let mut state_index = self.atp_state_index.write().await;
        let mut session_iterations = self.atp_session_iterations.write().await;

        let initial_count = sessions.len();
        let mut sessions_to_remove = Vec::new();

        // Find sessions to remove
        for (key, session) in sessions.iter() {
            if session.session_created_at < older_than {
                sessions_to_remove.push((key.clone(), session.clone()));
            }
        }

        // Remove sessions and update indices
        for (key, session) in sessions_to_remove.iter() {
            sessions.remove(key);
            state_index.remove(&session.atp_oauth_state);

            if let Some(did) = session.did.as_ref() {
                let index_key = Self::session_index_key(did, &session.session_id);
                if let Some(iterations) = session_iterations.get_mut(&index_key) {
                    iterations.retain(|&i| i != session.iteration);
                    if iterations.is_empty() {
                        session_iterations.remove(&index_key);
                    }
                }
            }
        }

        Ok(initial_count - sessions.len())
    }
}

#[async_trait]
impl AuthorizationRequestStorage for MemoryOAuthStorage {
    async fn store_authorization_request(
        &self,
        session_id: &str,
        request: &AuthorizationRequest,
    ) -> Result<()> {
        let mut requests = self.auth_requests.write().await;
        requests.insert(session_id.to_string(), request.clone());
        Ok(())
    }

    async fn get_authorization_request(
        &self,
        session_id: &str,
    ) -> Result<Option<AuthorizationRequest>> {
        let requests = self.auth_requests.read().await;
        Ok(requests.get(session_id).cloned())
    }

    async fn remove_authorization_request(&self, session_id: &str) -> Result<()> {
        let mut requests = self.auth_requests.write().await;
        requests.remove(session_id);
        Ok(())
    }
}

#[async_trait]
impl AppPasswordStore for MemoryOAuthStorage {
    async fn store_app_password(&self, app_password: &AppPassword) -> Result<()> {
        let mut passwords = self.app_passwords.write().await;
        let key = Self::app_password_key(&app_password.client_id, &app_password.did);
        passwords.insert(key, app_password.clone());
        Ok(())
    }

    async fn get_app_password(&self, client_id: &str, did: &str) -> Result<Option<AppPassword>> {
        let passwords = self.app_passwords.read().await;
        let key = Self::app_password_key(client_id, did);
        Ok(passwords.get(&key).cloned())
    }

    async fn delete_app_password(&self, client_id: &str, did: &str) -> Result<()> {
        let mut passwords = self.app_passwords.write().await;
        let key = Self::app_password_key(client_id, did);
        passwords.remove(&key);

        // Also delete all associated sessions
        let mut sessions = self.app_password_sessions.write().await;
        sessions.remove(&key);

        Ok(())
    }

    async fn list_app_passwords_by_did(&self, did: &str) -> Result<Vec<AppPassword>> {
        let passwords = self.app_passwords.read().await;
        let result: Vec<_> = passwords
            .values()
            .filter(|p| p.did == did)
            .cloned()
            .collect();
        Ok(result)
    }

    async fn list_app_passwords_by_client(&self, client_id: &str) -> Result<Vec<AppPassword>> {
        let passwords = self.app_passwords.read().await;
        let result: Vec<_> = passwords
            .values()
            .filter(|p| p.client_id == client_id)
            .cloned()
            .collect();
        Ok(result)
    }
}

#[async_trait]
impl AppPasswordSessionStore for MemoryOAuthStorage {
    async fn store_app_password_session(&self, session: &AppPasswordSession) -> Result<()> {
        let mut sessions = self.app_password_sessions.write().await;
        let key = Self::app_password_key(&session.client_id, &session.did);
        sessions.insert(key, session.clone());
        Ok(())
    }

    async fn get_app_password_session(
        &self,
        client_id: &str,
        _did: &str,
    ) -> Result<Option<AppPasswordSession>> {
        let sessions = self.app_password_sessions.read().await;
        let key = Self::app_password_key(client_id, _did);
        Ok(sessions.get(&key).cloned())
    }

    async fn update_app_password_session(&self, session: &AppPasswordSession) -> Result<()> {
        let mut sessions = self.app_password_sessions.write().await;
        let key = Self::app_password_key(&session.client_id, &session.did);

        if let std::collections::hash_map::Entry::Occupied(mut e) = sessions.entry(key) {
            e.insert(session.clone());
            Ok(())
        } else {
            Err(StorageError::QueryFailed(
                "App password session not found".to_string(),
            ))
        }
    }

    async fn delete_app_password_sessions(&self, client_id: &str, did: &str) -> Result<()> {
        let mut sessions = self.app_password_sessions.write().await;
        let key = Self::app_password_key(client_id, did);
        sessions.remove(&key);
        Ok(())
    }

    async fn list_app_password_sessions_by_did(
        &self,
        _did: &str,
    ) -> Result<Vec<AppPasswordSession>> {
        let sessions = self.app_password_sessions.read().await;
        let result: Vec<_> = sessions
            .values()
            .filter(|s| s.did == _did)
            .cloned()
            .collect();
        Ok(result)
    }

    async fn list_app_password_sessions_by_client(
        &self,
        client_id: &str,
    ) -> Result<Vec<AppPasswordSession>> {
        let sessions = self.app_password_sessions.read().await;
        let result: Vec<_> = sessions
            .values()
            .filter(|s| s.client_id == client_id)
            .cloned()
            .collect();
        Ok(result)
    }
}

impl OAuthStorage for MemoryOAuthStorage {}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Duration;

    #[tokio::test]
    async fn test_authorization_code_lifecycle() {
        let storage = MemoryOAuthStorage::new();

        let code = AuthorizationCode {
            code: "test-code".to_string(),
            client_id: "test-client".to_string(),
            user_id: "test-user".to_string(),
            redirect_uri: "https://example.com/callback".to_string(),
            scope: Some("read".to_string()),
            code_challenge: None,
            code_challenge_method: None,
            nonce: None,
            created_at: Utc::now(),
            expires_at: Utc::now() + Duration::minutes(10),
            used: false,
            session_id: None,
        };

        // Store code
        storage.store_code(&code).await.unwrap();

        // Consume code (should work first time)
        let consumed = storage.consume_code("test-code").await.unwrap().unwrap();
        assert!(consumed.used);

        // Try to consume again (should fail)
        let consumed_again = storage.consume_code("test-code").await.unwrap();
        assert!(consumed_again.is_none());
    }

    #[tokio::test]
    async fn test_token_expiry() {
        let storage = MemoryOAuthStorage::new();

        let token = AccessToken {
            token: "test-token".to_string(),
            token_type: TokenType::Bearer,
            client_id: "test-client".to_string(),
            user_id: Some("test-user".to_string()),
            session_id: None,
            session_iteration: None,
            scope: Some("read".to_string()),
            created_at: Utc::now(),
            expires_at: Utc::now() - Duration::minutes(1), // Expired
            dpop_jkt: None,
            nonce: None,
        };

        // Store expired token
        storage.store_token(&token).await.unwrap();

        // Try to retrieve (should return None for expired token)
        let retrieved = storage.get_token("test-token").await.unwrap();
        assert!(retrieved.is_none());
    }

    #[tokio::test]
    async fn test_key_storage() {
        use atproto_identity::key::{KeyType, generate_key};

        let storage = MemoryOAuthStorage::new();

        // Generate test keys
        let p256_key = generate_key(KeyType::P256Private).unwrap();
        let k256_key = generate_key(KeyType::K256Private).unwrap();

        // Test signing key storage
        storage.store_signing_key(&p256_key).await.unwrap();
        let retrieved_signing_key = storage.get_signing_key().await.unwrap().unwrap();
        assert_eq!(p256_key.to_string(), retrieved_signing_key.to_string());

        // Test general key storage
        storage.store_key("p256-test", &p256_key).await.unwrap();
        storage.store_key("k256-test", &k256_key).await.unwrap();

        let retrieved_p256 = storage.get_key("p256-test").await.unwrap().unwrap();
        let retrieved_k256 = storage.get_key("k256-test").await.unwrap().unwrap();

        assert_eq!(p256_key.to_string(), retrieved_p256.to_string());
        assert_eq!(k256_key.to_string(), retrieved_k256.to_string());

        // Test key listing
        let key_ids = storage.list_key_ids().await.unwrap();
        assert!(key_ids.contains(&"p256-test".to_string()));
        assert!(key_ids.contains(&"k256-test".to_string()));
        assert_eq!(key_ids.len(), 2);

        // Test non-existent key
        let non_existent = storage.get_key("non-existent").await.unwrap();
        assert!(non_existent.is_none());
    }

    #[tokio::test]
    async fn test_key_type_validation() {
        use atproto_identity::key::{KeyType, generate_key, to_public};

        let storage = MemoryOAuthStorage::new();

        // Test both private and public key storage
        let private_key = generate_key(KeyType::P256Private).unwrap();
        let public_key = to_public(&private_key).unwrap();

        storage.store_key("private", &private_key).await.unwrap();
        storage.store_key("public", &public_key).await.unwrap();

        let retrieved_private = storage.get_key("private").await.unwrap().unwrap();
        let retrieved_public = storage.get_key("public").await.unwrap().unwrap();

        // Verify key types
        assert_eq!(*retrieved_private.key_type(), KeyType::P256Private);
        assert_eq!(*retrieved_public.key_type(), KeyType::P256Public);
    }

    #[tokio::test]
    async fn test_keydata_string_serialization() {
        use atproto_identity::key::{KeyType, generate_key, identify_key};

        let storage = MemoryOAuthStorage::new();

        // Test P-256 key serialization/deserialization
        let p256_key = generate_key(KeyType::P256Private).unwrap();
        let p256_string = p256_key.to_string();

        storage.store_key("p256-test", &p256_key).await.unwrap();
        let retrieved_p256 = storage.get_key("p256-test").await.unwrap().unwrap();

        // Verify the key round-trips correctly
        assert_eq!(p256_key.to_string(), retrieved_p256.to_string());
        assert_eq!(*p256_key.key_type(), *retrieved_p256.key_type());

        // Test K-256 key serialization/deserialization
        let k256_key = generate_key(KeyType::K256Private).unwrap();
        let k256_string = k256_key.to_string();

        storage.store_key("k256-test", &k256_key).await.unwrap();
        let retrieved_k256 = storage.get_key("k256-test").await.unwrap().unwrap();

        // Verify the key round-trips correctly
        assert_eq!(k256_key.to_string(), retrieved_k256.to_string());
        assert_eq!(*k256_key.key_type(), *retrieved_k256.key_type());

        // Test that identify_key can parse the stored string formats
        let parsed_p256 = identify_key(&p256_string).unwrap();
        let parsed_k256 = identify_key(&k256_string).unwrap();

        assert_eq!(*parsed_p256.key_type(), KeyType::P256Private);
        assert_eq!(*parsed_k256.key_type(), KeyType::K256Private);
    }

    #[tokio::test]
    async fn test_keydata_error_handling() {
        use atproto_identity::key::{KeyType, generate_key};

        let storage = MemoryOAuthStorage::new();

        // Test retrieval of non-existent key
        let result = storage.get_key("non-existent").await.unwrap();
        assert!(result.is_none());

        // Test storage and retrieval of various key types
        let keys = vec![
            ("p256-private", generate_key(KeyType::P256Private).unwrap()),
            ("k256-private", generate_key(KeyType::K256Private).unwrap()),
        ];

        for (key_id, key) in &keys {
            storage.store_key(key_id, key).await.unwrap();
        }

        // Verify all keys can be retrieved
        for (key_id, original_key) in &keys {
            let retrieved = storage.get_key(key_id).await.unwrap().unwrap();
            assert_eq!(original_key.to_string(), retrieved.to_string());
            assert_eq!(*original_key.key_type(), *retrieved.key_type());
        }

        // Test key ID listing
        let key_ids = storage.list_key_ids().await.unwrap();
        assert_eq!(key_ids.len(), 2);
        assert!(key_ids.contains(&"p256-private".to_string()));
        assert!(key_ids.contains(&"k256-private".to_string()));
    }

    #[tokio::test]
    async fn test_signing_key_storage() {
        use atproto_identity::key::{KeyType, generate_key, to_public};

        let storage = MemoryOAuthStorage::new();

        // Initially no signing key
        let initial = storage.get_signing_key().await.unwrap();
        assert!(initial.is_none());

        // Store a P-256 signing key
        let private_key = generate_key(KeyType::P256Private).unwrap();
        storage.store_signing_key(&private_key).await.unwrap();

        // Retrieve and verify
        let retrieved = storage.get_signing_key().await.unwrap().unwrap();
        assert_eq!(private_key.to_string(), retrieved.to_string());
        assert_eq!(*private_key.key_type(), KeyType::P256Private);

        // Test that we can derive the public key from stored private key
        let public_key = to_public(&retrieved).unwrap();
        assert_eq!(*public_key.key_type(), KeyType::P256Public);

        // Store the derived public key and verify it's different
        storage
            .store_key("derived-public", &public_key)
            .await
            .unwrap();
        let stored_public = storage.get_key("derived-public").await.unwrap().unwrap();
        assert_eq!(public_key.to_string(), stored_public.to_string());
        assert_ne!(private_key.to_string(), stored_public.to_string());
    }

    #[tokio::test]
    async fn test_client_storage() {
        let storage = MemoryOAuthStorage::new();

        let client = OAuthClient {
            client_id: "test-client".to_string(),
            client_secret: Some("secret".to_string()),
            client_name: Some("Test Client".to_string()),
            redirect_uris: vec!["https://example.com/callback".to_string()],
            grant_types: vec![GrantType::AuthorizationCode],
            response_types: vec![ResponseType::Code],
            scope: Some("read write".to_string()),
            token_endpoint_auth_method: ClientAuthMethod::ClientSecretBasic,
            client_type: ClientType::Confidential,
            created_at: Utc::now(),
            updated_at: Utc::now(),
            metadata: serde_json::Value::Null,
            access_token_expiration: chrono::Duration::days(1),
            refresh_token_expiration: chrono::Duration::days(14),
            require_redirect_exact: true,
            registration_access_token: Some("test-registration-token".to_string()),
        };

        // Store client
        storage.store_client(&client).await.unwrap();

        // Retrieve client
        let retrieved = storage.get_client("test-client").await.unwrap().unwrap();
        assert_eq!(retrieved.client_id, client.client_id);

        // List clients
        let clients = storage.list_clients(None).await.unwrap();
        assert_eq!(clients.len(), 1);
    }
}
