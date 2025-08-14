//! In-memory ATProtocol storage implementations
//!
//! This module provides in-memory implementations for ATProtocol-related storage traits.

use crate::errors::StorageError;
use crate::oauth::types::AuthorizationRequest;
use crate::storage::traits::*;
use async_trait::async_trait;
use chrono::{DateTime, Utc};
use std::collections::HashMap;

pub type Result<T> = std::result::Result<T, StorageError>;

/// In-memory implementation for ATProtocol OAuth session storage
#[derive(Default)]
pub struct MemoryAtpOAuthSessionStorage {
    sessions: tokio::sync::RwLock<HashMap<String, AtpOAuthSession>>, // session_key -> session
    state_index: tokio::sync::RwLock<HashMap<String, String>>,       // atp_state -> session_key
    session_iterations: tokio::sync::RwLock<HashMap<String, Vec<u32>>>, // (did, session_id) -> iterations
}

impl MemoryAtpOAuthSessionStorage {
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
}

#[async_trait]
impl AtpOAuthSessionStorage for MemoryAtpOAuthSessionStorage {
    async fn store_session(&self, session: &AtpOAuthSession) -> Result<()> {
        let mut sessions = self.sessions.write().await;
        let mut state_index = self.state_index.write().await;
        let mut session_iterations = self.session_iterations.write().await;

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
        let sessions = self.sessions.read().await;
        let session_iterations = self.session_iterations.read().await;

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
        let sessions = self.sessions.read().await;
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
        let mut sessions = self.sessions.write().await;
        let session_key = Self::session_key(&session.session_id, session.iteration);

        if let std::collections::hash_map::Entry::Occupied(mut e) = sessions.entry(session_key) {
            e.insert(session.clone());
            Ok(())
        } else {
            Err(StorageError::QueryFailed("Session not found".to_string()))
        }
    }

    async fn get_session_by_atp_state(&self, atp_state: &str) -> Result<Option<AtpOAuthSession>> {
        let state_index = self.state_index.read().await;
        if let Some(session_key) = state_index.get(atp_state) {
            let sessions = self.sessions.read().await;
            Ok(sessions.get(session_key).cloned())
        } else {
            Ok(None)
        }
    }


    async fn get_sessions_by_did(&self, did: &str) -> Result<Vec<AtpOAuthSession>> {
        let sessions = self.sessions.read().await;

        let mut result: Vec<AtpOAuthSession> = sessions
            .values()
            .filter(|s| s.did.as_ref().map(|d| d.as_str()) == Some(did))
            .cloned()
            .collect();

        // Sort by creation time, newest first
        result.sort_by(|a, b| b.session_created_at.cmp(&a.session_created_at));
        Ok(result)
    }

    async fn update_session_tokens(
        &self,
        _did: &str,
        session_id: &str,
        iteration: u32,
        access_token: Option<String>,
        refresh_token: Option<String>,
        access_token_created_at: Option<DateTime<Utc>>,
        access_token_expires_at: Option<DateTime<Utc>>,
        access_token_scopes: Option<Vec<String>>,
    ) -> Result<()> {
        let mut sessions = self.sessions.write().await;
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
        let mut sessions = self.sessions.write().await;
        let mut state_index = self.state_index.write().await;
        let mut session_iterations = self.session_iterations.write().await;

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

    async fn cleanup_old_sessions(&self, older_than: DateTime<Utc>) -> Result<usize> {
        let mut sessions = self.sessions.write().await;
        let mut state_index = self.state_index.write().await;
        let mut session_iterations = self.session_iterations.write().await;

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

/// In-memory implementation for authorization request storage
#[derive(Default)]
pub struct MemoryAuthorizationRequestStorage {
    requests: tokio::sync::RwLock<HashMap<String, AuthorizationRequest>>,
}

impl MemoryAuthorizationRequestStorage {
    pub fn new() -> Self {
        Self::default()
    }
}

#[async_trait]
impl AuthorizationRequestStorage for MemoryAuthorizationRequestStorage {
    async fn store_authorization_request(
        &self,
        session_id: &str,
        request: &AuthorizationRequest,
    ) -> Result<()> {
        let mut requests = self.requests.write().await;
        requests.insert(session_id.to_string(), request.clone());
        Ok(())
    }

    async fn get_authorization_request(
        &self,
        session_id: &str,
    ) -> Result<Option<AuthorizationRequest>> {
        let requests = self.requests.read().await;
        Ok(requests.get(session_id).cloned())
    }

    async fn remove_authorization_request(&self, session_id: &str) -> Result<()> {
        let mut requests = self.requests.write().await;
        requests.remove(session_id);
        Ok(())
    }
}
