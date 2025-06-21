//! In-memory nonce storage implementation
//!
//! This module provides in-memory storage for DPoP nonces to prevent replay attacks.
//! Nonces are stored with their timestamps for expiration checking.

use crate::errors::DPoPError;
use crate::storage::traits::NonceStorage;
use async_trait::async_trait;
use std::collections::HashMap;
use std::sync::Mutex;
use time::OffsetDateTime;

/// In-memory nonce store (for testing/development)
#[derive(Default)]
pub struct MemoryNonceStorage {
    nonces: Mutex<HashMap<String, OffsetDateTime>>,
}

impl MemoryNonceStorage {
    /// Create a new memory nonce storage
    pub fn new() -> Self {
        Self::default()
    }
}

#[async_trait]
impl NonceStorage for MemoryNonceStorage {
    async fn check_and_use_nonce(
        &self,
        nonce: &str,
        expiry: OffsetDateTime,
    ) -> Result<bool, DPoPError> {
        let mut nonces = self.nonces.lock().map_err(|e| {
            DPoPError::InvalidProof(format!("Failed to acquire nonce store lock: {}", e))
        })?;

        if nonces.contains_key(nonce) {
            return Ok(false); // Nonce already used
        }

        nonces.insert(nonce.to_string(), expiry);
        Ok(true)
    }

    async fn cleanup_expired(&self) -> Result<(), DPoPError> {
        let mut nonces = self.nonces.lock().map_err(|e| {
            DPoPError::InvalidProof(format!("Failed to acquire nonce store lock: {}", e))
        })?;

        let now = OffsetDateTime::now_utc();
        nonces.retain(|_, expiry| *expiry > now);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use time::Duration;

    #[tokio::test]
    async fn test_nonce_store() {
        let store = MemoryNonceStorage::new();
        let nonce = "test-nonce";
        let expiry = OffsetDateTime::now_utc() + Duration::minutes(5);

        // First use should succeed
        assert!(store.check_and_use_nonce(nonce, expiry).await.unwrap());

        // Second use should fail (replay attack)
        assert!(!store.check_and_use_nonce(nonce, expiry).await.unwrap());
    }

    #[tokio::test]
    async fn test_cleanup_expired() {
        let store = MemoryNonceStorage::new();
        let nonce = "test-nonce";
        let expired_time = OffsetDateTime::now_utc() - Duration::minutes(1);

        // Add an expired nonce
        store
            .check_and_use_nonce(nonce, expired_time)
            .await
            .unwrap();

        // Cleanup should remove expired nonces
        store.cleanup_expired().await.unwrap();

        // The nonce should be available again after cleanup
        let future_expiry = OffsetDateTime::now_utc() + Duration::minutes(5);
        assert!(
            store
                .check_and_use_nonce(nonce, future_expiry)
                .await
                .unwrap()
        );
    }
}
