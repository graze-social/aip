//! DPoP nonce generation and validation.
//!
//! Generates and validates server nonces for DPoP proofs using rolling 30-second windows.

use async_trait::async_trait;
use chrono::Utc;
use metrohash::MetroHash64;
use std::fmt;
use std::hash::Hasher;
use std::sync::Arc;
use tokio::sync::Mutex;

/// Trait for providing DPoP nonces for validation
#[async_trait]
pub trait DPoPNonceProvider: Send + Sync {
    /// Generate valid nonce values for DPoP validation
    ///
    /// Returns a vector of currently valid nonce strings that can be used
    /// to validate DPoP proofs. The implementation may return multiple values
    /// to support rolling windows or other validation schemes.
    async fn generate_nonces(&self) -> Vec<String>;
}

/// DPoP nonce generator with rolling window support
#[derive(Debug, Clone)]
struct InnerDPoPNonceGenerator {
    /// Seed for nonce generation
    seed: String,

    values: Vec<DPopNonce>,
}

#[derive(Debug, Clone)]
pub struct DPoPNonceGenerator {
    count: usize,
    inner: Arc<Mutex<InnerDPoPNonceGenerator>>,
}

#[derive(Debug, Clone)]
struct DPopNonce(String, i64);

impl fmt::Display for DPopNonce {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut h = MetroHash64::default();
        h.write(self.0.as_bytes());
        h.write(&(self.1).to_be_bytes());
        f.write_str(&crockford::encode(h.finish()))
    }
}

impl DPopNonce {
    fn current(seed: String) -> Self {
        let now: i64 = Utc::now().timestamp();
        let window = (now / 30) * 30;

        Self(seed, window)
    }
}

impl InnerDPoPNonceGenerator {
    // Constructor
    fn new(seed: String) -> Self {
        Self {
            seed: seed.clone(),
            values: vec![DPopNonce::current(seed)],
        }
    }
}

impl DPoPNonceGenerator {
    /// Create a new DPoP nonce generator
    pub fn new(seed: String, count: usize) -> Self {
        Self {
            count,
            inner: Arc::new(Mutex::new(InnerDPoPNonceGenerator::new(seed))),
        }
    }

    pub async fn generate_nonces(&self) -> Vec<String> {
        let mut data = self.inner.lock().await;

        let now: i64 = Utc::now().timestamp();

        // If we don't have any values yet, initialize with the current nonce
        if data.values.is_empty() {
            let current = DPopNonce::current(data.seed.clone());
            data.values.push(current);
        }

        // Check if we need to update nonces based on current time
        if data.values.is_empty() || now >= data.values[0].1 + 30 {
            let current = DPopNonce::current(data.seed.clone());

            // Add the current nonce to the front
            data.values.insert(0, current);

            // Keep only the specified count of nonces
            if data.values.len() > self.count {
                data.values.truncate(self.count);
            }
        }

        data.values.iter().map(|value| value.to_string()).collect()
    }
}

#[async_trait]
impl DPoPNonceProvider for DPoPNonceGenerator {
    async fn generate_nonces(&self) -> Vec<String> {
        self.generate_nonces().await
    }
}
