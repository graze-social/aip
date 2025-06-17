//! In-memory key provider for ATProtocol identity operations.

use async_trait::async_trait;
use atproto_identity::key::{KeyData, KeyProvider};
use std::collections::HashMap;

#[derive(Clone)]
pub struct SimpleKeyProvider {
    keys: HashMap<String, KeyData>,
}

impl Default for SimpleKeyProvider {
    fn default() -> Self {
        Self::new()
    }
}

impl SimpleKeyProvider {
    pub fn new() -> Self {
        Self {
            keys: HashMap::new(),
        }
    }
}

#[async_trait]
impl KeyProvider for SimpleKeyProvider {
    async fn get_private_key_by_id(&self, key_id: &str) -> anyhow::Result<Option<KeyData>> {
        Ok(self.keys.get(key_id).cloned())
    }
}
