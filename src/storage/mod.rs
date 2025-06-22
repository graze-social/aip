//! Trait-based storage abstractions with in-memory, SQLite, and PostgreSQL backends.

pub mod inmemory;
pub mod key_provider;
pub mod traits;

// Feature-gated storage implementations
#[cfg(feature = "sqlite")]
pub mod sqlite;

#[cfg(feature = "postgres")]
pub mod postgres;

// Re-export commonly used types and traits
pub use inmemory::{MemoryNonceStorage, MemoryOAuthStorage};
pub use key_provider::SimpleKeyProvider;
pub use traits::*;

#[cfg(feature = "postgres")]
pub use postgres::{PostgresOAuthRequestStorage, PostgresOAuthStorage};

use crate::errors::StorageError;
use std::sync::Arc;

/// Storage backend configuration and factory
#[derive(Clone)]
pub enum StorageBackend {
    Memory,
    #[cfg(feature = "sqlite")]
    Sqlite(String), // Connection string/path
    #[cfg(feature = "postgres")]
    Postgres(String), // Connection string
}

/// Create a storage backend based on configuration
pub async fn create_storage_backend(
    backend: StorageBackend,
) -> std::result::Result<Arc<dyn OAuthStorage>, StorageError> {
    match backend {
        StorageBackend::Memory => Ok(Arc::new(MemoryOAuthStorage::new())),
        #[cfg(feature = "sqlite")]
        StorageBackend::Sqlite(database_url) => {
            let pool = sqlx::SqlitePool::connect(&database_url)
                .await
                .map_err(|e| {
                    StorageError::ConnectionFailed(format!("SQLite connection failed: {}", e))
                })?;

            let storage = sqlite::SqliteOAuthStorage::new(pool);

            // Run migrations
            storage.migrate().await?;

            Ok(Arc::new(storage))
        }
        #[cfg(feature = "postgres")]
        StorageBackend::Postgres(database_url) => {
            let pool = sqlx::postgres::PgPool::connect(&database_url)
                .await
                .map_err(|e| {
                    StorageError::ConnectionFailed(format!("PostgreSQL connection failed: {}", e))
                })?;

            let storage = postgres::PostgresOAuthStorage::new(pool);

            // Run migrations
            storage.migrate().await?;

            Ok(Arc::new(storage))
        }
    }
}

/// Parse storage backend from configuration string
pub fn parse_storage_backend(
    backend_name: &str,
    database_url: Option<&str>,
) -> std::result::Result<StorageBackend, StorageError> {
    match backend_name {
        "memory" => Ok(StorageBackend::Memory),
        #[cfg(feature = "sqlite")]
        "sqlite" => {
            let url = database_url.unwrap_or("sqlite:aip.db");
            Ok(StorageBackend::Sqlite(url.to_string()))
        }
        #[cfg(feature = "postgres")]
        "postgres" => {
            let url = database_url.ok_or_else(|| {
                StorageError::InvalidData("DATABASE_URL required for postgres backend".to_string())
            })?;
            Ok(StorageBackend::Postgres(url.to_string()))
        }
        _ => Err(StorageError::InvalidData(format!(
            "Unknown storage backend: {}",
            backend_name
        ))),
    }
}
