//! PostgreSQL implementation of DidDocumentStorage trait
//!
//! This module provides PostgreSQL-based storage for ATProtocol DID documents.
//! Documents are stored as JSONB for efficient querying and indexing.

use anyhow::Result;
use async_trait::async_trait;
use atproto_identity::{model::Document, storage::DidDocumentStorage};
use chrono::Utc;
use sqlx::postgres::PgPool;

/// PostgreSQL implementation of DidDocumentStorage
pub struct PostgresDidDocumentStorage {
    pool: PgPool,
}

impl PostgresDidDocumentStorage {
    /// Create a new PostgreSQL DID document storage instance
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }
}

#[async_trait]
impl DidDocumentStorage for PostgresDidDocumentStorage {
    async fn get_document_by_did(&self, did: &str) -> Result<Option<Document>> {
        let row: Option<(serde_json::Value,)> =
            sqlx::query_as("SELECT document FROM did_documents WHERE did = $1")
                .bind(did)
                .fetch_optional(&self.pool)
                .await?;

        if let Some((doc_json,)) = row {
            let document: Document = serde_json::from_value(doc_json)?;
            Ok(Some(document))
        } else {
            Ok(None)
        }
    }

    async fn store_document(&self, document: Document) -> Result<()> {
        let doc_json = serde_json::to_value(&document)?;
        let now = Utc::now();

        sqlx::query(
            r#"
            INSERT INTO did_documents (did, document, created_at, updated_at) 
            VALUES ($1, $2, $3, $3)
            ON CONFLICT (did) 
            DO UPDATE SET 
                document = EXCLUDED.document,
                updated_at = EXCLUDED.updated_at
            "#,
        )
        .bind(&document.id)
        .bind(doc_json)
        .bind(now)
        .execute(&self.pool)
        .await?;

        Ok(())
    }

    async fn delete_document_by_did(&self, did: &str) -> Result<()> {
        sqlx::query("DELETE FROM did_documents WHERE did = $1")
            .bind(did)
            .execute(&self.pool)
            .await?;

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use atproto_identity::model::{Document, Service, VerificationMethod};
    use sqlx::PgPool;
    use std::collections::HashMap;

    async fn setup_test_pool() -> PgPool {
        // This would be used for integration tests with a test database
        // For now, we'll just show the structure
        todo!("Setup test database pool")
    }

    #[tokio::test]
    #[ignore] // Requires test database setup
    async fn test_store_and_retrieve_document() {
        let pool = setup_test_pool().await;
        let storage = PostgresDidDocumentStorage::new(pool);

        let document = Document {
            id: "did:plc:test123".to_string(),
            also_known_as: vec!["at://test.bsky.social".to_string()],
            service: vec![Service {
                id: "#atproto_pds".to_string(),
                r#type: "AtprotoPersonalDataServer".to_string(),
                service_endpoint: "https://test.pds.example.com".to_string(),
                extra: HashMap::new(),
            }],
            verification_method: vec![VerificationMethod::Multikey {
                id: "did:plc:test123#atproto".to_string(),
                controller: "did:plc:test123".to_string(),
                public_key_multibase: "zQ3shXvCK2RyPrSLYQjBEw5CExZkUhJH3n1K2Mb9sC7JbvRMF"
                    .to_string(),
                extra: HashMap::new(),
            }],
            extra: HashMap::new(),
        };

        // Store document
        storage.store_document(document.clone()).await.unwrap();

        // Retrieve document
        let retrieved = storage
            .get_document_by_did("did:plc:test123")
            .await
            .unwrap();
        assert_eq!(retrieved.as_ref().map(|d| &d.id), Some(&document.id));

        // Delete document
        storage
            .delete_document_by_did("did:plc:test123")
            .await
            .unwrap();
        let deleted = storage
            .get_document_by_did("did:plc:test123")
            .await
            .unwrap();
        assert_eq!(deleted, None);
    }

    #[tokio::test]
    #[ignore] // Requires test database setup
    async fn test_update_document() {
        let pool = setup_test_pool().await;
        let storage = PostgresDidDocumentStorage::new(pool);

        let mut document = Document {
            id: "did:plc:test456".to_string(),
            also_known_as: vec!["at://original.bsky.social".to_string()],
            service: vec![],
            verification_method: vec![],
            extra: HashMap::new(),
        };

        // Store original document
        storage.store_document(document.clone()).await.unwrap();

        // Update document
        document.also_known_as = vec!["at://updated.bsky.social".to_string()];
        storage.store_document(document.clone()).await.unwrap();

        // Verify update
        let retrieved = storage
            .get_document_by_did("did:plc:test456")
            .await
            .unwrap();
        assert_eq!(
            retrieved.unwrap().also_known_as,
            vec!["at://updated.bsky.social".to_string()]
        );
    }
}
