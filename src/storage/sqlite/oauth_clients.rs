//! SQLite implementation for OAuth client storage

use crate::errors::StorageError;
use crate::oauth::types::*;
use crate::storage::traits::{OAuthClientStore, Result};
use async_trait::async_trait;
use chrono::Utc;
use sqlx::Row;
use sqlx::sqlite::{SqlitePool, SqliteRow};

/// SQLite implementation of OAuth client storage
pub struct SqliteOAuthClientStore {
    pool: SqlitePool,
}

impl SqliteOAuthClientStore {
    /// Create a new SQLite OAuth client store
    pub fn new(pool: SqlitePool) -> Self {
        Self { pool }
    }

    /// Convert GrantType enum to string representation
    fn grant_type_to_string(grant_type: &GrantType) -> &'static str {
        match grant_type {
            GrantType::AuthorizationCode => "authorization_code",
            GrantType::ClientCredentials => "client_credentials",
            GrantType::RefreshToken => "refresh_token",
        }
    }

    /// Convert string to GrantType enum
    fn string_to_grant_type(s: &str) -> Result<GrantType> {
        match s {
            "authorization_code" => Ok(GrantType::AuthorizationCode),
            "client_credentials" => Ok(GrantType::ClientCredentials),
            "refresh_token" => Ok(GrantType::RefreshToken),
            _ => Err(StorageError::InvalidData(format!(
                "Unknown grant type: {}",
                s
            ))),
        }
    }

    /// Convert ResponseType enum to string representation
    fn response_type_to_string(response_type: &ResponseType) -> &'static str {
        match response_type {
            ResponseType::Code => "code",
            ResponseType::IdToken => "id_token",
        }
    }

    /// Convert string to ResponseType enum
    fn string_to_response_type(s: &str) -> Result<ResponseType> {
        match s {
            "code" => Ok(ResponseType::Code),
            "id_token" => Ok(ResponseType::IdToken),
            _ => Err(StorageError::InvalidData(format!(
                "Unknown response type: {}",
                s
            ))),
        }
    }

    /// Convert ClientAuthMethod enum to string representation
    fn auth_method_to_string(method: &ClientAuthMethod) -> &'static str {
        match method {
            ClientAuthMethod::ClientSecretBasic => "client_secret_basic",
            ClientAuthMethod::ClientSecretPost => "client_secret_post",
            ClientAuthMethod::None => "none",
            ClientAuthMethod::PrivateKeyJwt => "private_key_jwt",
        }
    }

    /// Convert string to ClientAuthMethod enum
    fn string_to_auth_method(s: &str) -> Result<ClientAuthMethod> {
        match s {
            "client_secret_basic" => Ok(ClientAuthMethod::ClientSecretBasic),
            "client_secret_post" => Ok(ClientAuthMethod::ClientSecretPost),
            "none" => Ok(ClientAuthMethod::None),
            "private_key_jwt" => Ok(ClientAuthMethod::PrivateKeyJwt),
            _ => Err(StorageError::InvalidData(format!(
                "Unknown auth method: {}",
                s
            ))),
        }
    }

    /// Convert ClientType enum to string representation
    fn client_type_to_string(client_type: &ClientType) -> &'static str {
        match client_type {
            ClientType::Public => "public",
            ClientType::Confidential => "confidential",
        }
    }

    /// Convert string to ClientType enum
    fn string_to_client_type(s: &str) -> Result<ClientType> {
        match s {
            "public" => Ok(ClientType::Public),
            "confidential" => Ok(ClientType::Confidential),
            _ => Err(StorageError::InvalidData(format!(
                "Unknown client type: {}",
                s
            ))),
        }
    }

    /// Serialize grant types to JSON string
    fn serialize_grant_types(grant_types: &[GrantType]) -> Result<String> {
        let strings: Vec<&str> = grant_types.iter().map(Self::grant_type_to_string).collect();
        serde_json::to_string(&strings).map_err(|e| StorageError::SerializationError(e.to_string()))
    }

    /// Deserialize grant types from JSON string
    fn deserialize_grant_types(json: &str) -> Result<Vec<GrantType>> {
        let strings: Vec<String> = serde_json::from_str(json)
            .map_err(|e| StorageError::SerializationError(e.to_string()))?;
        strings
            .iter()
            .map(|s| Self::string_to_grant_type(s))
            .collect()
    }

    /// Serialize response types to JSON string
    fn serialize_response_types(response_types: &[ResponseType]) -> Result<String> {
        let strings: Vec<&str> = response_types
            .iter()
            .map(Self::response_type_to_string)
            .collect();
        serde_json::to_string(&strings).map_err(|e| StorageError::SerializationError(e.to_string()))
    }

    /// Deserialize response types from JSON string
    fn deserialize_response_types(json: &str) -> Result<Vec<ResponseType>> {
        let strings: Vec<String> = serde_json::from_str(json)
            .map_err(|e| StorageError::SerializationError(e.to_string()))?;
        strings
            .iter()
            .map(|s| Self::string_to_response_type(s))
            .collect()
    }

    /// Convert chrono::Duration to seconds as i64
    fn duration_to_seconds(duration: &chrono::Duration) -> i64 {
        duration.num_seconds()
    }

    /// Convert seconds (i64) to chrono::Duration
    fn seconds_to_duration(seconds: i64) -> chrono::Duration {
        chrono::Duration::seconds(seconds)
    }

    /// Convert SQLite row to OAuthClient
    fn row_to_oauth_client(row: &SqliteRow) -> Result<OAuthClient> {
        let redirect_uris_json: String = row.try_get("redirect_uris").map_err(|e| {
            StorageError::DatabaseError(format!("Failed to get redirect_uris: {}", e))
        })?;
        let redirect_uris: Vec<String> = serde_json::from_str(&redirect_uris_json)
            .map_err(|e| StorageError::SerializationError(e.to_string()))?;

        let grant_types_json: String = row.try_get("grant_types").map_err(|e| {
            StorageError::DatabaseError(format!("Failed to get grant_types: {}", e))
        })?;
        let grant_types = Self::deserialize_grant_types(&grant_types_json)?;

        let response_types_json: String = row.try_get("response_types").map_err(|e| {
            StorageError::DatabaseError(format!("Failed to get response_types: {}", e))
        })?;
        let response_types = Self::deserialize_response_types(&response_types_json)?;

        let auth_method_str: String = row.try_get("token_endpoint_auth_method").map_err(|e| {
            StorageError::DatabaseError(format!("Failed to get token_endpoint_auth_method: {}", e))
        })?;
        let token_endpoint_auth_method = Self::string_to_auth_method(&auth_method_str)?;

        let client_type_str: String = row.try_get("client_type").map_err(|e| {
            StorageError::DatabaseError(format!("Failed to get client_type: {}", e))
        })?;
        let client_type = Self::string_to_client_type(&client_type_str)?;

        let created_at_str: String = row
            .try_get("created_at")
            .map_err(|e| StorageError::DatabaseError(format!("Failed to get created_at: {}", e)))?;
        let created_at = chrono::DateTime::parse_from_rfc3339(&created_at_str)
            .map_err(|e| StorageError::InvalidData(format!("Invalid created_at timestamp: {}", e)))?
            .with_timezone(&Utc);

        let updated_at_str: String = row
            .try_get("updated_at")
            .map_err(|e| StorageError::DatabaseError(format!("Failed to get updated_at: {}", e)))?;
        let updated_at = chrono::DateTime::parse_from_rfc3339(&updated_at_str)
            .map_err(|e| StorageError::InvalidData(format!("Invalid updated_at timestamp: {}", e)))?
            .with_timezone(&Utc);

        let metadata_json: String = row
            .try_get("metadata")
            .map_err(|e| StorageError::DatabaseError(format!("Failed to get metadata: {}", e)))?;
        let metadata: serde_json::Value = serde_json::from_str(&metadata_json)
            .map_err(|e| StorageError::SerializationError(e.to_string()))?;

        let client_id: String = row
            .try_get("client_id")
            .map_err(|e| StorageError::DatabaseError(format!("Failed to get client_id: {}", e)))?;
        let client_secret: Option<String> = row.try_get("client_secret").map_err(|e| {
            StorageError::DatabaseError(format!("Failed to get client_secret: {}", e))
        })?;
        let client_name: Option<String> = row.try_get("client_name").map_err(|e| {
            StorageError::DatabaseError(format!("Failed to get client_name: {}", e))
        })?;
        let scope: Option<String> = row
            .try_get("scope")
            .map_err(|e| StorageError::DatabaseError(format!("Failed to get scope: {}", e)))?;

        let access_token_expiration_seconds: i64 =
            row.try_get("access_token_expiration").map_err(|e| {
                StorageError::DatabaseError(format!("Failed to get access_token_expiration: {}", e))
            })?;
        let access_token_expiration = Self::seconds_to_duration(access_token_expiration_seconds);

        let refresh_token_expiration_seconds: i64 =
            row.try_get("refresh_token_expiration").map_err(|e| {
                StorageError::DatabaseError(format!(
                    "Failed to get refresh_token_expiration: {}",
                    e
                ))
            })?;
        let refresh_token_expiration = Self::seconds_to_duration(refresh_token_expiration_seconds);

        let require_redirect_exact: i64 = row.try_get("require_redirect_exact").map_err(|e| {
            StorageError::DatabaseError(format!("Failed to get require_redirect_exact: {}", e))
        })?;
        let require_redirect_exact = require_redirect_exact != 0;

        let registration_access_token: Option<String> =
            row.try_get("registration_access_token").map_err(|e| {
                StorageError::DatabaseError(format!(
                    "Failed to get registration_access_token: {}",
                    e
                ))
            })?;

        Ok(OAuthClient {
            client_id,
            client_secret,
            client_name,
            redirect_uris,
            grant_types,
            response_types,
            scope,
            token_endpoint_auth_method,
            client_type,
            created_at,
            updated_at,
            metadata,
            access_token_expiration,
            refresh_token_expiration,
            require_redirect_exact,
            registration_access_token,
        })
    }
}

#[async_trait]
impl OAuthClientStore for SqliteOAuthClientStore {
    async fn store_client(&self, client: &OAuthClient) -> Result<()> {
        let redirect_uris_json = serde_json::to_string(&client.redirect_uris)
            .map_err(|e| StorageError::SerializationError(e.to_string()))?;

        let grant_types_json = Self::serialize_grant_types(&client.grant_types)?;
        let response_types_json = Self::serialize_response_types(&client.response_types)?;
        let auth_method_str = Self::auth_method_to_string(&client.token_endpoint_auth_method);
        let client_type_str = Self::client_type_to_string(&client.client_type);
        let created_at_str = client.created_at.to_rfc3339();
        let updated_at_str = client.updated_at.to_rfc3339();
        let metadata_json = serde_json::to_string(&client.metadata)
            .map_err(|e| StorageError::SerializationError(e.to_string()))?;
        let access_token_expiration_seconds =
            Self::duration_to_seconds(&client.access_token_expiration);
        let refresh_token_expiration_seconds =
            Self::duration_to_seconds(&client.refresh_token_expiration);

        sqlx::query(
            r#"
            INSERT INTO oauth_clients (
                client_id, client_secret, client_name, redirect_uris, grant_types, 
                response_types, scope, token_endpoint_auth_method, client_type,
                created_at, updated_at, metadata, access_token_expiration, refresh_token_expiration,
                require_redirect_exact, registration_access_token
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            "#,
        )
        .bind(&client.client_id)
        .bind(&client.client_secret)
        .bind(&client.client_name)
        .bind(&redirect_uris_json)
        .bind(&grant_types_json)
        .bind(&response_types_json)
        .bind(&client.scope)
        .bind(auth_method_str)
        .bind(client_type_str)
        .bind(&created_at_str)
        .bind(&updated_at_str)
        .bind(&metadata_json)
        .bind(access_token_expiration_seconds)
        .bind(refresh_token_expiration_seconds)
        .bind(if client.require_redirect_exact {
            1i64
        } else {
            0i64
        })
        .bind(&client.registration_access_token)
        .execute(&self.pool)
        .await
        .map_err(|e| StorageError::DatabaseError(e.to_string()))?;

        Ok(())
    }

    async fn get_client(&self, client_id: &str) -> Result<Option<OAuthClient>> {
        let row = sqlx::query("SELECT * FROM oauth_clients WHERE client_id = ?")
            .bind(client_id)
            .fetch_optional(&self.pool)
            .await
            .map_err(|e| StorageError::DatabaseError(e.to_string()))?;

        match row {
            Some(row) => {
                let client = Self::row_to_oauth_client(&row)?;
                Ok(Some(client))
            }
            None => Ok(None),
        }
    }

    async fn update_client(&self, client: &OAuthClient) -> Result<()> {
        let redirect_uris_json = serde_json::to_string(&client.redirect_uris)
            .map_err(|e| StorageError::SerializationError(e.to_string()))?;

        let grant_types_json = Self::serialize_grant_types(&client.grant_types)?;
        let response_types_json = Self::serialize_response_types(&client.response_types)?;
        let auth_method_str = Self::auth_method_to_string(&client.token_endpoint_auth_method);
        let client_type_str = Self::client_type_to_string(&client.client_type);
        let updated_at_str = client.updated_at.to_rfc3339();
        let metadata_json = serde_json::to_string(&client.metadata)
            .map_err(|e| StorageError::SerializationError(e.to_string()))?;
        let access_token_expiration_seconds =
            Self::duration_to_seconds(&client.access_token_expiration);
        let refresh_token_expiration_seconds =
            Self::duration_to_seconds(&client.refresh_token_expiration);

        let result = sqlx::query(
            r#"
            UPDATE oauth_clients SET 
                client_secret = ?, client_name = ?, redirect_uris = ?, grant_types = ?,
                response_types = ?, scope = ?, token_endpoint_auth_method = ?, 
                client_type = ?, updated_at = ?, metadata = ?, access_token_expiration = ?, 
                refresh_token_expiration = ?, require_redirect_exact = ?, registration_access_token = ?
            WHERE client_id = ?
            "#,
        )
        .bind(&client.client_secret)
        .bind(&client.client_name)
        .bind(&redirect_uris_json)
        .bind(&grant_types_json)
        .bind(&response_types_json)
        .bind(&client.scope)
        .bind(auth_method_str)
        .bind(client_type_str)
        .bind(&updated_at_str)
        .bind(&metadata_json)
        .bind(access_token_expiration_seconds)
        .bind(refresh_token_expiration_seconds)
        .bind(if client.require_redirect_exact { 1i64 } else { 0i64 })
        .bind(&client.registration_access_token)
        .bind(&client.client_id)
        .execute(&self.pool)
        .await
        .map_err(|e| StorageError::DatabaseError(e.to_string()))?;

        if result.rows_affected() == 0 {
            return Err(StorageError::NotFound(format!(
                "Client not found: {}",
                client.client_id
            )));
        }

        Ok(())
    }

    async fn delete_client(&self, client_id: &str) -> Result<()> {
        let result = sqlx::query("DELETE FROM oauth_clients WHERE client_id = ?")
            .bind(client_id)
            .execute(&self.pool)
            .await
            .map_err(|e| StorageError::DatabaseError(e.to_string()))?;

        if result.rows_affected() == 0 {
            return Err(StorageError::NotFound(format!(
                "Client not found: {}",
                client_id
            )));
        }

        Ok(())
    }

    async fn list_clients(&self, limit: Option<usize>) -> Result<Vec<OAuthClient>> {
        let sql = match limit {
            Some(limit) => format!(
                "SELECT * FROM oauth_clients ORDER BY created_at DESC LIMIT {}",
                limit
            ),
            None => "SELECT * FROM oauth_clients ORDER BY created_at DESC".to_string(),
        };

        let rows = sqlx::query(&sql)
            .fetch_all(&self.pool)
            .await
            .map_err(|e| StorageError::DatabaseError(e.to_string()))?;

        let mut clients = Vec::new();
        for row in rows {
            let client = Self::row_to_oauth_client(&row)?;
            clients.push(client);
        }

        Ok(clients)
    }
}
