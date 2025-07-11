//! PostgreSQL implementation for OAuth client storage

use crate::errors::StorageError;
use crate::oauth::types::*;
use crate::storage::traits::{OAuthClientStore, Result};
use async_trait::async_trait;
use sqlx::Row;
use sqlx::postgres::{PgPool, PgRow};

/// PostgreSQL implementation of OAuth client storage
pub struct PostgresOAuthClientStore {
    pool: PgPool,
}

impl PostgresOAuthClientStore {
    /// Create a new PostgreSQL OAuth client store
    pub fn new(pool: PgPool) -> Self {
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

    /// Convert chrono::Duration to seconds as i64
    fn duration_to_seconds(duration: &chrono::Duration) -> i64 {
        duration.num_seconds()
    }

    /// Convert seconds (i64) to chrono::Duration
    fn seconds_to_duration(seconds: i64) -> chrono::Duration {
        chrono::Duration::seconds(seconds)
    }

    /// Serialize grant types to JSON value
    fn serialize_grant_types(grant_types: &[GrantType]) -> serde_json::Value {
        let strings: Vec<&str> = grant_types.iter().map(Self::grant_type_to_string).collect();
        serde_json::Value::Array(
            strings
                .into_iter()
                .map(|s| serde_json::Value::String(s.to_string()))
                .collect(),
        )
    }

    /// Deserialize grant types from JSON value
    fn deserialize_grant_types(json: &serde_json::Value) -> Result<Vec<GrantType>> {
        match json {
            serde_json::Value::Array(arr) => {
                let mut grant_types = Vec::new();
                for value in arr {
                    if let serde_json::Value::String(s) = value {
                        grant_types.push(Self::string_to_grant_type(s)?);
                    } else {
                        return Err(StorageError::InvalidData(
                            "Grant type must be a string".to_string(),
                        ));
                    }
                }
                Ok(grant_types)
            }
            _ => Err(StorageError::InvalidData(
                "Grant types must be an array".to_string(),
            )),
        }
    }

    /// Serialize response types to JSON value
    fn serialize_response_types(response_types: &[ResponseType]) -> serde_json::Value {
        let strings: Vec<&str> = response_types
            .iter()
            .map(Self::response_type_to_string)
            .collect();
        serde_json::Value::Array(
            strings
                .into_iter()
                .map(|s| serde_json::Value::String(s.to_string()))
                .collect(),
        )
    }

    /// Deserialize response types from JSON value
    fn deserialize_response_types(json: &serde_json::Value) -> Result<Vec<ResponseType>> {
        match json {
            serde_json::Value::Array(arr) => {
                let mut response_types = Vec::new();
                for value in arr {
                    if let serde_json::Value::String(s) = value {
                        response_types.push(Self::string_to_response_type(s)?);
                    } else {
                        return Err(StorageError::InvalidData(
                            "Response type must be a string".to_string(),
                        ));
                    }
                }
                Ok(response_types)
            }
            _ => Err(StorageError::InvalidData(
                "Response types must be an array".to_string(),
            )),
        }
    }

    /// Convert PostgreSQL row to OAuthClient
    fn row_to_oauth_client(row: &PgRow) -> Result<OAuthClient> {
        let redirect_uris_json: serde_json::Value = row.try_get("redirect_uris").map_err(|e| {
            StorageError::DatabaseError(format!("Failed to get redirect_uris: {}", e))
        })?;
        let redirect_uris: Vec<String> = match redirect_uris_json {
            serde_json::Value::Array(arr) => {
                let mut uris = Vec::new();
                for value in arr {
                    if let serde_json::Value::String(s) = value {
                        uris.push(s);
                    } else {
                        return Err(StorageError::InvalidData(
                            "Redirect URI must be a string".to_string(),
                        ));
                    }
                }
                uris
            }
            _ => {
                return Err(StorageError::InvalidData(
                    "Redirect URIs must be an array".to_string(),
                ));
            }
        };

        let grant_types_json: serde_json::Value = row.try_get("grant_types").map_err(|e| {
            StorageError::DatabaseError(format!("Failed to get grant_types: {}", e))
        })?;
        let grant_types = Self::deserialize_grant_types(&grant_types_json)?;

        let response_types_json: serde_json::Value =
            row.try_get("response_types").map_err(|e| {
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

        let created_at: chrono::DateTime<chrono::Utc> = row
            .try_get("created_at")
            .map_err(|e| StorageError::DatabaseError(format!("Failed to get created_at: {}", e)))?;

        let updated_at: chrono::DateTime<chrono::Utc> = row
            .try_get("updated_at")
            .map_err(|e| StorageError::DatabaseError(format!("Failed to get updated_at: {}", e)))?;

        let metadata: serde_json::Value = row
            .try_get("metadata")
            .map_err(|e| StorageError::DatabaseError(format!("Failed to get metadata: {}", e)))?;

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

        let require_redirect_exact: bool = row.try_get("require_redirect_exact").map_err(|e| {
            StorageError::DatabaseError(format!("Failed to get require_redirect_exact: {}", e))
        })?;

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
impl OAuthClientStore for PostgresOAuthClientStore {
    async fn store_client(&self, client: &OAuthClient) -> Result<()> {
        let redirect_uris_json = serde_json::Value::Array(
            client
                .redirect_uris
                .iter()
                .map(|uri| serde_json::Value::String(uri.clone()))
                .collect(),
        );

        let grant_types_json = Self::serialize_grant_types(&client.grant_types);
        let response_types_json = Self::serialize_response_types(&client.response_types);
        let auth_method_str = Self::auth_method_to_string(&client.token_endpoint_auth_method);
        let client_type_str = Self::client_type_to_string(&client.client_type);
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
            ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16)
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
        .bind(client.created_at)
        .bind(client.updated_at)
        .bind(&client.metadata)
        .bind(access_token_expiration_seconds)
        .bind(refresh_token_expiration_seconds)
        .bind(client.require_redirect_exact)
        .bind(&client.registration_access_token)
        .execute(&self.pool)
        .await
        .map_err(|e| StorageError::DatabaseError(e.to_string()))?;

        Ok(())
    }

    async fn get_client(&self, client_id: &str) -> Result<Option<OAuthClient>> {
        let row = sqlx::query("SELECT * FROM oauth_clients WHERE client_id = $1")
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
        let redirect_uris_json = serde_json::Value::Array(
            client
                .redirect_uris
                .iter()
                .map(|uri| serde_json::Value::String(uri.clone()))
                .collect(),
        );

        let grant_types_json = Self::serialize_grant_types(&client.grant_types);
        let response_types_json = Self::serialize_response_types(&client.response_types);
        let auth_method_str = Self::auth_method_to_string(&client.token_endpoint_auth_method);
        let client_type_str = Self::client_type_to_string(&client.client_type);
        let access_token_expiration_seconds =
            Self::duration_to_seconds(&client.access_token_expiration);
        let refresh_token_expiration_seconds =
            Self::duration_to_seconds(&client.refresh_token_expiration);

        let result = sqlx::query(
            r#"
            UPDATE oauth_clients SET 
                client_secret = $2, client_name = $3, redirect_uris = $4, grant_types = $5,
                response_types = $6, scope = $7, token_endpoint_auth_method = $8, 
                client_type = $9, updated_at = $10, metadata = $11, access_token_expiration = $12, 
                refresh_token_expiration = $13, require_redirect_exact = $14, registration_access_token = $15
            WHERE client_id = $1
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
        .bind(client.updated_at)
        .bind(&client.metadata)
        .bind(access_token_expiration_seconds)
        .bind(refresh_token_expiration_seconds)
        .bind(client.require_redirect_exact)
        .bind(&client.registration_access_token)
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
        let result = sqlx::query("DELETE FROM oauth_clients WHERE client_id = $1")
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
        let rows = match limit {
            Some(limit) => {
                sqlx::query("SELECT * FROM oauth_clients ORDER BY created_at DESC LIMIT $1")
                    .bind(limit as i64)
                    .fetch_all(&self.pool)
                    .await
                    .map_err(|e| StorageError::DatabaseError(e.to_string()))?
            }
            None => sqlx::query("SELECT * FROM oauth_clients ORDER BY created_at DESC")
                .fetch_all(&self.pool)
                .await
                .map_err(|e| StorageError::DatabaseError(e.to_string()))?,
        };

        let mut clients = Vec::new();
        for row in rows {
            let client = Self::row_to_oauth_client(&row)?;
            clients.push(client);
        }

        Ok(clients)
    }
}
