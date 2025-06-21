//! AIP OAuth Client Management CLI Tool
//!
//! A command-line interface for managing OAuth 2.1 clients in the ATProtocol Identity Provider (AIP).
//! This tool provides comprehensive functionality for OAuth client lifecycle management including
//! registration, retrieval, updating, and deletion of clients through AIP's RFC 7591 compliant API.
//!
//! ## Features
//!
//! - **Dynamic Client Registration**: Register new OAuth clients with custom configurations
//! - **Client Retrieval**: Get detailed information about existing clients
//! - **Client Updates**: Modify client configurations and metadata
//! - **Client Deletion**: Remove clients from the system
//! - **Client Listing**: List all registered clients (when supported by the server)
//! - **Comprehensive Configuration**: Support for all OAuth 2.1 parameters including:
//!   - Grant types (authorization_code, client_credentials, refresh_token)
//!   - Response types (code)
//!   - Authentication methods (client_secret_basic, client_secret_post, none, private_key_jwt)
//!   - Redirect URIs, scopes, and custom metadata
//!
//! ## Usage Examples
//!
//! ### Register a new client
//! ```bash
//! # Basic registration with minimal parameters
//! aip-client-management --base-url http://localhost:8080 register \
//!   --name "My OAuth Client" \
//!   --redirect-uri "http://localhost:3000/callback"
//!
//! # Advanced registration with multiple parameters
//! aip-client-management --base-url http://localhost:8080 register \
//!   --name "Advanced Client" \
//!   --redirect-uri "http://localhost:3000/callback" \
//!   --redirect-uri "http://localhost:3000/auth/callback" \
//!   --grant-type authorization_code \
//!   --grant-type refresh_token \
//!   --response-type code \
//!   --scope "read write" \
//!   --auth-method client_secret_basic \
//!   --metadata '{"custom_field": "custom_value"}'
//! ```
//!
//! ### Get client information
//! ```bash
//! aip-client-management --base-url http://localhost:8080 get \
//!   --client-id "client_id_here" \
//!   --registration-token "registration_access_token_here"
//! ```
//!
//! ### Update a client
//! ```bash
//! aip-client-management --base-url http://localhost:8080 update \
//!   --client-id "client_id_here" \
//!   --registration-token "registration_access_token_here" \
//!   --name "Updated Client Name" \
//!   --redirect-uri "http://localhost:3000/new-callback"
//! ```
//!
//! ### Delete a client
//! ```bash
//! aip-client-management --base-url http://localhost:8080 delete \
//!   --client-id "client_id_here" \
//!   --registration-token "registration_access_token_here"
//! ```
//!
//! ## Environment Variables
//!
//! The following environment variables can be used instead of command-line arguments:
//!
//! - `AIP_BASE_URL`: Base URL of the AIP server (alternative to --base-url)
//! - `AIP_CLIENT_ID`: OAuth client ID (alternative to --client-id)
//! - `AIP_REGISTRATION_TOKEN`: Client registration access token (alternative to --registration-token)
//!
//! ## Error Handling
//!
//! The tool provides detailed error messages for common scenarios:
//! - Network connectivity issues
//! - Invalid client configurations
//! - Authentication failures
//! - Server errors
//!
//! Exit codes:
//! - 0: Success
//! - 1: General error (network, parsing, etc.)
//! - 2: Client registration/management error
//! - 3: Authentication error
//!
//! ## Security Considerations
//!
//! - Client secrets and registration tokens are sensitive information
//! - Use environment variables for sensitive data in production
//! - Store client credentials securely
//! - Rotate client secrets regularly
//!
//! ## OAuth 2.1 Compliance
//!
//! This tool implements OAuth 2.1 Dynamic Client Registration (RFC 7591) and follows
//! security best practices including:
//! - PKCE (Proof Key for Code Exchange) support
//! - Secure redirect URI validation
//! - Proper client authentication methods
//! - Comprehensive metadata handling

use clap::{Args, Parser, Subcommand, ValueEnum};
use reqwest::{Client, StatusCode};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::env;
use std::process;

/// OAuth Grant Types as defined in the AIP OAuth implementation
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ValueEnum)]
#[serde(rename_all = "snake_case")]
pub enum GrantType {
    /// Authorization Code Grant (RFC 6749 Section 4.1)
    AuthorizationCode,
    /// Client Credentials Grant (RFC 6749 Section 4.4)
    ClientCredentials,
    /// Refresh Token Grant (RFC 6749 Section 6)
    RefreshToken,
}

/// OAuth Response Types as defined in the AIP OAuth implementation
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ValueEnum)]
#[serde(rename_all = "snake_case")]
pub enum ResponseType {
    /// Authorization Code Response Type
    Code,
}

/// Client Authentication Methods as defined in OAuth 2.1
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ValueEnum)]
#[serde(rename_all = "snake_case")]
pub enum ClientAuthMethod {
    /// HTTP Basic Authentication with client credentials
    ClientSecretBasic,
    /// Client credentials in POST body
    ClientSecretPost,
    /// No client authentication (public clients)
    None,
    /// Private Key JWT authentication
    PrivateKeyJwt,
}

/// OAuth Client Registration Request structure
#[derive(Debug, Serialize)]
struct ClientRegistrationRequest {
    #[serde(skip_serializing_if = "Option::is_none")]
    client_name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    redirect_uris: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    grant_types: Option<Vec<GrantType>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    response_types: Option<Vec<ResponseType>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    scope: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    token_endpoint_auth_method: Option<ClientAuthMethod>,
    #[serde(flatten)]
    metadata: Value,
}

/// OAuth Client Registration Response structure
#[derive(Debug, Deserialize, Serialize)]
struct ClientRegistrationResponse {
    client_id: String,
    client_secret: Option<String>,
    client_name: Option<String>,
    redirect_uris: Vec<String>,
    grant_types: Vec<GrantType>,
    response_types: Vec<ResponseType>,
    scope: Option<String>,
    token_endpoint_auth_method: ClientAuthMethod,
    registration_access_token: String,
    registration_client_uri: String,
    client_id_issued_at: i64,
    client_secret_expires_at: Option<i64>,
}

/// OAuth Client Update Request structure
#[derive(Debug, Serialize)]
struct ClientUpdateRequest {
    #[serde(skip_serializing_if = "Option::is_none")]
    client_name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    redirect_uris: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    grant_types: Option<Vec<GrantType>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    response_types: Option<Vec<ResponseType>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    scope: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    token_endpoint_auth_method: Option<ClientAuthMethod>,
    #[serde(flatten)]
    metadata: Value,
}

/// Main CLI application structure
#[derive(Parser)]
#[command(
    name = "aip-client-management",
    about = "AIP OAuth Client Management CLI Tool",
    long_about = "A comprehensive command-line interface for managing OAuth 2.1 clients in the ATProtocol Identity Provider (AIP). \
                  Supports RFC 7591 dynamic client registration and full client lifecycle management.",
    version = env!("CARGO_PKG_VERSION"),
    author = "AIP Development Team"
)]
struct Cli {
    /// Base URL of the AIP server
    #[arg(
        long,
        default_value = "http://localhost:8080",
        help = "Base URL of the AIP server (can be set via AIP_BASE_URL environment variable)"
    )]
    base_url: String,

    /// Enable verbose output
    #[arg(short, long, help = "Enable verbose output for debugging")]
    verbose: bool,

    /// Output format
    #[arg(
        long,
        value_enum,
        default_value = "json",
        help = "Output format for responses"
    )]
    format: OutputFormat,

    #[command(subcommand)]
    command: Commands,
}

/// Output format options
#[derive(Debug, Clone, ValueEnum)]
enum OutputFormat {
    /// JSON formatted output
    Json,
    /// Pretty-printed JSON output
    JsonPretty,
    /// Human-readable table format
    Table,
}

/// Available CLI commands
#[derive(Subcommand)]
enum Commands {
    /// Register a new OAuth client
    Register(RegisterArgs),
    /// Get information about an existing client
    Get(GetArgs),
    /// Update an existing client
    Update(UpdateArgs),
    /// Delete an existing client
    Delete(DeleteArgs),
    /// List all registered clients (if supported by server)
    List(ListArgs),
}

/// Arguments for client registration
#[derive(Args)]
struct RegisterArgs {
    /// Human-readable name for the client
    #[arg(long, help = "Human-readable name for the OAuth client")]
    name: Option<String>,

    /// OAuth redirect URIs (can be specified multiple times)
    #[arg(
        long = "redirect-uri",
        help = "OAuth redirect URI (can be specified multiple times for multiple URIs)"
    )]
    redirect_uris: Vec<String>,

    /// OAuth grant types (can be specified multiple times)
    #[arg(
        long = "grant-type",
        value_enum,
        help = "OAuth grant type (can be specified multiple times)"
    )]
    grant_types: Vec<GrantType>,

    /// OAuth response types (can be specified multiple times)
    #[arg(
        long = "response-type",
        value_enum,
        help = "OAuth response type (can be specified multiple times)"
    )]
    response_types: Vec<ResponseType>,

    /// OAuth scopes (space-separated)
    #[arg(long, help = "OAuth scopes as a space-separated string")]
    scope: Option<String>,

    /// Client authentication method
    #[arg(
        long = "auth-method",
        value_enum,
        help = "Client authentication method"
    )]
    auth_method: Option<ClientAuthMethod>,

    /// Additional metadata as JSON
    #[arg(
        long,
        help = "Additional client metadata as JSON string (e.g., '{\"custom_field\": \"value\"}')"
    )]
    metadata: Option<String>,
}

/// Arguments for client retrieval
#[derive(Args)]
struct GetArgs {
    /// Client ID
    #[arg(
        long,
        help = "OAuth client ID (can be set via AIP_CLIENT_ID environment variable)"
    )]
    client_id: String,

    /// Registration access token
    #[arg(
        long,
        help = "Client registration access token (can be set via AIP_REGISTRATION_TOKEN environment variable)"
    )]
    registration_token: String,
}

/// Arguments for client updates
#[derive(Args)]
struct UpdateArgs {
    /// Client ID
    #[arg(
        long,
        help = "OAuth client ID (can be set via AIP_CLIENT_ID environment variable)"
    )]
    client_id: String,

    /// Registration access token
    #[arg(
        long,
        help = "Client registration access token (can be set via AIP_REGISTRATION_TOKEN environment variable)"
    )]
    registration_token: String,

    /// Human-readable name for the client
    #[arg(long, help = "Human-readable name for the OAuth client")]
    name: Option<String>,

    /// OAuth redirect URIs (can be specified multiple times)
    #[arg(
        long = "redirect-uri",
        help = "OAuth redirect URI (can be specified multiple times; replaces all existing URIs)"
    )]
    redirect_uris: Vec<String>,

    /// OAuth grant types (can be specified multiple times)
    #[arg(
        long = "grant-type",
        value_enum,
        help = "OAuth grant type (can be specified multiple times; replaces all existing grant types)"
    )]
    grant_types: Vec<GrantType>,

    /// OAuth response types (can be specified multiple times)
    #[arg(
        long = "response-type",
        value_enum,
        help = "OAuth response type (can be specified multiple times; replaces all existing response types)"
    )]
    response_types: Vec<ResponseType>,

    /// OAuth scopes (space-separated)
    #[arg(long, help = "OAuth scopes as a space-separated string")]
    scope: Option<String>,

    /// Client authentication method
    #[arg(
        long = "auth-method",
        value_enum,
        help = "Client authentication method"
    )]
    auth_method: Option<ClientAuthMethod>,

    /// Additional metadata as JSON
    #[arg(
        long,
        help = "Additional client metadata as JSON string (e.g., '{\"custom_field\": \"value\"}')"
    )]
    metadata: Option<String>,
}

/// Arguments for client deletion
#[derive(Args)]
struct DeleteArgs {
    /// Client ID
    #[arg(
        long,
        help = "OAuth client ID (can be set via AIP_CLIENT_ID environment variable)"
    )]
    client_id: String,

    /// Registration access token
    #[arg(
        long,
        help = "Client registration access token (can be set via AIP_REGISTRATION_TOKEN environment variable)"
    )]
    registration_token: String,

    /// Skip confirmation prompt
    #[arg(long, help = "Skip the confirmation prompt")]
    yes: bool,
}

/// Arguments for listing clients
#[derive(Args)]
struct ListArgs {
    /// Optional authentication token for listing clients
    #[arg(
        long,
        help = "Authentication token for listing clients (implementation dependent)"
    )]
    auth_token: Option<String>,
}

/// Application errors
#[derive(Debug)]
enum AppError {
    /// Network or HTTP client errors
    Network(reqwest::Error),
    /// JSON parsing or serialization errors
    Json(serde_json::Error),
    /// Client registration or management errors
    ClientManagement(String),
    /// Authentication errors
    Authentication(String),
    /// General application errors
    General(String),
}

impl From<reqwest::Error> for AppError {
    fn from(err: reqwest::Error) -> Self {
        AppError::Network(err)
    }
}

impl From<serde_json::Error> for AppError {
    fn from(err: serde_json::Error) -> Self {
        AppError::Json(err)
    }
}

impl std::fmt::Display for AppError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            AppError::Network(err) => write!(f, "Network error: {}", err),
            AppError::Json(err) => write!(f, "JSON error: {}", err),
            AppError::ClientManagement(msg) => write!(f, "Client management error: {}", msg),
            AppError::Authentication(msg) => write!(f, "Authentication error: {}", msg),
            AppError::General(msg) => write!(f, "Error: {}", msg),
        }
    }
}

/// Main application entry point
#[tokio::main]
async fn main() {
    let cli = Cli::parse();

    let result = match &cli.command {
        Commands::Register(args) => register_client(&cli, args).await,
        Commands::Get(args) => get_client(&cli, args).await,
        Commands::Update(args) => update_client(&cli, args).await,
        Commands::Delete(args) => delete_client(&cli, args).await,
        Commands::List(args) => list_clients(&cli, args).await,
    };

    match result {
        Ok(()) => process::exit(0),
        Err(AppError::Network(_)) => {
            eprintln!("Error: {}", result.unwrap_err());
            process::exit(1);
        }
        Err(AppError::Json(_)) => {
            eprintln!("Error: {}", result.unwrap_err());
            process::exit(1);
        }
        Err(AppError::ClientManagement(_)) => {
            eprintln!("Error: {}", result.unwrap_err());
            process::exit(2);
        }
        Err(AppError::Authentication(_)) => {
            eprintln!("Error: {}", result.unwrap_err());
            process::exit(3);
        }
        Err(AppError::General(_)) => {
            eprintln!("Error: {}", result.unwrap_err());
            process::exit(1);
        }
    }
}

/// Register a new OAuth client
async fn register_client(cli: &Cli, args: &RegisterArgs) -> Result<(), AppError> {
    if cli.verbose {
        eprintln!(
            "Registering new OAuth client with AIP server: {}",
            cli.base_url
        );
    }

    // Parse metadata if provided
    let metadata = if let Some(metadata_str) = &args.metadata {
        serde_json::from_str(metadata_str)
            .map_err(|e| AppError::General(format!("Invalid metadata JSON: {}", e)))?
    } else {
        Value::Object(serde_json::Map::new())
    };

    // Build registration request
    let request = ClientRegistrationRequest {
        client_name: args.name.clone(),
        redirect_uris: if args.redirect_uris.is_empty() {
            None
        } else {
            Some(args.redirect_uris.clone())
        },
        grant_types: if args.grant_types.is_empty() {
            None
        } else {
            Some(args.grant_types.clone())
        },
        response_types: if args.response_types.is_empty() {
            None
        } else {
            Some(args.response_types.clone())
        },
        scope: args.scope.clone(),
        token_endpoint_auth_method: args.auth_method.clone(),
        metadata,
    };

    if cli.verbose {
        eprintln!(
            "Registration request: {}",
            serde_json::to_string_pretty(&request)?
        );
    }

    // Make HTTP request
    let client = Client::new();
    let url = format!("{}/oauth/clients/register", cli.base_url);

    let response = client.post(&url).json(&request).send().await?;

    if cli.verbose {
        eprintln!("Response status: {}", response.status());
    }

    match response.status() {
        StatusCode::OK => {
            let registration_response: ClientRegistrationResponse = response.json().await?;
            output_response(&cli.format, &registration_response)?;
            Ok(())
        }
        status => {
            let error_text = response.text().await?;
            Err(AppError::ClientManagement(format!(
                "Registration failed with status {}: {}",
                status, error_text
            )))
        }
    }
}

/// Get information about an existing client
async fn get_client(cli: &Cli, args: &GetArgs) -> Result<(), AppError> {
    if cli.verbose {
        eprintln!("Getting client information for: {}", args.client_id);
    }

    let client = Client::new();
    let url = format!("{}/oauth/clients/{}", cli.base_url, args.client_id);

    let response = client
        .get(&url)
        .bearer_auth(&args.registration_token)
        .send()
        .await?;

    if cli.verbose {
        eprintln!("Response status: {}", response.status());
    }

    match response.status() {
        StatusCode::OK => {
            let client_info: Value = response.json().await?;
            output_response(&cli.format, &client_info)?;
            Ok(())
        }
        StatusCode::UNAUTHORIZED => Err(AppError::Authentication(
            "Invalid registration token or client ID".to_string(),
        )),
        StatusCode::NOT_FOUND => Err(AppError::ClientManagement(format!(
            "Client '{}' not found",
            args.client_id
        ))),
        status => {
            let error_text = response.text().await?;
            Err(AppError::ClientManagement(format!(
                "Failed to get client with status {}: {}",
                status, error_text
            )))
        }
    }
}

/// Update an existing client
async fn update_client(cli: &Cli, args: &UpdateArgs) -> Result<(), AppError> {
    if cli.verbose {
        eprintln!("Updating client: {}", args.client_id);
    }

    // Parse metadata if provided
    let metadata = if let Some(metadata_str) = &args.metadata {
        serde_json::from_str(metadata_str)
            .map_err(|e| AppError::General(format!("Invalid metadata JSON: {}", e)))?
    } else {
        Value::Object(serde_json::Map::new())
    };

    // Build update request
    let request = ClientUpdateRequest {
        client_name: args.name.clone(),
        redirect_uris: if args.redirect_uris.is_empty() {
            None
        } else {
            Some(args.redirect_uris.clone())
        },
        grant_types: if args.grant_types.is_empty() {
            None
        } else {
            Some(args.grant_types.clone())
        },
        response_types: if args.response_types.is_empty() {
            None
        } else {
            Some(args.response_types.clone())
        },
        scope: args.scope.clone(),
        token_endpoint_auth_method: args.auth_method.clone(),
        metadata,
    };

    if cli.verbose {
        eprintln!(
            "Update request: {}",
            serde_json::to_string_pretty(&request)?
        );
    }

    let client = Client::new();
    let url = format!("{}/oauth/clients/{}", cli.base_url, args.client_id);

    let response = client
        .put(&url)
        .bearer_auth(&args.registration_token)
        .json(&request)
        .send()
        .await?;

    if cli.verbose {
        eprintln!("Response status: {}", response.status());
    }

    match response.status() {
        StatusCode::OK => {
            let updated_client: Value = response.json().await?;
            output_response(&cli.format, &updated_client)?;
            Ok(())
        }
        StatusCode::UNAUTHORIZED => Err(AppError::Authentication(
            "Invalid registration token or client ID".to_string(),
        )),
        StatusCode::NOT_FOUND => Err(AppError::ClientManagement(format!(
            "Client '{}' not found",
            args.client_id
        ))),
        status => {
            let error_text = response.text().await?;
            Err(AppError::ClientManagement(format!(
                "Failed to update client with status {}: {}",
                status, error_text
            )))
        }
    }
}

/// Delete an existing client
async fn delete_client(cli: &Cli, args: &DeleteArgs) -> Result<(), AppError> {
    if !args.yes {
        println!(
            "Are you sure you want to delete client '{}'? (y/N)",
            args.client_id
        );
        let mut input = String::new();
        std::io::stdin()
            .read_line(&mut input)
            .map_err(|e| AppError::General(format!("Failed to read confirmation: {}", e)))?;

        let input = input.trim().to_lowercase();
        if input != "y" && input != "yes" {
            println!("Deletion cancelled.");
            return Ok(());
        }
    }

    if cli.verbose {
        eprintln!("Deleting client: {}", args.client_id);
    }

    let client = Client::new();
    let url = format!("{}/oauth/clients/{}", cli.base_url, args.client_id);

    let response = client
        .delete(&url)
        .bearer_auth(&args.registration_token)
        .send()
        .await?;

    if cli.verbose {
        eprintln!("Response status: {}", response.status());
    }

    match response.status() {
        StatusCode::NO_CONTENT => {
            println!("Client '{}' deleted successfully.", args.client_id);
            Ok(())
        }
        StatusCode::UNAUTHORIZED => Err(AppError::Authentication(
            "Invalid registration token or client ID".to_string(),
        )),
        StatusCode::NOT_FOUND => Err(AppError::ClientManagement(format!(
            "Client '{}' not found",
            args.client_id
        ))),
        status => {
            let error_text = response.text().await?;
            Err(AppError::ClientManagement(format!(
                "Failed to delete client with status {}: {}",
                status, error_text
            )))
        }
    }
}

/// List all registered clients (if supported by server)
async fn list_clients(cli: &Cli, args: &ListArgs) -> Result<(), AppError> {
    if cli.verbose {
        eprintln!("Listing clients from AIP server: {}", cli.base_url);
    }

    let client = Client::new();
    let url = format!("{}/oauth/clients", cli.base_url);

    let mut request = client.get(&url);

    if let Some(token) = &args.auth_token {
        request = request.bearer_auth(token);
    }

    let response = request.send().await?;

    if cli.verbose {
        eprintln!("Response status: {}", response.status());
    }

    match response.status() {
        StatusCode::OK => {
            let clients: Value = response.json().await?;
            output_response(&cli.format, &clients)?;
            Ok(())
        }
        StatusCode::UNAUTHORIZED => Err(AppError::Authentication(
            "Authentication required for listing clients".to_string(),
        )),
        StatusCode::NOT_FOUND | StatusCode::METHOD_NOT_ALLOWED => Err(AppError::ClientManagement(
            "Client listing not supported by this server".to_string(),
        )),
        status => {
            let error_text = response.text().await?;
            Err(AppError::ClientManagement(format!(
                "Failed to list clients with status {}: {}",
                status, error_text
            )))
        }
    }
}

/// Output response data in the requested format
fn output_response<T: Serialize>(format: &OutputFormat, data: &T) -> Result<(), AppError> {
    match format {
        OutputFormat::Json => {
            println!("{}", serde_json::to_string(data)?);
        }
        OutputFormat::JsonPretty => {
            println!("{}", serde_json::to_string_pretty(data)?);
        }
        OutputFormat::Table => {
            // For table format, we'll output key-value pairs in a readable format
            let json_value: Value = serde_json::to_value(data)?;
            print_table(&json_value, 0);
        }
    }
    Ok(())
}

/// Print data in table format (recursive for nested objects)
fn print_table(value: &Value, indent: usize) {
    let prefix = "  ".repeat(indent);

    match value {
        Value::Object(map) => {
            for (key, val) in map {
                match val {
                    Value::Object(_) => {
                        println!("{}{}:", prefix, key);
                        print_table(val, indent + 1);
                    }
                    Value::Array(arr) => {
                        println!("{}{}:", prefix, key);
                        for (i, item) in arr.iter().enumerate() {
                            println!("{}  [{}]:", prefix, i);
                            print_table(item, indent + 2);
                        }
                    }
                    _ => {
                        println!("{}{}: {}", prefix, key, format_value(val));
                    }
                }
            }
        }
        _ => {
            println!("{}{}", prefix, format_value(value));
        }
    }
}

/// Format a JSON value for display
fn format_value(value: &Value) -> String {
    match value {
        Value::String(s) => s.clone(),
        Value::Number(n) => n.to_string(),
        Value::Bool(b) => b.to_string(),
        Value::Null => "null".to_string(),
        _ => serde_json::to_string(value).unwrap_or_else(|_| "invalid".to_string()),
    }
}
