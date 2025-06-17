//! AIP Lifecycle Website
//!
//! A web application that demonstrates ATProtocol lifecycle management with DPoP authentication.
//! This client can be configured with a pre-existing DPoP key and service DID for proxying requests.

use atproto_client::client::{get_dpop_json_with_headers, DPoPAuth};
use atproto_identity::key::{generate_key, identify_key, sign, to_public, KeyData, KeyType};
use atproto_oauth::jwk;
use axum::{
    extract::{Query, State},
    http::StatusCode,
    response::Html,
    routing::get,
    Router,
};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use chrono::{offset::LocalResult, Utc};
use reqwest::header::HeaderMap;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    collections::HashMap,
    sync::Arc,
    time::{SystemTime, UNIX_EPOCH},
};
use tokio::{net::TcpListener, sync::Mutex};
use tracing_subscriber::prelude::*;
use uuid::Uuid;

/// Application configuration
#[derive(Clone)]
struct AppConfig {
    /// Base URL of the AIP server
    aip_base_url: String,
    /// This demo client's base URL
    demo_base_url: String,
    /// Service DID for proxying ATProtocol requests
    service_did: Option<String>,
}

/// OAuth state storage for managing login sessions
type OAuthStateStorage = Arc<Mutex<HashMap<String, OAuthState>>>;

/// Storage for invoke responses
type InvokeResponseStorage = Arc<Mutex<Vec<InvokeResponse>>>;

/// DPoP key pair for signing proofs
#[derive(Clone)]
struct DPoPKeyPair {
    /// Private key for signing DPoP proofs (ES256)
    private_key: KeyData,
    /// Public key for JWK generation
    public_key: KeyData,
    /// Public key JWK for DPoP proofs
    public_key_jwk: serde_json::Value,
    /// JWK thumbprint for DPoP binding
    jkt: String,
}

/// Application state shared across handlers
#[derive(Clone)]
struct AppState {
    config: Arc<AppConfig>,
    http_client: reqwest::Client,
    oauth_states: OAuthStateStorage,
    registered_client: Arc<Mutex<Option<RegisteredClient>>>,
    dpop_key_pair: Arc<DPoPKeyPair>,
    invoke_responses: InvokeResponseStorage,
}

/// OAuth Authorization Server Metadata (RFC 8414)
#[derive(Debug, Deserialize)]
struct OAuthServerMetadata {
    issuer: String,
    authorization_endpoint: String,
    token_endpoint: String,
    pushed_authorization_request_endpoint: Option<String>,
    registration_endpoint: Option<String>,
    response_types_supported: Vec<String>,
    grant_types_supported: Option<Vec<String>>,
    code_challenge_methods_supported: Option<Vec<String>>,
    scopes_supported: Option<Vec<String>>,
    dpop_signing_alg_values_supported: Option<Vec<String>>,
}

/// Dynamic Client Registration Request (RFC 7591)
#[derive(Debug, Serialize)]
struct ClientRegistrationRequest {
    client_name: String,
    client_uri: Option<String>,
    redirect_uris: Vec<String>,
    response_types: Vec<String>,
    grant_types: Vec<String>,
    token_endpoint_auth_method: String,
    scope: String,
    contacts: Option<Vec<String>>,
    dpop_bound_access_tokens: Option<bool>,
}

/// Dynamic Client Registration Response (RFC 7591)
#[derive(Debug, Deserialize)]
struct ClientRegistrationResponse {
    client_id: String,
    client_secret: Option<String>,
    client_id_issued_at: Option<u64>,
    client_secret_expires_at: Option<u64>,
    registration_access_token: Option<String>,
}

/// Registered client credentials
#[derive(Debug, Clone)]
struct RegisteredClient {
    client_id: String,
    client_secret: Option<String>,
    registration_access_token: Option<String>,
    expires_at: Option<u64>,
}

/// OAuth state information stored between login and callback
#[derive(Debug, Clone)]
struct OAuthState {
    state: String,
    code_verifier: String,
    code_challenge: String,
    redirect_uri: String,
    scope: String,
}

/// PAR (Pushed Authorization Request) request
#[derive(Debug, Serialize)]
struct PARRequest {
    client_id: String,
    response_type: String,
    redirect_uri: String,
    scope: String,
    state: String,
    code_challenge: String,
    code_challenge_method: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    login_hint: Option<String>,
}

/// PAR response
#[derive(Debug, Deserialize)]
struct PARResponse {
    request_uri: String,
    expires_in: u64,
}

/// OAuth token request
#[derive(Debug, Serialize)]
struct TokenRequest {
    grant_type: String,
    client_id: String,
    code: String,
    redirect_uri: String,
    code_verifier: String,
}

/// OAuth token response
#[derive(Debug, Deserialize)]
struct TokenResponse {
    access_token: String,
    token_type: String,
    expires_in: Option<u64>,
    refresh_token: Option<String>,
    scope: Option<String>,
}

/// OAuth callback query parameters
#[derive(Debug, Deserialize)]
struct CallbackQuery {
    code: Option<String>,
    state: Option<String>,
    error: Option<String>,
    error_description: Option<String>,
}

/// Test page query parameters
#[derive(Debug, Deserialize)]
struct TestQuery {
    access_token: Option<String>,
    dpop_key: Option<String>,
}

/// Login route query parameters
#[derive(Debug, Deserialize)]
struct LoginQuery {
    handle: Option<String>,
}

/// Invoke endpoint query parameters
#[derive(Debug, Deserialize)]
struct InvokeQuery {
    access_token: String,
    dpop_key: String,
    service_did: String,

    #[serde(default)]
    force_refresh: Option<String>,
}

/// ATProtocol session response from AIP API
#[derive(Debug, Deserialize, Serialize)]
struct AtpSessionResponse {
    did: String,
    handle: String,
    access_token: String,
    token_type: String,
    scopes: Vec<String>,
    pds_endpoint: String,
    dpop_key: String,
    expires_at: i64,
}

/// Response from the invoke endpoint stored for display
#[derive(Debug, Clone)]
struct InvokeResponse {
    timestamp: String,
    aip_status: String,
    pds_status: String,
    did: String,
    handle: String,
    pds_response: String,
    expires: i64,
}

/// DPoP proof JWT claims
#[derive(Debug, Serialize)]
struct DPoPClaims {
    jti: String,
    htm: String,
    htu: String,
    iat: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    ath: Option<String>,
}

impl DPoPKeyPair {
    /// Generate a new ES256 key pair for DPoP
    fn generate() -> Result<Self, Box<dyn std::error::Error>> {
        let private_key = generate_key(KeyType::P256Private)?;
        let public_key = to_public(&private_key)?;
        let jwk_wrapped = jwk::generate(&public_key)?;
        let public_key_jwk: serde_json::Value = serde_json::to_value(&jwk_wrapped)?;
        let jkt = atproto_oauth::jwk::thumbprint(&jwk_wrapped)?;

        Ok(Self {
            private_key,
            public_key,
            public_key_jwk,
            jkt,
        })
    }

    /// Create from serialized KeyData string
    fn from_serialized(serialized: &str) -> Result<Self, Box<dyn std::error::Error>> {
        // Parse the JSON string to get key type and data
        let json_value: serde_json::Value = serde_json::from_str(serialized)?;
        let key_type = json_value
            .get("key_type")
            .and_then(|v| v.as_str())
            .ok_or("Missing key_type")?;
        let key_data = json_value
            .get("key_data")
            .and_then(|v| v.as_str())
            .ok_or("Missing key_data")?;

        // Decode the base64 key data
        let decoded_key = base64::engine::general_purpose::STANDARD.decode(key_data)?;

        // Create KeyData based on type
        let key_type_enum = match key_type {
            "P256Private" => KeyType::P256Private,
            "P384Private" => KeyType::P384Private,
            "K256Private" => KeyType::K256Private,
            _ => return Err("Unsupported key type".into()),
        };

        let private_key = KeyData::new(key_type_enum, decoded_key);

        let public_key = to_public(&private_key)?;
        let jwk_wrapped = jwk::generate(&public_key)?;
        let public_key_jwk: serde_json::Value = serde_json::to_value(&jwk_wrapped)?;
        let jkt = atproto_oauth::jwk::thumbprint(&jwk_wrapped)?;

        Ok(Self {
            private_key,
            public_key,
            public_key_jwk,
            jkt,
        })
    }

    /// Create a DPoP proof JWT
    fn create_dpop_proof(
        &self,
        method: &str,
        url: &str,
        access_token: Option<&str>,
    ) -> Result<String, Box<dyn std::error::Error>> {
        let now = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();

        let mut claims = DPoPClaims {
            jti: Uuid::new_v4().to_string(),
            htm: method.to_uppercase(),
            htu: url.to_string(),
            iat: now,
            ath: None,
        };

        if let Some(token) = access_token {
            let token_hash = Sha256::digest(token.as_bytes());
            claims.ath = Some(URL_SAFE_NO_PAD.encode(&token_hash));
        }

        let header_json = serde_json::json!({
            "typ": "dpop+jwt",
            "alg": "ES256",
            "jwk": self.public_key_jwk
        });

        let header_b64 = URL_SAFE_NO_PAD.encode(serde_json::to_string(&header_json)?);
        let claims_b64 = URL_SAFE_NO_PAD.encode(serde_json::to_string(&claims)?);

        let signing_input = format!("{}.{}", header_b64, claims_b64);

        let signature = sign(&self.private_key, signing_input.as_bytes())?;
        let signature_b64 = URL_SAFE_NO_PAD.encode(&signature);

        Ok(format!("{}.{}", signing_input, signature_b64))
    }
}

/// Generate PKCE code verifier and challenge
fn generate_pkce() -> (String, String) {
    use rand::Rng;

    const CHARSET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-._~";
    let mut rng = rand::thread_rng();
    let code_verifier: String = (0..128)
        .map(|_| {
            let idx = rng.gen_range(0..CHARSET.len());
            CHARSET[idx] as char
        })
        .collect();

    let challenge_hash = Sha256::digest(code_verifier.as_bytes());
    let code_challenge = URL_SAFE_NO_PAD.encode(&challenge_hash);

    (code_verifier, code_challenge)
}

/// Generate random state parameter
fn generate_state() -> String {
    Uuid::new_v4().to_string()
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Initialize tracing
    tracing_subscriber::registry()
        .with(tracing_subscriber::EnvFilter::new(
            std::env::var("RUST_LOG").unwrap_or_else(|_| "aip_lifecycle_website=debug,info".into()),
        ))
        .with(tracing_subscriber::fmt::layer().pretty())
        .init();

    // Configuration
    let config = AppConfig {
        aip_base_url: std::env::var("AIP_BASE_URL")
            .unwrap_or_else(|_| "http://localhost:8080".to_string()),
        demo_base_url: std::env::var("DEMO_BASE_URL")
            .unwrap_or_else(|_| "http://localhost:3003".to_string()),
        service_did: std::env::var("SERVICE_DID").ok(),
    };

    let port: u16 = std::env::var("PORT")
        .unwrap_or_else(|_| "3003".to_string())
        .parse()
        .unwrap_or(3003);

    tracing::info!("AIP Lifecycle Website starting up");
    tracing::info!("AIP Server: {}", config.aip_base_url);
    tracing::info!("Demo Client: {}", config.demo_base_url);
    tracing::info!("Service DID: {:?}", config.service_did);
    tracing::info!("Listening on port: {}", port);

    // Generate or load DPoP key pair
    let dpop_key_pair = Arc::new(if let Ok(serialized_key) = std::env::var("DPOP_KEY") {
        tracing::info!("Loading DPoP key from environment variable");
        DPoPKeyPair::from_serialized(&serialized_key)?
    } else {
        tracing::info!("Generating new DPoP key pair");
        DPoPKeyPair::generate()?
    });
    tracing::info!("DPoP key pair ready with JKT: {}", dpop_key_pair.jkt);

    // Initialize HTTP client
    let http_client = reqwest::Client::new();

    // Initialize storage
    let oauth_states: OAuthStateStorage = Arc::new(Mutex::new(HashMap::new()));
    let invoke_responses: InvokeResponseStorage = Arc::new(Mutex::new(Vec::new()));

    // Perform client registration
    let registered_client = Arc::new(Mutex::new(None));
    {
        match register_client(&config, &http_client, &dpop_key_pair).await {
            Ok(client) => {
                let mut client_guard = registered_client.lock().await;
                *client_guard = Some(client);
                tracing::info!("Client registration completed successfully");
            }
            Err(e) => {
                tracing::error!("Client registration failed: {}. Server may not be running or may not support dynamic registration.", e);
                tracing::warn!("Continuing without registered client - OAuth flows will fail until client is registered");
            }
        }
    }

    // Create application state
    let app_state = AppState {
        config: Arc::new(config),
        http_client,
        oauth_states,
        registered_client,
        dpop_key_pair,
        invoke_responses,
    };

    // Build the application
    let app = Router::new()
        .route("/", get(home_handler))
        .route("/login", get(login_handler))
        .route("/callback", get(callback_handler))
        .route("/test", get(test_handler))
        .route("/invoke", get(invoke_handler))
        .with_state(app_state);

    // Start the server
    let listener = TcpListener::bind(format!("0.0.0.0:{}", port)).await?;
    tracing::info!("AIP Lifecycle Website listening on port {}", port);
    tracing::info!("Open http://localhost:{} in your browser", port);

    axum::serve(listener, app).await?;

    Ok(())
}

/// Perform dynamic client registration
async fn register_client(
    config: &AppConfig,
    http_client: &reqwest::Client,
    _dpop_key_pair: &DPoPKeyPair,
) -> Result<RegisteredClient, Box<dyn std::error::Error>> {
    let auth_server_metadata_url = format!(
        "{}/.well-known/oauth-authorization-server",
        config.aip_base_url
    );

    tracing::info!(
        "Fetching OAuth server metadata from: {}",
        auth_server_metadata_url
    );

    let server_metadata = match http_client.get(&auth_server_metadata_url).send().await {
        Ok(response) => {
            if response.status().is_success() {
                match response.json::<OAuthServerMetadata>().await {
                    Ok(metadata) => {
                        tracing::info!("Successfully fetched OAuth server metadata");
                        metadata
                    }
                    Err(e) => {
                        return Err(format!("Failed to parse OAuth server metadata: {}", e).into());
                    }
                }
            } else {
                return Err(format!(
                    "OAuth server metadata request failed with status: {} {}",
                    response.status(),
                    response.text().await.expect("failure body ready")
                )
                .into());
            }
        }
        Err(e) => {
            return Err(format!("Failed to fetch OAuth server metadata: {}", e).into());
        }
    };

    let registration_endpoint = match server_metadata.registration_endpoint {
        Some(endpoint) => {
            tracing::info!("Dynamic client registration supported at: {}", endpoint);
            endpoint
        }
        None => {
            let fallback_endpoint = format!("{}/oauth/clients/register", config.aip_base_url);
            tracing::warn!(
                "No registration endpoint in metadata, trying fallback: {}",
                fallback_endpoint
            );
            fallback_endpoint
        }
    };

    let redirect_uri = format!("{}/callback", config.demo_base_url);

    let registration_request = ClientRegistrationRequest {
        client_name: "AIP Lifecycle Website".to_string(),
        client_uri: Some(config.demo_base_url.clone()),
        redirect_uris: vec![redirect_uri],
        response_types: vec!["code".to_string()],
        grant_types: vec!["authorization_code".to_string()],
        token_endpoint_auth_method: "client_secret_post".to_string(),
        scope: "atproto:atproto atproto:transition:generic".to_string(),
        contacts: Some(vec!["admin@lifecycle-website.example".to_string()]),
        dpop_bound_access_tokens: Some(true),
    };

    tracing::info!("Registering client: {}", registration_request.client_name);

    let registration_response = match http_client
        .post(&registration_endpoint)
        .json(&registration_request)
        .send()
        .await
    {
        Ok(response) => {
            if response.status().is_success() {
                match response.json::<ClientRegistrationResponse>().await {
                    Ok(resp) => {
                        tracing::info!(
                            "Client registration successful! Client ID: {}",
                            resp.client_id
                        );
                        resp
                    }
                    Err(e) => {
                        return Err(
                            format!("Failed to parse client registration response: {}", e).into(),
                        );
                    }
                }
            } else {
                let status = response.status();
                let error_text = response
                    .text()
                    .await
                    .unwrap_or_else(|_| "Unknown error".to_string());
                return Err(format!(
                    "Client registration failed with status: {} - {}",
                    status, error_text
                )
                .into());
            }
        }
        Err(e) => {
            return Err(format!("Failed to make client registration request: {}", e).into());
        }
    };

    let registered_client = RegisteredClient {
        client_id: registration_response.client_id,
        client_secret: registration_response.client_secret,
        registration_access_token: registration_response.registration_access_token,
        expires_at: registration_response.client_secret_expires_at,
    };

    Ok(registered_client)
}

/// Home page handler
async fn home_handler(State(state): State<AppState>) -> Html<String> {
    let client_status = {
        let client_guard = state.registered_client.lock().await;
        match client_guard.as_ref() {
            Some(client) => format!(
                r#"
                <div class="info">
                    <h3>✅ OAuth Client Registered</h3>
                    <p><strong>Client ID:</strong> {}</p>
                    <p><strong>DPoP JKT:</strong> {}</p>
                    <p><strong>Service DID:</strong> {}</p>
                </div>
                "#,
                html_escape::encode_text(&client.client_id),
                html_escape::encode_text(&state.dpop_key_pair.jkt),
                html_escape::encode_text(&state.config.service_did.as_deref().unwrap_or("Not configured"))
            ),
            None => r#"
                <div class="info">
                    <h3>⚠️ OAuth Client Not Registered</h3>
                    <p>Client registration failed during startup. OAuth flows will not work until the client is properly registered with the AIP server.</p>
                </div>
            "#.to_string(),
        }
    };

    Html(format!(
        r#"<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>AIP Lifecycle Website</title>
    <style>
        body {{
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
            max-width: 800px;
            margin: 0 auto;
            padding: 2rem;
            line-height: 1.6;
            background: #f0f2f5;
            color: #333;
        }}
        .container {{
            background: white;
            border-radius: 12px;
            padding: 2rem;
            box-shadow: 0 2px 10px rgba(0, 0, 0, 0.1);
        }}
        h1 {{
            color: #1a73e8;
            margin-bottom: 1rem;
        }}
        .auth-form {{
            border: 2px solid #e9ecef;
            border-radius: 8px;
            padding: 2rem;
            margin: 2rem 0;
            background: #f8f9fa;
        }}
        .form-group {{
            margin-bottom: 1.5rem;
        }}
        .form-label {{
            display: block;
            margin-bottom: 0.5rem;
            font-weight: 600;
            color: #495057;
        }}
        .form-input {{
            width: 100%;
            padding: 12px;
            border: 2px solid #ced4da;
            border-radius: 6px;
            font-size: 1rem;
            box-sizing: border-box;
        }}
        .form-input:focus {{
            outline: none;
            border-color: #1a73e8;
        }}
        .auth-button {{
            background: #1a73e8;
            color: white;
            padding: 12px 24px;
            border: none;
            border-radius: 6px;
            font-size: 1rem;
            cursor: pointer;
            transition: background 0.2s;
        }}
        .auth-button:hover {{
            background: #1557b0;
        }}
        .auth-button:disabled {{
            background: #6c757d;
            cursor: not-allowed;
        }}
        .info {{
            background: #f8f9fa;
            border: 1px solid #dee2e6;
            border-radius: 8px;
            padding: 1rem;
            margin: 1rem 0;
        }}
    </style>
    <script>
        function validateForm() {{
            const submitButton = document.getElementById('submitButton');
            // Always enable submit button since handle is optional
            submitButton.disabled = false;
        }}
        
        function handleSubmit(event) {{
            // Allow form submission regardless of handle value
            return true;
        }}
    </script>
</head>
<body>
    <div class="container">
        <h1>🔄 AIP Lifecycle Website</h1>
        <p>ATProtocol lifecycle management with DPoP authentication and service proxying</p>
        
        {}
        
        <div class="auth-form">
            <h3>🔐 ATProtocol Authentication</h3>
            <p>Enter your ATProtocol handle to start the authentication process, or leave empty to be prompted by AIP:</p>
            
            <form action="/login" method="get" onsubmit="return handleSubmit(event)">
                <div class="form-group">
                    <label for="handle" class="form-label">ATProtocol Handle (Optional)</label>
                    <input 
                        type="text" 
                        id="handle" 
                        name="handle" 
                        class="form-input"
                        placeholder="alice.bsky.social (optional)"
                        oninput="validateForm()"
                    />
                </div>
                
                <button type="submit" id="submitButton" class="auth-button">
                    Start OAuth Login
                </button>
            </form>
        </div>
    </div>
</body>
</html>"#,
        client_status
    ))
}

/// OAuth login handler
async fn login_handler(
    State(state): State<AppState>,
    Query(query): Query<LoginQuery>,
) -> Result<axum::response::Redirect, (StatusCode, Html<String>)> {
    let handle_desc = query
        .handle
        .as_deref()
        .unwrap_or("(none - will use login form)");
    tracing::info!("Starting OAuth login flow with handle: {}", handle_desc);

    let client_credentials = {
        let client_guard = state.registered_client.lock().await;
        match client_guard.as_ref() {
            Some(client) => client.clone(),
            None => {
                tracing::error!("No registered client found");
                return Err((StatusCode::INTERNAL_SERVER_ERROR, Html(
                    "<!DOCTYPE html><html><body><h1>Configuration Error</h1><p>No registered OAuth client found.</p><a href=\"/\">← Back to Home</a></body></html>".to_string()
                )));
            }
        }
    };

    let auth_server_metadata_url = format!(
        "{}/.well-known/oauth-authorization-server",
        state.config.aip_base_url
    );

    tracing::info!(
        "Fetching OAuth server metadata from: {}",
        auth_server_metadata_url
    );

    let server_metadata = match state
        .http_client
        .get(&auth_server_metadata_url)
        .send()
        .await
    {
        Ok(response) => {
            if response.status().is_success() {
                match response.json::<OAuthServerMetadata>().await {
                    Ok(metadata) => {
                        tracing::info!("Successfully fetched OAuth server metadata");
                        metadata
                    }
                    Err(e) => {
                        tracing::error!("Failed to parse OAuth server metadata: {}", e);
                        return Err((StatusCode::INTERNAL_SERVER_ERROR, Html(format!(
                            "<!DOCTYPE html><html><body><h1>OAuth Metadata Error</h1><p>Failed to parse OAuth server metadata: {}</p><a href=\"/\">← Back to Home</a></body></html>", 
                            e
                        ))));
                    }
                }
            } else {
                tracing::error!(
                    "OAuth server metadata request failed with status: {}",
                    response.status()
                );
                return Err((StatusCode::BAD_GATEWAY, Html(format!(
                    "<!DOCTYPE html><html><body><h1>OAuth Metadata Error</h1><p>Failed to fetch OAuth server metadata. Status: {}</p><a href=\"/\">← Back to Home</a></body></html>", 
                    response.status()
                ))));
            }
        }
        Err(e) => {
            tracing::error!("Failed to fetch OAuth server metadata: {}", e);
            return Err((StatusCode::INTERNAL_SERVER_ERROR, Html(format!(
                "<!DOCTYPE html><html><body><h1>OAuth Metadata Error</h1><p>Failed to connect to OAuth server: {}</p><a href=\"/\">← Back to Home</a></body></html>", 
                e
            ))));
        }
    };

    let (code_verifier, code_challenge) = generate_pkce();
    let oauth_state = generate_state();

    let redirect_uri = format!("{}/callback", state.config.demo_base_url);
    let scope = "atproto:atproto atproto:transition:generic".to_string();

    let oauth_state_data = OAuthState {
        state: oauth_state.clone(),
        code_verifier: code_verifier.clone(),
        code_challenge: code_challenge.clone(),
        redirect_uri: redirect_uri.clone(),
        scope: scope.clone(),
    };

    {
        let mut states = state.oauth_states.lock().await;
        states.insert(oauth_state.clone(), oauth_state_data);
        tracing::info!("Stored OAuth state: {}", oauth_state);
    }

    if let Some(par_endpoint) = &server_metadata.pushed_authorization_request_endpoint {
        tracing::info!("Using PAR endpoint: {}", par_endpoint);

        let dpop_proof = match state
            .dpop_key_pair
            .create_dpop_proof("POST", par_endpoint, None)
        {
            Ok(proof) => proof,
            Err(e) => {
                tracing::error!("Failed to create DPoP proof for PAR: {}", e);
                return Err((StatusCode::INTERNAL_SERVER_ERROR, Html(format!(
                    "<!DOCTYPE html><html><body><h1>DPoP Error</h1><p>Failed to create DPoP proof: {}</p><a href=\"/\">← Back to Home</a></body></html>", 
                    e
                ))));
            }
        };

        let par_request = PARRequest {
            client_id: client_credentials.client_id.clone(),
            response_type: "code".to_string(),
            redirect_uri: redirect_uri.clone(),
            scope: scope.clone(),
            state: oauth_state.clone(),
            code_challenge: code_challenge.clone(),
            code_challenge_method: "S256".to_string(),
            login_hint: query
                .handle
                .as_ref()
                .filter(|h| !h.trim().is_empty())
                .cloned(),
        };

        let par_response = match state
            .http_client
            .post(par_endpoint)
            .header("DPoP", dpop_proof)
            .form(&par_request)
            .send()
            .await
        {
            Ok(response) => {
                if response.status().is_success() {
                    match response.json::<PARResponse>().await {
                        Ok(par_resp) => {
                            tracing::info!("PAR request successful: {:?}", par_resp);
                            par_resp
                        }
                        Err(e) => {
                            tracing::error!("Failed to parse PAR response: {}", e);
                            return Err((StatusCode::INTERNAL_SERVER_ERROR, Html(format!(
                                "<!DOCTYPE html><html><body><h1>PAR Error</h1><p>Failed to parse PAR response: {}</p><a href=\"/\">← Back to Home</a></body></html>", 
                                e
                            ))));
                        }
                    }
                } else {
                    let status = response.status();
                    let error_text = response
                        .text()
                        .await
                        .unwrap_or_else(|_| "Unknown error".to_string());
                    tracing::error!(
                        "PAR request failed with status: {} - {}",
                        status,
                        error_text
                    );
                    return Err((StatusCode::BAD_GATEWAY, Html(format!(
                        "<!DOCTYPE html><html><body><h1>PAR Error</h1><p>PAR request failed. Status: {}</p><p>Error: {}</p><a href=\"/\">← Back to Home</a></body></html>", 
                        status,
                        html_escape::encode_text(&error_text)
                    ))));
                }
            }
            Err(e) => {
                tracing::error!("Failed to make PAR request: {}", e);
                return Err((StatusCode::INTERNAL_SERVER_ERROR, Html(format!(
                    "<!DOCTYPE html><html><body><h1>PAR Error</h1><p>Failed to connect for PAR request: {}</p><a href=\"/\">← Back to Home</a></body></html>", 
                    e
                ))));
            }
        };

        let auth_url = format!(
            "{}?client_id={}&request_uri={}",
            server_metadata.authorization_endpoint,
            urlencoding::encode(&client_credentials.client_id),
            urlencoding::encode(&par_response.request_uri)
        );

        tracing::info!("Redirecting to authorization endpoint: {}", auth_url);
        Ok(axum::response::Redirect::to(&auth_url))
    } else {
        tracing::info!("PAR not supported, using traditional OAuth flow");

        let mut auth_url_params = vec![
            format!("response_type=code"),
            format!(
                "client_id={}",
                urlencoding::encode(&client_credentials.client_id)
            ),
            format!("redirect_uri={}", urlencoding::encode(&redirect_uri)),
            format!("scope={}", urlencoding::encode(&scope)),
            format!("state={}", urlencoding::encode(&oauth_state)),
            format!("code_challenge={}", urlencoding::encode(&code_challenge)),
            format!("code_challenge_method=S256"),
        ];

        // Only include login_hint if handle is provided and not empty
        if let Some(handle) = &query.handle {
            if !handle.trim().is_empty() {
                auth_url_params.push(format!("login_hint={}", urlencoding::encode(handle)));
            }
        }

        let auth_url = format!(
            "{}?{}",
            server_metadata.authorization_endpoint,
            auth_url_params.join("&")
        );

        tracing::info!("Redirecting to authorization endpoint: {}", auth_url);
        Ok(axum::response::Redirect::to(&auth_url))
    }
}

/// OAuth callback handler
async fn callback_handler(
    State(state): State<AppState>,
    Query(query): Query<CallbackQuery>,
) -> Result<axum::response::Redirect, (StatusCode, Html<String>)> {
    tracing::info!("OAuth callback received: {:?}", query);

    let client_credentials = {
        let client_guard = state.registered_client.lock().await;
        match client_guard.as_ref() {
            Some(client) => client.clone(),
            None => {
                tracing::error!("No registered client found in callback handler");
                return Err((StatusCode::INTERNAL_SERVER_ERROR, Html(
                    "<!DOCTYPE html><html><body><h1>Configuration Error</h1><p>No registered OAuth client found.</p><a href=\"/\">← Back to Home</a></body></html>".to_string()
                )));
            }
        }
    };

    if let Some(error) = &query.error {
        let error_description = query
            .error_description
            .as_deref()
            .unwrap_or("Unknown OAuth error");

        tracing::error!("OAuth callback error: {} - {}", error, error_description);

        return Err((StatusCode::BAD_REQUEST, Html(format!(
            "<!DOCTYPE html><html><body><h1>Authentication Error</h1><p>OAuth Error: {}</p><p>{}</p><a href=\"/\">← Back to Home</a></body></html>",
            error, error_description
        ))));
    }

    let authorization_code = query.code.ok_or_else(|| {
        tracing::error!("No authorization code received in callback");
        (
            StatusCode::BAD_REQUEST,
            Html("<!DOCTYPE html><html><body><h1>Invalid Callback</h1><p>No authorization code received.</p><a href=\"/\">← Back to Home</a></body></html>".to_string()),
        )
    })?;

    let received_state = query.state.ok_or_else(|| {
        tracing::error!("No state parameter received in callback");
        (
            StatusCode::BAD_REQUEST,
            Html("<!DOCTYPE html><html><body><h1>Invalid Callback</h1><p>No state parameter received.</p><a href=\"/\">← Back to Home</a></body></html>".to_string()),
        )
    })?;

    let oauth_state_data = {
        let mut states = state.oauth_states.lock().await;
        states.remove(&received_state).ok_or_else(|| {
            tracing::error!("OAuth state not found or expired: {}", received_state);
            (
                StatusCode::BAD_REQUEST,
                Html("<!DOCTYPE html><html><body><h1>Invalid OAuth State</h1><p>OAuth state not found or expired.</p><a href=\"/\">← Back to Home</a></body></html>".to_string()),
            )
        })?
    };

    tracing::info!("Valid OAuth state found, proceeding with token exchange");

    let auth_server_metadata_url = format!(
        "{}/.well-known/oauth-authorization-server",
        state.config.aip_base_url
    );
    let server_metadata = match state
        .http_client
        .get(&auth_server_metadata_url)
        .send()
        .await
    {
        Ok(response) => {
            if response.status().is_success() {
                match response.json::<OAuthServerMetadata>().await {
                    Ok(metadata) => metadata,
                    Err(e) => {
                        tracing::error!("Failed to parse OAuth server metadata in callback: {}", e);
                        return Err((StatusCode::INTERNAL_SERVER_ERROR, Html(format!(
                            "<!DOCTYPE html><html><body><h1>OAuth Metadata Error</h1><p>Failed to parse OAuth server metadata: {}</p><a href=\"/\">← Back to Home</a></body></html>", 
                            e
                        ))));
                    }
                }
            } else {
                tracing::error!(
                    "OAuth server metadata request failed in callback with status: {}",
                    response.status()
                );
                return Err((StatusCode::BAD_GATEWAY, Html(format!(
                    "<!DOCTYPE html><html><body><h1>OAuth Metadata Error</h1><p>Failed to fetch OAuth server metadata. Status: {}</p><a href=\"/\">← Back to Home</a></body></html>", 
                    response.status()
                ))));
            }
        }
        Err(e) => {
            tracing::error!("Failed to fetch OAuth server metadata in callback: {}", e);
            return Err((StatusCode::INTERNAL_SERVER_ERROR, Html(format!(
                "<!DOCTYPE html><html><body><h1>OAuth Metadata Error</h1><p>Failed to connect to OAuth server: {}</p><a href=\"/\">← Back to Home</a></body></html>", 
                e
            ))));
        }
    };

    let dpop_proof = match state.dpop_key_pair.create_dpop_proof(
        "POST",
        &server_metadata.token_endpoint,
        None,
    ) {
        Ok(proof) => proof,
        Err(e) => {
            tracing::error!("Failed to create DPoP proof for token exchange: {}", e);
            return Err((StatusCode::INTERNAL_SERVER_ERROR, Html(format!(
                "<!DOCTYPE html><html><body><h1>DPoP Error</h1><p>Failed to create DPoP proof for token exchange: {}</p><a href=\"/\">← Back to Home</a></body></html>", 
                e
            ))));
        }
    };

    let token_request = TokenRequest {
        grant_type: "authorization_code".to_string(),
        client_id: client_credentials.client_id.clone(),
        code: authorization_code,
        redirect_uri: oauth_state_data.redirect_uri,
        code_verifier: oauth_state_data.code_verifier,
    };

    tracing::info!(
        "Exchanging authorization code for access token at: {}",
        server_metadata.token_endpoint
    );

    let mut request_builder = state
        .http_client
        .post(&server_metadata.token_endpoint)
        .header("DPoP", dpop_proof)
        .form(&token_request);

    if let Some(client_secret) = &client_credentials.client_secret {
        tracing::debug!("Using client secret authentication for token exchange");
        request_builder =
            request_builder.basic_auth(&client_credentials.client_id, Some(client_secret));
    }

    let token_response = match request_builder.send().await {
        Ok(response) => {
            if response.status().is_success() {
                match response.json::<TokenResponse>().await {
                    Ok(token_resp) => {
                        tracing::info!(?token_resp, "Successfully exchanged code for access token");
                        token_resp
                    }
                    Err(e) => {
                        tracing::error!("Failed to parse token response: {}", e);
                        return Err((StatusCode::INTERNAL_SERVER_ERROR, Html(format!(
                            "<!DOCTYPE html><html><body><h1>Token Exchange Error</h1><p>Failed to parse token response: {}</p><a href=\"/\">← Back to Home</a></body></html>", 
                            e
                        ))));
                    }
                }
            } else {
                let status = response.status();
                let error_text = response
                    .text()
                    .await
                    .unwrap_or_else(|_| "Unknown error".to_string());
                tracing::error!(
                    "Token exchange failed with status: {} - {}",
                    status,
                    error_text
                );
                return Err((StatusCode::BAD_GATEWAY, Html(format!(
                    "<!DOCTYPE html><html><body><h1>Token Exchange Error</h1><p>Token exchange failed. Status: {}</p><p>Error: {}</p><a href=\"/\">← Back to Home</a></body></html>", 
                    status,
                    html_escape::encode_text(&error_text)
                ))));
            }
        }
        Err(e) => {
            tracing::error!("Failed to make token exchange request: {}", e);
            return Err((StatusCode::INTERNAL_SERVER_ERROR, Html(format!(
                "<!DOCTYPE html><html><body><h1>Token Exchange Error</h1><p>Failed to connect for token exchange: {}</p><a href=\"/\">← Back to Home</a></body></html>", 
                e
            ))));
        }
    };

    // Serialize the DPoP key for passing to the test page
    let dpop_key_serialized = {
        let key_type_str = match state.dpop_key_pair.private_key.key_type() {
            KeyType::P256Private => "P256Private",
            KeyType::P384Private => "P384Private",
            KeyType::K256Private => "K256Private",
            _ => {
                tracing::error!("Unsupported key type for serialization");
                return Err((StatusCode::INTERNAL_SERVER_ERROR, Html(
                    "<!DOCTYPE html><html><body><h1>Key Serialization Error</h1><p>Unsupported key type.</p><a href=\"/\">← Back to Home</a></body></html>".to_string()
                )));
            }
        };

        serde_json::json!({
            "key_type": key_type_str,
            "key_data": base64::engine::general_purpose::STANDARD.encode(state.dpop_key_pair.private_key.bytes())
        }).to_string()
    };

    // Redirect to test page with access token and DPoP key
    let test_url = format!(
        "/test?access_token={}&dpop_key={}",
        urlencoding::encode(&token_response.access_token),
        urlencoding::encode(&dpop_key_serialized)
    );

    tracing::info!("Redirecting to test page");
    Ok(axum::response::Redirect::to(&test_url))
}

/// Test page handler
async fn test_handler(
    State(state): State<AppState>,
    Query(query): Query<TestQuery>,
) -> Html<String> {
    let (access_token, dpop_key) = match (query.access_token, query.dpop_key) {
        (Some(token), Some(key)) => (token, key),
        _ => {
            return Html(
                r#"<!DOCTYPE html>
<html><body>
<h1>Missing Credentials</h1>
<p>No access token or DPoP key provided. Please complete the OAuth flow first.</p>
<a href="/">← Back to Home</a>
</body></html>"#
                    .to_string(),
            );
        }
    };

    let service_did = state
        .config
        .service_did
        .clone()
        .unwrap_or_else(|| "did:plc:example".to_string());

    let now = Utc::now().timestamp();
    use chrono::TimeZone;

    // Get past responses
    let past_responses = {
        let responses = state.invoke_responses.lock().await;
        responses.iter()
            .rev()
            .take(10)
            .map(|resp| {

                let expires_at = match Utc.timestamp_opt(resp.expires, 0) {
                    LocalResult::Single(value) => value.to_string(),
                    _ => "unknown".to_string()
                };

                format!(
                    r#"<div class="response-item">
                        <div class="response-header">
                            <span class="timestamp">{}</span>
                            <span class="did">{} ({})</span>
                        </div>
                        <div class="response-status">
                            <span class="status-label">AIP:</span> <span class="{}">{}</span>
                            <span class="status-label">PDS:</span> <span class="{}">{}</span>
                            <span class="status-label">Session Expires:</span> <span class="{}">{}</span>
                        </div>
                        <details>
                            <summary>PDS Response</summary>
                            <pre>{}</pre>
                        </details>
                    </div>"#,
                    html_escape::encode_text(&resp.timestamp),
                    html_escape::encode_text(&resp.did),
                    html_escape::encode_text(&resp.handle),
                    if resp.aip_status == "Success" { "status-success" } else { "status-error" },
                    html_escape::encode_text(&resp.aip_status),
                    if resp.pds_status == "Success" { "status-success" } else { "status-error" },
                    html_escape::encode_text(&resp.aip_status),
                    if resp.expires > now { "status-success" } else { "status-error" },
                    html_escape::encode_text(&expires_at),
                    html_escape::encode_text(&resp.pds_response)
                )
            })
            .collect::<Vec<_>>()
            .join("\n")
    };

    // Build HTMX attributes
    let hx_get = format!(
        "/invoke?access_token={}&dpop_key={}&service_did={}",
        urlencoding::encode(&access_token),
        urlencoding::encode(&dpop_key),
        urlencoding::encode(&service_did)
    );

    // Build the HTML page with proper string concatenation
    let mut html = String::from(
        r#"<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Test - AIP Lifecycle Website</title>
    <script src="https://unpkg.com/htmx.org@1.9.10"></script>
    <style>
        body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
            max-width: 900px;
            margin: 0 auto;
            padding: 2rem;
            line-height: 1.6;
            background: #f0f2f5;
        }
        .container {
            background: white;
            border-radius: 12px;
            padding: 2rem;
            box-shadow: 0 2px 10px rgba(0, 0, 0, 0.1);
        }
        h1 {
            color: #1a73e8;
            margin-bottom: 1rem;
        }
        .invoke-section {
            background: #f8f9fa;
            border: 2px solid #e9ecef;
            border-radius: 8px;
            padding: 1.5rem;
            margin: 2rem 0;
        }
        .invoke-button {
            background: #1a73e8;
            color: white;
            padding: 12px 24px;
            border: none;
            border-radius: 6px;
            font-size: 1rem;
            cursor: pointer;
            transition: all 0.2s;
        }
        .invoke-button:hover {
            background: #1557b0;
        }
        .invoke-button:disabled {
            background: #6c757d;
            cursor: not-allowed;
        }
        .refresh-button {
            background: #28a745;
            color: white;
            padding: 8px 16px;
            border: none;
            border-radius: 6px;
            font-size: 0.9rem;
            cursor: pointer;
            transition: all 0.2s;
            margin-left: 1rem;
        }
        .refresh-button:hover {
            background: #218838;
        }
        .checkbox-container {
            margin-bottom: 1rem;
            display: flex;
            align-items: center;
        }
        .checkbox-container input[type="checkbox"] {
            margin-right: 0.5rem;
        }
        .checkbox-container label {
            font-weight: 500;
        }
        #invoke-result {
            margin-top: 1rem;
            padding: 1rem;
            background: #f8f9fa;
            border-radius: 6px;
            border: 1px solid #dee2e6;
        }
        .responses-section {
            margin-top: 2rem;
        }
        .response-item {
            background: #f8f9fa;
            border: 1px solid #dee2e6;
            border-radius: 6px;
            padding: 1rem;
            margin-bottom: 1rem;
        }
        .response-header {
            display: flex;
            justify-content: space-between;
            margin-bottom: 0.5rem;
            font-weight: 600;
        }
        .timestamp {
            color: #6c757d;
            font-size: 0.9rem;
        }
        .did {
            color: #495057;
            font-family: monospace;
            font-size: 0.9rem;
        }
        .response-status {
            margin-bottom: 0.5rem;
        }
        .status-label {
            font-weight: 600;
            margin-right: 0.5rem;
        }
        .status-success {
            color: #28a745;
        }
        .status-error {
            color: #dc3545;
        }
        details {
            margin-top: 0.5rem;
        }
        summary {
            cursor: pointer;
            color: #1a73e8;
            font-weight: 500;
        }
        pre {
            background: white;
            border: 1px solid #dee2e6;
            border-radius: 4px;
            padding: 0.5rem;
            overflow-x: auto;
            font-size: 0.875rem;
            margin-top: 0.5rem;
        }
        .loading {
            display: inline-block;
            width: 16px;
            height: 16px;
            border: 2px solid #f3f3f3;
            border-top: 2px solid #1a73e8;
            border-radius: 50%;
            animation: spin 1s linear infinite;
            margin-left: 8px;
            vertical-align: middle;
        }
        @keyframes spin {
            0% { transform: rotate(0deg); }
            100% { transform: rotate(360deg); }
        }
    </style>
    <script>
        function getForceRefreshValue() {
            const checkbox = document.getElementById('force-refresh-checkbox');
            return checkbox.checked ? 'force_refresh' : '';
        }
        
        function refreshPage() {
            window.location.reload();
        }
    </script>
</head>
<body>
    <div class="container">
        <h1>🧪 Lifecycle Test Page</h1>
        <p>You are now authenticated. Use the button below to test DPoP-authenticated API calls.</p>
        
        <div class="invoke-section">
            <h3>🚀 Invoke DPoP API Calls</h3>
            <p>Click the button to make authenticated requests to AIP and the PDS with the configured service DID.</p>
            <p><strong>Service DID:</strong> <code>"#,
    );

    html.push_str(&html_escape::encode_text(&service_did));
    html.push_str("</code></p>\n            \n            ");
    html.push_str(r#"<div class="checkbox-container">
                <input type="checkbox" id="force-refresh-checkbox">
                <label for="force-refresh-checkbox">Force refresh session (even if not expired)</label>
            </div>
            
            <button class="invoke-button" id="invoke-button" "#);
    html.push_str("hx-get=\"");
    html.push_str(&html_escape::encode_text(&hx_get));
    html.push_str("\" ");
    html.push_str("hx-vals='js:{force_refresh: getForceRefreshValue()}' ");
    html.push_str("hx-target=\"#invoke-result\" ");
    html.push_str("hx-indicator=\"#loading\">");
    html.push_str(
        r#"
                Invoke API Calls
                <span id="loading" class="loading" style="display:none;"></span>
            </button>
            
            <button class="refresh-button" onclick="refreshPage()">
                🔄 Refresh Page
            </button>
            
            <div id="invoke-result"></div>
        </div>
        
        <div class="responses-section">
            <h3>📊 Past Responses</h3>
            <div id="past-responses">
                "#,
    );

    if past_responses.is_empty() {
        html.push_str(r#"<p style="color: #6c757d;">No responses yet. Click the button above to make your first API call.</p>"#);
    } else {
        html.push_str(&past_responses);
    }

    html.push_str(
        r#"
            </div>
        </div>
        
        <div style="margin-top: 2rem;">
            <a href="/" style="color: #1a73e8; text-decoration: none;">← Back to Home</a>
        </div>
    </div>
</body>
</html>"#,
    );

    Html(html)
}

/// Invoke endpoint handler
async fn invoke_handler(
    State(state): State<AppState>,
    Query(query): Query<InvokeQuery>,
) -> Result<Html<String>, (StatusCode, Html<String>)> {
    tracing::info!(
        ?query,
        "Invoke endpoint called with service DID: {}",
        query.service_did
    );

    let now = Utc::now();

    // Parse the DPoP key
    let dpop_key_pair = match DPoPKeyPair::from_serialized(&query.dpop_key) {
        Ok(key_pair) => key_pair,
        Err(e) => {
            tracing::error!("Failed to parse DPoP key: {}", e);
            return Ok(Html(format!(
                r#"<div class="error">❌ Failed to parse DPoP key: {}<br/{}</div>"#,
                html_escape::encode_text(&e.to_string()),
                html_escape::encode_text(&now.to_string())
            )));
        }
    };

    // Step 1: Call AIP's /api/atprotocol/session endpoint
    let session_url = if query.force_refresh.is_some_and(|v| &v == "force_refresh") {
        format!(
            "{}/api/atprotocol/session?force_refresh=force_refresh",
            state.config.aip_base_url
        )
    } else {
        format!("{}/api/atprotocol/session", state.config.aip_base_url)
    };

    let dpop_auth = DPoPAuth {
        dpop_private_key_data: dpop_key_pair.private_key.clone(),
        oauth_access_token: query.access_token.clone(),
    };

    let session_json = match get_dpop_json_with_headers(
        &state.http_client,
        &dpop_auth,
        &session_url,
        &HeaderMap::new(),
    )
    .await
    {
        Ok(json) => json,
        Err(e) => {
            tracing::error!("Failed to get AIP session: {}", e);
            return Ok(Html(format!(
                r#"<div class="error">❌ Failed to get AIP session: {}</div>"#,
                html_escape::encode_text(&e.to_string())
            )));
        }
    };
    tracing::info!(?session_json, "session json");

    let session_response: AtpSessionResponse = match serde_json::from_value(session_json.clone()) {
        Ok(response) => response,
        Err(e) => {
            tracing::error!("Failed to parse session response: {}", e);
            return Ok(Html(format!(
                r#"<div class="error">❌ Failed to parse session response: {}<br/>{}</div>"#,
                html_escape::encode_text(&e.to_string()),
                html_escape::encode_text(&now.to_string())
            )));
        }
    };
    tracing::info!(?session_response, "session response");

    tracing::info!(
        "AIP session retrieved successfully for DID: {}",
        session_response.did
    );

    // Step 2: Call the PDS endpoint
    let pds_endpoint = session_response.pds_endpoint.clone();
    let pds_url = format!(
        "{}/xrpc/garden.lexicon.ngerakines.helloworld.Hello",
        pds_endpoint
    );

    // Create headers with atproto-proxy
    let mut headers = HeaderMap::new();
    headers.insert("atproto-proxy", query.service_did.parse().unwrap());

    let private_hello_world_key_data = identify_key(&session_response.dpop_key).expect("boo");

    // Use the DPoP authentication from the session response
    let pds_dpop_auth = DPoPAuth {
        dpop_private_key_data: private_hello_world_key_data,
        oauth_access_token: session_response.access_token.clone(),
    };

    let pds_result =
        match get_dpop_json_with_headers(&state.http_client, &pds_dpop_auth, &pds_url, &headers)
            .await
        {
            Ok(json) => (json, "Success"),
            Err(e) => {
                tracing::error!("Failed to call PDS endpoint: {}", e);
                (serde_json::json!({"error": e.to_string()}), "Error")
            }
        };

    // Store the response
    let invoke_response = InvokeResponse {
        timestamp: chrono::Utc::now()
            .format("%Y-%m-%d %H:%M:%S UTC")
            .to_string(),
        aip_status: "Success".to_string(),
        pds_status: pds_result.1.to_string(),
        did: session_response.did.clone(),
        handle: session_response.handle.clone(),
        pds_response: serde_json::to_string_pretty(&pds_result.0)
            .unwrap_or_else(|_| "Failed to serialize".to_string()),
        expires: session_response.expires_at,
    };

    {
        let mut responses = state.invoke_responses.lock().await;
        responses.push(invoke_response.clone());
        if responses.len() > 100 {
            responses.remove(0);
        }
    }

    // Return HTML snippet with results
    Ok(Html(format!(
        r#"<div class="result-summary">
            <h4>✅ API Calls Completed</h4>
            <div class="api-call">
                <strong>1. AIP Session Call:</strong>
                <ul>
                    <li>Endpoint: <code>{}</code></li>
                    <li>Status: <span class="status-success">Success</span></li>
                    <li>DID: <code>{}</code></li>
                    <li>Handle: <code>{}</code></li>
                </ul>
            </div>
            <div class="api-call">
                <strong>2. PDS Hello World Call:</strong>
                <ul>
                    <li>Endpoint: <code>{}</code></li>
                    <li>Status: <span class="{}">{}</span></li>
                    <li>Proxy DID: <code>{}</code></li>
                </ul>
            </div>
            <p style="margin-top: 1rem; color: #6c757d;">{}</p>
        </div>"#,
        html_escape::encode_text(&session_url),
        html_escape::encode_text(&session_response.did),
        html_escape::encode_text(&session_response.handle),
        html_escape::encode_text(&pds_url),
        if pds_result.1 == "Success" {
            "status-success"
        } else {
            "status-error"
        },
        pds_result.1,
        html_escape::encode_text(&query.service_did),
        html_escape::encode_text(&now.to_string())
    )))
}
