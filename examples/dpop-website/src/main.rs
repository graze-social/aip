//! AIP Demo DPoP Client Website
//!
//! A minimal functional website that demonstrates authentication with AIP (ATProtocol Identity Provider)
//! using DPoP (Demonstration of Proof-of-Possession) tokens and PAR (Pushed Authorization Request).
//! This demo client includes:
//! - Home page with authentication link
//! - OAuth callback handler with DPoP token binding
//! - Protected route that displays ATProtocol session information using DPoP-bound tokens
//! - Full DPoP implementation with proof generation and key management

use atproto_client::client::{get_dpop_json_with_headers, DPoPAuth};
use atproto_identity::key::{generate_key, sign, to_public, KeyData, KeyType};
use atproto_oauth::jwk;
use axum::{
    extract::{Query, State},
    http::StatusCode,
    response::Html,
    routing::get,
    Router,
};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
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
    /// Base URL of the AIP server (e.g., "http://localhost:8080")
    aip_base_url: String,
    /// This demo client's base URL (e.g., "http://localhost:3001")
    demo_base_url: String,
}

/// OAuth state storage for managing login sessions
type OAuthStateStorage = Arc<Mutex<HashMap<String, OAuthState>>>;

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

/// OAuth Protected Resource Metadata  
#[derive(Debug, Deserialize)]
struct OAuthResourceMetadata {
    resource: String,
    authorization_servers: Vec<String>,
    bearer_methods_supported: Option<Vec<String>>,
    resource_documentation: Option<String>,
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
    logo_uri: Option<String>,
    policy_uri: Option<String>,
    tos_uri: Option<String>,
    software_id: Option<String>,
    software_version: Option<String>,
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
    registration_client_uri: Option<String>,
    client_name: Option<String>,
    client_uri: Option<String>,
    redirect_uris: Vec<String>,
    response_types: Vec<String>,
    grant_types: Vec<String>,
    token_endpoint_auth_method: String,
    scope: Option<String>,
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

/// Protected route query parameters
#[derive(Debug, Deserialize)]
struct ProtectedQuery {
    #[serde(rename = "access_token")]
    token: Option<String>,
}

/// Login route query parameters
#[derive(Debug, Deserialize)]
struct LoginQuery {
    subject: Option<String>,
}

/// ATProtocol session response from AIP API
#[derive(Debug, Deserialize, Serialize)]
struct AtpSessionResponse {
    did: String,
    handle: Option<String>,
    access_token: String,
    token_type: String,
    scopes: Vec<String>,
    pds_endpoint: Option<String>,
    dpop_jkt: Option<String>,
    expires_at: Option<i64>,
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
        // Generate ES256 (P-256) key pair using atproto_identity
        let private_key = generate_key(KeyType::P256Private)?;
        let public_key = to_public(&private_key)?;

        // Generate JWK from public key using atproto_oauth
        let jwk_wrapped = jwk::generate(&public_key)?;
        // Convert WrappedJsonWebKey to serde_json::Value using serde_json::to_value
        let public_key_jwk: serde_json::Value = serde_json::to_value(&jwk_wrapped)?;

        // Calculate JWK thumbprint
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

        // Create claims
        let mut claims = DPoPClaims {
            jti: Uuid::new_v4().to_string(),
            htm: method.to_uppercase(),
            htu: url.to_string(),
            iat: now,
            ath: None,
        };

        // Add access token hash if provided
        if let Some(token) = access_token {
            let token_hash = Sha256::digest(token.as_bytes());
            claims.ath = Some(URL_SAFE_NO_PAD.encode(&token_hash));
        }

        // Create header with embedded JWK
        let header_json = serde_json::json!({
            "typ": "dpop+jwt",
            "alg": "ES256",
            "jwk": self.public_key_jwk
        });

        // Encode header and claims
        let header_b64 = URL_SAFE_NO_PAD.encode(serde_json::to_string(&header_json)?);
        let claims_b64 = URL_SAFE_NO_PAD.encode(serde_json::to_string(&claims)?);

        let signing_input = format!("{}.{}", header_b64, claims_b64);

        // Sign the data using atproto_identity
        let signature = sign(&self.private_key, signing_input.as_bytes())?;
        let signature_b64 = URL_SAFE_NO_PAD.encode(&signature);

        Ok(format!("{}.{}", signing_input, signature_b64))
    }
}

/// Generate PKCE code verifier and challenge
fn generate_pkce() -> (String, String) {
    use rand::Rng;

    // Generate code verifier (43-128 characters, URL-safe)
    const CHARSET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-._~";
    let mut rng = rand::thread_rng();
    let code_verifier: String = (0..128)
        .map(|_| {
            let idx = rng.gen_range(0..CHARSET.len());
            CHARSET[idx] as char
        })
        .collect();

    // Generate code challenge (SHA256 hash of verifier, base64url encoded)
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
            std::env::var("RUST_LOG").unwrap_or_else(|_| "aip_demo_dpop_client=debug,info".into()),
        ))
        .with(tracing_subscriber::fmt::layer().pretty())
        .init();

    // Configuration
    let config = AppConfig {
        aip_base_url: std::env::var("AIP_BASE_URL")
            .unwrap_or_else(|_| "http://localhost:8080".to_string()),
        demo_base_url: std::env::var("DEMO_BASE_URL")
            .unwrap_or_else(|_| "http://localhost:3002".to_string()),
    };

    let port: u16 = std::env::var("PORT")
        .unwrap_or_else(|_| "3002".to_string())
        .parse()
        .unwrap_or(3002);

    tracing::info!("AIP Demo DPoP Client starting up");
    tracing::info!("AIP Server: {}", config.aip_base_url);
    tracing::info!("Demo Client: {}", config.demo_base_url);
    tracing::info!("Listening on port: {}", port);

    // Generate DPoP key pair
    let dpop_key_pair = Arc::new(DPoPKeyPair::generate()?);
    tracing::info!("Generated DPoP key pair with JKT: {}", dpop_key_pair.jkt);

    // Initialize HTTP client
    let http_client = reqwest::Client::new();

    // Initialize OAuth state storage
    let oauth_states: OAuthStateStorage = Arc::new(Mutex::new(HashMap::new()));

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
    };

    // Build the application
    let app = Router::new()
        .route("/", get(home_handler))
        .route("/login", get(login_handler))
        .route("/callback", get(callback_handler))
        .route("/protected", get(protected_handler))
        .with_state(app_state);

    // Start the server
    let listener = TcpListener::bind(format!("0.0.0.0:{}", port)).await?;
    tracing::info!("Demo DPoP client listening on port {}", port);
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
    // Step 1: Discover OAuth server metadata to find registration endpoint
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
                        tracing::info!(
                            "DPoP signing algorithms supported: {:?}",
                            metadata.dpop_signing_alg_values_supported
                        );
                        metadata
                    }
                    Err(e) => {
                        return Err(format!("Failed to parse OAuth server metadata: {}", e).into());
                    }
                }
            } else {
                return Err(format!(
                    "OAuth server metadata request failed with status: {}",
                    response.status()
                )
                .into());
            }
        }
        Err(e) => {
            return Err(format!("Failed to fetch OAuth server metadata: {}", e).into());
        }
    };

    // Step 2: Check if dynamic client registration is supported
    let registration_endpoint = match server_metadata.registration_endpoint {
        Some(endpoint) => {
            tracing::info!("Dynamic client registration supported at: {}", endpoint);
            endpoint
        }
        None => {
            // Fallback: try a common registration endpoint pattern
            let fallback_endpoint = format!("{}/oauth/clients/register", config.aip_base_url);
            tracing::warn!(
                "No registration endpoint in metadata, trying fallback: {}",
                fallback_endpoint
            );
            fallback_endpoint
        }
    };

    // Step 3: Prepare client registration request with DPoP support
    let redirect_uri = format!("{}/callback", config.demo_base_url);

    let registration_request = ClientRegistrationRequest {
        client_name: "AIP Demo DPoP Client".to_string(),
        client_uri: Some(config.demo_base_url.clone()),
        redirect_uris: vec![redirect_uri],
        response_types: vec!["code".to_string()],
        grant_types: vec!["authorization_code".to_string()],
        token_endpoint_auth_method: "client_secret_post".to_string(),
        scope: "atproto:atproto atproto:transition:generic".to_string(),
        contacts: Some(vec!["admin@demo-dpop-client.example".to_string()]),
        logo_uri: None,
        policy_uri: Some(format!("{}/policy", config.demo_base_url)),
        tos_uri: Some(format!("{}/terms", config.demo_base_url)),
        software_id: Some("aip-demo-dpop-client".to_string()),
        software_version: Some(env!("CARGO_PKG_VERSION").to_string()),
        dpop_bound_access_tokens: Some(true), // Request DPoP-bound tokens
    };

    tracing::info!(
        "Registering DPoP client: {}",
        registration_request.client_name
    );

    // Step 4: Make the registration request
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

    // Step 5: Store client credentials
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
                    <p><strong>Authentication Method:</strong> DPoP-bound tokens</p>
                </div>
                "#,
                html_escape::encode_text(&client.client_id),
                html_escape::encode_text(&state.dpop_key_pair.jkt)
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
    <title>AIP Demo DPoP Client</title>
    <style>
        body {{
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Oxygen, Ubuntu, Cantarell, sans-serif;
            max-width: 800px;
            margin: 0 auto;
            padding: 2rem;
            line-height: 1.6;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            min-height: 100vh;
            color: #333;
        }}
        .container {{
            background: white;
            border-radius: 12px;
            padding: 2rem;
            box-shadow: 0 10px 30px rgba(0, 0, 0, 0.1);
        }}
        h1 {{
            color: #2c3e50;
            margin-bottom: 1rem;
            font-size: 2.5rem;
        }}
        .subtitle {{
            color: #7f8c8d;
            margin-bottom: 2rem;
            font-size: 1.1rem;
        }}
        .auth-form {{
            border: 2px solid #e9ecef;
            border-radius: 12px;
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
            padding: 12px 16px;
            border: 2px solid #ced4da;
            border-radius: 8px;
            font-size: 1rem;
            transition: border-color 0.2s, box-shadow 0.2s;
            box-sizing: border-box;
        }}
        .form-input:focus {{
            outline: none;
            border-color: #0066cc;
            box-shadow: 0 0 0 2px rgba(0, 102, 204, 0.25);
        }}
        .form-hint {{
            font-size: 0.875rem;
            color: #6c757d;
            margin-top: 0.25rem;
        }}
        .auth-button {{
            display: inline-block;
            background: #0066cc;
            color: white;
            padding: 12px 24px;
            text-decoration: none;
            border: none;
            border-radius: 8px;
            font-weight: 500;
            font-size: 1rem;
            cursor: pointer;
            transition: background-color 0.2s;
        }}
        .auth-button:hover {{
            background: #0056b3;
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
        .dpop-info {{
            background: #e7f3ff;
            border: 1px solid #b6d7ff;
            border-radius: 8px;
            padding: 1rem;
            margin: 1rem 0;
        }}
        .footer {{
            margin-top: 2rem;
            padding-top: 1rem;
            border-top: 1px solid #dee2e6;
            color: #6c757d;
            font-size: 0.9rem;
        }}
    </style>
    <script>
        function validateForm() {{
            const submitButton = document.getElementById('submitButton');
            // Always enable submit button since subject is optional
            submitButton.disabled = false;
        }}
        
        function handleSubmit(event) {{
            // Allow form submission regardless of subject value
            return true;
        }}
    </script>
</head>
<body>
    <div class="container">
        <h1>🔐 AIP Demo DPoP Client</h1>
        <p class="subtitle">Demonstration of ATProtocol OAuth with DPoP (Demonstration of Proof-of-Possession) and PAR (Pushed Authorization Request)</p>
        
        <div class="dpop-info">
            <h3>🛡️ DPoP Security Features</h3>
            <p>This demo implements <strong>DPoP (Demonstration of Proof-of-Possession)</strong> which provides:</p>
            <ul>
                <li><strong>Token Binding:</strong> Access tokens are cryptographically bound to the client's key pair</li>
                <li><strong>Replay Protection:</strong> Each request includes a unique proof token</li>
                <li><strong>Enhanced Security:</strong> Prevents token theft and misuse</li>
                <li><strong>PAR Integration:</strong> Combines with Pushed Authorization Request for maximum security</li>
            </ul>
        </div>
        
        {}
        
        <div class="auth-form">
            <h3>🔐 ATProtocol DPoP Authentication</h3>
            <p>Enter your ATProtocol handle or DID to start the secure OAuth login process with DPoP token binding:</p>
            
            <form action="/login" method="get" onsubmit="return handleSubmit(event)">
                <div class="form-group">
                    <label for="subject" class="form-label">ATProtocol Handle or DID</label>
                    <input 
                        type="text" 
                        id="subject" 
                        name="subject" 
                        class="form-input"
                        placeholder="alice.bsky.social or did:plc:... (optional)"
                        oninput="validateForm()"
                    />
                    <div class="form-hint">
                        Enter your ATProtocol handle (e.g., alice.bsky.social) or DID (e.g., did:plc:abc123...) or leave empty to be prompted by AIP
                    </div>
                </div>
                
                <button type="submit" id="submitButton" class="auth-button">
                    🚀 Start DPoP OAuth Login
                </button>
            </form>
        </div>

        <div class="info">
            <h3>📋 OAuth 2.1 + DPoP + PAR Flow</h3>
            <p>This demonstration implements the complete OAuth 2.1 security flow:</p>
            <ol>
                <li><strong>Dynamic Client Registration:</strong> Automatically registers with DPoP support</li>
                <li><strong>Pushed Authorization Request (PAR):</strong> Securely submits authorization parameters</li>
                <li><strong>PKCE Protection:</strong> Prevents authorization code interception</li>
                <li><strong>DPoP Token Exchange:</strong> Binds tokens to client's cryptographic key</li>
                <li><strong>DPoP Protected API Calls:</strong> Each API call includes cryptographic proof</li>
            </ol>
        </div>

        <div class="info">
            <h3>🔧 Configuration</h3>
            <p><strong>AIP Server:</strong> <code>{}</code></p>
            <p><strong>Demo Client:</strong> <code>{}</code></p>
            <p><strong>DPoP Algorithm:</strong> ES256 (ECDSA P-256)</p>
        </div>

        <div class="footer">
            <p>AIP Demo DPoP Client v{} | Built with Rust & Axum</p>
            <p>This demo showcases enterprise-grade OAuth 2.1 security with DPoP and PAR</p>
        </div>
    </div>
</body>
</html>"#,
        client_status,
        html_escape::encode_text(&state.config.aip_base_url),
        html_escape::encode_text(&state.config.demo_base_url),
        env!("CARGO_PKG_VERSION")
    ))
}

/// OAuth login handler - initiates the OAuth flow with PAR and DPoP
async fn login_handler(
    State(state): State<AppState>,
    Query(query): Query<LoginQuery>,
) -> Result<axum::response::Redirect, (StatusCode, Html<String>)> {
    let subject_desc = query
        .subject
        .as_deref()
        .unwrap_or("(none - will use login form)");
    tracing::info!(
        "Starting DPoP OAuth login flow with subject: {}",
        subject_desc
    );

    // Step 0: Get registered client credentials
    let client_credentials = {
        let client_guard = state.registered_client.lock().await;
        match client_guard.as_ref() {
            Some(client) => client.clone(),
            None => {
                tracing::error!("No registered client found - client registration may have failed");
                return Err((StatusCode::INTERNAL_SERVER_ERROR, Html(
                    "<!DOCTYPE html><html><body><h1>Configuration Error</h1><p>No registered OAuth client found. Please restart the application to retry client registration.</p><a href=\"/\">← Back to Home</a></body></html>".to_string()
                )));
            }
        }
    };

    tracing::info!(
        "Using registered client ID: {}",
        client_credentials.client_id
    );

    // Step 1: Discover OAuth server metadata
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
                        tracing::info!(
                            "DPoP algorithms supported: {:?}",
                            metadata.dpop_signing_alg_values_supported
                        );
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

    // Step 2: Generate PKCE parameters
    let (code_verifier, code_challenge) = generate_pkce();
    let oauth_state = generate_state();

    // Step 3: Prepare OAuth parameters
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

    // Step 4: Check if server supports PAR and use it
    if let Some(par_endpoint) = &server_metadata.pushed_authorization_request_endpoint {
        tracing::info!("Using PAR endpoint with DPoP: {}", par_endpoint);

        // Create DPoP proof for PAR request
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

        // Make PAR request with DPoP
        let par_request = PARRequest {
            client_id: client_credentials.client_id.clone(),
            response_type: "code".to_string(),
            redirect_uri: redirect_uri.clone(),
            scope: scope.clone(),
            state: oauth_state.clone(),
            code_challenge: code_challenge.clone(),
            code_challenge_method: "S256".to_string(),
            login_hint: query
                .subject
                .as_ref()
                .filter(|s| !s.trim().is_empty())
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
                            tracing::info!("PAR request with DPoP successful: {:?}", par_resp);
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

        // Step 5: Redirect to authorization endpoint with request_uri
        let auth_url = format!(
            "{}?client_id={}&request_uri={}",
            server_metadata.authorization_endpoint,
            urlencoding::encode(&client_credentials.client_id),
            urlencoding::encode(&par_response.request_uri)
        );

        tracing::info!("Redirecting to authorization endpoint: {}", auth_url);
        Ok(axum::response::Redirect::to(&auth_url))
    } else {
        // Fallback: Traditional OAuth without PAR (still with DPoP)
        tracing::info!("PAR not supported, using traditional OAuth flow with DPoP");

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

        // Only include login_hint if subject is provided and not empty
        if let Some(subject) = &query.subject {
            if !subject.trim().is_empty() {
                auth_url_params.push(format!("login_hint={}", urlencoding::encode(subject)));
            }
        }

        let auth_url = format!(
            "{}?{}",
            server_metadata.authorization_endpoint,
            auth_url_params.join("&")
        );

        tracing::info!(
            "Redirecting to authorization endpoint (no PAR): {}",
            auth_url
        );
        Ok(axum::response::Redirect::to(&auth_url))
    }
}

/// OAuth callback handler - exchanges code for DPoP-bound tokens
async fn callback_handler(
    State(state): State<AppState>,
    Query(query): Query<CallbackQuery>,
) -> Result<axum::response::Redirect, (StatusCode, Html<String>)> {
    tracing::info!("OAuth callback received: {:?}", query);

    // Get registered client credentials
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

    // Check for OAuth errors
    if let Some(error) = &query.error {
        let error_description = query
            .error_description
            .as_deref()
            .unwrap_or("Unknown OAuth error");

        tracing::error!("OAuth callback error: {} - {}", error, error_description);

        let error_html = format!(
            r#"<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Authentication Error - AIP Demo DPoP Client</title>
    <style>
        body {{
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Oxygen, Ubuntu, Cantarell, sans-serif;
            max-width: 800px;
            margin: 0 auto;
            padding: 2rem;
            line-height: 1.6;
        }}
        .error {{
            background: #f8d7da;
            border: 1px solid #f5c6cb;
            color: #721c24;
            border-radius: 8px;
            padding: 1rem;
            margin: 1rem 0;
        }}
        .home-link {{
            display: inline-block;
            background: #6c757d;
            color: white;
            padding: 8px 16px;
            text-decoration: none;
            border-radius: 4px;
            margin-top: 1rem;
        }}
    </style>
</head>
<body>
    <h1>Authentication Error</h1>
    <div class="error">
        <h3>OAuth Error: {}</h3>
        <p>{}</p>
    </div>
    <a href="/" class="home-link">← Back to Home</a>
</body>
</html>"#,
            error, error_description
        );

        return Err((StatusCode::BAD_REQUEST, Html(error_html)));
    }

    // Extract authorization code and state
    let authorization_code = query.code.ok_or_else(|| {
        tracing::error!("No authorization code received in callback");
        (
            StatusCode::BAD_REQUEST,
            Html("<!DOCTYPE html><html><body><h1>Invalid Callback</h1><p>No authorization code received from AIP server.</p><a href=\"/\">← Back to Home</a></body></html>".to_string()),
        )
    })?;

    let received_state = query.state.ok_or_else(|| {
        tracing::error!("No state parameter received in callback");
        (
            StatusCode::BAD_REQUEST,
            Html("<!DOCTYPE html><html><body><h1>Invalid Callback</h1><p>No state parameter received from AIP server.</p><a href=\"/\">← Back to Home</a></body></html>".to_string()),
        )
    })?;

    // Retrieve and validate stored OAuth state
    let oauth_state_data = {
        let mut states = state.oauth_states.lock().await;
        states.remove(&received_state).ok_or_else(|| {
            tracing::error!("OAuth state not found or expired: {}", received_state);
            (
                StatusCode::BAD_REQUEST,
                Html("<!DOCTYPE html><html><body><h1>Invalid OAuth State</h1><p>OAuth state parameter not found or expired. This may indicate a CSRF attack or session timeout.</p><a href=\"/\">← Back to Home</a></body></html>".to_string()),
            )
        })?
    };

    tracing::info!("Valid OAuth state found, proceeding with token exchange");

    // Fetch OAuth server metadata to get token endpoint
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

    // Create DPoP proof for token exchange
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

    // Exchange authorization code for DPoP-bound JWT access token
    let token_request = TokenRequest {
        grant_type: "authorization_code".to_string(),
        client_id: client_credentials.client_id.clone(),
        code: authorization_code,
        redirect_uri: oauth_state_data.redirect_uri,
        code_verifier: oauth_state_data.code_verifier,
    };

    tracing::info!(
        "Exchanging authorization code for DPoP-bound access token at: {}",
        server_metadata.token_endpoint
    );

    // Prepare the token exchange request with DPoP proof and optional client authentication
    let mut request_builder = state
        .http_client
        .post(&server_metadata.token_endpoint)
        .header("DPoP", dpop_proof)
        .form(&token_request);

    // Add client authentication if we have a client secret
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
                        tracing::info!("Successfully exchanged code for DPoP-bound access token");
                        tracing::info!("Token type: {}", token_resp.token_type);
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

    tracing::info!(?token_response, "token_response");

    let mut query_params = vec![];
    query_params.push(format!(
        "token_type={}",
        urlencoding::encode(&token_response.token_type)
    ));
    query_params.push(format!(
        "access_token={}",
        urlencoding::encode(&token_response.access_token)
    ));
    if let Some(value) = token_response.expires_in {
        query_params.push(format!("expires_in={value}"));
    }
    if let Some(value) = token_response.refresh_token {
        query_params.push(format!("refresh_token={}", urlencoding::encode(&value)));
    }
    if let Some(value) = token_response.scope {
        query_params.push(format!("scope={}", urlencoding::encode(&value)));
    }

    // Redirect to protected page with the DPoP-bound JWT token as a query parameter
    let protected_url = format!("/protected?{}", query_params.join("&"));
    tracing::info!("Redirecting to protected page with DPoP-bound JWT token");

    Ok(axum::response::Redirect::to(&protected_url))
}

/// Protected route handler - calls AIP session endpoint using DPoP-bound JWT bearer token
async fn protected_handler(
    State(state): State<AppState>,
    Query(query): Query<ProtectedQuery>,
) -> Result<Html<String>, (StatusCode, Html<String>)> {
    // Extract JWT token from query parameters
    let jwt_token = query.token.ok_or_else(|| {
        tracing::error!("No JWT token provided in protected route");
        (
            StatusCode::BAD_REQUEST,
            Html(r#"<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Missing Token - AIP Demo DPoP Client</title>
    <style>
        body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Oxygen, Ubuntu, Cantarell, sans-serif;
            max-width: 800px;
            margin: 0 auto;
            padding: 2rem;
            line-height: 1.6;
        }
        .error {
            background: #f8d7da;
            border: 1px solid #f5c6cb;
            color: #721c24;
            border-radius: 8px;
            padding: 1rem;
            margin: 1rem 0;
        }
        .home-link {
            display: inline-block;
            background: #6c757d;
            color: white;
            padding: 8px 16px;
            text-decoration: none;
            border-radius: 4px;
            margin-top: 1rem;
        }
    </style>
</head>
<body>
    <h1>Missing JWT Token</h1>
    <div class="error">
        <h3>No authentication token provided</h3>
        <p>This protected route requires a DPoP-bound JWT token. Please complete the OAuth login flow first.</p>
    </div>
    <a href="/" class="home-link">← Back to Home</a>
    <a href="/login" class="home-link">Start Login</a>
</body>
</html>"#.to_string()),
        )
    })?;

    let session_url = format!("{}/api/atprotocol/session", state.config.aip_base_url);

    tracing::info!(
        "Calling AIP session endpoint with DPoP-bound JWT bearer token: {}",
        session_url
    );

    // Create DPoP authentication using atproto_client
    let dpop_auth = DPoPAuth {
        dpop_private_key_data: state.dpop_key_pair.private_key.clone(),
        oauth_access_token: jwt_token.clone(),
    };

    // Make a request to the AIP session endpoint using atproto_client with DPoP
    let session_json = match get_dpop_json_with_headers(
        &state.http_client,
        &dpop_auth,
        &session_url,
        &HeaderMap::new(), // No additional headers
    )
    .await
    {
        Ok(session_data) => {
            tracing::info!("Successfully retrieved session data with DPoP using atproto_client");
            session_data
        }
        Err(e) => {
            let error_html = format!(
                r#"<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>API Error - AIP Demo DPoP Client</title>
    <style>
        body {{
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Oxygen, Ubuntu, Cantarell, sans-serif;
            max-width: 800px;
            margin: 0 auto;
            padding: 2rem;
            line-height: 1.6;
        }}
        .error {{
            background: #f8d7da;
            border: 1px solid #f5c6cb;
            color: #721c24;
            border-radius: 8px;
            padding: 1rem;
            margin: 1rem 0;
        }}
    </style>
</head>
<body>
    <h1>API Request Failed</h1>
    <div class="error">
        <h3>Failed to connect to AIP server</h3>
        <p>Error: {}</p>
        <p><strong>API Endpoint:</strong> {}</p>
    </div>
    <p><a href="/">← Back to Home</a></p>
</body>
</html>"#,
                html_escape::encode_text(&e.to_string()),
                html_escape::encode_text(&session_url)
            );
            return Err((StatusCode::INTERNAL_SERVER_ERROR, Html(error_html)));
        }
    };

    // Deserialize the JSON response to AtpSessionResponse
    let response: AtpSessionResponse = match serde_json::from_value(session_json.clone()) {
        Ok(session_response) => session_response,
        Err(e) => {
            tracing::error!("Failed to deserialize session response: {}", e);
            let error_html = format!(
                r#"<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Deserialization Error - AIP Demo DPoP Client</title>
    <style>
        body {{
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Oxygen, Ubuntu, Cantarell, sans-serif;
            max-width: 800px;
            margin: 0 auto;
            padding: 2rem;
            line-height: 1.6;
        }}
        .error {{
            background: #f8d7da;
            border: 1px solid #f5c6cb;
            color: #721c24;
            border-radius: 8px;
            padding: 1rem;
            margin: 1rem 0;
        }}
    </style>
</head>
<body>
    <h1>Response Parsing Error</h1>
    <div class="error">
        <h3>Failed to parse session response</h3>
        <p>Error: {}</p>
        <p><strong>API Endpoint:</strong> {}</p>
    </div>
    <p><a href="/">← Back to Home</a></p>
</body>
</html>"#,
                html_escape::encode_text(&e.to_string()),
                html_escape::encode_text(&session_url)
            );
            return Err((StatusCode::INTERNAL_SERVER_ERROR, Html(error_html)));
        }
    };

    // The session JSON for display
    let session_json_display = serde_json::to_string_pretty(&session_json)
        .unwrap_or_else(|_| "Failed to serialize session data".to_string());

    Ok(Html(format!(
        r#"<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Protected Resource - AIP Demo DPoP Client</title>
    <style>
        body {{
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Oxygen, Ubuntu, Cantarell, sans-serif;
            max-width: 900px;
            margin: 0 auto;
            padding: 2rem;
            line-height: 1.6;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            min-height: 100vh;
            color: #333;
        }}
        .container {{
            background: white;
            border-radius: 12px;
            padding: 2rem;
            box-shadow: 0 10px 30px rgba(0, 0, 0, 0.1);
        }}
        h1 {{
            color: #2c3e50;
            margin-bottom: 1rem;
        }}
        .success {{
            background: #d4edda;
            border: 1px solid #c3e6cb;
            color: #155724;
            border-radius: 8px;
            padding: 1rem;
            margin: 1rem 0;
        }}
        .dpop-success {{
            background: #e7f3ff;
            border: 1px solid #b6d7ff;
            color: #0c5460;
            border-radius: 8px;
            padding: 1rem;
            margin: 1rem 0;
        }}
        .session-data {{
            background: #f8f9fa;
            border: 1px solid #dee2e6;
            border-radius: 8px;
            padding: 1rem;
            margin: 1rem 0;
            overflow-x: auto;
        }}
        .session-data pre {{
            margin: 0;
            font-family: 'Monaco', 'Menlo', 'Ubuntu Mono', monospace;
            font-size: 0.9rem;
            line-height: 1.4;
        }}
        .home-link {{
            display: inline-block;
            background: #0066cc;
            color: white;
            padding: 8px 16px;
            text-decoration: none;
            border-radius: 4px;
            margin-top: 1rem;
            margin-right: 1rem;
        }}
        .info-grid {{
            display: grid;
            grid-template-columns: 1fr 1fr;
            gap: 1rem;
            margin: 1rem 0;
        }}
        .info-card {{
            background: #f8f9fa;
            border: 1px solid #dee2e6;
            border-radius: 8px;
            padding: 1rem;
        }}
        .info-card h4 {{
            margin-top: 0;
            color: #495057;
        }}
        .verification-details {{
            background: #fff3cd;
            border: 1px solid #ffeaa7;
            border-radius: 8px;
            padding: 1rem;
            margin: 1rem 0;
        }}
        @media (max-width: 768px) {{
            .info-grid {{
                grid-template-columns: 1fr;
            }}
        }}
    </style>
</head>
<body>
    <div class="container">
        <h1>🎉 DPoP Authentication Successful!</h1>
        
        <div class="dpop-success">
            <h3>🛡️ DPoP Token Verification Complete</h3>
            <p><strong>Your request was successfully authenticated using DPoP (Demonstration of Proof-of-Possession)!</strong></p>
            <p>This demonstrates that:</p>
            <ul>
                <li>✅ The access token is cryptographically bound to your client</li>
                <li>✅ The DPoP proof was successfully verified by the server</li>
                <li>✅ Your request cannot be replayed by attackers</li>
                <li>✅ Enhanced security through cryptographic binding</li>
            </ul>
        </div>

        <div class="success">
            <h3>✅ API Call Successful</h3>
            <p>Successfully called the AIP protected endpoint <code>/api/atprotocol/session</code> using your DPoP-bound JWT token.</p>
            <p><em>Using atproto_client with DPoP authentication</em></p>
        </div>

        <div class="info-grid">
            <div class="info-card">
                <h4>🔐 Security Features</h4>
                <ul>
                    <li><strong>DPoP Binding:</strong> Token bound to key pair</li>
                    <li><strong>PAR Security:</strong> Protected authorization</li>
                    <li><strong>PKCE Protection:</strong> Code interception prevention</li>
                    <li><strong>JWT Tokens:</strong> Stateless verification</li>
                </ul>
            </div>
            <div class="info-card">
                <h4>📊 Session Information</h4>
                <p><strong>DID:</strong> <code>{}</code></p>
                <p><strong>Handle:</strong> <code>{}</code></p>
                <p><strong>Token Type:</strong> <code>{}</code></p>
                <p><strong>DPoP JKT:</strong> <code>{}</code></p>
            </div>
        </div>

        <div class="verification-details">
            <h4>🔍 DPoP Verification Details</h4>
            <p>The server verified your DPoP proof by:</p>
            <ol>
                <li>Validating the JWT signature using the embedded public key</li>
                <li>Checking the access token hash (ath claim) matches the provided token</li>
                <li>Verifying the HTTP method and URI (htm/htu claims)</li>
                <li>Ensuring the proof is not replayed (jti claim)</li>
                <li>Confirming the token is bound to your key pair (JKT binding)</li>
            </ol>
        </div>

        <div class="session-data">
            <h3>📄 ATProtocol Session Data</h3>
            <pre>{}</pre>
        </div>

        <a href="/" class="home-link">← Back to Home</a>
        <a href="/login" class="home-link">🔄 Try Another Login</a>
    </div>
</body>
</html>"#,
        html_escape::encode_text(&response.did),
        html_escape::encode_text(&response.handle.as_deref().unwrap_or("N/A")),
        html_escape::encode_text(&response.token_type),
        html_escape::encode_text(
            &response
                .dpop_jkt
                .as_deref()
                .unwrap_or(&state.dpop_key_pair.jkt)
        ),
        html_escape::encode_text(&session_json_display)
    )))
}
