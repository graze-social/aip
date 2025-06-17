//! AIP Demo Client Website
//!
//! A minimal functional website that demonstrates authentication with AIP (ATProtocol Identity Provider).
//! This demo client includes:
//! - Home page with authentication link
//! - OAuth callback handler
//! - Protected route that displays ATProtocol session information

use axum::{
    extract::{Query, State},
    http::StatusCode,
    response::Html,
    routing::get,
    Router,
};
use serde::{Deserialize, Serialize};
use std::{collections::HashMap, sync::Arc};
use tokio::{net::TcpListener, sync::Mutex};
use tracing_subscriber::prelude::*;

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

/// Application state shared across handlers
#[derive(Clone)]
struct AppState {
    config: Arc<AppConfig>,
    http_client: reqwest::Client,
    oauth_states: OAuthStateStorage,
    registered_client: Arc<Mutex<Option<RegisteredClient>>>,
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
}

/// OAuth Protected Resource Metadata  
#[derive(Debug, Deserialize)]
struct OAuthResourceMetadata {
    resource: String,
    authorization_servers: Vec<String>,
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

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Initialize tracing
    tracing_subscriber::registry()
        .with(tracing_subscriber::EnvFilter::new(
            std::env::var("RUST_LOG").unwrap_or_else(|_| "aip_demo_client=debug,info".into()),
        ))
        .with(tracing_subscriber::fmt::layer().pretty())
        .init();

    // Load configuration from environment variables
    let config = AppConfig {
        aip_base_url: std::env::var("AIP_BASE_URL")
            .unwrap_or_else(|_| "http://localhost:8080".to_string()),
        demo_base_url: std::env::var("DEMO_BASE_URL")
            .unwrap_or_else(|_| "http://localhost:3001".to_string()),
    };

    tracing::info!("AIP Base URL: {}", config.aip_base_url);
    tracing::info!("Demo Base URL: {}", config.demo_base_url);

    // Create HTTP client
    let http_client = reqwest::Client::new();

    // Create OAuth state storage
    let oauth_states: OAuthStateStorage = Arc::new(Mutex::new(HashMap::new()));

    // Create registered client storage
    let registered_client = Arc::new(Mutex::new(None));

    // Create application state
    let app_state = AppState {
        config: Arc::new(config.clone()),
        http_client: http_client.clone(),
        oauth_states,
        registered_client: registered_client.clone(),
    };

    // Perform dynamic client registration
    if let Err(e) = register_client(&app_state).await {
        tracing::error!("Failed to register OAuth client: {}", e);
        tracing::error!("The demo client will not function properly without client registration");
        return Err(e);
    }

    // Build the router
    let app = Router::new()
        .route("/", get(home_handler))
        .route("/login", get(login_handler))
        .route("/callback", get(callback_handler))
        .route("/protected", get(protected_handler))
        .with_state(app_state);

    // Start the server
    let port = std::env::var("PORT")
        .unwrap_or_else(|_| "3001".to_string())
        .parse::<u16>()
        .expect("PORT must be a valid port number");

    let bind_address = format!("0.0.0.0:{}", port);
    tracing::info!("Starting AIP Demo Client on {}", bind_address);

    let listener = TcpListener::bind(&bind_address).await?;
    axum::serve(listener, app).await?;

    Ok(())
}

/// Generate PKCE code verifier and challenge
fn generate_pkce() -> (String, String) {
    use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
    use rand::Rng;
    use sha2::{Digest, Sha256};

    // Generate code verifier (43-128 characters, URL-safe)
    let mut rng = rand::thread_rng();
    let code_verifier: String = (0..43)
        .map(|_| {
            let chars = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-._~";
            chars[rng.gen_range(0..chars.len())] as char
        })
        .collect();

    // Generate code challenge (SHA256 hash of verifier, base64url encoded)
    let mut hasher = Sha256::new();
    hasher.update(code_verifier.as_bytes());
    let hash = hasher.finalize();
    let code_challenge = URL_SAFE_NO_PAD.encode(hash);

    (code_verifier, code_challenge)
}

/// Generate random state parameter
fn generate_state() -> String {
    use rand::Rng;
    let mut rng = rand::thread_rng();
    (0..32)
        .map(|_| {
            let chars = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
            chars[rng.gen_range(0..chars.len())] as char
        })
        .collect()
}

/// Register a dynamic OAuth client with the AIP server (RFC 7591)
async fn register_client(app_state: &AppState) -> Result<(), Box<dyn std::error::Error>> {
    tracing::info!("Starting dynamic client registration with AIP server");

    // Step 1: Discover OAuth server metadata to find registration endpoint
    let auth_server_metadata_url = format!(
        "{}/.well-known/oauth-authorization-server",
        app_state.config.aip_base_url
    );

    tracing::info!(
        "Fetching OAuth server metadata from: {}",
        auth_server_metadata_url
    );

    let server_metadata = match app_state
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
            let fallback_endpoint =
                format!("{}/oauth/clients/register", app_state.config.aip_base_url);
            tracing::warn!(
                "No registration endpoint in metadata, trying fallback: {}",
                fallback_endpoint
            );
            fallback_endpoint
        }
    };

    // Step 3: Prepare client registration request
    let redirect_uri = format!("{}/callback", app_state.config.demo_base_url);

    let registration_request = ClientRegistrationRequest {
        client_name: "AIP Demo Client".to_string(),
        client_uri: Some(app_state.config.demo_base_url.clone()),
        redirect_uris: vec![redirect_uri],
        response_types: vec!["code".to_string()],
        grant_types: vec!["authorization_code".to_string()],
        token_endpoint_auth_method: "client_secret_post".to_string(),
        scope: "atproto:atproto atproto:transition:generic".to_string(),
        contacts: Some(vec!["admin@demo-client.example".to_string()]),
        logo_uri: None,
        policy_uri: Some(format!("{}/policy", app_state.config.demo_base_url)),
        tos_uri: Some(format!("{}/terms", app_state.config.demo_base_url)),
        software_id: Some("aip-demo-client".to_string()),
        software_version: Some(env!("CARGO_PKG_VERSION").to_string()),
    };

    tracing::info!("Registering client: {}", registration_request.client_name);

    // Step 4: Make the registration request
    let registration_response = match app_state
        .http_client
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
                tracing::error!(
                    "Client registration failed with status: {} - {}",
                    status,
                    error_text
                );
                return Err(format!(
                    "Client registration failed. Status: {} - Error: {}",
                    status, error_text
                )
                .into());
            }
        }
        Err(e) => {
            return Err(format!("Failed to make client registration request: {}", e).into());
        }
    };

    // Step 5: Store the registered client credentials
    let registered_client = RegisteredClient {
        client_id: registration_response.client_id.clone(),
        client_secret: registration_response.client_secret.clone(),
        registration_access_token: registration_response.registration_access_token.clone(),
        expires_at: registration_response.client_secret_expires_at,
    };

    {
        let mut client_guard = app_state.registered_client.lock().await;
        *client_guard = Some(registered_client);
    }

    tracing::info!("Dynamic client registration completed successfully");
    tracing::info!("Client ID: {}", registration_response.client_id);
    tracing::info!(
        "Client Secret: {}",
        registration_response
            .client_secret
            .as_deref()
            .unwrap_or("(not provided)")
    );

    Ok(())
}

/// Home page handler - displays a form to initiate AIP authentication with ATProtocol subject
async fn home_handler(State(state): State<AppState>) -> Html<String> {
    // Get registered client info for display
    let client_info = {
        let client_guard = state.registered_client.lock().await;
        client_guard.clone()
    };

    let html = format!(
        r#"<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>AIP Demo Client</title>
    <style>
        body {{
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Oxygen, Ubuntu, Cantarell, sans-serif;
            max-width: 800px;
            margin: 0 auto;
            padding: 2rem;
            line-height: 1.6;
        }}
        .auth-form {{
            background: #f8f9fa;
            border: 1px solid #dee2e6;
            border-radius: 8px;
            padding: 2rem;
            margin: 2rem 0;
        }}
        .form-group {{
            margin-bottom: 1rem;
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
            border: 1px solid #ced4da;
            border-radius: 6px;
            font-size: 1rem;
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
    <h1>AIP Demo Client</h1>
    <p>This is a demonstration website that shows how to authenticate with AIP (ATProtocol Identity Provider).</p>
    
    <div class="auth-form">
        <h3>🔐 ATProtocol Authentication</h3>
        <p>Enter your ATProtocol handle or DID to start the OAuth login process:</p>
        
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
                Start OAuth Login
            </button>
        </form>
    </div>
    
    <div class="info">
        <h3>How it works:</h3>
        <ol>
            <li>Enter your ATProtocol handle or DID above</li>
            <li>Click "Start OAuth Login" to begin the authentication process</li>
            <li>The demo client will discover AIP's OAuth server metadata</li>
            <li>Your ATProtocol subject will be included in the OAuth request</li>
            <li>You'll be redirected to AIP to complete authentication</li>
            <li>After authentication, you'll be redirected back with an authorization code</li>
            <li>The code will be exchanged for a JWT access token</li>
            <li>Visit <a href="/protected">/protected</a> to see your ATProtocol session information</li>
        </ol>
    </div>

    <div class="info">
        <h3>Configuration:</h3>
        <ul>
            <li><strong>AIP Server:</strong> {}</li>
            <li><strong>Demo Client:</strong> {}</li>
        </ul>
    </div>

    <div class="info">
        <h3>Dynamic Client Registration:</h3>
        <ul>
            <li><strong>Status:</strong> {}</li>
            <li><strong>Client ID:</strong> {}</li>
            <li><strong>Client Secret:</strong> {}</li>
        </ul>
    </div>

    <div class="footer">
        <p>This demo client implements OAuth 2.1 + PAR with dynamic client registration to authenticate with AIP and retrieve ATProtocol session information.</p>
    </div>
</body>
</html>"#,
        state.config.aip_base_url,
        state.config.demo_base_url,
        if client_info.is_some() {
            "✅ Registered"
        } else {
            "❌ Not Registered"
        },
        client_info
            .as_ref()
            .map(|c| c.client_id.as_str())
            .unwrap_or("(not registered)"),
        client_info
            .as_ref()
            .and_then(|c| c.client_secret.as_deref())
            .unwrap_or("(not provided)")
    );

    Html(html)
}

/// Login handler - initiates OAuth flow with metadata discovery and PAR
async fn login_handler(
    State(state): State<AppState>,
    Query(query): Query<LoginQuery>,
) -> Result<axum::response::Redirect, (StatusCode, Html<String>)> {
    let subject_desc = query
        .subject
        .as_deref()
        .unwrap_or("(none - will use login form)");
    tracing::info!("Starting OAuth login flow with subject: {}", subject_desc);

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
    let resource_metadata_url = format!(
        "{}/.well-known/oauth-protected-resource",
        state.config.aip_base_url
    );

    tracing::info!(
        "Fetching OAuth server metadata from: {}",
        auth_server_metadata_url
    );
    tracing::info!(
        "Fetching OAuth protected resource metadata from: {}",
        resource_metadata_url
    );

    // Fetch both metadata endpoints concurrently
    let (server_metadata_result, resource_metadata_result) = tokio::join!(
        state.http_client.get(&auth_server_metadata_url).send(),
        state.http_client.get(&resource_metadata_url).send()
    );

    // Process OAuth protected resource metadata (optional, for informational purposes)
    if let Ok(resource_response) = resource_metadata_result {
        if resource_response.status().is_success() {
            match resource_response.json::<OAuthResourceMetadata>().await {
                Ok(resource_metadata) => {
                    tracing::info!(
                        "Successfully fetched OAuth protected resource metadata: {:?}",
                        resource_metadata
                    );
                }
                Err(e) => {
                    tracing::warn!("Failed to parse OAuth protected resource metadata: {}", e);
                }
            }
        } else {
            tracing::warn!(
                "OAuth protected resource metadata request failed with status: {}",
                resource_response.status()
            );
        }
    } else {
        tracing::warn!("Failed to fetch OAuth protected resource metadata");
    }

    // Process OAuth authorization server metadata
    let server_metadata = match server_metadata_result {
        Ok(response) => {
            if response.status().is_success() {
                match response.json::<OAuthServerMetadata>().await {
                    Ok(metadata) => {
                        tracing::info!(
                            "Successfully fetched OAuth server metadata: {:?}",
                            metadata
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

    // Step 2: Generate PKCE parameters and state
    let (code_verifier, code_challenge) = generate_pkce();
    let oauth_state = generate_state();
    let redirect_uri = format!("{}/callback", state.config.demo_base_url);
    // Use standard scope without ATProtocol subject prefix
    let scope = "atproto:atproto atproto:transition:generic".to_string();

    // Step 3: Store OAuth state for callback verification
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

    tracing::info!(?server_metadata, "server metadata");

    // Step 4: Check if server supports PAR
    if let Some(par_endpoint) = &server_metadata.pushed_authorization_request_endpoint {
        tracing::info!("Using PAR endpoint: {}", par_endpoint);

        // Make PAR request
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
        // Fallback: Traditional OAuth without PAR
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

        tracing::info!("Redirecting to authorization endpoint: {}", auth_url);
        Ok(axum::response::Redirect::to(&auth_url))
    }
}

/// OAuth callback handler - exchanges authorization code for JWT and redirects to protected page
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
    <title>Authentication Error - AIP Demo Client</title>
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
                Html("<!DOCTYPE html><html><body><h1>Invalid State</h1><p>OAuth state not found or expired. Please start the login process again.</p><a href=\"/\">← Back to Home</a></body></html>".to_string()),
            )
        })?
    };

    tracing::info!("Retrieved OAuth state for: {}", received_state);

    // Fetch OAuth server metadata again to get token endpoint
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

    // Exchange authorization code for JWT access token
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

    // Prepare the token exchange request with optional client authentication
    let mut request_builder = state
        .http_client
        .post(&server_metadata.token_endpoint)
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
                        tracing::info!("Successfully exchanged code for access token");
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

    // Redirect to protected page with the JWT token as a query parameter
    let protected_url = format!("/protected?{}", query_params.join("&"));
    tracing::info!("Redirecting to protected page with JWT token");

    Ok(axum::response::Redirect::to(&protected_url))
}

/// Protected route handler - calls AIP session endpoint using JWT bearer token
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
    <title>Missing Token - AIP Demo Client</title>
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
        <p>This protected route requires a JWT token. Please complete the OAuth login flow first.</p>
    </div>
    <a href="/" class="home-link">← Back to Home</a>
    <a href="/login" class="home-link">Start Login</a>
</body>
</html>"#.to_string()),
        )
    })?;

    let session_url = format!("{}/api/atprotocol/session", state.config.aip_base_url);

    tracing::info!(
        "Calling AIP hello endpoint with JWT bearer token: {}",
        session_url
    );

    // Make a request to the AIP session endpoint using the JWT token as bearer token
    let response = match state
        .http_client
        .get(&session_url)
        .header("Authorization", format!("Bearer {}", jwt_token))
        .send()
        .await
    {
        Ok(resp) => resp,
        Err(e) => {
            let error_html = format!(
                r#"<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>API Error - AIP Demo Client</title>
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
                e, session_url
            );
            return Err((StatusCode::INTERNAL_SERVER_ERROR, Html(error_html)));
        }
    };

    let status = response.status();
    let response_text = match response.text().await {
        Ok(text) => text,
        Err(e) => {
            let error_html = format!(
                r#"<!DOCTYPE html>
<html><body>
<h1>Response Parsing Error</h1>
<p>Failed to read response from AIP server: {}</p>
<a href="/">← Back to Home</a>
</body></html>"#,
                e
            );
            return Err((StatusCode::INTERNAL_SERVER_ERROR, Html(error_html)));
        }
    };

    if status.is_success() {
        // Try to parse as ATProtocol session response
        match serde_json::from_str::<AtpSessionResponse>(&response_text) {
            Ok(session) => {
                tracing::debug!(?session, "session_response");
                let session_html = format!(
                    r#"<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Protected Content - AIP Demo Client</title>
    <style>
        body {{
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Oxygen, Ubuntu, Cantarell, sans-serif;
            max-width: 800px;
            margin: 0 auto;
            padding: 2rem;
            line-height: 1.6;
        }}
        .session-info {{
            background: #e7f3ff;
            border: 1px solid #b3d9ff;
            border-radius: 8px;
            padding: 1rem;
            margin: 1rem 0;
        }}
        .token-display {{
            background: #f8f9fa;
            border: 1px solid #dee2e6;
            border-radius: 8px;
            padding: 1rem;
            margin: 1rem 0;
            word-break: break-all;
            font-family: 'SF Mono', Monaco, 'Cascadia Code', 'Roboto Mono', Consolas, 'Courier New', monospace;
            font-size: 0.9rem;
        }}
        .dpop-key {{
            background: #fff3cd;
            border: 1px solid #ffeaa7;
            border-radius: 8px;
            padding: 1rem;
            margin: 1rem 0;
            word-break: break-all;
            font-family: 'SF Mono', Monaco, 'Cascadia Code', 'Roboto Mono', Consolas, 'Courier New', monospace;
            font-size: 0.9rem;
        }}
        .metadata {{
            display: grid;
            grid-template-columns: auto 1fr;
            gap: 0.5rem 1rem;
            background: #f8f9fa;
            border: 1px solid #dee2e6;
            border-radius: 8px;
            padding: 1rem;
            margin: 1rem 0;
        }}
        .metadata dt {{
            font-weight: 600;
            color: #495057;
        }}
        .metadata dd {{
            margin: 0;
            color: #6c757d;
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
    <h1>🔐 Protected Content - ATProtocol Session</h1>
    
    <div class="session-info">
        <h3>✅ Successfully retrieved ATProtocol session from AIP!</h3>
        <p>This page demonstrates accessing protected resources using AIP authentication.</p>
    </div>

    <h3>JWT Access Token Used</h3>
    <div class="token-display">
        <strong>JWT Token:</strong> {}<br>
        <strong>Token Type:</strong> Bearer
    </div>

    <h3>ATProtocol Access Token (from session)</h3>
    <div class="token-display">
        <strong>Token:</strong> {}<br>
        <strong>Type:</strong> {}
    </div>

    <h3>DPoP Key Information</h3>
    <div class="dpop-key">
        <strong>DPoP JKT:</strong> {}
    </div>

    <h3>Session Metadata</h3>
    <dl class="metadata">
        <dt>DID:</dt>
        <dd>{}</dd>
        <dt>Handle:</dt>
        <dd>{}</dd>
        <dt>Scopes:</dt>
        <dd>{}</dd>
        <dt>PDS Endpoint:</dt>
        <dd>{}</dd>
        <dt>Expires At:</dt>
        <dd>{}</dd>
    </dl>

    <a href="/" class="home-link">← Back to Home</a>
</body>
</html>"#,
                    jwt_token,
                    session.access_token,
                    session.token_type,
                    session.dpop_jkt.as_deref().unwrap_or("(not set)"),
                    session.did,
                    session.handle.as_deref().unwrap_or("(not set)"),
                    session.scopes.join(", "),
                    session.pds_endpoint.as_deref().unwrap_or("(not set)"),
                    session.expires_at.map_or("(not set)".to_string(), |ts| {
                        format!("{} (Unix timestamp)", ts)
                    })
                );
                Ok(Html(session_html))
            }
            Err(_) => {
                // Response wasn't a session, show raw response
                let raw_html = format!(
                    r#"<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>API Response - AIP Demo Client</title>
    <style>
        body {{
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Oxygen, Ubuntu, Cantarell, sans-serif;
            max-width: 800px;
            margin: 0 auto;
            padding: 2rem;
            line-height: 1.6;
        }}
        .response {{
            background: #f8f9fa;
            border: 1px solid #dee2e6;
            border-radius: 8px;
            padding: 1rem;
            margin: 1rem 0;
            white-space: pre-wrap;
            font-family: 'SF Mono', Monaco, 'Cascadia Code', 'Roboto Mono', Consolas, 'Courier New', monospace;
            font-size: 0.9rem;
        }}
    </style>
</head>
<body>
    <h1>Protected Content - AIP API Response</h1>
    <p><strong>Status:</strong> {} {}</p>
    <h3>Response Body:</h3>
    <div class="response">{}</div>
    <a href="/">← Back to Home</a>
</body>
</html>"#,
                    status.as_u16(),
                    status.canonical_reason().unwrap_or("Unknown"),
                    html_escape::encode_text(&response_text)
                );
                Ok(Html(raw_html))
            }
        }
    } else {
        // API returned an error
        let error_html = format!(
            r#"<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>API Error - AIP Demo Client</title>
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
        .response {{
            background: #f8f9fa;
            border: 1px solid #dee2e6;
            border-radius: 8px;
            padding: 1rem;
            margin: 1rem 0;
            white-space: pre-wrap;
            font-family: 'SF Mono', Monaco, 'Cascadia Code', 'Roboto Mono', Consolas, 'Courier New', monospace;
            font-size: 0.9rem;
        }}
    </style>
</head>
<body>
    <h1>API Error</h1>
    <div class="error">
        <h3>AIP API returned error: {} {}</h3>
        <p><strong>Endpoint:</strong> {}</p>
    </div>
    <h3>Response Body:</h3>
    <div class="response">{}</div>
    <a href="/">← Back to Home</a>
</body>
</html>"#,
            status.as_u16(),
            status.canonical_reason().unwrap_or("Unknown"),
            session_url,
            html_escape::encode_text(&response_text)
        );
        Err((StatusCode::BAD_GATEWAY, Html(error_html)))
    }
}
