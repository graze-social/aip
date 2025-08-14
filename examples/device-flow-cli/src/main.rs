//! OAuth 2.0 Device Authorization Grant CLI Example
//!
//! This CLI demonstrates how to implement the OAuth 2.0 Device Authorization Grant
//! (RFC 8628) flow with AIP. It shows the complete flow from device code request
//! to access token retrieval.

use anyhow::{Context, Result};
use clap::{Arg, Command};
use reqwest::Client;
use serde::{Deserialize, Serialize};
use std::time::Duration;
use tracing::{error, info};

const DEFAULT_AIP_BASE_URL: &str = "http://localhost:8080";
const DEFAULT_CLIENT_ID: &str = "device-flow-cli-example";

#[derive(Debug, Serialize)]
struct DeviceAuthorizationRequest {
    client_id: String,
    scope: Option<String>,
}

#[derive(Debug, Deserialize)]
struct DeviceAuthorizationResponse {
    device_code: String,
    user_code: String,
    verification_uri: String,
    verification_uri_complete: Option<String>,
    expires_in: u64,
    interval: Option<u64>,
}

#[derive(Debug, Serialize)]
struct DeviceTokenRequest {
    grant_type: String,
    device_code: String,
    client_id: String,
}

#[derive(Debug, Deserialize)]
struct TokenResponse {
    access_token: String,
    expires_in: Option<u64>,
    refresh_token: Option<String>,
    token_type: Option<String>,
    scope: Option<String>,
}

#[derive(Debug, Deserialize)]
struct TokenError {
    error: String,
    error_description: Option<String>,
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt::init();

    let matches = Command::new("device-flow-cli")
        .about("OAuth 2.0 Device Authorization Grant CLI Example")
        .arg(
            Arg::new("aip-url")
                .long("aip-url")
                .value_name("URL")
                .help("AIP server base URL")
                .default_value(DEFAULT_AIP_BASE_URL),
        )
        .arg(
            Arg::new("client-id")
                .long("client-id")
                .value_name("CLIENT_ID")
                .help("OAuth client ID")
                .default_value(DEFAULT_CLIENT_ID),
        )
        .arg(
            Arg::new("scope")
                .long("scope")
                .value_name("SCOPE")
                .help("OAuth scope (optional)")
                .required(false),
        )
        .get_matches();

    let aip_base_url = matches.get_one::<String>("aip-url").unwrap();
    let client_id = matches.get_one::<String>("client-id").unwrap();
    let scope = matches.get_one::<String>("scope").map(|s| s.to_string()).or_else(|| Some("atproto:atproto".to_string()));

    info!("🚀 Starting OAuth 2.0 Device Authorization Grant flow");
    info!("📡 AIP Server: {}", aip_base_url);
    info!("🆔 Client ID: {}", client_id);
    if let Some(ref s) = scope {
        info!("📋 Scope: {}", s);
    }

    let client = Client::new();

    // Step 1: Request device authorization
    let auth_response = request_device_authorization(&client, aip_base_url, client_id, scope.as_deref())
        .await
        .context("Failed to request device authorization")?;

    println!("\n📱 Device Authorization Required");
    println!("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
    println!("📋 User Code: {}", auth_response.user_code);
    println!("🌐 Verification URL: {}", auth_response.verification_uri);

    if let Some(ref complete_uri) = auth_response.verification_uri_complete {
        println!("🔗 Quick Link: {}", complete_uri);
        println!("\n💡 Open the quick link above to skip manual code entry!");
    }

    println!("⏰ Code expires in {} seconds", auth_response.expires_in);
    println!("\n🎯 Next Steps:");
    println!("   1. Open {} in your browser", auth_response.verification_uri);
    println!("   2. Enter the user code: {}", auth_response.user_code);
    println!("   3. Complete the authentication process");
    println!("   4. Return here - the CLI will automatically detect completion\n");

    // Step 2: Poll for access token
    let token_response = poll_for_token(
        &client,
        aip_base_url,
        client_id,
        &auth_response.device_code,
        auth_response.interval.unwrap_or(5),
        auth_response.expires_in,
    )
    .await
    .context("Failed to obtain access token")?;

    println!("\n✅ Authentication Successful!");
    println!("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
    println!("🎫 Access Token: {}...{}",
        &token_response.access_token[..8],
        &token_response.access_token[token_response.access_token.len()-8..]);

    if let Some(expires_in) = token_response.expires_in {
        println!("⏰ Expires in: {} seconds", expires_in);
    }

    if let Some(ref token_type) = token_response.token_type {
        println!("🏷️ Token Type: {}", token_type);
    }

    if let Some(ref scope) = token_response.scope {
        println!("📋 Granted Scope: {}", scope);
    }

    // Step 3: Test the access token
    println!("\n🔍 Testing Access Token...");
    match test_access_token(&client, aip_base_url, &token_response.access_token).await {
        Ok(session_info) => {
            println!("✅ Token is valid!");
            println!("👤 User: {}", session_info.get("did").and_then(|v| v.as_str()).unwrap_or("Unknown"));
        }
        Err(e) => {
            error!("❌ Token test failed: {}", e);
        }
    }

    println!("\n🎉 Device flow complete! You can now use the access token to make authenticated API calls.");

    Ok(())
}

async fn request_device_authorization(
    client: &Client,
    aip_base_url: &str,
    client_id: &str,
    scope: Option<&str>,
) -> Result<DeviceAuthorizationResponse> {
    let url = format!("{}/oauth/device", aip_base_url);

    let request = DeviceAuthorizationRequest {
        client_id: client_id.to_string(),
        scope: scope.map(|s| s.to_string()),
    };

    info!("📤 Requesting device authorization from: {}", url);

    let response = client
        .post(&url)
        .form(&request)
        .send()
        .await
        .context("Failed to send device authorization request")?;

    if !response.status().is_success() {
        let status = response.status();
        let body = response.text().await.unwrap_or_default();
        anyhow::bail!("Device authorization request failed: {} - {}", status, body);
    }

    let auth_response: DeviceAuthorizationResponse = response
        .json()
        .await
        .context("Failed to parse device authorization response")?;

    info!("✅ Device authorization received: user_code={}", auth_response.user_code);

    Ok(auth_response)
}

async fn poll_for_token(
    client: &Client,
    aip_base_url: &str,
    client_id: &str,
    device_code: &str,
    interval: u64,
    expires_in: u64,
) -> Result<TokenResponse> {
    let url = format!("{}/oauth/token", aip_base_url);
    let poll_interval = Duration::from_secs(interval);
    let start_time = std::time::Instant::now();
    let timeout = Duration::from_secs(expires_in);

    let request = DeviceTokenRequest {
        grant_type: "urn:ietf:params:oauth:grant-type:device_code".to_string(),
        device_code: device_code.to_string(),
        client_id: client_id.to_string(),
    };

    info!("🔄 Starting token polling (interval: {}s, timeout: {}s)", interval, expires_in);

    let mut poll_count = 0;
    loop {
        if start_time.elapsed() > timeout {
            anyhow::bail!("Device code expired after {} seconds", expires_in);
        }

        poll_count += 1;
        info!("📡 Polling attempt #{}", poll_count);

        let response = client
            .post(&url)
            .form(&request)
            .send()
            .await
            .context("Failed to send token request")?;

        if response.status().is_success() {
            let token_response: TokenResponse = response
                .json()
                .await
                .context("Failed to parse token response")?;

            info!("🎉 Access token obtained successfully!");
            return Ok(token_response);
        }

        // Check for error response
        let error_response: TokenError = response
            .json()
            .await
            .context("Failed to parse error response")?;

        match error_response.error.as_str() {
            "authorization_pending" => {
                info!("⏳ Authorization still pending, waiting {} seconds...", interval);
            }
            "slow_down" => {
                info!("🐌 Slow down requested, increasing poll interval");
                tokio::time::sleep(poll_interval * 2).await;
                continue;
            }
            "expired_token" => {
                anyhow::bail!("Device code has expired");
            }
            "access_denied" => {
                anyhow::bail!("User denied the authorization request");
            }
            "server_error" => {
                // Check if it's actually an authorization pending error from AIP
                let description = error_response.error_description.as_deref().unwrap_or("");
                if description.contains("Authorization pending") || description.contains("Device code not yet authorized") {
                    info!("⏳ Authorization still pending, waiting {} seconds...", interval);
                } else {
                    anyhow::bail!("Server error: {}", description);
                }
            }
            _ => {
                anyhow::bail!("Token request failed: {} - {}",
                    error_response.error,
                    error_response.error_description.unwrap_or_default());
            }
        }

        tokio::time::sleep(poll_interval).await;
    }
}

async fn test_access_token(
    client: &Client,
    aip_base_url: &str,
    access_token: &str,
) -> Result<serde_json::Value> {
    let url = format!("{}/api/atprotocol/session", aip_base_url);

    let response = client
        .get(&url)
        .bearer_auth(access_token)
        .send()
        .await
        .context("Failed to test access token")?;

    if !response.status().is_success() {
        let status = response.status();
        let body = response.text().await.unwrap_or_default();
        anyhow::bail!("Access token test failed: {} - {}", status, body);
    }

    let session_info: serde_json::Value = response
        .json()
        .await
        .context("Failed to parse session info")?;

    Ok(session_info)
}
