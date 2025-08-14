//! Device authorization page handler for RFC 8628 device flow
//!
//! This handler provides the web interface where users enter the device code
//! to authorize their device. Users must authenticate via ATProtocol OAuth
//! before they can authorize devices.

use crate::http::context::AppState;
use axum::{
    extract::{Query, State},
    response::{IntoResponse, Redirect},
    Form,
};
use axum_template::RenderHtml;
use base64::prelude::*;
use minijinja::context;
use rand::Rng;
use serde::Deserialize;
use sha2::{Digest, Sha256};
use url::Url;

/// Query parameters for device authorization page
#[derive(Deserialize)]
pub struct DeviceQuery {
    /// Pre-filled user code from verification_uri_complete
    pub user_code: Option<String>,
    /// User DID for authenticated user
    pub user_id: Option<String>,
}

/// Form data for device authorization
#[derive(Deserialize)]
pub struct DeviceAuthorizationForm {
    /// The user code entered by the user
    pub user_code: String,
    /// User DID for authenticated user
    pub user_id: Option<String>,
}

/// GET /device - Show device authorization page or redirect to login
pub async fn device_authorization_page(
    Query(query): Query<DeviceQuery>,
    State(state): State<AppState>,
) -> impl IntoResponse {
    let user_code = query.user_code.as_deref().unwrap_or("");

    // Check if user has an authenticated user_id
    if let Some(user_id) = &query.user_id {
        // User is authenticated, show the device authorization form
        RenderHtml(
            "device.html",
            state.template_env,
            context! {
                user_code => user_code,
                user_id => user_id,
                title => "Device Authorization",
            },
        ).into_response()
    } else if !user_code.is_empty() {
        // Look up the device code to verify it exists
        match state.oauth_storage.get_device_code_by_user_code(user_code).await {
            Ok(Some(device_entry)) => {
                // Device code exists, redirect to OAuth authorization flow
                // The user needs to authenticate first before authorizing the device
                let redirect_uri = format!("{}/device/callback", state.config.external_base);
                let internal_client_id = state.config.internal_device_auth_client_id.as_ref();
                let scope = device_entry.scope.as_deref().unwrap_or("atproto");

                // Generate PKCE parameters for public client

                let mut rng = rand::thread_rng();
                let code_verifier_bytes: [u8; 32] = rng.r#gen();
                let code_verifier = BASE64_URL_SAFE_NO_PAD.encode(code_verifier_bytes);

                let mut hasher = Sha256::new();
                hasher.update(code_verifier.as_bytes());
                let code_challenge = BASE64_URL_SAFE_NO_PAD.encode(hasher.finalize());

                // Store code_verifier in state parameter along with user_code
                let device_auth_state = format!("{}:{}", user_code, code_verifier);

                // Redirect to the existing OAuth authorize endpoint
                let mut oauth_url = Url::parse(&format!("{}/oauth/authorize", state.config.external_base))
                    .expect("Invalid external_base URL");
                oauth_url.query_pairs_mut()
                    .append_pair("response_type", "code")
                    .append_pair("client_id", internal_client_id)
                    .append_pair("redirect_uri", &redirect_uri)
                    .append_pair("scope", scope)
                    .append_pair("state", &device_auth_state)
                    .append_pair("code_challenge", &code_challenge)
                    .append_pair("code_challenge_method", "S256");

                Redirect::to(oauth_url.as_str()).into_response()
            }
            _ => {
                // Device code not found or error, show form with error
                RenderHtml(
                    "device.html",
                    state.template_env,
                    context! {
                        user_code => user_code,
                        error => "Invalid or expired device code",
                        title => "Device Authorization - Error",
                    },
                ).into_response()
            }
        }
    } else {
        // No user code provided, show empty form
        RenderHtml(
            "device.html",
            state.template_env,
            context! {
                user_code => "",
                title => "Device Authorization",
            },
        ).into_response()
    }
}

/// POST /device/authorize - Process device authorization
pub async fn device_authorize(
    State(state): State<AppState>,
    Form(form): Form<DeviceAuthorizationForm>,
) -> impl IntoResponse {
    let user_code = form.user_code.trim().to_uppercase();

    // Validate user code format (basic validation)
    if user_code.len() < 4 || user_code.len() > 9 {
        return RenderHtml(
            "device.html",
            state.template_env,
            context! {
                error => "Invalid code format. Please enter the code exactly as shown on your device.",
                user_code => "",
                title => "Device Authorization - Error",
            },
        ).into_response();
    }

    // Check if user has an authenticated user_id
    let user_did = if let Some(user_id) = &form.user_id {
        user_id.clone()
    } else {
        // No session provided - redirect to OAuth login first
        // Look up the device code to verify it exists before redirecting
        match state.oauth_storage.get_device_code_by_user_code(&user_code).await {
            Ok(Some(device_entry)) => {
                // Device code exists, redirect to OAuth authorization flow
                // The user needs to authenticate first before authorizing the device
                let redirect_uri = format!("{}/device/callback", state.config.external_base);
                let internal_client_id = state.config.internal_device_auth_client_id.as_ref();
                let scope = device_entry.scope.as_deref().unwrap_or("atproto");

                // Generate PKCE parameters for public client

                let mut rng = rand::thread_rng();
                let code_verifier_bytes: [u8; 32] = rng.r#gen();
                let code_verifier = BASE64_URL_SAFE_NO_PAD.encode(code_verifier_bytes);

                let mut hasher = Sha256::new();
                hasher.update(code_verifier.as_bytes());
                let code_challenge = BASE64_URL_SAFE_NO_PAD.encode(hasher.finalize());

                // Store code_verifier in state parameter along with user_code
                let device_auth_state = format!("{}:{}", user_code, code_verifier);

                // Redirect to the existing OAuth authorize endpoint
                let mut oauth_url = Url::parse(&format!("{}/oauth/authorize", state.config.external_base))
                    .expect("Invalid external_base URL");
                oauth_url.query_pairs_mut()
                    .append_pair("response_type", "code")
                    .append_pair("client_id", internal_client_id)
                    .append_pair("redirect_uri", &redirect_uri)
                    .append_pair("scope", scope)
                    .append_pair("state", &device_auth_state)
                    .append_pair("code_challenge", &code_challenge)
                    .append_pair("code_challenge_method", "S256");

                return Redirect::to(oauth_url.as_str()).into_response();
            }
            _ => {
                // Device code not found or error, show form with error
                return RenderHtml(
                    "device.html",
                    state.template_env,
                    context! {
                        error => "Invalid or expired device code",
                        user_code => "",
                        title => "Device Authorization - Error",
                    },
                ).into_response();
            }
        }
    };

    // Try to authorize the device code
    match state.oauth_storage.authorize_device_code(&user_code, &user_did).await {
        Ok(()) => {
            // Success! Show confirmation page
            RenderHtml(
                "device_success.html",
                state.template_env,
                context! {
                    success => true,
                    user_code => user_code,
                    title => "Device Authorized",
                },
            ).into_response()
        }
        Err(e) => {
            // Handle different error types
            let error_message = if e.to_string().contains("not found") {
                "Code not found. Please check that you entered it correctly, or it may have expired."
            } else if e.to_string().contains("expired") {
                "This code has expired. Please try again from your device."
            } else {
                "Unable to authorize device. Please try again."
            };

            RenderHtml(
                "device.html",
                state.template_env,
                context! {
                    error => error_message,
                    user_code => "",
                    title => "Device Authorization - Error",
                },
            ).into_response()
        }
    }
}

/// Query parameters for OAuth callback
#[derive(Deserialize)]
pub struct OAuthCallbackQuery {
    pub code: Option<String>,
    pub state: Option<String>,
    pub error: Option<String>,
    pub error_description: Option<String>,
}

/// GET /device/callback - Handle OAuth callback and redirect back to device authorization
pub async fn device_oauth_callback(
    Query(query): Query<OAuthCallbackQuery>,
    State(state): State<AppState>,
) -> impl IntoResponse {
    // Handle OAuth errors
    if let Some(_error) = query.error {
        let description = query.error_description.unwrap_or_else(|| "OAuth authentication failed".to_string());

        return RenderHtml(
            "device.html",
            state.template_env,
            context! {
                error => format!("Authentication failed: {}", description),
                title => "Device Authorization - Error",
            },
        ).into_response();
    }

    // Extract authorization code and user_code from state
    let auth_code = match query.code {
        Some(code) => code,
        None => {
            return RenderHtml(
                "device.html",
                state.template_env,
                context! {
                    error => "No authorization code received",
                    title => "Device Authorization - Error",
                },
            ).into_response();
        }
    };

    // Extract user_code and code_verifier from state parameter
    let state_parts: Vec<&str> = query.state.as_deref().unwrap_or_default().split(':').collect();
    let (user_code, code_verifier) = if state_parts.len() >= 2 {
        (state_parts[0].to_string(), state_parts[1].to_string())
    } else {
        (query.state.unwrap_or_default(), String::new())
    };

    // Exchange authorization code for access token using internal client
    let internal_client_id = state.config.internal_device_auth_client_id.as_ref();
    let token_response = match exchange_auth_code_for_token(&state, &auth_code, internal_client_id, &code_verifier).await {
        Ok(token) => token,
        Err(e) => {
            return RenderHtml(
                "device.html",
                state.template_env,
                context! {
                    error => format!("Token exchange failed: {}", e),
                    title => "Device Authorization - Error",
                },
            ).into_response();
        }
    };

    // Get the user's DID from the access token
    let user_did = match get_user_did_from_token(&state, &token_response.access_token).await {
        Ok(did) => did,
        Err(e) => {
            return RenderHtml(
                "device.html",
                state.template_env,
                context! {
                    error => format!("Failed to get user identity: {}", e),
                    title => "Device Authorization - Error",
                },
            ).into_response();
        }
    };

    // Instead of immediately authorizing, redirect to confirmation page 
    // Pass the user DID as the user_id parameter so the confirmation page knows who is authenticated
    let redirect_url = format!("/device?user_code={}&user_id={}", user_code, user_did);
    Redirect::to(&redirect_url).into_response()
}

/// Exchange authorization code for access token
async fn exchange_auth_code_for_token(
    state: &AppState,
    auth_code: &str,
    client_id: &str,
    code_verifier: &str,
) -> Result<crate::oauth::TokenResponse, Box<dyn std::error::Error>> {
    use crate::oauth::auth_server::{TokenForm, extract_client_auth};
    use crate::oauth::types::TokenRequest;

    // Get the client for authentication
    let client = state.oauth_storage.get_client(client_id).await?
        .ok_or("Client not found")?;

    // Build token request
    let form = TokenForm {
        grant_type: "authorization_code".to_string(),
        code: Some(auth_code.to_string()),
        redirect_uri: Some(format!("{}/device/callback", state.config.external_base)),
        code_verifier: if code_verifier.is_empty() { None } else { Some(code_verifier.to_string()) },
        refresh_token: None,
        device_code: None,
        client_id: Some(client.client_id.clone()),
        client_secret: client.client_secret.clone(),
        scope: None,
    };

    let request = TokenRequest::try_from(form)?;
    let headers = axum::http::HeaderMap::new();
    let client_auth = extract_client_auth(&headers, &TokenForm {
        grant_type: "authorization_code".to_string(),
        code: Some(auth_code.to_string()),
        redirect_uri: Some(format!("{}/device/callback", state.config.external_base)),
        code_verifier: if code_verifier.is_empty() { None } else { Some(code_verifier.to_string()) },
        refresh_token: None,
        device_code: None,
        client_id: Some(client.client_id),
        client_secret: client.client_secret,
        scope: None,
    });

    // Create authorization server and exchange token
    let auth_server = crate::http::utils_oauth::create_base_auth_server(state).await
        .map_err(|e| format!("Failed to create auth server: {}", e))?;
    let token_response = auth_server.token(request, &headers, client_auth).await
        .map_err(|e| format!("Token exchange failed: {}", e))?;

    Ok(token_response)
}

/// Get user's DID from access token
async fn get_user_did_from_token(
    state: &AppState,
    access_token: &str,
) -> Result<String, Box<dyn std::error::Error>> {
    // Look up the access token to get the user_id (which should be the DID)
    let token = state.oauth_storage.get_token(access_token).await?
        .ok_or("Access token not found")?;

    let user_did = token.user_id.ok_or("No user ID in access token")?;
    Ok(user_did)
}

