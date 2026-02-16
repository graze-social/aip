//! Handles POST /api/atprotocol/dpop-proof - Signs DPoP proofs for authenticated sessions
//!
//! Instead of returning the private key to delegates, AIP keeps the key and signs
//! DPoP proofs on demand. This ensures revocation is immediate — every signing request
//! re-checks delegation status.

use atproto_identity::key::{identify_key, sign, to_public};
use atproto_oauth::jwk::generate as generate_jwk;
use axum::{
    extract::State,
    http::StatusCode,
    response::Json,
};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::time::{SystemTime, UNIX_EPOCH};
use uuid::Uuid;

use super::context::AppState;
use super::utils_error::{bad_request, server_error, unauthorized};
use super::utils_oauth::validate_did;
use crate::http::middleware_auth::ExtractedAuth;

/// Request body for DPoP proof signing
#[derive(Debug, Deserialize)]
pub struct DpopProofRequest {
    /// HTTP method for the DPoP proof (e.g. "POST", "GET")
    pub method: String,
    /// Target URL for the DPoP proof
    pub url: String,
    /// Owner DID to act on behalf of (optional, for delegate access)
    pub delegate_for: Option<String>,
    /// PDS-provided nonce for retry (optional)
    pub nonce: Option<String>,
}

/// Response containing the signed DPoP proof
#[derive(Debug, Serialize)]
pub struct DpopProofResponse {
    /// Signed DPoP proof JWT
    pub dpop_proof: String,
    /// DPoP-bound access token (useless without the proof)
    pub access_token: String,
}

/// DPoP JWT claims
#[derive(Debug, Serialize)]
struct DPoPClaims {
    jti: String,
    htm: String,
    htu: String,
    iat: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    ath: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    nonce: Option<String>,
}

/// Sign a DPoP proof for an authenticated session
/// POST /api/atprotocol/dpop-proof
pub async fn dpop_proof_handler(
    State(state): State<AppState>,
    ExtractedAuth(access_token): ExtractedAuth,
    Json(body): Json<DpopProofRequest>,
) -> Result<Json<DpopProofResponse>, (StatusCode, Json<Value>)> {
    // 1. Extract caller DID
    let caller_did = access_token
        .user_id
        .as_ref()
        .ok_or_else(|| unauthorized("Token missing user_id (DID)"))?;

    // 2. Validate method and url
    let method_upper = body.method.to_uppercase();
    match method_upper.as_str() {
        "GET" | "POST" | "PUT" | "DELETE" | "PATCH" | "HEAD" | "OPTIONS" => {}
        _ => return Err(bad_request(format!("Invalid HTTP method: {}", body.method))),
    }

    if url::Url::parse(&body.url).is_err() {
        return Err(bad_request(format!("Invalid URL: {}", body.url)));
    }

    // 3. If delegate_for is set, validate and check delegation
    let target_did = if let Some(ref owner_did) = body.delegate_for {
        if let Err(e) = validate_did(owner_did) {
            return Err(bad_request(format!("Invalid delegate_for DID: {}", e)));
        }

        let is_delegate = state
            .oauth_storage
            .is_delegate(owner_did, caller_did)
            .await
            .map_err(|e| {
                server_error(format!("Failed to check delegate access: {}", e))
            })?;

        if !is_delegate {
            return Err((
                StatusCode::FORBIDDEN,
                Json(json!({
                    "error": "forbidden",
                    "error_description": "You are not a delegate for this account"
                })),
            ));
        }

        owner_did.as_str()
    } else {
        caller_did.as_str()
    };

    // 4. Look up best session for target DID
    let target_sessions = state
        .oauth_storage
        .get_sessions_by_did(target_did)
        .await
        .map_err(|e| {
            server_error(format!("Failed to look up sessions: {}", e))
        })?;

    let session = target_sessions
        .into_iter()
        .filter(|s| {
            s.access_token.is_some()
                && s.session_exchanged_at.is_some()
                && s.exchange_error.is_none()
        })
        .max_by_key(|s| s.access_token_expires_at)
        .ok_or_else(|| {
            (
                StatusCode::NOT_FOUND,
                Json(json!({
                    "error": "session_not_found",
                    "error_description": "No valid session found"
                })),
            )
        })?;

    // Get the access token from the session
    let session_access_token = session.access_token.as_ref().ok_or_else(|| {
        server_error("Session has no access token")
    })?;

    // 5. Parse session.dpop_key via identify_key
    let private_key_data = identify_key(&session.dpop_key)
        .map_err(|e| server_error(format!("Failed to parse DPoP key: {}", e)))?;

    // 6. Generate public JWK for JWT header
    let public_key_data = to_public(&private_key_data)
        .map_err(|e| server_error(format!("Failed to derive public key: {}", e)))?;
    let jwk_wrapped = generate_jwk(&public_key_data)
        .map_err(|e| server_error(format!("Failed to generate JWK: {}", e)))?;
    let public_key_jwk: serde_json::Value = serde_json::to_value(&jwk_wrapped)
        .map_err(|e| server_error(format!("Failed to serialize JWK: {}", e)))?;

    // 7. Build DPoP proof JWT
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|e| server_error(format!("System time error: {}", e)))?
        .as_secs();

    let token_hash = Sha256::digest(session_access_token.as_bytes());
    let ath = URL_SAFE_NO_PAD.encode(&token_hash);

    let claims = DPoPClaims {
        jti: Uuid::new_v4().to_string(),
        htm: method_upper,
        htu: body.url,
        iat: now,
        ath: Some(ath),
        nonce: body.nonce,
    };

    let header_json = json!({
        "typ": "dpop+jwt",
        "alg": "ES256",
        "jwk": public_key_jwk
    });

    let header_b64 = URL_SAFE_NO_PAD.encode(
        serde_json::to_string(&header_json)
            .map_err(|e| server_error(format!("Failed to serialize header: {}", e)))?,
    );
    let claims_b64 = URL_SAFE_NO_PAD.encode(
        serde_json::to_string(&claims)
            .map_err(|e| server_error(format!("Failed to serialize claims: {}", e)))?,
    );

    let signing_input = format!("{}.{}", header_b64, claims_b64);

    let signature = sign(&private_key_data, signing_input.as_bytes())
        .map_err(|e| server_error(format!("Failed to sign DPoP proof: {}", e)))?;
    let signature_b64 = URL_SAFE_NO_PAD.encode(&signature);

    let dpop_proof = format!("{}.{}", signing_input, signature_b64);

    // 8. Return proof and access token
    Ok(Json(DpopProofResponse {
        dpop_proof,
        access_token: session_access_token.clone(),
    }))
}
