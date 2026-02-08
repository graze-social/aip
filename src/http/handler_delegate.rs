//! Handles delegate access management endpoints

use axum::{
    extract::State,
    http::StatusCode,
    response::Json,
};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

use super::context::AppState;
use super::utils_error::{StorageResultExt, bad_request, unauthorized};
use super::utils_oauth::validate_did;
use crate::http::middleware_auth::ExtractedAuth;

/// Request body for grant/revoke operations
#[derive(Debug, Deserialize)]
pub struct DelegateBody {
    pub delegate_did: String,
}

/// A delegate grant in API responses
#[derive(Debug, Serialize)]
pub struct DelegateGrantResponse {
    pub owner_did: String,
    pub delegate_did: String,
    pub granted_at: String,
}

/// Grant delegate access
/// POST /api/delegate/grant
pub async fn grant_delegate_handler(
    State(state): State<AppState>,
    ExtractedAuth(access_token): ExtractedAuth,
    Json(body): Json<DelegateBody>,
) -> Result<Json<Value>, (StatusCode, Json<Value>)> {
    let owner_did = access_token
        .user_id
        .as_ref()
        .ok_or_else(|| unauthorized("Token missing user_id (DID)"))?;

    if let Err(e) = validate_did(&body.delegate_did) {
        return Err(bad_request(format!("Invalid delegate_did: {}", e)));
    }

    if owner_did == &body.delegate_did {
        return Err(bad_request("Cannot delegate to yourself"));
    }

    state
        .oauth_storage
        .grant_delegate(owner_did, &body.delegate_did)
        .await
        .to_http_error("Failed to grant delegate access")?;

    Ok(Json(json!({
        "owner_did": owner_did,
        "delegate_did": body.delegate_did,
        "message": "Delegate access granted"
    })))
}

/// Revoke delegate access
/// POST /api/delegate/revoke
pub async fn revoke_delegate_handler(
    State(state): State<AppState>,
    ExtractedAuth(access_token): ExtractedAuth,
    Json(body): Json<DelegateBody>,
) -> Result<Json<Value>, (StatusCode, Json<Value>)> {
    let owner_did = access_token
        .user_id
        .as_ref()
        .ok_or_else(|| unauthorized("Token missing user_id (DID)"))?;

    if let Err(e) = validate_did(&body.delegate_did) {
        return Err(bad_request(format!("Invalid delegate_did: {}", e)));
    }

    state
        .oauth_storage
        .revoke_delegate(owner_did, &body.delegate_did)
        .await
        .to_http_error("Failed to revoke delegate access")?;

    Ok(Json(json!({
        "owner_did": owner_did,
        "delegate_did": body.delegate_did,
        "message": "Delegate access revoked"
    })))
}

/// List delegates for the authenticated user (as owner)
/// GET /api/delegate/delegates
pub async fn list_delegates_handler(
    State(state): State<AppState>,
    ExtractedAuth(access_token): ExtractedAuth,
) -> Result<Json<Value>, (StatusCode, Json<Value>)> {
    let owner_did = access_token
        .user_id
        .as_ref()
        .ok_or_else(|| unauthorized("Token missing user_id (DID)"))?;

    let grants = state
        .oauth_storage
        .list_delegates(owner_did)
        .await
        .to_http_error("Failed to list delegates")?;

    let response: Vec<DelegateGrantResponse> = grants
        .into_iter()
        .map(|g| DelegateGrantResponse {
            owner_did: g.owner_did,
            delegate_did: g.delegate_did,
            granted_at: g.granted_at.to_rfc3339(),
        })
        .collect();

    Ok(Json(json!({ "delegates": response })))
}

/// List owners the authenticated user is a delegate for
/// GET /api/delegate/owners
pub async fn list_owners_handler(
    State(state): State<AppState>,
    ExtractedAuth(access_token): ExtractedAuth,
) -> Result<Json<Value>, (StatusCode, Json<Value>)> {
    let delegate_did = access_token
        .user_id
        .as_ref()
        .ok_or_else(|| unauthorized("Token missing user_id (DID)"))?;

    let grants = state
        .oauth_storage
        .list_owners(delegate_did)
        .await
        .to_http_error("Failed to list owners")?;

    let response: Vec<DelegateGrantResponse> = grants
        .into_iter()
        .map(|g| DelegateGrantResponse {
            owner_did: g.owner_did,
            delegate_did: g.delegate_did,
            granted_at: g.granted_at.to_rfc3339(),
        })
        .collect();

    Ok(Json(json!({ "owners": response })))
}
