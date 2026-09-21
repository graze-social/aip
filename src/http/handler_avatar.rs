//! Handles GET /oauth/avatar/{cid} — serves profile-avatar blobs mirrored to
//! the cluster Garage (OVHP-117). Garage has no anonymous reads, so AIP
//! streams the object itself; missing objects or an unconfigured store → 404.

use axum::{
    Json,
    body::Body,
    extract::{Path, State},
    http::{StatusCode, header},
    response::{IntoResponse, Response},
};
use serde_json::{Value, json};

use super::context::AppState;
use crate::oauth::avatar_storage::AvatarStorage;

/// GET /oauth/avatar/{cid}
pub async fn handle_avatar(
    State(_state): State<AppState>,
    Path(cid): Path<String>,
) -> Response {
    let Some(storage) = AvatarStorage::from_env() else {
        return json_error(StatusCode::NOT_FOUND, "avatar storage not configured");
    };

    match storage.get(&cid).await {
        Ok(bytes) => {
            let mime = crate::oauth::avatar_storage::sniff_image_content_type(&bytes);
            let mut response = Response::new(Body::from(bytes));
            if let Ok(value) = header::HeaderValue::from_str(mime) {
                response.headers_mut().insert(header::CONTENT_TYPE, value);
            }
            response.headers_mut().insert(
                header::CACHE_CONTROL,
                header::HeaderValue::from_static("public, max-age=31536000, immutable"),
            );
            response
        }
        Err(e) => {
            tracing::warn!(cid = %cid, error = %e, "avatar object fetch failed");
            json_error(StatusCode::NOT_FOUND, "avatar not found")
        }
    }
}

fn json_error(status: StatusCode, description: &str) -> Response {
    let body: Json<Value> = Json(json!({ "error": "not_found", "error_description": description }));
    (status, body).into_response()
}