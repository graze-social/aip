//! Avatar blob storage — cluster Garage (S3-compatible), env-configured.
//!
//! AIP mirrors the user's atproto profile avatar (`app.bsky.actor.profile`
//! → `avatar` blob) into an S3-compatible store (Garage, `aip-avatars`
//! bucket) at userinfo time and exposes it as the standard OIDC `picture`
//! claim (OVHP-117). Garage has no anonymous reads, so AIP streams the
//! object itself at `/oauth/avatar/{cid}`.
//!
//! Config is read from the process env (the `aip.env` the unit loads) —
//! deliberately NOT through `Config`, so the avatar feature stays
//! self-contained (no claim when the store isn't configured):
//!
//! ```text
//! AVATAR_STORAGE_ENDPOINT=http://10.0.0.11:3900
//! AVATAR_STORAGE_REGION=garage
//! AVATAR_STORAGE_BUCKET=aip-avatars
//! AVATAR_STORAGE_ACCESS_KEY=…
//! AVATAR_STORAGE_SECRET_KEY=…
//! ```
//!
//! Fail-open by design: every fetch/storage error just omits the claim.
//!
//! Backend: the `object_store` crate (apache-arrow), the standard object
//! storage abstraction (S3/GS/Azure/Local), replacing a hand-rolled `rust-s3`
//! client per upstream review feedback. Garage is path-style S3, which is
//! object_store's default for the AWS backend. Content-type is stored on PUT;
//! since `object_store` 0.12 does not surface it on GET, the serving handler
//! sniffs the (image) bytes instead.

use std::env;
use std::sync::Arc;

use bytes::Bytes;
use object_store::aws::AmazonS3Builder;
use object_store::path::Path as StorePath;
use object_store::{Attribute, Attributes, ObjectStore, PutOptions, PutPayload};

/// S3-compatible avatar storage handle (Garage).
#[derive(Clone)]
pub struct AvatarStorage {
    store: Arc<dyn ObjectStore>,
}

impl AvatarStorage {
    /// Build storage from the environment; `None` when not fully configured.
    pub fn from_env() -> Option<Self> {
        let endpoint = env::var("AVATAR_STORAGE_ENDPOINT").ok()?;
        let region = env::var("AVATAR_STORAGE_REGION")
            .unwrap_or_else(|_| "garage".to_string());
        let bucket_name = env::var("AVATAR_STORAGE_BUCKET").ok()?;
        let access_key = env::var("AVATAR_STORAGE_ACCESS_KEY").ok()?;
        let secret_key = env::var("AVATAR_STORAGE_SECRET_KEY").ok()?;

        if endpoint.is_empty()
            || bucket_name.is_empty()
            || access_key.is_empty()
            || secret_key.is_empty()
        {
            return None;
        }

        let mut builder = AmazonS3Builder::new()
            .with_region(&region)
            .with_bucket_name(bucket_name)
            .with_access_key_id(access_key)
            .with_secret_access_key(secret_key)
            .with_endpoint(&endpoint);

        // Garage is plain HTTP on the cluster LAN and uses path-style
        // addressing (object_store's default for the AWS backend).
        if !endpoint.starts_with("https") {
            builder = builder.with_allow_http(true);
        }

        match builder.build() {
            Ok(store) => Some(Self {
                store: Arc::new(store),
            }),
            Err(e) => {
                tracing::warn!(error = %e, "avatar storage: store init failed");
                None
            }
        }
    }

    /// Upload (idempotent by design — objects are keyed by their atproto blob
    /// CID, so re-uploading the same avatar overwrites with identical bytes).
    pub async fn put(&self, cid: &str, bytes: &[u8], content_type: &str) -> Result<(), String> {
        let mut attributes = Attributes::new();
        attributes.insert(
            Attribute::ContentType,
            content_type.to_string().into(),
        );

        self.store
            .put_opts(
                &StorePath::from(cid),
                PutPayload::from_bytes(Bytes::from(bytes.to_vec())),
                PutOptions {
                    attributes,
                    ..Default::default()
                },
            )
            .await
            .map(|_| ())
            .map_err(|e| format!("avatar storage put failed: {}", e))
    }

    /// Fetch an object's bytes (content-type is sniffed by the caller; see the
    /// module docs).
    pub async fn get(&self, cid: &str) -> Result<Bytes, String> {
        let result = self
            .store
            .get(&StorePath::from(cid))
            .await
            .map_err(|e| format!("avatar storage get failed: {}", e))?;
        result
            .bytes()
            .await
            .map_err(|e| format!("avatar storage get stream failed: {}", e))
    }
}

/// Best-effort content-type for avatar blobs (all common atproto avatar
/// formats), sniffed from the leading bytes.
pub fn sniff_image_content_type(bytes: &[u8]) -> &'static str {
    if bytes.starts_with(&[0x89, b'P', b'N', b'G', 0x0d, 0x0a, 0x1a, 0x0a]) {
        "image/png"
    } else if bytes.len() >= 3 && bytes[0] == 0xff && bytes[1] == 0xd8 && bytes[2] == 0xff {
        "image/jpeg"
    } else if bytes.starts_with(b"GIF8") {
        "image/gif"
    } else if bytes.len() >= 12
        && bytes.starts_with(b"RIFF")
        && &bytes[8..12] == b"WEBP"
    {
        "image/webp"
    } else if bytes.starts_with(b"\x00\x00\x00") {
        "image/heic"
    } else {
        "application/octet-stream"
    }
}

/// The claim URL AIP serves the avatar at (browser-friendly, AIP-hosted).
pub fn picture_url(cid: &str) -> Option<String> {
    let external_base = env::var("EXTERNAL_BASE").ok()?;
    Some(format!("{}/oauth/avatar/{}", external_base, cid))
}