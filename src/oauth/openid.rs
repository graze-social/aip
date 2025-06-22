//! OpenID Connect support for ID token generation and validation.

use anyhow::Result;
use base64::Engine;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

use crate::errors::OAuthError;

/// Unified OpenID Connect Claims structure for both ID tokens and UserInfo responses
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct OpenIDClaims {
    /// Issuer - The URL of the authorization server
    #[serde(skip_serializing_if = "Option::is_none")]
    pub iss: Option<String>,

    /// Subject - DID of the end user
    pub sub: String,

    /// Audience - Client ID that this token is intended for
    #[serde(skip_serializing_if = "Option::is_none")]
    pub aud: Option<String>,

    /// Expiration time - Unix timestamp when token expires
    #[serde(skip_serializing_if = "Option::is_none")]
    pub exp: Option<i64>,

    /// Issued at - Unix timestamp when token was issued
    #[serde(skip_serializing_if = "Option::is_none")]
    pub iat: Option<i64>,

    /// Authentication time - Unix timestamp when user authenticated
    #[serde(skip_serializing_if = "Option::is_none")]
    pub auth_time: Option<i64>,

    /// Nonce - String value used to associate a client session with an ID token (only for id_token)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub nonce: Option<String>,

    /// Access token hash - Hash of access token (only for id_token)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub at_hash: Option<String>,

    /// Code hash - Hash of authorization code (only for id_token)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub c_hash: Option<String>,

    /// DID - The user's DID from the DID document
    #[serde(skip_serializing_if = "Option::is_none")]
    pub did: Option<String>,

    /// Name - The user's handle from the DID document
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,

    /// Profile - The user's profile URL
    #[serde(skip_serializing_if = "Option::is_none")]
    pub profile: Option<String>,

    /// PDS endpoint - The user's PDS endpoint from the DID document
    #[serde(skip_serializing_if = "Option::is_none")]
    pub pds_endpoint: Option<String>,

    /// Email - The user's email address
    #[serde(skip_serializing_if = "Option::is_none")]
    pub email: Option<String>,

    /// Additional claims
    #[serde(flatten)]
    pub additional_claims: HashMap<String, serde_json::Value>,
}

/// OpenID Connect ID Token Claims (deprecated - use OpenIDClaims instead)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IdTokenClaims {
    /// Issuer - The URL of the authorization server
    pub iss: String,
    /// Subject - Unique identifier for the end user
    pub sub: String,
    /// Audience - Client ID that this token is intended for
    pub aud: String,
    /// Expiration time - Unix timestamp when token expires
    pub exp: i64,
    /// Issued at - Unix timestamp when token was issued
    pub iat: i64,
    /// Authentication time - Unix timestamp when user authenticated (optional)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub auth_time: Option<i64>,
    /// Nonce - String value used to associate a client session with an ID token (optional)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub nonce: Option<String>,
    /// Access token hash - Hash of access token when present (optional)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub at_hash: Option<String>,
    /// Additional claims
    #[serde(flatten)]
    pub additional_claims: HashMap<String, serde_json::Value>,
}

impl OpenIDClaims {
    /// Create new claims for ID token
    pub fn new_id_token(
        issuer: String,
        subject: String,
        audience: String,
        auth_time: DateTime<Utc>,
    ) -> Self {
        let now = Utc::now();
        // Set expiration to 14 days from now
        let exp = (now + chrono::Duration::days(14)).timestamp();
        // Set issued at to 30 seconds ago
        let iat = (now - chrono::Duration::seconds(30)).timestamp();

        Self {
            iss: Some(issuer),
            sub: subject,
            aud: Some(audience),
            exp: Some(exp),
            iat: Some(iat),
            auth_time: Some(auth_time.timestamp()),
            nonce: None,
            at_hash: None,
            c_hash: None,
            did: None,
            name: None,
            profile: None,
            pds_endpoint: None,
            email: None,
            additional_claims: HashMap::new(),
        }
    }

    /// Create new claims for UserInfo response
    pub fn new_userinfo(subject: String) -> Self {
        Self {
            sub: subject,
            ..Default::default()
        }
    }

    /// Set nonce value (for ID tokens)
    pub fn with_nonce(mut self, nonce: Option<String>) -> Self {
        self.nonce = nonce;
        self
    }

    /// Set access token hash (for ID tokens)
    pub fn with_at_hash(mut self, access_token: &str) -> Self {
        self.at_hash = Some(calculate_hash(access_token));
        self
    }

    /// Set code hash (for ID tokens)
    pub fn with_c_hash(mut self, code: &str) -> Self {
        self.c_hash = Some(calculate_hash(code));
        self
    }

    /// Set DID
    pub fn with_did(mut self, did: String) -> Self {
        self.did = Some(did);
        self
    }

    /// Set name (handle)
    pub fn with_name(mut self, handle: Option<String>) -> Self {
        self.name = handle.or(Some("unknown".to_string()));
        // Also set profile if we have a handle
        if let Some(ref name) = self.name {
            if name != "unknown" {
                self.profile = Some(format!("https://bsky.app/profile/{}", name));
            }
        }
        self
    }

    /// Set profile URL
    pub fn with_profile(mut self, profile: Option<String>) -> Self {
        self.profile = profile;
        self
    }

    /// Set PDS endpoint
    pub fn with_pds_endpoint(mut self, pds_endpoint: Option<String>) -> Self {
        self.pds_endpoint = pds_endpoint;
        self
    }

    /// Set email
    pub fn with_email(mut self, email: Option<String>) -> Self {
        self.email = email;
        self
    }

    /// Add additional claim
    pub fn with_claim(mut self, key: String, value: serde_json::Value) -> Self {
        self.additional_claims.insert(key, value);
        self
    }
}

impl IdTokenClaims {
    /// Create new ID token claims
    pub fn new(issuer: String, subject: String, audience: String, expires_in_seconds: u64) -> Self {
        let now = Utc::now();
        let exp = (now + chrono::Duration::seconds(expires_in_seconds as i64)).timestamp();
        let iat = now.timestamp();

        Self {
            iss: issuer,
            sub: subject,
            aud: audience,
            exp,
            iat,
            auth_time: None,
            nonce: None,
            at_hash: None,
            additional_claims: HashMap::new(),
        }
    }

    /// Set authentication time
    pub fn with_auth_time(mut self, auth_time: DateTime<Utc>) -> Self {
        self.auth_time = Some(auth_time.timestamp());
        self
    }

    /// Set nonce value
    pub fn with_nonce(mut self, nonce: String) -> Self {
        self.nonce = Some(nonce);
        self
    }

    /// Set access token hash
    pub fn with_at_hash(mut self, at_hash: String) -> Self {
        self.at_hash = Some(at_hash);
        self
    }

    /// Add additional claim
    pub fn with_claim(mut self, key: String, value: serde_json::Value) -> Self {
        self.additional_claims.insert(key, value);
        self
    }
}

/// Generate ID token from claims using manual JWT construction
/// This is a simplified implementation - in production you'd want full JWT signing
pub fn generate_id_token(
    claims: &IdTokenClaims,
    _signing_key: &atproto_identity::key::KeyData,
) -> Result<String, OAuthError> {
    // For now, create a simple unsigned JWT for testing purposes
    // In production, this would use proper ES256 signing with the provided key

    let header = serde_json::json!({
        "alg": "ES256",
        "typ": "JWT"
    });

    let header_encoded = base64::prelude::BASE64_URL_SAFE_NO_PAD.encode(
        serde_json::to_string(&header)
            .map_err(|e| OAuthError::InvalidRequest(format!("Failed to encode header: {}", e)))?,
    );

    let payload_encoded = base64::prelude::BASE64_URL_SAFE_NO_PAD.encode(
        serde_json::to_string(claims)
            .map_err(|e| OAuthError::InvalidRequest(format!("Failed to encode claims: {}", e)))?,
    );

    // TODO: Implement proper ES256 signature using the signing key
    let signature = "PLACEHOLDER_SIGNATURE";

    Ok(format!(
        "{}.{}.{}",
        header_encoded, payload_encoded, signature
    ))
}

/// Generate ID token from unified OpenID claims
pub fn generate_id_token_from_claims(
    claims: &OpenIDClaims,
    _signing_key: &atproto_identity::key::KeyData,
) -> Result<String, OAuthError> {
    // For now, create a simple unsigned JWT for testing purposes
    // In production, this would use proper ES256 signing with the provided key

    let header = serde_json::json!({
        "alg": "ES256",
        "typ": "JWT"
    });

    let header_encoded = base64::prelude::BASE64_URL_SAFE_NO_PAD.encode(
        serde_json::to_string(&header)
            .map_err(|e| OAuthError::InvalidRequest(format!("Failed to encode header: {}", e)))?,
    );

    let payload_encoded = base64::prelude::BASE64_URL_SAFE_NO_PAD.encode(
        serde_json::to_string(claims)
            .map_err(|e| OAuthError::InvalidRequest(format!("Failed to encode claims: {}", e)))?,
    );

    // TODO: Implement proper ES256 signature using the signing key
    let signature = "PLACEHOLDER_SIGNATURE";

    Ok(format!(
        "{}.{}.{}",
        header_encoded, payload_encoded, signature
    ))
}

/// Calculate access token hash for at_hash claim (ES256)
pub fn calculate_at_hash(access_token: &str) -> String {
    calculate_hash(access_token)
}

/// Calculate hash for at_hash or c_hash claims (ES256)
/// Uses the same implementation as atproto_oauth::pkce::challenge
pub fn calculate_hash(input: &str) -> String {
    // This matches the implementation from atproto_oauth::pkce::challenge
    atproto_oauth::pkce::challenge(input)
}

#[cfg(test)]
mod tests {
    use super::*;
    // Tests will use the existing atproto-oauth validation functionality

    #[test]
    fn test_id_token_claims_creation() {
        let claims = IdTokenClaims::new(
            "https://example.com".to_string(),
            "user123".to_string(),
            "client456".to_string(),
            3600,
        );

        assert_eq!(claims.iss, "https://example.com");
        assert_eq!(claims.sub, "user123");
        assert_eq!(claims.aud, "client456");
        assert!(claims.exp > claims.iat);
        assert!(claims.auth_time.is_none());
        assert!(claims.nonce.is_none());
        assert!(claims.at_hash.is_none());
    }

    #[test]
    fn test_id_token_claims_with_optional_fields() {
        let auth_time = Utc::now();
        let claims = IdTokenClaims::new(
            "https://example.com".to_string(),
            "user123".to_string(),
            "client456".to_string(),
            3600,
        )
        .with_auth_time(auth_time)
        .with_nonce("test-nonce".to_string())
        .with_at_hash("test-hash".to_string())
        .with_claim(
            "email".to_string(),
            serde_json::Value::String("user@example.com".to_string()),
        );

        assert_eq!(claims.auth_time, Some(auth_time.timestamp()));
        assert_eq!(claims.nonce, Some("test-nonce".to_string()));
        assert_eq!(claims.at_hash, Some("test-hash".to_string()));
        assert_eq!(
            claims.additional_claims.get("email"),
            Some(&serde_json::Value::String("user@example.com".to_string()))
        );
    }

    #[test]
    fn test_at_hash_calculation() {
        let access_token = "test-access-token";
        let hash = calculate_at_hash(access_token);

        // Should produce a base64url-encoded string
        assert!(!hash.is_empty());
        assert!(!hash.contains('='));
        assert!(!hash.contains('+'));
        assert!(!hash.contains('/'));
    }

    #[test]
    fn test_at_hash_consistency() {
        let access_token = "test-access-token";
        let hash1 = calculate_at_hash(access_token);
        let hash2 = calculate_at_hash(access_token);

        // Same input should produce same hash
        assert_eq!(hash1, hash2);
    }

    #[test]
    fn test_openid_claims_with_name_and_profile() {
        let claims = OpenIDClaims::new_userinfo("did:plc:test123".to_string())
            .with_name(Some("alice.bsky.social".to_string()));

        assert_eq!(claims.sub, "did:plc:test123");
        assert_eq!(claims.name, Some("alice.bsky.social".to_string()));
        assert_eq!(
            claims.profile,
            Some("https://bsky.app/profile/alice.bsky.social".to_string())
        );
    }

    #[test]
    fn test_openid_claims_with_unknown_name() {
        let claims = OpenIDClaims::new_userinfo("did:plc:test123".to_string()).with_name(None);

        assert_eq!(claims.sub, "did:plc:test123");
        assert_eq!(claims.name, Some("unknown".to_string()));
        // Profile should not be set for "unknown" handle
        assert_eq!(claims.profile, None);
    }
}
