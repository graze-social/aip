//! OpenID Connect support for ID token generation and validation.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

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
pub(crate) struct IdTokenClaims {
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

/// Calculate hash for at_hash or c_hash claims (ES256)
/// Uses the same implementation as atproto_oauth::pkce::challenge
fn calculate_hash(input: &str) -> String {
    // This matches the implementation from atproto_oauth::pkce::challenge
    atproto_oauth::pkce::challenge(input)
}

#[cfg(test)]
mod tests {
    use super::*;

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
