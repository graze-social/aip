//! DPoP (Demonstration of Proof-of-Possession) implementation (RFC 9449).
//!
//! Validates DPoP proofs for OAuth access tokens using atproto-oauth validation.

use crate::errors::DPoPError;
use crate::storage::traits::NonceStorage;
use atproto_identity::key::{KeyData, KeyType};
use atproto_oauth::{
    dpop::{DpopValidationConfig, validate_dpop_jwt},
    jwk::{WrappedJsonWebKey, to_key_data as jwk_to_key_data_impl},
    jwt,
};
use base64::prelude::*;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use time::{Duration, OffsetDateTime};

/// DPoP JWT Header
#[derive(Clone, Serialize, Deserialize)]
pub struct DPoPHeader {
    /// Token type (must be "dpop+jwt")
    pub typ: String,
    /// Algorithm (ES256 for p256, ES256K for k256)
    pub alg: String,
    /// JSON Web Key
    pub jwk: WrappedJsonWebKey,
}

/// DPoP JWT Claims
#[derive(Clone, Serialize, Deserialize)]
pub struct DPoPClaims {
    /// Unique JWT identifier
    pub jti: String,
    /// HTTP method
    pub htm: String,
    /// HTTP URI
    pub htu: String,
    /// Issued at timestamp
    pub iat: i64,
    /// Access token hash (SHA-256, base64url-encoded)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ath: Option<String>,
    /// Server-provided nonce
    #[serde(skip_serializing_if = "Option::is_none")]
    pub nonce: Option<String>,
}

/// DPoP Proof
#[derive(Clone)]
pub struct DPoPProof {
    /// JWT header
    pub header: DPoPHeader,
    /// JWT claims
    pub claims: DPoPClaims,
    /// Raw JWT token
    pub token: String,

    pub thumbprint: String,
}

/// Conversion utilities between DPoP types and standardized JWT types
impl DPoPClaims {
    /// Convert DPoP claims to standardized JWT claims
    pub fn to_jose_claims(&self) -> jwt::JoseClaims {
        jwt::JoseClaims {
            json_web_token_id: Some(self.jti.clone()),
            http_method: Some(self.htm.clone()),
            http_uri: Some(self.htu.clone()),
            issued_at: Some(self.iat as u64),
            auth: self.ath.clone(),
            nonce: self.nonce.clone(),
            ..Default::default()
        }
    }

    /// Create DPoP claims from standardized JWT claims
    pub fn from_jose_claims(jose: &jwt::JoseClaims) -> Result<Self, DPoPError> {
        Ok(Self {
            jti: jose.json_web_token_id.clone().unwrap_or_default(),
            htm: jose.http_method.clone().unwrap_or_default(),
            htu: jose.http_uri.clone().unwrap_or_default(),
            iat: jose.issued_at.unwrap_or(0) as i64,
            ath: jose.auth.clone(),
            nonce: jose.nonce.clone(),
        })
    }
}

impl DPoPHeader {
    /// Get algorithm from header using standardized algorithm detection
    pub fn detect_algorithm_from_key(&self, key_data: &KeyData) -> Result<String, DPoPError> {
        let header: Result<jwt::Header, _> = key_data.clone().try_into();
        match header {
            Ok(jwt_header) => Ok(jwt_header
                .algorithm
                .clone()
                .unwrap_or_else(|| "ES256".to_string())),
            Err(_) => {
                // Fallback to manual detection based on key type
                match *key_data.key_type() {
                    KeyType::P256Public | KeyType::P256Private => Ok("ES256".to_string()),
                    KeyType::K256Public | KeyType::K256Private => Ok("ES256K".to_string()),
                    _ => Err(DPoPError::InvalidProof(format!(
                        "Unsupported key type: {}",
                        key_data.key_type()
                    ))),
                }
            }
        }
    }
}

/// DPoP Validator using standardized atproto-oauth validation
pub struct DPoPValidator {
    /// Maximum age of DPoP proof in seconds
    max_age: Duration,
    /// Clock skew tolerance in seconds
    clock_skew_tolerance: Duration,
    /// Nonce storage for replay protection
    nonce_store: Box<dyn NonceStorage + Send + Sync>,
}

impl DPoPValidator {
    /// Create a new DPoP validator
    pub fn new(nonce_store: Box<dyn NonceStorage + Send + Sync>) -> Self {
        Self {
            max_age: Duration::minutes(5),               // 5 minute max age
            clock_skew_tolerance: Duration::seconds(30), // 30 second clock skew tolerance
            nonce_store,
        }
    }

    /// Create a new DPoP validator with custom timing settings
    pub fn new_with_timing(
        nonce_store: Box<dyn NonceStorage + Send + Sync>,
        max_age: Duration,
        clock_skew_tolerance: Duration,
    ) -> Self {
        Self {
            max_age,
            clock_skew_tolerance,
            nonce_store,
        }
    }

    /// Parse and validate a DPoP proof JWT using standardized validation
    pub async fn validate_proof(
        &self,
        dpop_header: &str,
        http_method: &str,
        http_uri: &str,
        access_token: Option<&str>,
    ) -> Result<DPoPProof, DPoPError> {
        // Create validation configuration
        let config = DpopValidationConfig {
            expected_http_method: Some(http_method.to_string()),
            expected_http_uri: Some(http_uri.to_string()),
            expected_access_token_hash: access_token.map(|t| t.to_string()),
            max_age_seconds: self.max_age.whole_seconds() as u64,
            allow_future_iat: false,
            clock_skew_tolerance_seconds: self.clock_skew_tolerance.whole_seconds() as u64,
            now: chrono::Utc::now().timestamp(),
            expected_nonce_values: Vec::new(),
        };

        // Use standardized DPoP validation
        let jwk_thumbprint = validate_dpop_jwt(dpop_header, &config)
            .map_err(|e| DPoPError::InvalidProof(format!("DPoP validation failed: {}", e)))?;

        // Extract JWK from header for additional processing
        let jwk = self.extract_jwk_from_header(dpop_header)?;

        // Parse claims for nonce checking and return structure
        let claims = self.parse_claims_from_jwt(dpop_header)?;

        // Validate access token hash if required
        if let Some(token) = access_token {
            if let Some(ath) = &claims.ath {
                let expected_hash = self.compute_access_token_hash(token);
                if ath != &expected_hash {
                    return Err(DPoPError::InvalidProof(
                        "Access token hash mismatch".to_string(),
                    ));
                }
            } else {
                return Err(DPoPError::InvalidProof(
                    "Missing access token hash (ath) claim".to_string(),
                ));
            }
        }

        // Check for replay attacks using nonce store
        let expiry = OffsetDateTime::now_utc() + self.max_age;
        if !self
            .nonce_store
            .check_and_use_nonce(&claims.jti, expiry)
            .await?
        {
            return Err(DPoPError::ReplayAttack("JTI already used".to_string()));
        }

        // Create DPoP header struct
        let dpop_header_struct = DPoPHeader {
            typ: "dpop+jwt".to_string(),
            alg: self.detect_algorithm_from_jwk(&jwk)?,
            jwk,
        };

        Ok(DPoPProof {
            header: dpop_header_struct,
            claims,
            token: dpop_header.to_string(),
            thumbprint: jwk_thumbprint,
        })
    }

    /// Detect algorithm from JWK
    fn detect_algorithm_from_jwk(&self, jwk: &WrappedJsonWebKey) -> Result<String, DPoPError> {
        // Convert JWK to KeyData to determine algorithm
        let key_data = self.jwk_to_key_data(jwk)?;

        match *key_data.key_type() {
            KeyType::P256Public | KeyType::P256Private => Ok("ES256".to_string()),
            KeyType::P384Public | KeyType::P384Private => Ok("ES384".to_string()),
            KeyType::K256Public | KeyType::K256Private => Ok("ES256K".to_string()),
        }
    }

    /// Extract JWK from JWT header
    fn extract_jwk_from_header(&self, jwt: &str) -> Result<WrappedJsonWebKey, DPoPError> {
        // This is a simplified implementation
        // In a production system, you'd want to parse the JWT header properly
        let parts: Vec<&str> = jwt.split('.').collect();
        if parts.len() != 3 {
            return Err(DPoPError::InvalidProof("Invalid JWT format".to_string()));
        }

        let header_json = BASE64_URL_SAFE_NO_PAD
            .decode(parts[0])
            .map_err(|e| DPoPError::InvalidProof(format!("Failed to decode header: {}", e)))?;

        let header_value: serde_json::Value = serde_json::from_slice(&header_json)
            .map_err(|e| DPoPError::InvalidProof(format!("Failed to parse header JSON: {}", e)))?;

        let jwk = header_value
            .get("jwk")
            .ok_or_else(|| DPoPError::InvalidProof("Missing jwk in header".to_string()))?;

        serde_json::from_value(jwk.clone())
            .map_err(|e| DPoPError::InvalidProof(format!("Invalid JWK format: {}", e)))
    }

    /// Parse DPoP claims from JWT token
    fn parse_claims_from_jwt(&self, jwt: &str) -> Result<DPoPClaims, DPoPError> {
        let parts: Vec<&str> = jwt.split('.').collect();
        if parts.len() != 3 {
            return Err(DPoPError::InvalidProof("Invalid JWT format".to_string()));
        }

        let payload_json = BASE64_URL_SAFE_NO_PAD
            .decode(parts[1])
            .map_err(|e| DPoPError::InvalidProof(format!("Failed to decode payload: {}", e)))?;

        let payload_value: serde_json::Value = serde_json::from_slice(&payload_json)
            .map_err(|e| DPoPError::InvalidProof(format!("Failed to parse payload JSON: {}", e)))?;

        Ok(DPoPClaims {
            jti: payload_value
                .get("jti")
                .and_then(|v| v.as_str())
                .unwrap_or_default()
                .to_string(),
            htm: payload_value
                .get("htm")
                .and_then(|v| v.as_str())
                .unwrap_or_default()
                .to_string(),
            htu: payload_value
                .get("htu")
                .and_then(|v| v.as_str())
                .unwrap_or_default()
                .to_string(),
            iat: payload_value
                .get("iat")
                .and_then(|v| v.as_i64())
                .unwrap_or(0),
            ath: payload_value
                .get("ath")
                .and_then(|v| v.as_str())
                .map(|s| s.to_string()),
            nonce: payload_value
                .get("nonce")
                .and_then(|v| v.as_str())
                .map(|s| s.to_string()),
        })
    }

    /// Convert JWK to KeyData using the atproto_oauth::jwk::to_key_data function
    fn jwk_to_key_data(&self, jwk: &WrappedJsonWebKey) -> Result<KeyData, DPoPError> {
        // Use the standardized conversion function from atproto_oauth
        jwk_to_key_data_impl(jwk).map_err(|e| {
            DPoPError::InvalidProof(format!("Failed to convert JWK to KeyData: {}", e))
        })
    }

    /// Compute SHA-256 hash of access token
    fn compute_access_token_hash(&self, access_token: &str) -> String {
        let mut hasher = Sha256::new();
        hasher.update(access_token.as_bytes());
        let hash = hasher.finalize();
        BASE64_URL_SAFE_NO_PAD.encode(hash)
    }
}

/// Compute JWK thumbprint using the standardized atproto-oauth implementation
pub fn compute_jwk_thumbprint(jwk: &WrappedJsonWebKey) -> Result<String, DPoPError> {
    atproto_oauth::jwk::thumbprint(jwk).map_err(|err| DPoPError::Thumbprint(err.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::storage::MemoryNonceStorage;

    #[tokio::test]
    async fn test_nonce_store() {
        let store = MemoryNonceStorage::new();
        let nonce = "test-nonce";
        let expiry = OffsetDateTime::now_utc() + Duration::minutes(5);

        // First use should succeed
        assert!(store.check_and_use_nonce(nonce, expiry).await.unwrap());

        // Second use should fail (replay attack)
        assert!(!store.check_and_use_nonce(nonce, expiry).await.unwrap());
    }

    #[test]
    fn test_jwk_thumbprint_computation() {
        use atproto_identity::key::{KeyType, generate_key, to_public};
        use atproto_oauth::jwk::generate as generate_jwk;

        // Generate a real P-256 key and convert to JWK
        let private_key_data = generate_key(KeyType::P256Private).unwrap();
        let public_key_data = to_public(&private_key_data).unwrap();
        let public_jwk = generate_jwk(&public_key_data).unwrap();

        // Test thumbprint computation with standardized function
        let thumbprint = compute_jwk_thumbprint(&public_jwk).unwrap();
        assert!(!thumbprint.is_empty());
        assert_eq!(thumbprint.len(), 43); // Standard SHA-256 base64url length
    }

    #[test]
    fn test_dpop_validator_initialization() {
        let store = Box::new(MemoryNonceStorage::new());
        let validator = DPoPValidator::new(store);

        // Verify validator is initialized with correct defaults
        assert_eq!(validator.max_age.whole_seconds(), 300); // 5 minutes
        assert_eq!(validator.clock_skew_tolerance.whole_seconds(), 30); // 30 seconds
    }

    #[tokio::test]
    async fn test_dpop_validation_with_standardized_implementation() {
        use atproto_identity::key::{KeyType, generate_key};
        use atproto_oauth::dpop::auth_dpop;

        let store = Box::new(MemoryNonceStorage::new());
        let validator = DPoPValidator::new(store);

        // Generate a valid key and create a proper DPoP token
        let key_data = generate_key(KeyType::P256Private).unwrap();
        let (dpop_token, _, _) = auth_dpop(&key_data, "POST", "/oauth/token").unwrap();

        // The validation should succeed with valid DPoP proof
        let result = validator
            .validate_proof(&dpop_token, "POST", "/oauth/token", None)
            .await;
        assert!(result.is_ok());
    }

    #[test]
    fn test_jwk_to_keydata_conversion() {
        use atproto_identity::key::{KeyType, generate_key, to_public};
        use atproto_oauth::jwk::generate as generate_jwk;

        let store = Box::new(MemoryNonceStorage::new());
        let validator = DPoPValidator::new(store);

        // Test P-256 JWK to KeyData conversion
        let p256_private = generate_key(KeyType::P256Private).unwrap();
        let p256_public = to_public(&p256_private).unwrap();
        let p256_jwk = generate_jwk(&p256_public).unwrap();

        let result = validator.jwk_to_key_data(&p256_jwk);
        assert!(result.is_ok());
        let key_data = result.unwrap();
        assert_eq!(
            *key_data.key_type(),
            atproto_identity::key::KeyType::P256Public
        );

        // Test secp256k1 JWK to KeyData conversion
        let k256_private = generate_key(KeyType::K256Private).unwrap();
        let k256_public = to_public(&k256_private).unwrap();
        let k256_jwk = generate_jwk(&k256_public).unwrap();

        let result = validator.jwk_to_key_data(&k256_jwk);
        assert!(result.is_ok());
        let key_data = result.unwrap();
        assert_eq!(
            *key_data.key_type(),
            atproto_identity::key::KeyType::K256Public
        );
    }

    #[tokio::test]
    async fn test_dpop_with_standardized_validation() {
        use atproto_identity::key::{KeyType, generate_key};
        use atproto_oauth::dpop::auth_dpop;

        let store = Box::new(MemoryNonceStorage::new());
        let validator = DPoPValidator::new(store);

        // Generate a P-256 key pair for testing
        let private_key = generate_key(KeyType::P256Private).unwrap();

        // Create a proper DPoP token using standardized implementation
        let (dpop_token, _, _) = auth_dpop(&private_key, "POST", "/oauth/token").unwrap();

        // Test full DPoP validation workflow
        let result = validator
            .validate_proof(&dpop_token, "POST", "/oauth/token", None)
            .await;
        assert!(result.is_ok());

        let dpop_proof = result.unwrap();
        assert_eq!(dpop_proof.claims.htm, "POST");
        assert_eq!(dpop_proof.claims.htu, "/oauth/token");
        assert!(!dpop_proof.claims.jti.is_empty());
    }

    #[tokio::test]
    async fn test_dpop_nonce_replay_protection() {
        use atproto_identity::key::{KeyType, generate_key};
        use atproto_oauth::dpop::auth_dpop;

        let store = Box::new(MemoryNonceStorage::new());
        let validator = DPoPValidator::new(store);

        // Generate a key and create a DPoP token
        let key_data = generate_key(KeyType::P256Private).unwrap();
        let (dpop_token, _, _) = auth_dpop(&key_data, "POST", "/oauth/token").unwrap();

        // First validation should succeed
        let result1 = validator
            .validate_proof(&dpop_token, "POST", "/oauth/token", None)
            .await;
        assert!(result1.is_ok());

        // Second validation with same token should fail due to nonce replay protection
        let result2 = validator
            .validate_proof(&dpop_token, "POST", "/oauth/token", None)
            .await;
        assert!(result2.is_err());
    }

    #[test]
    fn test_algorithm_detection_integration() {
        use atproto_identity::key::{KeyType, generate_key, to_public};
        use atproto_oauth::jwk::generate as generate_jwk;

        let store = Box::new(MemoryNonceStorage::new());
        let validator = DPoPValidator::new(store);

        // Test that JWK conversion and algorithm detection works correctly
        let test_private = generate_key(KeyType::P256Private).unwrap();
        let test_public = to_public(&test_private).unwrap();
        let test_jwk = generate_jwk(&test_public).unwrap();

        let result = validator.jwk_to_key_data(&test_jwk);
        assert!(result.is_ok());
        let converted_key = result.unwrap();
        assert_eq!(*converted_key.key_type(), KeyType::P256Public);

        // Test algorithm detection
        let alg = validator.detect_algorithm_from_jwk(&test_jwk);
        assert!(alg.is_ok());
        assert_eq!(alg.unwrap(), "ES256");
    }
}
