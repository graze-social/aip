//! Environment-based configuration types for AIP server runtime settings.

use anyhow::Result;
use atproto_identity::key::{KeyData, KeyType, generate_key, identify_key};
use std::time::Duration;

use crate::errors::ConfigError;

/// HTTP server port configuration
#[derive(Clone)]
pub struct HttpPort(u16);

/// Certificate bundles for HTTPS connections
#[derive(Clone)]
pub struct CertificateBundles(Vec<String>);

/// DNS nameservers for ATProtocol handle resolution
#[derive(Clone)]
pub struct DnsNameservers(Vec<std::net::IpAddr>);

/// HTTP client timeout configuration
#[derive(Clone)]
pub struct HttpClientTimeout(Duration);

/// ATProtocol OAuth signing keys configuration
#[derive(Clone, Default)]
pub struct PrivateKeys(Vec<KeyData>);

/// OAuth supported scopes configuration
#[derive(Clone)]
pub struct OAuthSupportedScopes(Vec<String>);

/// Client default access token expiration configuration
#[derive(Clone)]
pub struct ClientDefaultAccessTokenExpiration(chrono::Duration);

/// Client default refresh token expiration configuration
#[derive(Clone)]
pub struct ClientDefaultRefreshTokenExpiration(chrono::Duration);

/// Admin DIDs configuration
#[derive(Clone)]
pub struct AdminDids(Vec<String>);

/// Client default redirect exact matching configuration
#[derive(Clone)]
pub struct ClientDefaultRedirectExact(bool);

/// ATProtocol client name configuration
#[derive(Clone)]
pub struct AtprotoClientName(String);

/// ATProtocol client logo configuration
#[derive(Clone)]
pub struct AtprotoClientLogo(Option<String>);

/// ATProtocol client terms of service configuration
#[derive(Clone)]
pub struct AtprotoClientTos(Option<String>);

/// ATProtocol client policy configuration
#[derive(Clone)]
pub struct AtprotoClientPolicy(Option<String>);

/// Main application configuration
#[derive(Clone)]
pub struct Config {
    pub version: String,
    pub http_port: HttpPort,
    pub http_static_path: String,
    pub http_templates_path: String,
    pub external_base: String,
    pub certificate_bundles: CertificateBundles,
    pub user_agent: String,
    pub plc_hostname: String,
    pub dns_nameservers: DnsNameservers,
    pub http_client_timeout: HttpClientTimeout,
    pub atproto_oauth_signing_keys: PrivateKeys,
    pub oauth_signing_keys: PrivateKeys,
    pub oauth_supported_scopes: OAuthSupportedScopes,
    pub dpop_nonce_seed: String,
    pub storage_backend: String,
    pub database_url: Option<String>,
    pub redis_url: Option<String>,
    pub enable_client_api: bool,
    pub client_default_access_token_expiration: ClientDefaultAccessTokenExpiration,
    pub client_default_refresh_token_expiration: ClientDefaultRefreshTokenExpiration,
    pub admin_dids: AdminDids,
    pub client_default_redirect_exact: ClientDefaultRedirectExact,
    pub atproto_client_name: AtprotoClientName,
    pub atproto_client_logo: AtprotoClientLogo,
    pub atproto_client_tos: AtprotoClientTos,
    pub atproto_client_policy: AtprotoClientPolicy,
}

impl Config {
    /// Create a new configuration from environment variables
    pub fn new() -> Result<Self> {
        let atproto_oauth_signing_keys: PrivateKeys =
            optional_env("ATPROTO_OAUTH_SIGNING_KEYS").try_into()?;
        let certificate_bundles: CertificateBundles =
            optional_env("CERTIFICATE_BUNDLES").try_into()?;
        let default_user_agent =
            format!("aip/{} (+https://github.com/graze-social/aip)", version()?);
        let dns_nameservers: DnsNameservers = optional_env("DNS_NAMESERVERS").try_into()?;
        let dpop_nonce_seed = require_env("DPOP_NONCE_SEED")?;
        let external_base = require_env("EXTERNAL_BASE")?;
        let http_client_timeout: HttpClientTimeout =
            default_env("HTTP_CLIENT_TIMEOUT", "10s").try_into()?;
        let http_port: HttpPort = default_env("HTTP_PORT", "8080").try_into()?;
        let http_static_path = optional_env("HTTP_STATIC_PATH")
            .unwrap_or_else(|| format!("{}/static", env!("CARGO_MANIFEST_DIR")));
        let http_templates_path = optional_env("HTTP_TEMPLATES_PATH")
            .unwrap_or_else(|| format!("{}/templates", env!("CARGO_MANIFEST_DIR")));
        let oauth_signing_keys: PrivateKeys = optional_env("OAUTH_SIGNING_KEYS").try_into()?;
        let oauth_supported_scopes: OAuthSupportedScopes = default_env(
            "OAUTH_SUPPORTED_SCOPES",
            "openid profile email atproto:atproto atproto:transition:generic atproto:transition:email",
        )
        .try_into()?;
        let plc_hostname = default_env("PLC_HOSTNAME", "plc.directory");
        let storage_backend = default_env("STORAGE_BACKEND", "memory");
        let database_url = optional_env("DATABASE_URL");
        let redis_url = optional_env("REDIS_URL");
        let user_agent = default_env("USER_AGENT", &default_user_agent);
        let enable_client_api = optional_env("ENABLE_CLIENT_API")
            .map(|v| v == "true")
            .unwrap_or(false);
        let client_default_access_token_expiration: ClientDefaultAccessTokenExpiration =
            default_env("CLIENT_DEFAULT_ACCESS_TOKEN_EXPIRATION", "1d").try_into()?;
        let client_default_refresh_token_expiration: ClientDefaultRefreshTokenExpiration =
            default_env("CLIENT_DEFAULT_REFRESH_TOKEN_EXPIRATION", "14d").try_into()?;
        let admin_dids: AdminDids = optional_env("ADMIN_DIDS").try_into()?;
        let client_default_redirect_exact: ClientDefaultRedirectExact =
            default_env("CLIENT_DEFAULT_REDIRECT_EXACT", "true").try_into()?;
        let atproto_client_name: AtprotoClientName =
            default_env("ATPROTO_CLIENT_NAME", "AIP OAuth Server").try_into()?;
        let atproto_client_logo: AtprotoClientLogo =
            optional_env("ATPROTO_CLIENT_LOGO").try_into()?;
        let atproto_client_tos: AtprotoClientTos = optional_env("ATPROTO_CLIENT_TOS").try_into()?;
        let atproto_client_policy: AtprotoClientPolicy =
            optional_env("ATPROTO_CLIENT_POLICY").try_into()?;

        Ok(Self {
            version: version()?,
            http_port,
            http_static_path,
            http_templates_path,
            external_base,
            certificate_bundles,
            user_agent,
            plc_hostname,
            dns_nameservers,
            http_client_timeout,
            atproto_oauth_signing_keys,
            oauth_signing_keys,
            oauth_supported_scopes,
            dpop_nonce_seed,
            storage_backend,
            database_url,
            redis_url,
            enable_client_api,
            client_default_access_token_expiration,
            client_default_refresh_token_expiration,
            admin_dids,
            client_default_redirect_exact,
            atproto_client_name,
            atproto_client_logo,
            atproto_client_tos,
            atproto_client_policy,
        })
    }
}

/// Get application version from build environment
pub fn version() -> Result<String> {
    option_env!("GIT_HASH")
        .or(option_env!("CARGO_PKG_VERSION"))
        .map(|val| val.to_string())
        .ok_or(ConfigError::VersionNotSet.into())
}

fn require_env(name: &str) -> Result<String> {
    std::env::var(name).map_err(|_| ConfigError::EnvVarRequired(name.to_string()).into())
}

pub(crate) fn optional_env(name: &str) -> Option<String> {
    std::env::var(name).ok()
}

fn default_env(name: &str, default_value: &str) -> String {
    std::env::var(name).unwrap_or_else(|_| default_value.to_string())
}

impl TryFrom<String> for HttpPort {
    type Error = anyhow::Error;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        if value.is_empty() {
            Ok(Self(8080))
        } else {
            value
                .parse::<u16>()
                .map(Self)
                .map_err(|err| ConfigError::PortParsingFailed(err).into())
        }
    }
}

impl AsRef<u16> for HttpPort {
    fn as_ref(&self) -> &u16 {
        &self.0
    }
}

impl TryFrom<Option<String>> for CertificateBundles {
    type Error = anyhow::Error;

    fn try_from(value: Option<String>) -> Result<Self, Self::Error> {
        let value = value.unwrap_or_default();
        Ok(Self(
            value
                .split(';')
                .filter_map(|s| {
                    if s.is_empty() {
                        None
                    } else {
                        Some(s.to_string())
                    }
                })
                .collect::<Vec<String>>(),
        ))
    }
}

impl TryFrom<String> for CertificateBundles {
    type Error = anyhow::Error;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        Self::try_from(Some(value))
    }
}

impl AsRef<Vec<String>> for CertificateBundles {
    fn as_ref(&self) -> &Vec<String> {
        &self.0
    }
}

impl TryFrom<Option<String>> for DnsNameservers {
    type Error = anyhow::Error;

    fn try_from(value: Option<String>) -> Result<Self, Self::Error> {
        let value = match value {
            None => return Ok(Self(Vec::new())),
            Some(v) if v.is_empty() => return Ok(Self(Vec::new())),
            Some(v) => v,
        };

        let nameservers = value
            .split(',')
            .map(|s| s.trim())
            .filter(|s| !s.is_empty())
            .map(|s| {
                s.parse::<std::net::IpAddr>()
                    .map_err(|e| ConfigError::NameserverParsingFailed(s.to_string(), e))
            })
            .collect::<Result<Vec<std::net::IpAddr>, ConfigError>>()?;

        Ok(Self(nameservers))
    }
}

impl TryFrom<String> for DnsNameservers {
    type Error = anyhow::Error;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        Self::try_from(Some(value))
    }
}

impl AsRef<Vec<std::net::IpAddr>> for DnsNameservers {
    fn as_ref(&self) -> &Vec<std::net::IpAddr> {
        &self.0
    }
}

impl TryFrom<String> for HttpClientTimeout {
    type Error = ConfigError;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        if value.is_empty() {
            return Ok(Self(Duration::from_secs(10)));
        }

        // Parse duration strings like "10s", "5m", etc.
        if value.ends_with('s') {
            let seconds = value
                .trim_end_matches('s')
                .parse::<u64>()
                .map_err(ConfigError::TimeoutParsingFailed)?;
            Ok(Self(Duration::from_secs(seconds)))
        } else if value.ends_with('m') {
            let minutes = value
                .trim_end_matches('m')
                .parse::<u64>()
                .map_err(ConfigError::TimeoutParsingFailed)?;
            Ok(Self(Duration::from_secs(minutes * 60)))
        } else {
            // Default to seconds if no suffix
            let seconds = value
                .parse::<u64>()
                .map_err(ConfigError::TimeoutParsingFailed)?;
            Ok(Self(Duration::from_secs(seconds)))
        }
    }
}

impl AsRef<Duration> for HttpClientTimeout {
    fn as_ref(&self) -> &Duration {
        &self.0
    }
}

impl TryFrom<Option<String>> for PrivateKeys {
    type Error = anyhow::Error;

    fn try_from(value: Option<String>) -> Result<Self, Self::Error> {
        match value {
            None => {
                // Generate a new P-256 private key if no keys are provided
                let key = generate_key(KeyType::P256Private)?;
                Ok(Self(vec![key]))
            }
            Some(value) if value.is_empty() => {
                // Generate a new P-256 private key if no keys are provided
                let key = generate_key(KeyType::P256Private)?;
                Ok(Self(vec![key]))
            }
            Some(value) => {
                // Parse semicolon-separated list of KeyData DID strings
                let mut keys = Vec::new();
                for key_str in value.split(';').filter(|s| !s.trim().is_empty()) {
                    let key = identify_key(key_str.trim())?;
                    keys.push(key);
                }

                if keys.is_empty() {
                    // Generate a new P-256 private key if parsing resulted in empty list
                    let key = generate_key(KeyType::P256Private)?;
                    Ok(Self(vec![key]))
                } else {
                    Ok(Self(keys))
                }
            }
        }
    }
}

impl AsRef<Vec<KeyData>> for PrivateKeys {
    fn as_ref(&self) -> &Vec<KeyData> {
        &self.0
    }
}

impl TryFrom<Option<String>> for OAuthSupportedScopes {
    type Error = anyhow::Error;

    fn try_from(value: Option<String>) -> Result<Self, Self::Error> {
        let value = value.unwrap_or_default();
        if value.is_empty() {
            return Ok(Self(vec![
                "atproto:atproto".to_string(),
                "atproto:transition:generic".to_string(),
                "atproto:transition:email".to_string(),
            ]));
        }

        let scopes = value
            .split_whitespace()
            .map(|s| s.to_string())
            .collect::<Vec<String>>();

        Ok(Self(scopes))
    }
}

impl TryFrom<String> for OAuthSupportedScopes {
    type Error = anyhow::Error;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        Self::try_from(Some(value))
    }
}

impl AsRef<Vec<String>> for OAuthSupportedScopes {
    fn as_ref(&self) -> &Vec<String> {
        &self.0
    }
}

impl TryFrom<String> for ClientDefaultAccessTokenExpiration {
    type Error = anyhow::Error;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        let duration = duration_str::parse(&value)
            .map_err(|e| ConfigError::DurationParsingFailed(value, e.to_string()))?;
        Ok(Self(chrono::Duration::from_std(duration)?))
    }
}

impl AsRef<chrono::Duration> for ClientDefaultAccessTokenExpiration {
    fn as_ref(&self) -> &chrono::Duration {
        &self.0
    }
}

impl TryFrom<String> for ClientDefaultRefreshTokenExpiration {
    type Error = anyhow::Error;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        let duration = duration_str::parse(&value)
            .map_err(|e| ConfigError::DurationParsingFailed(value, e.to_string()))?;
        Ok(Self(chrono::Duration::from_std(duration)?))
    }
}

impl AsRef<chrono::Duration> for ClientDefaultRefreshTokenExpiration {
    fn as_ref(&self) -> &chrono::Duration {
        &self.0
    }
}

impl TryFrom<Option<String>> for AdminDids {
    type Error = anyhow::Error;

    fn try_from(value: Option<String>) -> Result<Self, Self::Error> {
        let value = value.unwrap_or_default();
        if value.is_empty() {
            return Ok(Self(Vec::new()));
        }

        let dids = value
            .split(',')
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
            .collect::<Vec<String>>();

        Ok(Self(dids))
    }
}

impl TryFrom<String> for AdminDids {
    type Error = anyhow::Error;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        Self::try_from(Some(value))
    }
}

impl AsRef<Vec<String>> for AdminDids {
    fn as_ref(&self) -> &Vec<String> {
        &self.0
    }
}

impl TryFrom<String> for ClientDefaultRedirectExact {
    type Error = anyhow::Error;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        match value.to_lowercase().as_str() {
            "true" | "1" | "yes" | "on" => Ok(Self(true)),
            "false" | "0" | "no" | "off" => Ok(Self(false)),
            _ => Err(ConfigError::BoolParsingFailed(value).into()),
        }
    }
}

impl AsRef<bool> for ClientDefaultRedirectExact {
    fn as_ref(&self) -> &bool {
        &self.0
    }
}

impl TryFrom<String> for AtprotoClientName {
    type Error = anyhow::Error;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        Ok(Self(value))
    }
}

impl AsRef<String> for AtprotoClientName {
    fn as_ref(&self) -> &String {
        &self.0
    }
}

impl TryFrom<Option<String>> for AtprotoClientLogo {
    type Error = anyhow::Error;

    fn try_from(value: Option<String>) -> Result<Self, Self::Error> {
        Ok(Self(value.filter(|s| !s.is_empty())))
    }
}

impl AsRef<Option<String>> for AtprotoClientLogo {
    fn as_ref(&self) -> &Option<String> {
        &self.0
    }
}

impl TryFrom<Option<String>> for AtprotoClientTos {
    type Error = anyhow::Error;

    fn try_from(value: Option<String>) -> Result<Self, Self::Error> {
        Ok(Self(value.filter(|s| !s.is_empty())))
    }
}

impl AsRef<Option<String>> for AtprotoClientTos {
    fn as_ref(&self) -> &Option<String> {
        &self.0
    }
}

impl TryFrom<Option<String>> for AtprotoClientPolicy {
    type Error = anyhow::Error;

    fn try_from(value: Option<String>) -> Result<Self, Self::Error> {
        Ok(Self(value.filter(|s| !s.is_empty())))
    }
}

impl AsRef<Option<String>> for AtprotoClientPolicy {
    fn as_ref(&self) -> &Option<String> {
        &self.0
    }
}
