//! Trust checks for ATProtocol OAuth.
//!
//! Everything AIP learns during an ATProtocol OAuth flow after the DID document
//! (the PDS, its protected-resource metadata, the authorization server and its
//! endpoints, and the token response) comes from servers that anyone can stand
//! up. This module holds the two kinds of check that keep that from going wrong:
//!
//! * [`verify_subject_authority`] confirms that the authorization server which
//!   issued a token is the one the token's subject (`sub`) names through its own
//!   DID document and PDS. Without it, any authorization server can claim any
//!   DID.
//! * [`validate_remote_endpoint`], [`PublicOnlyResolver`] and
//!   [`redirect_policy`] keep URLs taken from that metadata from steering AIP's
//!   outbound requests at loopback, private, or otherwise internal hosts.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

use atproto_identity::model::Document;
use atproto_identity::resolve::SharedIdentityResolver;
use atproto_oauth::resources::oauth_protected_resource;
use thiserror::Error;

/// Errors from the ATProtocol OAuth trust checks.
#[derive(Debug, Error)]
pub enum TrustError {
    /// A URL taken from untrusted metadata is not allowed as a request target.
    #[error("error-aip-trust-1 Endpoint {url} is not allowed: {reason}")]
    EndpointNotAllowed {
        /// The rejected URL.
        url: String,
        /// Why it was rejected.
        reason: &'static str,
    },

    /// The token subject is not a supported DID.
    #[error("error-aip-trust-2 Token subject {0} is not a supported DID")]
    UnsupportedSubject(String),

    /// The token subject could not be resolved.
    #[error("error-aip-trust-3 Token subject {subject} could not be resolved: {reason}")]
    SubjectNotResolvable {
        /// The token subject.
        subject: String,
        /// Why resolution failed.
        reason: String,
    },

    /// The token subject differs from the identity the flow started with.
    #[error(
        "error-aip-trust-4 Token subject {actual} does not match the expected subject {expected}"
    )]
    SubjectMismatch {
        /// The DID the flow started with.
        expected: String,
        /// The DID in the token response.
        actual: String,
    },

    /// The token subject's PDS names a different authorization server.
    #[error(
        "error-aip-trust-5 Token subject {subject} is served by authorization server {actual}, not {expected}"
    )]
    AuthorityMismatch {
        /// The token subject.
        subject: String,
        /// The authorization server that issued the token.
        expected: String,
        /// The authorization server the subject's PDS names.
        actual: String,
    },

    /// The authorization server metadata names a different issuer.
    #[error("error-aip-trust-6 Authorization server issuer {actual} does not match {expected}")]
    IssuerMismatch {
        /// The issuer recorded when the flow started.
        expected: String,
        /// The issuer presented now.
        actual: String,
    },
}

fn not_allowed(url: &str, reason: &'static str) -> TrustError {
    TrustError::EndpointNotAllowed {
        url: url.to_string(),
        reason,
    }
}

/// Checks that a URL taken from untrusted metadata may be used as a request
/// target.
///
/// The URL must be `https`, carry no credentials, and name a public host: no IP
/// literal outside public unicast space, no `localhost`, no single-label name
/// (such as a container or service name), and no `.local` or `.internal` name.
/// Names that resolve to non-public addresses are caught separately by
/// [`PublicOnlyResolver`].
pub fn validate_remote_endpoint(url: &str) -> Result<(), TrustError> {
    let parsed = url::Url::parse(url).map_err(|_| not_allowed(url, "not a valid URL"))?;

    if parsed.scheme() != "https" {
        return Err(not_allowed(url, "only https URLs are allowed"));
    }
    if !parsed.username().is_empty() || parsed.password().is_some() {
        return Err(not_allowed(url, "URLs with credentials are not allowed"));
    }

    match parsed.host() {
        None => Err(not_allowed(url, "URL has no host")),
        Some(url::Host::Ipv4(ip)) => {
            if is_public_ip(IpAddr::V4(ip)) {
                Ok(())
            } else {
                Err(not_allowed(url, "IP address is not public"))
            }
        }
        Some(url::Host::Ipv6(ip)) => {
            if is_public_ip(IpAddr::V6(ip)) {
                Ok(())
            } else {
                Err(not_allowed(url, "IP address is not public"))
            }
        }
        Some(url::Host::Domain(domain)) => {
            let domain = domain.trim_end_matches('.').to_ascii_lowercase();
            if !domain.contains('.') {
                return Err(not_allowed(url, "single-label host names are not allowed"));
            }
            let internal_suffixes = [".localhost", ".local", ".internal", ".home.arpa"];
            if domain == "localhost" || internal_suffixes.iter().any(|s| domain.ends_with(s)) {
                return Err(not_allowed(url, "internal host names are not allowed"));
            }
            Ok(())
        }
    }
}

/// Returns true when an address is public unicast space.
///
/// Rejects unspecified, loopback, private (RFC 1918 and unique-local),
/// shared (CGNAT), link-local, benchmarking, documentation, multicast and
/// reserved ranges, and checks the IPv4 address embedded in IPv4-mapped,
/// IPv4-compatible and NAT64 IPv6 addresses.
pub fn is_public_ip(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => is_public_ipv4(v4),
        IpAddr::V6(v6) => is_public_ipv6(v6),
    }
}

fn is_public_ipv4(ip: Ipv4Addr) -> bool {
    let [a, b, c, _] = ip.octets();
    !(a == 0 // "this network"
        || a == 10 // private
        || (a == 100 && (64..=127).contains(&b)) // shared address space (CGNAT)
        || a == 127 // loopback
        || (a == 169 && b == 254) // link-local
        || (a == 172 && (16..=31).contains(&b)) // private
        || (a == 192 && b == 0 && c == 0) // IETF protocol assignments
        || (a == 192 && b == 0 && c == 2) // documentation
        || (a == 192 && b == 88 && c == 99) // 6to4 relay anycast
        || (a == 192 && b == 168) // private
        || (a == 198 && (18..=19).contains(&b)) // benchmarking
        || (a == 198 && b == 51 && c == 100) // documentation
        || (a == 203 && b == 0 && c == 113) // documentation
        || a >= 224) // multicast, reserved, broadcast
}

fn is_public_ipv6(ip: Ipv6Addr) -> bool {
    if let Some(v4) = ip.to_ipv4_mapped() {
        return is_public_ipv4(v4);
    }
    let segments = ip.segments();
    // IPv4-compatible (::a.b.c.d, deprecated) and NAT64 (64:ff9b::/96).
    if segments[..6] == [0, 0, 0, 0, 0, 0] && !ip.is_unspecified() && !ip.is_loopback() {
        return is_public_ipv4(embedded_ipv4(&segments));
    }
    if segments[..6] == [0x64, 0xff9b, 0, 0, 0, 0] {
        return is_public_ipv4(embedded_ipv4(&segments));
    }
    !(ip.is_unspecified()
        || ip.is_loopback()
        || (segments[0] & 0xfe00) == 0xfc00 // unique local
        || (segments[0] & 0xffc0) == 0xfe80 // link-local
        || (segments[0] & 0xffc0) == 0xfec0 // site-local (deprecated)
        || (segments[0] & 0xff00) == 0xff00 // multicast
        || (segments[0] == 0x2001 && segments[1] == 0x0db8) // documentation
        || (segments[0] == 0x0100 && segments[1..4] == [0, 0, 0])) // discard-only
}

fn embedded_ipv4(segments: &[u16; 8]) -> Ipv4Addr {
    let [hi, lo] = [segments[6], segments[7]];
    Ipv4Addr::new((hi >> 8) as u8, hi as u8, (lo >> 8) as u8, lo as u8)
}

/// A DNS resolver for reqwest that drops every non-public address.
///
/// Used on AIP's shared HTTP client so that a host name an attacker controls
/// cannot be pointed at an internal address. Because the check happens on the
/// addresses actually connected to, it also covers DNS rebinding. IP-literal
/// URLs skip DNS entirely and are checked by [`validate_remote_endpoint`] and
/// [`redirect_policy`] instead.
#[derive(Debug, Clone, Default)]
pub struct PublicOnlyResolver;

impl reqwest::dns::Resolve for PublicOnlyResolver {
    fn resolve(&self, name: reqwest::dns::Name) -> reqwest::dns::Resolving {
        let host = name.as_str().to_string();
        Box::pin(async move {
            let addrs: Vec<SocketAddr> = tokio::net::lookup_host((host.as_str(), 0))
                .await?
                .filter(|addr| is_public_ip(addr.ip()))
                .collect();
            if addrs.is_empty() {
                return Err(format!("{host} has no public addresses").into());
            }
            Ok(Box::new(addrs.into_iter()) as reqwest::dns::Addrs)
        })
    }
}

/// A redirect policy that follows at most five redirects and re-checks every
/// hop with [`validate_remote_endpoint`].
pub fn redirect_policy() -> reqwest::redirect::Policy {
    reqwest::redirect::Policy::custom(|attempt| {
        if attempt.previous().len() >= 5 {
            return attempt.error("too many redirects");
        }
        match validate_remote_endpoint(attempt.url().as_str()) {
            Ok(()) => attempt.follow(),
            Err(e) => attempt.error(e),
        }
    })
}

fn same_url(a: &str, b: &str) -> bool {
    a.trim_end_matches('/') == b.trim_end_matches('/')
}

/// Checks that authorization server metadata presented now names the issuer
/// recorded when the flow started.
pub fn verify_issuer(expected: &str, actual: &str) -> Result<(), TrustError> {
    if same_url(expected, actual) {
        Ok(())
    } else {
        Err(TrustError::IssuerMismatch {
            expected: expected.to_string(),
            actual: actual.to_string(),
        })
    }
}

/// Checks that the token subject is the identity the flow started with, when
/// the flow started with one.
pub fn verify_expected_subject(expected: Option<&str>, subject: &str) -> Result<(), TrustError> {
    match expected {
        Some(expected) if expected != subject => Err(TrustError::SubjectMismatch {
            expected: expected.to_string(),
            actual: subject.to_string(),
        }),
        _ => Ok(()),
    }
}

/// Confirms that `authorization_server` is the authorization server for
/// `subject`, as the ATProtocol OAuth specification requires before a token's
/// `sub` is trusted.
///
/// Resolves the subject's DID document, takes its PDS, reads that PDS's
/// protected-resource metadata, and requires the authorization server it names
/// to be the one that issued the token. Returns the resolved document.
pub async fn verify_subject_authority(
    http_client: &reqwest::Client,
    identity_resolver: &SharedIdentityResolver,
    subject: &str,
    authorization_server: &str,
) -> Result<Document, TrustError> {
    if !(subject.starts_with("did:plc:") || subject.starts_with("did:web:")) {
        return Err(TrustError::UnsupportedSubject(subject.to_string()));
    }

    let unresolvable = |reason: String| TrustError::SubjectNotResolvable {
        subject: subject.to_string(),
        reason,
    };

    let document = identity_resolver
        .resolve(subject)
        .await
        .map_err(|e| unresolvable(e.to_string()))?;
    if document.id != subject {
        return Err(unresolvable(format!(
            "resolved document is for {}",
            document.id
        )));
    }

    let pds = document
        .pds_endpoints()
        .first()
        .map(|p| p.to_string())
        .ok_or_else(|| unresolvable("DID document has no PDS endpoint".to_string()))?;
    validate_remote_endpoint(&pds)?;

    let protected_resource = oauth_protected_resource(http_client, &pds)
        .await
        .map_err(|e| unresolvable(format!("PDS protected resource metadata: {e}")))?;
    let actual = protected_resource
        .authorization_servers
        .first()
        .cloned()
        .ok_or_else(|| unresolvable("PDS names no authorization server".to_string()))?;

    if !same_url(&actual, authorization_server) {
        return Err(TrustError::AuthorityMismatch {
            subject: subject.to_string(),
            expected: authorization_server.to_string(),
            actual,
        });
    }

    Ok(document)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn allows_public_https_endpoints() {
        for url in [
            "https://bsky.social",
            "https://bsky.social/oauth/par",
            "https://morel.us-east.host.bsky.network",
            "https://pds.example.com:8443/xrpc",
            "https://8.8.8.8/",
            "https://[2606:4700:4700::1111]/",
        ] {
            assert!(validate_remote_endpoint(url).is_ok(), "{url}");
        }
    }

    #[test]
    fn rejects_endpoints_from_the_disclosure() {
        for url in [
            "http://127.0.0.1:9/",
            "http://127.0.0.1:8080/",
            "https://127.0.0.1/",
            "http://prowlarr:9696/",
            "https://maintainerr:6246/",
            "https://traefik:8080/dashboard/",
            "https://postgres:5432/",
            "https://redis:6379/",
        ] {
            assert!(validate_remote_endpoint(url).is_err(), "{url}");
        }
    }

    #[test]
    fn rejects_non_https_credentials_and_internal_names() {
        for url in [
            "http://bsky.social",
            "ftp://bsky.social",
            "file:///etc/passwd",
            "https://user:pass@bsky.social",
            "https://localhost/",
            "https://localhost./",
            "https://pds.localhost/",
            "https://printer.local/",
            "https://metadata.google.internal/",
            "https://router.home.arpa/",
            "not a url",
        ] {
            assert!(validate_remote_endpoint(url).is_err(), "{url}");
        }
    }

    #[test]
    fn rejects_non_public_ip_literals() {
        for url in [
            "https://10.0.0.1/",
            "https://100.64.0.1/",
            "https://169.254.169.254/latest/meta-data/",
            "https://172.16.0.1/",
            "https://172.31.255.255/",
            "https://192.168.1.1/",
            "https://0.0.0.0/",
            "https://224.0.0.1/",
            "https://255.255.255.255/",
            "https://[::1]/",
            "https://[::]/",
            "https://[fd00::1]/",
            "https://[fe80::1]/",
            "https://[::ffff:127.0.0.1]/",
            "https://[::ffff:10.0.0.1]/",
            "https://[64:ff9b::10.0.0.1]/",
            "https://[2001:db8::1]/",
        ] {
            assert!(validate_remote_endpoint(url).is_err(), "{url}");
        }
    }

    #[test]
    fn public_ip_edges() {
        assert!(is_public_ip("172.15.255.255".parse().unwrap()));
        assert!(is_public_ip("172.32.0.0".parse().unwrap()));
        assert!(is_public_ip("100.63.255.255".parse().unwrap()));
        assert!(is_public_ip("100.128.0.0".parse().unwrap()));
        assert!(is_public_ip("223.255.255.255".parse().unwrap()));
        assert!(is_public_ip("::ffff:8.8.8.8".parse().unwrap()));
        assert!(is_public_ip("64:ff9b::8.8.8.8".parse().unwrap()));
        assert!(!is_public_ip("100.64.0.0".parse().unwrap()));
        assert!(!is_public_ip("198.18.0.1".parse().unwrap()));
    }

    #[test]
    fn subject_must_match_expected_when_known() {
        assert!(verify_expected_subject(None, "did:plc:victim").is_ok());
        assert!(verify_expected_subject(Some("did:plc:alice"), "did:plc:alice").is_ok());
        assert!(matches!(
            verify_expected_subject(Some("did:plc:attacker"), "did:plc:victim"),
            Err(TrustError::SubjectMismatch { .. })
        ));
    }

    #[test]
    fn issuer_comparison_ignores_only_a_trailing_slash() {
        assert!(verify_issuer("https://bsky.social", "https://bsky.social/").is_ok());
        assert!(verify_issuer("https://bsky.social", "https://evil.example").is_err());
        assert!(verify_issuer("https://bsky.social", "http://bsky.social").is_err());
    }

    #[tokio::test]
    async fn resolver_drops_loopback_addresses() {
        use reqwest::dns::Resolve;
        let name: reqwest::dns::Name = "localhost".parse().unwrap();
        assert!(PublicOnlyResolver.resolve(name).await.is_err());
    }
}
