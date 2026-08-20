use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use thiserror::Error;

/// Security classification of an RPC endpoint after syntax and literal-host checks.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RpcEndpointClass {
    /// A public IP literal passed the conservative global-unicast filter.
    PublicIpLiteral,
    /// A public-looking DNS name still requires post-resolution peer-IP checks.
    DomainNeedsResolvedPeerCheck,
    /// A private endpoint was accepted only by an explicit direct-development override.
    PrivateDevelopmentOverride,
}

/// Failures from conservative RPC endpoint validation.
///
/// Variants deliberately contain no copy of the input URL, which may include a
/// session credential in its path.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
pub enum RpcUrlError {
    /// Only HTTPS is accepted, except HTTP to a private host under a direct-development override.
    #[error("RPC endpoint requires HTTPS")]
    HttpsRequired,
    /// The URL did not contain a valid authority and host.
    #[error("RPC endpoint authority is invalid")]
    InvalidAuthority,
    /// User information could carry credentials and is forbidden.
    #[error("RPC endpoint user information is forbidden")]
    UserInfoForbidden,
    /// Query strings and fragments can contain signed credentials and are forbidden.
    #[error("RPC endpoint query strings and fragments are forbidden")]
    SensitiveUrlComponent,
    /// The host was not a conservative ASCII DNS name or a valid IP literal.
    #[error("RPC endpoint host is invalid")]
    InvalidHost,
    /// The port was outside the valid TCP range.
    #[error("RPC endpoint port is invalid")]
    InvalidPort,
    /// The host is local, private, reserved, or otherwise not global unicast.
    #[error("RPC endpoint is not public global-unicast")]
    NonPublicAddress,
}

/// Classifies an endpoint without resolving DNS or opening a connection.
///
/// Domain results are provisional. Callers must resolve all A/AAAA answers and
/// validate the actual connected peer address with [`validate_resolved_peer`].
/// Redirects must be disabled or each redirect target must repeat the full check.
///
/// # Errors
///
/// Returns [`RpcUrlError`] for unsafe schemes/components, malformed authorities,
/// or local/private/reserved literal hosts without the development override.
pub fn classify_rpc_endpoint(
    endpoint: &str,
    allow_private_direct_development: bool,
) -> Result<RpcEndpointClass, RpcUrlError> {
    let (rest, secure_transport) = if let Some(rest) = endpoint.strip_prefix("https://") {
        (rest, true)
    } else if let Some(rest) = endpoint.strip_prefix("http://") {
        (rest, false)
    } else {
        return Err(RpcUrlError::HttpsRequired);
    };

    if rest.contains('?') || rest.contains('#') {
        return Err(RpcUrlError::SensitiveUrlComponent);
    }
    let authority_end = rest.find('/').unwrap_or(rest.len());
    let authority = &rest[..authority_end];
    if authority.is_empty() {
        return Err(RpcUrlError::InvalidAuthority);
    }
    if authority.contains('@') {
        return Err(RpcUrlError::UserInfoForbidden);
    }

    let host = parse_host(authority)?;
    let host_class = classify_host(host);
    match host_class {
        HostClass::PublicIp => {
            if secure_transport {
                Ok(RpcEndpointClass::PublicIpLiteral)
            } else {
                Err(RpcUrlError::HttpsRequired)
            }
        }
        HostClass::PublicDomain => {
            if secure_transport {
                Ok(RpcEndpointClass::DomainNeedsResolvedPeerCheck)
            } else {
                Err(RpcUrlError::HttpsRequired)
            }
        }
        HostClass::Private => {
            if allow_private_direct_development {
                Ok(RpcEndpointClass::PrivateDevelopmentOverride)
            } else {
                Err(RpcUrlError::NonPublicAddress)
            }
        }
        HostClass::Invalid => Err(RpcUrlError::InvalidHost),
    }
}

/// Validates a DNS answer or actual connected peer address.
///
/// This closes DNS-rebinding and connect-to-different-peer gaps left by URL-only
/// validation. The development override must be explicit for every session.
///
/// # Errors
///
/// Returns [`RpcUrlError::NonPublicAddress`] for a non-global resolved or actual
/// peer address unless the explicit direct-development override is active.
pub fn validate_resolved_peer(
    address: IpAddr,
    allow_private_direct_development: bool,
) -> Result<(), RpcUrlError> {
    if is_public_ip(address) || allow_private_direct_development {
        Ok(())
    } else {
        Err(RpcUrlError::NonPublicAddress)
    }
}

fn parse_host(authority: &str) -> Result<&str, RpcUrlError> {
    if let Some(bracketed) = authority.strip_prefix('[') {
        let Some(close_index) = bracketed.find(']') else {
            return Err(RpcUrlError::InvalidAuthority);
        };
        let host = &bracketed[..close_index];
        let suffix = &bracketed[close_index + 1..];
        if !suffix.is_empty() {
            let Some(port) = suffix.strip_prefix(':') else {
                return Err(RpcUrlError::InvalidAuthority);
            };
            validate_port(port)?;
        }
        return Ok(host);
    }

    if authority.matches(':').count() > 1 {
        return Err(RpcUrlError::InvalidAuthority);
    }
    if let Some((host, port)) = authority.rsplit_once(':') {
        validate_port(port)?;
        Ok(host)
    } else {
        Ok(authority)
    }
}

fn validate_port(port: &str) -> Result<(), RpcUrlError> {
    if port.is_empty() || !port.bytes().all(|byte| byte.is_ascii_digit()) {
        return Err(RpcUrlError::InvalidPort);
    }
    let parsed = port.parse::<u16>().map_err(|_| RpcUrlError::InvalidPort)?;
    if parsed == 0 {
        return Err(RpcUrlError::InvalidPort);
    }
    Ok(())
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum HostClass {
    PublicIp,
    PublicDomain,
    Private,
    Invalid,
}

fn classify_host(host: &str) -> HostClass {
    if host.is_empty() || !host.is_ascii() {
        return HostClass::Invalid;
    }
    if let Ok(ipv4) = host.parse::<Ipv4Addr>() {
        return if is_public_ipv4(ipv4) {
            HostClass::PublicIp
        } else {
            HostClass::Private
        };
    }
    if let Ok(ipv6) = host.parse::<Ipv6Addr>() {
        return if is_public_ipv6(ipv6) {
            HostClass::PublicIp
        } else {
            HostClass::Private
        };
    }
    let lowercase = host.to_ascii_lowercase();
    let final_label = lowercase.rsplit('.').next();
    if lowercase == "localhost"
        || lowercase.ends_with(".localhost")
        || final_label == Some("local")
        || lowercase.ends_with(".home.arpa")
        || !lowercase.contains('.')
    {
        return HostClass::Private;
    }
    if lowercase.len() > 253
        || lowercase.starts_with('.')
        || lowercase.ends_with('.')
        || lowercase.split('.').any(|label| {
            label.is_empty()
                || label.len() > 63
                || label.starts_with('-')
                || label.ends_with('-')
                || !label
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
        })
    {
        return HostClass::Invalid;
    }
    HostClass::PublicDomain
}

fn is_public_ip(address: IpAddr) -> bool {
    match address {
        IpAddr::V4(address) => is_public_ipv4(address),
        IpAddr::V6(address) => is_public_ipv6(address),
    }
}

fn is_public_ipv4(address: Ipv4Addr) -> bool {
    let [a, b, c, _] = address.octets();
    !(a == 0
        || a == 10
        || a == 127
        || (a == 100 && (64..=127).contains(&b))
        || (a == 169 && b == 254)
        || (a == 172 && (16..=31).contains(&b))
        || (a == 192 && b == 0 && c == 0)
        || (a == 192 && b == 0 && c == 2)
        || (a == 192 && b == 88 && c == 99)
        || (a == 192 && b == 168)
        || (a == 198 && (b == 18 || b == 19))
        || (a == 198 && b == 51 && c == 100)
        || (a == 203 && b == 0 && c == 113)
        || a >= 224)
}

fn is_public_ipv6(address: Ipv6Addr) -> bool {
    if let Some(mapped) = address.to_ipv4_mapped() {
        return is_public_ipv4(mapped);
    }
    let segments = address.segments();
    !(address.is_unspecified()
        || address.is_loopback()
        || address.is_multicast()
        || (segments[0] & 0xfe00) == 0xfc00
        || (segments[0] & 0xffc0) == 0xfe80
        || (segments[0] == 0x2001 && segments[1] == 0x0db8))
}

#[cfg(test)]
mod tests {
    use std::net::{IpAddr, Ipv4Addr};

    use super::{RpcEndpointClass, RpcUrlError, classify_rpc_endpoint, validate_resolved_peer};

    #[test]
    fn public_domain_is_provisional_until_dns_and_peer_check() {
        assert_eq!(
            classify_rpc_endpoint("https://rpc.example.com/v1/session-value", false),
            Ok(RpcEndpointClass::DomainNeedsResolvedPeerCheck)
        );
    }

    #[test]
    fn credential_bearing_url_shapes_are_rejected_without_echoing_input() {
        assert_eq!(
            classify_rpc_endpoint("https://name:credential@example.com", false),
            Err(RpcUrlError::UserInfoForbidden)
        );
        assert_eq!(
            classify_rpc_endpoint("https://rpc.example.com/?key=value", false),
            Err(RpcUrlError::SensitiveUrlComponent)
        );
    }

    #[test]
    fn local_and_private_targets_are_blocked_by_default() {
        for endpoint in [
            "http://localhost:8545",
            "https://127.0.0.1:8545",
            "https://10.0.0.1",
            "https://[::1]",
            "https://node.local",
            "https://single-label",
        ] {
            assert_eq!(
                classify_rpc_endpoint(endpoint, false),
                Err(RpcUrlError::NonPublicAddress)
            );
        }
    }

    #[test]
    fn direct_development_override_is_explicitly_classified() {
        assert_eq!(
            classify_rpc_endpoint("http://127.0.0.1:8545", true),
            Ok(RpcEndpointClass::PrivateDevelopmentOverride)
        );
    }

    #[test]
    fn resolved_private_peer_is_blocked_even_for_public_looking_domain() {
        let private = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 8));
        assert_eq!(
            validate_resolved_peer(private, false),
            Err(RpcUrlError::NonPublicAddress)
        );
        assert_eq!(validate_resolved_peer(private, true), Ok(()));
    }

    #[test]
    fn malformed_hosts_and_ports_are_rejected() {
        assert_eq!(
            classify_rpc_endpoint("https://bad_host.example", false),
            Err(RpcUrlError::InvalidHost)
        );
        assert_eq!(
            classify_rpc_endpoint("https://rpc.example.com:0", false),
            Err(RpcUrlError::InvalidPort)
        );
        assert_eq!(
            classify_rpc_endpoint("https://2001:db8::1", false),
            Err(RpcUrlError::InvalidAuthority)
        );
    }
}
