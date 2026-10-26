//! Browser policy (spec/01 §2.2 `policy`). M2 provides [`BrowserOrigin`], the single origin type
//! used by the approval model (spec/03 §11.1) and SIWE checks (spec/03 §9.4); the method
//! allowlist, connection grants and provider error codes arrive with M5 (spec/05).
//!
//! Ported from `archive/spec-v2.4:crates/wallet-model/src/context.rs:42-131` and narrowed to the
//! spec/05 §4.7 grammar: https with a lowercase DNS-style host, or http only for `localhost` and
//! `127.0.0.1`; no IPv6 literal, userinfo or path, and no default port.

use core::fmt;

/// Maximum serialized origin length (spec/05 §4.7).
pub const MAX_ORIGIN_BYTES: usize = 256;
const MAX_HOST_BYTES: usize = 253;
const MAX_LABEL_BYTES: usize = 63;

/// A serialized browser origin (`https://host[:port]` or `http://localhost|127.0.0.1[:port]`).
#[derive(Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct BrowserOrigin {
    text: String,
    http: bool,
    host_end: usize,
    port: Option<u16>,
}

impl fmt::Debug for BrowserOrigin {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Origins are not logged (spec/01 §5.4); Debug output stays redacted.
        formatter.write_str("BrowserOrigin([REDACTED])")
    }
}

fn valid_host(host: &str) -> bool {
    !host.is_empty()
        && host.len() <= MAX_HOST_BYTES
        && host.split('.').all(|label| {
            !label.is_empty()
                && label.len() <= MAX_LABEL_BYTES
                && label.bytes().all(|byte| {
                    byte.is_ascii_lowercase()
                        || byte.is_ascii_digit()
                        || byte == b'-'
                        || byte == b'_'
                })
        })
}

fn parse_port(text: &str) -> Option<u16> {
    if text.is_empty()
        || text.len() > 5
        || text.starts_with('0')
        || !text.bytes().all(|byte| byte.is_ascii_digit())
    {
        return None;
    }
    text.parse::<u16>().ok().filter(|port| *port != 0)
}

impl BrowserOrigin {
    /// Parses a serialized origin by the spec/05 §4.7 rules.
    #[must_use]
    pub fn parse(text: &str) -> Option<Self> {
        if text.len() > MAX_ORIGIN_BYTES || !text.is_ascii() {
            return None;
        }
        let (http, authority) = if let Some(rest) = text.strip_prefix("https://") {
            (false, rest)
        } else {
            (true, text.strip_prefix("http://")?)
        };
        if authority.contains(['/', '?', '#', '@', '[', ']', '\\']) {
            return None;
        }
        let (host, port) = match authority.split_once(':') {
            Some((host, port)) => (host, Some(parse_port(port)?)),
            None => (authority, None),
        };
        if http {
            if host != "localhost" && host != "127.0.0.1" {
                return None;
            }
            if port == Some(80) {
                return None;
            }
        } else {
            if !valid_host(host) {
                return None;
            }
            if port == Some(443) {
                return None;
            }
        }
        let scheme_len = if http { 7 } else { 8 };
        Some(Self {
            text: text.to_owned(),
            http,
            host_end: scheme_len + host.len(),
            port,
        })
    }

    /// Whether the scheme is `http` (local development origins, spec/05 §4.6).
    #[must_use]
    pub const fn is_http(&self) -> bool {
        self.http
    }

    /// The serialized origin (approval digest `origin_serialized`, spec/03 §11.4).
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.text
    }

    /// `"https"` or `"http"`.
    #[must_use]
    pub const fn scheme(&self) -> &'static str {
        if self.http { "http" } else { "https" }
    }

    /// The host (lowercase).
    #[must_use]
    pub fn host(&self) -> &str {
        let start = if self.http { 7 } else { 8 };
        self.text.get(start..self.host_end).unwrap_or("")
    }

    /// The explicit port, if any.
    #[must_use]
    pub const fn port(&self) -> Option<u16> {
        self.port
    }

    /// The effective port: explicit, else https 443 / http 80 (spec/03 §9.4 S05).
    #[must_use]
    pub const fn effective_port(&self) -> u16 {
        match self.port {
            Some(port) => port,
            None if self.http => 80,
            None => 443,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::BrowserOrigin;

    #[test]
    fn accepts_spec_05_4_7_origins() {
        for (text, http, host, port) in [
            ("https://app.example", false, "app.example", 443),
            ("https://app.example:8443", false, "app.example", 8443),
            ("https://a-b_c.d1.example", false, "a-b_c.d1.example", 443),
            (
                "https://xn--bcher-kva.example",
                false,
                "xn--bcher-kva.example",
                443,
            ),
            ("http://localhost", true, "localhost", 80),
            ("http://localhost:5173", true, "localhost", 5173),
            ("http://127.0.0.1:8080", true, "127.0.0.1", 8080),
            ("https://localhost", false, "localhost", 443),
        ] {
            let origin = BrowserOrigin::parse(text).unwrap();
            assert_eq!(origin.as_str(), text);
            assert_eq!(origin.is_http(), http, "{text}");
            assert_eq!(origin.host(), host, "{text}");
            assert_eq!(origin.effective_port(), port, "{text}");
        }
    }

    #[test]
    fn rejects_everything_else() {
        let long_label = format!("https://{}.example", "a".repeat(64));
        let long_host = format!("https://{}", vec!["a".repeat(63); 4].join("."));
        let too_long = format!("https://{}", "a.".repeat(130));
        for text in [
            "",
            "https://",
            "https://App.example",
            "https://app.example/",
            "https://app.example/path",
            "https://app.example?q",
            "https://app.example#f",
            "https://user@app.example",
            "https://[::1]",
            "https://app.example:443",
            "https://app.example:0",
            "https://app.example:080",
            "https://app.example:65536",
            "https://app.example:",
            "https://app..example",
            "https://app.example.",
            "https://.app.example",
            "https://app.exa mple",
            "https://ä.example",
            "http://app.example",
            "http://localhost:80",
            "http://127.0.0.2",
            "http://[::1]:8080",
            "ftp://app.example",
            "HTTPS://app.example",
            "null",
            long_label.as_str(),
            long_host.as_str(),
            too_long.as_str(),
        ] {
            assert!(BrowserOrigin::parse(text).is_none(), "{text:?}");
        }
    }

    #[test]
    fn debug_is_redacted() {
        let origin = BrowserOrigin::parse("https://app.example").unwrap();
        assert_eq!(format!("{origin:?}"), "BrowserOrigin([REDACTED])");
    }
}
