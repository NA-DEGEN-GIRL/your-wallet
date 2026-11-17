//! The pure HTTP types (spec/01 §7.4, §7.8): URL parsing and normalization, redacted formatting,
//! the header rule and the `HttpError` texts. 2026-11-17: moved from yw-win `http` unit tests with
//! the types; the `Display` tests of `HttpError` are new. 2026-11-17 S2: the `Transport` seam's
//! default methods.

use yw_platform::http::{
    EndpointUrl, HttpError, HttpReply, HttpsUrl, LoopbackUrl, Timeouts, Transport, valid_header,
};

#[test]
fn https_url_accepts_and_normalizes() {
    let url = HttpsUrl::parse("https://Name.Ethereum-Sepolia.QuikNode.pro/tok_EN-123/").unwrap();
    assert_eq!(url.host(), "name.ethereum-sepolia.quiknode.pro");
    assert_eq!(url.path(), "/tok_EN-123/");
    assert_eq!(
        url.expose(),
        "https://name.ethereum-sepolia.quiknode.pro/tok_EN-123/"
    );
    assert_eq!(HttpsUrl::parse("https://h.example").unwrap().path(), "/");
    assert_eq!(
        HttpsUrl::parse("https://h.example:8443/x?y=1")
            .unwrap()
            .port(),
        Some(8443)
    );
    assert!(HttpsUrl::parse(&format!("https://h.example/{}", "a".repeat(2_028))).is_ok());
    // Security review S16: the scheme is case-insensitive and an IPv6 literal is a host,
    // as for the loopback `http://[::1]`; both normalize to lowercase.
    assert_eq!(
        HttpsUrl::parse("HTTPS://Example.com/x").unwrap().expose(),
        "https://example.com/x"
    );
    let v6 = HttpsUrl::parse("https://[2001:DB8::1]:8545/rpc").unwrap();
    assert_eq!(v6.host(), "[2001:db8::1]");
    assert_eq!(v6.port(), Some(8545));
    assert_eq!(v6.expose(), "https://[2001:db8::1]:8545/rpc");
    assert!(HttpsUrl::parse("https://[::ffff:192.0.2.1]/").is_ok());
    assert!(matches!(
        EndpointUrl::parse("Https://api.example/v1"),
        Ok(EndpointUrl::Https(_))
    ));
    assert!(matches!(
        EndpointUrl::parse("HTTP://[::1]:11434/v1"),
        Ok(EndpointUrl::Loopback(_))
    ));
}

#[test]
fn https_url_rejections() {
    for bad in [
        "http://example.com",
        "https://",
        "https://user@example.com/",
        "https://example.com/#frag",
        "https://example.com/a b",
        "https://exa_mple.com/",
        "https://example.com:0/",
        "https://example.com:65536/",
        "https://example.com:/",
        "https://example.com:08/",
        "https://[::1",
        "https://[::1]x/",
        "https://[g::1]/",
        "https://[::1%25eth0]/",
        "https://[:::1]/",
        "https://[1::2::3]/",
        "https://[12345::1]/",
        "https://[]/",
        "https://[1.2.3.4]/",
        "ftp://example.com/",
        "httpsx://example.com/",
        "https://example.com/\u{e9}",
    ] {
        assert_eq!(HttpsUrl::parse(bad), Err(HttpError::InvalidUrl), "{bad}");
    }
    assert!(HttpsUrl::parse(&format!("https://h.example/{}", "a".repeat(2_040))).is_err());
}

#[test]
fn https_url_formatting_never_shows_host_or_path() {
    let url = HttpsUrl::parse("https://secret-name.rpc.example/token-path/").unwrap();
    for shown in [format!("{url}"), format!("{url:?}")] {
        assert_eq!(shown, "https://[redacted]");
        assert!(!shown.contains("secret-name"));
        assert!(!shown.contains("token"));
    }
}

#[test]
fn loopback_and_endpoint_dispatch() {
    assert!(LoopbackUrl::parse("http://127.0.0.1:11434/v1/chat/completions").is_ok());
    assert!(LoopbackUrl::parse("http://LOCALHOST/v1/chat/completions").is_ok());
    assert!(matches!(
        EndpointUrl::parse("http://[::1]:11434/v1/chat/completions"),
        Ok(EndpointUrl::Loopback(_))
    ));
    assert_eq!(
        EndpointUrl::parse("http://example.com/"),
        Err(HttpError::InvalidUrl)
    );
    assert_eq!(
        EndpointUrl::parse("http://127.0.0.2/"),
        Err(HttpError::InvalidUrl)
    );
    assert!(matches!(
        EndpointUrl::parse("https://api.example/v1/chat/completions"),
        Ok(EndpointUrl::Https(_))
    ));
    let shown = format!(
        "{}",
        LoopbackUrl::parse("http://localhost:8080/secret/path").unwrap()
    );
    assert_eq!(shown, "http://localhost:8080/…");
}

#[test]
fn loopback_accessors() {
    let url = LoopbackUrl::parse("http://[::1]:11434/v1/chat/completions?x=1").unwrap();
    assert_eq!(url.host(), "[::1]");
    assert_eq!(url.port(), Some(11434));
    assert_eq!(url.path(), "/v1/chat/completions?x=1");
    let url = LoopbackUrl::parse("http://LocalHost").unwrap();
    assert_eq!(url.host(), "localhost");
    assert_eq!(url.port(), None);
    assert_eq!(url.path(), "/");
    assert_eq!(format!("{url:?}"), "http://localhost/…");
}

#[test]
fn header_rules() {
    assert!(valid_header("Content-Type", b"application/json"));
    assert!(!valid_header("", b"x"));
    assert!(!valid_header("Bad Name", b"x"));
    assert!(!valid_header(&"a".repeat(65), b"x"));
    assert!(!valid_header("X", b"line\r\nbreak"));
    assert!(!valid_header("X", &[0x80]));
    assert!(valid_header("X", &vec![b'a'; 4_096]));
    assert!(!valid_header("X", &vec![b'a'; 4_097]));
}

#[test]
fn timeouts_total_is_the_saturating_sum() {
    let timeouts = Timeouts {
        resolve_ms: 5_000,
        connect_ms: 5_000,
        send_ms: 10_000,
        receive_ms: 10_000,
    };
    assert_eq!(timeouts.total_ms(), 30_000);
    let huge = Timeouts {
        resolve_ms: u32::MAX,
        connect_ms: u32::MAX,
        send_ms: u32::MAX,
        receive_ms: u32::MAX,
    };
    assert_eq!(huge.total_ms(), 4 * u64::from(u32::MAX));
}

/// `HttpError` texts are fixed: no URL, host, path, API name or response text (D28, spec/01
/// §5.4), even after a request to a URL that carries a host and a token.
#[test]
fn http_error_display_never_shows_url_or_host() {
    let url = HttpsUrl::parse("https://secret-host.rpc.example:8443/token-path/").unwrap();
    let cases = [
        (HttpError::InvalidUrl, "invalid URL"),
        (HttpError::InvalidHeader, "invalid header"),
        (HttpError::Timeout, "HTTP timeout"),
        (HttpError::Tls, "TLS failure"),
        (HttpError::TooLarge, "HTTP payload too large"),
        (
            HttpError::UpgradeRefused(401),
            "WebSocket upgrade refused: HTTP 401",
        ),
        (HttpError::Os(0x0000_2EFD), "OS error 0x00002EFD"),
        (HttpError::Os(0), "OS error 0x00000000"),
    ];
    for (error, text) in cases {
        let shown = error.to_string();
        assert_eq!(shown, text);
        for secret in [
            url.host(),
            url.path(),
            url.expose(),
            "secret",
            "token",
            "WinHttp",
        ] {
            assert!(!shown.contains(secret), "{shown} contains {secret}");
        }
        let debug = format!("{error:?}");
        assert!(!debug.contains("secret") && !debug.contains("token"));
    }
}

/// A transport that speaks only JSON-RPC: the indexer GET and the plain-text POST keep their
/// defaults, which send nothing and fail with `InvalidUrl` (spec/08 §4.1, §11.3).
#[test]
fn transport_defaults_refuse_get_and_text_post() {
    struct JsonOnly;

    impl Transport for JsonOnly {
        fn post_json(
            &self,
            _url: &HttpsUrl,
            body: &[u8],
            _max_response: usize,
        ) -> Result<HttpReply, HttpError> {
            Ok(HttpReply {
                status: 200,
                body: body.to_vec(),
            })
        }
    }

    let url = HttpsUrl::parse("https://rpc.example/").unwrap();
    let transport: &dyn Transport = &JsonOnly;
    assert_eq!(
        transport.post_json(&url, b"{}", 1_024),
        Ok(HttpReply {
            status: 200,
            body: b"{}".to_vec(),
        })
    );
    assert_eq!(transport.http_get(&url, 1_024), Err(HttpError::InvalidUrl));
    assert_eq!(
        transport.http_post_text(&url, b"00", 1_024),
        Err(HttpError::InvalidUrl)
    );
}
