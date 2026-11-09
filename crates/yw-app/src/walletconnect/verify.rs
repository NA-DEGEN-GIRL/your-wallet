//! The Verify API check of a proposal (spec/13 §7; reference `packages/core/src/controllers/
//! verify.ts` of `walletconnect-monorepo`).
//!
//! 1. v3: the relay message's `attestation` is an ES256 JWT signed by the Verify server; its
//!    public key is `GET https://verify.walletconnect.org/v3/public-key` (`{publicKey: JWK P-256,
//!    expiresAt}`, cached until `expiresAt`). The payload `{exp, id, origin, isScam, isVerified}`
//!    counts only when the signature verifies (CNG), `exp` is in the future and `id` equals
//!    `sha256(encrypted message)`; `isVerified: false` means unknown.
//! 2. v2 fallback: `GET https://verify.walletconnect.org/attestation/{sha256(JSON)}?v2Supported=true`
//!    → 200 `{origin, isScam?}`; anything else is unknown.
//!
//! Result: `isScam` → [`VerifyStatus::Scam`]; attested origin = claimed origin →
//! [`VerifyStatus::Valid`]; another origin → [`VerifyStatus::Invalid`] (also one this wallet
//! cannot parse — plain http off localhost, IPv6, an extension page, `null` — unless it is the
//! claimed URL's own origin); no answer → [`VerifyStatus::Unknown`]. Only the official server
//! is used (`metadata.verifyUrl` ignored).

use yw_json::{Limits, Value};

use super::VerifyStatus;
use super::engine::VerifyInput;

/// The Verify server.
pub const VERIFY_SERVER: &str = "https://verify.walletconnect.org";

const LIMITS: Limits = Limits {
    max_bytes: 65_536,
    max_depth: 8,
    max_nodes: 256,
    max_items: 128,
};

/// The Verify server's P-256 public key and when it expires (Unix s).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct VerifyKey {
    /// X.
    pub x: [u8; 32],
    /// Y.
    pub y: [u8; 32],
    /// `expiresAt`.
    pub expires_at: u64,
}

/// Parses `/v3/public-key`.
#[must_use]
pub fn parse_public_key(body: &[u8]) -> Option<VerifyKey> {
    let value = yw_json::parse(body, &LIMITS).ok()?;
    let object = value.as_object()?;
    let key = object.get("publicKey")?.as_object()?;
    if key.get("crv")?.as_str()? != "P-256" || key.get("kty")?.as_str()? != "EC" {
        return None;
    }
    let coordinate = |name: &str| -> Option<[u8; 32]> {
        let bytes = yw_core::walletconnect::base64url_decode(key.get(name)?.as_str()?)?;
        <[u8; 32]>::try_from(bytes.as_slice()).ok()
    };
    Some(VerifyKey {
        x: coordinate("x")?,
        y: coordinate("y")?,
        expires_at: object.get("expiresAt")?.as_number()?.as_u64()?,
    })
}

/// The decoded v3 attestation payload.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Attestation {
    /// Attested origin.
    pub origin: String,
    /// `isScam`.
    pub is_scam: bool,
    /// `isVerified`.
    pub is_verified: bool,
}

/// An ES256 check: `(x, y, sha256 digest, r ‖ s) → valid`.
pub type SignatureCheck = dyn Fn(&[u8; 32], &[u8; 32], &[u8; 32], &[u8; 64]) -> bool;

/// Checks a v3 attestation JWT: ES256 with `key` (`verify_signature(x, y, digest, sig)`), not
/// expired at `now_s`, `id == encrypted_id`.
#[must_use]
pub fn check_attestation(
    jwt: &str,
    key: &VerifyKey,
    encrypted_id: &str,
    now_s: u64,
    verify_signature: &SignatureCheck,
) -> Option<Attestation> {
    let mut parts = jwt.split('.');
    let (header, payload, signature) = (parts.next()?, parts.next()?, parts.next()?);
    if parts.next().is_some() {
        return None;
    }
    let signature = yw_core::walletconnect::base64url_decode(signature)?;
    let signature = <[u8; 64]>::try_from(signature.as_slice()).ok()?;
    let digest = yw_core::codec::sha256(format!("{header}.{payload}").as_bytes());
    if !verify_signature(&key.x, &key.y, &digest, &signature) {
        return None;
    }
    let header =
        yw_json::parse(&yw_core::walletconnect::base64url_decode(header)?, &LIMITS).ok()?;
    if header.as_object()?.get("alg")?.as_str()? != "ES256" {
        return None;
    }
    let payload =
        yw_json::parse(&yw_core::walletconnect::base64url_decode(payload)?, &LIMITS).ok()?;
    let object = payload.as_object()?;
    let exp = object.get("exp")?.as_number()?.as_u64()?;
    if exp <= now_s || object.get("id")?.as_str()? != encrypted_id {
        return None;
    }
    Some(Attestation {
        origin: object.get("origin")?.as_str()?.to_owned(),
        is_scam: object
            .get("isScam")
            .and_then(Value::as_bool)
            .unwrap_or(false),
        is_verified: object
            .get("isVerified")
            .and_then(Value::as_bool)
            .unwrap_or(false),
    })
}

/// Parses the v2 `GET /attestation/{id}` answer.
#[must_use]
pub fn parse_v2(body: &[u8]) -> Option<Attestation> {
    let value = yw_json::parse(body, &LIMITS).ok()?;
    let object = value.as_object()?;
    Some(Attestation {
        origin: object.get("origin")?.as_str()?.to_owned(),
        is_scam: object
            .get("isScam")
            .and_then(Value::as_bool)
            .unwrap_or(false),
        is_verified: true,
    })
}

/// The status of an attestation against the claimed `metadata.url`.
#[must_use]
pub fn status_of(attestation: Option<&Attestation>, claimed_url: &str) -> VerifyStatus {
    let Some(attestation) = attestation else {
        return VerifyStatus::Unknown;
    };
    if attestation.is_scam {
        return VerifyStatus::Scam;
    }
    if !attestation.is_verified {
        return VerifyStatus::Unknown;
    }
    match (
        super::claimed_origin(&attestation.origin),
        super::claimed_origin(claimed_url),
    ) {
        (Some(attested), Some(claimed)) if attested == claimed => VerifyStatus::Valid,
        // An attested origin outside what this wallet parses (a page on plain http, an IPv6
        // host, an extension page, `null`) is still another origin than the claimed one — the
        // reference SDK compares it with `new URL(metadata.url).origin` and says INVALID — unless
        // it is empty or that very origin (a LAN dev server), which this wallet cannot judge.
        (None, _)
            if attestation.origin.is_empty()
                || raw_origin(&attestation.origin)
                    .is_some_and(|attested| Some(attested) == raw_origin(claimed_url)) =>
        {
            VerifyStatus::Unknown
        }
        _ => VerifyStatus::Invalid,
    }
}

/// `scheme://authority` of `url`, lowercased, default port removed (`None` without `://` or
/// with user info) — a byte comparison for origins [`super::claimed_origin`] does not accept.
fn raw_origin(url: &str) -> Option<String> {
    let (scheme, rest) = url.trim().split_once("://")?;
    let scheme = scheme.to_ascii_lowercase();
    let authority = rest
        .split(['/', '?', '#'])
        .next()
        .unwrap_or("")
        .to_ascii_lowercase();
    if authority.is_empty() || authority.contains('@') {
        return None;
    }
    let default_port = match scheme.as_str() {
        "https" => ":443",
        "http" => ":80",
        _ => "",
    };
    let authority = match authority.strip_suffix(default_port) {
        Some(host) if !default_port.is_empty() => host.to_owned(),
        _ => authority,
    };
    Some(format!("{scheme}://{authority}"))
}

/// HTTP access for the check (the worker's `WinHTTP` client; a stub in tests).
pub trait VerifyHttp {
    /// `GET url` → `(status, body)`.
    fn get(&self, url: &str) -> Option<(u16, Vec<u8>)>;
}

impl VerifyHttp for yw_win::http::Client {
    fn get(&self, url: &str) -> Option<(u16, Vec<u8>)> {
        let url = yw_win::http::HttpsUrl::parse(url).ok()?;
        let response = yw_win::http::Client::get(self, &url, 65_536).ok()?;
        Some((response.status, response.body))
    }
}

/// Runs the check of a proposal (blocking, ≤ two requests of the client's timeouts).
pub fn resolve(
    http: &dyn VerifyHttp,
    cache: &mut Option<VerifyKey>,
    input: &VerifyInput,
    claimed_url: &str,
    now_s: u64,
) -> VerifyStatus {
    if let Some(jwt) = &input.attestation {
        if cache.is_none_or(|key| key.expires_at <= now_s) {
            *cache = http
                .get(&format!("{VERIFY_SERVER}/v3/public-key"))
                .filter(|(status, _)| *status == 200)
                .and_then(|(_, body)| parse_public_key(&body));
        }
        if let Some(key) = cache.as_ref()
            && let Some(attestation) = check_attestation(
                jwt,
                key,
                &input.encrypted_id,
                now_s,
                &|x, y, digest, signature| yw_win::cng::p256_verify(x, y, digest, signature),
            )
        {
            return status_of(Some(&attestation), claimed_url);
        }
    }
    let attestation = http
        .get(&format!(
            "{VERIFY_SERVER}/attestation/{}?v2Supported=true",
            input.hash
        ))
        .filter(|(status, _)| *status == 200)
        .and_then(|(_, body)| parse_v2(&body));
    status_of(attestation.as_ref(), claimed_url)
}
