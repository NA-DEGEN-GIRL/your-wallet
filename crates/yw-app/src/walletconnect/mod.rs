//! `WalletConnect` v2 (Reown) as a wallet (spec/13, D35): dApps connect by pasting a `wc:` URI
//! or by a QR read from a screenshot, the relay runs over `wss://relay.walletconnect.org` with the
//! user's Reown Cloud project id, and every request goes through the browser dispatcher as a
//! virtual connection — the same grants, approval window, arm delay, risk rules and simulation as
//! the extension.
//!
//! A session's dispatcher origin is synthetic, `https://<topic[..16]>.<topic[16..]>.walletconnect.invalid`
//! (`.invalid` never resolves, RFC 6761), so a session never shares a grant with the extension or
//! another session even when both claim the same site. The approval windows show the self-claimed
//! `metadata.url` as `WalletConnect: {origin} (사이트가 주장한 주소)` and the Verify result only as
//! a wallet-authored badge and warning (spec/13 §7).

pub mod engine;
pub mod qr_decode;
pub mod store;
pub mod verify;
pub mod worker;

#[cfg(test)]
mod tests;

use yw_core::policy::BrowserOrigin;
use yw_json::Value;

use crate::text::{json_object, json_str};

/// The synthetic origin suffix.
pub const ORIGIN_SUFFIX: &str = ".walletconnect.invalid";
/// The approval-window label prefix.
pub const LABEL_PREFIX: &str = "WalletConnect: ";

/// The Verify API result (spec/13 §7).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
pub enum VerifyStatus {
    /// The attested origin equals the claimed one.
    Valid,
    /// The attested origin differs: high risk.
    Invalid,
    /// Verify marks the site as a known scam: high risk.
    Scam,
    /// No attestation (or Verify unreachable).
    #[default]
    Unknown,
}

impl VerifyStatus {
    /// The stored value.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Valid => "valid",
            Self::Invalid => "invalid",
            Self::Scam => "scam",
            Self::Unknown => "unknown",
        }
    }

    /// Parses [`Self::as_str`].
    #[must_use]
    pub fn parse(text: &str) -> Option<Self> {
        match text {
            "valid" => Some(Self::Valid),
            "invalid" => Some(Self::Invalid),
            "scam" => Some(Self::Scam),
            "unknown" => Some(Self::Unknown),
            _ => None,
        }
    }

    /// The Korean status word (lists, badges).
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::Valid => "확인됨",
            Self::Invalid => "불일치(위험)",
            Self::Scam => "알려진 사기 사이트(위험)",
            Self::Unknown => "확인 불가",
        }
    }

    /// Whether the connection or request is high risk.
    #[must_use]
    pub const fn is_danger(self) -> bool {
        matches!(self, Self::Invalid | Self::Scam)
    }
}

/// Self-claimed dApp metadata (`proposer.metadata`), length-bounded.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Metadata {
    /// `name` (≤ 100 characters).
    pub name: String,
    /// `description` (≤ 300 characters).
    pub description: String,
    /// `url` as sent (≤ 512 bytes).
    pub url: String,
    /// `icons` (≤ 4 URLs; stored, never fetched).
    pub icons: Vec<String>,
}

fn bounded(value: Option<&Value>, max_chars: usize) -> String {
    value
        .and_then(Value::as_str)
        .map(|text| text.chars().take(max_chars).collect())
        .unwrap_or_default()
}

impl Metadata {
    /// From a `metadata` object (missing fields empty).
    #[must_use]
    pub fn from_value(value: Option<&Value>) -> Self {
        let object = value.and_then(Value::as_object);
        let get = |key: &str| object.and_then(|o| o.get(key));
        let url = get("url")
            .and_then(Value::as_str)
            .filter(|url| url.len() <= 512)
            .unwrap_or("")
            .to_owned();
        Self {
            name: bounded(get("name"), 100),
            description: bounded(get("description"), 300),
            url,
            icons: get("icons")
                .and_then(Value::as_array)
                .map(|items| {
                    items
                        .iter()
                        .filter_map(Value::as_str)
                        .filter(|u| u.len() <= 512)
                        .take(4)
                        .map(str::to_owned)
                        .collect()
                })
                .unwrap_or_default(),
        }
    }

    /// The stored form.
    #[must_use]
    pub fn to_value(&self) -> Value {
        json_object(vec![
            ("name", json_str(&self.name)),
            ("description", json_str(&self.description)),
            ("url", json_str(&self.url)),
            (
                "icons",
                Value::Array(self.icons.iter().map(|icon| json_str(icon)).collect()),
            ),
        ])
    }

    /// The name for lists and the connect window's `사이트 이름` field: one line (every run of
    /// whitespace, control, bidi or other hidden characters becomes one space), at most 100
    /// characters, escaped; "(이름 없음)" when empty. Never part of an origin or status line.
    #[must_use]
    pub fn display_name(&self) -> String {
        let name = yw_core::approval::escape_untrusted(&one_line(&self.name)).text;
        if name.is_empty() {
            "(이름 없음)".to_owned()
        } else {
            name
        }
    }

    /// The claimed URL for display: its normalized origin only. Unparsable text is never shown
    /// (it could imitate an origin or a status): "(주소 형식이 올바르지 않음)" instead.
    #[must_use]
    pub fn display_url(&self) -> String {
        claimed_origin(&self.url).map_or_else(
            || {
                if one_line(&self.url).is_empty() {
                    "(주소 없음)".to_owned()
                } else {
                    "(주소 형식이 올바르지 않음)".to_owned()
                }
            },
            |origin| origin.as_str().to_owned(),
        )
    }
}

/// Untrusted text on one line: each run of whitespace, control, bidi/format or other hidden
/// display characters (spec/03 §9.2) becomes a single space; trimmed.
#[must_use]
pub fn one_line(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    let mut gap = false;
    for character in text.chars() {
        if character.is_whitespace()
            || character.is_control()
            || yw_core::approval::is_forbidden_display_char(character)
        {
            gap = true;
        } else {
            if gap && !out.is_empty() {
                out.push(' ');
            }
            gap = false;
            out.push(character);
        }
    }
    out
}

/// `eip155:<id>`.
#[must_use]
pub fn chain_caip2(chain_id: u64) -> String {
    format!("eip155:{chain_id}")
}

/// The reference of an `eip155:<decimal>` chain (CAIP-2; no leading zeros).
#[must_use]
pub fn parse_caip2(text: &str) -> Option<u64> {
    let digits = text.strip_prefix("eip155:")?;
    if digits.is_empty()
        || digits.len() > 16
        || (digits.len() > 1 && digits.starts_with('0'))
        || !digits.bytes().all(|b| b.is_ascii_digit())
    {
        return None;
    }
    digits.parse().ok().filter(|id| *id > 0)
}

/// The synthetic dispatcher origin of a session topic.
#[must_use]
pub fn session_origin(topic: &[u8; 32]) -> Option<BrowserOrigin> {
    let hex = yw_core::hex::encode(topic);
    let (first, second) = hex.split_at(32);
    BrowserOrigin::parse(&format!("https://{first}.{second}{ORIGIN_SUFFIX}"))
}

/// Whether `origin` is a `WalletConnect` session origin.
#[must_use]
pub fn is_session_origin(origin: &BrowserOrigin) -> bool {
    topic_of_origin(origin).is_some()
}

/// The session topic of a synthetic origin.
#[must_use]
pub fn topic_of_origin(origin: &BrowserOrigin) -> Option<[u8; 32]> {
    let host = origin.host().strip_suffix(ORIGIN_SUFFIX)?;
    let (first, second) = host.split_once('.')?;
    if origin.is_http() || origin.port().is_some() || first.len() != 32 || second.len() != 32 {
        return None;
    }
    yw_core::hex::decode_array::<32>(&format!("{first}{second}")).ok()
}

/// The origin of a claimed `metadata.url` (`new URL(url).origin`, restricted to what
/// [`BrowserOrigin`] accepts: https with a DNS host, or http on localhost). `None` otherwise.
#[must_use]
pub fn claimed_origin(url: &str) -> Option<BrowserOrigin> {
    let trimmed = url.trim();
    let (scheme, rest) = trimmed.split_once("://")?;
    let scheme = scheme.to_ascii_lowercase();
    if scheme != "https" && scheme != "http" {
        return None;
    }
    let authority = rest.split(['/', '?', '#']).next().unwrap_or("");
    if authority.is_empty() || authority.contains('@') {
        return None;
    }
    let authority = authority.to_ascii_lowercase();
    let authority = match (scheme.as_str(), authority.strip_suffix(":443")) {
        ("https", Some(host)) => host.to_owned(),
        _ => match (scheme.as_str(), authority.strip_suffix(":80")) {
            ("http", Some(host)) => host.to_owned(),
            _ => authority,
        },
    };
    let origin = BrowserOrigin::parse(&format!("{scheme}://{authority}"))?;
    // Never a synthetic origin.
    (!is_session_origin(&origin)).then_some(origin)
}

/// The `요청 출처` text of a `WalletConnect` request (spec/13 §7): the normalized claimed origin
/// (or a fixed wallet text) only — never the dApp's name or raw text, and never the Verify state,
/// which only the wallet-authored badge and warning (C01–C04) carry.
#[must_use]
pub fn origin_label(peer: &Metadata) -> String {
    format!(
        "{LABEL_PREFIX}{} (사이트가 주장한 주소)",
        peer.display_url()
    )
}

/// The risk rule a `WalletConnect` request carries (C01 caution unverified, C02 mismatch, C03
/// scam, C04 info verified).
#[must_use]
pub fn verify_warning(verify: VerifyStatus) -> yw_core::approval::Warning {
    use yw_core::evm::risk::{C01, C02, C03, C04, warning};
    match verify {
        VerifyStatus::Valid => warning(C04, None),
        VerifyStatus::Invalid => warning(C02, None),
        VerifyStatus::Scam => warning(C03, None),
        VerifyStatus::Unknown => warning(C01, None),
    }
}
