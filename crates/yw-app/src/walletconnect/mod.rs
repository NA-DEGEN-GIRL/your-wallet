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

use yw_core::lang::Lang;
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
    /// The attested origin equals the claimed one. What the Verify server reported, not a proof:
    /// a dApp running outside a browser can obtain it (spec/13 §7), so it is shown as such.
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

    /// The status word (lists, badges) in `lang`. `Valid` says what the server reported, never
    /// "confirmed".
    #[must_use]
    pub const fn label(self, lang: Lang) -> &'static str {
        match self {
            Self::Valid => text::VERIFY_VALID,
            Self::Invalid => text::VERIFY_INVALID,
            Self::Scam => text::VERIFY_SCAM,
            Self::Unknown => text::VERIFY_UNKNOWN,
        }
        .get(lang)
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
    pub fn display_name(&self, lang: Lang) -> String {
        let name = yw_core::approval::escape_untrusted(&one_line(&self.name)).text;
        if name.is_empty() {
            text::NO_NAME.get(lang).to_owned()
        } else {
            name
        }
    }

    /// The claimed URL for display: its normalized origin only. Unparsable text is never shown
    /// (it could imitate an origin or a status): "(주소 형식이 올바르지 않음)" instead.
    #[must_use]
    pub fn display_url(&self, lang: Lang) -> String {
        claimed_origin(&self.url).map_or_else(
            || {
                if one_line(&self.url).is_empty() {
                    text::NO_URL.get(lang).to_owned()
                } else {
                    text::BAD_URL.get(lang).to_owned()
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
pub fn origin_label(lang: Lang, peer: &Metadata) -> String {
    format!(
        "{LABEL_PREFIX}{}",
        text::CLAIMED.fill(lang, [&peer.display_url(lang)])
    )
}

/// The `WalletConnect` texts of the approval display and the session lists (spec/13 §7;
/// English spec/14 §2). The origin label is digested display text.
pub mod text {
    yw_core::texts! {
        CLAIMED(1) = "{0} (사이트가 주장한 주소)" / "{0} (address claimed by the site)";
        NO_NAME = "(이름 없음)" / "(no name)";
        NO_URL = "(주소 없음)" / "(no address)";
        BAD_URL = "(주소 형식이 올바르지 않음)" / "(malformed address)";
        VERIFY_VALID = "일치(서버 알림)" / "match (server report)";
        VERIFY_INVALID = "불일치(위험)" / "mismatch (danger)";
        VERIFY_SCAM = "알려진 사기 사이트(위험)" / "known scam site (danger)";
        VERIFY_UNKNOWN = "확인 불가" / "unverified";
        CONNECT_VALID = "WalletConnect 연결입니다. Verify 서버는 이 연결이 사이트가 주장한 주소에서 시작되었다고 알렸습니다. 다만 브라우저 밖에서 도는 dApp은 이 결과를 꾸밀 수 있으니, 지금 직접 연 사이트에서 연결했는지 확인하세요."
            / "This is a WalletConnect connection. The Verify server reported that it started at the address the site claims. A dApp running outside a browser can fake this result, so check that you connected from a site you opened yourself just now.";
        CONNECT_UNKNOWN = "WalletConnect 연결입니다. 사이트 이름과 주소는 사이트가 스스로 주장한 값이며 확인되지 않았습니다. 지금 연결하려던 사이트가 맞는지 확인하세요."
            / "This is a WalletConnect connection. The site name and address are what the site claims and are not verified. Check that this is the site you meant to connect to.";
        CONNECT_INVALID = "위험: WalletConnect Verify 결과, 사이트가 주장한 주소와 실제 주소가 다릅니다. 피싱일 수 있습니다. 연결하지 마세요."
            / "Danger: WalletConnect Verify reports that the site's real address differs from the claimed one. This may be phishing. Do not connect.";
        CONNECT_SCAM = "위험: WalletConnect Verify가 이 사이트를 알려진 사기 사이트로 표시했습니다. 연결하지 마세요."
            / "Danger: WalletConnect Verify flagged this site as a known scam site. Do not connect.";
        SITE_NAME = "사이트 이름 (사이트가 주장)" / "Site name (claimed by the site)";
        NETWORKS = "연결할 네트워크 (WalletConnect)" / "Networks to connect (WalletConnect)";
        UNSUPPORTED(1) = "이 지갑이 지원하지 않는 요청은 거부됩니다: {0}" / "Requests this wallet does not support are rejected: {0}";
        DROPPED(1) = "사이트가 요구한 알 수 없는 요청·이벤트 이름 {0}개는 세션에서 뺐습니다."
            / "{0} unknown request or event name(s) the site asked for were left out of the session.";
    }
}

/// The risk rule a `WalletConnect` request carries (C01 caution unverified, C02 mismatch, C03
/// scam, C04 info: the Verify server reported a match).
#[must_use]
pub fn verify_warning(lang: Lang, verify: VerifyStatus) -> yw_core::approval::Warning {
    use yw_core::evm::risk::{C01, C02, C03, C04, warning};
    let rule = match verify {
        VerifyStatus::Valid => C04,
        VerifyStatus::Invalid => C02,
        VerifyStatus::Scam => C03,
        VerifyStatus::Unknown => C01,
    };
    warning(lang, rule, None)
}
