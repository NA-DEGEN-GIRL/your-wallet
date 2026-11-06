//! The pairing URI (`clients/core/pairing/pairing-uri.md`, EIP-1328):
//! `wc:{topic}@2?symKey={hex}&methods={…}&relay-protocol=irn[&relay-data=…][&expiryTimestamp=…]`.
//!
//! Accepted: surrounding whitespace, a percent-encoded URI (`wc%3A…`, as some "Copy link"
//! buttons and deep links produce), percent-encoded parameter values, upper-case hex digits.
//! Refused: version 1 (`@1`, the retired v1 protocol), a topic or `symKey` that is not 32 bytes
//! of hex, a relay protocol other than `irn`, duplicate parameters.

use core::fmt;

use zeroize::Zeroizing;

/// Longest pairing URI accepted (bytes).
pub const MAX_URI_BYTES: usize = 2_048;

/// A parsed pairing URI.
#[derive(Clone, PartialEq, Eq)]
pub struct PairingUri {
    /// Pairing topic (32 bytes).
    pub topic: [u8; 32],
    /// Pairing symmetric key.
    pub sym_key: Zeroizing<[u8; 32]>,
    /// `relay-protocol` (always `irn` after parsing).
    pub relay_protocol: String,
    /// `relay-data`, if present.
    pub relay_data: Option<String>,
    /// `expiryTimestamp` (Unix seconds), if present.
    pub expiry: Option<u64>,
    /// `methods` as written (informational; the proposal is what counts).
    pub methods: Option<String>,
}

impl fmt::Debug for PairingUri {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("PairingUri([REDACTED])")
    }
}

impl PairingUri {
    /// The topic as lowercase hex (the relay's topic string).
    #[must_use]
    pub fn topic_hex(&self) -> String {
        crate::hex::encode(&self.topic)
    }

    /// Whether the pairing expired at `now_unix_s` (no `expiryTimestamp`: never).
    #[must_use]
    pub fn expired(&self, now_unix_s: u64) -> bool {
        self.expiry.is_some_and(|expiry| expiry <= now_unix_s)
    }
}

/// Why a text is not a usable pairing URI.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum UriError {
    /// Not a `wc:` URI.
    NotWalletConnect,
    /// `@1`: the `WalletConnect` v1 protocol (shut down in 2023).
    Version1,
    /// No `@2` version or another version.
    UnsupportedVersion,
    /// Topic missing or not 64 hex digits.
    BadTopic,
    /// `symKey` missing or not 64 hex digits.
    BadSymKey,
    /// `relay-protocol` missing or not `irn`.
    BadRelay,
    /// Malformed query (duplicate key, bad escape, bad `expiryTimestamp`, too long).
    Malformed,
}

impl UriError {
    /// The Korean message for the paste field.
    #[must_use]
    pub const fn message(self) -> &'static str {
        match self {
            Self::NotWalletConnect => {
                "WalletConnect 연결 주소(wc:로 시작)가 아닙니다. dApp의 WalletConnect 창에서 '링크 복사'를 누른 뒤 붙여 넣으세요."
            }
            Self::Version1 => "WalletConnect v1 주소입니다. v1은 종료되어 지원하지 않습니다.",
            Self::UnsupportedVersion => "지원하지 않는 WalletConnect 버전입니다(v2만 지원).",
            Self::BadTopic | Self::BadSymKey | Self::Malformed => {
                "WalletConnect 연결 주소의 형식이 올바르지 않습니다. 다시 복사해 주세요."
            }
            Self::BadRelay => "지원하지 않는 릴레이 방식입니다(irn만 지원).",
        }
    }
}

impl fmt::Display for UriError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.message())
    }
}

impl std::error::Error for UriError {}

fn hex_value(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        _ => None,
    }
}

/// Percent-decoding (`%XX`; `+` stays `+`). `None` for a bad escape or non-UTF-8 result.
fn percent_decode(text: &str) -> Option<String> {
    let bytes = text.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut index = 0;
    while let Some(&byte) = bytes.get(index) {
        if byte == b'%' {
            let high = hex_value(*bytes.get(index + 1)?)?;
            let low = hex_value(*bytes.get(index + 2)?)?;
            out.push((high << 4) | low);
            index += 3;
        } else {
            out.push(byte);
            index += 1;
        }
    }
    String::from_utf8(out).ok()
}

fn hex32(text: &str) -> Option<[u8; 32]> {
    let bytes = text.as_bytes();
    if bytes.len() != 64 {
        return None;
    }
    let mut out = [0_u8; 32];
    for (slot, pair) in out.iter_mut().zip(bytes.chunks_exact(2)) {
        let high = hex_value(*pair.first()?)?;
        let low = hex_value(*pair.get(1)?)?;
        *slot = (high << 4) | low;
    }
    Some(out)
}

/// Parses a pairing URI.
///
/// # Errors
///
/// [`UriError`] as listed on the type.
pub fn parse_pairing_uri(text: &str) -> Result<PairingUri, UriError> {
    let trimmed = text.trim();
    if trimmed.len() > MAX_URI_BYTES {
        return Err(UriError::Malformed);
    }
    let decoded;
    let text = if trimmed.len() > 5 && trimmed.get(..5).is_some_and(|p| p.eq_ignore_ascii_case("wc%3a")) {
        decoded = percent_decode(trimmed).ok_or(UriError::Malformed)?;
        decoded.as_str()
    } else {
        trimmed
    };
    let rest = text
        .get(..3)
        .filter(|scheme| scheme.eq_ignore_ascii_case("wc:"))
        .and_then(|_| text.get(3..))
        .ok_or(UriError::NotWalletConnect)?;
    let rest = rest.strip_prefix("//").unwrap_or(rest);
    let (path, query) = rest.split_once('?').unwrap_or((rest, ""));
    let (topic, version) = path.split_once('@').ok_or(UriError::UnsupportedVersion)?;
    match version {
        "2" => {}
        "1" => return Err(UriError::Version1),
        _ => return Err(UriError::UnsupportedVersion),
    }
    let topic = hex32(topic).ok_or(UriError::BadTopic)?;
    let mut sym_key = None;
    let mut relay_protocol = None;
    let mut relay_data = None;
    let mut expiry = None;
    let mut methods = None;
    let mut seen: Vec<String> = Vec::new();
    for pair in query.split('&').filter(|pair| !pair.is_empty()) {
        let (key, value) = pair.split_once('=').unwrap_or((pair, ""));
        let key = percent_decode(key).ok_or(UriError::Malformed)?;
        let value = percent_decode(value).ok_or(UriError::Malformed)?;
        if seen.contains(&key) {
            return Err(UriError::Malformed);
        }
        seen.push(key.clone());
        match key.as_str() {
            "symKey" => sym_key = Some(Zeroizing::new(hex32(&value).ok_or(UriError::BadSymKey)?)),
            "relay-protocol" => relay_protocol = Some(value),
            "relay-data" => relay_data = Some(value),
            "expiryTimestamp" => {
                if value.is_empty() || value.len() > 12 || !value.bytes().all(|b| b.is_ascii_digit())
                {
                    return Err(UriError::Malformed);
                }
                expiry = Some(value.parse::<u64>().map_err(|_| UriError::Malformed)?);
            }
            "methods" => methods = Some(value),
            // Later parameters (e.g. `expiryTimestamp` variants) are ignored like the SDK does.
            _ => {}
        }
    }
    let sym_key = sym_key.ok_or(UriError::BadSymKey)?;
    let relay_protocol = relay_protocol.ok_or(UriError::BadRelay)?;
    if relay_protocol != super::RELAY_PROTOCOL {
        return Err(UriError::BadRelay);
    }
    Ok(PairingUri {
        topic,
        sym_key,
        relay_protocol,
        relay_data,
        expiry,
        methods,
    })
}
