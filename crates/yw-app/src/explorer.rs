//! Block explorer links (2026-11-11, spec/04 §2.6, §2.11 "블록 탐색기", §2.14): two URL
//! templates per network — a transaction page with `{hash}` and an address page with
//! `{address}` — the built-in defaults, the user's overrides (`settings.json` top-level key
//! [`EXPLORERS_KEY`], written only when there is one), template validation, and building a URL
//! from a validated template and a value whose character set fits the network.
//!
//! Window-free: the app side (`app_explorer`) resolves the templates in use, opens the URL with
//! `explorer.exe` and logs only the network id.

use core::fmt;

use yw_core::hypercore::HcNetwork;
use yw_core::lang::Lang;
use yw_core::zec::ZecNetwork;
use yw_json::Value;
use yw_win::http::HttpsUrl;

use crate::network::{BtcNet, NetworkId, SolCluster};
use crate::text::{json_object, json_object_owned, json_str};

/// The top-level `settings.json` key of the overrides. A new top-level key (spec/04 §6.6): an
/// older build keeps it unread and writes it back; inside a known object it would reset that
/// object there.
pub const EXPLORERS_KEY: &str = "explorers";
/// Longest template in bytes.
pub const TEMPLATE_MAX_BYTES: usize = 256;
/// Most override entries kept (7 built-in EVM + 32 user chains + 2 Solana + 2 Bitcoin + 2 Zcash
/// + 2 `HyperCore` = 47).
pub const MAX_OVERRIDES: usize = 48;
/// Placeholder of the transaction template.
pub const HASH_PLACEHOLDER: &str = "{hash}";
/// Placeholder of the address template.
pub const ADDRESS_PLACEHOLDER: &str = "{address}";

/// A network with explorer links: the `NetworkId`s plus the `HyperCore` networks (not RPC
/// networks of their own, spec/11).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum ExplorerNet {
    /// `eip155:<chainId>` (built-in or user chain).
    Evm(u64),
    /// `solana:<cluster>`.
    Solana(SolCluster),
    /// `bitcoin:<net>`.
    Bitcoin(BtcNet),
    /// `zcash:<net>`.
    Zcash(ZecNetwork),
    /// `hypercore:mainnet` / `hypercore:testnet`.
    HyperCore(HcNetwork),
}

impl From<NetworkId> for ExplorerNet {
    fn from(network: NetworkId) -> Self {
        match network {
            NetworkId::Eip155(id) => Self::Evm(id),
            NetworkId::Solana(cluster) => Self::Solana(cluster),
            NetworkId::Bitcoin(net) => Self::Bitcoin(net),
            NetworkId::Zcash(net) => Self::Zcash(net),
        }
    }
}

impl From<HcNetwork> for ExplorerNet {
    fn from(network: HcNetwork) -> Self {
        Self::HyperCore(network)
    }
}

impl ExplorerNet {
    /// Parses the settings key (`NetworkId` text, or `hypercore:mainnet|testnet`).
    #[must_use]
    pub fn parse(text: &str) -> Option<Self> {
        if let Some(net) = text.strip_prefix("hypercore:") {
            return HcNetwork::parse(net).map(Self::HyperCore);
        }
        NetworkId::parse(text).map(Self::from)
    }

    /// The `NetworkId` (`None` for `HyperCore`).
    #[must_use]
    pub const fn network_id(self) -> Option<NetworkId> {
        match self {
            Self::Evm(id) => Some(NetworkId::Eip155(id)),
            Self::Solana(cluster) => Some(NetworkId::Solana(cluster)),
            Self::Bitcoin(net) => Some(NetworkId::Bitcoin(net)),
            Self::Zcash(net) => Some(NetworkId::Zcash(net)),
            Self::HyperCore(_) => None,
        }
    }

    /// The `HyperCore` id word (logs).
    #[must_use]
    pub const fn hypercore_word(network: HcNetwork) -> &'static str {
        match network {
            HcNetwork::Mainnet => "hypercore:mainnet",
            HcNetwork::Testnet => "hypercore:testnet",
        }
    }
}

impl fmt::Display for ExplorerNet {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match *self {
            Self::Evm(id) => fmt::Display::fmt(&NetworkId::Eip155(id), formatter),
            Self::Solana(cluster) => fmt::Display::fmt(&NetworkId::Solana(cluster), formatter),
            Self::Bitcoin(net) => fmt::Display::fmt(&NetworkId::Bitcoin(net), formatter),
            Self::Zcash(net) => fmt::Display::fmt(&NetworkId::Zcash(net), formatter),
            Self::HyperCore(network) => formatter.write_str(Self::hypercore_word(network)),
        }
    }
}

/// Which page a link opens.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LinkKind {
    /// A transaction (`{hash}`).
    Tx,
    /// An address (`{address}`).
    Address,
}

impl LinkKind {
    /// The placeholder of this kind's template.
    #[must_use]
    pub const fn placeholder(self) -> &'static str {
        match self {
            Self::Tx => HASH_PLACEHOLDER,
            Self::Address => ADDRESS_PLACEHOLDER,
        }
    }

    /// The settings JSON member name.
    #[must_use]
    pub const fn key(self) -> &'static str {
        match self {
            Self::Tx => "tx",
            Self::Address => "address",
        }
    }

    /// The field name on S15 in `lang`.
    #[must_use]
    pub const fn label_in(self, lang: Lang) -> &'static str {
        match self {
            Self::Tx => text::TX_PAGE,
            Self::Address => text::ADDRESS_PAGE,
        }
        .get(lang)
    }
}

/// The two templates of a network (either may be missing).
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Templates {
    /// Transaction page with `{hash}`.
    pub tx: Option<String>,
    /// Address page with `{address}`.
    pub address: Option<String>,
}

impl Templates {
    fn pair(tx: &str, address: &str) -> Self {
        Self {
            tx: Some(tx.to_owned()),
            address: Some(address.to_owned()),
        }
    }

    /// The template of `kind`.
    #[must_use]
    pub fn get(&self, kind: LinkKind) -> Option<&str> {
        match kind {
            LinkKind::Tx => self.tx.as_deref(),
            LinkKind::Address => self.address.as_deref(),
        }
    }

    /// `{base}/tx/{hash}` and `{base}/address/{address}` (the EVM explorers' common paths).
    #[must_use]
    pub fn from_base(base: &str) -> Self {
        let base = base.trim_end_matches('/');
        Self {
            tx: Some(format!("{base}/tx/{HASH_PLACEHOLDER}")),
            address: Some(format!("{base}/address/{ADDRESS_PLACEHOLDER}")),
        }
    }
}

/// One user override (settings `explorers`): at least one of the templates is set; a missing one
/// falls back to the default of its kind.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ExplorerOverride {
    /// The network.
    pub net: ExplorerNet,
    /// The overriding templates.
    pub templates: Templates,
}

/// The built-in default templates of `net` (2026-11-11, verified against each site): EVM from
/// the chain table's `explorer` (spec/03 §1.1; a user chain's own `explorer` is applied by
/// [`defaults`]), Solscan, mempool.space, the Zcash explorer of the Zcash community
/// (`zcashexplorer.app`; its testnet has transaction pages but no working address pages) and
/// Hyperliquid's own explorer.
#[must_use]
pub fn builtin_defaults(net: ExplorerNet) -> Templates {
    match net {
        ExplorerNet::Evm(id) => yw_core::evm::chain::builtin_chain(id)
            .and_then(|chain| chain.explorer)
            .map(|base| Templates::from_base(&base))
            .unwrap_or_default(),
        ExplorerNet::Solana(SolCluster::Mainnet) => Templates::pair(
            "https://solscan.io/tx/{hash}",
            "https://solscan.io/account/{address}",
        ),
        ExplorerNet::Solana(SolCluster::Devnet) => Templates::pair(
            "https://solscan.io/tx/{hash}?cluster=devnet",
            "https://solscan.io/account/{address}?cluster=devnet",
        ),
        ExplorerNet::Bitcoin(BtcNet::Mainnet) => Templates::pair(
            "https://mempool.space/tx/{hash}",
            "https://mempool.space/address/{address}",
        ),
        ExplorerNet::Bitcoin(BtcNet::Testnet4) => Templates::pair(
            "https://mempool.space/testnet4/tx/{hash}",
            "https://mempool.space/testnet4/address/{address}",
        ),
        ExplorerNet::Zcash(ZecNetwork::Mainnet) => Templates::pair(
            "https://mainnet.zcashexplorer.app/transactions/{hash}",
            "https://mainnet.zcashexplorer.app/address/{address}",
        ),
        ExplorerNet::Zcash(ZecNetwork::Testnet) => Templates {
            tx: Some("https://testnet.zcashexplorer.app/transactions/{hash}".to_owned()),
            address: None,
        },
        ExplorerNet::HyperCore(HcNetwork::Mainnet) => Templates::pair(
            "https://app.hyperliquid.xyz/explorer/tx/{hash}",
            "https://app.hyperliquid.xyz/explorer/address/{address}",
        ),
        ExplorerNet::HyperCore(HcNetwork::Testnet) => Templates::pair(
            "https://app.hyperliquid-testnet.xyz/explorer/tx/{hash}",
            "https://app.hyperliquid-testnet.xyz/explorer/address/{address}",
        ),
    }
}

/// The defaults of `net` with `user_explorer` — a user chain's own `explorer` base (spec/04
/// §2.17) — taking the place of the built-in ones.
#[must_use]
pub fn defaults(net: ExplorerNet, user_explorer: Option<&str>) -> Templates {
    match (net, user_explorer) {
        (ExplorerNet::Evm(_), Some(base)) => Templates::from_base(base),
        _ => builtin_defaults(net),
    }
}

/// The templates in use: the override of each kind, else the default.
#[must_use]
pub fn effective(defaults: &Templates, entry: Option<&ExplorerOverride>) -> Templates {
    let pick = |kind: LinkKind| {
        entry
            .and_then(|entry| entry.templates.get(kind))
            .or_else(|| defaults.get(kind))
            .map(str::to_owned)
    };
    Templates {
        tx: pick(LinkKind::Tx),
        address: pick(LinkKind::Address),
    }
}

/// Why a template was refused (S15 message, settings banner).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TemplateError {
    /// Longer than [`TEMPLATE_MAX_BYTES`].
    TooLong,
    /// Not `https://`.
    NotHttps,
    /// A `#` fragment.
    Fragment,
    /// A `user@` part.
    Userinfo,
    /// The placeholder missing, twice, or the other kind's.
    Placeholder(LinkKind),
    /// The placeholder inside the host.
    PlaceholderInHost(LinkKind),
    /// A character outside the allowed set.
    Character,
    /// Not a valid HTTPS URL (host, port).
    Url,
}

impl TemplateError {
    /// The user text in `lang`.
    #[must_use]
    pub fn text_in(self, lang: Lang) -> String {
        match self {
            Self::TooLong => text::TOO_LONG.fill(lang, [&TEMPLATE_MAX_BYTES.to_string()]),
            Self::NotHttps => text::NOT_HTTPS.get(lang).to_owned(),
            Self::Fragment => text::FRAGMENT.get(lang).to_owned(),
            Self::Userinfo => text::USERINFO.get(lang).to_owned(),
            Self::Placeholder(kind) => text::PLACEHOLDER.fill(lang, [kind.placeholder()]),
            Self::PlaceholderInHost(kind) => {
                text::PLACEHOLDER_IN_HOST.fill(lang, [kind.placeholder()])
            }
            Self::Character => text::CHARACTER.get(lang).to_owned(),
            Self::Url => text::URL.get(lang).to_owned(),
        }
    }
}

/// Explorer template texts of S15 (spec/04 §2.11; English spec/14 §5).
pub mod text {
    yw_core::texts! {
        TX_PAGE = "거래 페이지" / "Transaction page";
        ADDRESS_PAGE = "주소 페이지" / "Address page";
        TOO_LONG(1) = "{0}자를 넘습니다." / "Longer than {0} characters.";
        NOT_HTTPS = "https:// 로 시작해야 합니다." / "Must start with https://.";
        FRAGMENT = "# 뒤 부분(fragment)은 넣을 수 없습니다."
            / "A part after # (fragment) is not allowed.";
        USERINFO = "사용자 정보(…@)는 넣을 수 없습니다." / "User info (…@) is not allowed.";
        PLACEHOLDER(1) = "{0}를 정확히 한 번 넣고, 다른 {…}는 넣지 마세요."
            / "Put {0} in exactly once, and no other {…}.";
        PLACEHOLDER_IN_HOST(1) = "{0}는 호스트 이름 뒤(경로나 ? 뒤)에 있어야 합니다."
            / "{0} must come after the host name (in the path or after ?).";
        CHARACTER = "쓸 수 없는 문자가 있습니다(영문·숫자와 - . _ ~ : / ? & = + 만)."
            / "Contains characters that are not allowed (only letters, digits and - . _ ~ : / ? & = +).";
        URL = "올바른 https 주소가 아닙니다(호스트 이름을 확인하세요)."
            / "Not a valid https address (check the host name).";
    }
}

/// The characters a template may hold besides its placeholder: no spaces, quotes, `%`, `,`,
/// `;` or anything a command line could read differently (`explorer.exe` gets the URL as its
/// argument, spec/04 §2.14).
fn template_byte_ok(byte: u8) -> bool {
    byte.is_ascii_alphanumeric()
        || matches!(
            byte,
            b'-' | b'.' | b'_' | b'~' | b':' | b'/' | b'?' | b'&' | b'=' | b'+'
        )
}

/// Validates a template of `kind` (spec/04 §2.11 "블록 탐색기"): `https://` only, no userinfo
/// or fragment, the kind's placeholder exactly once and after the host, no other `{`/`}`, only
/// the bytes of [`template_byte_ok`], ≤ [`TEMPLATE_MAX_BYTES`], and a valid HTTPS URL once the
/// placeholder is filled. Returns the text without surrounding whitespace.
///
/// # Errors
///
/// The first rule broken.
pub fn validate_template(text: &str, kind: LinkKind) -> Result<String, TemplateError> {
    let text = text.trim();
    if text.len() > TEMPLATE_MAX_BYTES {
        return Err(TemplateError::TooLong);
    }
    let Some(rest) = text.strip_prefix("https://") else {
        return Err(TemplateError::NotHttps);
    };
    if text.contains('#') {
        return Err(TemplateError::Fragment);
    }
    let authority = rest
        .find(['/', '?'])
        .map_or(rest, |end| rest.get(..end).unwrap_or(rest));
    if authority.contains('@') {
        return Err(TemplateError::Userinfo);
    }
    if authority.contains('{') {
        return Err(TemplateError::PlaceholderInHost(kind));
    }
    let placeholder = kind.placeholder();
    if text.matches(placeholder).count() != 1 {
        return Err(TemplateError::Placeholder(kind));
    }
    let without = text.replacen(placeholder, "", 1);
    if without.contains(['{', '}']) {
        return Err(TemplateError::Placeholder(kind));
    }
    if !without.bytes().all(template_byte_ok) {
        return Err(TemplateError::Character);
    }
    if HttpsUrl::parse(&text.replacen(placeholder, "0", 1)).is_err() {
        return Err(TemplateError::Url);
    }
    Ok(text.to_owned())
}

fn is_hex(text: &str) -> bool {
    !text.is_empty() && text.bytes().all(|byte| byte.is_ascii_hexdigit())
}

fn is_0x_hex(text: &str, digits: usize) -> bool {
    text.len() == digits.saturating_add(2)
        && text
            .strip_prefix("0x")
            .or_else(|| text.strip_prefix("0X"))
            .is_some_and(is_hex)
}

fn is_base58(text: &str) -> bool {
    !text.is_empty()
        && text.bytes().all(|byte| {
            matches!(byte, b'1'..=b'9' | b'A'..=b'H' | b'J'..=b'N' | b'P'..=b'Z' | b'a'..=b'k' | b'm'..=b'z')
        })
}

/// Lowercase bech32/bech32m shape: `hrp` `1` data, data from the bech32 alphabet.
fn is_bech32(text: &str) -> bool {
    const DATA: &[u8] = b"qpzry9x8gf2tvdw0s3jn54khce6mua7l";
    let Some((hrp, data)) = text.rsplit_once('1') else {
        return false;
    };
    !hrp.is_empty()
        && hrp
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit())
        && data.len() >= 6
        && data.bytes().all(|byte| DATA.contains(&byte))
}

/// Whether `value` has the character set and length of a `kind` value on `net`: hex for EVM /
/// `HyperCore` hashes and addresses and for Bitcoin / Zcash txids, base58 for Solana and
/// base58 or bech32 for Bitcoin / Zcash addresses. Checked before it goes into a URL.
#[must_use]
pub fn value_ok(net: ExplorerNet, kind: LinkKind, value: &str) -> bool {
    let length = value.len();
    match (net, kind) {
        (ExplorerNet::Evm(_) | ExplorerNet::HyperCore(_), LinkKind::Tx) => is_0x_hex(value, 64),
        (ExplorerNet::Evm(_) | ExplorerNet::HyperCore(_), LinkKind::Address) => {
            is_0x_hex(value, 40)
        }
        (ExplorerNet::Solana(_), LinkKind::Tx) => (64..=90).contains(&length) && is_base58(value),
        (ExplorerNet::Solana(_), LinkKind::Address) => {
            (32..=44).contains(&length) && is_base58(value)
        }
        (ExplorerNet::Bitcoin(_) | ExplorerNet::Zcash(_), LinkKind::Tx) => {
            length == 64 && is_hex(value)
        }
        (ExplorerNet::Bitcoin(_), LinkKind::Address) => {
            ((25..=35).contains(&length) && is_base58(value))
                || ((14..=90).contains(&length) && is_bech32(value))
        }
        (ExplorerNet::Zcash(_), LinkKind::Address) => {
            ((26..=40).contains(&length) && is_base58(value))
                || ((14..=90).contains(&length) && is_bech32(value))
        }
    }
}

/// The URL of `value` on `net`: only from a template that passes [`validate_template`] and a
/// value that passes [`value_ok`]; the result is checked once more as an HTTPS URL. `None`
/// otherwise (no link is shown or opened).
#[must_use]
pub fn build_url(template: &str, net: ExplorerNet, kind: LinkKind, value: &str) -> Option<String> {
    if !value_ok(net, kind, value) {
        return None;
    }
    let template = validate_template(template, kind).ok()?;
    let url = template.replacen(kind.placeholder(), value, 1);
    HttpsUrl::parse(&url)
        .ok()
        .map(|url| url.expose().to_owned())
}

/// The host of a built URL (the information band after opening it; not secret).
#[must_use]
pub fn url_host(url: &str) -> Option<String> {
    HttpsUrl::parse(url).ok().map(|url| url.host().to_owned())
}

/// The settings JSON of the overrides (`{"<net>": {"tx": …, "address": …}}`, set members only).
#[must_use]
pub fn overrides_json(entries: &[ExplorerOverride]) -> Value {
    json_object_owned(
        entries
            .iter()
            .map(|entry| {
                let mut members = Vec::new();
                for kind in [LinkKind::Tx, LinkKind::Address] {
                    if let Some(template) = entry.templates.get(kind) {
                        members.push((kind.key(), json_str(template)));
                    }
                }
                (entry.net.to_string(), json_object(members))
            })
            .collect(),
    )
    .unwrap_or_else(|| json_object(Vec::new()))
}

/// One entry: an object with `tx` and/or `address`, each a template exactly as
/// [`validate_template`] returns it.
fn parse_entry(net: ExplorerNet, value: &Value) -> Option<ExplorerOverride> {
    let object = value.as_object()?;
    if object.is_empty() || object.keys().any(|key| !matches!(key, "tx" | "address")) {
        return None;
    }
    let mut templates = Templates::default();
    for kind in [LinkKind::Tx, LinkKind::Address] {
        if let Some(member) = object.get(kind.key()) {
            let text = member.as_str()?;
            let checked = validate_template(text, kind).ok()?;
            if checked != text {
                return None;
            }
            match kind {
                LinkKind::Tx => templates.tx = Some(checked),
                LinkKind::Address => templates.address = Some(checked),
            }
        }
    }
    Some(ExplorerOverride { net, templates })
}

/// Reads the `explorers` value: entry by entry, a bad entry (unknown network, unknown member,
/// a template that fails validation, beyond [`MAX_OVERRIDES`]) is dropped with the banner
/// `explorers.<key>`; a value that is not an object is dropped whole (`explorers`).
pub fn load_overrides(value: &Value, banners: &mut Vec<String>) -> Vec<ExplorerOverride> {
    let Some(object) = value.as_object() else {
        banners.push(EXPLORERS_KEY.to_owned());
        return Vec::new();
    };
    let mut entries: Vec<ExplorerOverride> = Vec::new();
    for (key, entry) in object.iter() {
        let parsed = (entries.len() < MAX_OVERRIDES)
            .then(|| ExplorerNet::parse(key))
            .flatten()
            .and_then(|net| parse_entry(net, entry));
        match parsed {
            Some(entry) => entries.push(entry),
            None => banners.push(format!("{EXPLORERS_KEY}.{key}")),
        }
    }
    entries
}

#[cfg(test)]
mod tests {
    use yw_core::hypercore::HcNetwork;
    use yw_core::zec::ZecNetwork;

    use super::{
        ExplorerNet, ExplorerOverride, LinkKind, TemplateError, Templates, build_url,
        builtin_defaults, defaults, effective, validate_template, value_ok,
    };
    use crate::network::{BtcNet, NetworkId, SolCluster};

    const EVM_HASH: &str = "0x7a329aaf9f457ef8516d5a51631fe5a75e3c12d7d71b6a73a38ce42ad352de2d";
    const EVM_ADDRESS: &str = "0xF9900bb6FF2D2C67858c3468d21c5f103C4Ff646";
    const SOL_SIGNATURE: &str =
        "4FvcgLnb7wfoxUsijPfmFDHB9SVM8oLbdd3ovy9VDtS3W8ZvW362jBGYk79HNc5W8JPC38DFac46eDzzKiQtqHGQ";
    const SOL_ADDRESS: &str = "So11111111111111111111111111111111111111112";
    const TXID: &str = "f37e9f691fffb635de0999491d906ee85ba40cd36dae9f6e5911a8277d7c5f75";

    fn url(net: ExplorerNet, kind: LinkKind, value: &str) -> Option<String> {
        let templates = builtin_defaults(net);
        build_url(templates.get(kind)?, net, kind, value)
    }

    #[test]
    fn defaults_build_the_documented_urls() {
        let tx = LinkKind::Tx;
        let address = LinkKind::Address;
        assert_eq!(
            url(ExplorerNet::Evm(1), tx, EVM_HASH).as_deref(),
            Some(format!("https://etherscan.io/tx/{EVM_HASH}").as_str())
        );
        assert_eq!(
            url(ExplorerNet::Evm(11_155_111), address, EVM_ADDRESS).as_deref(),
            Some(format!("https://sepolia.etherscan.io/address/{EVM_ADDRESS}").as_str())
        );
        assert_eq!(
            url(ExplorerNet::Evm(999), tx, EVM_HASH).as_deref(),
            Some(format!("https://hyperevmscan.io/tx/{EVM_HASH}").as_str())
        );
        assert_eq!(
            url(ExplorerNet::Solana(SolCluster::Mainnet), tx, SOL_SIGNATURE).as_deref(),
            Some(format!("https://solscan.io/tx/{SOL_SIGNATURE}").as_str())
        );
        assert_eq!(
            url(
                ExplorerNet::Solana(SolCluster::Devnet),
                address,
                SOL_ADDRESS
            )
            .as_deref(),
            Some(format!("https://solscan.io/account/{SOL_ADDRESS}?cluster=devnet").as_str())
        );
        assert_eq!(
            url(ExplorerNet::Bitcoin(BtcNet::Mainnet), tx, TXID).as_deref(),
            Some(format!("https://mempool.space/tx/{TXID}").as_str())
        );
        assert_eq!(
            url(
                ExplorerNet::Bitcoin(BtcNet::Testnet4),
                address,
                "tb1qerzrlxcfu24davlur5sqmgzzgsal6wusda40er"
            )
            .as_deref(),
            Some(
                "https://mempool.space/testnet4/address/tb1qerzrlxcfu24davlur5sqmgzzgsal6wusda40er"
            )
        );
        assert_eq!(
            url(
                ExplorerNet::Zcash(ZecNetwork::Mainnet),
                address,
                "t1WT7Mfa3BEHhs2cS63ZBusybeVntsHGNHF"
            )
            .as_deref(),
            Some("https://mainnet.zcashexplorer.app/address/t1WT7Mfa3BEHhs2cS63ZBusybeVntsHGNHF")
        );
        assert_eq!(
            url(ExplorerNet::Zcash(ZecNetwork::Testnet), tx, TXID).as_deref(),
            Some(format!("https://testnet.zcashexplorer.app/transactions/{TXID}").as_str())
        );
        // The Zcash testnet explorer has no working address pages: no default.
        assert_eq!(
            url(
                ExplorerNet::Zcash(ZecNetwork::Testnet),
                address,
                "tmTwLU5Y855hfBZ25ZaWuTvcrqjrCMFAZR9"
            ),
            None
        );
        assert_eq!(
            url(
                ExplorerNet::HyperCore(HcNetwork::Mainnet),
                address,
                EVM_ADDRESS
            )
            .as_deref(),
            Some(format!("https://app.hyperliquid.xyz/explorer/address/{EVM_ADDRESS}").as_str())
        );
        assert_eq!(
            url(ExplorerNet::HyperCore(HcNetwork::Testnet), tx, EVM_HASH).as_deref(),
            Some(format!("https://app.hyperliquid-testnet.xyz/explorer/tx/{EVM_HASH}").as_str())
        );
    }

    #[test]
    fn every_default_passes_its_own_validation() {
        let mut nets: Vec<ExplorerNet> = crate::network::BUILTIN_EVM
            .iter()
            .map(|id| ExplorerNet::Evm(*id))
            .collect();
        nets.extend([
            ExplorerNet::Solana(SolCluster::Mainnet),
            ExplorerNet::Solana(SolCluster::Devnet),
            ExplorerNet::Bitcoin(BtcNet::Mainnet),
            ExplorerNet::Bitcoin(BtcNet::Testnet4),
            ExplorerNet::Zcash(ZecNetwork::Mainnet),
            ExplorerNet::Zcash(ZecNetwork::Testnet),
            ExplorerNet::HyperCore(HcNetwork::Mainnet),
            ExplorerNet::HyperCore(HcNetwork::Testnet),
        ]);
        for net in nets {
            let templates = builtin_defaults(net);
            assert!(templates.tx.is_some(), "{net}");
            for kind in [LinkKind::Tx, LinkKind::Address] {
                if let Some(template) = templates.get(kind) {
                    assert_eq!(validate_template(template, kind).as_deref(), Ok(template));
                }
            }
        }
    }

    #[test]
    fn user_chains_use_their_explorer_and_overrides_win_per_kind() {
        let net = ExplorerNet::Evm(10);
        assert_eq!(builtin_defaults(net), Templates::default());
        let base = defaults(net, Some("https://optimistic.etherscan.io"));
        assert_eq!(
            base.tx.as_deref(),
            Some("https://optimistic.etherscan.io/tx/{hash}")
        );
        let entry = ExplorerOverride {
            net,
            templates: Templates {
                tx: None,
                address: Some("https://scan.example/addr/{address}?tab=txs".to_owned()),
            },
        };
        let used = effective(&base, Some(&entry));
        assert_eq!(used.tx, base.tx);
        assert_eq!(
            build_url(
                used.address.as_deref().unwrap(),
                net,
                LinkKind::Address,
                EVM_ADDRESS
            )
            .as_deref(),
            Some(format!("https://scan.example/addr/{EVM_ADDRESS}?tab=txs").as_str())
        );
        // A built-in chain's user override replaces its default.
        let mainnet = ExplorerOverride {
            net: ExplorerNet::Evm(1),
            templates: Templates {
                tx: Some("https://eth.blockscout.com/tx/{hash}".to_owned()),
                address: None,
            },
        };
        let used = effective(&builtin_defaults(ExplorerNet::Evm(1)), Some(&mainnet));
        assert_eq!(
            used.tx.as_deref(),
            Some("https://eth.blockscout.com/tx/{hash}")
        );
        assert_eq!(
            used.address.as_deref(),
            Some("https://etherscan.io/address/{address}")
        );
        assert_eq!(
            ExplorerNet::from(NetworkId::Eip155(10)).to_string(),
            "eip155:10"
        );
        assert_eq!(
            ExplorerNet::parse("hypercore:testnet"),
            Some(ExplorerNet::HyperCore(HcNetwork::Testnet))
        );
        assert_eq!(ExplorerNet::parse("hypercore:devnet"), None);
    }

    #[test]
    fn template_rules() {
        let tx = LinkKind::Tx;
        assert_eq!(
            validate_template("  https://scan.example/tx/{hash}  ", tx).as_deref(),
            Ok("https://scan.example/tx/{hash}")
        );
        assert_eq!(
            validate_template("https://scan.example/search?q={hash}&x=1", tx).as_deref(),
            Ok("https://scan.example/search?q={hash}&x=1")
        );
        let refused = [
            ("http://scan.example/tx/{hash}", TemplateError::NotHttps),
            ("scan.example/tx/{hash}", TemplateError::NotHttps),
            (
                "https://scan.example/tx/{hash}#top",
                TemplateError::Fragment,
            ),
            ("https://me@scan.example/tx/{hash}", TemplateError::Userinfo),
            (
                "https://{hash}.scan.example/",
                TemplateError::PlaceholderInHost(tx),
            ),
            ("https://scan.example/tx/", TemplateError::Placeholder(tx)),
            (
                "https://scan.example/{hash}/{hash}",
                TemplateError::Placeholder(tx),
            ),
            (
                "https://scan.example/{address}",
                TemplateError::Placeholder(tx),
            ),
            (
                "https://scan.example/tx/{hash}/{x}",
                TemplateError::Placeholder(tx),
            ),
            (
                "https://scan.example/tx/{hash} ok",
                TemplateError::Character,
            ),
            (
                "https://scan.example/tx/{hash}%20",
                TemplateError::Character,
            ),
            ("https://scan.example/tx/{hash},1", TemplateError::Character),
            ("https://scan.example/tx/\"{hash}", TemplateError::Character),
            ("https://scan_example/tx/{hash}", TemplateError::Url),
            ("https://scan.example:0/tx/{hash}", TemplateError::Url),
        ];
        for (text, error) in refused {
            assert_eq!(validate_template(text, tx), Err(error), "{text}");
        }
        let long = format!("https://scan.example/{}/{{hash}}", "a".repeat(240));
        assert_eq!(validate_template(&long, tx), Err(TemplateError::TooLong));
        assert_eq!(
            validate_template("https://scan.example/a/{address}", LinkKind::Address).as_deref(),
            Ok("https://scan.example/a/{address}")
        );
    }

    #[test]
    fn values_outside_their_charset_are_refused() {
        let evm = ExplorerNet::Evm(1);
        let template = "https://scan.example/tx/{hash}";
        assert!(build_url(template, evm, LinkKind::Tx, EVM_HASH).is_some());
        for bad in [
            "",
            "0x",
            "7a329aaf9f457ef8516d5a51631fe5a75e3c12d7d71b6a73a38ce42ad352de2d",
            "0x7a329aaf9f457ef8516d5a51631fe5a75e3c12d7d71b6a73a38ce42ad352de2",
            "0x7a329aaf9f457ef8516d5a51631fe5a75e3c12d7d71b6a73a38ce42ad352de2g",
            "0x7a329aaf9f457ef8516d5a51631fe5a75e3c12d7d71b6a73a38ce42ad352de/?",
            "0x7a329aaf9f457ef8516d5a51631fe5a75e3c12d7d71b6a73a38ce42ad3&x=1#",
        ] {
            assert_eq!(build_url(template, evm, LinkKind::Tx, bad), None, "{bad}");
        }
        assert!(!value_ok(evm, LinkKind::Address, EVM_HASH));
        let sol = ExplorerNet::Solana(SolCluster::Mainnet);
        assert!(value_ok(sol, LinkKind::Tx, SOL_SIGNATURE));
        assert!(value_ok(sol, LinkKind::Address, SOL_ADDRESS));
        // base58 has no 0, O, I or l; nothing else of a URL either.
        assert!(!value_ok(
            sol,
            LinkKind::Address,
            "So1111111111111111111111111111111111111110"
        ));
        assert!(!value_ok(
            sol,
            LinkKind::Address,
            "So11111111111111111111111111111111111111/1"
        ));
        assert!(!value_ok(sol, LinkKind::Tx, SOL_ADDRESS));
        let btc = ExplorerNet::Bitcoin(BtcNet::Mainnet);
        assert!(value_ok(btc, LinkKind::Tx, TXID));
        assert!(!value_ok(btc, LinkKind::Tx, &format!("0x{TXID}")));
        assert!(value_ok(
            btc,
            LinkKind::Address,
            "bc1qar0srrr7xfkvy5l643lydnw9re59gtzzwf5mdq"
        ));
        assert!(value_ok(
            btc,
            LinkKind::Address,
            "1BvBMSEYstWetqTFn5Au4m4GFg7xJaNVN2"
        ));
        assert!(!value_ok(
            btc,
            LinkKind::Address,
            "BC1QAR0SRRR7XFKVY5L643LYDNW9RE59GTZZWF5MDQ"
        ));
        assert!(!value_ok(
            btc,
            LinkKind::Address,
            "bc1qar0srrr7xfkvy5l643lydnw9re59gtzzwf5mdb"
        ));
        let zec = ExplorerNet::Zcash(ZecNetwork::Mainnet);
        assert!(value_ok(
            zec,
            LinkKind::Address,
            "t1WT7Mfa3BEHhs2cS63ZBusybeVntsHGNHF"
        ));
        assert!(!value_ok(
            zec,
            LinkKind::Address,
            "t1WT7Mfa3BEHhs2cS63Z?usybeVntsHGNHF"
        ));
        assert!(!value_ok(zec, LinkKind::Tx, &TXID.replace('f', "_")));
        let hc = ExplorerNet::HyperCore(HcNetwork::Mainnet);
        assert!(value_ok(hc, LinkKind::Address, EVM_ADDRESS));
        assert!(!value_ok(hc, LinkKind::Address, SOL_ADDRESS));
        // A template that does not validate never builds a URL.
        assert_eq!(
            build_url(
                "https://scan.example/tx/{hash}#x",
                evm,
                LinkKind::Tx,
                EVM_HASH
            ),
            None
        );
    }

    #[test]
    fn settings_keep_overrides_only_in_their_own_top_level_key() {
        use crate::settings::{Settings, load};
        // No override: the key is not written.
        let plain = Settings::default().to_json();
        let mut text = String::from_utf8(plain).unwrap();
        assert!(!text.contains(super::EXPLORERS_KEY));
        text.pop();
        text.push_str(
            r#","explorers":{"eip155:1":{"tx":"https://eth.blockscout.com/tx/{hash}"},"hypercore:testnet":{"address":"https://hypurrscan.io/address/{address}"},"solana:testnet":{"tx":"https://x.example/{hash}"},"eip155:56":{"tx":"http://bscscan.com/tx/{hash}"},"bitcoin:mainnet":{"tx":"https://m.example/tx/{hash}","extra":"x"},"zcash:mainnet":{},"eip155:8453":{"tx":" https://basescan.org/tx/{hash}"}},"uiTheme":"dark"}"#,
        );
        let loaded = load(Some(text.as_bytes()));
        assert_eq!(
            loaded.banners,
            [
                "explorers.solana:testnet",
                "explorers.eip155:56",
                "explorers.bitcoin:mainnet",
                "explorers.zcash:mainnet",
                "explorers.eip155:8453",
            ]
        );
        assert_eq!(
            loaded.settings.explorers,
            [
                ExplorerOverride {
                    net: ExplorerNet::Evm(1),
                    templates: Templates {
                        tx: Some("https://eth.blockscout.com/tx/{hash}".to_owned()),
                        address: None,
                    },
                },
                ExplorerOverride {
                    net: ExplorerNet::HyperCore(HcNetwork::Testnet),
                    templates: Templates {
                        tx: None,
                        address: Some("https://hypurrscan.io/address/{address}".to_owned()),
                    },
                },
            ]
        );
        // Not kept twice: only the other unknown key goes back after the known ones.
        assert_eq!(loaded.settings.compat.unknown_keys(), ["uiTheme"]);
        let written = loaded.settings.to_json();
        let again = load(Some(&written));
        assert!(again.banners.is_empty());
        assert_eq!(again.settings, loaded.settings);
        let written = String::from_utf8(written).unwrap();
        assert!(written.ends_with(
            r#","explorers":{"eip155:1":{"tx":"https://eth.blockscout.com/tx/{hash}"},"hypercore:testnet":{"address":"https://hypurrscan.io/address/{address}"}},"uiTheme":"dark"}"#
        ));
        // A value that is not an object is dropped whole.
        let broken = written.replace(
            r#""explorers":{"eip155:1":{"tx":"https://eth.blockscout.com/tx/{hash}"},"hypercore:testnet":{"address":"https://hypurrscan.io/address/{address}"}}"#,
            r#""explorers":[]"#,
        );
        let loaded = load(Some(broken.as_bytes()));
        assert_eq!(loaded.banners, ["explorers"]);
        assert!(loaded.settings.explorers.is_empty());
    }
}
