//! `apikeys.dpapi` (spec/04 §6.3, D13): per-network RPC endpoint URLs (`rpc:<NetworkId>`),
//! provider template credentials (`tpl:quicknode`, `tpl:alchemy`) and the LLM key (`llm`),
//! encrypted with DPAPI for the current user. A whole URL is a secret (token in the path, endpoint
//! name in the host): values are never logged or displayed; screens use [`mask_url`].
//!
//! Also the pure helpers of spec/04 §2.11.1: [`template_url`] and [`mask_url`].

use core::fmt;

use yw_core::evm::chain::builtin_chain;
use yw_core::secret::Zeroizing;
use yw_win::http::HttpsUrl;

use crate::network::{BtcNet, NetworkId, SolCluster};
use crate::settings::{RpcTemplate, Settings};
use crate::text::{is_dns_label, is_token_text};

/// DPAPI optional entropy.
pub const APIKEYS_ENTROPY: &[u8] = b"your-wallet/v3/apikeys";
/// Plaintext magic.
pub const APIKEYS_MAGIC: &[u8; 8] = b"YWAPIK01";
/// Largest plaintext.
pub const APIKEYS_MAX_PLAINTEXT: usize = 131_072;
/// Largest entry count.
pub const APIKEYS_MAX_ENTRIES: usize = 48;
const MAX_NAME: usize = 32;
const MAX_VALUE: usize = 2_048;

/// Entry name.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum KeyName {
    /// `rpc:<NetworkId>`.
    Rpc(NetworkId),
    /// `tpl:quicknode`.
    TplQuickNode,
    /// `tpl:alchemy`.
    TplAlchemy,
    /// `llm`.
    Llm,
}

impl fmt::Display for KeyName {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Rpc(network) => write!(formatter, "rpc:{network}"),
            Self::TplQuickNode => formatter.write_str("tpl:quicknode"),
            Self::TplAlchemy => formatter.write_str("tpl:alchemy"),
            Self::Llm => formatter.write_str("llm"),
        }
    }
}

impl KeyName {
    fn parse(text: &str) -> Option<Self> {
        match text {
            "tpl:quicknode" => Some(Self::TplQuickNode),
            "tpl:alchemy" => Some(Self::TplAlchemy),
            "llm" => Some(Self::Llm),
            _ => text
                .strip_prefix("rpc:")
                .and_then(NetworkId::parse)
                .map(Self::Rpc),
        }
    }
}

/// Plaintext format error (E-KEY-001; every entry is then treated as absent).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ApiKeysFormatError;

impl fmt::Display for ApiKeysFormatError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("apikeys plaintext format error")
    }
}

impl std::error::Error for ApiKeysFormatError {}

/// `QuickNode` endpoint name check (`^[a-z0-9]+(-[a-z0-9]+)*$`, 1–63) after lowercasing.
#[must_use]
pub fn valid_quicknode_name(name: &str) -> bool {
    is_dns_label(name)
}

/// `QuickNode` token / Alchemy key check (`^[A-Za-z0-9_-]{16,128}$`).
#[must_use]
pub fn valid_provider_token(token: &str) -> bool {
    is_token_text(token, 16, 128)
}

fn valid_value(name: KeyName, value: &str) -> bool {
    match name {
        KeyName::Rpc(_) => HttpsUrl::parse(value).is_ok_and(|url| url.expose() == value),
        KeyName::TplQuickNode => value.split_once(':').is_some_and(|(endpoint, token)| {
            valid_quicknode_name(endpoint) && valid_provider_token(token)
        }),
        KeyName::TplAlchemy => valid_provider_token(value),
        KeyName::Llm => {
            (1..=512).contains(&value.len())
                && value.bytes().all(|byte| (0x21..=0x7E).contains(&byte))
        }
    }
}

/// The decrypted entries, owned by the UI thread (spec/04 §6.3).
#[derive(Default)]
pub struct ApiKeys {
    entries: Vec<(KeyName, Zeroizing<String>)>,
}

impl fmt::Debug for ApiKeys {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let names: Vec<String> = self
            .entries
            .iter()
            .map(|(name, _)| name.to_string())
            .collect();
        formatter
            .debug_struct("ApiKeys")
            .field("names", &names)
            .finish()
    }
}

/// Decoding result: entries plus the names of ignored orphan `rpc:eip155:*` entries.
#[derive(Debug)]
pub struct Decoded {
    /// Registered entries.
    pub keys: ApiKeys,
    /// Orphans (logged by name, dropped at the next save).
    pub orphans: Vec<KeyName>,
}

struct Reader<'a> {
    bytes: &'a [u8],
    at: usize,
}

impl<'a> Reader<'a> {
    fn take(&mut self, len: usize) -> Option<&'a [u8]> {
        let end = self.at.checked_add(len)?;
        let slice = self.bytes.get(self.at..end)?;
        self.at = end;
        Some(slice)
    }

    fn byte(&mut self) -> Option<u8> {
        self.take(1)?.first().copied()
    }
}

impl ApiKeys {
    /// Decodes the plaintext. `registered(network)` answers whether an `rpc:` network is known
    /// (built-in, user EVM chain from settings, Solana, Bitcoin); unknown `rpc:eip155:*` entries are
    /// orphans and dropped.
    ///
    /// # Errors
    ///
    /// [`ApiKeysFormatError`] for any format violation (all entries then count as absent).
    pub fn decode(
        plain: &[u8],
        registered: &dyn Fn(NetworkId) -> bool,
    ) -> Result<Decoded, ApiKeysFormatError> {
        if plain.len() > APIKEYS_MAX_PLAINTEXT {
            return Err(ApiKeysFormatError);
        }
        let mut reader = Reader {
            bytes: plain,
            at: 0,
        };
        if reader.take(8) != Some(APIKEYS_MAGIC.as_slice()) {
            return Err(ApiKeysFormatError);
        }
        let count = usize::from(reader.byte().ok_or(ApiKeysFormatError)?);
        if count > APIKEYS_MAX_ENTRIES {
            return Err(ApiKeysFormatError);
        }
        let mut keys = ApiKeys::default();
        let mut orphans = Vec::new();
        let mut seen: Vec<KeyName> = Vec::new();
        for _ in 0..count {
            let name_len = usize::from(reader.byte().ok_or(ApiKeysFormatError)?);
            if !(1..=MAX_NAME).contains(&name_len) {
                return Err(ApiKeysFormatError);
            }
            let name_bytes = reader.take(name_len).ok_or(ApiKeysFormatError)?;
            let name = core::str::from_utf8(name_bytes)
                .ok()
                .and_then(KeyName::parse)
                .ok_or(ApiKeysFormatError)?;
            if seen.contains(&name) {
                return Err(ApiKeysFormatError);
            }
            seen.push(name);
            let length_bytes = reader.take(2).ok_or(ApiKeysFormatError)?;
            let value_len = usize::from(u16::from_be_bytes(
                length_bytes.try_into().map_err(|_| ApiKeysFormatError)?,
            ));
            if !(1..=MAX_VALUE).contains(&value_len) {
                return Err(ApiKeysFormatError);
            }
            let value_bytes = reader.take(value_len).ok_or(ApiKeysFormatError)?;
            let value = core::str::from_utf8(value_bytes).map_err(|_| ApiKeysFormatError)?;
            if !valid_value(name, value) {
                return Err(ApiKeysFormatError);
            }
            if let KeyName::Rpc(network) = name
                && !registered(network)
            {
                orphans.push(name);
                continue;
            }
            let mut owned = Zeroizing::new(String::with_capacity(value.len()));
            owned.push_str(value);
            keys.entries.push((name, owned));
        }
        if reader.at != plain.len() {
            return Err(ApiKeysFormatError);
        }
        Ok(Decoded { keys, orphans })
    }

    /// Builds the plaintext from the current entries.
    #[must_use]
    pub fn encode(&self) -> Zeroizing<Vec<u8>> {
        let mut out = Zeroizing::new(Vec::with_capacity(
            self.entries
                .iter()
                .map(|(_, value)| value.len().saturating_add(40))
                .sum::<usize>()
                .saturating_add(9),
        ));
        out.extend_from_slice(APIKEYS_MAGIC);
        out.push(u8::try_from(self.entries.len()).unwrap_or(0));
        for (name, value) in &self.entries {
            let name = name.to_string();
            out.push(u8::try_from(name.len()).unwrap_or(0));
            out.extend_from_slice(name.as_bytes());
            out.extend_from_slice(&u16::try_from(value.len()).unwrap_or(0).to_be_bytes());
            out.extend_from_slice(value.as_bytes());
        }
        out
    }

    fn get(&self, name: KeyName) -> Option<&str> {
        self.entries
            .iter()
            .find(|(entry, _)| *entry == name)
            .map(|(_, value)| value.as_str())
    }

    fn set(&mut self, name: KeyName, value: &str) {
        let mut owned = Zeroizing::new(String::with_capacity(value.len()));
        owned.push_str(value);
        if let Some(slot) = self.entries.iter_mut().find(|(entry, _)| *entry == name) {
            slot.1 = owned;
        } else {
            self.entries.push((name, owned));
        }
    }

    /// Removes an entry; returns whether it existed.
    pub fn remove(&mut self, name: KeyName) -> bool {
        let before = self.entries.len();
        self.entries.retain(|(entry, _)| *entry != name);
        before != self.entries.len()
    }

    /// Whether `name` is stored.
    #[must_use]
    pub fn has(&self, name: KeyName) -> bool {
        self.get(name).is_some()
    }

    /// The stored endpoint URL of `network`.
    #[must_use]
    pub fn rpc_url(&self, network: NetworkId) -> Option<HttpsUrl> {
        self.get(KeyName::Rpc(network))
            .and_then(|text| HttpsUrl::parse(text).ok())
    }

    /// Stores the endpoint URL of `network`.
    pub fn set_rpc(&mut self, network: NetworkId, url: &HttpsUrl) {
        self.set(KeyName::Rpc(network), url.expose());
    }

    /// Stores the `QuickNode` credentials (validated by the caller).
    pub fn set_quicknode(&mut self, name: &str, token: &str) {
        let mut value = Zeroizing::new(String::with_capacity(
            name.len().saturating_add(token.len()).saturating_add(1),
        ));
        value.push_str(name);
        value.push(':');
        value.push_str(token);
        self.set(KeyName::TplQuickNode, &value);
    }

    /// Stores the Alchemy key (validated by the caller).
    pub fn set_alchemy(&mut self, key: &str) {
        self.set(KeyName::TplAlchemy, key);
    }

    /// The credential of `template`, if stored.
    #[must_use]
    pub fn credential(&self, template: RpcTemplate) -> Option<TemplateCred> {
        match template {
            RpcTemplate::QuickNode => {
                let (name, token) = self.get(KeyName::TplQuickNode)?.split_once(':')?;
                let mut secret = Zeroizing::new(String::with_capacity(token.len()));
                secret.push_str(token);
                Some(TemplateCred::QuickNode {
                    name: name.to_owned(),
                    token: secret,
                })
            }
            RpcTemplate::Alchemy => {
                let key = self.get(KeyName::TplAlchemy)?;
                let mut secret = Zeroizing::new(String::with_capacity(key.len()));
                secret.push_str(key);
                Some(TemplateCred::Alchemy { key: secret })
            }
            RpcTemplate::Manual => None,
        }
    }

    /// `RpcConfig.endpoints`: every `rpc:*` URL (template credentials never leave the UI thread).
    #[must_use]
    pub fn endpoints(&self) -> Vec<(NetworkId, HttpsUrl)> {
        self.entries
            .iter()
            .filter_map(|(name, value)| match name {
                KeyName::Rpc(network) => HttpsUrl::parse(value).ok().map(|url| (*network, url)),
                _ => None,
            })
            .collect()
    }

    /// Entry names (for logs).
    #[must_use]
    pub fn names(&self) -> Vec<KeyName> {
        self.entries.iter().map(|(name, _)| *name).collect()
    }

    /// `네트워크 URL 생성` step 3 (spec/04 §2.11.1): writes the template URL of every target
    /// without a URL, and of targets with one only when `overwrite`. Targets without a template
    /// entry are left alone. Returns the networks written (in memory; the caller saves).
    pub fn generate_urls(
        &mut self,
        template: RpcTemplate,
        credential: &TemplateCred,
        settings: &Settings,
        targets: &[NetworkId],
        overwrite: bool,
    ) -> Vec<NetworkId> {
        let mut written = Vec::new();
        for &network in targets {
            if self.has(KeyName::Rpc(network)) && !overwrite {
                continue;
            }
            let entry = template_entry(template, network, settings);
            if let Some(url) = template_url(template, credential, entry.as_ref()) {
                self.set_rpc(network, &url);
                written.push(network);
            }
        }
        written
    }
}

/// Whether an `rpc:` network is registered under `settings` (spec/04 §6.3 orphan rule).
#[must_use]
pub fn is_registered(settings: &Settings, network: NetworkId) -> bool {
    match network {
        NetworkId::Eip155(id) => settings.registered_evm().contains(&id),
        NetworkId::Solana(_) | NetworkId::Bitcoin(_) => true,
    }
}

/// A provider template credential.
pub enum TemplateCred {
    /// `QuickNode` endpoint name + token.
    QuickNode {
        /// Endpoint name (host label).
        name: String,
        /// Token (URL path segment).
        token: Zeroizing<String>,
    },
    /// Alchemy key.
    Alchemy {
        /// API key.
        key: Zeroizing<String>,
    },
}

impl fmt::Debug for TemplateCred {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::QuickNode { .. } => "TemplateCred::QuickNode([REDACTED])",
            Self::Alchemy { .. } => "TemplateCred::Alchemy([REDACTED])",
        })
    }
}

/// A network's template entry (spec/04 §2.11.1 `entry`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum TemplateEntry {
    /// `QuickNode`: subdomain (`None` = no subdomain) and optional path after the token.
    QuickNode {
        /// Subdomain.
        subdomain: Option<String>,
        /// Path appended after the token.
        path: Option<String>,
    },
    /// Alchemy label.
    Alchemy {
        /// Label.
        label: String,
    },
}

/// The template entry of `network` for `template` (built-in EVM from spec/03 §1.1, SOL from
/// spec/07 §15.1, BTC from spec/08 §2, user chains from `evmChains[]`), `None` when absent.
#[must_use]
pub fn template_entry(
    template: RpcTemplate,
    network: NetworkId,
    settings: &Settings,
) -> Option<TemplateEntry> {
    let quicknode = |subdomain: Option<&str>, path: Option<&str>| TemplateEntry::QuickNode {
        subdomain: subdomain.map(str::to_owned),
        path: path.map(str::to_owned),
    };
    let alchemy = |label: &str| TemplateEntry::Alchemy {
        label: label.to_owned(),
    };
    match (template, network) {
        (RpcTemplate::Manual, _) => None,
        (_, NetworkId::Eip155(id)) => {
            if let Some(chain) = builtin_chain(id) {
                let templates = chain.templates?;
                return match template {
                    RpcTemplate::QuickNode => Some(quicknode(
                        templates.quicknode_subdomain,
                        templates.quicknode_path,
                    )),
                    RpcTemplate::Alchemy => templates.alchemy_label.map(alchemy),
                    RpcTemplate::Manual => None,
                };
            }
            let chain = settings
                .evm_chains
                .iter()
                .find(|chain| chain.chain_id == id)?;
            match template {
                RpcTemplate::QuickNode => chain
                    .quicknode_subdomain
                    .as_deref()
                    .map(|subdomain| quicknode(Some(subdomain), None)),
                RpcTemplate::Alchemy => chain.alchemy_label.as_deref().map(alchemy),
                RpcTemplate::Manual => None,
            }
        }
        (RpcTemplate::QuickNode, NetworkId::Solana(cluster)) => Some(quicknode(
            Some(match cluster {
                SolCluster::Mainnet => "solana-mainnet",
                SolCluster::Devnet => "solana-devnet",
            }),
            None,
        )),
        (RpcTemplate::Alchemy, NetworkId::Solana(cluster)) => Some(alchemy(match cluster {
            SolCluster::Mainnet => "solana-mainnet",
            SolCluster::Devnet => "solana-devnet",
        })),
        (RpcTemplate::QuickNode, NetworkId::Bitcoin(net)) => Some(quicknode(
            Some(match net {
                BtcNet::Mainnet => "btc",
                BtcNet::Testnet4 => "btc-testnet4",
            }),
            None,
        )),
        (RpcTemplate::Alchemy, NetworkId::Bitcoin(net)) => Some(alchemy(match net {
            BtcNet::Mainnet => "bitcoin-mainnet",
            BtcNet::Testnet4 => "bitcoin-testnet4",
        })),
    }
}

/// `template_url` (spec/04 §2.11.1): the URL a template would produce for one network, already
/// passed through `HttpsUrl::parse`; `None` for `Manual`, a missing entry or a credential of
/// another template.
#[must_use]
pub fn template_url(
    template: RpcTemplate,
    cred: &TemplateCred,
    entry: Option<&TemplateEntry>,
) -> Option<HttpsUrl> {
    let entry = entry?;
    let mut text = Zeroizing::new(String::with_capacity(160));
    match (template, cred, entry) {
        (
            RpcTemplate::QuickNode,
            TemplateCred::QuickNode { name, token },
            TemplateEntry::QuickNode { subdomain, path },
        ) => {
            text.push_str("https://");
            text.push_str(name);
            if let Some(subdomain) = subdomain {
                text.push('.');
                text.push_str(subdomain);
            }
            text.push_str(".quiknode.pro/");
            text.push_str(token);
            text.push('/');
            if let Some(path) = path {
                text.push_str(path);
            }
        }
        (RpcTemplate::Alchemy, TemplateCred::Alchemy { key }, TemplateEntry::Alchemy { label }) => {
            text.push_str("https://");
            text.push_str(label);
            text.push_str(".g.alchemy.com/v2/");
            text.push_str(key);
        }
        _ => return None,
    }
    HttpsUrl::parse(&text).ok()
}

/// `mask_url` (spec/04 §2.11.1): `https://●●●●` + provider suffix (`.quiknode.pro` /
/// `.g.alchemy.com` / nothing) + `/●●●●`. Never shows the name, subdomain, label, path or token.
#[must_use]
pub fn mask_url(url: &HttpsUrl) -> String {
    let host = url.host();
    let suffix = if host.ends_with(".quiknode.pro") {
        ".quiknode.pro"
    } else if host.ends_with(".g.alchemy.com") {
        ".g.alchemy.com"
    } else {
        ""
    };
    format!("https://\u{25CF}\u{25CF}\u{25CF}\u{25CF}{suffix}/\u{25CF}\u{25CF}\u{25CF}\u{25CF}")
}
