//! `apikeys.dpapi` (spec/04 §6.3, D13): per-network RPC endpoint URLs (`rpc:<NetworkId>`),
//! provider template credentials (`tpl:quicknode`, `tpl:alchemy`), the LLM key (`llm`) and the
//! endpoint `host[:port]` that key is bound to (`llm:host`), encrypted with DPAPI for the current
//! user. A whole URL is a secret (token in the path, endpoint
//! name in the host): values are never logged or displayed; screens use [`mask_url`].
//!
//! Also the pure helpers of spec/04 §2.11.1: [`template_url`] and [`mask_url`], and the S15
//! `QuickNode` input helper [`quicknode_credentials`] that accepts a pasted endpoint URL.
//!
//! Format compatibility (spec/04 §6.6): `rpc:` entries of networks that are not registered now
//! (orphans) and entries with names this version does not know are never used, but they are kept
//! ("dormant") and written back on every save until the user removes them explicitly.

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
    /// `llm:host`: the endpoint `host[:port]` the `llm` key was entered for (spec/06 §2.1). The
    /// key is attached only to requests to that host. Older versions keep it dormant.
    LlmHost,
}

impl fmt::Display for KeyName {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Rpc(network) => write!(formatter, "rpc:{network}"),
            Self::TplQuickNode => formatter.write_str("tpl:quicknode"),
            Self::TplAlchemy => formatter.write_str("tpl:alchemy"),
            Self::Llm => formatter.write_str("llm"),
            Self::LlmHost => formatter.write_str("llm:host"),
        }
    }
}

impl KeyName {
    fn parse(text: &str) -> Option<Self> {
        match text {
            "tpl:quicknode" => Some(Self::TplQuickNode),
            "tpl:alchemy" => Some(Self::TplAlchemy),
            "llm" => Some(Self::Llm),
            "llm:host" => Some(Self::LlmHost),
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
        KeyName::LlmHost => valid_llm_host(value),
    }
}

/// An endpoint `host[:port]` as `explain::config::parse_endpoint` produces it (lowercase):
/// lowercase ASCII letters, digits and `.:_[]-`, 1–300 bytes.
#[must_use]
pub fn valid_llm_host(text: &str) -> bool {
    (1..=300).contains(&text.len())
        && text.bytes().all(|byte| {
            byte.is_ascii_lowercase()
                || byte.is_ascii_digit()
                || matches!(byte, b'.' | b':' | b'_' | b'-' | b'[' | b']')
        })
}

/// The name of a newer version's entry: `^[a-z0-9][a-z0-9:._-]*$` (length checked by the caller),
/// not a malformed name of a known family (`rpc:eip155:<not a canonical chain id>`).
fn valid_unknown_name(text: &str) -> bool {
    let mut bytes = text.bytes();
    bytes
        .next()
        .is_some_and(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit())
        && bytes.all(|byte| {
            byte.is_ascii_lowercase()
                || byte.is_ascii_digit()
                || matches!(byte, b':' | b'.' | b'_' | b'-')
        })
        && !text.starts_with("rpc:eip155:")
        && text != "rpc:"
}

/// An entry kept only to be written back (spec/04 §6.6): never an endpoint, credential or key.
struct Dormant {
    /// Entry name (ASCII, not secret).
    name: String,
    /// Value bytes as read (may be secret).
    value: Zeroizing<Vec<u8>>,
}

/// The decrypted entries, owned by the UI thread (spec/04 §6.3).
#[derive(Default)]
pub struct ApiKeys {
    entries: Vec<(KeyName, Zeroizing<String>)>,
    /// Orphan `rpc:` entries and unknown names, in file order (spec/04 §6.6).
    dormant: Vec<Dormant>,
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
            .field("dormant", &self.dormant_names())
            .finish()
    }
}

/// Decoding result: entries plus the names of orphan `rpc:` entries (networks not registered now).
#[derive(Debug)]
pub struct Decoded {
    /// Registered entries (orphans and unknown names are kept dormant inside, never used).
    pub keys: ApiKeys,
    /// Orphans (logged by name; kept and written back, spec/04 §6.6).
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
    /// (built-in, user EVM chain from settings, Solana, Bitcoin); other `rpc:` entries are orphans.
    /// Orphans and entries whose name this version does not know (a newer version's) are kept
    /// dormant: never used, written back by [`ApiKeys::encode`] (spec/04 §6.6).
    ///
    /// # Errors
    ///
    /// [`ApiKeysFormatError`] for any format violation (all entries then count as absent): bad
    /// magic, count, lengths, duplicate names, a malformed name of a known family
    /// (`rpc:eip155:01`), a name outside `[a-z0-9:._-]`, an invalid value of a known name, or
    /// trailing bytes.
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
        let mut seen: Vec<&str> = Vec::new();
        for _ in 0..count {
            let name_len = usize::from(reader.byte().ok_or(ApiKeysFormatError)?);
            if !(1..=MAX_NAME).contains(&name_len) {
                return Err(ApiKeysFormatError);
            }
            let name_bytes = reader.take(name_len).ok_or(ApiKeysFormatError)?;
            let name_text = core::str::from_utf8(name_bytes).map_err(|_| ApiKeysFormatError)?;
            let name = KeyName::parse(name_text);
            if (name.is_none() && !valid_unknown_name(name_text)) || seen.contains(&name_text) {
                return Err(ApiKeysFormatError);
            }
            seen.push(name_text);
            let length_bytes = reader.take(2).ok_or(ApiKeysFormatError)?;
            let value_len = usize::from(u16::from_be_bytes(
                length_bytes.try_into().map_err(|_| ApiKeysFormatError)?,
            ));
            if !(1..=MAX_VALUE).contains(&value_len) {
                return Err(ApiKeysFormatError);
            }
            let value_bytes = reader.take(value_len).ok_or(ApiKeysFormatError)?;
            let Some(name) = name else {
                // A newer version's entry: opaque bytes, kept for write-back.
                keys.dormant.push(Dormant {
                    name: name_text.to_owned(),
                    value: Zeroizing::new(value_bytes.to_vec()),
                });
                continue;
            };
            let value = core::str::from_utf8(value_bytes).map_err(|_| ApiKeysFormatError)?;
            if !valid_value(name, value) {
                return Err(ApiKeysFormatError);
            }
            if let KeyName::Rpc(network) = name
                && !registered(network)
            {
                orphans.push(name);
                keys.dormant.push(Dormant {
                    name: name_text.to_owned(),
                    value: Zeroizing::new(value_bytes.to_vec()),
                });
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

    /// Builds the plaintext from the current entries followed by the dormant ones (spec/04 §6.6).
    /// Dormant entries beyond the 48-entry bound are left out (the active entries always fit).
    #[must_use]
    pub fn encode(&self) -> Zeroizing<Vec<u8>> {
        let dormant_room = APIKEYS_MAX_ENTRIES.saturating_sub(self.entries.len());
        let dormant = self.dormant.iter().take(dormant_room);
        let mut out = Zeroizing::new(Vec::with_capacity(
            self.entries
                .iter()
                .map(|(_, value)| value.len())
                .chain(dormant.clone().map(|entry| entry.value.len()))
                .map(|len| len.saturating_add(40))
                .sum::<usize>()
                .saturating_add(9),
        ));
        out.extend_from_slice(APIKEYS_MAGIC);
        let count = self
            .entries
            .len()
            .saturating_add(self.dormant.len().min(dormant_room));
        out.push(u8::try_from(count).unwrap_or(0));
        let mut push = |name: &str, value: &[u8]| {
            out.push(u8::try_from(name.len()).unwrap_or(0));
            out.extend_from_slice(name.as_bytes());
            out.extend_from_slice(&u16::try_from(value.len()).unwrap_or(0).to_be_bytes());
            out.extend_from_slice(value);
        };
        for (name, value) in &self.entries {
            push(&name.to_string(), value.as_bytes());
        }
        for entry in dormant {
            push(&entry.name, &entry.value);
        }
        out
    }

    /// Names of the dormant entries (orphan `rpc:` entries and unknown names), not secret.
    #[must_use]
    pub fn dormant_names(&self) -> Vec<String> {
        self.dormant
            .iter()
            .map(|entry| entry.name.clone())
            .collect()
    }

    /// Removes every dormant entry (an explicit user action only, spec/04 §6.6); returns how many
    /// were removed. The caller saves.
    pub fn prune_dormant(&mut self) -> usize {
        let count = self.dormant.len();
        self.dormant.clear();
        count
    }

    fn drop_dormant(&mut self, name: KeyName) -> bool {
        let text = name.to_string();
        let before = self.dormant.len();
        self.dormant.retain(|entry| entry.name != text);
        before != self.dormant.len()
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
        // A new value replaces a dormant entry of the same name (e.g. a chain added again).
        self.drop_dormant(name);
        if let Some(slot) = self.entries.iter_mut().find(|(entry, _)| *entry == name) {
            slot.1 = owned;
        } else {
            self.entries.push((name, owned));
        }
    }

    /// Removes an entry (also a dormant one of the same name); returns whether one existed.
    /// Removing `llm` also removes its `llm:host` binding.
    pub fn remove(&mut self, name: KeyName) -> bool {
        let before = self.entries.len();
        self.entries.retain(|(entry, _)| *entry != name);
        let dormant = self.drop_dormant(name);
        if name == KeyName::Llm {
            self.entries.retain(|(entry, _)| *entry != KeyName::LlmHost);
            self.drop_dormant(KeyName::LlmHost);
        }
        before != self.entries.len() || dormant
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

    /// Stores the LLM API key (validated by the caller, spec/06 §2.1) bound to the endpoint
    /// `host[:port]` it was entered for. `None` (no valid endpoint saved yet) stores the key
    /// unbound: it is never sent until [`ApiKeys::bind_llm_host`] binds it.
    pub fn set_llm(&mut self, key: &str, host: Option<&str>) {
        self.set(KeyName::Llm, key);
        if let Some(host) = host.filter(|host| valid_llm_host(host)) {
            self.set(KeyName::LlmHost, host);
        } else {
            self.entries.retain(|(entry, _)| *entry != KeyName::LlmHost);
            self.drop_dormant(KeyName::LlmHost);
        }
    }

    /// The LLM API key, for building the `yw-llm` configuration only (spec/06 §9).
    #[must_use]
    pub fn llm_key(&self) -> Option<&str> {
        self.get(KeyName::Llm)
    }

    /// The endpoint `host[:port]` the LLM key is bound to (`None`: no key, or a key stored
    /// without a host by an older version and not bound yet).
    #[must_use]
    pub fn llm_host(&self) -> Option<&str> {
        self.get(KeyName::Llm)?;
        self.get(KeyName::LlmHost)
    }

    /// Binds a stored but unbound LLM key to `host` (a key from an older version, bound to the
    /// endpoint saved when it is first loaded; or a key entered before any endpoint was saved).
    /// A key that is already bound is left alone. Returns whether a binding was added (in
    /// memory; the caller saves).
    pub fn bind_llm_host(&mut self, host: &str) -> bool {
        if self.get(KeyName::Llm).is_none()
            || self.get(KeyName::LlmHost).is_some()
            || !valid_llm_host(host)
        {
            return false;
        }
        self.set(KeyName::LlmHost, host);
        true
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
        NetworkId::Solana(_) | NetworkId::Bitcoin(_) | NetworkId::Zcash(_) => true,
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
        (RpcTemplate::Manual, _) | (RpcTemplate::Alchemy, NetworkId::Zcash(_)) => None,
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
        // spec/12 §4.1: QuickNode Zcash docs use `zec-mainnet` (testnet `zec-testnet`, checked
        // at first use); Alchemy has no Zcash endpoint (`Manual` arm above).
        (RpcTemplate::QuickNode, NetworkId::Zcash(net)) => Some(quicknode(
            Some(match net {
                yw_core::zec::ZecNetwork::Mainnet => "zec-mainnet",
                yw_core::zec::ZecNetwork::Testnet => "zec-testnet",
            }),
            None,
        )),
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

/// Takes apart a `QuickNode` endpoint URL copied from the dashboard: `https://<name>.quiknode.pro/
/// <token>/…` or `https://<name>.<subdomain>.quiknode.pro/<token>/…` (the WSS form `wss://…` shows
/// the same name and token). Returns the lowercase endpoint name and the token; the subdomain and
/// any path after the token (`nanoreth`, `evm`) are dropped because the template tables add them
/// per network (spec/04 §2.11.1). `None` when `text` is not such a URL.
#[must_use]
pub fn parse_quicknode_url(text: &str) -> Option<(String, Zeroizing<String>)> {
    let text = text.trim();
    let scheme_end = text.find("://")?;
    let scheme = text.get(..scheme_end)?;
    if !scheme.eq_ignore_ascii_case("https") && !scheme.eq_ignore_ascii_case("wss") {
        return None;
    }
    let rest = text.get(scheme_end.checked_add(3)?..)?;
    let mut https = Zeroizing::new(String::with_capacity(rest.len().saturating_add(8)));
    https.push_str("https://");
    https.push_str(rest);
    let url = HttpsUrl::parse(&https).ok()?;
    if url.port().is_some() {
        return None;
    }
    let labels = url.host().strip_suffix(".quiknode.pro")?;
    let mut parts = labels.split('.');
    let name = parts.next().filter(|name| valid_quicknode_name(name))?;
    match (parts.next(), parts.next()) {
        (None, _) => {}
        (Some(subdomain), None) if is_dns_label(subdomain) => {}
        _ => return None,
    }
    let token = url
        .path()
        .strip_prefix('/')?
        .split(['/', '?'])
        .next()
        .filter(|token| valid_provider_token(token))?;
    let mut secret = Zeroizing::new(String::with_capacity(token.len()));
    secret.push_str(token);
    Some((name.to_owned(), secret))
}

/// The S15 `QuickNode` field an input error refers to (the E-KEY-002 `{항목}`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum QuickNodeField {
    /// `엔드포인트 이름`.
    Name,
    /// `토큰`.
    Token,
}

impl QuickNodeField {
    /// The item name shown in E-KEY-002.
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::Name => "엔드포인트 이름",
            Self::Token => "토큰",
        }
    }
}

/// The `QuickNode` credential from the two S15 fields (spec/04 §2.11): either field may hold the
/// whole endpoint URL from the dashboard ([`parse_quicknode_url`]); the other field is then empty,
/// the same URL or the matching part. Otherwise the name is lowercased and both are checked
/// (`^[a-z0-9]+(-[a-z0-9]+)*$` 1–63, token `^[A-Za-z0-9_-]{16,128}$`). Surrounding spaces are
/// ignored.
///
/// # Errors
///
/// The [`QuickNodeField`] to name in E-KEY-002.
pub fn quicknode_credentials(
    name_field: &str,
    token_field: &str,
) -> Result<(String, Zeroizing<String>), QuickNodeField> {
    let name_in = name_field.trim();
    let token_in = token_field.trim();
    let from_name = parse_quicknode_url(name_in);
    let from_token = parse_quicknode_url(token_in);
    let Some((name, token)) = from_name.as_ref().or(from_token.as_ref()) else {
        let lower = name_in.to_ascii_lowercase();
        if !valid_quicknode_name(&lower) {
            return Err(QuickNodeField::Name);
        }
        if !valid_provider_token(token_in) {
            return Err(QuickNodeField::Token);
        }
        let mut secret = Zeroizing::new(String::with_capacity(token_in.len()));
        secret.push_str(token_in);
        return Ok((lower, secret));
    };
    let same = |parsed: &Option<(String, Zeroizing<String>)>| {
        parsed
            .as_ref()
            .is_some_and(|(other_name, other_token)| other_name == name && other_token == token)
    };
    if !(name_in.is_empty() || name_in.eq_ignore_ascii_case(name) || same(&from_name)) {
        return Err(QuickNodeField::Name);
    }
    if !(token_in.is_empty() || token_in == token.as_str() || same(&from_token)) {
        return Err(QuickNodeField::Token);
    }
    Ok((name.clone(), token.clone()))
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
