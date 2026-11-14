//! User EVM chains (spec/03 §1.6, spec/04 §2.17): the S17 input rules (ST-3) and the RPC check
//! before saving (chain id, block-0 hash pinned on first trust, EIP-1559 base fee).

use yw_core::evm::chain::{MAX_CHAIN_ID, SimulationSupport, builtin_chains};
use yw_core::lang::Lang;
use yw_win::http::HttpsUrl;

use super::SharedTransport;
use crate::apikeys::{ApiKeys, TemplateEntry, template_url};
use crate::errors::ErrorCode;
use crate::network::parse_decimal_u64;
use crate::rpc::evm::{chain_id_text, genesis_hash, has_base_fee, parse_chain_id};
use crate::rpc::{RpcClient, RpcFailure, canonical_quantity, classify};
use crate::settings::{MAX_CUSTOM_EVM_CHAINS, RpcTemplate, Settings, validate_explorer};
use crate::text::{is_dns_label, is_symbol, is_valid_label};

/// Raw S17 input (non-secret fields; the RPC text is secret and wiped by the caller).
#[derive(Clone, Copy, Debug)]
pub struct ChainForm<'a> {
    /// chainId (decimal) — ignored when editing.
    pub chain_id: &'a str,
    /// Name.
    pub name: &'a str,
    /// Native symbol.
    pub symbol: &'a str,
    /// Native decimals.
    pub decimals: &'a str,
    /// RPC: an `https://` URL or a template identifier (empty when editing = keep).
    pub rpc: &'a str,
    /// Explorer URL (optional).
    pub explorer: &'a str,
    /// Simulation support.
    pub simulation: SimulationSupport,
}

/// How the RPC field was given.
#[derive(Clone, Debug)]
pub enum RpcSpec {
    /// Edit without an RPC change.
    Keep,
    /// A direct URL (template identifiers unchanged).
    Url(HttpsUrl),
    /// A template identifier and the URL it produces.
    Template {
        /// Template.
        template: RpcTemplate,
        /// Lowercase subdomain or label.
        entry: String,
        /// URL.
        url: HttpsUrl,
    },
}

impl RpcSpec {
    /// The URL to check and store, if any.
    #[must_use]
    pub const fn url(&self) -> Option<&HttpsUrl> {
        match self {
            Self::Keep => None,
            Self::Url(url) | Self::Template { url, .. } => Some(url),
        }
    }
}

/// A validated S17 input.
#[derive(Clone, Debug)]
pub struct ValidChainForm {
    /// chainId.
    pub chain_id: u64,
    /// Name.
    pub name: String,
    /// Symbol.
    pub symbol: String,
    /// Decimals.
    pub decimals: u8,
    /// Explorer (normalized, no trailing `/`).
    pub explorer: Option<String>,
    /// Simulation.
    pub simulation: SimulationSupport,
    /// RPC.
    pub rpc: RpcSpec,
}

/// An S17 input error: code and, for E-CHN-004, the item name.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FormError {
    /// Code.
    pub code: ErrorCode,
    /// Item for `{항목}`: `chainId` or the Korean side of a [`text`] `ITEM_*` entry
    /// ([`FormError::message_in`] shows the entry in the language asked for).
    pub item: Option<&'static str>,
}

/// S17 item names of E-CHN-004 (spec/04 §2.17.1; English spec/14 §5).
pub mod text {
    yw_core::texts! {
        ITEM_QUICKNODE = "QuickNode 서브도메인" / "QuickNode subdomain";
        ITEM_ALCHEMY = "알케미 라벨" / "Alchemy label";
        ITEM_SYMBOL = "네이티브 심볼" / "Native symbol";
        ITEM_DECIMALS = "소수 자릿수" / "Decimals";
        ITEM_EXPLORER = "탐색기 URL" / "Explorer URL";
    }
}

/// The item name of `item` in `lang` (`chainId` is the same in both).
fn item_in(item: &'static str, lang: Lang) -> &'static str {
    [
        text::ITEM_QUICKNODE,
        text::ITEM_ALCHEMY,
        text::ITEM_SYMBOL,
        text::ITEM_DECIMALS,
        text::ITEM_EXPLORER,
    ]
    .into_iter()
    .find(|entry| entry.ko == item)
    .map_or(item, |entry| entry.get(lang))
}

impl FormError {
    const fn new(code: ErrorCode) -> Self {
        Self { code, item: None }
    }

    const fn item(item: &'static str) -> Self {
        Self {
            code: ErrorCode::Chn004,
            item: Some(item),
        }
    }

    /// The fixed message in `lang`.
    #[must_use]
    pub fn message_in(&self, lang: Lang) -> String {
        match self.item {
            Some(item) => self.code.render_in(lang, item_in(item, lang)),
            None => self.code.text_in(lang),
        }
    }
}

fn validate_rpc(
    text: &str,
    settings: &Settings,
    apikeys: &ApiKeys,
    editing: bool,
) -> Result<RpcSpec, FormError> {
    let text = text.trim();
    if text.is_empty() {
        return if editing {
            Ok(RpcSpec::Keep)
        } else {
            Err(FormError::new(ErrorCode::Key003))
        };
    }
    if text.starts_with("https://") {
        return HttpsUrl::parse(text)
            .map(RpcSpec::Url)
            .map_err(|_| FormError::new(ErrorCode::Key003));
    }
    let template = settings.rpc_template;
    let lowered = text.to_ascii_lowercase();
    let (entry, item, entry_of): (&str, &'static str, fn(String) -> TemplateEntry) = match template
    {
        RpcTemplate::Manual => return Err(FormError::new(ErrorCode::Key003)),
        RpcTemplate::QuickNode => (lowered.as_str(), text::ITEM_QUICKNODE.ko, |entry| {
            TemplateEntry::QuickNode {
                subdomain: Some(entry),
                path: None,
            }
        }),
        RpcTemplate::Alchemy => (
            lowered.strip_suffix(".g.alchemy.com").unwrap_or(&lowered),
            text::ITEM_ALCHEMY.ko,
            |label| TemplateEntry::Alchemy { label },
        ),
    };
    if !is_dns_label(entry) {
        return Err(FormError::item(item));
    }
    let credential = apikeys
        .credential(template)
        .ok_or(FormError::new(ErrorCode::Key004))?;
    let url = template_url(template, &credential, Some(&entry_of(entry.to_owned())))
        .ok_or(FormError::new(ErrorCode::Key003))?;
    Ok(RpcSpec::Template {
        template,
        entry: entry.to_owned(),
        url,
    })
}

/// The S17 input rules (spec/04 §2.17.1, ST-3). `editing` is the chain id of the edited chain.
///
/// # Errors
///
/// [`FormError`] for the first violated rule.
pub fn validate_chain_form(
    form: &ChainForm<'_>,
    settings: &Settings,
    apikeys: &ApiKeys,
    editing: Option<u64>,
) -> Result<ValidChainForm, FormError> {
    let chain_id = if let Some(id) = editing {
        id
    } else {
        if settings.evm_chains.len() >= MAX_CUSTOM_EVM_CHAINS {
            return Err(FormError::new(ErrorCode::Chn006));
        }
        let id = parse_decimal_u64(form.chain_id.trim())
            .filter(|id| *id <= MAX_CHAIN_ID)
            .ok_or(FormError::item("chainId"))?;
        if settings.registered_evm().contains(&id) {
            return Err(FormError::new(ErrorCode::Chn003));
        }
        id
    };
    let name = form.name;
    if !is_valid_label(name) {
        return Err(FormError::new(ErrorCode::Inp017));
    }
    let lowered = name.to_ascii_lowercase();
    let builtin_clash = builtin_chains()
        .iter()
        .any(|chain| chain.name.to_ascii_lowercase() == lowered);
    let user_clash = settings
        .evm_chains
        .iter()
        .any(|chain| chain.chain_id != chain_id && chain.name.to_ascii_lowercase() == lowered);
    if builtin_clash || user_clash {
        return Err(FormError::new(ErrorCode::Chn005));
    }
    if !is_symbol(form.symbol) {
        return Err(FormError::item(text::ITEM_SYMBOL.ko));
    }
    let decimals = form
        .decimals
        .trim()
        .parse::<u8>()
        .ok()
        .filter(|decimals| *decimals <= 36 && !form.decimals.trim().starts_with('+'))
        .ok_or(FormError::item(text::ITEM_DECIMALS.ko))?;
    let explorer_text = form.explorer.trim();
    let explorer = if explorer_text.is_empty() {
        None
    } else {
        let stripped = explorer_text.strip_suffix('/').unwrap_or(explorer_text);
        Some(validate_explorer(stripped).ok_or(FormError::item(text::ITEM_EXPLORER.ko))?)
    };
    let rpc = validate_rpc(form.rpc, settings, apikeys, editing.is_some())?;
    Ok(ValidChainForm {
        chain_id,
        name: name.to_owned(),
        symbol: form.symbol.to_owned(),
        decimals,
        explorer,
        simulation: form.simulation,
        rpc,
    })
}

/// Why a chain RPC check failed (spec/04 §2.17.2-2, spec/03 §1.6 steps 2–4).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ProbeError {
    /// Transport, HTTP or JSON-RPC failure (E-CHN-002 + cause).
    Rpc(ErrorCode),
    /// `eth_chainId` differs (E-CHN-001 with the parsed value) or is not a quantity.
    ChainId {
        /// Parsed RPC value.
        rpc: Option<u64>,
    },
    /// Block 0 hash missing or not 32 bytes (E-CHN-002 + E-RPC-005).
    NoBlockZero,
    /// Block-0 hash differs from the pinned one (E-CHN-008).
    GenesisMismatch,
    /// No `baseFeePerGas` (EIP-1559 missing).
    NoBaseFee,
}

impl ProbeError {
    /// The fixed message in `lang` (only parsed values from the RPC, spec/04 §7).
    #[must_use]
    pub fn message_in(&self, lang: Lang) -> String {
        match self {
            Self::Rpc(code) => format!(
                "{} ({}, {})",
                ErrorCode::Chn002.message_in(lang),
                ErrorCode::Chn002.code(),
                code.code()
            ),
            Self::ChainId { rpc: Some(id) } => ErrorCode::Chn001.render_in(lang, &id.to_string()),
            Self::ChainId { rpc: None } | Self::NoBlockZero => format!(
                "{} ({}, {})",
                ErrorCode::Chn002.message_in(lang),
                ErrorCode::Chn002.code(),
                ErrorCode::Rpc005.code()
            ),
            Self::GenesisMismatch => ErrorCode::Chn008.text_in(lang),
            Self::NoBaseFee => ErrorCode::Chn010.text_in(lang),
        }
    }

    /// Code for logs.
    #[must_use]
    pub const fn code(&self) -> ErrorCode {
        match self {
            Self::Rpc(_) | Self::NoBlockZero | Self::ChainId { rpc: None } => ErrorCode::Chn002,
            Self::ChainId { .. } => ErrorCode::Chn001,
            Self::GenesisMismatch => ErrorCode::Chn008,
            Self::NoBaseFee => ErrorCode::Chn010,
        }
    }
}

/// The RPC check of a user chain URL (no retry, one call each): chain id, block-0 hash (compared
/// with `pinned` when editing or re-checking), and when adding the `baseFeePerGas` check.
///
/// # Errors
///
/// [`ProbeError`].
pub fn probe_chain(
    transport: &SharedTransport,
    url: &HttpsUrl,
    chain_id: u64,
    pinned: Option<[u8; 32]>,
    check_base_fee: bool,
) -> Result<[u8; 32], ProbeError> {
    let client = RpcClient::new(&**transport);
    let rpc_error = |failure: RpcFailure| match failure {
        RpcFailure::Malformed => ProbeError::NoBlockZero,
        other => ProbeError::Rpc(classify(other)),
    };
    let text = chain_id_text(&client, url).map_err(|failure| match failure {
        RpcFailure::Malformed => ProbeError::ChainId { rpc: None },
        other => ProbeError::Rpc(classify(other)),
    })?;
    let parsed = parse_chain_id(&text);
    if parsed.is_none() {
        return Err(ProbeError::ChainId { rpc: None });
    }
    if text.to_ascii_lowercase() != canonical_quantity(chain_id) {
        return Err(ProbeError::ChainId { rpc: parsed });
    }
    let genesis = genesis_hash(&client, url).map_err(rpc_error)?;
    if pinned.is_some_and(|pinned| pinned != genesis) {
        return Err(ProbeError::GenesisMismatch);
    }
    if check_base_fee
        && !has_base_fee(&client, url).map_err(|failure| ProbeError::Rpc(classify(failure)))?
    {
        return Err(ProbeError::NoBaseFee);
    }
    Ok(genesis)
}

/// Deleting a user chain (spec/04 §2.17, UI-M4-15): never the active chain (E-CHN-009), never
/// while a journal record of it is unfinished or a send on it is in progress (E-CHN-007).
///
/// # Errors
///
/// [`ErrorCode::Chn009`] or [`ErrorCode::Chn007`].
pub fn check_delete(
    chain_id: u64,
    active_chain_id: u64,
    records: &[yw_core::journal::evm::EvmRecord],
    sending: bool,
) -> Result<(), ErrorCode> {
    if chain_id == active_chain_id {
        return Err(ErrorCode::Chn009);
    }
    let open = records
        .iter()
        .any(|record| record.chain_id == chain_id && !record.is_terminal());
    if open || sending {
        return Err(ErrorCode::Chn007);
    }
    Ok(())
}
