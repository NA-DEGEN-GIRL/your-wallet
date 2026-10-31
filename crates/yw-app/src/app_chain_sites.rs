//! Solana and Bitcoin dApp connections on the UI thread (spec/05 §4.9, spec/07 §19, spec/08
//! §17): ownership proof only — one account per connection, message signing, no transaction.
//! The account choices of the connect window, connect approval and grant persistence (meta
//! `sol_sites`/`btc_sites`), the checks of a queued request, the approval draft and the answer of
//! a finished signature.

use yw_core::approval::{ApprovalDraft, SigningPayload};
use yw_core::bip32::path::BtcChain;
use yw_core::btc::msgsign::{BtcMessageProtocol, BtcMessageRequest, build_btc_message_request};
use yw_core::btc::{BtcKeySource, BtcNetwork, ScriptType};
use yw_core::policy::{
    BrowserOrigin, BtcGrant, BtcGrantAddress, BtcPurpose, Family, ProviderError, SolGrant,
};
use yw_core::slip10::SolKeySource;
use yw_core::sol::msgsign::{SolMessageRequest, build_sol_message_request};
use yw_json::Value;

use crate::app::App;
use crate::app_browser::SignWaiter;
use crate::browser::{SiteKind, SiteRequest};
use crate::events::{ChainMessageSigned, ChainSignature};
use crate::logging::{self, Field};
use crate::text::{json_object, json_str};
use crate::ui::approval::QueueOutcome;

/// One account offered by a connect window.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ConnectChoice {
    /// An EVM account.
    Evm(yw_core::evm::address::Address),
    /// A Solana account (public key).
    Sol([u8; 32]),
    /// A Bitcoin address for one purpose.
    Btc(BtcGrantAddress),
}

/// A connect-window row: `(choice, label, address text, radio group)`.
pub type ConnectEntry = (ConnectChoice, String, String, u8);

/// What the answer of a signed chain message needs besides the signature.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ChainAnswer {
    /// `sol_signMessage` / `sol_signIn`.
    Sol {
        /// Signing account.
        public: [u8; 32],
        /// The signed bytes (returned as `signedMessage` for a sign-in).
        message: Vec<u8>,
        /// `sol_signIn`.
        sign_in: bool,
    },
    /// `btc_signMessage`.
    Btc {
        /// Signing address.
        address: String,
        /// Protocol used.
        protocol: BtcMessageProtocol,
    },
}

/// A Solana account usable by dApps.
#[derive(Clone, Debug)]
pub struct SolRow {
    /// Public key.
    pub public: [u8; 32],
    /// Key source.
    pub source: SolKeySource,
    /// Label.
    pub label: String,
    /// Path text.
    pub path: String,
}

/// A Bitcoin account's stable address (receive index 0, or the imported key's address).
#[derive(Clone, Debug)]
pub struct BtcRow {
    /// Address, key and type.
    pub entry: BtcGrantAddress,
    /// Key source.
    pub source: BtcKeySource,
    /// Label.
    pub label: String,
    /// Path text.
    pub path: String,
}

/// The default protocol of an address type (sats-connect: BIP322 for Taproot, else ECDSA).
#[must_use]
pub const fn default_protocol(script_type: ScriptType) -> BtcMessageProtocol {
    match script_type {
        ScriptType::P2tr => BtcMessageProtocol::Bip322,
        _ => BtcMessageProtocol::Ecdsa,
    }
}

fn now_unix_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |elapsed| u64::try_from(elapsed.as_millis()).unwrap_or(0))
}

/// The answer of a signed chain message (spec/05 §3.6 result shapes).
#[must_use]
pub fn chain_answer_value(answer: &ChainAnswer, signature: &ChainSignature) -> Option<Value> {
    match (answer, signature) {
        (
            ChainAnswer::Sol {
                public,
                message,
                sign_in,
            },
            ChainSignature::Sol(bytes),
        ) => {
            let mut members = vec![
                (
                    "publicKey",
                    json_str(&yw_core::codec::base58::base58_encode(public)),
                ),
                ("signature", json_str(&yw_core::hex::encode(bytes))),
            ];
            if *sign_in {
                members.push(("signedMessage", json_str(&yw_core::hex::encode(message))));
            }
            Some(json_object(members))
        }
        (ChainAnswer::Btc { address, protocol }, ChainSignature::Btc(signed)) => {
            Some(json_object(vec![
                ("address", json_str(address)),
                ("signature", json_str(&signed.signature)),
                (
                    "messageHash",
                    json_str(&yw_core::hex::encode(&signed.message_hash)),
                ),
                ("protocol", json_str(protocol.as_str())),
            ]))
        }
        _ => None,
    }
}

impl App {
    /// The settings Bitcoin network.
    pub(crate) const fn btc_network_now(&self) -> BtcNetwork {
        crate::btc::core_network(self.settings.bitcoin.network)
    }

    /// Visible Solana accounts usable by dApps (standard accounts, then imported keys).
    pub(crate) fn sol_dapp_rows(&self) -> Vec<SolRow> {
        self.sol_account_rows()
            .into_iter()
            .filter_map(|(id, label, address)| {
                Some(SolRow {
                    public: address.to_bytes(),
                    source: id.source()?,
                    label,
                    path: id.path_text(),
                })
            })
            .collect()
    }

    /// Every Bitcoin account of the settings network with its stable address.
    pub(crate) fn btc_dapp_rows(&self) -> Vec<BtcRow> {
        let net = self.btc_network_now();
        let ctx = self.btc_ctx();
        ctx.accounts()
            .into_iter()
            .filter_map(|meta| {
                let account = meta.account();
                let pubkey = account.deriver().ok()?.pubkey(BtcChain::Receive, 0).ok()?;
                let address = meta.address(BtcChain::Receive, 0).ok()?;
                Some(BtcRow {
                    entry: BtcGrantAddress {
                        purpose: BtcPurpose::Any,
                        address: address.as_str().to_owned(),
                        pubkey,
                        script_type: account.script_type(),
                    },
                    source: account.key_source(BtcChain::Receive, 0),
                    label: crate::app_btc::account_label(account),
                    path: account.path_text(net, BtcChain::Receive, 0),
                })
            })
            .collect()
    }

    /// The immediate refusal of a Solana/Bitcoin connect while unlocked: no account to offer
    /// (4100 with the reason, spec/05 §4.9). With Bitcoin off every Bitcoin request is
    /// `NoBtcAccount`.
    pub(crate) fn chain_unlocked_refusal(&self, site: &SiteRequest) -> Option<ProviderError> {
        if matches!(
            site.kind,
            SiteKind::BtcConnect(_) | SiteKind::BtcSign { .. }
        ) && !self.settings.bitcoin.enabled
        {
            return Some(ProviderError::NoBtcAccount);
        }
        match &site.kind {
            SiteKind::SolConnect => self
                .sol_dapp_rows()
                .is_empty()
                .then_some(ProviderError::NoSolAccount),
            SiteKind::BtcConnect(purposes) => {
                let rows = self.btc_dapp_rows();
                purposes
                    .iter()
                    .any(|purpose| {
                        !rows
                            .iter()
                            .any(|row| purpose.accepts(row.entry.script_type))
                    })
                    .then_some(ProviderError::NoBtcAccount)
            }
            _ => None,
        }
    }

    /// The connect-window choices of a Solana or Bitcoin connect: `(choice, label, address,
    /// group)`, the default selection (the granted account, else the first of each group) and
    /// the network name.
    pub(crate) fn chain_connect_choices(
        &self,
        site: &SiteRequest,
    ) -> (Vec<ConnectEntry>, Vec<bool>, String) {
        let mut choices = Vec::new();
        let mut selected = Vec::new();
        match &site.kind {
            SiteKind::SolConnect => {
                let granted = self
                    .browser
                    .as_ref()
                    .and_then(|browser| {
                        browser
                            .core
                            .sol_grants()
                            .into_iter()
                            .find(|grant| grant.origin == site.origin)
                    })
                    .map(|grant| grant.public);
                let rows = self.sol_dapp_rows();
                let pick = rows
                    .iter()
                    .position(|row| Some(row.public) == granted)
                    .unwrap_or(0);
                for (index, row) in rows.into_iter().enumerate() {
                    choices.push((
                        ConnectChoice::Sol(row.public),
                        format!("{} · {}", row.label, row.path),
                        yw_core::codec::base58::base58_encode(&row.public),
                        0,
                    ));
                    selected.push(index == pick);
                }
                (
                    choices,
                    selected,
                    self.sol_cluster().display_name().to_owned(),
                )
            }
            SiteKind::BtcConnect(purposes) => {
                let rows = self.btc_dapp_rows();
                for (group, purpose) in purposes.iter().enumerate() {
                    let mut first = true;
                    for row in rows
                        .iter()
                        .filter(|row| purpose.accepts(row.entry.script_type))
                    {
                        let mut entry = row.entry.clone();
                        entry.purpose = *purpose;
                        let prefix = match purpose {
                            BtcPurpose::Payment => "[결제용] ",
                            BtcPurpose::Ordinals => "[오디널스용] ",
                            BtcPurpose::Any => "",
                        };
                        choices.push((
                            ConnectChoice::Btc(entry),
                            format!("{prefix}{} · {}", row.label, row.path),
                            row.entry.address.clone(),
                            u8::try_from(group).unwrap_or(0),
                        ));
                        selected.push(first);
                        first = false;
                    }
                }
                (
                    choices,
                    selected,
                    self.btc_network_now().display_name().to_owned(),
                )
            }
            _ => (choices, selected, String::new()),
        }
    }

    /// Whether the chosen accounts are still the wallet's on the settings network (the window
    /// may have been open across a Bitcoin network change, a hidden account or a removed key).
    fn chain_choices_current(&self, choices: &[ConnectChoice]) -> bool {
        let sol = self.sol_dapp_rows();
        let btc = if choices
            .iter()
            .any(|choice| matches!(choice, ConnectChoice::Btc(_)))
        {
            self.btc_dapp_rows()
        } else {
            Vec::new()
        };
        choices.iter().all(|choice| match choice {
            ConnectChoice::Sol(public) => sol.iter().any(|row| row.public == *public),
            ConnectChoice::Btc(entry) => btc.iter().any(|row| {
                row.entry.address == entry.address
                    && row.entry.pubkey == entry.pubkey
                    && row.entry.script_type == entry.script_type
            }),
            ConnectChoice::Evm(_) => false,
        })
    }

    /// A Solana/Bitcoin connect window was approved with `choices`: grant saved, answer sent,
    /// then the account event to the origin's documents. The choices are checked against the
    /// accounts of now (4100 `Unauthorized` when one is gone, e.g. after a Bitcoin network
    /// change while the window was open) and the 256-grant limit (4100 `TooManySites`).
    pub(crate) fn chain_connect_approved(&mut self, site: &SiteRequest, choices: &[ConnectChoice]) {
        let now = now_unix_ms();
        let Some(browser) = self.browser.as_ref() else {
            return;
        };
        let core = std::sync::Arc::clone(&browser.core);
        let family = site.kind.family();
        if family == Family::Bitcoin && !self.settings.bitcoin.enabled {
            self.respond(&site.reply, Err(ProviderError::NoBtcAccount));
            return;
        }
        if !self.chain_choices_current(choices) {
            logging::info("browser", "site.connect_stale", &[]);
            self.respond(&site.reply, Err(ProviderError::Unauthorized));
            return;
        }
        if !core.chain_grant_room(&site.origin, family) {
            self.respond(&site.reply, Err(ProviderError::TooManySites));
            return;
        }
        match &site.kind {
            SiteKind::SolConnect => {
                let [ConnectChoice::Sol(public)] = choices else {
                    self.respond(&site.reply, Err(ProviderError::Internal));
                    return;
                };
                self.respond(
                    &site.reply,
                    Ok(crate::browser::dispatch::sol_connect_value(public)),
                );
                let _ = core.upsert_sol_grant(SolGrant {
                    origin: site.origin.clone(),
                    public: *public,
                    granted_at_unix_ms: now,
                });
            }
            SiteKind::BtcConnect(purposes) => {
                let entries: Vec<BtcGrantAddress> = choices
                    .iter()
                    .filter_map(|choice| match choice {
                        ConnectChoice::Btc(entry) => Some(entry.clone()),
                        _ => None,
                    })
                    .collect();
                let Some(grant) =
                    BtcGrant::new(site.origin.clone(), self.btc_network_now(), entries, now)
                        .filter(|grant| grant.addresses.len() == purposes.len())
                else {
                    self.respond(&site.reply, Err(ProviderError::Internal));
                    return;
                };
                self.respond(
                    &site.reply,
                    Ok(crate::browser::dispatch::btc_accounts_value(&grant, None)),
                );
                let _ = core.upsert_btc_grant(grant);
            }
            _ => return,
        }
        self.write_grants();
        logging::info("browser", "site.connected", &[("accounts", Field::Num(1))]);
    }

    /// Checks of a queued Solana/Bitcoin site item (unlocked); `None` = not a chain kind,
    /// `Some(None)` = passed (show the window), `Some(Some(outcome))` = finished.
    #[expect(
        clippy::option_option,
        reason = "not-mine / passed / finished, as `site_preflight` reads it"
    )]
    pub(crate) fn chain_site_preflight(
        &mut self,
        site: &SiteRequest,
    ) -> Option<Option<QueueOutcome>> {
        let core = std::sync::Arc::clone(&self.browser.as_ref()?.core);
        // Queued while locked (no dispatcher check then): no account to offer, Bitcoin off, or
        // a new origin past the 256-grant limit end here with the reason (spec/05 §4.9).
        let refusal = || {
            self.chain_unlocked_refusal(site).or_else(|| {
                (site.kind.is_connect() && !core.chain_grant_room(&site.origin, site.kind.family()))
                    .then_some(ProviderError::TooManySites)
            })
        };
        Some(match &site.kind {
            SiteKind::SolConnect => {
                // A grant answers at once only while its account is still a visible one.
                let rows = self.sol_dapp_rows();
                if let Some(grant) = core.sol_grants().into_iter().find(|g| {
                    g.origin == site.origin && rows.iter().any(|row| row.public == g.public)
                }) {
                    self.respond(
                        &site.reply,
                        Ok(crate::browser::dispatch::sol_connect_value(&grant.public)),
                    );
                    Some(QueueOutcome::Approved)
                } else if let Some(error) = refusal() {
                    self.respond(&site.reply, Err(error));
                    Some(QueueOutcome::Cancelled)
                } else {
                    None
                }
            }
            SiteKind::BtcConnect(_) | SiteKind::BtcSign { .. }
                if !self.settings.bitcoin.enabled =>
            {
                self.respond(&site.reply, Err(ProviderError::NoBtcAccount));
                Some(QueueOutcome::Cancelled)
            }
            SiteKind::BtcConnect(_) => refusal().map(|error| {
                self.respond(&site.reply, Err(error));
                QueueOutcome::Cancelled
            }),
            SiteKind::SolSign { public, .. } => {
                let granted = core
                    .sol_grants()
                    .iter()
                    .any(|g| g.origin == site.origin && g.public == *public);
                let known = self.sol_dapp_rows().iter().any(|row| row.public == *public);
                (!granted || !known).then_some(QueueOutcome::Revoked)
            }
            SiteKind::BtcSign {
                address, protocol, ..
            } => {
                let net = self.btc_network_now();
                let granted = core.btc_grants().iter().any(|g| {
                    g.origin == site.origin && g.network == net && g.entry(address).is_some()
                });
                match self
                    .btc_dapp_rows()
                    .into_iter()
                    .find(|row| row.entry.address == *address)
                {
                    Some(row) if granted => {
                        let protocol = protocol.unwrap_or(default_protocol(row.entry.script_type));
                        if protocol.supports(row.entry.script_type) {
                            None
                        } else {
                            // e.g. ECDSA for a Taproot address: no BIP137 header exists.
                            self.respond(&site.reply, Err(ProviderError::InvalidParams));
                            Some(QueueOutcome::Cancelled)
                        }
                    }
                    _ => Some(QueueOutcome::Revoked),
                }
            }
            _ => return None,
        })
    }

    /// The approval draft of a Solana/Bitcoin message request (`None` when the account is gone).
    pub(crate) fn chain_sign_draft(&self, site: &SiteRequest) -> Option<ApprovalDraft> {
        let id = Self::new_approval_id().ok()?;
        match &site.kind {
            SiteKind::SolSign {
                public,
                message,
                sign_in,
            } => {
                let row = self
                    .sol_dapp_rows()
                    .into_iter()
                    .find(|row| row.public == *public)?;
                build_sol_message_request(
                    &SolMessageRequest {
                        id,
                        origin: site.origin.clone(),
                        cluster: self.sol_cluster(),
                        source: row.source,
                        public: *public,
                        label: row.label,
                        message: message.clone(),
                        sign_in: *sign_in,
                    },
                    now_unix_ms(),
                )
                .ok()
            }
            SiteKind::BtcSign {
                address,
                message,
                protocol,
            } => {
                let row = self
                    .btc_dapp_rows()
                    .into_iter()
                    .find(|row| row.entry.address == *address)?;
                build_btc_message_request(&BtcMessageRequest {
                    id,
                    origin: site.origin.clone(),
                    network: self.btc_network_now(),
                    source: row.source,
                    pubkey: row.entry.pubkey,
                    script_type: row.entry.script_type,
                    label: row.label,
                    path: row.path,
                    protocol: protocol.unwrap_or(default_protocol(row.entry.script_type)),
                    message: message.clone(),
                })
                .ok()
            }
            _ => None,
        }
    }

    /// The waiter of an approved chain message (from the site kind and the approved payload).
    pub(crate) fn chain_waiter(site: &SiteRequest, payload: &SigningPayload) -> Option<SignWaiter> {
        let answer = match (&site.kind, payload) {
            (
                SiteKind::SolSign {
                    public,
                    message,
                    sign_in,
                },
                SigningPayload::SolMessage(_),
            ) => ChainAnswer::Sol {
                public: *public,
                message: message.clone(),
                sign_in: *sign_in,
            },
            (SiteKind::BtcSign { address, .. }, SigningPayload::BtcMessage(payload)) => {
                ChainAnswer::Btc {
                    address: address.clone(),
                    protocol: payload.protocol,
                }
            }
            _ => return None,
        };
        Some(SignWaiter::Chain(site.reply, Box::new(answer)))
    }

    /// `SignChainMessage` finished: the dApp gets the signature, 4001 after a lock, -32603
    /// otherwise.
    pub(crate) fn browser_chain_message_signed(&mut self, signed: &ChainMessageSigned) {
        let Some(SignWaiter::Chain(reply, answer)) = self.take_sign_waiter(signed.ticket) else {
            return;
        };
        let body = match &signed.result {
            Ok(signature) => chain_answer_value(&answer, signature).ok_or(ProviderError::Internal),
            Err(true) => Err(ProviderError::UserRejected),
            Err(false) => Err(ProviderError::Internal),
        };
        self.respond(&reply, body);
    }

    /// A Solana account was hidden or its imported key removed: every grant naming it is
    /// deleted and written to meta, its origins get `solAccountsChanged([])` and their waiting
    /// Solana signing items end `Revoked` (spec/05 §4.9; importing the key again does not bring
    /// a connection back).
    pub(crate) fn sol_account_removed_from_sites(&mut self, public: &[u8; 32]) {
        // The same key may still be a visible account (an imported copy of a derived key).
        if self.sol_dapp_rows().iter().any(|row| row.public == *public) {
            return;
        }
        let origins = self
            .browser
            .as_ref()
            .map(|browser| browser.core.remove_sol_account(public))
            .unwrap_or_default();
        self.chain_grants_removed(&origins, Family::Solana);
    }

    /// Bitcoin addresses left the wallet (an imported key removed): every grant listing one is
    /// deleted as a whole, like [`Self::sol_account_removed_from_sites`].
    pub(crate) fn btc_addresses_removed_from_sites(&mut self, addresses: &[String]) {
        // An address another account still has (any network) stays connected.
        let held: Vec<String> = self.meta.as_ref().map_or_else(Vec::new, |meta| {
            meta.btc
                .as_deref()
                .into_iter()
                .chain(meta.btc_accounts.accounts.iter())
                .filter_map(|account| {
                    let address = account.address(BtcChain::Receive, 0).ok()?;
                    Some(address.as_str().to_owned())
                })
                .collect()
        });
        let mut origins = Vec::new();
        if let Some(browser) = self.browser.as_ref() {
            for address in addresses.iter().filter(|address| !held.contains(address)) {
                origins.extend(browser.core.remove_btc_address(address));
            }
        }
        self.chain_grants_removed(&origins, Family::Bitcoin);
    }

    fn chain_grants_removed(&mut self, origins: &[BrowserOrigin], family: Family) {
        if origins.is_empty() {
            return;
        }
        for origin in origins {
            self.revoke_waiting(origin, family);
        }
        self.write_grants();
        logging::info(
            "browser",
            "site.account_removed",
            &[("sites", Field::Num(origins.len() as u64))],
        );
    }

    /// Disconnects the Solana or Bitcoin grant of `origin` (S13, dApp disconnect after unlock).
    pub fn disconnect_chain_site(&mut self, origin: &BrowserOrigin, family: Family) {
        if let Some(browser) = self.browser.as_ref() {
            match family {
                Family::Solana => {
                    browser.core.remove_sol_grant(origin);
                }
                Family::Bitcoin => {
                    browser.core.remove_btc_grant(origin);
                }
                Family::Evm => {}
            }
        }
        self.revoke_waiting(origin, family);
        self.write_grants();
        logging::info("browser", "site.disconnected", &[]);
        self.refresh();
    }
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;
    use std::sync::Arc;

    use super::{ChainAnswer, ConnectChoice, chain_answer_value, default_protocol};
    use crate::apikeys::ApiKeys;
    use crate::app::{App, Paths};
    use crate::app_approval::ConnectState;
    use crate::app_browser::{BrowserUi, GrantWrite};
    use crate::browser::envelope::{Correlation, Id16, Id32};
    use crate::browser::{Reply, SiteKind, SiteRequest};
    use crate::events::{ChainSignature, EventQueue};
    use crate::settings::Settings;
    use crate::ui::approval::QueueOutcome;
    use yw_core::approval::{ApprovalKind, RiskLevel};
    use yw_core::btc::msgsign::{BtcMessageProtocol, BtcMessageSignature};
    use yw_core::btc::{BtcPubKey, ScriptType};
    use yw_core::policy::{BrowserOrigin, BtcGrantAddress, BtcPurpose, Family, ProviderError};

    const SOL_KEY: &str = "FVen3X669xLzsi6N2V91DoiyzHzg1uAgqiT8jZ9nS96Z";

    fn app(with_sol: bool) -> App {
        let dir = std::env::temp_dir().join(format!("yw-app-chain-{}", std::process::id()));
        let mut app = App::new(
            Paths {
                data: dir.clone(),
                logs: dir.join("logs"),
            },
            true,
            Settings::default(),
            ApiKeys::default(),
        );
        let events = Arc::new(EventQueue::new(Box::new(|| {})));
        let core = crate::browser::BrowserCore::new(
            "abcdefghijklmnopabcdefghijklmnop",
            events as Arc<dyn crate::browser::DappSink>,
            Arc::new(crate::flow::evm::SystemClock),
        );
        app.browser = Some(BrowserUi {
            core,
            reads: Arc::new(crate::browser::read::ReadContext::new(None)),
            server: None,
            pipe_error: None,
            threads: Vec::new(),
            connections: 0,
            waiters: HashMap::new(),
            broadcasts: HashMap::new(),
            dapp_unlock: false,
            unlocked: false,
            locking: false,
            grant_write: GrantWrite::default(),
            site_rows: crate::app_browser::SiteRows::default(),
        });
        let mut meta = crate::meta::Meta::default();
        if with_sol {
            meta.sol_accounts.push(crate::meta::Account {
                index: 0,
                label: "SOL 1".to_owned(),
                address: SOL_KEY.to_owned(),
                hidden: false,
            });
        }
        app.meta = Some(meta);
        app
    }

    fn site(kind: SiteKind) -> SiteRequest {
        SiteRequest {
            reply: Reply {
                conn: 1,
                correlation: Correlation {
                    session_id: Id32([1; 32]),
                    sequence: 1,
                    activation_nonce: Id32([2; 32]),
                    request_id: Id16([3; 16]),
                },
            },
            origin: BrowserOrigin::parse("https://app.example").unwrap(),
            chain_id: yw_core::evm::chain::SEPOLIA,
            deadline_ms: u64::MAX,
            method: yw_core::policy::Method::SolConnect,
            kind,
            compat_mode: None,
        }
    }

    fn public() -> [u8; 32] {
        yw_core::codec::base58::base58_decode_32(SOL_KEY).unwrap()
    }

    #[test]
    fn connect_refusals_and_choices() {
        let empty = app(false);
        assert_eq!(
            empty.chain_unlocked_refusal(&site(SiteKind::SolConnect)),
            Some(ProviderError::NoSolAccount)
        );
        assert_eq!(
            empty.chain_unlocked_refusal(&site(SiteKind::BtcConnect(vec![BtcPurpose::Ordinals]))),
            Some(ProviderError::NoBtcAccount)
        );
        let app = app(true);
        assert_eq!(
            app.chain_unlocked_refusal(&site(SiteKind::SolConnect)),
            None
        );
        let (choices, selected, network) = app.chain_connect_choices(&site(SiteKind::SolConnect));
        assert_eq!(choices.len(), 1);
        assert_eq!(selected, vec![true]);
        assert!(matches!(&choices[0].0, ConnectChoice::Sol(key) if *key == public()));
        assert_eq!(choices[0].2, SOL_KEY);
        assert!(network.starts_with("Solana"));
    }

    #[test]
    fn signing_preflight_and_drafts() {
        let mut app = app(true);
        let sign = site(SiteKind::SolSign {
            public: public(),
            message: b"Prove it".to_vec(),
            sign_in: false,
        });
        // Not granted: revoked (4100).
        assert_eq!(
            app.chain_site_preflight(&sign),
            Some(Some(QueueOutcome::Revoked))
        );
        if let Some(browser) = app.browser.as_ref() {
            browser.core.upsert_sol_grant(yw_core::policy::SolGrant {
                origin: sign.origin.clone(),
                public: public(),
                granted_at_unix_ms: 1,
            });
        }
        assert_eq!(app.chain_site_preflight(&sign), Some(None));
        let draft = app.chain_sign_draft(&sign).unwrap();
        assert_eq!(draft.kind, ApprovalKind::SolMessage);
        assert_eq!(draft.display.risk, RiskLevel::Info);
        // Transaction bytes are blocked in the window.
        let mut tx = vec![1, 0, 1, 2];
        tx.extend_from_slice(&[0x11; 96]);
        tx.extend_from_slice(&[1, 1, 1, 0, 4, 2, 0, 0, 0]);
        let blocked = site(SiteKind::SolSign {
            public: public(),
            message: tx,
            sign_in: false,
        });
        assert_eq!(
            app.chain_sign_draft(&blocked).unwrap().display.risk,
            RiskLevel::Blocked
        );
        let waiter = App::chain_waiter(&sign, &draft.payload);
        assert!(matches!(
            waiter,
            Some(crate::app_browser::SignWaiter::Chain(_, _))
        ));
        // EVM kinds are not chain kinds.
        assert_eq!(
            app.chain_site_preflight(&site(SiteKind::RequestAccounts)),
            None
        );
    }

    #[test]
    fn btc_connect_window_is_one_radio_per_purpose() {
        let entry = |purpose, script_type, address: &str| {
            ConnectChoice::Btc(BtcGrantAddress {
                purpose,
                address: address.to_owned(),
                pubkey: BtcPubKey::Compressed([2; 33]),
                script_type,
            })
        };
        let mut state = ConnectState {
            accounts: vec![
                (
                    entry(BtcPurpose::Payment, ScriptType::P2wpkh, "a"),
                    String::new(),
                    "a".to_owned(),
                    0,
                ),
                (
                    entry(BtcPurpose::Payment, ScriptType::P2shP2wpkh, "b"),
                    String::new(),
                    "b".to_owned(),
                    0,
                ),
                (
                    entry(BtcPurpose::Ordinals, ScriptType::P2tr, "c"),
                    String::new(),
                    "c".to_owned(),
                    1,
                ),
            ],
            selected: vec![true, false, false],
            chain_name: String::new(),
            family: Family::Bitcoin,
            groups: 2,
        };
        assert_eq!(state.gate_count(), 0, "ordinals group empty");
        state.toggle(2);
        assert_eq!(state.gate_count(), 2);
        state.toggle(1);
        assert_eq!(state.selected, vec![false, true, true]);
        assert_eq!(state.gate_count(), 2);
    }

    fn sol_grant(origin: &str, public: [u8; 32]) -> yw_core::policy::SolGrant {
        yw_core::policy::SolGrant {
            origin: BrowserOrigin::parse(origin).unwrap(),
            public,
            granted_at_unix_ms: 1,
        }
    }

    fn core(app: &App) -> Arc<crate::browser::BrowserCore> {
        Arc::clone(&app.browser.as_ref().unwrap().core)
    }

    /// The dispatcher view of an unlocked wallet with the app's current accounts.
    fn unlocked_view(app: &App) -> crate::browser::WalletView {
        crate::browser::WalletView {
            vault: crate::browser::VaultView::Unlocked,
            sol_accounts: app.sol_dapp_rows().iter().map(|row| row.public).collect(),
            btc_enabled: true,
            btc_network: app.btc_network_now(),
            btc_accounts: app
                .btc_dapp_rows()
                .into_iter()
                .map(|row| row.entry.address)
                .collect(),
            ..crate::browser::WalletView::default()
        }
    }

    /// Lock, then unlock with the grants meta holds now (what the next session sees).
    fn relock(app: &App) -> bool {
        let core = core(app);
        core.lock_wallet();
        core.set_wallet(unlocked_view(app));
        let meta = app.meta.as_ref().unwrap();
        core.unlock_chains(
            crate::browser::grants::sol_sites_from_values(&meta.chain_sites.sol),
            crate::browser::grants::btc_sites_from_values(&meta.chain_sites.btc),
        )
    }

    #[test]
    fn removed_or_hidden_solana_accounts_lose_their_grants_for_good() {
        let mut app = app(true);
        let key7 = yw_core::sol::SolAddress::from_bytes([7; 32]).to_base58();
        let imported = crate::meta::SolRawAccount {
            record_id: [5; 16],
            label: "가져온 키".to_owned(),
            address: key7,
        };
        // A second imported copy of the derived account 0 key.
        let duplicate = crate::meta::SolRawAccount {
            record_id: [6; 16],
            label: "같은 키".to_owned(),
            address: SOL_KEY.to_owned(),
        };
        let meta = app.meta.as_mut().unwrap();
        meta.sol_raw_accounts.push(imported.clone());
        meta.sol_raw_accounts.push(duplicate);
        let core = core(&app);
        assert!(core.upsert_sol_grant(sol_grant("https://app.example", [7; 32])));
        assert!(core.upsert_sol_grant(sol_grant("https://other.example", [9; 32])));
        assert!(core.upsert_sol_grant(sol_grant("https://dup.example", public())));
        app.write_grants();
        assert_eq!(app.meta.as_ref().unwrap().chain_sites.sol.len(), 3);
        // The imported key is removed: its grant leaves the dispatcher and meta.
        app.on_imported_key_removed(
            yw_core::vault::RecordId::from_bytes([5; 16]),
            yw_core::keyimport::ImportChain::Sol,
        );
        let left: Vec<[u8; 32]> = core.sol_grants().iter().map(|g| g.public).collect();
        assert_eq!(left, vec![[9; 32], public()]);
        assert_eq!(app.meta.as_ref().unwrap().chain_sites.sol.len(), 2);
        // Removing an imported copy of a key that is still a visible account keeps its grant.
        app.on_imported_key_removed(
            yw_core::vault::RecordId::from_bytes([6; 16]),
            yw_core::keyimport::ImportChain::Sol,
        );
        assert_eq!(core.sol_grants().len(), 2);
        // Importing the same key again does not bring the connection back.
        app.meta.as_mut().unwrap().sol_raw_accounts.push(imported);
        assert!(!relock(&app));
        assert!(
            core.sol_grants()
                .iter()
                .all(|grant| grant.public != [7; 32])
        );
        // Hiding a derived account (index 1) drops its grants the same way.
        let meta = app.meta.as_mut().unwrap();
        meta.sol_raw_accounts.clear();
        meta.sol_accounts.push(crate::meta::Account {
            index: 1,
            label: "SOL 2".to_owned(),
            address: yw_core::sol::SolAddress::from_bytes([9; 32]).to_base58(),
            hidden: false,
        });
        meta.prefs.sol_account = 1;
        app.sol_hide_selected();
        let left: Vec<[u8; 32]> = core.sol_grants().iter().map(|g| g.public).collect();
        assert_eq!(left, vec![public()]);
        assert_eq!(app.meta.as_ref().unwrap().chain_sites.sol.len(), 1);
    }

    #[test]
    fn removed_bitcoin_account_drops_every_grant_listing_its_address() {
        use yw_core::btc::{BtcAccountKey, BtcAccounts, BtcMeta, BtcNetwork};
        let mut app = app(false);
        let node = yw_core::bip32::AccountXpub {
            pubkey: yw_core::hex::decode_array::<33>(
                "03b88e0fbe3f646337ed93bc0c0f3b843fcf7d2589e5ec884754e6402027a890b4",
            )
            .unwrap(),
            chain_code: [7; 32],
        };
        let key = BtcAccountKey::hd(ScriptType::P2wpkh, 1, node).unwrap();
        let account = BtcMeta::with_key(BtcNetwork::Mainnet, key);
        let address = account
            .address(yw_core::bip32::path::BtcChain::Receive, 0)
            .unwrap()
            .as_str()
            .to_owned();
        let mut accounts = BtcAccounts::default();
        accounts.upsert(account).unwrap();
        app.meta.as_mut().unwrap().btc_accounts = accounts;
        let grant = yw_core::policy::BtcGrant::new(
            BrowserOrigin::parse("https://app.example").unwrap(),
            BtcNetwork::Mainnet,
            vec![BtcGrantAddress {
                purpose: BtcPurpose::Payment,
                address,
                pubkey: BtcPubKey::Compressed([2; 33]),
                script_type: ScriptType::P2wpkh,
            }],
            1,
        )
        .unwrap();
        let core = core(&app);
        assert!(core.upsert_btc_grant(grant));
        app.write_grants();
        // The key worker reports the account gone (imported key removed).
        app.btc_apply(vec![crate::app_btc::BtcAction::SetMeta(
            None,
            Box::default(),
        )]);
        assert!(core.btc_grants().is_empty());
        assert!(app.meta.as_ref().unwrap().chain_sites.btc.is_empty());
    }

    #[test]
    fn preflight_checks_hidden_accounts_bitcoin_off_and_the_grant_limit() {
        let mut app = app(true);
        let core = core(&app);
        // A grant of a key that is no longer a visible account: the window, not the old key.
        assert!(core.upsert_sol_grant(sol_grant("https://app.example", [9; 32])));
        assert_eq!(
            app.chain_site_preflight(&site(SiteKind::SolConnect)),
            Some(None)
        );
        assert!(core.upsert_sol_grant(sol_grant("https://app.example", public())));
        assert_eq!(
            app.chain_site_preflight(&site(SiteKind::SolConnect)),
            Some(Some(QueueOutcome::Approved))
        );
        // Bitcoin off: every Bitcoin request ends with NoBtcAccount, without a window.
        app.settings.bitcoin.enabled = false;
        let btc_connect = site(SiteKind::BtcConnect(vec![BtcPurpose::Payment]));
        assert_eq!(
            app.chain_unlocked_refusal(&btc_connect),
            Some(ProviderError::NoBtcAccount)
        );
        let btc_sign = site(SiteKind::BtcSign {
            address: "bc1q".to_owned(),
            message: b"hi".to_vec(),
            protocol: None,
        });
        assert_eq!(
            app.chain_site_preflight(&btc_sign),
            Some(Some(QueueOutcome::Cancelled))
        );
        assert_eq!(
            app.chain_site_preflight(&btc_connect),
            Some(Some(QueueOutcome::Cancelled))
        );
        // 256 Solana grants (queued while locked, so the dispatcher never checked): a new origin
        // is refused before the window; the granted origin is still answered.
        for index in 0..yw_core::policy::MAX_CHAIN_GRANTS - 1 {
            assert!(
                core.upsert_sol_grant(sol_grant(&format!("https://s{index}.example"), [9; 32]))
            );
        }
        let mut other = site(SiteKind::SolConnect);
        other.origin = BrowserOrigin::parse("https://new.example").unwrap();
        assert_eq!(
            app.chain_site_preflight(&other),
            Some(Some(QueueOutcome::Cancelled))
        );
        assert_eq!(
            app.chain_site_preflight(&site(SiteKind::SolConnect)),
            Some(Some(QueueOutcome::Approved))
        );
        // An approval that would pass the limit stores nothing.
        app.chain_connect_approved(&other, &[ConnectChoice::Sol(public())]);
        assert_eq!(core.sol_grants().len(), yw_core::policy::MAX_CHAIN_GRANTS);
        assert!(core.sol_grants().iter().all(|g| g.origin != other.origin));
    }

    #[test]
    fn stale_connect_choices_are_refused() {
        let mut app = app(true);
        let core = core(&app);
        // The chosen key is not (or no longer) one of the wallet's accounts.
        app.chain_connect_approved(&site(SiteKind::SolConnect), &[ConnectChoice::Sol([9; 32])]);
        assert!(core.sol_grants().is_empty());
        // A Bitcoin address of the other network (the network changed while the window was open).
        let choice = ConnectChoice::Btc(BtcGrantAddress {
            purpose: BtcPurpose::Payment,
            address: "tb1qstale".to_owned(),
            pubkey: BtcPubKey::Compressed([2; 33]),
            script_type: ScriptType::P2wpkh,
        });
        app.settings.bitcoin.enabled = true;
        app.chain_connect_approved(
            &site(SiteKind::BtcConnect(vec![BtcPurpose::Payment])),
            &[choice],
        );
        assert!(core.btc_grants().is_empty());
        app.chain_connect_approved(&site(SiteKind::SolConnect), &[ConnectChoice::Sol(public())]);
        assert_eq!(core.sol_grants().len(), 1);
    }

    #[test]
    fn site_rows_disconnect_the_grant_they_were_drawn_for_and_page() {
        use crate::ui::screens_sites::ids;
        let mut app = app(true);
        let core = core(&app);
        for index in 0..120 {
            assert!(
                core.upsert_sol_grant(sol_grant(&format!("https://s{index}.example"), [9; 32]))
            );
        }
        let keys = |app: &App| -> Vec<String> {
            app.browser
                .as_ref()
                .unwrap()
                .site_rows
                .keys
                .borrow()
                .iter()
                .map(|(origin, family)| {
                    assert_eq!(*family, Family::Solana);
                    origin.as_str().to_owned()
                })
                .collect()
        };
        let mut items = Vec::new();
        app.sites_screen(&mut items);
        let drawn = keys(&app);
        assert_eq!(drawn.len(), ids::SITES_PAGE_ROWS);
        assert_eq!(drawn[0], "https://s0.example");
        // The list changes under the screen (a dApp disconnected s0 meanwhile): the first
        // button still means s0 — nothing else is disconnected.
        assert!(core.remove_sol_grant(&BrowserOrigin::parse("https://s0.example").unwrap()));
        assert!(app.on_sites_command(ids::SITE_ROW_BASE));
        assert_eq!(core.sol_grants().len(), 119);
        assert!(app.on_sites_command(ids::SITE_ROW_BASE + 1));
        assert_eq!(core.sol_grants().len(), 118);
        assert!(
            core.sol_grants()
                .iter()
                .all(|g| g.origin.as_str() != "https://s1.example")
        );
        // Pages: every grant gets a button (no 256-row limit), 50 per page.
        assert!(app.on_sites_command(ids::SITES_NEXT));
        app.sites_screen(&mut Vec::new());
        assert_eq!(keys(&app)[0], "https://s52.example");
        assert!(app.on_sites_command(ids::SITES_NEXT));
        assert!(app.on_sites_command(ids::SITES_NEXT));
        app.sites_screen(&mut Vec::new());
        assert_eq!(keys(&app).len(), 18);
        assert_eq!(keys(&app).last().unwrap(), "https://s119.example");
        assert!(app.on_sites_command(ids::SITES_PREV));
        app.sites_screen(&mut Vec::new());
        assert_eq!(keys(&app)[0], "https://s52.example");
    }

    /// What `show_next_approval` does up to the window: the next shown site item that passed its
    /// preflight (items finished by the preflight are answered and skipped).
    fn next_window(app: &mut App) -> Option<SiteRequest> {
        use crate::app_evm::QueuedItem;
        loop {
            let mut finished = Vec::new();
            let shown = app.evm.queue.show_next(0, &mut finished);
            for (item, outcome) in finished {
                app.approval_finished(&item.payload, outcome);
            }
            shown?;
            let QueuedItem::Site(site) = app.evm.queue.shown()?.payload.clone() else {
                return None;
            };
            match app.site_preflight(&site) {
                Some(outcome) => {
                    if let Some((done, outcome)) = app.evm.queue.finish_shown(outcome) {
                        app.approval_finished(&done.payload, outcome);
                    }
                }
                None => return Some(*site),
            }
        }
    }

    /// Regression (screenshot tour): after a rejected `sol_signMessage`, the following
    /// `btc_signMessage` of the same site never got a window. The queue was fine; every Bitcoin
    /// message draft (and every SIWS / off-chain Solana draft) carried a display key without a
    /// window label (0x0406 `서명 방식`, 0x0405 SIWS), so `validate_for_display` failed and the
    /// window closed at once with E-UI-001.
    #[test]
    fn chain_message_windows_follow_each_other_after_a_rejection() {
        use crate::app_evm::QueuedItem;
        use crate::ui::approval::{QueueSource, field_label, validate_for_display};
        use yw_core::btc::{BtcAccountKey, BtcMeta};
        for key in 0..=u16::MAX {
            let key = yw_core::approval::FieldKey(key);
            assert!(
                key.flags().is_none() || field_label(key).is_some(),
                "display key {key:?} has no window label"
            );
        }
        let mut app = app(true);
        app.settings.bitcoin.enabled = true;
        let node = yw_core::bip32::AccountXpub {
            pubkey: yw_core::hex::decode_array::<33>(
                "03b88e0fbe3f646337ed93bc0c0f3b843fcf7d2589e5ec884754e6402027a890b4",
            )
            .unwrap(),
            chain_code: [7; 32],
        };
        let key = BtcAccountKey::hd(ScriptType::P2wpkh, 1, node).unwrap();
        let account = BtcMeta::with_key(app.btc_network_now(), key);
        app.meta
            .as_mut()
            .unwrap()
            .btc_accounts
            .upsert(account)
            .unwrap();
        let row = app.btc_dapp_rows().pop().unwrap();
        let core = core(&app);
        assert!(core.upsert_sol_grant(sol_grant("https://app.example", public())));
        let grant = yw_core::policy::BtcGrant::new(
            BrowserOrigin::parse("https://app.example").unwrap(),
            app.btc_network_now(),
            vec![BtcGrantAddress {
                purpose: BtcPurpose::Payment,
                ..row.entry.clone()
            }],
            1,
        )
        .unwrap();
        assert!(core.upsert_btc_grant(grant));
        let siws = yw_core::sol::msgsign::SiwsMessage {
            domain: "app.example".to_owned(),
            address: SOL_KEY.to_owned(),
            statement: Some("Sign in".to_owned()),
            ..yw_core::sol::msgsign::SiwsMessage::default()
        };
        let sol = |sign_in: bool| {
            site(SiteKind::SolSign {
                public: public(),
                message: if sign_in {
                    siws.to_text().into_bytes()
                } else {
                    b"Prove it".to_vec()
                },
                sign_in,
            })
        };
        let btc = site(SiteKind::BtcSign {
            address: row.entry.address.clone(),
            message: b"Prove it".to_vec(),
            protocol: None,
        });
        let evm = site(SiteKind::RequestAccounts);
        for order in [
            vec![sol(false), btc.clone()],
            vec![btc.clone(), sol(false)],
            vec![sol(true), evm.clone(), btc.clone(), sol(false)],
            vec![evm.clone(), btc.clone(), evm.clone(), sol(true)],
        ] {
            for request in &order {
                let source = QueueSource::Site {
                    origin: request.origin.as_str().to_owned(),
                    deadline_ms: u64::MAX,
                };
                app.evm
                    .queue
                    .enqueue(source, QueuedItem::Site(Box::new(request.clone())))
                    .unwrap();
            }
            for expected in &order {
                // Each request of the site gets its window in turn, and is then rejected.
                let shown = next_window(&mut app).expect("a window for the next request");
                assert_eq!(shown.kind, expected.kind);
                if shown.kind.is_signing() {
                    let draft = app.chain_sign_draft(&shown).unwrap();
                    assert_eq!(validate_for_display(&draft.display), Ok(()));
                    let request = app.evm.store.issue(draft, 0, 0).unwrap();
                    app.evm.store.reject(request.id);
                }
                if let Some((done, outcome)) = app.evm.queue.finish_shown(QueueOutcome::Rejected) {
                    app.approval_finished(&done.payload, outcome);
                }
            }
            assert!(next_window(&mut app).is_none());
            assert!(app.evm.queue.is_empty());
        }
    }

    #[test]
    fn answers_and_defaults() {
        assert_eq!(
            default_protocol(ScriptType::P2tr),
            BtcMessageProtocol::Bip322
        );
        assert_eq!(
            default_protocol(ScriptType::P2wpkh),
            BtcMessageProtocol::Ecdsa
        );
        let sol = ChainAnswer::Sol {
            public: [1; 32],
            message: b"hi".to_vec(),
            sign_in: true,
        };
        let value = chain_answer_value(&sol, &ChainSignature::Sol([2; 64])).unwrap();
        let text = String::from_utf8(yw_json::to_vec(&value)).unwrap();
        assert!(text.contains(r#""signedMessage":"6869""#), "{text}");
        let btc = ChainAnswer::Btc {
            address: "bc1q".to_owned(),
            protocol: BtcMessageProtocol::Bip322,
        };
        let signed = ChainSignature::Btc(BtcMessageSignature {
            signature: "AA==".to_owned(),
            message_hash: [0; 32],
        });
        let text = String::from_utf8(yw_json::to_vec(&chain_answer_value(&btc, &signed).unwrap()))
            .unwrap();
        assert!(text.contains(r#""protocol":"bip322""#), "{text}");
        assert_eq!(
            chain_answer_value(&btc, &ChainSignature::Sol([0; 64])),
            None
        );
    }
}
