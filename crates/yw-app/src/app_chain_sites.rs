//! Solana and Bitcoin dApp connections on the UI thread (spec/05 §4.9, spec/07 §19, spec/08
//! §17): one account per connection and message signing; Solana dApp transactions (spec/07 §20)
//! share the checks and the answer here, their preview and signing are `app_sol_dapp`.
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

use crate::app::Wallet;
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
        /// The requesting site: its grant must still name `public` when the answer goes out
        /// (spec/05 §4.5, 2026-11-13).
        origin: BrowserOrigin,
        /// The signed bytes (returned as `signedMessage` for a sign-in).
        message: Vec<u8>,
        /// `sol_signIn`.
        sign_in: bool,
    },
    /// `btc_signMessage`.
    Btc {
        /// Signing address.
        address: String,
        /// The requesting site: its grant must still list `address` when the answer goes out
        /// (spec/05 §4.5, 2026-11-13).
        origin: BrowserOrigin,
        /// Protocol used.
        protocol: BtcMessageProtocol,
    },
    /// `sol_signTransaction` / `sol_signAllTransactions` / `sol_signAndSendTransaction`.
    SolTx {
        /// Signing account.
        public: [u8; 32],
        /// The requesting site: its grant must still name `public` when the answer goes out
        /// (spec/07 §20.10-4).
        origin: BrowserOrigin,
        /// `sol_signAllTransactions` (`signedTransactions`).
        batch: bool,
        /// `sol_signAndSendTransaction` (answered by the broadcast, not by signed bytes).
        send: bool,
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

/// The answer of a signed chain message (spec/05 §3.6 result shapes).
#[must_use]
pub fn chain_answer_value(answer: &ChainAnswer, signature: &ChainSignature) -> Option<Value> {
    match (answer, signature) {
        (
            ChainAnswer::Sol {
                public,
                message,
                sign_in,
                ..
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
        (
            ChainAnswer::SolTx {
                public,
                batch,
                send: false,
                ..
            },
            ChainSignature::SolTxs(signed),
        ) => {
            let public = (
                "publicKey",
                json_str(&yw_core::codec::base58::base58_encode(public)),
            );
            let hex = |tx: &Vec<u8>| json_str(&yw_core::hex::encode(tx));
            match (batch, signed.as_slice()) {
                (true, list) if !list.is_empty() => Some(json_object(vec![
                    public,
                    (
                        "signedTransactions",
                        Value::Array(list.iter().map(hex).collect()),
                    ),
                ])),
                (false, [one]) => Some(json_object(vec![public, ("signedTransaction", hex(one))])),
                _ => None,
            }
        }
        (
            ChainAnswer::Btc {
                address, protocol, ..
            },
            ChainSignature::Btc(signed),
        ) => Some(json_object(vec![
            ("address", json_str(address)),
            ("signature", json_str(&signed.signature)),
            (
                "messageHash",
                json_str(&yw_core::hex::encode(&signed.message_hash)),
            ),
            ("protocol", json_str(protocol.as_str())),
        ])),
        _ => None,
    }
}

impl Wallet {
    /// The settings Bitcoin network.
    pub(crate) const fn btc_network_now(&self) -> BtcNetwork {
        crate::btc::core_network(self.settings.bitcoin.network)
    }

    /// Visible Solana accounts usable by dApps (standard accounts, then imported keys).
    pub(crate) fn sol_dapp_rows(&self) -> Vec<SolRow> {
        self.sol_account_rows()
            .into_iter()
            .filter_map(|(id, label, address)| {
                // `{label} ({phrase})` with several phrases (S13, the connect window, the
                // approval's account line; 2026-11-10).
                let label = if id.is_imported() || id.is_hardware() {
                    label
                } else {
                    self.mnemonic_named(&label, id.mnemonic())
                };
                Some(SolRow {
                    public: address.to_bytes(),
                    source: id.source()?,
                    label,
                    path: id.path_text_in(self.settings.language),
                })
            })
            .collect()
    }

    /// Every visible Bitcoin account of the settings network with its stable address (a hidden
    /// account is never offered or used, 2026-11-15, spec/05 §4.9).
    pub(crate) fn btc_dapp_rows(&self) -> Vec<BtcRow> {
        let net = self.btc_network_now();
        let ctx = self.btc_ctx();
        ctx.accounts()
            .into_iter()
            .filter(|meta| {
                !self
                    .meta
                    .as_ref()
                    .is_some_and(|document| document.btc_hidden(meta.network(), meta.id()))
            })
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
                    label: self.btc_account_label(account),
                    path: yw_core::btc::text::path_text(
                        self.approval_lang(),
                        account,
                        net,
                        BtcChain::Receive,
                        0,
                    ),
                })
            })
            .collect()
    }

    /// The immediate refusal of a Solana/Bitcoin connect while unlocked: no account to offer
    /// (4100 with the reason, spec/05 §4.9). With Bitcoin off every Bitcoin request is
    /// `BtcDisabled`.
    pub(crate) fn chain_unlocked_refusal(&self, site: &SiteRequest) -> Option<ProviderError> {
        if matches!(
            site.kind,
            SiteKind::BtcConnect(_) | SiteKind::BtcSign { .. }
        ) && !self.settings.bitcoin.enabled
        {
            return Some(ProviderError::BtcDisabled);
        }
        match &site.kind {
            // An account on its way (account 0 derived with the session's meta, spec/07 §3.1)
            // is waited for: [`Self::sol_connect_waits_for_account`].
            SiteKind::SolConnect => (self.sol_dapp_rows().is_empty() && !self.sol.creating)
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

    /// Whether the approval queue waits for a Solana account being derived: a dApp's
    /// `sol_connect` waits in it, the wallet shows no Solana account yet and one is on its way
    /// (account 0 comes with the session's meta, spec/07 §3.1). The queue moves again when the
    /// key worker answers; the connect then gets its window, or `NoSolAccount` if nothing came.
    pub(crate) fn sol_connect_waits_for_account(&self) -> bool {
        self.sol.creating
            && self.evm.queue.waiting_payloads().any(|item| {
                matches!(item, crate::app_evm::QueuedItem::Site(site) if site.kind == SiteKind::SolConnect)
            })
            && self.sol_dapp_rows().is_empty()
    }

    /// The connect-window choices of a Solana or Bitcoin connect: `(choice, label, address,
    /// group)`, the default selection (the granted account, else the first of each group that
    /// can sign) and the network name.
    pub(crate) fn chain_connect_choices(
        &self,
        site: &SiteRequest,
    ) -> (Vec<ConnectEntry>, Vec<bool>, String) {
        match &site.kind {
            SiteKind::SolConnect => self.sol_connect_choices(&site.origin),
            SiteKind::BtcConnect(purposes) => self.btc_connect_choices(&site.origin, purposes),
            _ => (Vec::new(), Vec::new(), String::new()),
        }
    }

    /// [`Self::chain_connect_choices`] of a Solana connect: one radio group.
    fn sol_connect_choices(
        &self,
        origin: &BrowserOrigin,
    ) -> (Vec<ConnectEntry>, Vec<bool>, String) {
        let granted = self
            .browser
            .as_ref()
            .and_then(|browser| {
                browser
                    .core
                    .sol_grants()
                    .into_iter()
                    .find(|grant| grant.origin == *origin)
            })
            .map(|grant| grant.public);
        let rows = self.sol_dapp_rows();
        // An account whose phrase is not backed up, or whose YubiKey is still on its factory
        // PINs, can receive but not sign: tagged, and not the default while another account is.
        let unconfirmed: Vec<_> = rows
            .iter()
            .map(|row| self.sol_source_unconfirmed(row.source))
            .collect();
        let factory: Vec<_> = rows
            .iter()
            .map(|row| self.sol_card_gate(row.source))
            .collect();
        let can_sign = |index: usize| {
            unconfirmed.get(index).is_some_and(Option::is_none)
                && factory.get(index).is_some_and(Option::is_none)
        };
        // A new site starts with the account chosen in the Solana tab (2026-11-10), like the
        // EVM window; a granted account is kept.
        let current = self.sol_selected().and_then(|(_, _, address)| {
            rows.iter().position(|row| row.public == address.to_bytes())
        });
        let pick = rows
            .iter()
            .position(|row| Some(row.public) == granted)
            .or_else(|| current.filter(|index| can_sign(*index)))
            .or_else(|| (0..rows.len()).find(|index| can_sign(*index)))
            .unwrap_or(0);
        let mut choices = Vec::new();
        let mut selected = Vec::new();
        for ((index, row), (phrase, serial)) in rows
            .into_iter()
            .enumerate()
            .zip(unconfirmed.into_iter().zip(factory))
        {
            choices.push((
                ConnectChoice::Sol(row.public),
                format!(
                    "{}{}{}\n{}",
                    row.label,
                    self.mn_connect_tag(phrase),
                    self.card_connect_tag(serial),
                    row.path
                ),
                yw_core::codec::base58::base58_encode(&row.public),
                0,
            ));
            selected.push(index == pick);
        }
        (
            choices,
            selected,
            self.sol_cluster()
                .display_name_in(self.approval_lang())
                .to_owned(),
        )
    }

    /// [`Self::chain_connect_choices`] of a Bitcoin connect: one radio group per purpose.
    fn btc_connect_choices(
        &self,
        origin: &BrowserOrigin,
        purposes: &[BtcPurpose],
    ) -> (Vec<ConnectEntry>, Vec<bool>, String) {
        let rows = self.btc_dapp_rows();
        // The origin's grant on this network: a reconnect starts on the connected addresses
        // (spec/05 §4.9), not on each group's first account.
        let net = self.btc_network_now();
        let granted: Vec<BtcGrantAddress> = self
            .browser
            .as_ref()
            .and_then(|browser| {
                browser
                    .core
                    .btc_grants()
                    .into_iter()
                    .find(|grant| grant.origin == *origin && grant.network == net)
            })
            .map(|grant| grant.addresses)
            .unwrap_or_default();
        // The Bitcoin tab's account (its stable receive address 0, as the rows offer).
        let selected_address = {
            let ctx = self.btc_ctx();
            ctx.btc_meta()
                .and_then(|meta| meta.address(BtcChain::Receive, 0).ok())
                .map(|address| address.as_str().to_owned())
        };
        let mut choices = Vec::new();
        let mut selected = Vec::new();
        for (group, purpose) in purposes.iter().enumerate() {
            let members: Vec<&BtcRow> = rows
                .iter()
                .filter(|row| purpose.accepts(row.entry.script_type))
                .collect();
            let unconfirmed: Vec<_> = members
                .iter()
                .map(|row| self.btc_source_unconfirmed(&row.source))
                .collect();
            let factory: Vec<_> = members
                .iter()
                .map(|row| self.btc_source_card_gate(&row.source))
                .collect();
            let can_sign = |index: usize| {
                unconfirmed.get(index).is_some_and(Option::is_none)
                    && factory.get(index).is_some_and(Option::is_none)
            };
            // The granted address of this purpose, else any granted address this group offers
            // (a UniSat `any` grant asked again for `payment`), else the account chosen in the
            // Bitcoin tab (2026-11-10), else the first account that can sign (one whose phrase
            // is not backed up, or whose YubiKey has its factory PINs, only receives).
            let current = selected_address
                .as_ref()
                .and_then(|address| members.iter().position(|row| row.entry.address == *address));
            let pick = granted
                .iter()
                .filter(|entry| entry.purpose == *purpose)
                .chain(granted.iter())
                .find_map(|entry| {
                    members
                        .iter()
                        .position(|row| row.entry.address == entry.address)
                })
                .or_else(|| current.filter(|index| can_sign(*index)))
                .or_else(|| (0..members.len()).find(|index| can_sign(*index)))
                .unwrap_or(0);
            let prefix = match purpose {
                BtcPurpose::Payment => text::TAG_PAYMENT.get(self.approval_lang()),
                BtcPurpose::Ordinals => text::TAG_ORDINALS.get(self.approval_lang()),
                BtcPurpose::Any => "",
            };
            for ((index, row), (phrase, serial)) in members
                .into_iter()
                .enumerate()
                .zip(unconfirmed.into_iter().zip(factory))
            {
                let mut entry = row.entry.clone();
                entry.purpose = *purpose;
                choices.push((
                    ConnectChoice::Btc(entry),
                    format!(
                        "{prefix}{}{}{}\n{}",
                        row.label,
                        self.mn_connect_tag(phrase),
                        self.card_connect_tag(serial),
                        row.path
                    ),
                    row.entry.address.clone(),
                    u8::try_from(group).unwrap_or(0),
                ));
                selected.push(index == pick);
            }
        }
        (
            choices,
            selected,
            yw_core::btc::text::network_name(self.approval_lang(), net).to_owned(),
        )
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
        let now = self.clock.now_unix_ms();
        let Some(browser) = self.browser.as_ref() else {
            return;
        };
        let core = std::sync::Arc::clone(&browser.core);
        let family = site.kind.family();
        if family == Family::Bitcoin && !self.settings.bitcoin.enabled {
            self.refuse_site(site, ProviderError::BtcDisabled);
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

    /// The origin's Bitcoin grant that may be used now (the settings network, every address
    /// still one of the wallet's) and has an address for every purpose of `purposes`.
    fn btc_grant_covering(
        &self,
        core: &crate::browser::BrowserCore,
        origin: &BrowserOrigin,
        purposes: &[BtcPurpose],
    ) -> Option<BtcGrant> {
        let net = self.btc_network_now();
        let rows = self.btc_dapp_rows();
        core.btc_grants().into_iter().find(|grant| {
            grant.origin == *origin
                && grant.network == net
                && grant
                    .addresses
                    .iter()
                    .all(|entry| rows.iter().any(|row| row.entry.address == entry.address))
                && purposes.iter().all(|purpose| {
                    grant
                        .addresses
                        .iter()
                        .any(|entry| entry.purpose == *purpose)
                })
        })
    }

    /// Checks of a queued Solana/Bitcoin site item (unlocked); `None` = not a chain kind,
    /// `Some(None)` = passed (show the window), `Some(Some(outcome))` = finished.
    #[expect(
        clippy::option_option,
        reason = "not-mine / passed / finished, as `site_preflight` reads it"
    )]
    #[expect(
        clippy::too_many_lines,
        reason = "one arm per Solana/Bitcoin request kind"
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
                } else if let Some(error) =
                    refusal().or_else(|| rows.is_empty().then_some(ProviderError::NoSolAccount))
                {
                    // An empty list never opens a window (an account still on its way included).
                    self.refuse_site(site, error);
                    Some(QueueOutcome::Cancelled)
                } else {
                    None
                }
            }
            SiteKind::BtcConnect(_) | SiteKind::BtcSign { .. }
                if !self.settings.bitcoin.enabled =>
            {
                self.refuse_site(site, ProviderError::BtcDisabled);
                Some(QueueOutcome::Cancelled)
            }
            SiteKind::BtcConnect(purposes) => {
                // Like a queued `sol_connect` and `eth_requestAccounts`: answered at once from a
                // grant that covers it, as the dispatcher does while unlocked.
                if let Some(grant) = self.btc_grant_covering(&core, &site.origin, purposes) {
                    self.respond(
                        &site.reply,
                        Ok(crate::browser::dispatch::btc_accounts_value(
                            &grant,
                            Some(purposes.as_slice()),
                        )),
                    );
                    Some(QueueOutcome::Approved)
                } else if let Some(error) = refusal() {
                    self.refuse_site(site, error);
                    Some(QueueOutcome::Cancelled)
                } else {
                    None
                }
            }
            SiteKind::SolSign { public, .. } | SiteKind::SolTx { public, .. } => {
                let granted = core
                    .sol_grants()
                    .iter()
                    .any(|g| g.origin == site.origin && g.public == *public);
                match self
                    .sol_dapp_rows()
                    .into_iter()
                    .find(|row| row.public == *public)
                {
                    Some(row) if granted => {
                        // Not backed up: the vault would refuse the key after the approval; a
                        // YubiKey on its factory PINs: the card step would (spec/10 §9.3).
                        if let Some(phrase) = self.sol_source_unconfirmed(row.source) {
                            self.refuse_unconfirmed(site, phrase);
                            Some(QueueOutcome::Cancelled)
                        } else if let Some(serial) = self.sol_card_gate(row.source) {
                            self.refuse_card_defaults(site, serial);
                            Some(QueueOutcome::Cancelled)
                        } else if let SiteKind::SolTx { mode, cluster, .. } = &site.kind
                            && let Some(error) = self.sol_dapp_refusal(public, *cluster, *mode)
                        {
                            self.respond(&site.reply, Err(error));
                            Some(QueueOutcome::Cancelled)
                        } else {
                            None
                        }
                    }
                    _ => Some(QueueOutcome::Revoked),
                }
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
                        if let Some(phrase) = self.btc_source_unconfirmed(&row.source) {
                            // Not backed up: the vault would refuse the key after the approval.
                            self.refuse_unconfirmed(site, phrase);
                            Some(QueueOutcome::Cancelled)
                        } else if let Some(serial) = self.btc_source_card_gate(&row.source) {
                            // A YubiKey on its factory PINs (spec/10 §9.3).
                            self.refuse_card_defaults(site, serial);
                            Some(QueueOutcome::Cancelled)
                        } else if protocol.supports(row.entry.script_type) {
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
                    self.approval_lang(),
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
                    self.clock.now_unix_ms(),
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
                build_btc_message_request(
                    self.approval_lang(),
                    &BtcMessageRequest {
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
                    },
                )
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
                origin: site.origin.clone(),
                message: message.clone(),
                sign_in: *sign_in,
            },
            (SiteKind::BtcSign { address, .. }, SigningPayload::BtcMessage(payload)) => {
                ChainAnswer::Btc {
                    address: address.clone(),
                    origin: site.origin.clone(),
                    protocol: payload.protocol,
                }
            }
            _ => return None,
        };
        Some(SignWaiter::Chain(site.reply, Box::new(answer)))
    }

    /// Whether the Solana grant of `origin` still names `public` (spec/07 §20.10-4: checked
    /// again before signed transaction bytes leave the wallet).
    pub(crate) fn sol_grant_holds(&self, origin: &BrowserOrigin, public: &[u8; 32]) -> bool {
        self.browser.as_ref().is_some_and(|browser| {
            browser
                .core
                .sol_grants()
                .iter()
                .any(|grant| grant.origin == *origin && grant.public == *public)
        })
    }

    /// Whether the Bitcoin grant of `origin` still lists `address` (spec/05 §4.5: checked again
    /// before a message signature leaves the wallet, 2026-11-13).
    pub(crate) fn btc_grant_holds(&self, origin: &BrowserOrigin, address: &str) -> bool {
        self.browser.as_ref().is_some_and(|browser| {
            browser.core.btc_grants().iter().any(|grant| {
                grant.origin == *origin && grant.addresses.iter().any(|e| e.address == address)
            })
        })
    }

    /// Whether the site of a chain answer may still get the signature: its grant names the
    /// signing key or address (spec/05 §4.5, spec/07 §20.10-4).
    pub(crate) fn chain_grant_holds(&self, answer: &ChainAnswer) -> bool {
        match answer {
            ChainAnswer::Sol { public, origin, .. } | ChainAnswer::SolTx { public, origin, .. } => {
                self.sol_grant_holds(origin, public)
            }
            ChainAnswer::Btc {
                address, origin, ..
            } => self.btc_grant_holds(origin, address),
        }
    }

    /// `SignChainMessage` finished: the dApp gets the signature, 4001 after a lock, -32603
    /// otherwise. A signature (message, sign-in or signed dApp transactions) goes out only while
    /// the origin's grant still names the key or address; a site disconnected meanwhile gets 4100
    /// and the signature or bytes are dropped (spec/07 §20.10-4; messages since 2026-11-13,
    /// spec/05 §4.5).
    pub(crate) fn browser_chain_message_signed(&mut self, signed: &ChainMessageSigned) {
        let Some(SignWaiter::Chain(reply, answer)) = self.take_sign_waiter(signed.ticket) else {
            return;
        };
        if signed.result.is_ok() && !self.chain_grant_holds(&answer) {
            let event = if matches!(*answer, ChainAnswer::SolTx { .. }) {
                "sol_tx.grant_gone"
            } else {
                "site.grant_gone"
            };
            logging::info("browser", event, &[]);
            self.respond(&reply, Err(ProviderError::Unauthorized));
            return;
        }
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

    /// Bitcoin addresses left the wallet (an imported key removed) or an account was hidden
    /// (2026-11-15): every grant listing one is deleted as a whole, like
    /// [`Self::sol_account_removed_from_sites`].
    pub(crate) fn btc_addresses_removed_from_sites(&mut self, addresses: &[String]) {
        // An address another visible account still has (any network) stays connected; a hidden
        // account keeps no grant alive (spec/05 §4.9, as EVM's "숨기지 않은 다른 계정").
        let held: Vec<String> = self.meta.as_ref().map_or_else(Vec::new, |meta| {
            meta.btc
                .as_deref()
                .into_iter()
                .chain(meta.btc_accounts.accounts.iter())
                .filter(|account| !meta.btc_hidden(account.network(), account.id()))
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

/// Connect-window texts of Solana and Bitcoin sites (spec/05 §4; English spec/14 §5).
pub mod text {
    yw_core::texts! {
        /// The prefix of a Bitcoin `payment` choice.
        TAG_PAYMENT = "[결제용] " / "[payment] ";
        /// The prefix of a Bitcoin `ordinals` choice.
        TAG_ORDINALS = "[오디널스용] " / "[ordinals] ";
    }
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;
    use std::sync::Arc;

    // `BtcRow`: the moved tests of `app_tests` name it as `super::BtcRow` (2026-11-21, S4 W0).
    use super::{BtcRow, ChainAnswer, ConnectChoice, chain_answer_value, default_protocol};
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
            Arc::clone(&app.clock),
        );
        app.browser = Some(BrowserUi {
            core,
            reads: Arc::new(crate::browser::read::ReadContext::new(None)),
            connections: 0,
            waiters: HashMap::new(),
            broadcasts: HashMap::new(),
            sol_broadcasts: HashMap::new(),
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
            chain_id: 0,
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
            origin: BrowserOrigin::parse("https://app.example").unwrap(),
            message: b"hi".to_vec(),
            sign_in: true,
        };
        let value = chain_answer_value(&sol, &ChainSignature::Sol([2; 64])).unwrap();
        let text = String::from_utf8(yw_json::to_vec(&value)).unwrap();
        assert!(text.contains(r#""signedMessage":"6869""#), "{text}");
        let btc = ChainAnswer::Btc {
            address: "bc1q".to_owned(),
            origin: BrowserOrigin::parse("https://app.example").unwrap(),
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
        // Solana dApp transactions (spec/05 §3.6): one hex string, or the list in order; a send
        // is never answered with bytes, a count mismatch is no answer.
        let tx = |batch: bool, send: bool| ChainAnswer::SolTx {
            public: [1; 32],
            origin: BrowserOrigin::parse("https://app.example").unwrap(),
            batch,
            send,
        };
        let text = |value: Option<yw_json::Value>| {
            value.map(|value| String::from_utf8(yw_json::to_vec(&value)).unwrap())
        };
        let key = yw_core::codec::base58::base58_encode(&[1; 32]);
        assert_eq!(
            text(chain_answer_value(
                &tx(false, false),
                &ChainSignature::SolTxs(vec![vec![0xab, 1]])
            )),
            Some(format!(
                r#"{{"publicKey":"{key}","signedTransaction":"ab01"}}"#
            ))
        );
        assert_eq!(
            text(chain_answer_value(
                &tx(true, false),
                &ChainSignature::SolTxs(vec![vec![1], vec![2]])
            )),
            Some(format!(
                r#"{{"publicKey":"{key}","signedTransactions":["01","02"]}}"#
            ))
        );
        for (answer, signed) in [
            (tx(false, false), vec![vec![1], vec![2]]),
            (tx(true, false), Vec::new()),
            (tx(false, true), vec![vec![1]]),
        ] {
            assert_eq!(
                chain_answer_value(&answer, &ChainSignature::SolTxs(signed)),
                None
            );
        }
        assert_eq!(
            chain_answer_value(&tx(false, false), &ChainSignature::Sol([0; 64])),
            None
        );
    }

    /// A legacy transaction the fixture key signs and pays for (one unknown-program
    /// instruction with data `[tag]`).
    fn sol_tx(tag: u8) -> Vec<u8> {
        let mut out = vec![1_u8];
        out.extend_from_slice(&[0; 64]);
        out.extend_from_slice(&[1, 0, 1, 2]);
        out.extend_from_slice(&public());
        out.extend_from_slice(&[5; 32]);
        out.extend_from_slice(&[7; 32]);
        out.extend_from_slice(&[1, 1, 1, 0, 1, tag]);
        out
    }

    const DEVNET: yw_core::sol::SolCluster = yw_core::sol::SolCluster::Devnet;

    /// A request of [`sol_tx`] bound to devnet.
    fn sol_tx_kind(mode: yw_core::sol::dapp::SolTxMode) -> SiteKind {
        SiteKind::SolTx {
            public: public(),
            cluster: DEVNET,
            txs: vec![sol_tx(1)],
            mode,
            batch: false,
            options: yw_core::sol::dapp::SolSendOptions::default(),
        }
    }

    /// A `Pending` dApp send record of `public` on devnet (only the fields the caps read).
    fn dapp_pending(public: [u8; 32]) -> yw_core::journal::sol::SolRecord {
        yw_core::journal::sol::SolRecord {
            state: yw_core::journal::sol::SolTxState::Pending,
            cluster: yw_core::sol::SolCluster::Devnet,
            source: yw_core::slip10::SolKeySource::Standard(
                yw_core::bip32::path::AccountIndex::ZERO,
            ),
            intent_id: [0; 16],
            intent_hash: [0; 32],
            signed_at_ms: 1,
            last_valid_block_height: 1,
            terminal_slot: 0,
            terminal_err: 0,
            tx: sol_tx(1),
            dapp: Some(yw_core::journal::sol::SolDappMeta {
                public,
                signer_slot: 0,
                flags: 1,
                origin: "https://app.example".to_owned(),
            }),
        }
    }

    /// One preview entry per transaction (no tables, no simulation result).
    fn preview(n: usize) -> crate::sol::flow::DappPreview {
        let item = yw_core::sol::dapp::SolTxItemFacts {
            tables: Ok((0, Vec::new())),
            pre: Vec::new(),
            post: None,
            sim: yw_core::sol::display::SimSummary::NoResult,
            sim_replaced_blockhash: false,
            rpc_fee: Some(5_000),
            blockhash_valid: Some(true),
        };
        crate::sol::flow::DappPreview {
            items: vec![item; n],
            mints: Vec::new(),
            unread_mints: Vec::new(),
        }
    }

    /// A devnet wallet with a devnet endpoint (no request is ever sent: the RPC worker is a
    /// channel in these tests).
    fn devnet(app: &mut App) {
        app.settings.solana.cluster = crate::network::SolCluster::Devnet;
        let url = yw_platform::http::HttpsUrl::parse("https://sol.example.test/").unwrap();
        app.apikeys.set_rpc(
            crate::network::NetworkId::Solana(crate::network::SolCluster::Devnet),
            &url,
        );
    }

    /// The window's part for `site`: its draft issued and consumed.
    fn approve_site(app: &App, site: &SiteRequest) -> yw_core::approval::Approved {
        let draft = app.sol_dapp_draft(site, Ok(preview(1))).unwrap();
        let mut store = yw_core::approval::ApprovalStore::new();
        let request = store.issue(draft, 1, 1_800_000_000_000).unwrap();
        store.consume(request.id, request.digest, 2).unwrap()
    }

    /// [`queued_sol_tx`] as `sol_signAndSendTransaction`.
    fn queued_send(app: &App, events: &EventQueue, conn: u64, n: u8) -> SiteRequest {
        let mut send = queued_sol_tx(app, events, conn, n);
        if let SiteKind::SolTx { mode, .. } = &mut send.kind {
            *mode = yw_core::sol::dapp::SolTxMode::SignAndSend;
        }
        send
    }

    /// The send waiter `sol_dapp_consumed` leaves for `site`.
    fn send_waiter(app: &mut App, site: &SiteRequest) -> crate::events::SignTicket {
        app.push_sign_waiter(crate::app_browser::SignWaiter::Chain(
            site.reply,
            Box::new(ChainAnswer::SolTx {
                public: public(),
                origin: site.origin.clone(),
                batch: false,
                send: true,
            }),
        ))
    }

    /// A journaled send of [`public`] with transaction id `tx_id`.
    fn summary(
        tx_id: [u8; 64],
        reused: bool,
        min_context_slot: Option<u64>,
    ) -> crate::events::SolDappSignedSummary {
        crate::events::SolDappSignedSummary {
            cluster: DEVNET,
            public: public(),
            tx_id,
            own_signature: tx_id,
            tx: sol_tx(1),
            signed_at_ms: 1,
            last_valid_block_height: 1,
            min_context_slot,
            reused,
        }
    }

    /// The first broadcast round of `tx_id` with `state` and `outcome`.
    fn first_round(
        tx_id: [u8; 64],
        state: yw_core::sol::broadcast::LoopState,
        outcome: Result<yw_core::sol::broadcast::Outcome, crate::errors::ErrorCode>,
    ) -> crate::events::RpcEvent {
        crate::events::RpcEvent::SolTracked(Box::new(crate::sol::flow::TrackResult {
            signature: tx_id,
            state,
            outcome,
            genesis_ok: Some(true),
            sends: 1,
            generation: 0,
        }))
    }

    /// The `{publicKey, signature}` text of a send answer.
    fn send_answer_text(tx_id: [u8; 64]) -> String {
        format!(
            r#"{{"publicKey":"{SOL_KEY}","signature":"{}"}}"#,
            yw_core::hex::encode(&tx_id)
        )
    }

    fn texts(
        found: Vec<Result<yw_json::Value, ProviderError>>,
    ) -> Vec<Result<String, ProviderError>> {
        found
            .into_iter()
            .map(|body| body.map(|value| String::from_utf8(yw_json::to_vec(&value)).unwrap()))
            .collect()
    }

    /// A recorded connection on a fresh dispatcher of `app`, unlocked with the app's accounts
    /// and the Solana grant of `https://app.example`: the queue its requests go to, the frames
    /// it answers with, and the connection.
    fn recorded(
        app: &mut App,
    ) -> (
        Arc<EventQueue>,
        std::sync::mpsc::Receiver<crate::browser::Outbound>,
        crate::browser::ConnId,
    ) {
        let events = Arc::new(EventQueue::new(Box::new(|| {})));
        let core = crate::browser::BrowserCore::new(
            "abcdefghijklmnopabcdefghijklmnop",
            Arc::clone(&events) as Arc<dyn crate::browser::DappSink>,
            Arc::clone(&app.clock),
        );
        core.set_wallet(unlocked_view(app));
        core.upsert_sol_grant(sol_grant("https://app.example", public()));
        let (sender, receiver) = std::sync::mpsc::channel();
        let conn = core.open_connection(Box::new(sender));
        if let Some(browser) = app.browser.as_mut() {
            browser.core = core;
        }
        let _ = events.drain();
        (events, receiver, conn)
    }

    /// Sends `sol_signTransaction` of [`sol_tx`] on `conn` and returns the queued request.
    fn queued_sol_tx(app: &App, events: &EventQueue, conn: u64, n: u8) -> SiteRequest {
        let deadline = app.clock.now_unix_ms() + 600_000;
        let frame = format!(
            concat!(
                r#"{{"namespace":"your-wallet","version":1,"role":"extension","kind":"request","#,
                r#""sessionId":"{session}","sequence":{n},"deadlineUnixMs":{deadline},"#,
                r#""profileInstallId":"{profile}","activationNonce":"{activation}","#,
                r#""requestId":"{request}","method":"sol_signTransaction","#,
                r#""params":[{{"publicKey":"{key}","transaction":"{tx}"}}],"route":"signing","#,
                r#""context":{{"browserFamily":"chrome","extensionId":"abcdefghijklmnopabcdefghijklmnop","#,
                r#""tabId":17,"frameId":0,"documentId":"document-17","topOrigin":"https://app.example","#,
                r#""frameOrigin":"https://app.example","documentLifecycle":"active","#,
                r#""channelNonce":"{channel}"}}}}"#
            ),
            n = n,
            deadline = deadline,
            session = "bb".repeat(32),
            profile = "aa".repeat(32),
            activation = format!("{}0c", "00".repeat(31)),
            channel = format!("{}0d", "00".repeat(31)),
            request = format!("{n:02x}").repeat(16),
            key = SOL_KEY,
            tx = yw_core::hex::encode(&sol_tx(n)),
        );
        core(app).handle_frame(conn, frame.as_bytes());
        events
            .drain()
            .into_iter()
            .find_map(|event| match event {
                crate::events::UiEvent::Dapp(crate::browser::DappEvent::Request(request)) => {
                    Some(*request)
                }
                _ => None,
            })
            .expect("queued")
    }

    /// The answers recorded since the last call.
    fn answers(
        frames: &std::sync::mpsc::Receiver<crate::browser::Outbound>,
    ) -> Vec<Result<yw_json::Value, ProviderError>> {
        frames
            .try_iter()
            .filter_map(|frame| match frame {
                crate::browser::Outbound::Response { body, .. } => Some(body),
                crate::browser::Outbound::Event { .. } => None,
            })
            .collect()
    }

    /// The EVM account the grant tests sign with.
    fn evm_account() -> yw_core::evm::address::Address {
        yw_core::evm::address::Address::from_bytes([0x6f; 20])
    }

    /// The EVM grant of `https://app.example` naming [`evm_account`].
    fn evm_grant() -> yw_core::policy::ConnectedSite {
        yw_core::policy::ConnectedSite::new(
            BrowserOrigin::parse("https://app.example").unwrap(),
            vec![evm_account()],
            yw_core::evm::chain::SEPOLIA,
            1,
        )
        .unwrap()
    }

    /// [`evm_account`] signing for `https://app.example`.
    fn evm_signer() -> crate::app_browser::SiteSigner {
        crate::app_browser::SiteSigner {
            origin: BrowserOrigin::parse("https://app.example").unwrap(),
            account: evm_account(),
        }
    }

    /// The names of the key jobs queued since the last call (`pop` blocks on an empty queue).
    fn job_names(app: &App) -> Vec<&'static str> {
        std::iter::from_fn(|| {
            (!app.key_queue.is_empty())
                .then(|| app.key_queue.pop())
                .flatten()
        })
        .map(|(_, job)| job.name())
        .collect()
    }

    /// A consumed `personal_sign` approval of the `YubiKey` EVM account 1 for
    /// `https://app.example`.
    fn approved_card_message() -> yw_core::approval::Approved {
        use yw_core::approval::{ApprovalId, ApprovalKind, ApprovalOrigin, ApprovalStore};
        let draft = yw_core::approval::build_personal_request(
            yw_core::lang::Lang::Ko,
            ApprovalId::random().unwrap(),
            ApprovalOrigin::Site(BrowserOrigin::parse("https://app.example").unwrap()),
            yw_core::vault::EvmKeySource::Hardware(
                yw_core::bip32::path::AccountIndex::new(1).unwrap(),
            ),
            evm_account(),
            ApprovalKind::EvmPersonalSign,
            &yw_core::evm::chain::sepolia(),
            &yw_core::evm::eip191::decode_personal_message(b"hi".to_vec()),
            1_790_000_000_000,
        )
        .unwrap();
        let mut store = ApprovalStore::new();
        let request = store.issue(draft, 0, 1_790_000_000_000).unwrap();
        store.consume(request.id, request.digest, 1).unwrap()
    }

    /// A consumed transaction approval of the `YubiKey` EVM account 1 for `https://app.example`
    /// (Sepolia, 1000 wei to a public test address; no simulation).
    fn approved_card_tx() -> yw_core::approval::Approved {
        use yw_core::approval::{ApprovalId, ApprovalKind, ApprovalOrigin, ApprovalStore};
        use yw_core::evm::amount::U256;
        use yw_core::evm::decode::{DecodedTx, decode_call};
        let chain = yw_core::evm::chain::sepolia();
        let tx = yw_core::evm::tx::Eip1559Tx {
            chain_id: yw_core::evm::chain::SEPOLIA,
            nonce: 0,
            max_priority_fee_per_gas: U256::from_u64(1_000_000_000),
            max_fee_per_gas: U256::from_u64(2_000_000_000),
            gas_limit: 21_000,
            to: yw_core::evm::address::Address::from_bytes([0x70; 20]),
            value: U256::from_u64(1_000),
            data: Vec::new(),
            access_list: Vec::new(),
        };
        let decoded = DecodedTx {
            call: decode_call(&chain, &tx.to, &tx.data),
            tx,
        };
        let draft = yw_core::approval::build_evm_tx_request(
            yw_core::lang::Lang::Ko,
            ApprovalId::random().unwrap(),
            ApprovalOrigin::Site(BrowserOrigin::parse("https://app.example").unwrap()),
            yw_core::vault::EvmKeySource::Hardware(
                yw_core::bip32::path::AccountIndex::new(1).unwrap(),
            ),
            evm_account(),
            ApprovalKind::EvmTransaction,
            &chain,
            &decoded,
            &yw_core::evm::simulate::SimResult::skipped(),
            &yw_core::approval::ChainFacts::default(),
            Vec::new(),
            1_790_000_000_000,
        )
        .unwrap();
        let mut store = ApprovalStore::new();
        let request = store.issue(draft, 0, 1_790_000_000_000).unwrap();
        store.consume(request.id, request.digest, 1).unwrap()
    }

    /// The record fields of [`approved_card_tx`].
    fn card_tx_info() -> crate::events::SignInfo {
        crate::events::SignInfo {
            origin: "https://app.example".to_owned(),
            label: "dApp 거래".to_owned(),
            role: yw_core::journal::evm::Role::Original,
            now_unix_ms: 1_790_000_000_000,
        }
    }

    /// The tests that build an `App` (2026-11-21, S4 W0, spec/09 §2.1), in
    /// `app/tests/chain_sites.rs`: a child of this module, so that they reach its helpers.
    /// The path is relative to `app_chain_sites/tests/` (an inline module of a
    /// non-`mod.rs` file).
    #[path = "../../app/tests/chain_sites.rs"]
    mod app_tests;
}
