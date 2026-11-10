//! `HyperCore` on the UI thread (D34, spec/11 §8): the card on the EVM tab (balances), the
//! transfer form (S-HC), the approval item (`HyperCore 전송`, kind 0x40), the signed-action
//! submission and the session activity. Trading is out of scope.
//!
//! Flow: form → [`HcApprovalItem`] → A01 (draft built in yw-core from the item) → consume →
//! `SignMessage { typed: true }` (vault) or the card step (`YubiKey`) → the signature comes back
//! through [`App::hc_message_signed`] → `POST /exchange` on the RPC worker → the reply status is
//! the activity status (Hyperliquid has no transaction hash; the nonce/time is the key) →
//! balances refresh.

use std::collections::HashMap;

use yw_core::approval::Approved;
use yw_core::evm::address::Address;
use yw_core::evm::amount::{U256, parse_units};
use yw_core::evm::eip712::{DecodedTypedData, HlUserAction, KnownSchema, TdNode};
use yw_core::hypercore::display::{HcRecipient, HlSiteFacts};
use yw_core::hypercore::{
    HcAction, HcExchangeReply, HcKind, HcNetwork, HcPayload, HcToken, USD_DECIMALS,
    WITHDRAW_FEE_USDC, parse_amount,
};
use yw_core::vault::EvmKeySource;

use crate::app::{App, AppMode, Screen};
use crate::app_evm::{QueuedItem, SendAsset};
use crate::browser::SiteRequest;
use crate::events::{KeyJob, MessageSignFailure, MessageSigned, SignTicket};
use crate::flow::evm::form::{AddressNote, check_recipient};
use crate::hypercore::{HcBalances, HcEndpoint, HcEvent, HcRpcJob};
use crate::logging::{self, Field};
use crate::ui::approval::{QueueOutcome, QueueSource};
use crate::workers::rpc::RpcJob;

/// Balance refresh while the card or S-HC is visible.
pub const HC_REFRESH_MS: u64 = 60_000;
/// Session activity rows kept.
const MAX_ACTIVITY: usize = 50;
/// S-HC while the balances load (a status, not an input error).
pub const HC_LOADING_TEXT: &str = "HyperCore 잔액을 불러오는 중입니다";
/// A withdrawal to the signing account itself (the form's default): information, not the
/// "보내는 계정과 같은 주소" warning of a send.
pub const HC_WITHDRAW_OWN_TEXT: &str =
    "서명 계정과 같은 주소 — Arbitrum One의 내 주소로 출금합니다.";

/// What the S-HC form does.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum HcFormKind {
    /// `보내기(Core)`: perp USDC (`usdSend`) or a spot token (`spotSend`).
    #[default]
    Send,
    /// `현물↔선물 이동` (`usdClassTransfer`).
    ClassTransfer,
    /// `Arbitrum으로 출금` (`withdraw3`).
    Withdraw,
    /// `HyperEVM으로 이동` (`sendAsset` to the token's system address).
    ToEvm,
}

/// The asset of the send / `HyperEVM` form.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum HcAsset {
    /// Perp USDC (`usdSend`).
    #[default]
    PerpUsdc,
    /// A spot token by index (`spotSend` / `sendAsset`).
    Spot(u32),
}

/// S-HC form state.
#[derive(Clone, Debug, Default)]
pub struct HcForm {
    /// Kind.
    pub kind: HcFormKind,
    /// Asset.
    pub asset: HcAsset,
    /// Recipient text.
    pub to_text: String,
    /// Amount text.
    pub amount_text: String,
    /// `usdClassTransfer` direction: spot → perp.
    pub to_perp: bool,
    /// `주소 전체를 직접 확인했습니다` (look-alike).
    pub ack: bool,
    /// The recipient `ack` was given for: another recipient (another look-alike included) needs
    /// its own, like S11 and the Bitcoin form.
    pub ack_for: Option<Address>,
    /// The recipient of the last check.
    pub recipient: Option<Address>,
    /// Recipient notes of the last check.
    pub notes: Vec<AddressNote>,
    /// Validation message (blocks `검토`).
    pub error: Option<String>,
    /// Info line (after review, expiry).
    pub info: Option<String>,
    /// Last edit (monotonic ms) awaiting validation (500 ms debounce, like S11).
    pub dirty_ms: Option<u64>,
}

/// Status of a submitted action.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum HcStatus {
    /// Approved, waiting for the signature.
    Signing,
    /// Signed and posted.
    Submitting,
    /// `status: ok`.
    Ok,
    /// `status: err` with the server message.
    Rejected(String),
    /// No answer (the action may still have been processed — check the balances).
    Unknown(String),
    /// Not signed (lock, card failure, error).
    NotSigned(String),
}

impl HcStatus {
    /// Display text.
    #[must_use]
    pub fn text(&self) -> String {
        match self {
            Self::Signing => "서명 중".to_owned(),
            Self::Submitting => "전송 중".to_owned(),
            Self::Ok => "성공 (Hyperliquid status ok)".to_owned(),
            Self::Rejected(message) => format!("거부됨 (status err): {message}"),
            Self::Unknown(message) => {
                format!("결과 불명 — 잔액을 확인하세요 ({message})")
            }
            Self::NotSigned(message) => format!("서명하지 않음 — {message}"),
        }
    }
}

/// One submitted action of this run.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HcActivity {
    /// Network.
    pub network: HcNetwork,
    /// Nonce (= `time`, unix ms).
    pub nonce: u64,
    /// Account.
    pub account: Address,
    /// Kind.
    pub kind: HcKind,
    /// Amount with its symbol.
    pub amount: String,
    /// Recipient.
    pub to: Option<Address>,
    /// Status.
    pub status: HcStatus,
}

/// A queued `HyperCore 전송` approval.
#[derive(Clone, Debug)]
pub struct HcApprovalItem {
    /// The action (nonce fixed at `검토`).
    pub action: HcAction,
    /// Signing account.
    pub account: Address,
    /// Key source.
    pub signer: EvmKeySource,
    /// The spot token (`spotSend`, `sendAsset`).
    pub token: Option<HcToken>,
    /// Recipient checks.
    pub recipient: HcRecipient,
}

/// `HyperCore` UI state.
#[derive(Debug, Default)]
pub struct HcUi {
    /// Outstanding load job.
    pub job: u64,
    /// A load is running.
    pub loading: bool,
    /// `spotMeta` of a network.
    pub tokens: Option<(HcNetwork, Vec<HcToken>)>,
    /// Balances of an account on a network.
    pub balances: Option<(HcNetwork, Address, HcBalances)>,
    /// Last load error.
    pub error: Option<String>,
    /// Last load (monotonic ms).
    pub loaded_ms: Option<u64>,
    /// S-HC.
    pub form: HcForm,
    /// Signing jobs waiting for their signature.
    pub pending: HashMap<SignTicket, HcAction>,
    /// Session activity, newest first.
    pub activity: Vec<HcActivity>,
    /// Settings: testnet API text.
    pub api_text: Option<String>,
    /// Settings message.
    pub settings_message: Option<String>,
    /// The S10 card was unfolded with `펼치기 ▸` (this run only, 2026-11-10).
    pub unfolded: bool,
}

impl HcUi {
    /// Drops everything account-related (lock).
    pub fn clear_unlocked(&mut self) {
        self.balances = None;
        self.error = None;
        self.loading = false;
        self.loaded_ms = None;
        self.form = HcForm::default();
        for action in std::mem::take(&mut self.pending).into_values() {
            if let Some(row) = self
                .activity
                .iter_mut()
                .find(|row| row.network == action.network && row.nonce == action.nonce)
            {
                row.status = HcStatus::NotSigned("잠겨서 취소됨".to_owned());
            }
        }
    }

    /// The token of `index` on `network`.
    #[must_use]
    pub fn token(&self, network: HcNetwork, index: u32) -> Option<&HcToken> {
        self.tokens
            .as_ref()
            .filter(|(net, _)| *net == network)
            .and_then(|(_, tokens)| tokens.iter().find(|token| token.index == index))
    }
}

/// Smallest units of an API decimal (`"14.625485"`) at `decimals`, the fraction truncated.
#[must_use]
pub fn api_units(text: &str, decimals: u8) -> Option<U256> {
    if text.starts_with('-') {
        return Some(U256::ZERO);
    }
    let (integer, fraction) = text.split_once('.').unwrap_or((text, ""));
    let fraction: String = fraction.chars().take(usize::from(decimals)).collect();
    let integer = integer.trim_start_matches('0');
    let integer = if integer.is_empty() { "0" } else { integer };
    let normalized = if fraction.is_empty() {
        integer.to_owned()
    } else {
        format!("{integer}.{fraction}")
    };
    parse_units(&normalized, decimals).ok()
}

fn now_unix_ms() -> u64 {
    u64::try_from(
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |elapsed| elapsed.as_millis()),
    )
    .unwrap_or(0)
}

impl App {
    /// The S-HC checks of a dApp-requested Hyperliquid transfer (spec/11 §7): the recipient check
    /// of its `destination` (own accounts, address book, look-alikes — the form's
    /// [`check_recipient`]) and the cached `spotMeta` of its `hyperliquidChain`. `None` for other
    /// typed data.
    pub(crate) fn hl_site_facts(
        &self,
        typed: &DecodedTypedData,
        account: &Address,
    ) -> Option<HlSiteFacts> {
        let Some(KnownSchema::HyperliquidUser(HlUserAction::Transfer(_))) = typed.schema else {
            return None;
        };
        let text = |name: &str| typed.root.field(name).and_then(TdNode::string);
        let network = text("hyperliquidChain").and_then(|chain| {
            [HcNetwork::Mainnet, HcNetwork::Testnet]
                .into_iter()
                .find(|network| network.chain_name() == chain)
        });
        let spot_meta = self
            .hypercore
            .tokens
            .as_ref()
            .filter(|(net, _)| Some(*net) == network)
            .map(|(_, tokens)| tokens.clone());
        let known = self.known_addresses();
        let recipient = text("destination")
            .and_then(|destination| check_recipient(destination, account, None, &known).ok())
            .map(|(_, notes)| HcRecipient {
                look_alike: notes.iter().any(AddressNote::needs_ack),
                not_in_book: notes.contains(&AddressNote::NotInBook),
                notes: notes.iter().map(AddressNote::text).collect(),
            });
        Some(HlSiteFacts {
            recipient,
            spot_meta,
        })
    }

    /// The origin that may use the Hyperliquid L1 Agent exception for `site` (spec/11 §7): the
    /// extension site origin only (the browser vouches for it). A `WalletConnect` session never
    /// does, even with Verify `Valid`: the attested origin is what the dApp's own environment
    /// reported to the Verify server, which a dApp run outside a browser (the pairing URI shown
    /// on a phishing page) can choose — so its L1 Agent documents keep the T01 rejection.
    pub(crate) fn hl_l1_origin(site: &SiteRequest) -> Option<String> {
        (!crate::walletconnect::is_session_origin(&site.origin))
            .then(|| site.origin.as_str().to_owned())
    }

    /// The card's network.
    #[must_use]
    pub const fn hc_network(&self) -> HcNetwork {
        self.settings.hypercore.network
    }

    fn hc_endpoint(&self, network: HcNetwork) -> HcEndpoint {
        HcEndpoint {
            network,
            api: self.settings.hypercore_api(network),
        }
    }

    /// Whether the card is shown (setting on, unlocked).
    #[must_use]
    pub fn hc_visible(&self) -> bool {
        self.settings.hypercore.enabled && matches!(self.mode, AppMode::Unlocked { .. })
    }

    /// Balances of the selected account on the card's network (and `spotMeta` once).
    pub fn hc_refresh(&mut self) {
        if !self.hc_visible() {
            return;
        }
        let Some((account, ..)) = self.selected_account() else {
            return;
        };
        let network = self.hc_network();
        let meta = self
            .hypercore
            .tokens
            .as_ref()
            .is_none_or(|(net, _)| *net != network);
        self.hypercore.job = self.hypercore.job.wrapping_add(1);
        self.hypercore.loading = true;
        self.hypercore.loaded_ms = Some(yw_win::time::monotonic_ms());
        let job = HcRpcJob::Load {
            job: self.hypercore.job,
            endpoint: self.hc_endpoint(network),
            account,
            meta,
        };
        if !self.rpc(RpcJob::HyperCore(Box::new(job))) {
            self.hypercore.loading = false;
            self.hypercore.error = Some("RPC 작업자를 사용할 수 없습니다".to_owned());
        }
    }

    /// Main-timer part: refresh while S10 shows the card or S-HC is open (a failed load is
    /// retried there too).
    pub fn hc_tick(&mut self, now: u64) {
        let due = self
            .hypercore
            .loaded_ms
            .is_none_or(|at| now.saturating_sub(at) >= HC_REFRESH_MS);
        if due && matches!(self.screen, Screen::Main | Screen::HyperCore) && !self.hypercore.loading
        {
            self.hc_refresh();
        }
        if let Some(changed) = self.hypercore.form.dirty_ms
            && now.saturating_sub(changed) >= crate::app_evm::SEND_DEBOUNCE_MS
        {
            self.hypercore.form.dirty_ms = None;
            self.hc_validate();
            self.refresh();
        }
    }

    /// RPC worker results.
    pub fn hc_rpc_event(&mut self, event: HcEvent) {
        match event {
            HcEvent::Loaded {
                job,
                network,
                account,
                meta,
                balances,
            } => {
                if job != self.hypercore.job {
                    return;
                }
                self.hypercore.loading = false;
                match meta {
                    Some(Ok(tokens)) => self.hypercore.tokens = Some((network, tokens)),
                    Some(Err(text)) => self.hypercore.error = Some(text),
                    None => {}
                }
                match balances {
                    Ok(balances) => {
                        self.hypercore.balances = Some((network, account, balances));
                        if self.hypercore.tokens.is_some() {
                            self.hypercore.error = None;
                        }
                    }
                    Err(text) => self.hypercore.error = Some(text),
                }
                if matches!(self.screen, Screen::HyperCore) {
                    self.hc_validate();
                }
                self.refresh();
            }
            HcEvent::Submitted {
                network,
                nonce,
                result,
            } => {
                let status = match result {
                    Ok(HcExchangeReply::Ok) => HcStatus::Ok,
                    Ok(HcExchangeReply::Err(message)) => {
                        HcStatus::Rejected(yw_core::approval::escape_untrusted(&message).text)
                    }
                    Err(text) => HcStatus::Unknown(text),
                };
                self.hc_set_status(network, nonce, status);
                self.hc_refresh();
                self.refresh();
            }
        }
    }

    fn hc_set_status(&mut self, network: HcNetwork, nonce: u64, status: HcStatus) {
        if let Some(row) = self
            .hypercore
            .activity
            .iter_mut()
            .find(|row| row.network == network && row.nonce == nonce)
        {
            row.status = status;
        }
    }

    /// Opens S-HC for `kind`.
    pub fn hc_open_form(&mut self, kind: HcFormKind) {
        let own = self
            .selected_account()
            .map(|(account, ..)| account.to_checksum())
            .unwrap_or_default();
        self.hypercore.form = HcForm {
            kind,
            to_text: if kind == HcFormKind::Withdraw {
                own
            } else {
                String::new()
            },
            to_perp: true,
            asset: match kind {
                HcFormKind::ToEvm => self
                    .hc_evm_tokens()
                    .first()
                    .map_or(HcAsset::PerpUsdc, |token| HcAsset::Spot(token.index)),
                _ => HcAsset::PerpUsdc,
            },
            ..HcForm::default()
        };
        self.set_screen(Screen::HyperCore);
        self.hc_refresh();
        self.hc_validate();
    }

    /// Spot tokens with a balance and a `HyperEVM` link (the `HyperEVM으로 이동` choices).
    #[must_use]
    pub fn hc_evm_tokens(&self) -> Vec<HcToken> {
        let network = self.hc_network();
        self.hc_spot_rows()
            .into_iter()
            .filter_map(|(index, _, _)| self.hypercore.token(network, index).cloned())
            .filter(|token| token.evm.is_some() && token.evm_transfer_decimals().is_some())
            .collect()
    }

    /// Spot balances of the selected account: `(token index, coin, available text)`.
    #[must_use]
    pub fn hc_spot_rows(&self) -> Vec<(u32, String, String)> {
        let network = self.hc_network();
        let account = self.selected_account().map(|(account, ..)| account);
        let Some((net, owner, balances)) = self.hypercore.balances.as_ref() else {
            return Vec::new();
        };
        if *net != network || Some(*owner) != account {
            return Vec::new();
        }
        balances
            .spot
            .iter()
            .filter(|balance| api_units(&balance.total, 18).is_some_and(|units| !units.is_zero()))
            .map(|balance| (balance.token, balance.coin.clone(), balance.total.clone()))
            .collect()
    }

    /// The current account's balances on the card network, if loaded.
    #[must_use]
    pub fn hc_balances(&self) -> Option<&HcBalances> {
        let account = self.selected_account().map(|(account, ..)| account)?;
        let (net, owner, balances) = self.hypercore.balances.as_ref()?;
        (*net == self.hc_network() && *owner == account).then_some(balances)
    }

    /// Available units of the form's source balance and its decimals.
    fn hc_available(&self, kind: HcFormKind, asset: HcAsset, to_perp: bool) -> Option<(U256, u8)> {
        let balances = self.hc_balances()?;
        let spot = |index: u32, decimals: u8| {
            balances
                .spot
                .iter()
                .find(|balance| balance.token == index)
                .and_then(|balance| {
                    let total = api_units(&balance.total, decimals)?;
                    let hold = api_units(&balance.hold, decimals).unwrap_or(U256::ZERO);
                    Some(total.checked_sub(hold).unwrap_or(U256::ZERO))
                })
                .unwrap_or(U256::ZERO)
        };
        let perp = || api_units(&balances.perp.withdrawable, USD_DECIMALS);
        match (kind, asset) {
            (HcFormKind::ClassTransfer, _) if to_perp => {
                Some((spot(0, USD_DECIMALS), USD_DECIMALS))
            }
            (HcFormKind::ClassTransfer | HcFormKind::Withdraw, _)
            | (HcFormKind::Send, HcAsset::PerpUsdc) => Some((perp()?, USD_DECIMALS)),
            (HcFormKind::Send | HcFormKind::ToEvm, HcAsset::Spot(index)) => {
                let token = self.hypercore.token(self.hc_network(), index)?;
                Some((spot(index, token.wei_decimals), token.wei_decimals))
            }
            (HcFormKind::ToEvm, HcAsset::PerpUsdc) => None,
        }
    }

    /// The form's available amount as wire text at the form's own decimals (fewer than the
    /// balance's for a `HyperEVM` move: the rest is cut, never rounded up) and its symbol: what
    /// `최대` fills. `None` until the balances and `spotMeta` are loaded.
    #[must_use]
    pub fn hc_form_available(&self) -> Option<(String, String)> {
        let form = &self.hypercore.form;
        let (available, balance_decimals) =
            self.hc_available(form.kind, form.asset, form.to_perp)?;
        let token = match form.asset {
            HcAsset::Spot(index) => Some(self.hypercore.token(self.hc_network(), index)?),
            HcAsset::PerpUsdc => None,
        };
        let decimals = match (form.kind, token) {
            (HcFormKind::ToEvm, Some(token)) => token.evm_transfer_decimals()?,
            (HcFormKind::Send, Some(token)) => token.wei_decimals,
            (HcFormKind::ToEvm, None) => return None,
            _ => USD_DECIMALS,
        };
        let scale = 10_u64
            .checked_pow(u32::from(balance_decimals.checked_sub(decimals)?))
            .and_then(core::num::NonZeroU64::new)?;
        let (units, _) = available.div_rem_u64(scale);
        let symbol = token.map_or_else(
            || "USDC".to_owned(),
            |token| yw_core::approval::escape_untrusted(&token.name).text,
        );
        Some((yw_core::hypercore::wire_amount(&units, decimals), symbol))
    }

    /// `최대`: the whole available amount (a withdrawal's fee comes out of it, spec/11 §5-3).
    pub fn hc_fill_max(&mut self) {
        let Some((amount, _)) = self.hc_form_available() else {
            return;
        };
        self.hypercore.form.amount_text.clone_from(&amount);
        self.hypercore.form.dirty_ms = None;
        self.controls
            .set_text(crate::ui::screens_hypercore::ids::AMOUNT_EDIT, &amount);
        self.hc_validate();
        self.refresh();
    }

    /// Validates S-HC and returns the action and its item parts when it is complete.
    #[expect(
        clippy::too_many_lines,
        reason = "one block per form kind of spec/11 §8"
    )]
    fn hc_build(&self) -> Result<(HcPayload, Option<HcToken>, HcRecipient), String> {
        let form = &self.hypercore.form;
        let (sender, ..) = self
            .selected_account()
            .ok_or_else(|| "계정을 선택하세요".to_owned())?;
        if self.hc_balances().is_none() {
            return Err(if self.hypercore.loading {
                HC_LOADING_TEXT.to_owned()
            } else {
                "HyperCore 잔액을 불러오지 못했습니다 — 위의 '새로고침'을 누르세요".to_owned()
            });
        }
        let network = self.hc_network();
        let token = match form.asset {
            HcAsset::Spot(index) => Some(
                self.hypercore
                    .token(network, index)
                    .cloned()
                    .ok_or_else(|| "토큰 정보(spotMeta)를 확인할 수 없습니다".to_owned())?,
            ),
            HcAsset::PerpUsdc => None,
        };
        let decimals = match (form.kind, &token) {
            (HcFormKind::ToEvm, Some(token)) => token
                .evm_transfer_decimals()
                .ok_or_else(|| "이 토큰은 HyperEVM에 연결되어 있지 않습니다".to_owned())?,
            (HcFormKind::Send, Some(token)) => token.wei_decimals,
            (HcFormKind::ToEvm, None) => return Err("HyperEVM으로 옮길 토큰을 고르세요".to_owned()),
            _ => USD_DECIMALS,
        };
        let recipient_of = |text: &str| -> Result<(Address, HcRecipient), String> {
            let known = self.known_addresses();
            let (address, notes) = check_recipient(text, &sender, None, &known)
                .map_err(crate::errors::ErrorCode::text)?;
            // A system address only moves its own token to HyperEVM; Send/Withdraw to one
            // loses the funds (spec/11 §5).
            if yw_core::hypercore::system_address_index(&address).is_some()
                || address == yw_core::hypercore::HYPE_SYSTEM_ADDRESS
            {
                return Err(
                    "HyperEVM 시스템 주소입니다 — HyperEVM으로 옮기려면 'HyperEVM으로 이동'을 쓰세요"
                        .to_owned(),
                );
            }
            Ok((
                address,
                HcRecipient {
                    look_alike: notes.iter().any(AddressNote::needs_ack),
                    not_in_book: notes.contains(&AddressNote::NotInBook),
                    notes: notes
                        .iter()
                        .map(|note| {
                            if form.kind == HcFormKind::Withdraw
                                && *note == AddressNote::SameAsSender
                            {
                                HC_WITHDRAW_OWN_TEXT.to_owned()
                            } else {
                                note.text()
                            }
                        })
                        .collect(),
                },
            ))
        };
        let (units, amount) = if form.amount_text.trim().is_empty() {
            return Err("금액을 입력하세요".to_owned());
        } else {
            parse_amount(&form.amount_text, decimals)
                .map_err(|_| format!("금액 형식이 올바르지 않습니다 (소수 {decimals}자리까지)"))?
        };
        let (available, available_decimals) = self
            .hc_available(form.kind, form.asset, form.to_perp)
            .ok_or_else(|| "잔액을 확인할 수 없습니다".to_owned())?;
        // The amount is parsed at the form's decimals (fewer for HyperEVM moves), the balance at
        // weiDecimals: compare in the balance's units.
        let units_at_balance = available_decimals
            .checked_sub(decimals)
            .and_then(U256::checked_pow10)
            .and_then(|scale| units.checked_mul(scale))
            .ok_or_else(|| "잔액을 확인할 수 없습니다".to_owned())?;
        let fee = if form.kind == HcFormKind::Withdraw {
            parse_units(WITHDRAW_FEE_USDC, USD_DECIMALS).unwrap_or(U256::ZERO)
        } else {
            U256::ZERO
        };
        if form.kind == HcFormKind::Withdraw && units <= fee {
            return Err(format!(
                "출금 금액은 수수료 {WITHDRAW_FEE_USDC} USDC보다 커야 합니다"
            ));
        }
        // The withdrawal fee comes out of the amount itself (Arbitrum receives amount − fee),
        // so the whole withdrawable balance can be withdrawn.
        if units_at_balance > available {
            return Err("잔액이 부족합니다".to_owned());
        }
        let payload = match (form.kind, &token) {
            (HcFormKind::Send, None) => {
                let (destination, recipient) = recipient_of(&form.to_text)?;
                return Ok((
                    HcPayload::UsdSend {
                        destination,
                        amount,
                    },
                    None,
                    recipient,
                ));
            }
            (HcFormKind::Send, Some(token)) => {
                let (destination, recipient) = recipient_of(&form.to_text)?;
                return Ok((
                    HcPayload::SpotSend {
                        destination,
                        token: token.wire(),
                        amount,
                    },
                    Some(token.clone()),
                    recipient,
                ));
            }
            (HcFormKind::Withdraw, _) => {
                let (destination, recipient) = recipient_of(&form.to_text)?;
                return Ok((
                    HcPayload::Withdraw {
                        destination,
                        amount,
                    },
                    None,
                    recipient,
                ));
            }
            (HcFormKind::ClassTransfer, _) => HcPayload::UsdClassTransfer {
                amount,
                to_perp: form.to_perp,
            },
            (HcFormKind::ToEvm, Some(token)) => HcPayload::SendAsset {
                destination: token.system_address(),
                source_dex: "spot".to_owned(),
                destination_dex: "spot".to_owned(),
                token: token.wire(),
                amount,
            },
            (HcFormKind::ToEvm, None) => return Err("HyperEVM으로 옮길 토큰을 고르세요".to_owned()),
        };
        Ok((payload, token, HcRecipient::default()))
    }

    /// Re-checks the form (after every edit and load).
    pub fn hc_validate(&mut self) {
        let result = self.hc_build();
        let known = self.known_addresses();
        let checked = match self.selected_account() {
            Some((sender, ..)) if !self.hypercore.form.to_text.trim().is_empty() => {
                check_recipient(&self.hypercore.form.to_text, &sender, None, &known).ok()
            }
            _ => None,
        };
        let recipient = checked.as_ref().map(|(address, _)| *address);
        let form = &mut self.hypercore.form;
        // The acknowledgement belongs to one address: any change of the recipient drops it.
        if form.recipient != recipient {
            form.ack = false;
            form.ack_for = None;
        }
        form.recipient = recipient;
        match (result, checked) {
            (Ok((_, _, checks)), checked) => {
                form.error = None;
                form.notes = checked.map(|(_, notes)| notes).unwrap_or_default();
                if !checks.look_alike {
                    form.ack = false;
                    form.ack_for = None;
                }
            }
            (Err(text), _) => {
                form.error = Some(text);
                form.notes.clear();
            }
        }
    }

    /// `주소 전체를 직접 확인했습니다` toggled: it covers the recipient checked last only.
    pub fn hc_toggle_ack(&mut self) {
        let form = &mut self.hypercore.form;
        form.ack = !form.ack && form.recipient.is_some();
        form.ack_for = if form.ack { form.recipient } else { None };
        self.refresh();
    }

    /// `검토` allowed.
    #[must_use]
    pub fn hc_can_review(&self) -> bool {
        let form = &self.hypercore.form;
        let look_alike = form.notes.iter().any(AddressNote::needs_ack);
        let acknowledged = form.ack && form.ack_for.is_some() && form.ack_for == form.recipient;
        form.error.is_none()
            && (!look_alike || acknowledged)
            && matches!(self.mode, AppMode::Unlocked { .. })
            && self.hypercore.pending.is_empty()
            // U7: the signing account's phrase waits for its backup quiz (the band says so).
            && !self.mn_send_blocked(self.evm_selected_gate())
    }

    /// `검토`: queue the approval (the nonce is the current wall-clock ms).
    pub fn hc_review(&mut self) {
        self.hc_validate();
        if !self.hc_can_review() {
            self.refresh();
            return;
        }
        let Ok((payload, token, recipient)) = self.hc_build() else {
            return;
        };
        let Some((account, signer, _)) = self.selected_account() else {
            return;
        };
        let action = HcAction::new(self.hc_network(), now_unix_ms(), payload);
        if action.validate().is_err() {
            self.hypercore.form.error = Some("작업 형식이 올바르지 않습니다".to_owned());
            self.refresh();
            return;
        }
        let item = HcApprovalItem {
            action,
            account,
            signer,
            token,
            recipient,
        };
        if self
            .evm
            .queue
            .enqueue(QueueSource::App, QueuedItem::HyperCore(Box::new(item)))
            .is_ok()
        {
            self.hypercore.form.info = None;
            self.show_next_approval();
        } else {
            self.hypercore.form.info = Some(crate::errors::ErrorCode::App005.text());
            self.refresh();
        }
    }

    /// Builds the draft of a queued item at its first Ready display.
    pub(crate) fn prepare_hypercore(&mut self, item: &HcApprovalItem) {
        let Ok(id) = Self::new_approval_id() else {
            self.show_failure(
                crate::errors::ErrorCode::Vlt005,
                false,
                crate::errors::ErrorCode::Vlt005.text(),
            );
            return;
        };
        let input = yw_core::hypercore::display::HcApprovalInput {
            action: &item.action,
            account: item.account,
            signer: item.signer,
            token: item.token.as_ref(),
            recipient: item.recipient.clone(),
        };
        match yw_core::hypercore::display::build_hypercore_request(id, &input) {
            Ok(draft) => self.show_ready_draft_at(draft, None, now_unix_ms()),
            Err(_) => self.show_failure(
                crate::errors::ErrorCode::App009,
                false,
                crate::errors::ErrorCode::App009.text(),
            ),
        }
    }

    /// `consume` succeeded: sign on the vault or the card (`YubiKey`), then submit.
    pub(crate) fn hc_consumed(&mut self, approved: Approved, item: &HcApprovalItem) {
        let ticket = self.push_sign_waiter(crate::app_browser::SignWaiter::App);
        self.hypercore.pending.insert(ticket, item.action.clone());
        let amount = match &item.token {
            Some(token) => format!(
                "{} {}",
                item.action.amount(),
                yw_core::approval::escape_untrusted(&token.name).text
            ),
            None => format!("{} USDC", item.action.amount()),
        };
        self.hypercore.activity.insert(
            0,
            HcActivity {
                network: item.action.network,
                nonce: item.action.nonce,
                account: item.account,
                kind: item.action.kind(),
                amount,
                to: item.action.destination(),
                status: HcStatus::Signing,
            },
        );
        self.hypercore.activity.truncate(MAX_ACTIVITY);
        self.hypercore.form = HcForm::default();
        logging::info(
            "app",
            "hypercore.approved",
            &[
                ("net", Field::Word(item.action.network.as_str())),
                ("type", Field::Word(item.action.kind().wire_type())),
            ],
        );
        if let Err(approved) = self.card_begin(
            approved,
            crate::app_card::CardJobKind::EvmMessage { typed: true },
            Some(ticket),
        ) {
            self.key(KeyJob::SignMessage {
                ticket,
                approved,
                typed: true,
            });
        }
        if matches!(self.screen, Screen::HyperCore) {
            self.set_screen(Screen::Main);
        }
        self.refresh();
    }

    /// A message signature finished: `true` when it was a `HyperCore` job (then posted).
    pub(crate) fn hc_message_signed(&mut self, signed: &MessageSigned) -> bool {
        let Some(action) = self.hypercore.pending.remove(&signed.ticket) else {
            return false;
        };
        let _ = self.take_sign_waiter(signed.ticket);
        match &signed.result {
            Ok(signature) => {
                let job = HcRpcJob::Submit {
                    endpoint: self.hc_endpoint(action.network),
                    nonce: action.nonce,
                    body: action.exchange_body(signature),
                };
                let status = if self.rpc(RpcJob::HyperCore(Box::new(job))) {
                    HcStatus::Submitting
                } else {
                    HcStatus::Unknown("RPC 작업자를 사용할 수 없습니다".to_owned())
                };
                self.hc_set_status(action.network, action.nonce, status);
            }
            Err(failure) => {
                let text = match failure {
                    MessageSignFailure::Locked => "잠겨서 취소됨".to_owned(),
                    MessageSignFailure::Card(error) => error.to_string(),
                    MessageSignFailure::Sign(error) => error.to_string(),
                };
                self.hc_set_status(action.network, action.nonce, HcStatus::NotSigned(text));
            }
        }
        self.refresh();
        true
    }

    /// A consumed signing job was cancelled (lock, card window closed): `true` when it was ours.
    pub(crate) fn hc_sign_cancelled(&mut self, ticket: SignTicket) -> bool {
        let Some(action) = self.hypercore.pending.remove(&ticket) else {
            return false;
        };
        self.hc_set_status(
            action.network,
            action.nonce,
            HcStatus::NotSigned("취소됨".to_owned()),
        );
        true
    }

    /// An approval ended.
    pub(crate) fn hc_approval_finished(&mut self, outcome: QueueOutcome) {
        if outcome == QueueOutcome::Expired {
            self.hypercore.form.info = Some("승인 시간이 지났습니다. 다시 검토하세요.".to_owned());
        }
        logging::info(
            "app",
            "approval.finished",
            &[(
                "outcome",
                Field::Word(crate::app_evm::outcome_name(outcome)),
            )],
        );
        self.refresh();
    }

    /// `HyperEVM에서 Core로 이동`: the EVM send form on `HyperEVM` with HYPE's system address
    /// (another linked token: choose it in the form; the recipient guard checks the pair).
    pub fn hc_open_from_evm(&mut self) {
        let chain_id = self.hc_network().hyperevm_chain_id();
        if !self.settings.registered_evm().contains(&chain_id) {
            self.notice(
                format!(
                    "HyperEVM(chainId {chain_id})이 등록되어 있지 않습니다. 설정 → EVM 체인에서 추가하세요."
                ),
                crate::ui::main_window::Tone::Warn,
            );
            return;
        }
        if self.settings.evm_chain_id != chain_id {
            let mut settings = self.settings.clone();
            settings.evm_chain_id = chain_id;
            self.save_settings(settings, "evmChainId");
            self.evm_balances_due();
        }
        self.evm.send = crate::app_evm::SendForm {
            asset: SendAsset::Native,
            to_text: yw_core::hypercore::HYPE_SYSTEM_ADDRESS.to_checksum(),
            ..crate::app_evm::SendForm::default()
        };
        self.open_send();
        self.validate_send(true);
    }

    /// The `HyperEVM` system-address guard of the EVM send form (spec/11 §5.5): on `HyperEVM`, a
    /// recipient that is a system address must match the asset — HYPE (native) only to
    /// `0x2222…2222`, a token only to the system address whose `spotMeta` link is that token.
    /// `None` = fine or not a system address.
    #[must_use]
    pub fn hc_system_recipient_error(
        &self,
        chain_id: u64,
        recipient: &Address,
        asset: SendAsset,
    ) -> Option<String> {
        let network = [HcNetwork::Mainnet, HcNetwork::Testnet]
            .into_iter()
            .find(|network| network.hyperevm_chain_id() == chain_id)?;
        let hype = *recipient == yw_core::hypercore::HYPE_SYSTEM_ADDRESS;
        let index = yw_core::hypercore::system_address_index(recipient);
        if !hype && index.is_none() {
            return None;
        }
        match (asset, hype, index) {
            (SendAsset::Native, true, _) | (SendAsset::Token(_), false, None) => None,
            (SendAsset::Native, false, _) => Some(
                "HYPE는 0x2222…2222로만 HyperCore로 옮길 수 있습니다 — 이 시스템 주소로 보내면 잃을 수 있습니다".to_owned(),
            ),
            (SendAsset::Token(_), true, _) => Some(
                "0x2222…2222는 HYPE 전용 시스템 주소입니다 — 토큰을 보내면 잃을 수 있습니다".to_owned(),
            ),
            (SendAsset::Token(token), false, Some(index)) => {
                let Some(linked) = self.hypercore.token(network, index) else {
                    return Some(
                        "HyperCore 토큰 정보를 확인할 수 없어 시스템 주소를 검증하지 못했습니다 — EVM 탭의 HyperCore 카드에서 새로고침하세요".to_owned(),
                    );
                };
                let ok = linked.evm.is_some_and(|link| link.address == token);
                (!ok).then(|| {
                    format!(
                        "이 시스템 주소(토큰 index {index})에 연결된 토큰이 아닙니다 — 보내면 잃을 수 있습니다"
                    )
                })
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use yw_core::evm::address::{Address, parse_address};
    use yw_core::hypercore::{HcEvmLink, HcKind, HcNetwork, HcPerpState, HcSpotBalance, HcToken};

    use super::{HC_WITHDRAW_OWN_TEXT, HcActivity, HcAsset, HcForm, HcFormKind, HcStatus};
    use crate::apikeys::ApiKeys;
    use crate::app::{App, AppMode, Paths, Screen};
    use crate::flow::evm::form::AddressNote;
    use crate::hypercore::HcBalances;
    use crate::meta::{Account, EvmAccountPref, Meta};
    use crate::settings::Settings;
    use crate::ui::main_window::{Ctl, Item, Tone};
    use crate::ui::screens_hypercore::ids;

    const OWN: &str = "0x9858effd232b4033e47d90003d41ec34ecaeda94";
    const OTHER: &str = "0x00000000000000000000000000000000000000b2";
    /// Look-alikes of `OWN` (the first and the last six hex digits).
    const LOOK_A: &str = "0x9858ef1111111111111111111111111111aeda94";
    const LOOK_B: &str = "0x9858ef2222222222222222222222222222aeda94";

    fn address(text: &str) -> Address {
        parse_address(text).unwrap()
    }

    /// An unlocked wallet with EVM accounts `OWN` (selected) and `OTHER`, the mainnet `HyperCore`
    /// balances of `OWN` (100 USDC perp; 1.23456789 of a token whose `HyperEVM` side has two
    /// decimals fewer) and S-HC open.
    fn app() -> App {
        let dir = std::env::temp_dir().join(format!("yw-app-hc-ui-{}", std::process::id()));
        let mut app = App::new(
            Paths {
                data: dir.clone(),
                logs: dir.join("logs"),
            },
            true,
            Settings::default(),
            ApiKeys::default(),
        );
        app.mode = AppMode::Unlocked {
            alt_passphrase: false,
        };
        let mut meta = Meta::default();
        meta.evm_accounts[0].address = OWN.to_owned();
        meta.evm_accounts.push(Account {
            index: 1,
            label: "계정 2".to_owned(),
            address: OTHER.to_owned(),
            hidden: false,
        });
        app.meta = Some(meta);
        let token = HcToken {
            name: "TKN".to_owned(),
            index: 1,
            token_id: "0x0000000000000000000000000000000a".to_owned(),
            sz_decimals: 2,
            wei_decimals: 8,
            evm: Some(HcEvmLink {
                address: address("0x00000000000000000000000000000000000000c3"),
                extra_wei_decimals: -2,
            }),
            full_name: None,
        };
        app.hypercore.tokens = Some((HcNetwork::Mainnet, vec![token]));
        app.hypercore.balances = Some((
            HcNetwork::Mainnet,
            address(OWN),
            HcBalances {
                spot: vec![HcSpotBalance {
                    coin: "TKN".to_owned(),
                    token: 1,
                    total: "1.23456789".to_owned(),
                    hold: "0.0".to_owned(),
                }],
                perp: HcPerpState {
                    account_value: "100.0".to_owned(),
                    withdrawable: "100.0".to_owned(),
                    positions: 0,
                },
            },
        ));
        app.screen = Screen::HyperCore;
        app
    }

    fn form(app: &mut App, kind: HcFormKind, to: &str, amount: &str) {
        app.hypercore.form = HcForm {
            kind,
            to_text: to.to_owned(),
            amount_text: amount.to_owned(),
            to_perp: true,
            asset: if kind == HcFormKind::ToEvm {
                HcAsset::Spot(1)
            } else {
                HcAsset::PerpUsdc
            },
            ..HcForm::default()
        };
        app.hc_validate();
    }

    fn shown(app: &App, card: bool) -> Vec<Item> {
        let mut items = Vec::new();
        if card {
            app.hc_card(&mut items);
        } else {
            app.hc_screen(&mut items);
        }
        items
    }

    fn banners(items: &[Item]) -> Vec<(String, Tone)> {
        items
            .iter()
            .filter_map(|item| match item {
                Item::Banner(text, tone) => Some((text.clone(), *tone)),
                _ => None,
            })
            .collect()
    }

    fn control(items: &[Item], id: u16) -> Option<Ctl> {
        items
            .iter()
            .flat_map(|item| match item {
                Item::Row(row) | Item::LabeledRow(_, row) => row.clone(),
                _ => Vec::new(),
            })
            .find(|ctl| ctl.id == id)
    }

    /// The look-alike acknowledgement covers one recipient: a change to another look-alike drops
    /// it (S11 and the Bitcoin form do the same).
    #[test]
    fn look_alike_acknowledgement_follows_the_recipient() {
        let mut app = app();
        form(&mut app, HcFormKind::Send, LOOK_A, "1");
        assert!(app.hypercore.form.error.is_none());
        assert!(app.hypercore.form.notes.iter().any(AddressNote::needs_ack));
        assert!(!app.hc_can_review());
        app.hc_toggle_ack();
        assert!(app.hc_can_review());
        // Another look-alike in the field: not acknowledged.
        app.hypercore.form.to_text = LOOK_B.to_owned();
        app.hc_validate();
        assert!(app.hypercore.form.notes.iter().any(AddressNote::needs_ack));
        assert!(!app.hypercore.form.ack && !app.hc_can_review());
        app.hc_toggle_ack();
        assert!(app.hc_can_review());
        // An acknowledgement recorded for another address does not count.
        app.hypercore.form.ack_for = Some(address(LOOK_A));
        assert!(!app.hc_can_review());
    }

    /// The card lists the selected account's transfers only.
    #[test]
    fn card_activity_is_the_selected_accounts() {
        let mut app = app();
        app.screen = Screen::Main;
        // Whole next to HyperEVM (the card folds to one line next to other chains, 2026-11-10).
        app.settings.evm_chain_id = 999;
        for (account, amount) in [(OWN, "10 USDC"), (OTHER, "20 USDC")] {
            app.hypercore.activity.push(HcActivity {
                network: HcNetwork::Mainnet,
                nonce: 1_790_000_000_000,
                account: address(account),
                kind: HcKind::UsdSend,
                amount: amount.to_owned(),
                to: Some(address(LOOK_A)),
                status: HcStatus::Ok,
            });
        }
        let texts = |app: &App| -> Vec<String> {
            shown(app, true)
                .into_iter()
                .filter_map(|item| match item {
                    Item::Text(text) => Some(text),
                    _ => None,
                })
                .collect()
        };
        let own = texts(&app);
        assert!(own.iter().any(|text| text.contains("10 USDC")), "{own:?}");
        assert!(!own.iter().any(|text| text.contains("20 USDC")), "{own:?}");
        app.meta.as_mut().unwrap().prefs.evm_account = EvmAccountPref::Index(1);
        let other = texts(&app);
        assert!(
            other.iter().any(|text| text.contains("20 USDC")),
            "{other:?}"
        );
        assert!(
            !other.iter().any(|text| text.contains("10 USDC")),
            "{other:?}"
        );
    }

    /// S-HC shows what can be sent and `최대` fills it at the form's decimals (a `HyperEVM` move
    /// cuts the digits the EVM side lacks); a withdrawal to the signing account is information;
    /// a failed load says so with `새로고침` instead of "loading" forever.
    #[test]
    fn forms_show_the_available_amount_and_the_load_state() {
        let mut app = app();
        form(&mut app, HcFormKind::Withdraw, OWN, "");
        assert!(control(&shown(&app, false), ids::MAX).is_some_and(|ctl| ctl.enabled));
        app.hc_fill_max();
        assert_eq!(app.hypercore.form.amount_text, "100");
        assert!(app.hypercore.form.error.is_none() && app.hc_can_review());
        let items = shown(&app, false);
        assert!(
            banners(&items).contains(&(HC_WITHDRAW_OWN_TEXT.to_owned(), Tone::Info)),
            "{:?}",
            banners(&items)
        );

        form(&mut app, HcFormKind::ToEvm, "", "");
        assert_eq!(
            app.hc_form_available(),
            Some(("1.234567".to_owned(), "TKN".to_owned()))
        );
        app.hc_fill_max();
        assert_eq!(app.hypercore.form.amount_text, "1.234567");
        assert!(
            app.hypercore.form.error.is_none(),
            "{:?}",
            app.hypercore.form.error
        );

        // The load failed: the reason and `새로고침`, not an endless "불러오는 중".
        app.hypercore.balances = None;
        app.hypercore.loading = false;
        app.hypercore.error = Some("Hyperliquid API에 연결할 수 없습니다".to_owned());
        app.hc_validate();
        let error = app.hypercore.form.error.clone().unwrap();
        assert!(error.contains("불러오지 못했습니다"), "{error}");
        let items = shown(&app, false);
        assert!(control(&items, ids::REFRESH).is_some());
        assert!(
            banners(&items)
                .iter()
                .any(|(text, _)| text == "Hyperliquid API에 연결할 수 없습니다")
        );
        assert!(control(&items, ids::MAX).is_some_and(|ctl| !ctl.enabled));
    }
}
