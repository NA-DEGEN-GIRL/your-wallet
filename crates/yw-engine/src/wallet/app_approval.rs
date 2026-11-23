//! The approval flow (spec/04 §3.4–§3.7, spec/03 §11): the queue's shown request from its open
//! to its end — the open and its answer, the preparation and re-simulation, the AI explanation's
//! flow, approve, reject, expiry, `consume_and_sign` (the only `consume`) and the hand-off to the
//! signing jobs. The approval window A01 (its painting, its window procedures and the
//! `Effect::Approval` executor) stays in yw-app `app_approval.rs`; the two meet only through
//! `Cmd::Approval`/`Cmd::ApprovalOpened` and `Effect::Approval`.
//!
//! 2026-11-23 (spec/15 §11.4 S4d E1): the flow half of yw-app `app_approval.rs` moved here
//! unchanged (bodies, docs): the three `impl Wallet` blocks, `ConnectState`, `AiReady`, `AfterOpen`,
//! `explain_kind`, the header badges' order (`network_badge`, `order_badges`) and
//! `site_fee_warning`. Before (2026-11-20 S4a … 2026-11-22 S4c W14c), both halves were one file.

use crate::approval::flow::{
    ApprovalEffect, ApprovalInput, ApprovalSignal, OpenOutcome, ShownId, StatusAction,
    connect_gate_count,
};
use crate::effect::Effect;
use yw_core::approval::RiskLevel;
use yw_core::evm::chain::SEPOLIA;
use yw_core::evm::simulate::needs_resimulation;
use yw_core::lang::{Lang, Text};

use crate::approval::QueueOutcome;
use crate::approval::interaction::{InteractionEvent, PrepareState, ReadyContent};
use crate::approval::text;
use crate::approval::view::view;
use crate::badge::Badge;
use crate::browser::{SiteKind, SiteRequest};
use crate::errors::ErrorCode;
use crate::events::{KeyJob, SignInfo};
use crate::explain::input::RequestKind;
use crate::explain::panel::{AiPanel, Dispatch, Ended};
use crate::explain::{
    ExplainError, ExplainInput, ExplainSource, LlmDone, LlmJob, RequestStats, build_input,
};
use crate::flow::evm::Limits;
use crate::flow::evm::prepare::{
    PrepareJob, PrepareOutcome, PrepareResult, Prepared, ResimJob, ResimKind, ResimResult,
};
use crate::logging::{self, Field};
use crate::wallet::Wallet;
use crate::wallet::app_evm::{AppApproval, QueuedItem};
use crate::wallet::app_llm::log_request;
use crate::wallet::approval_flow::{AiFlow, AiReserved, ApprovalFlow};
use crate::workers::rpc::RpcJob;

const SKIP_BLOCKED: Text = text::AI_SKIP_BLOCKED;

const SKIP_FAILED: Text = text::AI_SKIP_FAILED;

/// What a Ready display means for the AI panel.
enum AiReady {
    Input(Result<ExplainInput, ExplainError>),
    Skip(&'static str),
}

/// Connect-window state (spec/05 §4.2, §4.9).
#[derive(Clone, Debug)]
pub struct ConnectState {
    /// Offered accounts `(choice, label, address text, group)` in list order. EVM accounts are
    /// checkboxes (1–16); Solana and Bitcoin choices are one radio group per purpose.
    pub accounts: Vec<crate::wallet::app_chain_sites::ConnectEntry>,
    /// Selection.
    pub selected: Vec<bool>,
    /// Origin chain name.
    pub chain_name: String,
    /// EVM: the origin chain shown (`chain_name`). Re-read from the dispatcher at every render
    /// and checked at approval, which stores exactly this chain (security review L4(c)).
    pub chain_id: u64,
    /// The request's chain family.
    pub family: yw_core::policy::Family,
    /// Number of radio groups (Solana 1, Bitcoin one per purpose; unused for EVM).
    pub groups: u8,
}

impl ConnectState {
    /// The gate's `connect_selected`: the checked count for EVM; for Solana/Bitcoin the count
    /// when every group has exactly one choice, else 0 (approve disabled). (2026-11-19, S4 B3:
    /// the rule is `yw_engine::approval::flow::connect_gate_count`, moved from here unchanged.)
    #[must_use]
    pub fn gate_count(&self) -> usize {
        connect_gate_count(
            &self.accounts,
            |(_, _, _, group)| *group,
            &self.selected,
            self.groups,
            self.family == yw_core::policy::Family::Evm,
        )
    }

    /// Toggles entry `index`: a checkbox for EVM, a radio button within its group otherwise.
    pub fn toggle(&mut self, index: usize) {
        if self.family == yw_core::policy::Family::Evm {
            if let Some(slot) = self.selected.get_mut(index) {
                *slot = !*slot;
            }
            return;
        }
        let Some(group) = self.accounts.get(index).map(|(_, _, _, group)| *group) else {
            return;
        };
        for (position, ((_, _, _, of), slot)) in self
            .accounts
            .iter()
            .zip(self.selected.iter_mut())
            .enumerate()
        {
            if *of == group {
                *slot = position == index;
            }
        }
    }
}

/// The AI explanation kind of a queued item (spec/06 §3.1): dApp transactions, `personal_sign`
/// and typed data; the window reserves its panel only while the LLM worker exists. 2026-11-19
/// (S4 B5): the match of `open_approval`, shared with the open's answer.
fn explain_kind(item: &QueuedItem) -> Option<RequestKind> {
    match item {
        QueuedItem::Site(site) => match &site.kind {
            SiteKind::Send(_) => Some(RequestKind::EvmTx),
            SiteKind::PersonalSign { .. } => Some(RequestKind::PersonalSign),
            SiteKind::TypedData { .. } => Some(RequestKind::TypedData),
            SiteKind::RequestAccounts
            | SiteKind::RequestPermissions
            | SiteKind::Revoke
            | SiteKind::SolConnect
            | SiteKind::BtcConnect(_)
            | SiteKind::SolSign { .. }
            | SiteKind::SolTx { .. }
            | SiteKind::BtcSign { .. } => None,
        },
        QueuedItem::App(_)
        | QueuedItem::Sol(_)
        | QueuedItem::Btc(_)
        | QueuedItem::Zec(_)
        | QueuedItem::HyperCore(_) => None,
    }
}

/// The header network badge (spec/04 §3 header): built-in mainnets (Ethereum, `HyperEVM`,
/// Arbitrum One, Base, BNB Smart Chain, Robinhood Chain, Solana mainnet) say plainly that real assets move; Sepolia and Solana devnet are test
/// networks. User chains have no testnet classification and get neither; Bitcoin has its own
/// network banner. Returns the text and whether it is the testnet coloring.
#[doc(hidden)]
#[must_use]
pub fn network_badge(
    lang: Lang,
    evm_chain: Option<u64>,
    sol: Option<yw_core::sol::SolCluster>,
) -> Option<(&'static str, bool)> {
    use yw_core::evm::chain::is_builtin_mainnet;
    use yw_core::sol::SolCluster;
    match (evm_chain, sol) {
        (_, Some(SolCluster::Devnet)) => Some((text::BADGE_DEVNET.get(lang), true)),
        (_, Some(SolCluster::Mainnet)) => Some((text::BADGE_MAINNET.get(lang), false)),
        (Some(chain), None) if is_builtin_mainnet(chain) => {
            Some((text::BADGE_MAINNET.get(lang), false))
        }
        (Some(SEPOLIA), None) => Some((text::BADGE_TESTNET.get(lang), true)),
        _ => None,
    }
}

/// Whether `badge` is `text` in either language (the badge order and colors do not depend on
/// the window's language).
#[must_use]
pub fn is_badge(badge: &str, text: Text) -> bool {
    Lang::ALL.iter().any(|lang| badge == text.get(*lang))
}

/// Whether `badge` starts with the fixed part of `text` (before any `{0}`) in either language.
fn badge_starts<const N: usize>(badge: &str, text: yw_core::lang::Tpl<N>) -> bool {
    Lang::ALL.iter().any(|lang| {
        let template = text.template(*lang);
        badge.starts_with(template.split('{').next().unwrap_or(template))
    })
}

/// Where a header badge goes (spec/04 §3.2, 2026-11-10): the network first (mainnet / testnet),
/// then the origin's risk (punycode, http), the compatibility mode and the `WalletConnect`
/// session, the user chain, and last the signer (`YubiKey`) and the Verify state. Signing,
/// connect and `WalletConnect` connect windows use the same order. The badges are app chrome
/// outside the digested display.
fn badge_rank(badge: &str) -> u8 {
    if [
        text::BADGE_MAINNET,
        text::BADGE_TESTNET,
        text::BADGE_DEVNET,
        text::BADGE_HC_TESTNET,
    ]
    .into_iter()
    .any(|text| is_badge(badge, text))
        || Lang::ALL.iter().any(|lang| {
            [
                yw_core::btc::BtcNetwork::Mainnet,
                yw_core::btc::BtcNetwork::Testnet4,
            ]
            .iter()
            .any(|network| badge == network.banner_in(*lang))
        })
    {
        0
    } else if badge_starts(badge, text::BADGE_PUNYCODE) {
        1
    } else if badge_starts(badge, text::BADGE_HTTP) {
        2
    } else if badge_starts(badge, text::BADGE_COMPAT) {
        3
    } else if is_badge(badge, text::BADGE_WALLETCONNECT) {
        4
    } else if badge_starts(badge, text::BADGE_CUSTOM_CHAIN) {
        5
    } else if badge_starts(badge, text::BADGE_YUBIKEY) {
        6
    } else if badge.starts_with("Verify ") {
        7
    } else {
        8
    }
}

/// Puts header badges in [`badge_rank`] order (stable within a rank).
#[doc(hidden)]
pub fn order_badges(badges: &mut [String]) {
    badges.sort_by_key(|badge| badge_rank(badge));
}

/// What a caller of [`Wallet::show_next_approval_then`] did after the call before 2026-11-20 (S4
/// P9, plan §4.4 S5, §4.6): it runs once the open of the next window is answered
/// (`Cmd::ApprovalOpened`; P9's `App::after_approval_opened`, since P10a
/// [`Wallet::approval_open_answered`] and [`Wallet::after_pending_open`]: after the answer's own steps
/// — the first view and the preparation, or the rejection of a window that could not be made),
/// or at once when no window was asked for. While the executor applied effects at once (until
/// P10b) that was the point where the caller went on before; with the outbox (since P10b) the
/// caller's steps still follow the answer instead of running before it.
///
/// 2026-11-20 (S4 P10a, plan §4.4 S5, §4.6 rule 2): the steps that ran after a call that may
/// open an approval window, in the same fn, are these too (except the lines the S5 check lists
/// with their reasons) and go through [`Wallet::after_pending_open`]: kept for the answer of the
/// open still waiting for one, else run at once. While the executor applied effects at once
/// (until P10b) no open waited when logic code ran, so each step ran at the point and in the
/// order it ran before (byte-equal by construction); with the outbox (since P10b) it runs after
/// the open's answer, when the entry drains, as it did. Before, those steps ran right after the
/// call (`PENDING_P10` lines of the S5 check). A step reads the wallet when it runs, as the code
/// it replaced did then. 2026-11-21 (S4 F14, owner decision, spec/04 §5.3): a lock drops the
/// kept steps (`Wallet::lock_steps`, at the `lock_epoch` bump; 2026-11-21, S4 W3a: before,
/// `App::lock`), so none runs after it (pinned by
/// `a_lock_drops_the_steps_kept_for_an_open_in_the_same_entry`,
/// `a_lock_drops_the_steps_kept_for_an_open_of_an_earlier_entry` and, since the F14 review,
/// `a_suspend_lock_drops_the_steps_kept_for_an_open_before_its_drain`); from P10b (review,
/// 2026-11-20) until F14 a lock in the entry that queued the open kept them, and they ran after
/// the lock with the stale open's answer.
#[doc(hidden)]
pub enum AfterOpen {
    /// `card_site_check` (a revoke of signing requests or of an account: an approved request
    /// waiting for its `YubiKey` PIN ends too, spec/10 §9.2).
    CardSiteCheck,
    /// `card_site_check`, then `refresh` (a page's cancel, `cancel_site`).
    CardSiteCheckThenRefresh,
    /// The rest of a Bitcoin controller batch after its `Enqueue`, then the batch's `refresh`
    /// (`Wallet::btc_apply_rest`).
    BtcRest(Vec<crate::wallet::app_btc::BtcAction>),
    /// The steps kept for a window whose open was just answered, in the order they were kept
    /// (`Wallet::on_cmd`'s `Cmd::ApprovalOpened` arm, `App::on_cmd`'s before 2026-11-22 S4c W15; before P10a, `after_approval_opened` ran the
    /// one kept step there).
    Steps(Vec<AfterOpen>),
    /// `refresh` (a Bitcoin press, a journal read, a site grant change).
    Refresh,
    /// `refresh` when the Bitcoin controller returned no action (`btc_call_and_repaint`; a batch
    /// repaints itself).
    RefreshUnlessActed(bool),
    /// `set_screen` (a confirmation overlay's next screen after its action).
    SetScreen(crate::wallet::Screen),
    /// The hidden account's note, then `refresh` (`hide_selected`); the label.
    HiddenNote(String),
    /// The grants written, then `refresh` (a revoke the dispatcher reported). 2026-11-21 (S4 F14
    /// review, spec/15 §18 item 16): dropped by a lock before the open's answer, so the revoke is
    /// not saved to meta; the same before F14 (it ran after the lock, with no meta). Unreachable
    /// while every entry drains; open for S4d E2. 2026-11-21 (S4 F16, owner decision): the revoke
    /// is noted as a waiting write (`GrantWrite::revoke`), which the lock writes at its start
    /// (`Wallet::flush_grant_writes`) before it drops this step, so the revoke is saved.
    WriteGrantsThenRefresh,
    /// `finish_approval` (a consumed Bitcoin approval).
    Finish(QueueOutcome),
    /// The close box: `finish_approval(Rejected)` when window `shown` is still the shown one
    /// (S4 F1, L-1).
    CloseIfShown(ShownId),
    /// The opened window's preparation (`on_approval_opened`).
    StartPrepare,
    /// The view built again (`start_prepare`).
    RebuildView,
    /// The AI explanation of a ready transaction.
    AiReadyTx,
    /// The AI explanation of a ready message.
    AiReadyMessage,
    /// The AI explanation of ready typed data, with its facts.
    AiReadyTyped(Box<yw_core::approval::ChainFacts>),
    /// The meta load's chain hooks (`KeyOutcome::Meta(Ok)`): the journal, then Bitcoin, then
    /// [`AfterOpen::AfterBtcMeta`].
    AfterMeta,
    /// The rest of the meta load's hooks after Bitcoin's: Zcash, then the card.
    AfterBtcMeta,
    /// The rest of the EVM timer part after the approval's (`evm_tick`), at its `now`.
    EvmTickRest(u64),
    /// The Zcash refresh's snapshot kept, then `refresh` (`zec_rpc_event`).
    ZecSnapshot(yw_core::zec::ZecNetwork, Box<crate::zec::work::ZecSnapshot>),
    /// The Bitcoin tab's opening refresh when it is shown and idle (`btc_journal_changed`).
    BtcOpenTab,
    /// S12 Bitcoin unless it or an overlay shows (`BtcPress::ReceiveOpen`).
    BtcReceiveScreen,
    /// The typed-fee field dropped when no longer asked for (a fee radio; `true`: the bump form).
    BtcDropStaleTyped(bool),
    /// The Esplora URL edit of `net` shows the stored URL (`field`); with `saved_only`, only
    /// when the save left no settings message.
    EsploraField {
        /// The network.
        net: yw_core::btc::BtcNetwork,
        /// Its edit.
        field: crate::form::EditField,
        /// `저장` (`true`) or `기본값으로`.
        saved_only: bool,
    },
}

/// The step's name and the number of the batch's remaining actions only (D28); 2026-11-20 (S4
/// P10a): the new steps print their names, counts and lengths, flags and ids only (no label,
/// screen, URL, facts or snapshot).
impl core::fmt::Debug for AfterOpen {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::CardSiteCheck => formatter.write_str("CardSiteCheck"),
            Self::CardSiteCheckThenRefresh => formatter.write_str("CardSiteCheckThenRefresh"),
            Self::BtcRest(rest) => formatter.debug_tuple("BtcRest").field(&rest.len()).finish(),
            Self::Steps(steps) => formatter.debug_tuple("Steps").field(steps).finish(),
            Self::Refresh => formatter.write_str("Refresh"),
            Self::RefreshUnlessActed(acted) => formatter
                .debug_tuple("RefreshUnlessActed")
                .field(acted)
                .finish(),
            Self::SetScreen(_) => formatter.write_str("SetScreen"),
            Self::HiddenNote(label) => formatter
                .debug_tuple("HiddenNote")
                .field(&label.chars().count())
                .finish(),
            Self::WriteGrantsThenRefresh => formatter.write_str("WriteGrantsThenRefresh"),
            Self::Finish(outcome) => formatter.debug_tuple("Finish").field(outcome).finish(),
            Self::CloseIfShown(shown) => {
                formatter.debug_tuple("CloseIfShown").field(shown).finish()
            }
            Self::StartPrepare => formatter.write_str("StartPrepare"),
            Self::RebuildView => formatter.write_str("RebuildView"),
            Self::AiReadyTx => formatter.write_str("AiReadyTx"),
            Self::AiReadyMessage => formatter.write_str("AiReadyMessage"),
            Self::AiReadyTyped(_) => formatter.write_str("AiReadyTyped"),
            Self::AfterMeta => formatter.write_str("AfterMeta"),
            Self::AfterBtcMeta => formatter.write_str("AfterBtcMeta"),
            Self::EvmTickRest(now) => formatter.debug_tuple("EvmTickRest").field(now).finish(),
            Self::ZecSnapshot(..) => formatter.write_str("ZecSnapshot"),
            Self::BtcOpenTab => formatter.write_str("BtcOpenTab"),
            Self::BtcReceiveScreen => formatter.write_str("BtcReceiveScreen"),
            Self::BtcDropStaleTyped(bump) => formatter
                .debug_tuple("BtcDropStaleTyped")
                .field(bump)
                .finish(),
            Self::EsploraField { saved_only, .. } => formatter
                .debug_struct("EsploraField")
                .field("saved_only", saved_only)
                .finish_non_exhaustive(),
        }
    }
}

impl Wallet {
    // ----- queue and window lifecycle -----------------------------------------------------

    /// Shows the next queued approval (unlocked only, spec/04 §3.7). Site items that need no
    /// window (connected `eth_requestAccounts`, revoke after unlock) or fail their checks are
    /// answered and skipped.
    pub fn show_next_approval(&mut self) {
        self.show_next_approval_with(None);
    }

    /// [`Self::show_next_approval`] for a caller with steps after it (2026-11-20, S4 P9): `after`
    /// runs once the window's open is answered, or at once when none is asked for ([`AfterOpen`]).
    /// Before, the caller ran them after this call returned.
    pub(crate) fn show_next_approval_then(&mut self, after: AfterOpen) {
        self.show_next_approval_with(Some(after));
    }

    /// The body of [`Self::show_next_approval`]; `after` runs at every return that asked for no
    /// window (where the caller went on before, 2026-11-20 S4 P9), or goes with the open.
    fn show_next_approval_with(&mut self, after: Option<AfterOpen>) {
        if self.evm.approval.is_some()
            || !matches!(self.mode, crate::wallet::AppMode::Unlocked { .. })
        {
            if self.mode == crate::wallet::AppMode::BackupPending {
                let finished = self.evm.queue.drain_waiting_matching(
                    |item| matches!(item, QueuedItem::Site(_)),
                    QueueOutcome::NotReady,
                );
                for (item, outcome) in finished {
                    self.approval_finished(&item.payload, outcome);
                }
            }
            self.refresh();
            self.run_after_open(after);
            return;
        }
        if self.sol_connect_waits_for_account() {
            // Moves again when the account arrives (`KeyOutcome::SolKeys`).
            self.refresh();
            self.run_after_open(after);
            return;
        }
        loop {
            let now = self.clock.now_ms();
            let mut finished = Vec::new();
            let shown = self.evm.queue.show_next(now, &mut finished);
            for (item, outcome) in finished {
                self.approval_finished(&item.payload, outcome);
            }
            if shown.is_none() {
                self.refresh();
                self.run_after_open(after);
                return;
            }
            let Some(item) = self.evm.queue.shown().map(|shown| shown.payload.clone()) else {
                self.run_after_open(after);
                return;
            };
            if let QueuedItem::Site(site) = &item
                && let Some(outcome) = self.site_preflight(site)
            {
                if let Some((done, outcome)) = self.evm.queue.finish_shown(outcome) {
                    self.approval_finished(&done.payload, outcome);
                }
                continue;
            }
            // 2026-11-19 (S4 B5): the open's answer (`on_approval_opened`) starts the
            // preparation or rejects the item with E-APP-009 (was here, on `open_approval`'s
            // result). 2026-11-20 (S4 P9): `after` goes with the open.
            self.open_approval(item, after);
            return;
        }
    }

    /// Runs a caller's steps after an open ([`AfterOpen`]; 2026-11-20, S4 P9). `None`: nothing.
    /// 2026-11-20 (S4 P10a): the steps of P10a's [`AfterOpen`] variants are the code that ran
    /// after the call before, moved here unchanged (with its later steps after a further call that
    /// may open handed on through [`Self::after_pending_open`] in turn).
    fn run_after_open(&mut self, after: Option<AfterOpen>) {
        match after {
            None | Some(AfterOpen::RefreshUnlessActed(true)) => {}
            Some(AfterOpen::CardSiteCheck) => {
                self.card_site_check();
            }
            Some(AfterOpen::CardSiteCheckThenRefresh) => {
                self.card_site_check();
                self.refresh();
            }
            Some(AfterOpen::BtcRest(rest)) => self.btc_apply_rest(rest),
            // The first step, then the others after the answer of an open it asked for.
            Some(AfterOpen::Steps(steps)) => {
                let mut steps = steps.into_iter();
                if let Some(first) = steps.next() {
                    let rest: Vec<AfterOpen> = steps.collect();
                    self.after_pending_open(first);
                    self.after_pending_open(AfterOpen::Steps(rest));
                }
            }
            Some(AfterOpen::Refresh | AfterOpen::RefreshUnlessActed(false)) => self.refresh(),
            Some(AfterOpen::SetScreen(screen)) => self.set_screen(screen),
            Some(AfterOpen::HiddenNote(label)) => {
                self.notice(
                    crate::wallet::app_hidden::hidden_note(self.settings.language, &label),
                    crate::screen::Tone::Info,
                );
                self.refresh();
            }
            Some(AfterOpen::WriteGrantsThenRefresh) => {
                self.write_grants();
                self.refresh();
            }
            Some(AfterOpen::Finish(outcome)) => self.finish_approval(outcome),
            Some(AfterOpen::CloseIfShown(shown)) => self.close_if_shown(shown),
            Some(AfterOpen::StartPrepare) => self.start_prepare(),
            Some(AfterOpen::RebuildView) => self.rebuild_view(),
            Some(AfterOpen::AiReadyTx) => self.ai_ready_tx(),
            Some(AfterOpen::AiReadyMessage) => self.ai_ready_message(),
            Some(AfterOpen::AiReadyTyped(facts)) => self.ai_ready_typed(&facts),
            Some(AfterOpen::AfterMeta) => {
                if self.evm.journal.is_none() {
                    self.evm_after_unlock();
                }
                self.btc_after_meta();
                self.after_pending_open(AfterOpen::AfterBtcMeta);
            }
            Some(AfterOpen::AfterBtcMeta) => {
                self.zec_ensure_account();
                self.card_after_meta();
            }
            Some(AfterOpen::EvmTickRest(now)) => self.evm_tick_rest(now),
            Some(AfterOpen::ZecSnapshot(network, snapshot)) => {
                self.zec.snapshot = Some((network, snapshot));
                self.refresh();
            }
            Some(AfterOpen::BtcOpenTab) => self.btc_open_tab_if_idle(),
            Some(AfterOpen::BtcReceiveScreen) => self.btc_receive_shown(),
            Some(AfterOpen::BtcDropStaleTyped(bump)) => self.btc_drop_stale_typed(bump),
            Some(AfterOpen::EsploraField {
                net,
                field,
                saved_only,
            }) => self.esplora_field_shows(net, field, saved_only),
        }
    }

    /// The close box's end of its own request ([`AfterOpen::CloseIfShown`]; 2026-11-20, S4
    /// P10a: was inline in `on_approval_input`): `finish_approval(Rejected)` when window `shown`
    /// is still the shown one (S4 F1, L-1).
    fn close_if_shown(&mut self, shown: ShownId) {
        if self.shown_now() == Some(shown) {
            self.finish_approval(QueueOutcome::Rejected);
        }
    }

    /// S12 Bitcoin unless it or an overlay shows ([`AfterOpen::BtcReceiveScreen`]; 2026-11-20,
    /// S4 P10a: was inline in `on_btc`).
    fn btc_receive_shown(&mut self) {
        if !matches!(
            self.screen,
            crate::wallet::Screen::BtcReceive | crate::wallet::Screen::Confirm(_)
        ) {
            self.set_screen(crate::wallet::Screen::BtcReceive);
        }
    }

    /// The Esplora URL edit of `net` shows the stored URL; with `saved_only` only when the save
    /// left no settings message ([`AfterOpen::EsploraField`]; 2026-11-20, S4 P10a: was inline in
    /// `on_btc_esplora`).
    fn esplora_field_shows(
        &mut self,
        net: yw_core::btc::BtcNetwork,
        field: crate::form::EditField,
        saved_only: bool,
    ) {
        if !saved_only || self.btc.settings_message.is_none() {
            let saved = self.btc_ctx().esplora_text(net).to_owned();
            self.emit(Effect::SetField { field, text: saved });
        }
    }

    /// Runs `after` once the newest approval-window open still waiting for its answer
    /// (`EvmUi::open_unanswered`) is answered, after the steps kept for it before; at once when
    /// none waits (2026-11-20, S4 P10a, plan §4.4 S5, §4.6 rule 2). 2026-11-20 (S4 P10b): an
    /// open waits in the outbox until its entry drains, so `after` follows the answer, as it
    /// followed the open before. 2026-11-21 (S4 F14, owner decision, spec/04 §5.3): a lock
    /// before that answer drops `after` (`Wallet::lock_steps`, at the `lock_epoch` bump; 2026-11-21,
    /// S4 W3a: before, `App::lock`); from P10b until F14 it ran after the lock
    /// (pinned then by `a_step_kept_for_an_open_runs_after_a_lock_in_the_same_entry`).
    /// Before P10b the executor applied effects at once, an open was answered before `emit`
    /// returned, and `after` always ran here, where the caller ran it before.
    pub(crate) fn after_pending_open(&mut self, after: AfterOpen) {
        // No steps (an answer whose opener left none) is nothing to keep.
        if matches!(&after, AfterOpen::Steps(steps) if steps.is_empty()) {
            return;
        }
        match self.evm.open_unanswered {
            Some(shown) => self.evm.after_open.push((shown, after)),
            None => self.run_after_open(Some(after)),
        }
    }

    /// The answer to the open of window `shown` arrived (`Cmd::ApprovalOpened`; 2026-11-20, S4
    /// P10a): no longer waiting (unless a later open waits), and the steps its opener left for
    /// then, in the order they were kept. Before P10a, `after_approval_opened` took the one kept
    /// step after `on_approval_opened` returned (2026-11-20, S4 P9); the steps are taken first now
    /// so that what runs after the answer's own steps is a single [`Wallet::after_pending_open`]. An
    /// answer for a window whose flow has gone (stale) runs them too: they belong to the opener,
    /// not to the window. 2026-11-21 (S4 F14): except after a lock, which dropped them, so the
    /// stale answer of an open from before a lock finds none.
    pub(crate) fn approval_open_answered(&mut self, shown: ShownId) -> AfterOpen {
        if self.evm.open_unanswered == Some(shown) {
            self.evm.open_unanswered = None;
        }
        let mut steps = Vec::new();
        let mut kept = Vec::new();
        for (id, after) in core::mem::take(&mut self.evm.after_open) {
            if id == shown {
                steps.push(after);
            } else {
                kept.push((id, after));
            }
        }
        self.evm.after_open = kept;
        AfterOpen::Steps(steps)
    }

    pub(crate) fn connect_state(&self, site: &SiteRequest) -> ConnectState {
        let family = site.kind.family();
        if family != yw_core::policy::Family::Evm {
            let (accounts, selected, chain_name) = self.chain_connect_choices(site);
            let groups = match &site.kind {
                SiteKind::BtcConnect(purposes) => u8::try_from(purposes.len()).unwrap_or(1),
                _ => 1,
            };
            return ConnectState {
                accounts,
                selected,
                chain_name,
                chain_id: site.chain_id,
                family,
                groups,
            };
        }
        let granted: Vec<yw_core::evm::address::Address> = self
            .browser_grants()
            .into_iter()
            .find(|grant| grant.origin == site.origin)
            .map(|grant| grant.accounts)
            .unwrap_or_default();
        let accounts = self.own_account_rows();
        // An account whose recovery phrase is not backed up can receive but not sign (spec/02
        // §8.6), nor can a YubiKey key on a card still at its factory PINs (spec/10 §9.3): its
        // row says so, and it is not the default of a new site while another is.
        let unconfirmed: Vec<Option<yw_core::vault::RecordId>> = accounts
            .iter()
            .map(|(address, ..)| self.evm_account_unconfirmed(address))
            .collect();
        let factory: Vec<Option<u32>> = accounts
            .iter()
            .map(|(address, ..)| self.evm_account_card_gate(address))
            .collect();
        let can_sign = |index: usize| {
            unconfirmed.get(index).is_some_and(Option::is_none)
                && factory.get(index).is_some_and(Option::is_none)
        };
        // A new site starts with the account chosen on the main screen (2026-11-08; account 0
        // before), so the user picks deliberately; the window is still approved explicitly.
        let current = self.selected_account().and_then(|(current, ..)| {
            accounts
                .iter()
                .position(|(address, ..)| *address == current)
        });
        let first = current
            .filter(|index| can_sign(*index))
            .or_else(|| (0..accounts.len()).find(|index| can_sign(*index)))
            .or(current)
            .unwrap_or(0);
        let selected = accounts
            .iter()
            .enumerate()
            .map(|(index, (address, ..))| {
                if granted.is_empty() {
                    index == first
                } else {
                    granted.contains(address)
                }
            })
            .collect();
        ConnectState {
            // Each row: the name (and why it cannot sign), a muted line with its source and
            // path, then the address — the Solana window's shape (2026-11-10).
            accounts: accounts
                .into_iter()
                .zip(unconfirmed.into_iter().zip(factory))
                .map(|((address, label, path), (phrase, serial))| {
                    (
                        crate::wallet::app_chain_sites::ConnectChoice::Evm(address),
                        format!(
                            "{label}{}{}\n{path}",
                            self.mn_connect_tag(phrase),
                            self.card_connect_tag(serial)
                        ),
                        address.to_checksum(),
                        0,
                    )
                })
                .collect(),
            selected,
            chain_name: self.evm_chain_label(self.connect_origin_chain(site)),
            chain_id: self.connect_origin_chain(site),
            family,
            groups: 1,
        }
    }

    /// The origin's chain now (spec/05 §4.3), or the request's without a dispatcher.
    fn connect_origin_chain(&self, site: &SiteRequest) -> u64 {
        self.browser.as_ref().map_or(site.chain_id, |browser| {
            browser.core.origin_chain(&site.origin)
        })
    }

    fn evm_chain_label(&self, chain_id: u64) -> String {
        self.settings
            .evm_chain_name_in(self.approval_lang(), chain_id)
            .unwrap_or_else(|| format!("chainId {chain_id}"))
    }

    /// Security review L4(c): an open EVM connect window shows the origin's chain of now (a
    /// window-less `wallet_switchEthereumChain` may have changed it). Returns whether it changed.
    fn refresh_connect_chain(&mut self) -> bool {
        let Some(site) =
            self.evm
                .approval
                .as_ref()
                .and_then(|flow| match (flow.item(), flow.connect()) {
                    (QueuedItem::Site(site), Some(connect))
                        if connect.family == yw_core::policy::Family::Evm =>
                    {
                        Some(site.clone())
                    }
                    _ => None,
                })
        else {
            return false;
        };
        let chain_id = self.connect_origin_chain(&site);
        let name = self.evm_chain_label(chain_id);
        self.evm
            .approval
            .as_mut()
            .is_some_and(|flow| flow.set_connect_chain(chain_id, name))
    }

    /// Opens the approval window for `item` (the wallet half; 2026-11-19, S4 B5, plan §3.1): the
    /// flow is made at `now` and becomes `EvmUi.approval`, then the window is asked for with
    /// `Effect::Approval(Open)`, which the executor applies at once (`open_approval_window`) and
    /// answers with `Cmd::ApprovalOpened` (`on_approval_opened`: the AI explanation, the first
    /// view, then `start_prepare`; a refused open rejects the item with E-APP-009). Before B5 this
    /// function made the window, its panel and AI body, then the flow, centred, showed and focused
    /// the window, and `show_next_approval` called `start_prepare` or rejected on its `Err`. The
    /// flow is pure: making it before the window changes no message, Win32 call or clock read
    /// (its only error, a clock past `u64::MAX - 120 000` ms, cannot happen; it would reject
    /// before a window was made instead of after the made windows were dropped unshown).
    ///
    /// 2026-11-20 (S4 P9): `after` (the opener's later steps) is kept for the open's answer
    /// (`after_approval_opened`; since P10a `approval_open_answered`), or run at once when no
    /// window is asked for.
    fn open_approval(&mut self, item: QueuedItem, after: Option<AfterOpen>) {
        let now = self.clock.now_ms();
        let connect = match &item {
            QueuedItem::Site(site) if site.kind.is_connect() => Some(self.connect_state(site)),
            _ => None,
        };
        let lang = self.settings.language;
        // spec/06 §3.1: dApp transactions, personal_sign and typed data, only while the worker
        // exists (feature effectively on). The panel's height is reserved now (§6). 2026-11-19
        // (S4 B5 review): decided here once, with the endpoint's host and model of now, and kept
        // in the flow until the open's answer attaches it (the answer worked the condition out
        // again before).
        let ai_reserved = explain_kind(&item)
            .zip(self.llm.as_ref())
            .map(|(kind, service)| AiReserved {
                kind,
                host: service.host().to_owned(),
                model: service.model().to_owned(),
            });
        let reserve_ai = ai_reserved.is_some();
        let shown = self.evm.shown_id();
        let is_connect = connect.is_some();
        // 2026-11-19 (S4 B3): the deadline rule is `yw_engine::approval::flow::session_deadline`
        // (was inline here: the site deadline, else `now + MAX_LIFETIME_MS`, at least `now + 1`).
        // 2026-11-19 (S4 B4a): `ApprovalFlow::open` builds the gate and its session (was inline
        // here: the same gate, the same `now`).
        let Ok(flow) = ApprovalFlow::open(shown, lang, item, connect, ai_reserved, now) else {
            self.approval_open_failed();
            self.run_after_open(after);
            return;
        };
        self.evm.approval = Some(flow);
        if let Some(after) = after {
            self.evm.after_open.push((shown, after));
        }
        // 2026-11-20 (S4 P10a): waiting for its answer until `Cmd::ApprovalOpened` arrives
        // (`Wallet::approval_open_answered`). 2026-11-20 (S4 P10b): the open is queued, so this
        // waits until the entry drains; before, applied at once, the answer cleared it before
        // `emit` returned.
        self.evm.open_unanswered = Some(shown);
        self.emit(Effect::Approval(ApprovalEffect::Open {
            shown,
            lang,
            ai_reserved: reserve_ai,
            connect: is_connect,
        }));
    }

    /// The answer to `Effect::Approval(Open)` (S4 B5). Made: the AI explanation reserved when the
    /// flow opened joins it (the open asked for the AI body iff one was reserved), the flow takes
    /// the window's width class, then the open's log, the first view and the preparation, in the
    /// order of the code before B5. Not made: the flow ends (its `Close` finds no window and does
    /// nothing, critique A-3) and the item is rejected with E-APP-009, as `show_next_approval` did
    /// on `open_approval`'s `Err`. An answer for a window that is not the flow's is dropped; when
    /// that window was made, it is closed (2026-11-19, S4 B5 review, critique A-3: before, it was
    /// left without a flow; unreachable while effects were applied at once). 2026-11-20 (S4
    /// P10b): a stale answer is reachable now (a flow ended in the entry that queued its open);
    /// the stale open made no window (`open_approval_window`), so its `Failed` answer is dropped.
    pub(crate) fn on_approval_opened(&mut self, shown: ShownId, outcome: OpenOutcome, wide: bool) {
        if self.evm.approval.as_ref().map(ApprovalFlow::shown) != Some(shown) {
            if matches!(outcome, OpenOutcome::Shown { .. }) {
                self.emit(Effect::Approval(ApprovalEffect::Close { shown }));
            }
            return;
        }
        match outcome {
            OpenOutcome::Shown { .. } => {
                if let Some(flow) = self.evm.approval.as_mut() {
                    // 2026-11-19 (S4 B4b): the AI panel's state is the flow's `AiFlow`, its body
                    // child and scroll the shell's `AiBody`, made in the open in the same order.
                    // 2026-11-19 (S4 B5 review): attached from the reservation made at the open
                    // (was `explain_kind(item)` and the endpoint read again here).
                    if let Some(reserved) = flow.take_ai_reserved() {
                        self.llm_ui.next_window = self.llm_ui.next_window.saturating_add(1);
                        flow.attach_ai(AiFlow {
                            panel: AiPanel::new(true, flow.lang()),
                            serial: self.llm_ui.next_window,
                            host: reserved.host,
                            model: reserved.model,
                            kind: reserved.kind,
                        });
                    }
                    flow.set_wide(wide);
                }
                logging::info("app", "approval.open", &[]);
                self.rebuild_view();
                // 2026-11-22 (S4 W14a, preflight critic C5): the test builds' pairing check of the
                // flow and its window (`assert_flow_and_window_in_step`, the shell's) is no longer
                // made here; `App::drain` makes it once the queue is empty. Here it never asserted
                // (but the headless host's "no window", which the drain's check asserts too):
                // `rebuild_view` always queues an effect while the flow exists (`Rebuilt`, or the
                // rejection's `Close`), and the check returns while an effect is queued.
                // 2026-11-20 (S4 P10a): after the answer of an open the view's failure asked for
                // (`AfterOpen::StartPrepare`; before, called here directly).
                self.after_pending_open(AfterOpen::StartPrepare);
            }
            OpenOutcome::Refused(_) | OpenOutcome::Failed(_) => {
                if let Some(flow) = self.evm.approval.take() {
                    self.emit(Effect::Approval(ApprovalEffect::Close {
                        shown: flow.shown(),
                    }));
                }
                self.approval_open_failed();
            }
        }
    }

    /// The shown item could not get its window: rejected, E-APP-009 (`show_next_approval`'s
    /// open-failure branch before S4 B5).
    fn approval_open_failed(&mut self) {
        if let Some((item, outcome)) = self.evm.queue.finish_shown(QueueOutcome::Rejected) {
            self.approval_finished(&item.payload, outcome);
        }
        self.error_banner(ErrorCode::App009);
    }

    fn start_prepare(&mut self) {
        let job = self.evm.job();
        let Some(flow) = self.evm.approval.as_mut() else {
            return;
        };
        let item = flow.item().clone();
        flow.begin_prepare(job, self.clock.now_ms());
        match item {
            QueuedItem::App(app) => self.prepare_transaction(job, &app, None),
            QueuedItem::Site(site) => self.prepare_site(job, &site),
            QueuedItem::Sol(sol) => self.prepare_sol(job, &sol),
            QueuedItem::Btc(btc) => self.prepare_btc(&btc),
            QueuedItem::Zec(zec) => self.prepare_zec(&zec),
            QueuedItem::HyperCore(item) => self.prepare_hypercore(&item),
        }
        // 2026-11-20 (S4 P10a): after the answer of an open a failed preparation asked for
        // (`AfterOpen::RebuildView`; before, called here directly).
        self.after_pending_open(AfterOpen::RebuildView);
    }

    /// Steps 3–10 of spec/03 §3.7 on the RPC worker, for an app send or a dApp transaction.
    fn prepare_transaction(&mut self, job: u64, item: &AppApproval, site: Option<&SiteRequest>) {
        // The journal did not open and its choice was closed: one fixed reason, not the
        // `공간이 부족합니다` an absent journal's room would otherwise end with.
        if self.evm.journal.is_none() && self.sidecar.journal_closed {
            self.show_failure(
                ErrorCode::Vlt006,
                false,
                crate::wallet::app_sidecar::text::JOURNAL_CLOSED_SEND
                    .get(self.approval_lang())
                    .to_owned(),
            );
            return;
        }
        let records = self.evm.records().to_vec();
        let room = self
            .evm
            .journal
            .as_ref()
            .is_some_and(|journal| journal.room);
        let chain = match self.chain_job(item.chain_id) {
            Ok(chain) => chain,
            Err(code) => {
                let failure =
                    crate::flow::evm::prepare::PrepareFailure::no_endpoint(self.approval_lang());
                let message = failure.message(self.approval_lang());
                self.show_failure(code, false, message);
                return;
            }
        };
        let Ok(id) = Self::new_approval_id() else {
            self.show_failure(
                ErrorCode::Vlt005,
                false,
                ErrorCode::Vlt005.text_in(self.approval_lang()),
            );
            return;
        };
        let address_book = self.address_book_facts();
        let (origin, extra_warnings) = match site {
            Some(site) => (
                self.site_approval_origin(site),
                site_fee_warning(self.approval_lang(), site),
            ),
            None => (yw_core::approval::ApprovalOrigin::App, Vec::new()),
        };
        let lang = self.approval_lang();
        let sent = self.rpc(RpcJob::Prepare(Box::new(PrepareJob {
            job,
            lang,
            chain,
            id,
            origin,
            account: item.account,
            signer: item.signer,
            intent: item.intent.clone(),
            replace: item.replace.clone(),
            records,
            journal_room: room,
            address_book,
            own_accounts: self.own_accounts(),
            known: self.known_addresses(),
            extra_warnings,
            limits: Limits::PRODUCTION,
        })));
        if !sent {
            self.show_failure(
                ErrorCode::Rpc001,
                true,
                ErrorCode::Rpc001.text_in(self.approval_lang()),
            );
        }
    }

    /// The dApp items: connect window content, transaction preparation, message drafts.
    #[expect(clippy::too_many_lines, reason = "one arm per dApp request kind")]
    fn prepare_site(&mut self, job: u64, site: &SiteRequest) {
        let now = self.clock.now_ms();
        match &site.kind {
            SiteKind::RequestAccounts
            | SiteKind::RequestPermissions
            | SiteKind::SolConnect
            | SiteKind::BtcConnect(_) => {
                self.evm.queue.mark_ready(now);
                let deadline = self
                    .evm
                    .queue
                    .shown_deadline()
                    .unwrap_or(now.saturating_add(120_000));
                if let Some(flow) = self.evm.approval.as_mut() {
                    flow.connect_ready(deadline, now);
                }
            }
            SiteKind::Send(tx) => {
                let Some(signer) = self.account_source(&tx.from) else {
                    self.show_failure(
                        ErrorCode::App009,
                        false,
                        ErrorCode::App009.text_in(self.approval_lang()),
                    );
                    return;
                };
                let item = AppApproval {
                    chain_id: site.chain_id,
                    account: tx.from,
                    signer,
                    intent: crate::flow::evm::prepare::SendIntent {
                        to: tx.to,
                        value: tx.value,
                        data: tx.data.clone(),
                        access_list: tx.access_list.clone(),
                        dapp_gas: tx.gas,
                        dapp_nonce: tx.nonce,
                    },
                    replace: None,
                };
                self.prepare_transaction(job, &item, Some(site));
            }
            SiteKind::PersonalSign { .. } | SiteKind::TypedData { .. }
                if self.message_chain_failure(site.chain_id).is_some() =>
            {
                // L12: a chain known to answer for another chain blocks signatures too (E34).
                if let Some(failure) = self.message_chain_failure(site.chain_id) {
                    self.show_failure(failure.code, false, failure.message(self.approval_lang()));
                }
            }
            SiteKind::PersonalSign { account, message } => {
                let decoded = yw_core::evm::eip191::decode_personal_message(message.clone());
                let draft = self.message_chain(site.chain_id).and_then(|chain| {
                    let signer = self.account_source(account)?;
                    let id = Self::new_approval_id().ok()?;
                    yw_core::evm::display::build_personal_request(
                        self.approval_lang(),
                        id,
                        self.site_approval_origin(site),
                        signer,
                        *account,
                        yw_core::approval::ApprovalKind::EvmPersonalSign,
                        &chain,
                        &decoded,
                        self.clock.now_unix_ms(),
                    )
                    .ok()
                });
                match draft {
                    Some(draft) => {
                        self.show_ready_draft(draft, None);
                        // 2026-11-20 (S4 P10a): after the answer of an open a failed issue asked
                        // for (`AfterOpen::AiReadyMessage`; before, called here directly).
                        self.after_pending_open(AfterOpen::AiReadyMessage);
                    }
                    None => self.show_failure(
                        ErrorCode::App009,
                        false,
                        ErrorCode::App009.text_in(self.approval_lang()),
                    ),
                }
            }
            SiteKind::TypedData {
                account,
                source,
                value,
            } => {
                let l1_origin = Self::hl_l1_origin(site);
                let requester = l1_origin.as_deref().map_or(
                    yw_core::evm::eip712::HlL1Requester::Nobody,
                    yw_core::evm::eip712::HlL1Requester::Origin,
                );
                let Ok(typed) = yw_core::evm::eip712::validate_typed_data_v4_from(
                    source,
                    value,
                    site.chain_id,
                    requester,
                ) else {
                    self.respond(
                        &site.reply,
                        Err(yw_core::policy::ProviderError::InvalidParams),
                    );
                    self.finish_approval(QueueOutcome::Cancelled);
                    return;
                };
                let typed = Box::new(typed);
                if let Some(flow) = self.evm.approval.as_mut() {
                    flow.set_typed(typed.clone());
                }
                // Without the lookups (no endpoint, no worker) the spender counts as a failed
                // lookup (`Unknown`, T18, fail closed).
                let mut unlooked = yw_core::approval::ChainFacts {
                    address_book: self.address_book_facts(),
                    own_accounts: self.own_accounts(),
                    ..yw_core::approval::ChainFacts::default()
                };
                if let Some(info) = crate::flow::evm::chain_info(&self.settings, site.chain_id) {
                    crate::flow::evm::prepare::typed_spender_unknown_unless_classified(
                        &mut unlooked,
                        &info,
                        &typed,
                    );
                }
                if let Ok(chain) = self.chain_job(site.chain_id) {
                    let sent = self.rpc(RpcJob::TypedFacts {
                        job,
                        chain,
                        account: *account,
                        typed,
                        address_book: unlooked.address_book.clone(),
                        own_accounts: unlooked.own_accounts.clone(),
                    });
                    if !sent {
                        self.on_typed_facts(job, &unlooked, None);
                    }
                } else {
                    self.on_typed_facts(job, &unlooked, None);
                }
            }
            SiteKind::SolTx { .. } => self.prepare_sol_dapp(job, site),
            SiteKind::SolSign { .. } | SiteKind::BtcSign { .. } => {
                match self.chain_sign_draft(site) {
                    Some(draft) => self.show_ready_draft(draft, None),
                    None => self.show_failure(
                        ErrorCode::App009,
                        false,
                        ErrorCode::App009.text_in(self.approval_lang()),
                    ),
                }
            }
            SiteKind::Revoke => self.finish_approval(QueueOutcome::Cancelled),
        }
    }

    /// spec/03 §1.4 (security review L12): message signatures (`personal_sign`,
    /// `eth_signTypedData_v4`) on a chain whose last check found `RpcMismatch` are blocked with
    /// E34 like a send. No RPC is called for a message, so only a known mismatch blocks.
    pub(crate) fn message_chain_failure(
        &self,
        chain_id: u64,
    ) -> Option<crate::flow::evm::prepare::PrepareFailure> {
        let lang = self.approval_lang();
        self.evm
            .blocked(chain_id)
            .map(|kind| crate::flow::evm::prepare::PrepareFailure::chain_mismatch(lang, kind))
    }

    /// The language of the open approval window (the app language before it opens): every
    /// display, warning and failure of its request is built in it (spec/14 §2).
    pub fn approval_lang(&self) -> Lang {
        self.evm
            .approval
            .as_ref()
            .map_or(self.settings.language, ApprovalFlow::lang)
    }

    /// The chain of a message signature: the registered definition with the verified genesis
    /// when known (the approval binds the chain, spec/03 §11.1).
    fn message_chain(&self, chain_id: u64) -> Option<yw_core::evm::chain::ChainInfo> {
        let info = crate::flow::evm::chain_info(&self.settings, chain_id)?;
        Some(match self.evm.chain_checks.get(&chain_id) {
            Some(crate::flow::evm::ChainCheck::Verified { genesis, .. }) => {
                crate::flow::evm::with_genesis(&info, *genesis)
            }
            _ => info,
        })
    }

    /// Typed-data facts arrived: build the draft (spec/03 §8). `check` is the chain check the
    /// lookups were made under (`None` without lookups): a chain found to answer for another
    /// chain — now or before — blocks with E34 like a send (spec/03 §1.4, L12).
    pub fn on_typed_facts(
        &mut self,
        job: u64,
        facts: &yw_core::approval::ChainFacts,
        check: Option<crate::flow::evm::ChainCheck>,
    ) {
        let Some(flow) = self.evm.approval.as_ref() else {
            return;
        };
        if flow.job() != job {
            return;
        }
        let (QueuedItem::Site(site), Some(typed)) =
            (flow.item().clone(), flow.typed().cloned().map(Box::new))
        else {
            return;
        };
        let SiteKind::TypedData { account, .. } = &site.kind else {
            return;
        };
        let mismatch = match check {
            Some(crate::flow::evm::ChainCheck::Mismatch(kind)) => {
                Some(crate::flow::evm::prepare::PrepareFailure::chain_mismatch(
                    self.approval_lang(),
                    kind,
                ))
            }
            _ => self.message_chain_failure(site.chain_id),
        };
        if let Some(failure) = mismatch {
            self.show_failure(failure.code, false, failure.message(self.approval_lang()));
            return;
        }
        // A Hyperliquid transfer gets the S-HC recipient and spotMeta checks (spec/11 §7); a
        // verified book entry's row says so (`✓ 확인됨`).
        let mut facts = facts.clone();
        facts.hyperliquid = self.hl_site_facts(&typed, account);
        facts.known = self.known_addresses();
        let draft = self.message_chain(site.chain_id).and_then(|chain| {
            let signer = self.account_source(account)?;
            let id = Self::new_approval_id().ok()?;
            yw_core::evm::display::build_typed_request(
                self.approval_lang(),
                id,
                self.site_approval_origin(&site),
                signer,
                *account,
                yw_core::approval::ApprovalKind::EvmTypedData,
                &chain,
                &typed,
                &facts,
                self.clock.now_unix_ms(),
            )
            .ok()
        });
        match draft {
            Some(draft) => {
                let facts = Box::new(facts);
                self.show_ready_draft(draft, None);
                // 2026-11-20 (S4 P10a): after the answer of an open a failed issue asked for
                // (`AfterOpen::AiReadyTyped`, with the facts; before, called here directly).
                self.after_pending_open(AfterOpen::AiReadyTyped(facts));
            }
            None => self.show_failure(
                ErrorCode::App009,
                false,
                ErrorCode::App009.text_in(self.approval_lang()),
            ),
        }
    }

    pub(crate) fn show_failure(&mut self, code: ErrorCode, retryable: bool, text: String) {
        if let Some(flow) = self.evm.approval.as_mut() {
            flow.fail(text, code, retryable, self.clock.now_ms());
        }
        self.ai_ready(AiReady::Skip(SKIP_FAILED.get(self.approval_lang())));
        self.rebuild_view();
    }

    /// Closes the window without queue bookkeeping; a still-pending issued approval is rejected
    /// (it can never be consumed without its window).
    pub fn close_approval_window(&mut self) {
        // 2026-11-18 (S4 A7, critique A-2): the secret characterization's lock order.
        // 2026-11-20 (S4 P10b): logged after the effects queued before it are applied
        // (`secret_seam::log_after`), where the shell closes this window too.
        // 2026-11-23 (S4d E0b, preflight O-4): a probe note with the queued count, which the
        // tests' secret seam logs that way (before, a `cfg(test)` call of that seam).
        crate::probe::note(crate::probe::Probe::ApprovalClose {
            shown: self.evm.approval.is_some(),
            queued: self.outbox.len(),
        });
        // 2026-11-19 (S4 B4b): the flow and the shell state are taken together; the steps keep
        // their order (reject, AI close and its log, AI body, timer, panel, window).
        // 2026-11-19 (S4 B5): the flow ends here (reject, AI close and its log) and emits
        // `Effect::Approval(Close)`, whose executor arm (`close_approval_shell`) then drops the AI
        // body, stops the timer, destroys the panel and the window and raises the main window, in
        // that order (were inline here).
        if let Some(mut flow) = self.evm.approval.take() {
            if let Some(request) = flow.issued() {
                self.evm.store.reject(request.id);
            }
            // spec/06 §3.2: a result arriving after the window closed is dropped.
            if let Some(mut ai) = flow.take_ai()
                && let Some(ended) = ai.panel.close(self.clock.now_ms())
            {
                log_request(&ai.host, ai.kind, &ended, None);
            }
            self.emit(Effect::Approval(ApprovalEffect::Close {
                shown: flow.shown(),
            }));
        }
        // 2026-11-22 (S4 W14a, preflight critic C5): the test builds' pairing check
        // (`assert_flow_and_window_in_step`, the shell's) is no longer made here but only by
        // `App::drain` once the queue is empty. Here it asserted only when no flow was shown (a
        // flow's end queues its `Close` first, and the check returns while an effect is queued),
        // and then the window it checks was last changed by the drain that already checked it.
    }

    /// The approval window shown now, by its `ShownId` (`None`: none). An input of another window
    /// is dropped, and the later steps of one window message apply only while the window that got
    /// it is still the shown one: an earlier step of the same message may have ended its request
    /// and opened the next request's window (`finish_approval` → `show_next_approval`).
    /// (2026-11-19, S4 B6, critique A-12: the F1 guard is this id check; S4 F1 compared the queue
    /// item shown when the message arrived, `shown_window()`.)
    pub fn shown_now(&self) -> Option<ShownId> {
        self.evm.approval.as_ref().map(ApprovalFlow::shown)
    }

    pub(crate) fn finish_approval(&mut self, outcome: QueueOutcome) {
        let id = self
            .evm
            .approval
            .as_ref()
            .and_then(|flow| flow.issued().map(|request| request.id));
        if let Some(id) = id
            && outcome != QueueOutcome::Approved
        {
            self.evm.store.reject(id);
        }
        self.close_approval_window();
        if let Some((item, outcome)) = self.evm.queue.finish_shown(outcome) {
            self.approval_finished(&item.payload, outcome);
        }
        self.show_next_approval();
    }

    // ----- pipeline events ----------------------------------------------------------------

    /// `eth_simulateV1` started.
    pub fn on_simulating(&mut self, job: u64, since_ms: u64) {
        if let Some(flow) = self.evm.approval.as_mut()
            && flow.job() == job
        {
            flow.simulating(since_ms, self.clock.now_ms());
            self.rebuild_view();
        }
    }

    /// Preparation finished: issue at first Ready display (spec/03 §11.5).
    pub fn on_prepared(&mut self, result: PrepareResult) {
        self.apply_transitions(result.transitions.clone());
        let matches = self
            .evm
            .approval
            .as_ref()
            .is_some_and(|flow| flow.job() == result.job);
        if !matches {
            return;
        }
        match result.outcome {
            PrepareOutcome::Failed(failure) => {
                logging::warn(
                    "app",
                    "prepare.failed",
                    &[("code", Field::Code(failure.code))],
                );
                let site = self
                    .evm
                    .approval
                    .as_ref()
                    .and_then(|flow| match flow.item() {
                        QueuedItem::Site(site) => Some(site.reply),
                        QueuedItem::App(_)
                        | QueuedItem::Sol(_)
                        | QueuedItem::Btc(_)
                        | QueuedItem::Zec(_)
                        | QueuedItem::HyperCore(_) => None,
                    });
                if failure.invalid_params
                    && let Some(reply) = site
                {
                    // spec/03 §3.2: the dApp nonce differs — -32602 naming the rule (spec/05 §5
                    // `InvalidTxParams`), no failure window.
                    self.respond(
                        &reply,
                        Err(yw_core::policy::ProviderError::InvalidTxParams(
                            yw_core::policy::TxRule::Nonce,
                        )),
                    );
                    self.finish_approval(QueueOutcome::Cancelled);
                    return;
                }
                let text = failure.message(self.approval_lang());
                self.show_failure(failure.code, failure.retryable, text);
            }
            PrepareOutcome::Ready(prepared) => {
                if prepared.native_emitter_mismatch {
                    logging::info("app", "native-emitter-mismatch", &[]);
                }
                let draft = prepared.draft.clone();
                self.show_ready_draft(draft, Some(prepared));
                // 2026-11-20 (S4 P10a): after the answer of an open a failed issue asked for
                // (`AfterOpen::AiReadyTx`; before, called here directly).
                self.after_pending_open(AfterOpen::AiReadyTx);
            }
        }
    }

    /// Issues a draft at its first Ready display (spec/03 §11.5). Transactions keep their
    /// preparation (signing, journal, re-simulation); messages have none.
    pub(crate) fn show_ready_draft(
        &mut self,
        draft: yw_core::approval::ApprovalDraft,
        prepared: Option<Box<Prepared>>,
    ) {
        self.show_ready_draft_at(draft, prepared, self.clock.now_unix_ms());
    }

    /// [`Self::show_ready_draft`] with the wall-clock display time given (the SOL intent binds
    /// it as `created_at_ms`, spec/07 §13.1-3).
    pub(crate) fn show_ready_draft_at(
        &mut self,
        draft: yw_core::approval::ApprovalDraft,
        prepared: Option<Box<Prepared>>,
        now_unix: u64,
    ) {
        let now = self.clock.now_ms();
        let mut draft = draft;
        let site_origin = self
            .evm
            .approval
            .as_ref()
            .and_then(|flow| match flow.item() {
                QueuedItem::Site(site) => Some(site.origin.clone()),
                _ => None,
            });
        if !self.wc_decorate_draft(site_origin.as_ref(), &mut draft) {
            // spec/13 §7: a WalletConnect request is never shown without its label and warning.
            logging::warn("app", "E-UI-001", &[("wc", Field::Word("label"))]);
            self.error_banner(ErrorCode::Ui001);
            self.finish_approval(QueueOutcome::Rejected);
            return;
        }
        let Ok(request) = self.evm.store.issue(draft, now, now_unix) else {
            self.show_failure(
                ErrorCode::App009,
                false,
                ErrorCode::App009.text_in(self.approval_lang()),
            );
            return;
        };
        if crate::approval::validate_for_display(&request.display).is_err() {
            logging::warn("app", "E-UI-001", &[]);
            self.error_banner(ErrorCode::Ui001);
            self.finish_approval(QueueOutcome::Rejected);
            return;
        }
        self.evm.queue.mark_ready(now);
        let deadline = self
            .evm
            .queue
            .shown_deadline()
            .unwrap_or(now.saturating_add(120_000));
        if let Some(flow) = self.evm.approval.as_mut() {
            flow.show_ready(request, prepared, deadline, now);
        }
        self.rebuild_view();
    }

    /// Re-simulation finished (spec/03 §6.6-3/4, spec/04 §3.4).
    pub fn on_resimulated(&mut self, result: ResimResult) {
        let Some(flow) = self.evm.approval.as_ref() else {
            return;
        };
        if flow.job() != result.job {
            return;
        }
        let click = flow.resim_click();
        let Some(old) = flow.issued().cloned() else {
            return;
        };
        // A chain mismatch found now blocks like at preparation (`Failed`, only `거부`); it never
        // becomes an approvable "no simulation" warning.
        if let Some(failure) = result.failure.filter(|_| result.kind == ResimKind::Failed) {
            logging::warn(
                "app",
                "resim.failed",
                &[("code", Field::Code(failure.code))],
            );
            if let Some(flow) = self.evm.approval.as_mut() {
                flow.resim_failed();
            }
            self.show_failure(failure.code, false, failure.message(self.approval_lang()));
            return;
        }
        let Some(prepared) = result.prepared else {
            if let Some(flow) = self.evm.approval.as_mut() {
                // Same content, but a new approval (checkbox, arm delay, fresh interaction).
                flow.resim_no_result(self.clock.now_ms());
            }
            self.rebuild_view();
            return;
        };
        // The re-simulated draft is built afresh: a WalletConnect request gets its label and
        // Verify warning again (spec/13 §7), or is not shown.
        let mut draft = prepared.draft.clone();
        let site_origin = self
            .evm
            .approval
            .as_ref()
            .and_then(|flow| match flow.item() {
                QueuedItem::Site(site) => Some(site.origin.clone()),
                _ => None,
            });
        if !self.wc_decorate_draft(site_origin.as_ref(), &mut draft) {
            logging::warn("app", "E-UI-001", &[("wc", Field::Word("label"))]);
            self.error_banner(ErrorCode::Ui001);
            self.finish_approval(QueueOutcome::Rejected);
            return;
        }
        // The worker compared its undecorated draft with the shown request, which carries the
        // `WalletConnect` label and Verify warning: the stable part is compared again on the
        // decorated draft (an extension request is unchanged by decoration).
        let kind = match result.kind {
            ResimKind::Same | ResimKind::Changed => {
                if crate::flow::evm::prepare::stable_equal(&old, &draft) {
                    ResimKind::Same
                } else {
                    ResimKind::Changed
                }
            }
            other => other,
        };
        let replaced = self.evm.store.replace(old.id, old.digest, draft);
        let Ok(request) = replaced else {
            self.show_failure(
                ErrorCode::App009,
                false,
                ErrorCode::App009.text_in(self.approval_lang()),
            );
            return;
        };
        let now = self.clock.now_ms();
        if let Some(flow) = self.evm.approval.as_mut() {
            // The documented exception (plan H1): `issued` is the replaced request from here on,
            // the session keeps the drawn content until `resim_shown` below.
            flow.resim_replaced(request.clone(), prepared);
        }
        if click && kind == ResimKind::Same {
            self.consume_and_sign();
            return;
        }
        if let Some(flow) = self.evm.approval.as_mut() {
            flow.resim_shown(kind, request, now);
        }
        // spec/06 §3.2: a re-simulation that changes the input bytes re-requests.
        self.ai_ready_tx();
        self.rebuild_view();
    }

    fn approved(&mut self) {
        let now = self.clock.now_ms();
        let connect =
            self.evm
                .approval
                .as_ref()
                .and_then(|flow| match (flow.item(), flow.connect()) {
                    (QueuedItem::Site(site), Some(connect)) => {
                        Some((site.clone(), connect.clone()))
                    }
                    _ => None,
                });
        if let Some((site, connect)) = connect {
            if connect.gate_count() == 0 {
                return;
            }
            let choices: Vec<crate::wallet::app_chain_sites::ConnectChoice> = connect
                .accounts
                .iter()
                .zip(&connect.selected)
                .filter(|(_, checked)| **checked)
                .map(|((choice, _, _, _), _)| choice.clone())
                .collect();
            if connect.family == yw_core::policy::Family::Evm {
                // L4(c): the chain changed since the window was drawn — show the new one and
                // wait for a new click (re-armed), never store a chain the user did not see.
                // (2026-11-19, S4 F2, owner decision O-5: the click that found the change left
                // the interaction `Approved`, so `거부`, Escape and the window's own expiry did
                // nothing and only the close box or the main timer ended the window (L-2). A fresh
                // interaction first, then the arm delay: the redrawn chain needs a new armed
                // click at least 1 s later, as after a re-simulation that asks again (C1).)
                if self.refresh_connect_chain() {
                    if let Some(flow) = self.evm.approval.as_mut() {
                        flow.chain_changed_at_approve(now);
                    }
                    self.rebuild_view();
                    return;
                }
                let accounts = choices
                    .iter()
                    .filter_map(|choice| match choice {
                        crate::wallet::app_chain_sites::ConnectChoice::Evm(address) => {
                            Some(*address)
                        }
                        _ => None,
                    })
                    .collect();
                self.connect_approved(&site, accounts, connect.chain_id);
            } else {
                self.chain_connect_approved(&site, &choices);
            }
            self.finish_approval(QueueOutcome::Approved);
            return;
        }
        let Some(flow) = self.evm.approval.as_mut() else {
            return;
        };
        // C1: one approval is acted on once — a submission in flight (re-simulation or consume)
        // ignores any further approval until its result replaces or resets the content.
        if flow.submitting() {
            return;
        }
        let Some(request) = flow.issued().cloned() else {
            return;
        };
        if flow.prepared().is_none() {
            flow.begin_submit();
            self.consume_and_sign();
            return;
        }
        flow.begin_submit();
        flow.checking();
        let received = flow
            .prepared()
            .map_or(0, |prepared| prepared.sim_received_ms);
        if needs_resimulation(&request.simulation, received, now) {
            self.start_resimulation(true);
        } else {
            self.consume_and_sign();
        }
    }

    fn start_resimulation(&mut self, click: bool) {
        let job = self.evm.job();
        let address_book = self.address_book_facts();
        let Some(flow) = self.evm.approval.as_mut() else {
            return;
        };
        let (Some(request), Some(prepared)) = (
            flow.issued().cloned(),
            flow.prepared().cloned().map(Box::new),
        ) else {
            return;
        };
        flow.resim_requested(job, click);
        let chain_id = flow.item().chain_id();
        let extra_warnings = match flow.item() {
            QueuedItem::Site(site) => site_fee_warning(flow.lang(), site),
            QueuedItem::App(_)
            | QueuedItem::Sol(_)
            | QueuedItem::Btc(_)
            | QueuedItem::Zec(_)
            | QueuedItem::HyperCore(_) => Vec::new(),
        };
        let chain = match self.chain_job(chain_id) {
            Ok(chain) => chain,
            Err(code) => {
                let failure =
                    crate::flow::evm::prepare::PrepareFailure::no_endpoint(self.approval_lang());
                self.show_failure(code, false, failure.message(self.approval_lang()));
                return;
            }
        };
        let sent = self.rpc(RpcJob::Resimulate(Box::new(ResimJob {
            job,
            chain,
            request,
            context: prepared.context,
            address_book,
            extra_warnings,
            limits: Limits::PRODUCTION,
        })));
        if let Some(flow) = self.evm.approval.as_mut() {
            if sent {
                // C1: the approval that asked for this re-simulation has been acted on; the
                // terminal `Approved` status must not dispatch it again on the next tick.
                flow.resim_sent(self.clock.now_ms());
            } else {
                flow.resim_not_sent(self.clock.now_ms());
            }
        }
        self.rebuild_view();
    }

    #[expect(
        clippy::too_many_lines,
        reason = "one branch per approval kind, in the order of spec/03 §11.5"
    )]
    fn consume_and_sign(&mut self) {
        let now = self.clock.now_ms();
        let Some(flow) = self.evm.approval.as_ref() else {
            return;
        };
        // `issued` is the consume handle (2026-11-19, S4 B4a: was `ApprovalUi.request`).
        let Some(request) = flow.issued().cloned() else {
            return;
        };
        let prepared = flow.prepared().cloned().map(Box::new);
        let item = flow.item().clone();
        match self.evm.store.consume(request.id, request.digest, now) {
            Ok(approved) => {
                logging::info(
                    "app",
                    "approval.consumed",
                    &[("net", Field::Net(item.network()))],
                );
                // An EVM dApp request's answer and the grant it needs: the signature or hash goes
                // to the site only while its grant still names the signing account (spec/05
                // §4.5, 2026-11-13).
                let site_answer = match (&item, approved.account()) {
                    (QueuedItem::Site(site), yw_core::approval::AccountRef::Evm(account)) => {
                        Some((
                            site.reply,
                            crate::wallet::app_browser::SiteSigner {
                                origin: site.origin.clone(),
                                account,
                            },
                        ))
                    }
                    _ => None,
                };
                if let QueuedItem::Sol(sol) = &item
                    && request.kind == yw_core::approval::ApprovalKind::SolTransfer
                {
                    self.sol_consumed(approved, sol.cluster, now);
                    self.finish_approval(QueueOutcome::Approved);
                    return;
                }
                if let QueuedItem::HyperCore(hypercore) = &item
                    && request.kind == yw_core::approval::ApprovalKind::HyperCoreAction
                {
                    self.hc_consumed(approved, hypercore);
                    self.finish_approval(QueueOutcome::Approved);
                    return;
                }
                if let QueuedItem::Btc(btc) = &item
                    && request.kind.is_btc()
                {
                    self.btc_consumed(approved, btc);
                    // 2026-11-20 (S4 P10a): after the answer of an open the controller's batch
                    // asked for (`AfterOpen::Finish`; before, called here directly).
                    self.after_pending_open(AfterOpen::Finish(QueueOutcome::Approved));
                    return;
                }
                if let QueuedItem::Zec(zec) = &item
                    && request.kind == yw_core::approval::ApprovalKind::ZecSend
                {
                    self.zec_consumed(approved, zec);
                    self.finish_approval(QueueOutcome::Approved);
                    return;
                }
                // A dApp Solana transaction request (spec/07 §20.8): its own waiter and signer.
                if request.kind == yw_core::approval::ApprovalKind::SolTransaction {
                    let QueuedItem::Site(site) = &item else {
                        self.show_failure(
                            ErrorCode::App009,
                            false,
                            ErrorCode::App009.text_in(self.approval_lang()),
                        );
                        return;
                    };
                    self.sol_dapp_consumed(approved, site);
                    self.finish_approval(QueueOutcome::Approved);
                    return;
                }
                if request.kind.is_chain_message() {
                    let waiter = match &item {
                        QueuedItem::Site(site) => Self::chain_waiter(site, approved.payload()),
                        _ => None,
                    };
                    let Some(waiter) = waiter else {
                        self.show_failure(
                            ErrorCode::App009,
                            false,
                            ErrorCode::App009.text_in(self.approval_lang()),
                        );
                        return;
                    };
                    let ticket = self.push_sign_waiter(waiter);
                    // A YubiKey account signs on the card after its PIN (spec/10 §10).
                    if let Err(approved) = self.card_begin(
                        approved,
                        crate::wallet::app_card::CardJobKind::ChainMessage,
                        Some(ticket),
                    ) {
                        self.key(KeyJob::SignChainMessage { ticket, approved });
                    }
                    self.finish_approval(QueueOutcome::Approved);
                    return;
                }
                match (prepared, request.kind) {
                    (
                        _,
                        kind @ (yw_core::approval::ApprovalKind::EvmPersonalSign
                        | yw_core::approval::ApprovalKind::EvmTypedData),
                    ) => {
                        let waiter = match (&item, site_answer) {
                            (QueuedItem::Site(_), Some((reply, signer))) => {
                                crate::wallet::app_browser::SignWaiter::Message(reply, signer)
                            }
                            (QueuedItem::Site(_), None) => {
                                self.show_failure(
                                    ErrorCode::App009,
                                    false,
                                    ErrorCode::App009.text_in(self.approval_lang()),
                                );
                                return;
                            }
                            _ => crate::wallet::app_browser::SignWaiter::App,
                        };
                        let ticket = self.push_sign_waiter(waiter);
                        let typed = kind == yw_core::approval::ApprovalKind::EvmTypedData;
                        // A YubiKey account signs on the card after its PIN (spec/10 §9.2).
                        if let Err(approved) = self.card_begin(
                            approved,
                            crate::wallet::app_card::CardJobKind::EvmMessage { typed },
                            Some(ticket),
                        ) {
                            self.key(KeyJob::SignMessage {
                                ticket,
                                approved,
                                typed,
                            });
                        }
                    }
                    (Some(prepared), _) => {
                        let (origin, waiter) = match &item {
                            QueuedItem::Site(site) => {
                                let Some((reply, signer)) = site_answer else {
                                    self.show_failure(
                                        ErrorCode::App009,
                                        false,
                                        ErrorCode::App009.text_in(self.approval_lang()),
                                    );
                                    return;
                                };
                                (
                                    self.site_origin_text(site),
                                    crate::wallet::app_browser::SignWaiter::Tx(reply, signer),
                                )
                            }
                            QueuedItem::App(_)
                            | QueuedItem::Sol(_)
                            | QueuedItem::Btc(_)
                            | QueuedItem::Zec(_)
                            | QueuedItem::HyperCore(_) => (
                                "yw-app".to_owned(),
                                crate::wallet::app_browser::SignWaiter::App,
                            ),
                        };
                        let ticket = self.push_sign_waiter(waiter);
                        let info = SignInfo {
                            origin,
                            label: request.display.title.clone(),
                            role: prepared.context.role,
                            now_unix_ms: self.clock.now_unix_ms(),
                        };
                        // The S11 send: an app item that replaces nothing (speed-up and cancel
                        // come from the activity list).
                        let form = matches!(&item, QueuedItem::App(app) if app.replace.is_none());
                        self.dispatch_evm_sign(ticket, approved, info, form);
                    }
                    (None, _) => {
                        self.show_failure(
                            ErrorCode::App009,
                            false,
                            ErrorCode::App009.text_in(self.approval_lang()),
                        );
                        return;
                    }
                }
                self.finish_approval(QueueOutcome::Approved);
            }
            Err(_) => {
                self.show_failure(
                    ErrorCode::App009,
                    false,
                    ErrorCode::App009.text_in(self.approval_lang()),
                );
            }
        }
    }

    /// The signing job of a consumed EVM transaction approval: `SignEvm`, or — for a `YubiKey`
    /// account (`EvmKeySource::Hardware`) — the card step: the PIN window, then `SignEvmCard`
    /// (spec/10 §9.2). The job's send slot is noted by `ticket` (released when this job ends
    /// without a signature, spec/03 §3.6); `form` marks the S11 send.
    pub(crate) fn dispatch_evm_sign(
        &mut self,
        ticket: crate::events::SignTicket,
        approved: yw_core::approval::Approved,
        info: SignInfo,
        form: bool,
    ) {
        if let (
            yw_core::approval::ChainRef::Evm { chain_id, .. },
            yw_core::approval::AccountRef::Evm(account),
        ) = (approved.chain(), approved.account())
        {
            self.evm.signing.insert(
                ticket,
                crate::wallet::app_evm::SigningSlot {
                    chain_id,
                    account,
                    form,
                },
            );
        }
        if crate::yubikey::approval_role(&approved).is_none() {
            self.key(KeyJob::SignEvm {
                ticket,
                approved: Box::new(approved),
                info,
            });
            return;
        }
        let kind = crate::wallet::app_card::CardJobKind::EvmTx { info };
        if let Err(approved) = self.card_begin(approved, kind, Some(ticket)) {
            // Not reached (the role was checked); never signed in software by accident.
            drop(approved);
            self.browser_sign_cancelled(ticket);
            self.release_signing(ticket);
        }
    }

    /// Main-timer part: deadlines, re-arming, the simulation countdown.
    pub fn tick_approval(&mut self, now: u64) {
        self.card_tick(now);
        let finished = self.evm.queue.tick(now);
        let _ = self.evm.store.expire_due(now);
        let shown_gone = self.evm.queue.shown().is_none() && self.evm.approval.is_some();
        for (item, outcome) in finished {
            self.approval_finished(&item.payload, outcome);
        }
        if shown_gone {
            self.close_approval_window();
            self.show_next_approval();
        }
    }

    /// One input of an approval window (`Cmd::Approval`; 2026-11-19, S4 B6, plan §3.1, critique
    /// A-12, A-13): dropped unless its `ShownId` is the shown window's, then, by signal: an
    /// interaction event with the window's foreground sample (`approval_event`); the close box
    /// (its `RejectActivated`, then `Rejected` only while the same window is still shown: the
    /// S4 F1 guard as the id check); activation (the arm delay restarts unconditionally, then the
    /// gate is foreground; no sample); the checkbox (`Redraw` when it toggled), the raw fold and a
    /// connect toggle of the shown view (a new view); `다시 시도` and `다시 요청`; the window's
    /// width class (a new view). Each does what the window procedure did before B6
    /// (`interaction()`, `ActivateApp(true)`, `Close`, `toggle_ack`, `toggle_raw`,
    /// `toggle_connect_account`, `retry_action`, `ai_retry` and the A01 `WM_SIZE` arm), with
    /// these differences (2026-11-20, S4 B6 review; none visible in production, where the clock
    /// read has no side effect and a rebuild without a flow returns at once):
    /// - an `Event` reads `now` after the window's foreground sample (`interaction()` read `now`
    ///   first, then sampled); the sample still comes before the event;
    /// - a dropped input (another id, or no flow) reads no clock: `toggle_ack` and
    ///   `toggle_connect_account` read it even without a flow;
    /// - a dropped `ToggleAccount`, `ToggleRaw` or `Resized`, and a `ToggleAccount` of an older
    ///   view (A-13), rebuild no view: `toggle_connect_account`, `toggle_raw` and `Relayout`
    ///   always called `rebuild_view` (whose first step reads the clock).
    ///
    /// With a test clock that steps on every read, a skipped read moves every later timestamp;
    /// no scenario reaches these paths today.
    pub(crate) fn on_approval_input(&mut self, input: ApprovalInput) {
        // 2026-11-22 (S4 W14b, preflight critic C5): the test builds' pairing check of the flow
        // and its window (`assert_flow_and_window_in_step`, the shell's) is made by the shell's
        // senders `window_event`/`window_signal` right before they send this input, and by
        // `App::drain` (before, here, first).
        let shown = input.shown;
        if self.shown_now() != Some(shown) {
            return;
        }
        let foreground = input.foreground;
        match input.signal {
            ApprovalSignal::Event(event) => self.approval_event(foreground, event),
            ApprovalSignal::Close => {
                self.approval_event(foreground, InteractionEvent::RejectActivated);
                // A window whose `RejectActivated` changes nothing (an `Approved` interaction)
                // still shows the same request, so the close box still ends it; a rejection that
                // opened the next request's window ends only its own (S4 F1, L-1). 2026-11-20 (S4
                // P10a): after the answer of that next window's open (`AfterOpen::CloseIfShown`;
                // before, checked here directly).
                self.after_pending_open(AfterOpen::CloseIfShown(shown));
            }
            ApprovalSignal::Activated => {
                if let Some(flow) = self.evm.approval.as_mut() {
                    flow.activated(self.clock.now_ms());
                }
            }
            ApprovalSignal::ToggleAck => {
                let now = self.clock.now_ms();
                if self
                    .evm
                    .approval
                    .as_mut()
                    .is_some_and(|flow| flow.toggle_ack(now))
                {
                    self.emit(Effect::Approval(ApprovalEffect::Redraw { shown }));
                }
            }
            ApprovalSignal::ToggleRaw => {
                if let Some(flow) = self.evm.approval.as_mut() {
                    flow.toggle_raw();
                }
                self.rebuild_view();
            }
            ApprovalSignal::ToggleAccount { index, view_rev } => {
                let now = self.clock.now_ms();
                if self
                    .evm
                    .approval
                    .as_mut()
                    .is_some_and(|flow| flow.toggle_account(usize::from(index), view_rev, now))
                {
                    self.rebuild_view();
                }
            }
            ApprovalSignal::Retry => self.retry_action(),
            ApprovalSignal::AiRetry => self.ai_retry(),
            ApprovalSignal::Resized { wide } => {
                if let Some(flow) = self.evm.approval.as_mut() {
                    flow.set_wide(wide);
                }
                self.rebuild_view();
            }
        }
    }

    /// An interaction event of the shown window with its foreground sample (2026-11-19, S4 B6:
    /// the flow half of the former `interaction()`, whose window half samples in
    /// `window_event`).
    fn approval_event(&mut self, foreground: bool, event: InteractionEvent) {
        let now = self.clock.now_ms();
        let Some(flow) = self.evm.approval.as_mut() else {
            return;
        };
        // 2026-11-19 (S4 B4a): the foreground sample, the event, the early-release note and
        // `status_action` run in `ApprovalFlow::on_event`, in this order (were inline here).
        match flow.on_event(now, foreground, event) {
            StatusAction::Approve => self.approved(),
            StatusAction::Expire => self.finish_approval(QueueOutcome::Expired),
            StatusAction::Reject => {
                logging::info("app", "approval.rejected", &[]);
                self.finish_approval(QueueOutcome::Rejected);
            }
            StatusAction::Repaint => {
                // Only the bottom bar changes with interaction events and ticks: repaint just it,
                // and only when what it shows changed (no full-window redraw every 50 ms).
                // 2026-11-19 (S4 B5): `Effect::Approval(RepaintBar)`, applied at once by
                // `approval_repaint_bar` (the same code, was inline here).
                if let Some(shown) = self.evm.approval.as_ref().map(ApprovalFlow::shown) {
                    self.emit(Effect::Approval(ApprovalEffect::RepaintBar { shown }));
                }
            }
            StatusAction::Nothing => {}
        }
    }

    fn rebuild_view(&mut self) {
        self.rebuild_view_with(true);
    }

    /// Rebuilds the view; with `force == false` (the simulation countdown tick) nothing is
    /// invalidated when the rebuilt view is the one already shown.
    #[expect(
        clippy::too_many_lines,
        reason = "badges, connect view and signing view of every queue item kind"
    )]
    pub fn rebuild_view_with(&mut self, force: bool) {
        let now = self.clock.now_ms();
        self.refresh_connect_chain();
        let testnet_chain = self.evm.approval.as_ref().map(|flow| match flow.connect() {
            Some(connect) if connect.family == yw_core::policy::Family::Evm => connect.chain_id,
            _ => flow.item().chain_id(),
        });
        let Some(chain_id) = testnet_chain else {
            return;
        };
        let mut badges = Vec::new();
        let family = match self.evm.approval.as_ref().map(ApprovalFlow::item) {
            Some(QueuedItem::Site(site)) => site.kind.family(),
            _ => yw_core::policy::Family::Evm,
        };
        if family == yw_core::policy::Family::Evm
            && self
                .settings
                .evm_chains
                .iter()
                .any(|def| def.chain_id == chain_id)
        {
            badges.push(crate::badge::custom_chain_badge(
                self.evm
                    .approval
                    .as_ref()
                    .map_or(self.settings.language, ApprovalFlow::lang),
                chain_id,
            ));
        }
        let (evm_chain, sol_cluster) =
            match (self.evm.approval.as_ref().map(ApprovalFlow::item), family) {
                (Some(QueuedItem::Sol(item)), _) => (None, Some(item.cluster)),
                // A dApp transaction shows the cluster it is bound to, whatever is selected now.
                (Some(QueuedItem::Site(site)), yw_core::policy::Family::Solana) => match &site.kind
                {
                    SiteKind::SolTx { cluster, .. } => (None, Some(*cluster)),
                    _ => (None, Some(self.sol_cluster())),
                },
                (Some(QueuedItem::Site(_)), yw_core::policy::Family::Bitcoin)
                | (
                    Some(QueuedItem::Btc(_) | QueuedItem::Zec(_) | QueuedItem::HyperCore(_)) | None,
                    _,
                ) => (None, None),
                (Some(QueuedItem::App(_) | QueuedItem::Site(_)), _) => (Some(chain_id), None),
            };
        let site_btc_banner = (family == yw_core::policy::Family::Bitcoin)
            .then(|| crate::approval::view::BtcBanner::of(self.btc_network_now()));
        let chain_badge = match (self.evm.approval.as_ref().map(ApprovalFlow::item), family) {
            (Some(QueuedItem::Btc(item)), _) => Some(Badge::bitcoin(item.network)),
            (Some(QueuedItem::Site(_)), yw_core::policy::Family::Bitcoin) => {
                Some(Badge::bitcoin(self.btc_network_now()))
            }
            _ => sol_cluster.map(Badge::solana).or_else(|| {
                evm_chain.map(|id| {
                    Badge::evm(
                        id,
                        &self.network_name(crate::network::NetworkId::Eip155(id)),
                    )
                })
            }),
        };
        let mut testnet = false;
        let lang = self
            .evm
            .approval
            .as_ref()
            .map_or(self.settings.language, ApprovalFlow::lang);
        if let Some((badge, test)) = network_badge(lang, evm_chain, sol_cluster) {
            testnet = test;
            badges.push(badge.to_owned());
        }
        // HyperCore (spec/11 §6): the same mainnet / testnet badges as the EVM chains.
        if let Some(QueuedItem::HyperCore(item)) =
            self.evm.approval.as_ref().map(ApprovalFlow::item)
        {
            if item.action.network == yw_core::hypercore::HcNetwork::Testnet {
                testnet = true;
                badges.push(text::BADGE_HC_TESTNET.get(lang).to_owned());
            } else {
                badges.push(text::BADGE_MAINNET.get(lang).to_owned());
            }
        }
        // spec/10 §10: a YubiKey signer adds the "YubiKey로 서명" badge (app chrome only: the
        // badges are not part of the request's digested display, spec/03 §11.3).
        let card_badge = self.evm.approval.as_ref().and_then(|flow| {
            let (role, touches) = match (flow.item(), &flow.gate().prepare) {
                (QueuedItem::Btc(item), _) => (
                    crate::yubikey::btc_plan_role(&item.plan)?,
                    item.plan.inputs().len(),
                ),
                (QueuedItem::Zec(item), _) => (
                    crate::yubikey::zec_plan_role(&item.plan)?,
                    item.plan.inputs.len(),
                ),
                // A sign-only Solana dApp request: one touch per transaction.
                (_, PrepareState::Ready(ReadyContent::Signing(request))) => (
                    crate::yubikey::role_of(&request.signer, &request.payload)?,
                    match &request.payload {
                        yw_core::approval::SigningPayload::SolTx(payload) => payload.items.len(),
                        _ => 1,
                    },
                ),
                _ => return None,
            };
            Some(crate::wallet::app_card::card_badge(
                lang,
                (&self.card.records, self.card_names()),
                role,
                touches,
            ))
        });
        badges.extend(card_badge);
        // WalletConnect sessions (spec/13 §7): the claimed origin, chains and Verify state.
        let wc_patch = self
            .evm
            .approval
            .as_ref()
            .and_then(|flow| match flow.item() {
                QueuedItem::Site(site) => self.wc_connect_patch(&site.origin),
                _ => None,
            });
        // 2026-11-19 (S4 B4b): the view is the flow's, the invalidations the window's.
        // 2026-11-19 (S4 B5): the width class is the flow's (`wide`, reported by the shell when
        // the window opened and at each A01 size or DPI change; was read here from the window),
        // and a rebuilt view is `Effect::Approval(Rebuilt)` (`approval_rebuilt`: layout dropped,
        // window, panel and AI body invalidated; was inline here). The flow and the window are
        // shown together, so the guard on the window is the guard on the flow.
        let Some(flow) = self.evm.approval.as_mut() else {
            return;
        };
        let shown = flow.shown();
        let wide_layout = flow.wide();
        if let QueuedItem::Site(site) = flow.item() {
            if crate::walletconnect::is_session_origin(&site.origin) {
                badges.insert(0, text::BADGE_WALLETCONNECT.get(lang).to_owned());
            }
            // spec/05 §2.12: after the http/punycode badges, connect and approval views alike.
            if let Some(mode) = site.compat_mode {
                badges.insert(0, crate::approval::view::compat_mode_badge(lang, mode));
            }
            if let (Some(connect), PrepareState::Ready(ReadyContent::Connect(_))) =
                (flow.connect(), &flow.gate().prepare)
            {
                let accounts: Vec<(String, String)> = connect
                    .accounts
                    .iter()
                    .map(|(_, label, address, _)| (label.clone(), address.clone()))
                    .collect();
                let mut connect_view = crate::approval::view::connect_view(
                    lang,
                    site.origin.as_str(),
                    site.origin.is_http(),
                    &accounts,
                    &connect.selected,
                    &connect.chain_name,
                    connect.family,
                );
                if let Some(patch) = &wc_patch {
                    patch.apply(&mut connect_view);
                }
                connect_view.badges.extend(badges);
                order_badges(&mut connect_view.badges);
                connect_view.testnet = testnet;
                connect_view.chain = chain_badge;
                flow.set_view(connect_view);
                // A connect window has no AI body (spec/06 §3.1), so `Rebuilt` invalidates the
                // window and the panel only, as before.
                self.emit(Effect::Approval(ApprovalEffect::Rebuilt {
                    shown,
                    changed: true,
                }));
                return;
            }
            let mut site_badges = Vec::new();
            if site.origin.is_http() {
                site_badges.push(text::BADGE_HTTP.get(lang).to_owned());
            }
            if site
                .origin
                .host()
                .split('.')
                .any(|label| label.starts_with("xn--"))
            {
                site_badges.push(text::BADGE_PUNYCODE.get(lang).to_owned());
            }
            site_badges.extend(badges);
            badges = site_badges;
        }
        let btc_banner = match flow.item() {
            QueuedItem::Btc(item) => Some(crate::approval::view::BtcBanner::of(item.network)),
            QueuedItem::Site(_) => site_btc_banner,
            QueuedItem::App(_)
            | QueuedItem::Sol(_)
            | QueuedItem::Zec(_)
            | QueuedItem::HyperCore(_) => None,
        };
        match view(
            lang,
            &flow.gate().prepare,
            now,
            flow.raw_open(),
            wide_layout,
            badges,
            testnet,
            flow.failure(),
        ) {
            Ok(mut view) => {
                order_badges(&mut view.badges);
                view.btc_banner = btc_banner;
                view.chain = chain_badge;
                // W-ADDR-3 under the recipient (spec/04 §3.3, outside the digest).
                let note = match flow.item() {
                    QueuedItem::Btc(item) => item.look_alike.as_deref(),
                    QueuedItem::Zec(item) => item.look_alike.as_deref(),
                    QueuedItem::App(_)
                    | QueuedItem::Site(_)
                    | QueuedItem::Sol(_)
                    | QueuedItem::HyperCore(_) => None,
                };
                if let Some(note) = note {
                    crate::approval::view::attach_address_note(&mut view, lang, note);
                }
                if !force && view == *flow.view() {
                    self.emit(Effect::Approval(ApprovalEffect::Rebuilt {
                        shown,
                        changed: false,
                    }));
                    return;
                }
                flow.set_view(view);
                // The risk level or the acknowledgement may have changed (held_for_ack): the AI
                // body is invalidated too.
                self.emit(Effect::Approval(ApprovalEffect::Rebuilt {
                    shown,
                    changed: true,
                }));
            }
            Err(code) => {
                logging::warn("app", "E-UI-001", &[]);
                self.error_banner(code);
                self.finish_approval(QueueOutcome::Rejected);
            }
        }
    }
}

impl Wallet {
    /// `Step::AiExpand` of the window (`ai.down`, spec/06 §3.2): flips the shown flow's AI panel
    /// between short and expanded; `true` when it changed (the shell then puts the body's scroll
    /// at the top and repaints). 2026-11-22 (S4c W15): wallet code (the flow's AI state); before,
    /// the shell's `run_step` flipped it itself through `DerefMut`.
    pub fn toggle_ai_panel(&mut self) -> bool {
        self.evm
            .approval
            .as_mut()
            .and_then(ApprovalFlow::ai_mut)
            .is_some_and(|ai| ai.panel.toggle_expanded())
    }

    /// Before the AI body paints (spec/06 §3.2): the shown flow's AI panel is held while a
    /// High-risk request's acknowledgement checkbox is clear ([`ApprovalFlow::hold_ai_for_ack`],
    /// which writes that flag only); `true` when the window has an AI explanation to paint.
    /// 2026-11-22 (S4c W15): wallet code; before, the shell's `paint_ai_body` called it on the
    /// flow it had bound mutably.
    pub fn hold_shown_ai_for_ack(&mut self) -> bool {
        self.evm
            .approval
            .as_mut()
            .is_some_and(ApprovalFlow::hold_ai_for_ack)
    }

    /// `다시 시도` / `시뮬레이션 다시 실행` of the shown window (`ApprovalSignal::Retry`).
    fn retry_action(&mut self) {
        let failed_retryable = self.evm.approval.as_ref().is_some_and(|flow| {
            matches!(
                flow.gate().prepare,
                PrepareState::Failed {
                    retryable: true,
                    ..
                }
            )
        });
        if failed_retryable {
            self.start_prepare();
        } else {
            self.start_resimulation(false);
        }
    }
}

impl Wallet {
    // ----- AI explanation (spec/06) -------------------------------------------------------

    fn llm_busy(&self) -> bool {
        self.llm
            .as_ref()
            .is_none_or(crate::explain::ExplainService::busy)
    }

    /// Logs an ended request and hands a new one to the worker, then asks for the AI body and
    /// the window to be repainted (`Effect::Approval(RepaintAi)`; 2026-11-22, S4 W14a: before,
    /// this fn invalidated the AI body and A01 of the window open then, here, at the end; the
    /// effect is applied when the entry drains, before the next message can paint).
    fn ai_after(
        &mut self,
        ended: Option<Ended>,
        dispatch: Option<Dispatch>,
        stats: Option<&RequestStats>,
    ) {
        let now = self.clock.now_ms();
        let crate::wallet::Wallet { evm, llm, .. } = self;
        let Some(flow) = evm.approval.as_mut() else {
            return;
        };
        let shown = flow.shown();
        let Some(ai) = flow.ai_mut() else {
            return;
        };
        if let Some(ended) = ended {
            log_request(&ai.host, ai.kind, &ended, stats);
        }
        if let Some(dispatch) = dispatch {
            let generation = dispatch.generation;
            let job = LlmJob {
                window: ai.serial,
                generation,
                input: dispatch.input,
            };
            let sent = llm.as_ref().is_some_and(|service| service.submit(job));
            if !sent
                && let Some(ended) = ai
                    .panel
                    .on_result(now, generation, Err(ExplainError::Network))
            {
                log_request(&ai.host, ai.kind, &ended, None);
            }
        }
        self.emit(Effect::Approval(ApprovalEffect::RepaintAi {
            shown,
            body_only: false,
        }));
    }

    fn ai_ready(&mut self, ready: AiReady) {
        let now = self.clock.now_ms();
        let busy = self.llm_busy();
        let Some(ai) = self.evm.approval.as_mut().and_then(ApprovalFlow::ai_mut) else {
            return;
        };
        let (ended, dispatch) = match ready {
            AiReady::Input(Ok(input)) => ai.panel.set_input(now, input, busy),
            AiReady::Input(Err(error)) => (ai.panel.input_failed(now, error), None),
            AiReady::Skip(text) => (ai.panel.skip(now, text), None),
        };
        self.ai_after(ended, dispatch, None);
    }

    /// A dApp transaction reached Ready (first display or re-simulation): the input from the
    /// wallet's decoding and the simulation status (spec/06 §3.1, §4.3).
    fn ai_ready_tx(&mut self) {
        let ready = {
            let Some(flow) = self.evm.approval.as_ref() else {
                return;
            };
            if flow.ai().is_none() {
                return;
            }
            let (QueuedItem::Site(site), Some(prepared), Some(request)) =
                (flow.item(), flow.prepared(), flow.issued())
            else {
                return;
            };
            let yw_core::approval::AccountRef::Evm(user) = request.account else {
                return;
            };
            if request.display.risk == RiskLevel::Blocked {
                AiReady::Skip(SKIP_BLOCKED.get(self.approval_lang()))
            } else {
                crate::wallet::app_llm::transaction_input(
                    self.approval_lang(),
                    prepared,
                    &self.site_origin_text(site),
                    &user,
                )
                .map_or(
                    AiReady::Skip(SKIP_BLOCKED.get(self.approval_lang())),
                    AiReady::Input,
                )
            }
        };
        self.ai_ready(ready);
    }

    /// A `personal_sign` request reached Ready.
    fn ai_ready_message(&mut self) {
        let Some(flow) = self.evm.approval.as_ref() else {
            return;
        };
        // Only for the window whose draft was just shown (not a next window opened meanwhile).
        if flow.ai().is_none() || flow.issued().is_none() {
            return;
        }
        let QueuedItem::Site(site) = flow.item().clone() else {
            return;
        };
        let SiteKind::PersonalSign { account, message } = &site.kind else {
            return;
        };
        let blocked = flow
            .issued()
            .is_some_and(|request| request.display.risk == RiskLevel::Blocked);
        let ready = match self.message_chain(site.chain_id) {
            _ if blocked => AiReady::Skip(SKIP_BLOCKED.get(self.approval_lang())),
            Some(chain) => {
                let decoded = yw_core::evm::eip191::decode_personal_message(message.clone());
                AiReady::Input(build_input(
                    self.approval_lang(),
                    &ExplainSource::PersonalSign(&decoded),
                    &self.site_origin_text(&site),
                    account,
                    &chain,
                    &yw_core::approval::ChainFacts::default(),
                ))
            }
            None => AiReady::Skip(SKIP_FAILED.get(self.approval_lang())),
        };
        self.ai_ready(ready);
    }

    /// A typed-data request reached Ready (with the facts its display used).
    fn ai_ready_typed(&mut self, facts: &yw_core::approval::ChainFacts) {
        let Some(flow) = self.evm.approval.as_ref() else {
            return;
        };
        if flow.ai().is_none() || flow.issued().is_none() {
            return;
        }
        let (QueuedItem::Site(site), Some(typed)) =
            (flow.item().clone(), flow.typed().cloned().map(Box::new))
        else {
            return;
        };
        let SiteKind::TypedData { account, .. } = &site.kind else {
            return;
        };
        let blocked = flow
            .issued()
            .is_some_and(|request| request.display.risk == RiskLevel::Blocked);
        let ready = match self.message_chain(site.chain_id) {
            _ if blocked => AiReady::Skip(SKIP_BLOCKED.get(self.approval_lang())),
            Some(chain) => AiReady::Input(build_input(
                self.approval_lang(),
                &ExplainSource::TypedData(&typed),
                &self.site_origin_text(&site),
                account,
                &chain,
                facts,
            )),
            None => AiReady::Skip(SKIP_FAILED.get(self.approval_lang())),
        };
        self.ai_ready(ready);
    }

    /// The 50 ms tick: deadline and a request waiting for the worker (spec/06 §3.2). While a
    /// request waits, the AI body is repainted once a second for its elapsed time
    /// (`Effect::Approval(RepaintAi { body_only: true })`; 2026-11-22, S4 W14a: before, this fn
    /// invalidated the AI body of the window open then itself; the timer's tail drains right
    /// after this call, so it is applied at the same point).
    pub fn ai_tick(&mut self, now: u64) {
        let busy = self.llm_busy();
        let Some(flow) = self.evm.approval.as_mut() else {
            return;
        };
        let shown = flow.shown();
        let Some(ai) = flow.ai_mut() else {
            return;
        };
        let requesting = matches!(
            ai.panel.state(),
            crate::explain::AiPanelState::Requesting { .. }
        );
        let (ended, dispatch) = ai.panel.tick(now, busy);
        if ended.is_some() || dispatch.is_some() {
            self.ai_after(ended, dispatch, None);
        } else if requesting && now % 1_000 < 50 {
            self.emit(Effect::Approval(ApprovalEffect::RepaintAi {
                shown,
                body_only: true,
            }));
        }
    }

    /// `다시 요청` (mouse only; `ApprovalSignal::AiRetry`).
    fn ai_retry(&mut self) {
        let now = self.clock.now_ms();
        let busy = self.llm_busy();
        let Some(ai) = self.evm.approval.as_mut().and_then(ApprovalFlow::ai_mut) else {
            return;
        };
        let dispatch = ai.panel.retry(now, busy);
        self.ai_after(None, dispatch, None);
    }

    /// A `yw-llm` result (spec/06 §3.2): applied only to the open window's current request.
    pub(crate) fn on_llm_done(&mut self, done: LlmDone) {
        let now = self.clock.now_ms();
        let Some(ai) = self
            .evm
            .approval
            .as_mut()
            .and_then(ApprovalFlow::ai_mut)
            .filter(|ai| ai.serial == done.window)
        else {
            return;
        };
        let ended = ai.panel.on_result(now, done.generation, done.result);
        self.ai_after(ended, None, Some(&done.stats));
    }
}

/// E31 for a dApp transaction that carried fee fields (spec/03 §3.4, values ignored).
fn site_fee_warning(lang: Lang, site: &SiteRequest) -> Vec<yw_core::approval::Warning> {
    match &site.kind {
        SiteKind::Send(tx) if tx.fee_fields => {
            vec![yw_core::evm::risk::warning(
                lang,
                yw_core::evm::risk::E31,
                None,
            )]
        }
        _ => Vec::new(),
    }
}
