//! Test helpers that the yw-app tests use across the crate boundary (spec/15 §11.4 S2, D-f):
//! `cfg(test)` does not cross crates and dev-dependencies and features are frozen, so these are
//! always compiled but hidden from the docs (the same reason `yw_core::yubikey::mock` and
//! [`crate::yubikey::MockSource`] are always compiled). Production code never names this module:
//! a yw-app unit test (`card_pcsc`) scans its non-test sources for it.
//!
//! (2026-11-17, S2 E3: [`yubikey_wallet`] moved here from the key worker's `cfg(test)` tests
//! module, which the App tests reached as `workers::key::tests::yubikey_wallet` while both were in
//! yw-app; it now takes the folder instead of a tag, because only the caller knows whether the
//! folder is real. There is no raw meta-sidecar writer here: owner decision, the App tests seal
//! raw meta through a second vault session.)

use std::path::PathBuf;
use std::sync::{Arc, Mutex};

use yw_core::bip32::path::AccountIndex;
use yw_core::btc::BtcNetwork;
use yw_core::secret::Zeroizing;
use yw_core::yubikey::mock::MockCard;
use yw_core::yubikey::plan::{CardSlot, KeyRole, PgpKey, PivSlot, PlannedSlot};

use crate::events::{KeyJob, KeyOutcome, MetaLoaded};
use crate::workers::key::KeyWorker;
use crate::workers::key::platform::KeyDeps;

/// A worker on the `abandon` wallet with two emulated `YubiKey`s enrolled: card A (SIG = EVM 0,
/// AUT = EVM 1, PIV 82 = Solana 0) and card B (SIG = BIP84 mainnet address 0); both cards stay
/// inserted. Returns the worker, the cards (A, B), the folder and the reconciled meta.
/// `deps` gives the storage and the clock (its card source is replaced by the emulator): the
/// in-memory platform in the key worker's unit tests, the Windows platform on real files (no
/// readers) in the App tests, which read the files in `dir` themselves.
///
/// # Panics
///
/// When a step of the import or the enrolment fails (a test failure).
#[must_use]
#[expect(
    clippy::unwrap_used,
    reason = "test helper (spec/15 §11.4 S2): a failed step is a failed test"
)]
pub fn yubikey_wallet(
    dir: PathBuf,
    deps: KeyDeps,
) -> (KeyWorker, Arc<Mutex<Vec<MockCard>>>, PathBuf, MetaLoaded) {
    let about = format!("{} about", ["abandon"; 11].join(" "));
    let cards = Arc::new(Mutex::new(vec![MockCard::new(7_700_011)]));
    let mut worker =
        KeyWorker::new(&dir, deps).with_card_source(Box::new(crate::yubikey::MockSource {
            cards: Arc::clone(&cards),
        }));
    let bytes = |text: &str| Zeroizing::new(text.as_bytes().to_vec());
    worker.handle(KeyJob::Load);
    worker.handle(KeyJob::PreviewImport {
        password: Some(bytes("yubikey wallet password")),
        phrase: bytes(&about),
        passphrase: None,
    });
    assert!(matches!(
        worker.handle(KeyJob::CommitImport).first(),
        Some(KeyOutcome::Imported(Ok(())))
    ));
    let evm = |index| KeyRole::Evm {
        index: AccountIndex::new(index).unwrap(),
        btc: None,
    };
    let enrol = |worker: &mut KeyWorker, slots| match worker
        .handle(KeyJob::EnrolYubiKey {
            phrase: bytes(&about),
            passphrase: None,
            slots,
            admin_pin: bytes("12345678"),
            management_key: Zeroizing::new(yw_core::yubikey::piv::DEFAULT_MANAGEMENT_KEY.to_vec()),
        })
        .pop()
    {
        Some(KeyOutcome::YubiKeyEnrolled(Ok(_))) => {}
        other => unreachable!("enrolment failed: {other:?}"),
    };
    enrol(
        &mut worker,
        vec![
            PlannedSlot::recommended(CardSlot::OpenPgp(PgpKey::Sig), evm(0)),
            PlannedSlot::recommended(CardSlot::OpenPgp(PgpKey::Aut), evm(1)),
            PlannedSlot::recommended(
                CardSlot::Piv(PivSlot::new(0x82).unwrap()),
                KeyRole::Sol {
                    index: AccountIndex::ZERO,
                },
            ),
        ],
    );
    // Card B alone in the reader for its enrolment, then both inserted.
    let card_a = cards.lock().unwrap().pop().unwrap();
    cards.lock().unwrap().push(MockCard::new(7_700_012));
    enrol(
        &mut worker,
        vec![PlannedSlot::recommended(
            CardSlot::OpenPgp(PgpKey::Sig),
            KeyRole::Btc {
                network: BtcNetwork::Mainnet,
                script: yw_core::btc::ScriptType::P2wpkh,
                index: 0,
            },
        )],
    );
    cards.lock().unwrap().insert(0, card_a);
    for card in cards.lock().unwrap().iter_mut() {
        card.log.clear();
    }
    let Some(KeyOutcome::Meta(Ok(loaded))) = worker.handle(KeyJob::LoadMeta).pop() else {
        unreachable!("meta");
    };
    (worker, cards, dir, loaded)
}

// ----- The wallet's test entries (2026-11-23, spec/15 §11.4 S4d E1) ---------------------------
//
// Preflight O-2, O-11, O-14 and critic C2/C3 (주인 상시 결정(2026-11-21): 권고안, spec/15 §18 28):
// the wallet's consent and secret steps stay crate-private in yw-engine, and the yw-app tests
// (the frozen A-4 tests among them, unchanged) drive them through these traits as before. Before
// E1 they were `pub(crate)` items of the same crate. A method of these traits shadows nothing in
// yw-engine and resolves only where the trait is imported.
//
// 2026-11-23 (S4d E1 review): what keeps them out of production is a source check, not the
// compiler. This module is always compiled and `pub` (`#[doc(hidden)]` only), so any crate that
// imports a trait can call its methods; production code never names `testkit` (source check
// `testkit_is_named_only_by_tests`, which reads yw-app and yw-engine; 2026-11-23, S4d E4: and S7
// `approval_capability_is_engine_only`, which also keeps the consent names, `Approved`,
// `ApprovalStore`, `consume` and the approval carriers out of yw-app's code). The review also
// found that E1 had added two accessors beyond the preflight's recommendations that handed out
// the store itself (`&mut ApprovalStore`, from which `consume` makes an `Approved`) and the
// secret session slot (`&mut Option<SecretSession>`); they are replaced by [`StoreProbe`], which
// returns outcomes only, and by four setup steps that only put state in. Still, an `Approved` is
// made only by an `ApprovalStore`'s `consume` (yw-core).

use std::collections::VecDeque;
use std::sync::mpsc::Sender;

use yw_core::approval::{
    ApprovalDraft, ApprovalError, ApprovalId, ApprovalRequest, ApprovalStore, Approved,
    SigningPayload,
};
use yw_core::evm::address::Address;
use yw_core::lang::Lang;
use yw_core::policy::{BrowserOrigin, BtcPurpose, ProviderError};
use yw_core::sol::SolCluster;
use yw_core::sol::dapp::{PreSignCheck, SolTxMode};
use yw_core::vault::{BackupChallenge, EvmKeySource, RecordId};

use crate::approval::QueueOutcome;
use crate::approval::flow::{OpenOutcome, ShownId};
use crate::approval::interaction::{ApprovalSession, InteractionStatus, PrepareState};
use crate::browser::{SiteRequest, VaultView, WalletView};
use crate::cmd::{
    BookPress, BtcPress, ExplorerPress, HiddenPress, KeysPress, LinksPress, LlmPress, Press,
    ResetPress, SitesPress, SolPress,
};
use crate::effect::Effect;
use crate::errors::ErrorCode;
use crate::events::{ChainMessageSigned, MessageSigned, SignInfo, SignTicket, SolDappSigned};
use crate::flow::evm::form::Quote;
use crate::flow::evm::prepare::Prepared;
use crate::flow::evm::track::BroadcastOutcome;
use crate::form::{CredField, EditField, PressInput};
use crate::network::NetworkId;
use crate::secret::{CardSecretKind, DisplaySecret, SecretFormOp, SecretKind, Submission};
use crate::services::Services;
use crate::sol::flow::{DappPreview, PreSignError, TrackResult};
use crate::wallet::app_approval::{AfterOpen, ConnectState};
use crate::wallet::app_browser::{HardwareSiteAccounts, SignWaiter};
use crate::wallet::app_card::{CardJobKind, CardStep, PinBuffer};
use crate::wallet::app_chain_sites::{BtcRow, ConnectChoice, ConnectEntry};
use crate::wallet::app_mnemonics::MnPurpose;
use crate::wallet::app_sol_dapp::PendingDappSign;
use crate::wallet::app_yubikey::YkPurpose;
use crate::wallet::approval_flow::{AiFlow, ApprovalFlow};
use crate::wallet::lock::IdleTracker;
use crate::wallet::secret_session::{AfterShown, SecretSession};
use crate::wallet::{Purpose, TestState, Wallet};
use crate::wallet_files::{ResetError, ResetReport};
use crate::workers::key::mnemonics::MnOutcome;
use crate::workers::rpc::RpcJob;

/// The wallet's crate-private steps and buffers as the yw-app tests reach them (tests only).
pub trait WalletTestExt {
    /// `Wallet::card_begin`: an approval whose signer is a card waits for its PIN.
    ///
    /// # Errors
    ///
    /// The approval back when the signer is not a card key.
    fn card_begin(
        &mut self,
        approved: Approved,
        kind: CardJobKind,
        ticket: Option<SignTicket>,
    ) -> Result<(), Box<Approved>>;
    /// `Wallet::card_submit`: the PIN window's submission of card step `id`.
    fn card_submit(&mut self, id: u64, pin: Zeroizing<Vec<u8>>);
    /// `Wallet::card_cancel`: the PIN window's cancel of card step `id`.
    fn card_cancel(&mut self, id: u64);
    /// `Wallet::dispatch_evm_sign`: a consumed EVM approval goes to its signing job.
    fn dispatch_evm_sign(
        &mut self,
        ticket: SignTicket,
        approved: Approved,
        info: SignInfo,
        form: bool,
    );
    /// `Wallet::sol_dapp_consumed`: a consumed Solana dApp transaction approval.
    fn sol_dapp_consumed(&mut self, approved: Approved, site: &SiteRequest);
    /// `Wallet::push_sign_waiter`: a signing request's waiter.
    fn push_sign_waiter(&mut self, waiter: SignWaiter) -> SignTicket;
    /// `Wallet::begin_secret`: a secret session's start (its serial).
    fn begin_secret(&mut self, kind: SecretKind, purpose: Purpose, topmost: bool) -> u64;
    /// `Wallet::on_submit`: a secret window's submission for `purpose`.
    fn on_submit(&mut self, purpose: Purpose, submission: Submission);
    /// `Wallet::on_cancel`: a secret window's cancel for `purpose`.
    fn on_cancel(&mut self, purpose: Purpose);
    /// `Wallet::take_display_secret`: the display secret of session `serial`, moved out once.
    fn take_display_secret(&mut self, serial: u64) -> Option<DisplaySecret>;
    /// The open secret session (read-only; preflight O-11).
    fn secret_session(&self) -> Option<&SecretSession>;
    /// Puts `session` in the secret session slot (the one before is dropped and wiped here, never
    /// handed back). 2026-11-23 (S4d E1 review): with the three steps below it replaces the slot
    /// itself (`secret_session_mut`), which the yw-app tests that set a session up wrote through.
    fn set_secret_session(&mut self, session: Option<SecretSession>);
    /// The open secret session's window was reported shown (its kept step is dropped, not run).
    fn mark_secret_shown(&mut self);
    /// The open secret session holds `display` (the test's own secret) for its display window.
    fn hold_display_secret(&mut self, display: DisplaySecret);
    /// The open secret session keeps `after` for its window's `Shown`.
    fn then_when_secret_shown(&mut self, after: AfterShown);
    /// The last secret session's serial (read-only).
    fn secret_serial(&self) -> u64;
    /// The issued approvals (read-only; the frozen and flow tests read an item's state).
    fn evm_store(&self) -> &ApprovalStore;
    /// The issued approvals for the tests that issue, reject or re-consume one themselves (the
    /// single-use and re-consume checks): outcomes only, never the store or an `Approved`
    /// ([`StoreProbe`]). 2026-11-23 (S4d E1 review): it handed out `&mut ApprovalStore` at E1;
    /// the name stays so the two `mutable` frozen helpers E1 recorded with it keep their text.
    fn evm_store_mut(&mut self) -> StoreProbe<'_>;
    /// Whether the import flow holds its password and its words (flags only, never a value).
    fn import_held(&self) -> (bool, bool);
    /// The backup check's word positions (read-only; positions, never a word).
    fn challenge(&self) -> Option<BackupChallenge>;
    /// Whether the recovery-phrase flow holds its words and its quiz (debug builds; flags only).
    #[cfg(debug_assertions)]
    fn mn_holds(&self) -> (bool, bool);
    /// Whether the `YubiKey` wizard holds its admin PIN or words (debug builds; a flag only).
    #[cfg(debug_assertions)]
    fn yk_wizard_holds_secret(&self) -> bool;

    // 2026-11-23 (S4d final review, A-15, D-22): the wallet's fields and steps below were
    // `#[doc(hidden)] pub` from E1 on although only tests named them outside the engine, so any
    // crate could call a consent or hold-gated step (`connect_approved`, `reset_execute`,
    // `mn_hold_complete`, …) or write the outbox. They are `pub(crate)` again and the tests reach
    // them here, as the consent steps above; the methods keep their names, so the test bodies (the
    // frozen ones among them) call them unchanged with this trait imported.
    /// The effects queued and not applied yet (read-only).
    fn outbox(&self) -> &VecDeque<Effect>;
    /// The effects queued and not applied yet, taken out in order (none is applied).
    fn take_outbox(&mut self) -> Vec<Effect>;
    /// Puts `batch` back at the end of the queue unchanged (a test host's held batch).
    fn requeue_effects(&mut self, batch: Vec<Effect>);
    /// Puts `input` in as the press input and gives back the one before (`App::press_family`).
    fn swap_press_input(&mut self, input: PressInput) -> PressInput;
    /// `PressInput::take` on the press input (outside a press it counts a miss, debug builds).
    fn take_press_cred(&mut self, field: CredField) -> Zeroizing<Vec<u16>>;
    /// Debug builds: the press input's takes of a field its press did not capture.
    #[cfg(debug_assertions)]
    fn press_input_misses(&self) -> u32;
    /// The auto-lock idle tracker.
    fn idle_mut(&mut self) -> &mut IdleTracker;
    /// The platform services the optional network workers start from.
    fn services_mut(&mut self) -> &mut Services;
    /// The steps kept for an approval window's open answer (read-only).
    fn after_open_steps(&self) -> &[(ShownId, AfterOpen)];
    /// Keeps `after` for the open answer of window `shown`.
    fn keep_after_open(&mut self, shown: ShownId, after: AfterOpen);
    /// The approval window open that waits for its answer.
    fn open_unanswered(&self) -> Option<ShownId>;
    /// Sets the approval window open that waits for its answer.
    fn set_open_unanswered(&mut self, shown: Option<ShownId>);
    /// Whether the settings in use were compared with the meta snapshot.
    fn settings_verified(&self) -> bool;
    /// Marks the settings in use as compared with the meta snapshot.
    fn set_settings_verified(&mut self, verified: bool);
    /// The save keys written while no snapshot was available (read-only).
    fn settings_saved_early(&self) -> &[&'static str];
    /// `(seen, found)` of a `vault.ywv` generation older than the meta remembers.
    fn settings_rollback(&self) -> Option<(u64, u64)>;
    /// `Wallet::show_next_approval_then` (`wallet::app_approval`).
    fn show_next_approval_then(&mut self, after: AfterOpen);
    /// `Wallet::after_pending_open` (`wallet::app_approval`).
    fn after_pending_open(&mut self, after: AfterOpen);
    /// `Wallet::connect_state` (`wallet::app_approval`).
    fn connect_state(&self, site: &SiteRequest) -> ConnectState;
    /// `Wallet::on_approval_opened` (`wallet::app_approval`).
    fn on_approval_opened(&mut self, shown: ShownId, outcome: OpenOutcome, wide: bool);
    /// `Wallet::message_chain_failure` (`wallet::app_approval`).
    fn message_chain_failure(
        &self,
        chain_id: u64,
    ) -> Option<crate::flow::evm::prepare::PrepareFailure>;
    /// `Wallet::finish_approval` (`wallet::app_approval`).
    fn finish_approval(&mut self, outcome: QueueOutcome);
    /// `Wallet::show_ready_draft` (`wallet::app_approval`).
    fn show_ready_draft(
        &mut self,
        draft: yw_core::approval::ApprovalDraft,
        prepared: Option<Box<Prepared>>,
    );
    /// `Wallet::on_book_edit` (`wallet::app_book`).
    fn on_book_edit(&mut self, field: EditField, text: &str) -> bool;
    /// `Wallet::on_book` (`wallet::app_book`).
    fn on_book(&mut self, press: BookPress);
    /// `Wallet::on_links` (`wallet::app_book`).
    fn on_links(&mut self, press: LinksPress);
    /// `Wallet::vault_view` (`wallet::app_browser`).
    fn vault_view(&self) -> VaultView;
    /// `Wallet::wallet_view` (`wallet::app_browser`).
    fn wallet_view(&self) -> WalletView;
    /// `Wallet::write_grants` (`wallet::app_browser`).
    fn write_grants(&mut self);
    /// `Wallet::browser_vault_loaded` (`wallet::app_browser`).
    fn browser_vault_loaded(&mut self);
    /// `Wallet::unlocked_refusal` (`wallet::app_browser`).
    fn unlocked_refusal(&self, site: &SiteRequest) -> Option<ProviderError>;
    /// `Wallet::refuse_site` (`wallet::app_browser`).
    fn refuse_site(&mut self, site: &SiteRequest, error: ProviderError);
    /// `Wallet::site_preflight` (`wallet::app_browser`).
    fn site_preflight(&mut self, site: &SiteRequest) -> Option<QueueOutcome>;
    /// `Wallet::hardware_site_accounts` (`wallet::app_browser`).
    fn hardware_site_accounts(&self) -> Option<HardwareSiteAccounts>;
    /// `Wallet::connect_approved` (`wallet::app_browser`).
    fn connect_approved(&mut self, site: &SiteRequest, accounts: Vec<Address>, chain_id: u64);
    /// `Wallet::browser_tx_signed` (`wallet::app_browser`).
    fn browser_tx_signed(&mut self, ticket: SignTicket, result: Result<[u8; 32], ()>);
    /// `Wallet::browser_message_signed` (`wallet::app_browser`).
    fn browser_message_signed(&mut self, signed: MessageSigned);
    /// `Wallet::browser_sign_cancelled` (`wallet::app_browser`).
    fn browser_sign_cancelled(&mut self, ticket: SignTicket);
    /// `Wallet::browser_broadcast` (`wallet::app_browser`).
    fn browser_broadcast(&mut self, tx_hash: [u8; 32], outcome: BroadcastOutcome);
    /// `Wallet::on_sites` (`wallet::app_browser`).
    fn on_sites(&mut self, press: SitesPress);
    /// `Wallet::btc_apply_field` (`wallet::app_btc_commands`).
    fn btc_apply_field(&mut self, field: EditField, text: &str);
    /// `Wallet::on_btc_edit` (`wallet::app_btc_commands`).
    fn on_btc_edit(&mut self, field: EditField, text: &str) -> bool;
    /// `Wallet::on_btc` (`wallet::app_btc_commands`).
    fn on_btc(&mut self, press: BtcPress);
    /// `Wallet::card_after_meta` (`wallet::app_card`).
    fn card_after_meta(&mut self);
    /// `Wallet::evm_selected_card_gate` (`wallet::app_card`).
    fn evm_selected_card_gate(&self) -> Option<u32>;
    /// `Wallet::card_step_card` (`wallet::app_card`).
    fn card_step_card(&self, role: KeyRole) -> Option<String>;
    /// `Wallet::card_details` (`wallet::app_card`).
    fn card_details(&self, step: &CardStep) -> Vec<String>;
    /// `Wallet::card_tick` (`wallet::app_card`).
    fn card_tick(&mut self, now: u64);
    /// `Wallet::btc_network_now` (`wallet::app_chain_sites`).
    fn btc_network_now(&self) -> BtcNetwork;
    /// `Wallet::btc_dapp_rows` (`wallet::app_chain_sites`).
    fn btc_dapp_rows(&self) -> Vec<BtcRow>;
    /// `Wallet::chain_unlocked_refusal` (`wallet::app_chain_sites`).
    fn chain_unlocked_refusal(&self, site: &SiteRequest) -> Option<ProviderError>;
    /// `Wallet::sol_connect_waits_for_account` (`wallet::app_chain_sites`).
    fn sol_connect_waits_for_account(&self) -> bool;
    /// `Wallet::chain_connect_choices` (`wallet::app_chain_sites`).
    fn chain_connect_choices(&self, site: &SiteRequest) -> (Vec<ConnectEntry>, Vec<bool>, String);
    /// `Wallet::btc_connect_choices` (`wallet::app_chain_sites`).
    fn btc_connect_choices(
        &self,
        origin: &BrowserOrigin,
        purposes: &[BtcPurpose],
    ) -> (Vec<ConnectEntry>, Vec<bool>, String);
    /// `Wallet::chain_connect_approved` (`wallet::app_chain_sites`).
    fn chain_connect_approved(&mut self, site: &SiteRequest, choices: &[ConnectChoice]);
    /// `Wallet::chain_site_preflight` (`wallet::app_chain_sites`).
    #[expect(
        clippy::option_option,
        reason = "not-mine / passed / finished, as `Wallet::chain_site_preflight` returns it"
    )]
    fn chain_site_preflight(&mut self, site: &SiteRequest) -> Option<Option<QueueOutcome>>;
    /// `Wallet::chain_sign_draft` (`wallet::app_chain_sites`).
    fn chain_sign_draft(&self, site: &SiteRequest) -> Option<ApprovalDraft>;
    /// `Wallet::chain_waiter` (`wallet::app_chain_sites`).
    fn chain_waiter(site: &SiteRequest, payload: &SigningPayload) -> Option<SignWaiter>
    where
        Self: Sized;
    /// `Wallet::sol_grant_holds` (`wallet::app_chain_sites`).
    fn sol_grant_holds(&self, origin: &BrowserOrigin, public: &[u8; 32]) -> bool;
    /// `Wallet::browser_chain_message_signed` (`wallet::app_chain_sites`).
    fn browser_chain_message_signed(&mut self, signed: &ChainMessageSigned);
    /// `Wallet::sol_account_removed_from_sites` (`wallet::app_chain_sites`).
    fn sol_account_removed_from_sites(&mut self, public: &[u8; 32]);
    /// `Wallet::btc_addresses_removed_from_sites` (`wallet::app_chain_sites`).
    fn btc_addresses_removed_from_sites(&mut self, addresses: &[String]);
    /// `Wallet::evm_balance_tick` (`wallet::app_evm`).
    fn evm_balance_tick(&mut self, now: u64) -> bool;
    /// `Wallet::send_edit_wait_ms` (`wallet::app_evm`).
    fn send_edit_wait_ms(&self, recipient: bool) -> u64;
    /// `Wallet::on_send_timer` (`wallet::app_evm`).
    fn on_send_timer(&mut self);
    /// `Wallet::on_quote` (`wallet::app_evm`).
    fn on_quote(&mut self, job: u64, result: Result<Quote, ErrorCode>);
    /// `Wallet::account_source` (`wallet::app_evm`).
    fn account_source(&self, address: &Address) -> Option<EvmKeySource>;
    /// `Wallet::on_evm_edit` (`wallet::app_evm_commands`).
    fn on_evm_edit(&mut self, field: EditField, text: &str) -> bool;
    /// `Wallet::on_explorer_edit` (`wallet::app_explorer`).
    fn on_explorer_edit(&mut self, field: EditField, text: &str) -> bool;
    /// `Wallet::on_explorer` (`wallet::app_explorer`).
    fn on_explorer(&mut self, press: ExplorerPress);
    /// `Wallet::on_hidden` (`wallet::app_hidden`).
    fn on_hidden(&mut self, press: HiddenPress);
    /// `Wallet::on_hc_edit` (`wallet::app_hypercore`).
    fn on_hc_edit(&mut self, field: EditField, text: &str) -> bool;
    /// `Wallet::on_evm_raw_key_removed` (`wallet::app_keys`).
    fn on_evm_raw_key_removed(&mut self, id: RecordId);
    /// `Wallet::on_keys` (`wallet::app_keys`).
    fn on_keys(&mut self, press: KeysPress);
    /// `Wallet::on_llm_edit` (`wallet::app_llm`).
    fn on_llm_edit(&mut self, field: EditField, text: &str) -> bool;
    /// `Wallet::on_llm` (`wallet::app_llm`).
    fn on_llm(&mut self, press: LlmPress);
    /// `Wallet::llm_save` (`wallet::app_llm`).
    fn llm_save(&mut self);
    /// `Wallet::llm_store_key` (`wallet::app_llm`).
    fn llm_store_key(&mut self, key: &str);
    /// `Wallet::llm_test` (`wallet::app_llm`).
    fn llm_test(&mut self);
    /// `Wallet::evm_selected_gate` (`wallet::app_mnemonics`).
    fn evm_selected_gate(&self) -> Option<RecordId>;
    /// `Wallet::on_mn_edit` (`wallet::app_mnemonics`).
    fn on_mn_edit(&mut self, field: EditField, text: &str) -> bool;
    /// `Wallet::mn_hold_complete` (`wallet::app_mnemonics`).
    fn mn_hold_complete(&mut self, purpose: MnPurpose);
    /// `Wallet::on_mn_outcome` (`wallet::app_mnemonics`).
    fn on_mn_outcome(&mut self, outcome: MnOutcome, now: u64);
    /// `Wallet::request_meta` (`wallet::app_reset`).
    fn request_meta(&mut self);
    /// `Wallet::wait_tick` (`wallet::app_reset`).
    fn wait_tick(&mut self, now: u64);
    /// `Wallet::open_reset` (`wallet::app_reset`).
    fn open_reset(&mut self);
    /// `Wallet::cancel_reset` (`wallet::app_reset`).
    fn cancel_reset(&mut self);
    /// `Wallet::reset_phrase_changed` (`wallet::app_reset`).
    fn reset_phrase_changed(&mut self, text: &str);
    /// `Wallet::reset_execute` (`wallet::app_reset`).
    fn reset_execute(&mut self);
    /// `Wallet::on_wallet_reset` (`wallet::app_reset`).
    fn on_wallet_reset(&mut self, result: Result<ResetReport, ResetError>);
    /// `Wallet::reset_hold_tick` (`wallet::app_reset`).
    fn reset_hold_tick(&mut self, now: u64);
    /// `Wallet::on_reset` (`wallet::app_reset`).
    fn on_reset(&mut self, press: ResetPress);
    /// `Wallet::on_reset_edit` (`wallet::app_reset`).
    fn on_reset_edit(&mut self, field: EditField, text: &str) -> bool;
    /// `Wallet::sol_tick_tracking` (`wallet::app_sol`).
    fn sol_tick_tracking(&mut self, now: u64);
    /// `Wallet::on_sol_tracked` (`wallet::app_sol`).
    fn on_sol_tracked(&mut self, result: &TrackResult);
    /// `Wallet::on_sol_edit` (`wallet::app_sol_commands`).
    fn on_sol_edit(&mut self, field: EditField, text: &str) -> bool;
    /// `Wallet::on_sol` (`wallet::app_sol_commands`).
    fn on_sol(&mut self, press: SolPress);
    /// `Wallet::sol_dapp_refusal` (`wallet::app_sol_dapp`).
    fn sol_dapp_refusal(
        &self,
        public: &[u8; 32],
        cluster: SolCluster,
        mode: SolTxMode,
    ) -> Option<ProviderError>;
    /// `Wallet::sol_dapp_draft` (`wallet::app_sol_dapp`).
    ///
    /// # Errors
    ///
    /// As `Wallet::sol_dapp_draft`.
    fn sol_dapp_draft(
        &self,
        site: &SiteRequest,
        result: Result<DappPreview, ErrorCode>,
    ) -> Result<ApprovalDraft, (ErrorCode, bool)>;
    /// `Wallet::on_sol_dapp_presigned` (`wallet::app_sol_dapp`).
    fn on_sol_dapp_presigned(
        &mut self,
        job: u64,
        result: Result<(u64, PreSignCheck), PreSignError>,
    );
    /// `Wallet::on_sol_dapp_signed` (`wallet::app_sol_dapp`).
    fn on_sol_dapp_signed(&mut self, signed: SolDappSigned);
    /// `Wallet::sol_dapp_min_context_slot` (`wallet::app_sol_dapp`).
    fn sol_dapp_min_context_slot(&self, signature: &[u8; 64]) -> Option<u64>;
    /// `Wallet::wc_start` (`wallet::app_walletconnect`).
    fn wc_start(&mut self);
    /// `Wallet::wc_shutdown` (`wallet::app_walletconnect`).
    fn wc_shutdown(&mut self);
    /// `Wallet::on_wc_edit` (`wallet::app_walletconnect`).
    fn on_wc_edit(&mut self, field: EditField, text: &str) -> bool;
    /// `Wallet::yk_hold_complete` (`wallet::app_yubikey`).
    fn yk_hold_complete(&mut self, purpose: YkPurpose);
    /// `Wallet::yk_open_card_secret` (`wallet::app_yubikey`).
    fn yk_open_card_secret(&mut self, kind: CardSecretKind, purpose: YkPurpose, serial: u32);
    /// `Wallet::on_yk_edit` (`wallet::app_yubikey`).
    fn on_yk_edit(&mut self, field: EditField, text: &str) -> bool;
    /// `Wallet::on_zec_edit` (`wallet::app_zec`).
    fn on_zec_edit(&mut self, field: EditField, text: &str) -> bool;
    /// `Wallet::reads_due` (`wallet::mod`).
    fn reads_due(&mut self, now: u64);
    /// `Wallet::on_rpc_event` (`wallet::mod`).
    fn on_rpc_event(&mut self, network: NetworkId, message: String, ok: bool);
    /// `Wallet::secret_purpose` (`wallet::mod`).
    fn secret_purpose(&self) -> Option<Purpose>;
    /// `Wallet::secret_form` (`wallet::mod`).
    fn secret_form(&mut self, op: SecretFormOp);
    /// `Wallet::open_input` (`wallet::mod`).
    fn open_input(&mut self, kind: SecretKind, purpose: Purpose, topmost: bool);
    /// `Wallet::open_display` (`wallet::mod`).
    fn open_display(&mut self, kind: SecretKind, purpose: Purpose, display: DisplaySecret);
    /// `Wallet::save_meta` (`wallet::mod`).
    fn save_meta(&mut self);
    /// `Wallet::verify_settings` (`wallet::mod`).
    fn verify_settings(&mut self);
    /// `Wallet::on_field_edit` (`wallet::mod`).
    fn on_field_edit(&mut self, field: EditField, text: &str) -> bool;
    /// `Wallet::form_text` (`wallet::mod`).
    fn form_text(&self, field: EditField) -> Option<String>;
    /// `Wallet::set_rpc_message` (`wallet::mod`).
    fn set_rpc_message(&mut self, network: NetworkId, message: String, state: TestState);

    // 2026-11-23 (spec/15 §11.4 S5-0, §18 31 (가), 주인 결정(2026-11-23)): the three wallet
    // fields that frozen test bodies wrote or read as fields were `#[doc(hidden)] pub` from S4d E1
    // until the S4 freeze ended; they are `pub(crate)` and the tests reach them here.
    /// Gives the wallet the RPC worker's job queue (`Wallet::rpc_tx`).
    fn set_rpc_tx(&mut self, tx: Sender<RpcJob>);
    /// The lock epoch (`Wallet::lock_epoch`, read-only).
    fn lock_epoch(&self) -> u64;
    /// The last press (`Wallet::last_press`, read-only).
    fn last_press(&self) -> Press;
}

impl WalletTestExt for Wallet {
    fn card_begin(
        &mut self,
        approved: Approved,
        kind: CardJobKind,
        ticket: Option<SignTicket>,
    ) -> Result<(), Box<Approved>> {
        Self::card_begin(self, approved, kind, ticket)
    }

    fn card_submit(&mut self, id: u64, pin: Zeroizing<Vec<u8>>) {
        Self::card_submit(self, id, pin);
    }

    fn card_cancel(&mut self, id: u64) {
        Self::card_cancel(self, id);
    }

    fn dispatch_evm_sign(
        &mut self,
        ticket: SignTicket,
        approved: Approved,
        info: SignInfo,
        form: bool,
    ) {
        Self::dispatch_evm_sign(self, ticket, approved, info, form);
    }

    fn sol_dapp_consumed(&mut self, approved: Approved, site: &SiteRequest) {
        Self::sol_dapp_consumed(self, approved, site);
    }

    fn push_sign_waiter(&mut self, waiter: SignWaiter) -> SignTicket {
        Self::push_sign_waiter(self, waiter)
    }

    fn begin_secret(&mut self, kind: SecretKind, purpose: Purpose, topmost: bool) -> u64 {
        Self::begin_secret(self, kind, purpose, topmost)
    }

    fn on_submit(&mut self, purpose: Purpose, submission: Submission) {
        Self::on_submit(self, purpose, submission);
    }

    fn on_cancel(&mut self, purpose: Purpose) {
        Self::on_cancel(self, purpose);
    }

    fn take_display_secret(&mut self, serial: u64) -> Option<DisplaySecret> {
        Self::take_display_secret(self, serial)
    }

    fn secret_session(&self) -> Option<&SecretSession> {
        self.test_secret_session()
    }

    fn set_secret_session(&mut self, session: Option<SecretSession>) {
        self.test_set_secret_session(session);
    }

    fn mark_secret_shown(&mut self) {
        if let Some(session) = self.test_open_secret_session() {
            drop(session.mark_shown());
        }
    }

    fn hold_display_secret(&mut self, display: DisplaySecret) {
        if let Some(session) = self.test_open_secret_session() {
            session.hold_display(display);
        }
    }

    fn then_when_secret_shown(&mut self, after: AfterShown) {
        if let Some(session) = self.test_open_secret_session() {
            session.then_when_shown(after);
        }
    }

    fn secret_serial(&self) -> u64 {
        self.test_secret_serial()
    }

    fn evm_store(&self) -> &ApprovalStore {
        &self.evm.store
    }

    fn evm_store_mut(&mut self) -> StoreProbe<'_> {
        StoreProbe {
            store: &mut self.evm.store,
        }
    }

    fn import_held(&self) -> (bool, bool) {
        self.test_import_held()
    }

    fn challenge(&self) -> Option<BackupChallenge> {
        self.test_challenge()
    }

    #[cfg(debug_assertions)]
    fn mn_holds(&self) -> (bool, bool) {
        self.mn.test_holds()
    }

    #[cfg(debug_assertions)]
    fn yk_wizard_holds_secret(&self) -> bool {
        self.card
            .wizard
            .as_ref()
            .is_some_and(crate::wallet::app_yubikey::YkWizard::test_holds_secret)
    }

    fn outbox(&self) -> &VecDeque<Effect> {
        &self.outbox
    }

    fn take_outbox(&mut self) -> Vec<Effect> {
        self.outbox.drain(..).collect()
    }

    fn requeue_effects(&mut self, batch: Vec<Effect>) {
        self.outbox.extend(batch);
    }

    fn swap_press_input(&mut self, input: PressInput) -> PressInput {
        core::mem::replace(&mut self.input, input)
    }

    fn take_press_cred(&mut self, field: CredField) -> Zeroizing<Vec<u16>> {
        self.input.take(field)
    }

    #[cfg(debug_assertions)]
    fn press_input_misses(&self) -> u32 {
        self.input.misses()
    }

    fn idle_mut(&mut self) -> &mut IdleTracker {
        &mut self.idle
    }

    fn services_mut(&mut self) -> &mut Services {
        &mut self.services
    }

    fn after_open_steps(&self) -> &[(ShownId, AfterOpen)] {
        &self.evm.after_open
    }

    fn keep_after_open(&mut self, shown: ShownId, after: AfterOpen) {
        self.evm.after_open.push((shown, after));
    }

    fn open_unanswered(&self) -> Option<ShownId> {
        self.evm.open_unanswered
    }

    fn set_open_unanswered(&mut self, shown: Option<ShownId>) {
        self.evm.open_unanswered = shown;
    }

    fn settings_verified(&self) -> bool {
        self.guard.verified
    }

    fn set_settings_verified(&mut self, verified: bool) {
        self.guard.verified = verified;
    }

    fn settings_saved_early(&self) -> &[&'static str] {
        &self.guard.saved_early
    }

    fn settings_rollback(&self) -> Option<(u64, u64)> {
        self.guard.rollback
    }

    fn show_next_approval_then(&mut self, after: AfterOpen) {
        Self::show_next_approval_then(self, after);
    }

    fn after_pending_open(&mut self, after: AfterOpen) {
        Self::after_pending_open(self, after);
    }

    fn connect_state(&self, site: &SiteRequest) -> ConnectState {
        Self::connect_state(self, site)
    }

    fn on_approval_opened(&mut self, shown: ShownId, outcome: OpenOutcome, wide: bool) {
        Self::on_approval_opened(self, shown, outcome, wide);
    }

    fn message_chain_failure(
        &self,
        chain_id: u64,
    ) -> Option<crate::flow::evm::prepare::PrepareFailure> {
        Self::message_chain_failure(self, chain_id)
    }

    fn finish_approval(&mut self, outcome: QueueOutcome) {
        Self::finish_approval(self, outcome);
    }

    fn show_ready_draft(
        &mut self,
        draft: yw_core::approval::ApprovalDraft,
        prepared: Option<Box<Prepared>>,
    ) {
        Self::show_ready_draft(self, draft, prepared);
    }

    fn on_book_edit(&mut self, field: EditField, text: &str) -> bool {
        Self::on_book_edit(self, field, text)
    }

    fn on_book(&mut self, press: BookPress) {
        Self::on_book(self, press);
    }

    fn on_links(&mut self, press: LinksPress) {
        Self::on_links(self, press);
    }

    fn vault_view(&self) -> VaultView {
        Self::vault_view(self)
    }

    fn wallet_view(&self) -> WalletView {
        Self::wallet_view(self)
    }

    fn write_grants(&mut self) {
        Self::write_grants(self);
    }

    fn browser_vault_loaded(&mut self) {
        Self::browser_vault_loaded(self);
    }

    fn unlocked_refusal(&self, site: &SiteRequest) -> Option<ProviderError> {
        Self::unlocked_refusal(self, site)
    }

    fn refuse_site(&mut self, site: &SiteRequest, error: ProviderError) {
        Self::refuse_site(self, site, error);
    }

    fn site_preflight(&mut self, site: &SiteRequest) -> Option<QueueOutcome> {
        Self::site_preflight(self, site)
    }

    fn hardware_site_accounts(&self) -> Option<HardwareSiteAccounts> {
        Self::hardware_site_accounts(self)
    }

    fn connect_approved(&mut self, site: &SiteRequest, accounts: Vec<Address>, chain_id: u64) {
        Self::connect_approved(self, site, accounts, chain_id);
    }

    fn browser_tx_signed(&mut self, ticket: SignTicket, result: Result<[u8; 32], ()>) {
        Self::browser_tx_signed(self, ticket, result);
    }

    fn browser_message_signed(&mut self, signed: MessageSigned) {
        Self::browser_message_signed(self, signed);
    }

    fn browser_sign_cancelled(&mut self, ticket: SignTicket) {
        Self::browser_sign_cancelled(self, ticket);
    }

    fn browser_broadcast(&mut self, tx_hash: [u8; 32], outcome: BroadcastOutcome) {
        Self::browser_broadcast(self, tx_hash, outcome);
    }

    fn on_sites(&mut self, press: SitesPress) {
        Self::on_sites(self, press);
    }

    fn btc_apply_field(&mut self, field: EditField, text: &str) {
        Self::btc_apply_field(self, field, text);
    }

    fn on_btc_edit(&mut self, field: EditField, text: &str) -> bool {
        Self::on_btc_edit(self, field, text)
    }

    fn on_btc(&mut self, press: BtcPress) {
        Self::on_btc(self, press);
    }

    fn card_after_meta(&mut self) {
        Self::card_after_meta(self);
    }

    fn evm_selected_card_gate(&self) -> Option<u32> {
        Self::evm_selected_card_gate(self)
    }

    fn card_step_card(&self, role: KeyRole) -> Option<String> {
        Self::card_step_card(self, role)
    }

    fn card_details(&self, step: &CardStep) -> Vec<String> {
        Self::card_details(self, step)
    }

    fn card_tick(&mut self, now: u64) {
        Self::card_tick(self, now);
    }

    fn btc_network_now(&self) -> BtcNetwork {
        Self::btc_network_now(self)
    }

    fn btc_dapp_rows(&self) -> Vec<BtcRow> {
        Self::btc_dapp_rows(self)
    }

    fn chain_unlocked_refusal(&self, site: &SiteRequest) -> Option<ProviderError> {
        Self::chain_unlocked_refusal(self, site)
    }

    fn sol_connect_waits_for_account(&self) -> bool {
        Self::sol_connect_waits_for_account(self)
    }

    fn chain_connect_choices(&self, site: &SiteRequest) -> (Vec<ConnectEntry>, Vec<bool>, String) {
        Self::chain_connect_choices(self, site)
    }

    fn btc_connect_choices(
        &self,
        origin: &BrowserOrigin,
        purposes: &[BtcPurpose],
    ) -> (Vec<ConnectEntry>, Vec<bool>, String) {
        Self::btc_connect_choices(self, origin, purposes)
    }

    fn chain_connect_approved(&mut self, site: &SiteRequest, choices: &[ConnectChoice]) {
        Self::chain_connect_approved(self, site, choices);
    }

    fn chain_site_preflight(&mut self, site: &SiteRequest) -> Option<Option<QueueOutcome>> {
        Self::chain_site_preflight(self, site)
    }

    fn chain_sign_draft(&self, site: &SiteRequest) -> Option<ApprovalDraft> {
        Self::chain_sign_draft(self, site)
    }

    fn chain_waiter(site: &SiteRequest, payload: &SigningPayload) -> Option<SignWaiter> {
        Self::chain_waiter(site, payload)
    }

    fn sol_grant_holds(&self, origin: &BrowserOrigin, public: &[u8; 32]) -> bool {
        Self::sol_grant_holds(self, origin, public)
    }

    fn browser_chain_message_signed(&mut self, signed: &ChainMessageSigned) {
        Self::browser_chain_message_signed(self, signed);
    }

    fn sol_account_removed_from_sites(&mut self, public: &[u8; 32]) {
        Self::sol_account_removed_from_sites(self, public);
    }

    fn btc_addresses_removed_from_sites(&mut self, addresses: &[String]) {
        Self::btc_addresses_removed_from_sites(self, addresses);
    }

    fn evm_balance_tick(&mut self, now: u64) -> bool {
        Self::evm_balance_tick(self, now)
    }

    fn send_edit_wait_ms(&self, recipient: bool) -> u64 {
        Self::send_edit_wait_ms(self, recipient)
    }

    fn on_send_timer(&mut self) {
        Self::on_send_timer(self);
    }

    fn on_quote(&mut self, job: u64, result: Result<Quote, ErrorCode>) {
        Self::on_quote(self, job, result);
    }

    fn account_source(&self, address: &Address) -> Option<EvmKeySource> {
        Self::account_source(self, address)
    }

    fn on_evm_edit(&mut self, field: EditField, text: &str) -> bool {
        Self::on_evm_edit(self, field, text)
    }

    fn on_explorer_edit(&mut self, field: EditField, text: &str) -> bool {
        Self::on_explorer_edit(self, field, text)
    }

    fn on_explorer(&mut self, press: ExplorerPress) {
        Self::on_explorer(self, press);
    }

    fn on_hidden(&mut self, press: HiddenPress) {
        Self::on_hidden(self, press);
    }

    fn on_hc_edit(&mut self, field: EditField, text: &str) -> bool {
        Self::on_hc_edit(self, field, text)
    }

    fn on_evm_raw_key_removed(&mut self, id: RecordId) {
        Self::on_evm_raw_key_removed(self, id);
    }

    fn on_keys(&mut self, press: KeysPress) {
        Self::on_keys(self, press);
    }

    fn on_llm_edit(&mut self, field: EditField, text: &str) -> bool {
        Self::on_llm_edit(self, field, text)
    }

    fn on_llm(&mut self, press: LlmPress) {
        Self::on_llm(self, press);
    }

    fn llm_save(&mut self) {
        Self::llm_save(self);
    }

    fn llm_store_key(&mut self, key: &str) {
        Self::llm_store_key(self, key);
    }

    fn llm_test(&mut self) {
        Self::llm_test(self);
    }

    fn evm_selected_gate(&self) -> Option<RecordId> {
        Self::evm_selected_gate(self)
    }

    fn on_mn_edit(&mut self, field: EditField, text: &str) -> bool {
        Self::on_mn_edit(self, field, text)
    }

    fn mn_hold_complete(&mut self, purpose: MnPurpose) {
        Self::mn_hold_complete(self, purpose);
    }

    fn on_mn_outcome(&mut self, outcome: MnOutcome, now: u64) {
        Self::on_mn_outcome(self, outcome, now);
    }

    fn request_meta(&mut self) {
        Self::request_meta(self);
    }

    fn wait_tick(&mut self, now: u64) {
        Self::wait_tick(self, now);
    }

    fn open_reset(&mut self) {
        Self::open_reset(self);
    }

    fn cancel_reset(&mut self) {
        Self::cancel_reset(self);
    }

    fn reset_phrase_changed(&mut self, text: &str) {
        Self::reset_phrase_changed(self, text);
    }

    fn reset_execute(&mut self) {
        Self::reset_execute(self);
    }

    fn on_wallet_reset(&mut self, result: Result<ResetReport, ResetError>) {
        Self::on_wallet_reset(self, result);
    }

    fn reset_hold_tick(&mut self, now: u64) {
        Self::reset_hold_tick(self, now);
    }

    fn on_reset(&mut self, press: ResetPress) {
        Self::on_reset(self, press);
    }

    fn on_reset_edit(&mut self, field: EditField, text: &str) -> bool {
        Self::on_reset_edit(self, field, text)
    }

    fn sol_tick_tracking(&mut self, now: u64) {
        Self::sol_tick_tracking(self, now);
    }

    fn on_sol_tracked(&mut self, result: &TrackResult) {
        Self::on_sol_tracked(self, result);
    }

    fn on_sol_edit(&mut self, field: EditField, text: &str) -> bool {
        Self::on_sol_edit(self, field, text)
    }

    fn on_sol(&mut self, press: SolPress) {
        Self::on_sol(self, press);
    }

    fn sol_dapp_refusal(
        &self,
        public: &[u8; 32],
        cluster: SolCluster,
        mode: SolTxMode,
    ) -> Option<ProviderError> {
        Self::sol_dapp_refusal(self, public, cluster, mode)
    }

    fn sol_dapp_draft(
        &self,
        site: &SiteRequest,
        result: Result<DappPreview, ErrorCode>,
    ) -> Result<ApprovalDraft, (ErrorCode, bool)> {
        Self::sol_dapp_draft(self, site, result)
    }

    fn on_sol_dapp_presigned(
        &mut self,
        job: u64,
        result: Result<(u64, PreSignCheck), PreSignError>,
    ) {
        Self::on_sol_dapp_presigned(self, job, result);
    }

    fn on_sol_dapp_signed(&mut self, signed: SolDappSigned) {
        Self::on_sol_dapp_signed(self, signed);
    }

    fn sol_dapp_min_context_slot(&self, signature: &[u8; 64]) -> Option<u64> {
        Self::sol_dapp_min_context_slot(self, signature)
    }

    fn wc_start(&mut self) {
        Self::wc_start(self);
    }

    fn wc_shutdown(&mut self) {
        Self::wc_shutdown(self);
    }

    fn on_wc_edit(&mut self, field: EditField, text: &str) -> bool {
        Self::on_wc_edit(self, field, text)
    }

    fn yk_hold_complete(&mut self, purpose: YkPurpose) {
        Self::yk_hold_complete(self, purpose);
    }

    fn yk_open_card_secret(&mut self, kind: CardSecretKind, purpose: YkPurpose, serial: u32) {
        Self::yk_open_card_secret(self, kind, purpose, serial);
    }

    fn on_yk_edit(&mut self, field: EditField, text: &str) -> bool {
        Self::on_yk_edit(self, field, text)
    }

    fn on_zec_edit(&mut self, field: EditField, text: &str) -> bool {
        Self::on_zec_edit(self, field, text)
    }

    fn reads_due(&mut self, now: u64) {
        Self::reads_due(self, now);
    }

    fn on_rpc_event(&mut self, network: NetworkId, message: String, ok: bool) {
        Self::on_rpc_event(self, network, message, ok);
    }

    fn secret_purpose(&self) -> Option<Purpose> {
        Self::secret_purpose(self)
    }

    fn secret_form(&mut self, op: SecretFormOp) {
        Self::secret_form(self, op);
    }

    fn open_input(&mut self, kind: SecretKind, purpose: Purpose, topmost: bool) {
        Self::open_input(self, kind, purpose, topmost);
    }

    fn open_display(&mut self, kind: SecretKind, purpose: Purpose, display: DisplaySecret) {
        Self::open_display(self, kind, purpose, display);
    }

    fn save_meta(&mut self) {
        Self::save_meta(self);
    }

    fn verify_settings(&mut self) {
        Self::verify_settings(self);
    }

    fn on_field_edit(&mut self, field: EditField, text: &str) -> bool {
        Self::on_field_edit(self, field, text)
    }

    fn form_text(&self, field: EditField) -> Option<String> {
        Self::form_text(self, field)
    }

    fn set_rpc_message(&mut self, network: NetworkId, message: String, state: TestState) {
        Self::set_rpc_message(self, network, message, state);
    }

    fn set_rpc_tx(&mut self, tx: Sender<RpcJob>) {
        self.rpc_tx = Some(tx);
    }

    fn lock_epoch(&self) -> u64 {
        self.lock_epoch
    }

    fn last_press(&self) -> Press {
        self.last_press
    }
}

/// The approval flow's state as the yw-app tests and the render harness read it (read-only;
/// preflight critic C3). Before E1 these were `cfg(test)` accessors and `ApprovalPaint` fields.
pub trait FlowTestExt {
    /// The interaction session (read-only).
    fn session(&self) -> &ApprovalSession;
    /// The status message.
    fn status(&self) -> Option<&str>;
    /// The early-release line is shown.
    fn early_release(&self) -> bool;
    /// The view's revision.
    fn view_rev(&self) -> u64;
    /// The current preparation job id.
    fn job(&self) -> u64;
    /// The preparation of a transaction.
    fn prepared(&self) -> Option<&Prepared>;
    /// The one issued request (read-only; no store, so nothing can be consumed with it).
    fn issued(&self) -> Option<&ApprovalRequest>;
    /// The raw-data section is open.
    fn raw_open(&self) -> bool;
    /// The paint's test facts: the shown content, the interaction's status, a hold under way.
    fn paint_test_facts(&self) -> (&PrepareState, InteractionStatus, bool);
    /// `ApprovalFlow::lang`: the shown approval's language (2026-11-23, S4d final review: was a
    /// `#[doc(hidden)] pub` method; the three below too).
    fn lang(&self) -> Lang;
    /// `ApprovalFlow::connect`: the connect window's choices.
    fn connect(&self) -> Option<&ConnectState>;
    /// `ApprovalFlow::ai`: the AI explanation's state.
    fn ai(&self) -> Option<&AiFlow>;
}

/// A card step's facts as the yw-app tests read them (2026-11-23, S4d final review: was a
/// `#[doc(hidden)] pub` method).
pub trait CardStepTestExt {
    /// `CardStep::holds_approval`: the step still holds its `Approved` (a flag only).
    fn holds_approval(&self) -> bool;
}

impl CardStepTestExt for CardStep {
    fn holds_approval(&self) -> bool {
        Self::holds_approval(self)
    }
}

impl FlowTestExt for ApprovalFlow {
    fn session(&self) -> &ApprovalSession {
        Self::session(self)
    }

    fn status(&self) -> Option<&str> {
        Self::status(self)
    }

    fn early_release(&self) -> bool {
        Self::early_release(self)
    }

    fn view_rev(&self) -> u64 {
        Self::view_rev(self)
    }

    fn job(&self) -> u64 {
        Self::job(self)
    }

    fn prepared(&self) -> Option<&Prepared> {
        Self::prepared(self)
    }

    fn issued(&self) -> Option<&ApprovalRequest> {
        Self::issued(self)
    }

    fn raw_open(&self) -> bool {
        Self::raw_open(self)
    }

    fn paint_test_facts(&self) -> (&PrepareState, InteractionStatus, bool) {
        Self::paint_test_facts(self)
    }

    fn lang(&self) -> Lang {
        Self::lang(self)
    }

    fn connect(&self) -> Option<&ConnectState> {
        Self::connect(self)
    }

    fn ai(&self) -> Option<&AiFlow> {
        Self::ai(self)
    }
}

/// A secret session the tests set up (`SecretSession::new`, crate-private).
#[must_use]
pub fn secret_session(
    serial: u64,
    kind: SecretKind,
    purpose: Purpose,
    topmost: bool,
) -> SecretSession {
    SecretSession::new(serial, kind, purpose, topmost)
}

/// A secret session's state changes the tests make on a session of their own, not the wallet's
/// (crate-private on `SecretSession`; 2026-11-23, S4d E1 review: `mark_shown` and
/// `then_when_shown` were `#[doc(hidden)] pub` inherent methods at E1, so this trait was not the
/// only way to them as documented; they are `pub(crate)` now, and `hold_display`, which no test
/// calls on a session of its own any more, left the trait).
pub trait SessionTestExt {
    /// `SecretSession::mark_shown`: the window was shown; its kept step comes back.
    fn mark_shown(&mut self) -> Option<AfterShown>;
    /// `SecretSession::then_when_shown`: a step kept for the window's `Shown`.
    fn then_when_shown(&mut self, after: AfterShown);
}

impl SessionTestExt for SecretSession {
    fn mark_shown(&mut self) -> Option<AfterShown> {
        Self::mark_shown(self)
    }

    fn then_when_shown(&mut self, after: AfterShown) {
        Self::then_when_shown(self, after);
    }
}

/// The wallet's issued approvals as [`WalletTestExt::evm_store_mut`] hands them to a test
/// (2026-11-23, S4d E1 review): it issues, rejects and consumes on the real store, and gives back
/// outcomes only. A consume's `Approved` is dropped here, so neither the store nor an `Approved`
/// leaves the engine through it.
pub struct StoreProbe<'a> {
    store: &'a mut ApprovalStore,
}

/// The name only (the store's entries are not printed).
impl std::fmt::Debug for StoreProbe<'_> {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.debug_struct("StoreProbe").finish_non_exhaustive()
    }
}

/// A consume went through (the `Approved` was made and dropped inside [`StoreProbe::consume`]).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Consumed;

impl StoreProbe<'_> {
    /// `ApprovalStore::issue` on the wallet's store.
    ///
    /// # Errors
    ///
    /// The store's [`ApprovalError`].
    pub fn issue(
        &mut self,
        draft: ApprovalDraft,
        now_ms: u64,
        now_unix_ms: u64,
    ) -> Result<ApprovalRequest, ApprovalError> {
        self.store.issue(draft, now_ms, now_unix_ms)
    }

    /// `ApprovalStore::reject` on the wallet's store.
    pub fn reject(&mut self, id: ApprovalId) {
        self.store.reject(id);
    }

    /// `ApprovalStore::consume` on the wallet's store, outcome only.
    ///
    /// # Errors
    ///
    /// The store's [`ApprovalError`] (the entry's state changes as the store's own consume
    /// changes it).
    pub fn consume(
        &mut self,
        id: ApprovalId,
        shown: [u8; 32],
        now_ms: u64,
    ) -> Result<Consumed, ApprovalError> {
        self.store.consume(id, shown, now_ms).map(|approved| {
            drop(approved);
            Consumed
        })
    }
}

// ----- The recording shell of both reply schedules (2026-11-23, spec/15 §11.4 S4d E2) ----------
//
// Plan §3.7 and D-25, the S4d preflight's corrected row E2 (O-5): the same wallet logic runs under
// the shell's two reply schedules. `Immediate` is the Windows schedule (`App::drain`: the effects
// an entry queued are applied inside its borrow, one at a time, and each answer goes back to the
// wallet at once, before the next effect is applied). `Deferred` is the Android schedule of
// spec/15 §3.2 (`call` returns, the shell takes the effects with `next()`, applies them and sends
// each answer later with `ioComplete`): the entry's effects are held until it returned, then
// applied in order, and only then do their answers go back, each an entry of its own whose
// effects are held and applied in turn. `RecordingShell` holds the effects and runs those rounds;
// a [`ShellHost`] applies them (the yw-app tests: the Windows shell's own executor with its
// headless hosts; the engine tests: the shell model below, [`RecordingShell::entry`]). Nothing
// here makes a window, touches a file, the network, the clipboard or a card reader, and no
// secret is kept: a display secret the model takes for a verified window is wiped at once.

use crate::approval::flow::ApprovalEffect;
use crate::cmd::Cmd;
use crate::effect::Folder;
use crate::secret::SecretEffect;
use crate::wallet::DisplayCheck;

/// When a shell applies the effects one entry queued, and when their answers go back.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Schedule {
    /// Windows (`App::drain`): inside the entry's borrow, in order, each answer back at once.
    Immediate,
    /// Android (spec/15 §3.2): after the entry returned; the batch first, then its answers, each
    /// an entry of its own.
    Deferred,
}

/// The part of a shell that applies effects for a [`RecordingShell`] (tests only).
pub trait ShellHost {
    /// The wallet the effects came from.
    fn wallet(&mut self) -> &mut Wallet;
    /// Applies `batch` in order, as the shell does, and returns the answers in order. None of
    /// them has gone back to the wallet yet.
    fn apply_batch(&mut self, batch: Vec<Effect>) -> Vec<Cmd>;
}

/// The shell of both reply schedules (tests only; see the comment above).
pub struct RecordingShell {
    schedule: Schedule,
    /// Effects the wallet queued that this shell has not applied yet (`Deferred`).
    held: VecDeque<Effect>,
    /// The shell has not run yet: held effects stay held across later entries until
    /// [`Self::release`] (the Android UI thread busy while the next event already reached the
    /// wallet).
    keep: bool,
    /// The model's approval opens are refused (`Failed(E-APP-009)`).
    refuse_approval: bool,
    /// What the model applied and answered, in order (names, serials and lengths only).
    log: Vec<String>,
}

/// The schedule and the counts only.
impl std::fmt::Debug for RecordingShell {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("RecordingShell")
            .field("schedule", &self.schedule)
            .field("held", &self.held.len())
            .field("keep", &self.keep)
            .finish_non_exhaustive()
    }
}

impl RecordingShell {
    /// A shell of `schedule` with nothing held.
    #[must_use]
    pub const fn new(schedule: Schedule) -> Self {
        Self {
            schedule,
            held: VecDeque::new(),
            keep: false,
            refuse_approval: false,
            log: Vec::new(),
        }
    }

    /// The schedule.
    #[must_use]
    pub const fn schedule(&self) -> Schedule {
        self.schedule
    }

    /// Keeps held effects held across later entries (`true`) until [`Self::release`], or settles
    /// after each entry again (`false`).
    pub const fn keep(&mut self, on: bool) {
        self.keep = on;
    }

    /// Whether held effects stay held across entries.
    #[must_use]
    pub const fn keeps(&self) -> bool {
        self.keep
    }

    /// The model refuses its approval opens from now on (`Failed(E-APP-009)`), or makes them.
    pub const fn refuse_approval(&mut self, on: bool) {
        self.refuse_approval = on;
    }

    /// How many effects are held.
    #[must_use]
    pub fn held(&self) -> usize {
        self.held.len()
    }

    /// Takes every effect `wallet` queued into the held list, in order (the end of an entry under
    /// `Deferred`).
    pub fn hold(&mut self, wallet: &mut Wallet) {
        while let Some(effect) = wallet.next_effect() {
            self.held.push_back(effect);
        }
    }

    /// The held effects, taken out in order.
    pub fn take_held(&mut self) -> Vec<Effect> {
        self.held.drain(..).collect()
    }

    /// Applies what is held through `host` in rounds until nothing is: each round applies the
    /// held batch, then hands each answer back to the wallet as an entry of its own and holds what
    /// that entry queued (spec/15 §3.2 `next` then `ioComplete`). Stops keeping (`keep(false)`).
    pub fn release<H: ShellHost + ?Sized>(&mut self, host: &mut H) {
        self.keep = false;
        loop {
            let batch = self.take_held();
            if batch.is_empty() {
                return;
            }
            for answer in host.apply_batch(batch) {
                let wallet = host.wallet();
                wallet.on_cmd(answer);
                self.hold(wallet);
            }
        }
    }

    /// One shell entry into `wallet` with the shell model applying the effects: `step` runs, then
    /// [`Self::end_entry`].
    pub fn entry(&mut self, wallet: &mut Wallet, step: impl FnOnce(&mut Wallet)) {
        step(wallet);
        self.end_entry(wallet);
    }

    /// The end of a shell entry with the shell model: [`Self::drain`], then under `Deferred` the
    /// release (unless [`Self::keep`] is on).
    pub fn end_entry(&mut self, wallet: &mut Wallet) {
        self.drain(wallet);
        if self.schedule == Schedule::Deferred && !self.keep {
            self.release_model(wallet);
        }
    }

    /// A drain with the shell model, as `App::drain` (also the mid-entry drain of a shell
    /// composition, the lock's `Suspend` wait): `Immediate` applies the queued effects one at a
    /// time and hands each answer back at once; `Deferred` holds them (an Android shell applies
    /// nothing inside an entry).
    pub fn drain(&mut self, wallet: &mut Wallet) {
        match self.schedule {
            Schedule::Immediate => {
                while let Some(effect) = wallet.next_effect() {
                    if let Some(answer) = self.apply(wallet, effect) {
                        self.log.push(format!("={}", answer_name(&answer)));
                        wallet.on_cmd(answer);
                    }
                }
            }
            Schedule::Deferred => self.hold(wallet),
        }
    }

    /// [`Self::release`] with the shell model applying the effects.
    pub fn release_model(&mut self, wallet: &mut Wallet) {
        self.keep = false;
        loop {
            let batch = self.take_held();
            if batch.is_empty() {
                return;
            }
            let answers: Vec<Cmd> = batch
                .into_iter()
                .filter_map(|effect| self.apply(wallet, effect))
                .collect();
            for answer in answers {
                self.log.push(format!("={}", answer_name(&answer)));
                wallet.on_cmd(answer);
                self.hold(wallet);
            }
        }
    }

    /// The model's log since the last call: each effect applied (`effect_name`) and each answer
    /// as it went back (`=` and `answer_name`), in order.
    pub fn take_log(&mut self) -> Vec<String> {
        std::mem::take(&mut self.log)
    }

    /// The shell model: applies `effect` the way the Windows shell's executor answers it in the
    /// yw-app headless tests, without a window, and returns the answer. A screen, a timer, a
    /// field, a scroll, a hold or a lock wait has no window here (no answer, `FieldShown` for a
    /// field write: the edit shows what was written); a copy and a link succeed; an extension
    /// folder is not found; an approval open makes its window while it is the shown flow's (as
    /// the headless approval host, `Shown { capture_excluded: false }`, wide), else
    /// `Failed(E-APP-009)`; a secret window is made and its capture exclusion verified while its
    /// serial is the open, unshown session (else `Refused(E-SEC-001)`, critique A-3), and a
    /// display window's secret is handed over only then (`DisplayCheck::Verified`) and wiped at
    /// once.
    pub fn apply(&mut self, wallet: &mut Wallet, effect: Effect) -> Option<Cmd> {
        self.log.push(effect_name(&effect));
        match effect {
            Effect::SetField { field, text } => Some(Cmd::FieldShown {
                field,
                text: Some(field.clamp(&text)),
            }),
            Effect::ClearField { field } => Some(Cmd::FieldShown { field, text: None }),
            Effect::CopyText { mark, .. } => Some(Cmd::CopyDone { ok: true, mark }),
            Effect::OpenUrl { which, .. } => Some(Cmd::Opened { ok: true, which }),
            Effect::OpenFolder(Folder::Extension) => Some(Cmd::FolderMissing),
            Effect::Approval(ApprovalEffect::Open { shown, .. }) => {
                let current = wallet
                    .evm
                    .approval
                    .as_ref()
                    .map(crate::wallet::approval_flow::ApprovalFlow::shown);
                let made = !self.refuse_approval && current == Some(shown);
                Some(Cmd::ApprovalOpened {
                    shown,
                    outcome: if made {
                        OpenOutcome::Shown {
                            capture_excluded: false,
                        }
                    } else {
                        OpenOutcome::Failed(ErrorCode::App009)
                    },
                    wide: made,
                })
            }
            Effect::Secret(SecretEffect::OpenInput { serial, .. }) => Some(Cmd::SecretOpened {
                serial,
                outcome: if wallet.secret_unshown(serial) {
                    OpenOutcome::Shown {
                        capture_excluded: true,
                    }
                } else {
                    OpenOutcome::Refused(ErrorCode::Sec001)
                },
            }),
            Effect::Secret(SecretEffect::OpenDisplay { serial, .. }) => {
                let shown = wallet.secret_unshown(serial)
                    && wallet
                        .hand_display_secret(serial, DisplayCheck::Verified)
                        .is_some_and(|display| {
                            // The model's window: the secret is wiped here, never kept.
                            drop(display);
                            true
                        });
                if shown {
                    self.log.push(format!("display-handed#{serial}"));
                }
                Some(Cmd::SecretOpened {
                    serial,
                    outcome: if shown {
                        OpenOutcome::Shown {
                            capture_excluded: true,
                        }
                    } else {
                        OpenOutcome::Refused(ErrorCode::Sec001)
                    },
                })
            }
            // No answer: a screen, a credential edit, a timer, the main window's own work, a
            // scroll, a hold, the lock's wait, the data and log folders, the other approval and
            // secret operations (close, rebuild, repaint, form, clip clear).
            Effect::Render
            | Effect::ClearCred { .. }
            | Effect::StartTimer { .. }
            | Effect::StopTimer { .. }
            | Effect::Reveal(_)
            | Effect::RaiseMain
            | Effect::ScreenLeaving { .. }
            | Effect::ScreenEntered { .. }
            | Effect::OverlayClosedInPlace
            | Effect::TabTop { .. }
            | Effect::ScrollMemoryClear
            | Effect::ScrollTop
            | Effect::ReleaseHold
            | Effect::AwaitKeyLock { .. }
            | Effect::OpenFolder(Folder::Data | Folder::Logs)
            | Effect::Approval(_)
            | Effect::Secret(_) => None,
        }
    }
}

/// An effect's name for the logs (names, ids, serials and lengths only, never text).
#[must_use]
pub fn effect_name(effect: &Effect) -> String {
    match effect {
        Effect::Render => "render".to_owned(),
        Effect::SetField { field, .. } => format!("set-field:{field:?}"),
        Effect::ClearField { field } => format!("clear-field:{field:?}"),
        Effect::ClearCred { field } => format!("clear-cred:{field:?}"),
        Effect::StartTimer { .. } => "timer-start".to_owned(),
        Effect::StopTimer { .. } => "timer-stop".to_owned(),
        Effect::CopyText { text, .. } => format!("copy:len={}", text.chars().count()),
        Effect::Approval(approval) => match *approval {
            ApprovalEffect::Open { shown, .. } => format!("open#{}", shown.0),
            ApprovalEffect::Close { shown } => format!("close#{}", shown.0),
            ApprovalEffect::Rebuilt { shown, changed } => {
                format!("{}#{}", if changed { "rebuilt" } else { "same" }, shown.0)
            }
            ApprovalEffect::RepaintBar { shown } => format!("bar#{}", shown.0),
            ApprovalEffect::Redraw { shown } => format!("redraw#{}", shown.0),
            ApprovalEffect::RepaintAi { shown, .. } => format!("ai#{}", shown.0),
        },
        Effect::OpenUrl { url, .. } => format!("open-url:len={}", url.len()),
        Effect::OpenFolder(folder) => format!("open-folder:{folder:?}"),
        Effect::Reveal(_) => "reveal".to_owned(),
        Effect::RaiseMain => "raise-main".to_owned(),
        Effect::ScreenLeaving { .. } => "screen-leaving".to_owned(),
        Effect::ScreenEntered { .. } => "screen-entered".to_owned(),
        Effect::OverlayClosedInPlace => "overlay-closed".to_owned(),
        Effect::TabTop { .. } => "tab-top".to_owned(),
        Effect::ScrollMemoryClear => "scroll-memory-clear".to_owned(),
        Effect::ScrollTop => "scroll-top".to_owned(),
        Effect::ReleaseHold => "release-hold".to_owned(),
        Effect::Secret(secret) => match secret {
            SecretEffect::OpenInput { serial, .. } => format!("secret-open#{serial}"),
            SecretEffect::OpenDisplay { serial, .. } => format!("secret-display#{serial}"),
            SecretEffect::Close { serial } => format!("secret-close#{serial}"),
            SecretEffect::Form { serial, .. } => format!("secret-form#{serial}"),
            SecretEffect::ClearClip { .. } => "clear-clip".to_owned(),
        },
        Effect::AwaitKeyLock { .. } => "wait".to_owned(),
    }
}

/// An answer's name for the logs (names, ids, serials and outcomes only).
#[must_use]
pub fn answer_name(answer: &Cmd) -> String {
    match answer {
        Cmd::ApprovalOpened { shown, outcome, .. } => format!("opened#{}:{outcome:?}", shown.0),
        Cmd::SecretOpened { serial, outcome } => format!("secret-opened#{serial}:{outcome:?}"),
        Cmd::FieldShown { field, .. } => format!("field-shown:{field:?}"),
        Cmd::CopyDone { ok, .. } => format!("copy-done:{ok}"),
        Cmd::Opened { ok, .. } => format!("url-opened:{ok}"),
        Cmd::FolderMissing => "folder-missing".to_owned(),
        other => format!("{other:?}"),
    }
}

/// A waiting Solana dApp send as the frozen lock test builds it (critic C2 ii): the engine's
/// `PendingDappSign` keeps its approval and PIN private.
#[must_use]
pub fn pending_dapp_sign(
    ticket: SignTicket,
    approved: Box<Approved>,
    pin: Option<PinBuffer>,
    origin: String,
) -> PendingDappSign {
    PendingDappSign::new(ticket, approved, pin, origin)
}
