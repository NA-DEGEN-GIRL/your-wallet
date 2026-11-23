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
// `ApprovalStore` and `consume` out of yw-app's code). The review also found that E1 had added two accessors beyond the preflight's
// recommendations that handed out the store itself (`&mut ApprovalStore`, from which `consume`
// makes an `Approved`) and the secret session slot (`&mut Option<SecretSession>`); they are
// replaced by [`StoreProbe`], which returns outcomes only, and by four setup steps that only put
// state in. Still, an `Approved` is made only by an `ApprovalStore`'s `consume` (yw-core).

use yw_core::approval::{
    ApprovalDraft, ApprovalError, ApprovalId, ApprovalRequest, ApprovalStore, Approved,
};
use yw_core::vault::BackupChallenge;

use crate::approval::interaction::{ApprovalSession, InteractionStatus, PrepareState};
use crate::browser::SiteRequest;
use crate::events::{SignInfo, SignTicket};
use crate::flow::evm::prepare::Prepared;
use crate::secret::{DisplaySecret, SecretKind, Submission};
use crate::wallet::app_browser::SignWaiter;
use crate::wallet::app_card::{CardJobKind, PinBuffer};
use crate::wallet::app_sol_dapp::PendingDappSign;
use crate::wallet::approval_flow::ApprovalFlow;
use crate::wallet::secret_session::{AfterShown, SecretSession};
use crate::wallet::{Purpose, Wallet};

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

use std::collections::VecDeque;

use crate::approval::flow::{ApprovalEffect, OpenOutcome};
use crate::cmd::Cmd;
use crate::effect::{Effect, Folder};
use crate::errors::ErrorCode;
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
