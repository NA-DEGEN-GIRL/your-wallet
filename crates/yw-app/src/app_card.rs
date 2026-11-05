//! The `YubiKey` card step after approval (spec/10 §9.2, §10) and the enrolment entry point the
//! wizard calls (spec/10 §7).
//!
//! An approval whose signer is a `YubiKey` key (EVM `EvmKeySource::Hardware`, Solana
//! `SolKeySource::Hardware`, a Bitcoin account `BtcAccountKey::Hardware`, a Solana/Bitcoin dApp
//! message of such a source) is consumed as usual, then held here instead of going to the
//! software signing job: the PIN window W11 (`SecretKind::CardPin`, `Purpose::CardSign`) opens,
//! and its submitted PIN — a `Zeroizing` buffer moved straight into the card job and wiped with
//! it, never kept between operations — goes with the approval to `SignEvmCard`,
//! `SignMessageCard`, `SignChainMessageCard`, `SignSolCard` (after the blockhash) or
//! `SignBtcCard`. Cancelling the window drops the approval and answers a dApp with 4001: nothing
//! is signed.
//!
//! The card step has its own bound of 120 s from the approval (spec/10 §10). The key worker
//! checks the PIN on the card before the approval is used; a wrong PIN, another card or no card
//! returns the unused approval (`KeyOutcome::CardUnused`) and the window opens again with the
//! reason while the step is still within its bound (a blocked PIN ends it). Every other result
//! flows through the existing signing outcomes.

use yw_core::approval::Approved;
use yw_core::secret::Zeroizing;
use yw_core::yubikey::CardError;
use yw_core::yubikey::plan::{KeyRole, PlannedSlot};
use yw_core::yubikey::record::HwKeyRecord;

use crate::app::{App, Purpose};
use crate::events::{
    ChainMessageSigned, EvmSigned, KeyJob, KeyOutcome, MessageSigned, SignInfo, SignTicket,
    YubiKeyJobError,
};
use crate::logging::{self, Field};
use crate::ui::secret::SecretKind;
use crate::yubikey::CardJobError;

/// The card step's own bound after the approval click (spec/10 §10: PIN entry and touch).
pub const CARD_STEP_MS: u64 = 120_000;

/// What a held approval is signed with once the PIN is in.
#[derive(Clone, Debug)]
pub enum CardJobKind {
    /// An EVM transaction (`SignEvmCard`, the `Signed` journal commit).
    EvmTx {
        /// Record fields.
        info: SignInfo,
    },
    /// `personal_sign` / `eth_signTypedData_v4` (`SignMessageCard`).
    EvmMessage {
        /// Typed data.
        typed: bool,
    },
    /// A Solana or Bitcoin dApp message (`SignChainMessageCard`).
    ChainMessage,
    /// A SOL transfer: the blockhash is fetched after the PIN, then `SignSolCard`.
    SolTransfer {
        /// Cluster of the transfer.
        cluster: yw_core::sol::SolCluster,
    },
    /// A BTC send (`SignBtcCard`, one card signature per input).
    Btc {
        /// The approved plan.
        plan: Box<yw_core::btc::SendPlan>,
        /// Core tip of the plan.
        tip_height: u32,
    },
}

/// One approval waiting for (or signing with) the card.
pub struct CardStep {
    /// Step id (`Purpose::CardSign`).
    pub id: u64,
    /// The consumed approval while the PIN is awaited (`None` while the card job runs).
    pub approved: Option<Box<Approved>>,
    /// Its id (matches the approval coming back from the worker).
    pub approval_id: yw_core::approval::ApprovalId,
    /// What to dispatch.
    pub kind: CardJobKind,
    /// The waiter of EVM / message jobs.
    pub ticket: Option<SignTicket>,
    /// The key on the card.
    pub role: KeyRole,
    /// Monotonic deadline of the card step.
    pub deadline_ms: u64,
    /// Card signatures the operation needs (Bitcoin inputs).
    pub touches: u8,
    /// Why the PIN is asked again (the previous attempt's card error).
    pub error: Option<String>,
    /// The worker returned the approval for a retry: its failure outcome is not shown.
    pub swallow_failure: bool,
}

impl core::fmt::Debug for CardStep {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter
            .debug_struct("CardStep")
            .field("id", &self.id)
            .field("waiting_pin", &self.approved.is_some())
            .finish_non_exhaustive()
    }
}

/// A PIN held between the PIN window and the job that needs a network answer first (the SOL
/// blockhash): wiped on drop, never printed.
pub struct PinBuffer(Zeroizing<Vec<u8>>);

impl PinBuffer {
    /// Wraps a PIN buffer.
    #[must_use]
    pub const fn new(pin: Zeroizing<Vec<u8>>) -> Self {
        Self(pin)
    }

    /// Moves the buffer out (into a key job).
    #[must_use]
    pub fn into_inner(self) -> Zeroizing<Vec<u8>> {
        self.0
    }
}

impl core::fmt::Debug for PinBuffer {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter.write_str("PinBuffer([REDACTED])")
    }
}

/// What the enrolment wizard hands to [`App::enrol_yubikey`]: every secret is moved into the
/// `EnrolYubiKey` job and wiped with it.
pub struct EnrolRequest {
    /// Mnemonic text (entered once).
    pub phrase: Zeroizing<Vec<u8>>,
    /// Optional BIP39 passphrase.
    pub passphrase: Option<Zeroizing<Vec<u8>>>,
    /// The validated slot plan.
    pub slots: Vec<PlannedSlot>,
    /// `OpenPGP` admin PIN (PW3).
    pub admin_pin: Zeroizing<Vec<u8>>,
    /// PIV management key bytes (empty without PIV slots).
    pub management_key: Zeroizing<Vec<u8>>,
}

impl core::fmt::Debug for EnrolRequest {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(
            formatter,
            "EnrolRequest({} slots, [REDACTED])",
            self.slots.len()
        )
    }
}

/// The last enrolment as the wizard shows it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum EnrolState {
    /// `EnrolYubiKey` queued.
    Running,
    /// Enrolled: the card serial, its slot count and the defaults-to-change lines (spec/10
    /// §9.3; empty when nothing was left at its default).
    Done {
        /// Serial.
        serial: u32,
        /// Slots written.
        slots: usize,
        /// "기본값을 바꾸세요" lines.
        defaults: Vec<String>,
    },
    /// Failed (the text to show; spec/10 §7.4: earlier slots may be written).
    Failed(String),
}

/// `YubiKey` UI state.
#[derive(Debug, Default)]
pub struct CardUi {
    /// The approval in the card step (one at a time).
    pub step: Option<CardStep>,
    next_id: u64,
    /// The enrolled cards' slot maps (vault tag 5; refreshed after unlock and enrolment).
    pub records: Vec<HwKeyRecord>,
    /// The last enrolment.
    pub enrol: Option<EnrolState>,
    /// Keys of the last enrolment: their hidden accounts become visible at the next meta load.
    pending_unhide: Vec<KeyRole>,
    /// The vault record ids of [`CardUi::records`] (same order).
    pub record_ids: Vec<yw_core::vault::RecordId>,
    /// The enrolment wizard (spec/10 §7).
    pub wizard: Option<crate::app_yubikey::YkWizard>,
    /// The record `삭제` was pressed for.
    pub remove_target: Option<yw_core::vault::RecordId>,
    /// A card enrolled with factory defaults before the meta existed (new `YubiKey` wallet):
    /// joins `hw_accounts.defaults` at the next meta load.
    pending_default: Option<u32>,
}

impl CardUi {
    /// Forgets everything of the unlocked session (the held approval, the wizard and their
    /// buffers are dropped).
    pub fn clear(&mut self) {
        self.step = None;
        self.records.clear();
        self.record_ids.clear();
        self.enrol = None;
        self.wizard = None;
        self.remove_target = None;
        self.pending_default = None;
        self.pending_unhide.clear();
    }
}

/// The defaults-to-change lines of an enrolment (spec/10 §9.3).
#[must_use]
pub fn defaults_lines(defaults: yw_core::yubikey::enrol::DefaultsSeen) -> Vec<String> {
    let mut lines = Vec::new();
    if defaults.openpgp_admin {
        lines.push(
            "OpenPGP 관리자 PIN이 기본값(12345678)입니다. 사용자 PIN(기본 123456)과 함께 바꾸세요."
                .to_owned(),
        );
    }
    if defaults.piv_pin {
        lines.push("PIV PIN이 기본값(123456)입니다. PIN과 PUK를 바꾸세요.".to_owned());
    }
    if defaults.piv_management {
        lines.push(
            "PIV 관리 키가 기본값입니다. 새 관리 키로 바꾸고 적어 두세요(이 지갑은 관리 키를 저장하지 않습니다)."
                .to_owned(),
        );
    }
    lines
}

/// The approval window's `YubiKey` badge (spec/10 §10): `YubiKey로 서명`, the cards holding the
/// key and the touches the operation needs. It is app chrome next to the header badges; it is
/// not part of the digested display (spec/03 §11.3), which stays exactly the core's.
#[must_use]
pub fn card_badge(records: &[HwKeyRecord], role: KeyRole, touches: usize) -> String {
    let serials = crate::yubikey::holders(records, role);
    let mut text = "YubiKey로 서명".to_owned();
    if !serials.is_empty() {
        let list: Vec<String> = serials.iter().map(|serial| format!("#{serial}")).collect();
        text.push_str(" · ");
        text.push_str(&list.join(", "));
    }
    text.push_str(" · 터치 ");
    text.push_str(&touches.max(1).to_string());
    text.push('회');
    text
}

fn job_error_text(error: YubiKeyJobError) -> String {
    match error {
        YubiKeyJobError::Key(error) => crate::errors::key_code(error).text(),
        YubiKeyJobError::Vault(error) => crate::errors::vault_code(error).text(),
        YubiKeyJobError::Card(error) => error.to_string(),
    }
}

/// Whether the PIN window may open again after a refused PIN check (a blocked PIN, an internal
/// error or an enrolment error end the step).
const fn retryable(error: CardJobError) -> bool {
    !matches!(
        error,
        CardJobError::Card(CardError::PinBlocked | CardError::Internal) | CardJobError::Enrol(_)
    )
}

fn now_ms() -> u64 {
    yw_win::time::monotonic_ms()
}

fn now_unix_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |elapsed| {
            u64::try_from(elapsed.as_millis()).unwrap_or(u64::MAX)
        })
}

impl App {
    // ----- enrolment entry point (the wizard, spec/10 §7) ------------------------------------

    /// Enrols the inserted `YubiKey` (spec/10 §7.3): queues `KeyJob::EnrolYubiKey` with the
    /// request's buffers (moved, wiped with the job). The result arrives in
    /// [`App::on_yubikey_enrolled`]: the accounts are reconciled from vault tag 5 (meta reload)
    /// and [`CardUi::enrol`] tells the wizard the serial and the defaults to change.
    pub fn enrol_yubikey(&mut self, request: EnrolRequest) {
        let EnrolRequest {
            phrase,
            passphrase,
            slots,
            admin_pin,
            management_key,
        } = request;
        self.card.enrol = Some(EnrolState::Running);
        self.key(KeyJob::EnrolYubiKey {
            phrase,
            passphrase,
            slots,
            admin_pin,
            management_key,
        });
    }

    /// `EnrolYubiKey` finished: on success the card's serial joins `hw_accounts.defaults` when a
    /// factory default was seen, the enrolled keys' accounts are shown again if hidden, and the
    /// accounts are refreshed (`HardwareKeys` + `LoadMeta`, which reconciles EVM, Solana and
    /// Bitcoin accounts from the slot map).
    pub fn on_yubikey_enrolled(
        &mut self,
        result: Result<
            (yw_core::vault::RecordId, yw_core::yubikey::enrol::Enrolled),
            YubiKeyJobError,
        >,
    ) {
        self.yk_enrolled(&result);
        match result {
            Ok((_, enrolled)) => {
                let serial = enrolled.record.serial;
                let defaults = defaults_lines(enrolled.defaults);
                if !defaults.is_empty() && self.meta.is_none() {
                    self.card.pending_default = Some(serial);
                }
                logging::info(
                    "app",
                    "yubikey.enrolled",
                    &[(
                        "slots",
                        Field::Num(u64::try_from(enrolled.record.slots.len()).unwrap_or(0)),
                    )],
                );
                if !defaults.is_empty()
                    && let Some(meta) = self.meta.as_mut()
                    && !meta.hw_accounts.defaults.contains(&serial)
                {
                    meta.hw_accounts.defaults.push(serial);
                    meta.hw_accounts.defaults.sort_unstable();
                    meta.hw_accounts.defaults.truncate(8);
                    self.save_meta();
                }
                self.card.pending_unhide =
                    enrolled.record.slots.iter().map(|slot| slot.role).collect();
                self.card.enrol = Some(EnrolState::Done {
                    serial,
                    slots: enrolled.record.slots.len(),
                    defaults: defaults.clone(),
                });
                let mut text = format!(
                    "YubiKey #{serial}을(를) 등록했습니다 (슬롯 {}개).",
                    enrolled.record.slots.len()
                );
                for line in &defaults {
                    text.push(' ');
                    text.push_str(line);
                }
                if self.card.wizard.is_none() {
                    self.info = Some(text);
                }
                self.key(KeyJob::HardwareKeys);
                self.key(KeyJob::LoadMeta);
            }
            Err(error) => {
                logging::info("app", "yubikey.enrol_failed", &[]);
                let text = job_error_text(error);
                self.card.enrol = Some(EnrolState::Failed(text.clone()));
                // The wizard's result screen shows it (with the §7.4 note).
                if self.card.wizard.is_none() {
                    self.banner(None, text);
                }
            }
        }
        self.refresh();
    }

    /// After a meta load: the slot maps for the PIN window, and the accounts of the last
    /// enrolment shown again.
    pub(crate) fn card_after_meta(&mut self) {
        self.key(KeyJob::HardwareKeys);
        if let Some(serial) = self.card.pending_default.take()
            && let Some(meta) = self.meta.as_mut()
            && !meta.hw_accounts.defaults.contains(&serial)
        {
            meta.hw_accounts.defaults.push(serial);
            meta.hw_accounts.defaults.sort_unstable();
            meta.hw_accounts.defaults.truncate(8);
            self.save_meta();
        }
        let roles = core::mem::take(&mut self.card.pending_unhide);
        if roles.is_empty() {
            return;
        }
        let Some(meta) = self.meta.as_mut() else {
            return;
        };
        let mut changed = false;
        for role in roles {
            let (list, index) = match role {
                KeyRole::Evm { index, .. } => (&mut meta.hw_accounts.evm, index.get()),
                KeyRole::Sol { index } => (&mut meta.hw_accounts.sol, index.get()),
                KeyRole::Btc { .. } => continue,
            };
            for account in list.iter_mut().filter(|account| account.index == index) {
                changed |= account.hidden;
                account.hidden = false;
            }
        }
        if changed {
            self.save_meta();
        }
    }

    /// `HardwareKeys` finished.
    pub(crate) fn on_hardware_keys(
        &mut self,
        result: Result<Vec<yw_core::vault::HardwareKey>, yw_core::error::VaultError>,
    ) {
        if let Ok(keys) = result {
            self.card.record_ids = keys.iter().map(|key| key.id).collect();
            self.card.records = keys.into_iter().map(|key| key.record).collect();
            self.refresh();
        }
    }

    // ----- the card step ---------------------------------------------------------------------

    /// Whether an approval is signed on a `YubiKey` (its role), for the hand-off after consume.
    #[must_use]
    pub(crate) fn card_role(approved: &Approved, kind: &CardJobKind) -> Option<KeyRole> {
        match kind {
            CardJobKind::Btc { plan, .. } => crate::yubikey::btc_plan_role(plan),
            _ => crate::yubikey::approval_role(approved),
        }
    }

    /// Holds a consumed `YubiKey` approval and opens the PIN window (spec/10 §9.2). Returns the
    /// approval back when it is not a card approval (the caller signs it in software).
    pub(crate) fn card_begin(
        &mut self,
        approved: Approved,
        kind: CardJobKind,
        ticket: Option<SignTicket>,
    ) -> Result<(), Box<Approved>> {
        let Some(role) = Self::card_role(&approved, &kind) else {
            return Err(Box::new(approved));
        };
        let touches = match &kind {
            CardJobKind::Btc { plan, .. } => u8::try_from(plan.inputs().len()).unwrap_or(u8::MAX),
            _ => 1,
        };
        self.card.next_id = self.card.next_id.wrapping_add(1);
        if let Some(previous) = self.card.step.take() {
            // One card step at a time: an older one still waiting ends as cancelled.
            self.card_resolve_cancelled(previous);
        }
        self.card.step = Some(CardStep {
            id: self.card.next_id,
            approval_id: approved.id(),
            approved: Some(Box::new(approved)),
            kind,
            ticket,
            role,
            deadline_ms: now_ms().saturating_add(CARD_STEP_MS),
            touches,
            error: None,
            swallow_failure: false,
        });
        logging::info("app", "card.step", &[]);
        self.card_open_pin();
        Ok(())
    }

    /// The non-secret lines of the PIN window: the cards holding the key, the last error and
    /// the last-try warning.
    fn card_details(&self, step: &CardStep) -> Vec<String> {
        let serials = crate::yubikey::holders(&self.card.records, step.role);
        let mut lines = vec![format!(
            "서명할 키: {} ({})",
            step.role.title(),
            step.role.path_text()
        )];
        if serials.is_empty() {
            lines.push("이 키를 가진 YubiKey 기록을 아직 불러오지 못했습니다.".to_owned());
        } else {
            let list: Vec<String> = serials.iter().map(|serial| format!("#{serial}")).collect();
            lines.push(format!("이 키를 가진 YubiKey: {}", list.join(", ")));
        }
        if let Some(meta) = self.meta.as_ref()
            && serials
                .iter()
                .any(|serial| meta.hw_accounts.defaults.contains(serial))
        {
            lines.push(
                "기본 PIN 사용 중일 수 있습니다 — 등록 뒤 PIN을 바꾸세요(spec/10 §9.3).".to_owned(),
            );
        }
        lines
    }

    fn card_open_pin(&mut self) {
        let Some(step) = self.card.step.as_ref() else {
            return;
        };
        let (min, max) = crate::yubikey::pin_bounds(step.role);
        let kind = SecretKind::CardPin {
            min,
            max,
            touches: step.touches,
        };
        let details = self.card_details(step);
        let error = step.error.clone();
        let id = step.id;
        self.open_input(kind, Purpose::CardSign(id), true);
        self.with_form(|form| {
            form.set_details(details);
            form.set_error(error);
        });
    }

    /// Whether the card step `id` waits for its PIN (tests, the tour).
    #[must_use]
    pub fn card_waiting(&self, id: u64) -> bool {
        self.card
            .step
            .as_ref()
            .is_some_and(|step| step.id == id && step.approved.is_some())
    }

    /// The id of the card step waiting for its PIN, if any.
    #[must_use]
    pub fn card_waiting_id(&self) -> Option<u64> {
        self.card
            .step
            .as_ref()
            .filter(|step| step.approved.is_some())
            .map(|step| step.id)
    }

    /// W11 submitted: the PIN (moved) and the held approval go to the card job.
    pub(crate) fn card_submit(&mut self, id: u64, pin: Zeroizing<Vec<u8>>) {
        self.close_secret();
        let now = now_ms();
        let Some(step) = self.card.step.as_mut().filter(|step| step.id == id) else {
            drop(pin);
            return;
        };
        let Some(approved) = step.approved.take() else {
            drop(pin);
            return;
        };
        if now >= step.deadline_ms {
            drop(pin);
            drop(approved);
            if let Some(step) = self.card.step.take() {
                self.card_resolve_failed(
                    step,
                    "YubiKey 단계 시간(120초)이 지나 서명하지 않았습니다.",
                );
            }
            return;
        }
        step.error = None;
        let ticket = step.ticket;
        let kind = step.kind.clone();
        match kind {
            CardJobKind::EvmTx { info } => self.key(KeyJob::SignEvmCard {
                ticket: ticket.unwrap_or(SignTicket(0)),
                approved,
                info,
                pin,
            }),
            CardJobKind::EvmMessage { typed } => self.key(KeyJob::SignMessageCard {
                ticket: ticket.unwrap_or(SignTicket(0)),
                approved,
                typed,
                pin,
            }),
            CardJobKind::ChainMessage => self.key(KeyJob::SignChainMessageCard {
                ticket: ticket.unwrap_or(SignTicket(0)),
                approved,
                pin,
            }),
            CardJobKind::SolTransfer { cluster } => {
                // The SOL signing deadline runs from here: the blockhash is fetched now.
                self.sol_consumed_card(*approved, cluster, now, PinBuffer::new(pin));
            }
            CardJobKind::Btc { plan, tip_height } => self.key(KeyJob::SignBtcCard {
                approved,
                plan,
                tip_height,
                now_unix_ms: now_unix_ms(),
                pin,
            }),
        }
        self.info = Some("YubiKey가 깜박이면 터치하세요 (15초 안에).".to_owned());
        self.refresh();
    }

    /// W11 cancelled (or closed, or timed out): nothing is signed.
    pub(crate) fn card_cancel(&mut self, id: u64) {
        let Some(step) = self.card.step.take() else {
            return;
        };
        if step.id != id || step.approved.is_none() {
            self.card.step = Some(step);
            return;
        }
        self.card_resolve_cancelled(step);
        self.info = Some("YubiKey 서명을 취소했습니다. 아무것도 서명하지 않았습니다.".to_owned());
        self.refresh();
    }

    /// Ends a step whose approval was not used: a dApp gets 4001 (user rejected), the in-flight
    /// slot of the send is released.
    fn card_resolve_cancelled(&mut self, step: CardStep) {
        logging::info("app", "card.cancelled", &[]);
        let CardStep { ticket, kind, .. } = step;
        if let Some(ticket) = ticket {
            self.browser_sign_cancelled(ticket);
        }
        self.card_release(&kind);
    }

    /// Ends a step without a signature for another reason (`text` shown).
    fn card_resolve_failed(&mut self, step: CardStep, text: &str) {
        logging::info("app", "card.failed", &[]);
        let CardStep { ticket, kind, .. } = step;
        if let Some(ticket) = ticket {
            match kind {
                CardJobKind::EvmMessage { .. } => {
                    self.browser_message_signed(MessageSigned {
                        ticket,
                        result: Err(crate::events::MessageSignFailure::Card(CardJobError::Card(
                            CardError::Conditions,
                        ))),
                    });
                }
                CardJobKind::ChainMessage => {
                    self.browser_chain_message_signed(&ChainMessageSigned {
                        ticket,
                        result: Err(false),
                    });
                }
                _ => self.browser_tx_signed(ticket, Err(())),
            }
        }
        self.card_release(&kind);
        self.banner(None, text.to_owned());
        self.refresh();
    }

    fn card_release(&mut self, kind: &CardJobKind) {
        match kind {
            CardJobKind::EvmTx { .. } => self.evm.slots.clear(),
            CardJobKind::SolTransfer { .. } => self.sol.slot = None,
            CardJobKind::Btc { .. } => self.btc.slot = false,
            CardJobKind::EvmMessage { .. } | CardJobKind::ChainMessage => {}
        }
    }

    /// The worker returned an unused approval after a refused PIN check: while the step is
    /// within its bound and the error allows it, the PIN window opens again (the failure outcome
    /// that follows is then not shown); otherwise the approval is dropped and the failure is
    /// shown as usual.
    fn card_unused(&mut self, approved: Box<Approved>, error: CardJobError) {
        let now = now_ms();
        let Some(step) = self.card.step.as_mut() else {
            return;
        };
        if step.approved.is_some() || step.approval_id != approved.id() {
            return;
        }
        logging::info(
            "app",
            "card.pin_refused",
            &[(
                "error",
                Field::Word(match error {
                    CardJobError::Card(error) => error.log_name(),
                    CardJobError::NoCard => "no_card",
                    CardJobError::Enrol(_) => "enrol",
                }),
            )],
        );
        if !retryable(error) || now >= step.deadline_ms {
            return;
        }
        step.approved = Some(approved);
        step.swallow_failure = true;
        let mut text = error.to_string();
        if matches!(
            error,
            CardJobError::Card(CardError::WrongPin { retries: 1 })
        ) {
            text.push_str(" 한 번 더 틀리면 PIN이 잠깁니다.");
        }
        step.error = Some(text);
        self.card_open_pin();
    }

    /// Whether `outcome` is the final outcome of the card step's job.
    fn card_outcome_matches(step: &CardStep, outcome: &KeyOutcome) -> bool {
        match (&step.kind, outcome) {
            (CardJobKind::EvmTx { .. }, KeyOutcome::SignedEvm(EvmSigned { ticket, .. }))
            | (
                CardJobKind::EvmMessage { .. },
                KeyOutcome::SignedMessage(MessageSigned { ticket, .. }),
            )
            | (
                CardJobKind::ChainMessage,
                KeyOutcome::SignedChainMessage(ChainMessageSigned { ticket, .. }),
            ) => step.ticket == Some(*ticket),
            (CardJobKind::SolTransfer { .. }, KeyOutcome::SignedSol(_))
            | (CardJobKind::Btc { .. }, KeyOutcome::SignedBtc(_)) => true,
            _ => false,
        }
    }

    /// The card step's view of a key outcome, before the usual handling: `None` when it was
    /// taken here (a returned approval, or the failure of an attempt that is asked again).
    pub(crate) fn card_filter(&mut self, outcome: KeyOutcome) -> Option<KeyOutcome> {
        if let KeyOutcome::CardUnused(approved, error) = outcome {
            self.card_unused(approved, error);
            return None;
        }
        let Some(step) = self.card.step.as_mut() else {
            return Some(outcome);
        };
        if !Self::card_outcome_matches(step, &outcome) {
            return Some(outcome);
        }
        if step.swallow_failure {
            step.swallow_failure = false;
            return None;
        }
        if step.approved.is_none() {
            // The job ran: its outcome is final (shown by the usual handler).
            self.card.step = None;
        }
        Some(outcome)
    }

    /// Main timer: the card step's 120 s bound, and a PIN window that is gone (closed without
    /// a cancel, refused by capture exclusion) ends the step as cancelled.
    pub(crate) fn card_tick(&mut self, now: u64) {
        let Some(step) = self.card.step.as_ref() else {
            return;
        };
        if step.approved.is_none() {
            return;
        }
        let id = step.id;
        let expired = now >= step.deadline_ms;
        let window_gone = self.secret_purpose() != Some(Purpose::CardSign(id));
        if !expired && !window_gone {
            return;
        }
        if self.secret_purpose() == Some(Purpose::CardSign(id)) {
            self.close_secret();
        }
        if let Some(step) = self.card.step.take() {
            if expired {
                self.card_resolve_failed(
                    step,
                    "YubiKey 단계 시간(120초)이 지나 서명을 취소했습니다.",
                );
            } else {
                self.card_resolve_cancelled(step);
                self.refresh();
            }
        }
    }

    /// A SOL card transfer that will not reach the card (its blockhash step failed after the
    /// PIN): the in-flight step ends (the pending entry, with the PIN, is already dropped).
    pub(crate) fn card_abandon_sol(&mut self) {
        if self.card.step.as_ref().is_some_and(|step| {
            step.approved.is_none() && matches!(step.kind, CardJobKind::SolTransfer { .. })
        }) {
            self.card.step = None;
        }
    }

    /// Lock: the held approval and any PIN are dropped; a dApp waiter gets 4001.
    pub(crate) fn card_lock(&mut self) {
        if let Some(step) = self.card.step.take() {
            let waiting = step.approved.is_some();
            if waiting {
                self.card_resolve_cancelled(step);
            }
        }
        self.card.clear();
    }
}
