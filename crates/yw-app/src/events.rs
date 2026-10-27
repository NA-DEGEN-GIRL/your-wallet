//! Cross-thread queues (spec/04 §1.2–§1.3): the UI event queue with its doorbell message, and the
//! key worker's job queue where `Lock` jumps to the front and cancels everything still queued.
//! Secret buffers travel only by move inside `Zeroizing` values.

use std::collections::VecDeque;
use std::sync::{Condvar, Mutex};
use std::time::Duration;

use yw_core::approval::{Approved, TokenMeta};
use yw_core::error::{KeyError, VaultError};
use yw_core::evm::address::Address;
use yw_core::evm::amount::U256;
use yw_core::evm::sign::SignError;
use yw_core::journal::evm::{EvmRecord, GroupKey, Role, Transition};
use yw_core::secret::Zeroizing;
use yw_core::vault::{BackupChallenge, ChallengeId, EvmKeySource, FileKind, RecordId, VaultStatus};

use crate::errors::ErrorCode;
use crate::flow::evm::ChainCheck;
use crate::flow::evm::form::Quote;
use crate::flow::evm::prepare::{PrepareResult, ResimResult};
use crate::flow::evm::track::{BroadcastOutcome, TrackResult};
use crate::flow::evm::user_chain::ProbeError;
use crate::meta::{ActivityEntry, Meta};
use crate::network::NetworkId;

/// Event queue doorbell (`WM_APP + 1`).
pub const WM_YW_EVENTS: u32 = 0x8001;
/// Second instance → first instance (`WM_APP + 2`).
pub const WM_YW_ACTIVATE: u32 = 0x8002;
/// Secret window → main window (`WM_APP + 3`, wParam = window id).
pub const WM_YW_CHILD_DONE: u32 = 0x8003;
/// Ctrl+L observed by the message loop (`WM_APP + 4`).
pub const WM_YW_LOCK_SHORTCUT: u32 = 0x8004;
/// Event queue bound.
pub const EVENT_QUEUE_CAP: usize = 4_096;
/// Main window timer.
pub const MAIN_TIMER_MS: u32 = 250;

/// The secret being revealed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RevealWhat {
    /// The mnemonic (W08).
    Mnemonic,
    /// An EVM private key (W09).
    PrivateKey(EvmKeySource),
}

/// A key worker job (spec/04 §1.2). Buffers are moved, never copied.
pub enum KeyJob {
    /// `Vault::load` and report the status.
    Load,
    /// Create a 24-word wallet and write the default meta.
    CreateWallet {
        /// Vault password.
        password: Zeroizing<Vec<u8>>,
    },
    /// Hold the import buffers and compute account 0 without a vault.
    PreviewImport {
        /// Vault password (`None` = keep the one already held after a failed preview).
        password: Option<Zeroizing<Vec<u8>>>,
        /// Mnemonic text.
        phrase: Zeroizing<Vec<u8>>,
        /// BIP39 passphrase.
        passphrase: Option<Zeroizing<Vec<u8>>>,
    },
    /// Wipe the held mnemonic and passphrase (and the password unless `keep_password`).
    DiscardImport {
        /// Keep the password for another mnemonic attempt (`다릅니다`).
        keep_password: bool,
    },
    /// `Vault::import_mnemonic` with the held buffers, then the default meta.
    CommitImport,
    /// `Vault::unlock`.
    Unlock {
        /// Password.
        password: Zeroizing<Vec<u8>>,
    },
    /// `Vault::enter_passphrase`.
    EnterPassphrase {
        /// Passphrase.
        passphrase: Zeroizing<Vec<u8>>,
    },
    /// `Vault::retry_passphrase`.
    RetryPassphrase,
    /// `Vault::accept_mismatched_passphrase`.
    AcceptMismatch,
    /// `Vault::lock` (always first in the queue).
    Lock,
    /// `Vault::backup_challenge`.
    BackupChallenge,
    /// `Vault::confirm_backup`.
    ConfirmBackup {
        /// Challenge.
        id: ChallengeId,
        /// Four answers.
        words: [Zeroizing<Vec<u8>>; 4],
        /// Last 6 hex of account 0.
        suffix: Zeroizing<Vec<u8>>,
    },
    /// `reveal_mnemonic` / `reveal_evm_private_key`.
    Reveal {
        /// Password.
        password: Zeroizing<Vec<u8>>,
        /// What.
        what: RevealWhat,
    },
    /// `Vault::change_password`.
    ChangePassword {
        /// Current.
        old: Zeroizing<Vec<u8>>,
        /// New.
        new: Zeroizing<Vec<u8>>,
    },
    /// `Vault::import_evm_private_key`.
    ImportPrivateKey {
        /// 64 hex.
        hex: Zeroizing<Vec<u8>>,
    },
    /// `Vault::remove_evm_raw_key`.
    RemoveRawKey {
        /// Password.
        password: Zeroizing<Vec<u8>>,
        /// Record.
        id: RecordId,
    },
    /// `Vault::recover_from_prev`.
    RecoverFromPrev {
        /// Password.
        password: Zeroizing<Vec<u8>>,
    },
    /// Read meta (or the default), refresh the address caches.
    LoadMeta,
    /// Save meta.
    SaveMeta {
        /// The document.
        meta: Box<Meta>,
    },
    /// E-VLT-006 choice for a damaged sidecar: restore `.prev` or quarantine and start fresh.
    ResolveSidecar {
        /// File.
        kind: FileKind,
        /// `true` = use `.prev`.
        use_prev: bool,
    },
    /// Addresses for derived indices (account add).
    DeriveAddresses {
        /// Indices.
        indices: Vec<u32>,
    },
    /// Read the journal (after meta; spec/02 §5.4, spec/03 §5.4).
    LoadJournal,
    /// Sign an approved EVM transaction, verify it and commit the `Signed` record before anything
    /// is sent (spec/03 §4.2–§4.3, §5.3).
    SignEvm {
        /// The one-time approval (moved).
        approved: Box<Approved>,
        /// Record fields from the approval.
        info: SignInfo,
    },
    /// Sign an approved `personal_sign` or `eth_signTypedData_v4` (spec/03 §4.2, §9, §8).
    SignMessage {
        /// The one-time approval (moved).
        approved: Box<Approved>,
        /// `true` = typed data.
        typed: bool,
    },
    /// Apply and commit journal transitions (§5.2).
    JournalApply {
        /// Transitions.
        transitions: Vec<Transition>,
        /// Now.
        now_unix_ms: u64,
    },
    /// Stop the worker (after locking).
    Shutdown,
}

/// Journal record fields taken from the approval at signing time.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SignInfo {
    /// `"yw-app"` or the origin.
    pub origin: String,
    /// Approval title.
    pub label: String,
    /// Role.
    pub role: Role,
    /// Wall clock.
    pub now_unix_ms: u64,
}

/// The journal as the UI sees it (no secrets: signed transactions are public once sent).
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct JournalView {
    /// Decoded EVM records.
    pub records: Vec<EvmRecord>,
    /// EVM entries the decoder rejected ("저널 손상": EVM sending stops).
    pub corrupt: usize,
    /// A new EVM record fits after clean-up.
    pub room: bool,
}

/// A signed and journaled transaction ready to broadcast.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SignedSummary {
    /// Chain.
    pub chain_id: u64,
    /// Account.
    pub account: Address,
    /// Nonce.
    pub nonce: u64,
    /// Signed bytes.
    pub raw: Vec<u8>,
    /// Hash.
    pub tx_hash: [u8; 32],
}

/// Why signing produced nothing to send.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SignFailure {
    /// Signing or post-sign verification failed (E-TX-003; nothing stored or sent).
    Sign(SignError),
    /// No room in the journal (E-TX-005).
    JournalFull,
    /// The `Signed` record could not be committed ("저널 저장 실패"; nothing sent).
    JournalWrite(VaultError),
}

impl KeyJob {
    /// Static name for logs.
    #[must_use]
    pub const fn name(&self) -> &'static str {
        match self {
            Self::Load => "Load",
            Self::CreateWallet { .. } => "CreateWallet",
            Self::PreviewImport { .. } => "PreviewImport",
            Self::DiscardImport { .. } => "DiscardImport",
            Self::CommitImport => "CommitImport",
            Self::Unlock { .. } => "Unlock",
            Self::EnterPassphrase { .. } => "EnterPassphrase",
            Self::RetryPassphrase => "RetryPassphrase",
            Self::AcceptMismatch => "AcceptMismatch",
            Self::Lock => "Lock",
            Self::BackupChallenge => "BackupChallenge",
            Self::ConfirmBackup { .. } => "ConfirmBackup",
            Self::Reveal { .. } => "Reveal",
            Self::ChangePassword { .. } => "ChangePassword",
            Self::ImportPrivateKey { .. } => "ImportPrivateKey",
            Self::RemoveRawKey { .. } => "RemoveRawKey",
            Self::RecoverFromPrev { .. } => "RecoverFromPrev",
            Self::LoadMeta => "LoadMeta",
            Self::SaveMeta { .. } => "SaveMeta",
            Self::ResolveSidecar { .. } => "ResolveSidecar",
            Self::DeriveAddresses { .. } => "DeriveAddresses",
            Self::LoadJournal => "LoadJournal",
            Self::SignEvm { .. } => "SignEvm",
            Self::SignMessage { .. } => "SignMessage",
            Self::JournalApply { .. } => "JournalApply",
            Self::Shutdown => "Shutdown",
        }
    }

    const fn is_control(&self) -> bool {
        matches!(self, Self::Lock | Self::Shutdown)
    }
}

impl core::fmt::Debug for KeyJob {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter.write_str(self.name())
    }
}

/// A job that did not run because the wallet was locked first.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum KeyJobError {
    /// Cancelled by `Lock` (spec/04 §1.2; a yw-app error, not a yw-core one).
    Locked,
}

/// Meta after loading.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MetaLoaded {
    /// The document with refreshed address caches.
    pub meta: Meta,
    /// The caches had to be fixed (`MetaAddressMismatch`).
    pub mismatch: bool,
    /// `prefs` was reset.
    pub prefs_reset: bool,
}

/// What a key job produced.
pub enum KeyOutcome {
    /// Load status; `leftover` = meta/journal or their `.prev` exist without a vault.
    Loaded {
        /// Status.
        status: VaultStatus,
        /// Leftover sidecars.
        leftover: bool,
    },
    /// Wallet created: the phrase for W08 and account 0.
    Created(Result<(Zeroizing<String>, Address), VaultError>),
    /// Import preview.
    Preview(Result<Address, KeyError>),
    /// Import committed.
    Imported(Result<(), VaultError>),
    /// Unlock / recovery / passphrase steps: the new status.
    Status(Result<VaultStatus, VaultError>),
    /// Lock done.
    LockDone,
    /// Backup challenge.
    Challenge(Result<BackupChallenge, VaultError>),
    /// Backup confirmation.
    BackupConfirmed(Result<(), VaultError>),
    /// Revealed mnemonic (+ account 0) or private key.
    Revealed(Result<(RevealWhat, Zeroizing<String>, Option<Address>), VaultError>),
    /// Password changed.
    PasswordChanged(Result<(), VaultError>),
    /// Raw key imported.
    RawKeyImported(Result<(RecordId, Address), VaultError>),
    /// Raw key removed.
    RawKeyRemoved(Result<RecordId, VaultError>),
    /// Meta loaded.
    Meta(Result<MetaLoaded, VaultError>),
    /// Meta saved.
    MetaSaved(Result<(), VaultError>),
    /// Sidecar resolved.
    SidecarResolved(Result<(), ErrorCode>),
    /// Derived addresses (index, address).
    Addresses(Result<Vec<(u32, Address)>, VaultError>),
    /// Journal loaded or changed.
    Journal(Result<JournalView, VaultError>),
    /// `SignEvm` finished.
    SignedEvm(Result<SignedSummary, SignFailure>),
    /// `SignMessage` finished: the 65-byte `r ‖ s ‖ v` signature.
    SignedMessage(Result<[u8; 65], SignError>),
    /// Terminal journal records moved to activity (spec/03 §5.4).
    ActivityMoved(Vec<(NetworkId, ActivityEntry)>),
    /// The job was cancelled by `Lock`.
    Cancelled(&'static str, KeyJobError),
}

impl core::fmt::Debug for KeyOutcome {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter.write_str("KeyOutcome([REDACTED])")
    }
}

/// A key worker result with the lock epoch of its job (spec/04 §1.2).
#[derive(Debug)]
pub struct KeyResult {
    /// Epoch the job was queued in.
    pub epoch: u64,
    /// Outcome.
    pub outcome: KeyOutcome,
}

/// UI accepts a key result only from the current epoch (results from before a lock are dropped
/// and their buffers wiped by drop). `LockDone` is always accepted.
#[must_use]
pub fn accept_result(result: &KeyResult, current_epoch: u64) -> bool {
    matches!(
        result.outcome,
        KeyOutcome::LockDone
            | KeyOutcome::SignedEvm(_)
            | KeyOutcome::SignedMessage(_)
            | KeyOutcome::Cancelled("SignEvm" | "SignMessage", _)
    ) || result.epoch == current_epoch
}

/// The key worker's job queue.
#[derive(Debug, Default)]
pub struct KeyQueue {
    queue: Mutex<VecDeque<(u64, KeyJob)>>,
    ready: Condvar,
}

impl KeyQueue {
    /// Queues a job; `Lock` goes to the front.
    pub fn push(&self, epoch: u64, job: KeyJob) {
        if let Ok(mut queue) = self.queue.lock() {
            if matches!(job, KeyJob::Lock) {
                queue.push_front((epoch, job));
            } else {
                queue.push_back((epoch, job));
            }
        }
        self.ready.notify_one();
    }

    /// Blocks for the next job.
    pub fn pop(&self) -> Option<(u64, KeyJob)> {
        let mut queue = self.queue.lock().ok()?;
        loop {
            if let Some(job) = queue.pop_front() {
                return Some(job);
            }
            queue = self.ready.wait(queue).ok()?;
        }
    }

    /// Removes and returns every queued non-control job (processing `Lock`).
    pub fn cancel_pending(&self) -> Vec<(u64, KeyJob)> {
        let Ok(mut queue) = self.queue.lock() else {
            return Vec::new();
        };
        let mut cancelled = Vec::new();
        let mut kept = VecDeque::new();
        while let Some(entry) = queue.pop_front() {
            if entry.1.is_control() {
                kept.push_back(entry);
            } else {
                cancelled.push(entry);
            }
        }
        *queue = kept;
        cancelled
    }

    /// Number of queued jobs.
    #[must_use]
    pub fn len(&self) -> usize {
        self.queue.lock().map_or(0, |queue| queue.len())
    }

    /// Whether nothing is queued.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

/// Counts completed locks so the UI can wait for `LockDone` (suspend 1.5 s, shutdown 5 s).
#[derive(Debug, Default)]
pub struct LockSignal {
    done: Mutex<u64>,
    changed: Condvar,
}

impl LockSignal {
    /// Current count.
    #[must_use]
    pub fn count(&self) -> u64 {
        self.done.lock().map_or(0, |done| *done)
    }

    /// Worker: one more lock completed.
    pub fn signal(&self) {
        if let Ok(mut done) = self.done.lock() {
            *done = done.saturating_add(1);
        }
        self.changed.notify_all();
    }

    /// Waits until the count exceeds `before` or `timeout` passes; returns whether it did.
    #[must_use]
    pub fn wait_beyond(&self, before: u64, timeout: Duration) -> bool {
        let Ok(guard) = self.done.lock() else {
            return false;
        };
        self.changed
            .wait_timeout_while(guard, timeout, |done| *done <= before)
            .is_ok_and(|(done, _)| *done > before)
    }
}

/// Balances at one block (spec/04 §2.6).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BalanceSnapshot {
    /// Block number the values refer to.
    pub block: u64,
    /// Native balance per account.
    pub native: Vec<(Address, U256)>,
    /// Token balances of the selected account (`None` = lookup failed).
    pub tokens: Vec<(Address, Option<U256>)>,
}

/// An RPC worker result.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum RpcEvent {
    /// Endpoint `테스트` result (spec/04 §2.11.1).
    Test {
        /// Network tested.
        network: NetworkId,
        /// Fixed message (T-RPC-OK or an error text), never containing remote strings or URLs.
        message: String,
        /// Success.
        ok: bool,
    },
    /// A chain check result (spec/03 §1.4; a first-use pin is persisted by the UI).
    Chain {
        /// Chain.
        chain_id: u64,
        /// Result.
        check: ChainCheck,
    },
    /// Balances.
    Balances {
        /// Job.
        job: u64,
        /// Chain.
        chain_id: u64,
        /// Snapshot or error.
        result: Result<BalanceSnapshot, ErrorCode>,
    },
    /// Send-form fee quote.
    Quote {
        /// Job.
        job: u64,
        /// Quote or error.
        result: Result<Quote, ErrorCode>,
    },
    /// Recipient code check (W-ADDR-4).
    Code {
        /// Job.
        job: u64,
        /// Address.
        address: Address,
        /// Has code.
        result: Result<bool, ErrorCode>,
    },
    /// Token metadata (S16).
    TokenMeta {
        /// Job.
        job: u64,
        /// Token.
        token: Address,
        /// Metadata.
        result: Result<TokenMeta, ErrorCode>,
    },
    /// `eth_simulateV1` about to be sent (spec/04 §3.5 `Preparing(Simulating)`).
    Simulating {
        /// Job.
        job: u64,
        /// Monotonic start.
        since_ms: u64,
    },
    /// Preparation finished.
    Prepared(Box<PrepareResult>),
    /// Typed-data facts for a dApp signature.
    TypedFacts {
        /// Job.
        job: u64,
        /// Facts.
        facts: Box<yw_core::approval::ChainFacts>,
        /// The chain check made for them.
        check: ChainCheck,
    },
    /// Re-simulation finished.
    Resimulated(Box<ResimResult>),
    /// Broadcast finished.
    Broadcast {
        /// Chain.
        chain_id: u64,
        /// Hash.
        tx_hash: [u8; 32],
        /// Outcome.
        outcome: BroadcastOutcome,
        /// Observation time.
        at_unix_ms: u64,
    },
    /// A tracking round finished.
    Tracked {
        /// Group.
        key: GroupKey,
        /// Result.
        result: TrackResult,
    },
    /// User chain RPC check (S17, 다시 고정).
    Probe {
        /// Job.
        job: u64,
        /// Block-0 hash or error.
        result: Result<[u8; 32], ProbeError>,
    },
}

/// An event for the UI thread.
#[derive(Debug)]
pub enum UiEvent {
    /// Key worker result.
    Key(KeyResult),
    /// RPC worker result.
    Rpc(RpcEvent),
    /// Browser bridge event (spec/05).
    Dapp(crate::browser::DappEvent),
}

impl crate::browser::DappSink for EventQueue {
    fn push(&self, event: crate::browser::DappEvent) -> bool {
        Self::push(self, UiEvent::Dapp(event)).is_ok()
    }
}

/// The queue is full (E-APP-005).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct QueueFull;

/// The UI event queue: workers push, the UI thread drains on `WM_YW_EVENTS` and on its timer.
pub struct EventQueue {
    queue: Mutex<VecDeque<UiEvent>>,
    wake: Box<dyn Fn() + Send + Sync>,
}

impl core::fmt::Debug for EventQueue {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter.write_str("EventQueue")
    }
}

impl EventQueue {
    /// A queue whose doorbell is `wake` (posting `WM_YW_EVENTS`).
    #[must_use]
    pub fn new(wake: Box<dyn Fn() + Send + Sync>) -> Self {
        Self {
            queue: Mutex::new(VecDeque::new()),
            wake,
        }
    }

    /// Adds an event; rings the doorbell when the queue was empty.
    ///
    /// # Errors
    ///
    /// [`QueueFull`] at [`EVENT_QUEUE_CAP`].
    pub fn push(&self, event: UiEvent) -> Result<(), QueueFull> {
        let was_empty = {
            let mut queue = self.queue.lock().map_err(|_| QueueFull)?;
            if queue.len() >= EVENT_QUEUE_CAP {
                return Err(QueueFull);
            }
            let was_empty = queue.is_empty();
            queue.push_back(event);
            was_empty
        };
        if was_empty {
            (self.wake)();
        }
        Ok(())
    }

    /// Takes all events (UI thread only).
    #[must_use]
    pub fn drain(&self) -> Vec<UiEvent> {
        self.queue
            .lock()
            .map(|mut queue| queue.drain(..).collect())
            .unwrap_or_default()
    }
}
