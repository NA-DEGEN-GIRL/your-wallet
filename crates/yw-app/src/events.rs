//! Cross-thread queues (spec/04 §1.2–§1.3): the UI event queue with its doorbell message, and the
//! key worker's job queue where `Lock` jumps to the front and cancels everything still queued.
//! Secret buffers travel only by move inside `Zeroizing` values.

use std::collections::VecDeque;
use std::sync::{Condvar, Mutex};
use std::time::Duration;

use yw_core::approval::{Approved, TokenMeta};
use yw_core::btc::SendPlan;
use yw_core::error::{KeyError, VaultError};
use yw_core::evm::address::Address;
use yw_core::evm::amount::U256;
use yw_core::evm::sign::SignError;
use yw_core::journal::btc::BtcRecord;
use yw_core::journal::evm::{EvmRecord, GroupKey, Role, Transition};
use yw_core::journal::sol::{SolRecord, SolTransition};
use yw_core::keyimport::{BtcKeyInfo, ImportChain, ImportPreview, ImportSpec};
use yw_core::secret::{SecretString, Zeroizing};
use yw_core::slip10::SolKeySource;
use yw_core::sol::{SolAddress, SolCluster, SolSignError};
use yw_core::vault::{
    BackupChallenge, ChallengeId, EvmKeySource, FileKind, PasswordChange, RecordId, VaultStatus,
};

use crate::btc::work::BtcRpcEvent;
use crate::errors::ErrorCode;
use crate::flow::evm::ChainCheck;
use crate::flow::evm::form::Quote;
use crate::flow::evm::prepare::{PrepareResult, ResimResult};
use crate::flow::evm::track::{BroadcastOutcome, TrackResult};
use crate::flow::evm::user_chain::ProbeError;
use crate::meta::{ActivityEntry, Meta};
use crate::network::NetworkId;
use crate::sol::flow::{PreSignError, PreviewResult, TrackResult as SolTrackResult};
use crate::sol::scan::ScanRow;
use crate::workers::journal::btc::{
    BtcJournalDone, BtcJournalOp, BtcKeyError, BtcMetaOp, BtcMetaUpdate, BtcSignFailure,
    BtcSignedSummary,
};

/// Event queue doorbell (`WM_APP + 1`).
pub const WM_YW_EVENTS: u32 = 0x8001;
/// Second instance → first instance (`WM_APP + 2`).
pub const WM_YW_ACTIVATE: u32 = 0x8002;
/// Secret window → main window (`WM_APP + 3`, wParam = window id).
pub const WM_YW_CHILD_DONE: u32 = 0x8003;
/// Ctrl+L observed by the message loop (`WM_APP + 4`).
pub const WM_YW_LOCK_SHORTCUT: u32 = 0x8004;
/// Ctrl+1/2/3 observed by the message loop (`WM_APP + 5`, wParam = tab 1–3): the chain tabs.
pub const WM_YW_TAB_SHORTCUT: u32 = 0x8005;
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
    /// An imported key of any chain in its export format (W09: EVM hex, Solana base58 keypair,
    /// Bitcoin WIF).
    ImportedKey(RecordId),
}

/// An imported key just stored in the vault (public facts only).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ImportedAccount {
    /// EVM (`tag 2`).
    Evm(RecordId, Address),
    /// Solana (`tag 3`).
    Sol(RecordId, SolAddress),
    /// Bitcoin (`tag 4`).
    Btc(RecordId, BtcKeyInfo),
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
    /// "개인키로 시작하기": hold the password and the key text, parse the key and report the
    /// address to confirm (no vault is written).
    PreviewKeyStart {
        /// Vault password (`None` = keep the one already held after a failed preview).
        password: Option<Zeroizing<Vec<u8>>>,
        /// Chain (and Bitcoin script type).
        spec: ImportSpec,
        /// Key text.
        key: Zeroizing<Vec<u8>>,
    },
    /// Wipe the held key text (and the password unless `keep_password`).
    DiscardKeyStart {
        /// Keep the password for another key attempt (`다릅니다`).
        keep_password: bool,
    },
    /// `Vault::create_with_key` with the held buffers, then the key-only default meta.
    CommitKeyStart,
    /// `Vault::import_key` (Solana, Bitcoin; `Unlocked` only).
    ImportKey {
        /// Chain (and Bitcoin script type).
        spec: ImportSpec,
        /// Key text.
        key: Zeroizing<Vec<u8>>,
    },
    /// `Vault::remove_imported_key` (any chain).
    RemoveImportedKey {
        /// Password.
        password: Zeroizing<Vec<u8>>,
        /// Record.
        id: RecordId,
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
        /// Who answers the result ([`KeyOutcome::SignedEvm`] carries it back).
        ticket: SignTicket,
        /// The one-time approval (moved).
        approved: Box<Approved>,
        /// Record fields from the approval.
        info: SignInfo,
    },
    /// Sign an approved `personal_sign` or `eth_signTypedData_v4` (spec/03 §4.2, §9, §8).
    SignMessage {
        /// Who answers the result ([`KeyOutcome::SignedMessage`] carries it back).
        ticket: SignTicket,
        /// The one-time approval (moved).
        approved: Box<Approved>,
        /// `true` = typed data.
        typed: bool,
    },
    /// Sign an approved Solana or Bitcoin dApp message (spec/07 §19, spec/08 §17).
    SignChainMessage {
        /// Who answers the result.
        ticket: SignTicket,
        /// The one-time approval (moved).
        approved: Box<Approved>,
    },
    /// Apply and commit journal transitions (§5.2).
    JournalApply {
        /// Transitions.
        transitions: Vec<Transition>,
        /// Now.
        now_unix_ms: u64,
    },
    /// Solana public keys (`Vault::sol_public_keys`, spec/02 §10.3).
    SolKeys {
        /// Why.
        purpose: SolKeysPurpose,
        /// Sources (≤ 128).
        sources: Vec<SolKeySource>,
    },
    /// Sign an approved SOL transfer and commit its `Pending` record before anything is sent
    /// (spec/07 §13.1 steps 6–7).
    SignSol {
        /// The one-time approval (moved).
        approved: Box<Approved>,
        /// Monotonic ms of `consume`.
        consumed_at_ms: u64,
        /// Finalized blockhash fetched after approval.
        blockhash: [u8; 32],
        /// Its `lastValidBlockHeight`.
        last_valid_block_height: u64,
        /// Wall clock (journal `signed_at_ms`).
        now_unix_ms: u64,
    },
    /// Apply a SOL broadcast-loop transition; terminal records move to activity (spec/07 §14.1).
    SolApply {
        /// Transition.
        transition: SolTransition,
        /// Wall clock.
        now_unix_ms: u64,
    },
    /// Create, change or mutate the session's `BtcMeta` and persist it before the result is
    /// reported (spec/08 §2, §3.2, §3.4, §4.7, §7.6).
    BtcMeta {
        /// The change.
        op: BtcMetaOp,
    },
    /// Sign an approved BTC plan, verify it and commit its `Signed` record before anything is
    /// sent (spec/08 §11.1).
    SignBtc {
        /// The one-time approval (moved).
        approved: Box<Approved>,
        /// The approved plan (its payload is bound by the approval).
        plan: Box<SendPlan>,
        /// Core tip of the plan (journal clean-up).
        tip_height: u32,
        /// Wall clock.
        now_unix_ms: u64,
    },
    /// Apply a BTC journal step (spec/08 §11.3, §12.1–§12.4).
    BtcJournal {
        /// The step.
        op: BtcJournalOp,
        /// Wall clock.
        now_unix_ms: u64,
    },
    /// Stop the worker (after locking).
    Shutdown,
}

/// Ties a signing job to the waiter that answers its result. The UI matches results by this id,
/// never by queue order (a result can arrive for a job whose waiter is gone, and a lock cancels
/// queued jobs).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct SignTicket(pub u64);

/// A finished `SignEvm` job (or one cancelled by `Lock` before it ran).
#[derive(Debug, PartialEq, Eq)]
pub struct EvmSigned {
    /// The job's ticket.
    pub ticket: SignTicket,
    /// The journaled transaction or why there is none.
    pub result: Result<SignedSummary, SignFailure>,
}

/// Why a message signature was not produced.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MessageSignFailure {
    /// Signing refused.
    Sign(SignError),
    /// Cancelled by `Lock` before it ran (spec/04 §1.2).
    Locked,
}

/// A finished `SignMessage` job (or one cancelled by `Lock` before it ran).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct MessageSigned {
    /// The job's ticket.
    pub ticket: SignTicket,
    /// The 65-byte `r ‖ s ‖ v` signature or why there is none.
    pub result: Result<[u8; 65], MessageSignFailure>,
}

/// A Solana or Bitcoin message signature.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ChainSignature {
    /// Ed25519 signature.
    Sol([u8; 64]),
    /// Base64 Bitcoin signature and the committed hash.
    Btc(yw_core::btc::msgsign::BtcMessageSignature),
}

/// A finished `SignChainMessage` job (or one cancelled by `Lock` before it ran).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ChainMessageSigned {
    /// The job's ticket.
    pub ticket: SignTicket,
    /// The signature, `Err(true)` when cancelled by the lock, `Err(false)` when refused.
    pub result: Result<ChainSignature, bool>,
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
    /// Decoded SOL records (spec/07 §14.1).
    pub sol_records: Vec<SolRecord>,
    /// SOL entries the decoder rejected (SOL sending stops, bytes kept).
    pub sol_corrupt: usize,
    /// A new SOL `Pending` record fits after clean-up.
    pub sol_room: bool,
    /// Decoded BTC records (spec/08 §12.4), every network.
    pub btc_records: Vec<BtcRecord>,
    /// BTC entries the decoder rejected (BTC sending stops, bytes kept, E-VLT-006).
    pub btc_corrupt: usize,
    /// A new BTC `Signed` record fits without clean-up.
    pub btc_room: bool,
}

/// Why Solana public keys were asked for.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SolKeysPurpose {
    /// `계정 추가` / first Solana entry: the new standard account `index`.
    AddAccount {
        /// Index.
        index: u32,
    },
    /// The recovery scan (spec/07 §3.3).
    Scan,
}

/// A signed and journaled SOL transfer ready to broadcast.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SolSignedSummary {
    /// Cluster.
    pub cluster: SolCluster,
    /// Sender.
    pub from: SolAddress,
    /// Signature.
    pub signature: [u8; 64],
    /// Signed bytes.
    pub tx: Vec<u8>,
    /// Journal `signed_at_ms`.
    pub signed_at_ms: u64,
    /// Journal `last_valid_block_height`.
    pub last_valid_block_height: u64,
}

/// Why a SOL signing produced nothing to send.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SolSignFailure {
    /// Signing or verification refused (nothing signed or stored).
    Sign(SolSignError),
    /// A record with the same `intent_hash` exists (`AlreadySigned`).
    AlreadySigned,
    /// No room in the journal (E-TX-005).
    JournalFull,
    /// The `Pending` record could not be committed (the signature is dropped; nothing sent).
    JournalWrite(VaultError),
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
    /// Cancelled by `Lock` before it ran (spec/04 §1.2; nothing signed or stored).
    Locked,
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
            Self::PreviewKeyStart { .. } => "PreviewKeyStart",
            Self::DiscardKeyStart { .. } => "DiscardKeyStart",
            Self::CommitKeyStart => "CommitKeyStart",
            Self::ImportKey { .. } => "ImportKey",
            Self::RemoveImportedKey { .. } => "RemoveImportedKey",
            Self::LoadMeta => "LoadMeta",
            Self::SaveMeta { .. } => "SaveMeta",
            Self::ResolveSidecar { .. } => "ResolveSidecar",
            Self::DeriveAddresses { .. } => "DeriveAddresses",
            Self::LoadJournal => "LoadJournal",
            Self::SignEvm { .. } => "SignEvm",
            Self::SignMessage { .. } => "SignMessage",
            Self::SignChainMessage { .. } => "SignChainMessage",
            Self::JournalApply { .. } => "JournalApply",
            Self::SolKeys { .. } => "SolKeys",
            Self::SignSol { .. } => "SignSol",
            Self::SolApply { .. } => "SolApply",
            Self::BtcMeta { .. } => "BtcMeta",
            Self::SignBtc { .. } => "SignBtc",
            Self::BtcJournal { .. } => "BtcJournal",
            Self::Shutdown => "Shutdown",
        }
    }

    /// Control jobs survive `Lock`'s cancellation. `Load` is one: the lock procedure queues it
    /// right after `Lock` (spec/04 §5.3) so the UI learns the vault status the lock left, e.g.
    /// `Locked` after a `CreateWallet`/`CommitImport` whose result the lock discarded.
    const fn is_control(&self) -> bool {
        matches!(self, Self::Lock | Self::Shutdown | Self::Load)
    }

    /// What a job cancelled by `Lock` reports: signing jobs answer their ticket's waiter
    /// ([`SignFailure::Locked`] / [`MessageSignFailure::Locked`]), every other job
    /// [`KeyOutcome::Cancelled`]. The job (and any approval or secret it holds) is dropped here.
    #[must_use]
    pub fn cancelled_outcome(self) -> KeyOutcome {
        match self {
            Self::SignEvm { ticket, .. } => KeyOutcome::SignedEvm(EvmSigned {
                ticket,
                result: Err(SignFailure::Locked),
            }),
            Self::SignMessage { ticket, .. } => KeyOutcome::SignedMessage(MessageSigned {
                ticket,
                result: Err(MessageSignFailure::Locked),
            }),
            Self::SignChainMessage { ticket, .. } => {
                KeyOutcome::SignedChainMessage(ChainMessageSigned {
                    ticket,
                    result: Err(true),
                })
            }
            other => KeyOutcome::Cancelled(other.name(), KeyJobError::Locked),
        }
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
    /// The document with refreshed address caches (boxed: the largest key-worker outcome).
    pub meta: Box<Meta>,
    /// The caches had to be fixed (`MetaAddressMismatch`).
    pub mismatch: bool,
    /// `prefs` was reset.
    pub prefs_reset: bool,
    /// `false` for a key-only wallet (no recovery words, spec/02 §4.6).
    pub has_mnemonic: bool,
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
    Created(Result<(SecretString, Address), VaultError>),
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
    Revealed(Result<(RevealWhat, SecretString, Option<Address>), VaultError>),
    /// A `.prev` recovery moved `vault.ywv` aside under this file name (before its `Status`).
    Quarantined(String),
    /// Password changed (`Ok` = the new password is in effect; `PrevNotRefreshed` = `.prev`
    /// could not be rewritten with it).
    PasswordChanged(Result<PasswordChange, VaultError>),
    /// Raw key imported.
    RawKeyImported(Result<(RecordId, Address), VaultError>),
    /// Raw key removed.
    RawKeyRemoved(Result<RecordId, VaultError>),
    /// "개인키로 시작하기" preview: the address to confirm.
    KeyStartPreview(Result<ImportPreview, KeyError>),
    /// "개인키로 시작하기" committed (key-only vault created and unlocked).
    KeyStartCommitted(Result<(), VaultError>),
    /// A Solana or Bitcoin key imported.
    KeyImported(Result<ImportedAccount, VaultError>),
    /// An imported key removed (its chain).
    ImportedKeyRemoved(Result<(RecordId, ImportChain), VaultError>),
    /// `삭제` refused before the password check: the imported Bitcoin key's account has an
    /// in-flight transaction (nothing removed).
    ImportedKeyBusy(RecordId),
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
    /// `SignEvm` finished (or was cancelled by `Lock`), with its ticket.
    SignedEvm(EvmSigned),
    /// `SignMessage` finished (or was cancelled by `Lock`), with its ticket.
    SignedMessage(MessageSigned),
    /// A Solana or Bitcoin dApp message signature (or why there is none).
    SignedChainMessage(ChainMessageSigned),
    /// Terminal journal records moved to activity (spec/03 §5.4).
    ActivityMoved(Vec<(NetworkId, ActivityEntry)>),
    /// Solana public keys.
    SolKeys(
        SolKeysPurpose,
        Result<Vec<(SolKeySource, SolAddress)>, VaultError>,
    ),
    /// `SignSol` finished.
    SignedSol(Result<SolSignedSummary, SolSignFailure>),
    /// A `BtcMeta` job finished (the meta is persisted when `Ok`).
    BtcMeta(Result<BtcMetaUpdate, BtcKeyError>),
    /// `SignBtc` finished.
    SignedBtc(Result<BtcSignedSummary, BtcSignFailure>),
    /// A BTC journal step finished.
    BtcJournal(Result<BtcJournalDone, BtcKeyError>),
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
            | KeyOutcome::SignedChainMessage(_)
            | KeyOutcome::SignedSol(_)
            | KeyOutcome::SignedBtc(_)
            | KeyOutcome::Cancelled("SignEvm" | "SignMessage" | "SignSol" | "SignBtc", _)
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

    /// Removes and returns every queued non-control job (processing `Lock`); `Lock`, `Load` and
    /// `Shutdown` stay queued.
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
    /// Solana balances.
    SolBalances {
        /// Job.
        job: u64,
        /// Cluster.
        cluster: SolCluster,
        /// Balances or error.
        result: Result<Vec<crate::sol::flow::SolBalanceRow>, ErrorCode>,
    },
    /// Solana preview finished.
    SolPreviewed(Box<PreviewResult>),
    /// Solana pre-sign lookup finished.
    SolPreSigned {
        /// Job.
        job: u64,
        /// `(blockhash, lastValidBlockHeight)` or why not.
        result: Result<([u8; 32], u64), PreSignError>,
    },
    /// A Solana broadcast round finished.
    SolTracked(Box<SolTrackResult>),
    /// Recovery scan finished.
    SolScanned {
        /// Job.
        job: u64,
        /// Rows or error.
        result: Result<Vec<ScanRow>, ErrorCode>,
    },
    /// A Bitcoin job result (spec/08).
    Btc(Box<BtcRpcEvent>),
}

/// An event for the UI thread.
#[derive(Debug)]
pub enum UiEvent {
    /// Key worker result (boxed: meta documents make it the largest event).
    Key(Box<KeyResult>),
    /// RPC worker result.
    Rpc(RpcEvent),
    /// Browser bridge event (spec/05).
    Dapp(crate::browser::DappEvent),
    /// `yw-llm` result for an approval window (spec/06 §3.2).
    Llm(Box<crate::explain::LlmDone>),
    /// Settings `연결 테스트` result (spec/06 §2.2).
    LlmTest(Result<(), crate::explain::ExplainError>),
}

impl crate::browser::DappSink for EventQueue {
    fn push(&self, event: crate::browser::DappEvent) -> bool {
        Self::push(self, UiEvent::Dapp(event)).is_ok()
    }
}

/// The queue is full (E-APP-005).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct QueueFull;

/// Bound of the queued browser-bridge events (a share of [`EVENT_QUEUE_CAP`], so a flood of dApp
/// traffic never crowds out worker results).
pub const DAPP_EVENT_CAP: usize = 1_024;

/// The queued events and how many of each bounded lane they hold.
#[derive(Default)]
struct Lanes {
    events: VecDeque<UiEvent>,
    /// Queued [`UiEvent::Dapp`] events (bounded by [`DAPP_EVENT_CAP`]).
    dapp: usize,
    /// Queued RPC and LLM events (bounded by [`EVENT_QUEUE_CAP`]).
    other: usize,
}

impl Lanes {
    /// Folds `event` into an equivalent queued one: the connection count and a pending chain
    /// switch of the same origin keep only their latest value; an `Unverified` chain check adds
    /// nothing to a queued check of the same chain and is replaced by a conclusive one.
    fn merge(&mut self, event: &crate::browser::DappEvent) -> bool {
        use crate::browser::{DappEvent, GrantChange};
        for queued in self.events.iter_mut().rev() {
            let UiEvent::Dapp(queued) = queued else {
                continue;
            };
            match (queued, event) {
                (DappEvent::Connections(count), DappEvent::Connections(new)) => {
                    *count = *new;
                    return true;
                }
                (
                    DappEvent::GrantChanged { origin, change },
                    DappEvent::GrantChanged {
                        origin: new_origin,
                        change: GrantChange::Chain(new_target),
                    },
                ) if origin == new_origin => {
                    // Never across another change of the same origin (a revoke stays ordered).
                    let GrantChange::Chain(target) = change else {
                        return false;
                    };
                    *target = *new_target;
                    return true;
                }
                (
                    DappEvent::ChainChecked { chain_id, check },
                    DappEvent::ChainChecked {
                        chain_id: new_chain,
                        check: new_check,
                    },
                ) if chain_id == new_chain => {
                    if matches!(new_check, ChainCheck::Unverified(_)) {
                        return true;
                    }
                    if matches!(check, ChainCheck::Unverified(_)) {
                        *check = *new_check;
                        return true;
                    }
                    // Two conclusive results stay in order (a URL change may sit between).
                    return false;
                }
                _ => {}
            }
        }
        false
    }
}

/// The UI event queue: workers push, the UI thread drains on `WM_YW_EVENTS` and on its timer.
///
/// Three lanes share one FIFO: key worker results are never refused (they are bounded by the key
/// queue and a dropped signing result would leave its dApp waiter unanswered, spec/04 §1.2),
/// browser-bridge events are merged where only the latest value matters and bounded by
/// [`DAPP_EVENT_CAP`], everything else by [`EVENT_QUEUE_CAP`].
pub struct EventQueue {
    queue: Mutex<Lanes>,
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
            queue: Mutex::new(Lanes::default()),
            wake,
        }
    }

    /// Adds an event; rings the doorbell when the queue was empty. Key results are always
    /// accepted; browser events may be merged into a queued one.
    ///
    /// # Errors
    ///
    /// [`QueueFull`] when the event's lane is at its bound ([`DAPP_EVENT_CAP`] for browser
    /// events, [`EVENT_QUEUE_CAP`] for RPC and LLM events).
    pub fn push(&self, event: UiEvent) -> Result<(), QueueFull> {
        let was_empty = {
            let mut lanes = self
                .queue
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            match &event {
                UiEvent::Key(_) => {}
                UiEvent::Dapp(dapp) => {
                    if lanes.merge(dapp) {
                        return Ok(());
                    }
                    if lanes.dapp >= DAPP_EVENT_CAP {
                        return Err(QueueFull);
                    }
                    lanes.dapp += 1;
                }
                UiEvent::Rpc(_) | UiEvent::Llm(_) | UiEvent::LlmTest(_) => {
                    if lanes.other >= EVENT_QUEUE_CAP {
                        return Err(QueueFull);
                    }
                    lanes.other += 1;
                }
            }
            let was_empty = lanes.events.is_empty();
            lanes.events.push_back(event);
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
        let mut lanes = self
            .queue
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        lanes.dapp = 0;
        lanes.other = 0;
        lanes.events.drain(..).collect()
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};

    use super::{
        DAPP_EVENT_CAP, EVENT_QUEUE_CAP, EventQueue, EvmSigned, KeyJob, KeyOutcome, KeyResult,
        MessageSignFailure, MessageSigned, QueueFull, RpcEvent, SignFailure, SignTicket, UiEvent,
    };
    use crate::browser::{DappEvent, GrantChange};
    use crate::flow::evm::ChainCheck;
    use crate::rpc::RpcFailure;

    fn queue() -> (EventQueue, Arc<AtomicUsize>) {
        let rings = Arc::new(AtomicUsize::new(0));
        let counter = Arc::clone(&rings);
        let queue = EventQueue::new(Box::new(move || {
            counter.fetch_add(1, Ordering::Relaxed);
        }));
        (queue, rings)
    }

    fn key(ticket: u64) -> UiEvent {
        UiEvent::Key(Box::new(KeyResult {
            epoch: 1,
            outcome: KeyOutcome::SignedEvm(EvmSigned {
                ticket: SignTicket(ticket),
                result: Err(SignFailure::JournalFull),
            }),
        }))
    }

    fn rpc() -> UiEvent {
        UiEvent::Rpc(RpcEvent::Simulating {
            job: 1,
            since_ms: 0,
        })
    }

    #[test]
    fn key_results_are_never_dropped_when_the_other_lanes_are_full() {
        let (queue, rings) = queue();
        for _ in 0..EVENT_QUEUE_CAP {
            assert_eq!(queue.push(rpc()), Ok(()));
        }
        assert_eq!(queue.push(rpc()), Err(QueueFull));
        for index in 0..DAPP_EVENT_CAP {
            let origin =
                yw_core::policy::BrowserOrigin::parse(&format!("https://s{index}.example"))
                    .unwrap();
            let event = DappEvent::GrantChanged {
                origin,
                change: GrantChange::Revoked,
            };
            assert_eq!(queue.push(UiEvent::Dapp(event)), Ok(()));
        }
        assert_eq!(
            queue.push(UiEvent::Dapp(DappEvent::Cancel(
                crate::browser::RequestKey {
                    conn: 1,
                    activation: crate::browser::envelope::Id32([1; 32]),
                    request: crate::browser::envelope::Id16([1; 16]),
                }
            ))),
            Err(QueueFull)
        );
        for ticket in 0..64 {
            assert_eq!(queue.push(key(ticket)), Ok(()));
        }
        assert_eq!(rings.load(Ordering::Relaxed), 1, "doorbell only when empty");
        let drained = queue.drain();
        let tickets: Vec<u64> = drained
            .iter()
            .filter_map(|event| match event {
                UiEvent::Key(result) => match &result.outcome {
                    KeyOutcome::SignedEvm(signed) => Some(signed.ticket.0),
                    _ => None,
                },
                _ => None,
            })
            .collect();
        assert_eq!(tickets, (0..64).collect::<Vec<_>>());
        // Drained: the lanes are free again.
        assert_eq!(queue.push(rpc()), Ok(()));
    }

    #[test]
    fn dapp_events_merge_where_only_the_latest_value_matters() {
        let (queue, _) = queue();
        let site = yw_core::policy::BrowserOrigin::parse("https://app.example").unwrap();
        let other = yw_core::policy::BrowserOrigin::parse("https://other.example").unwrap();
        let switch = |origin: &yw_core::policy::BrowserOrigin, target| {
            UiEvent::Dapp(DappEvent::GrantChanged {
                origin: origin.clone(),
                change: GrantChange::Chain(target),
            })
        };
        for count in 1..=5 {
            queue
                .push(UiEvent::Dapp(DappEvent::Connections(count)))
                .unwrap();
        }
        for target in [1, 999, 11_155_111] {
            queue.push(switch(&site, target)).unwrap();
        }
        queue.push(switch(&other, 1)).unwrap();
        let unverified = ChainCheck::Unverified(RpcFailure::Late);
        let verified = ChainCheck::Verified {
            genesis: [1; 32],
            pinned_now: true,
        };
        for check in [unverified, unverified, verified, unverified] {
            queue
                .push(UiEvent::Dapp(DappEvent::ChainChecked {
                    chain_id: 999,
                    check,
                }))
                .unwrap();
        }
        let events: Vec<DappEvent> = queue
            .drain()
            .into_iter()
            .filter_map(|event| match event {
                UiEvent::Dapp(event) => Some(event),
                _ => None,
            })
            .collect();
        assert_eq!(
            events,
            vec![
                DappEvent::Connections(5),
                DappEvent::GrantChanged {
                    origin: site,
                    change: GrantChange::Chain(11_155_111)
                },
                DappEvent::GrantChanged {
                    origin: other,
                    change: GrantChange::Chain(1)
                },
                // The first-use pin is never lost to a later inconclusive check.
                DappEvent::ChainChecked {
                    chain_id: 999,
                    check: verified
                },
            ]
        );
    }

    #[test]
    fn lock_cancelled_jobs_and_signing_results_of_old_epochs() {
        assert!(matches!(
            KeyJob::LoadMeta.cancelled_outcome(),
            KeyOutcome::Cancelled("LoadMeta", super::KeyJobError::Locked)
        ));
        // Signing results (with their ticket) are accepted from any epoch so the right waiter
        // is answered (4001 for a lock-cancelled one).
        let outcome = KeyOutcome::SignedMessage(MessageSigned {
            ticket: SignTicket(7),
            result: Err(MessageSignFailure::Locked),
        });
        assert!(super::accept_result(&KeyResult { epoch: 0, outcome }, 9));
    }
}
