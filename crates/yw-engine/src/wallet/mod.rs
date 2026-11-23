//! The wallet: its state ([`Wallet`]) and the logic on it, shared by every platform shell
//! (spec/15 §11.4 S4, plan §3.3): the modes, screens, banners, confirmations and secret-window
//! purposes, the core screens, key results, settings and RPC rows, the lock and shutdown halves,
//! the secret session, the outbox, and one module per handler family (`app_evm`, `app_sol`, …,
//! the approval flow `app_approval` and its state `approval_flow`). The shell enters it with a
//! `Cmd` (`Wallet::on_cmd`), a typed in-process entry (`worker_event`, a secret window's action,
//! the display secret's hand-off, the `rpc.json` plan) or the lock/shutdown halves its
//! compositions call, and applies its `Effect`s (`Wallet::next_effect`). No window, handle,
//! control id, file or OS call: yw-engine depends on no OS crate (spec/01 §2.3b).
//!
//! 2026-11-23 (spec/15 §11.4 S4d E1): moved here from yw-app (`app/wallet.rs` and the `app_*.rs`,
//! `approval_flow.rs`, `secret_session.rs` and `lock.rs` files; the approval flow half of
//! `app_approval.rs`) unchanged but for paths and visibility (D-22): what the Windows shell and its
//! render builders read is `pub`; the consent and secret steps (`card_begin`, `consume_and_sign`,
//! the `*_consumed` handlers, `begin_secret`, `on_submit`, …), the `Approved` holders and the
//! secret session, import and challenge buffers stay crate-private (critique A-15). Before E1,
//! 2026-11-23 (S4d E0b), this was yw-app `app::wallet`, split out of `app.rs` that day.

pub mod app_approval;
pub mod app_book;
pub mod app_browser;
pub mod app_btc;
pub mod app_btc_commands;
pub mod app_btc_view;
pub mod app_card;
pub mod app_chain_sites;
pub mod app_evm;
pub mod app_evm_commands;
pub mod app_explorer;
pub mod app_hidden;
pub mod app_hypercore;
pub mod app_keys;
pub mod app_llm;
pub mod app_mnemonics;
pub mod app_received;
pub mod app_removed;
pub mod app_reset;
pub mod app_rpc_plan;
pub mod app_sidecar;
pub mod app_sol;
pub mod app_sol_commands;
pub mod app_sol_dapp;
pub mod app_tokens;
pub mod app_walletconnect;
pub mod app_yubikey;
pub mod app_zec;
pub mod approval_flow;
pub mod lock;
pub mod secret_session;
pub mod text;

use std::collections::VecDeque;
use std::sync::Arc;
use std::sync::mpsc::Sender;

use yw_core::error::VaultError;
use yw_core::evm::address::Address;
use yw_core::secret::Zeroizing;
use yw_core::vault::{
    BackupChallenge, ChallengeId, EvmKeySource, FileKind, PasswordChange, RecordId, VaultStatus,
};
use yw_platform::Clock;
use yw_platform::http::HttpsUrl;

use crate::apikeys::{
    ApiKeys, KeyName, quicknode_credentials, template_entry, valid_provider_token,
};
use crate::errors::{ErrorCode, key_code, vault_code};
use crate::events::{
    KeyJob, KeyOutcome, KeyQueue, KeyResult, LockSignal, MetaLoaded, RevealWhat, RpcEvent, UiEvent,
    accept_result,
};
use crate::logging::{self, Field};
use crate::meta::{EvmAccountPref, Meta, RawAccount};
use crate::network::NetworkId;
use crate::secret::Submission;
use crate::settings::{RpcTemplate, Settings};
use crate::text::is_valid_label;
use crate::wallet::lock::{IdleTracker, LockReason, WalletLock};
use crate::wallet::secret_session::{AfterShown, SecretAction, SecretSession};
// `IDOK`/`IDCANCEL`: the ids `IsDialogMessageW` sends for Enter and Esc (2026-11-18, S3 B2: they
// were constants of this file).
use crate::app_store::AppStore;
use crate::approval::flow::OpenOutcome;
use crate::cmd::{Cmd, CorePress, Press, Row, RpcImportPress, RpcRowAction, TickPart};
use crate::effect::{Effect, Folder, RevealTarget, TimerId};
use crate::workers::key::new_account;
use crate::workers::rpc::RpcJob;
use yw_core::lang::{Lang, Text};
// `CredField`: debug builds only until S3 C3 (the shadow reads of plan §3.2a; 2026-11-18 B4–B5
// review); since C3 `Wallet::take_cred` uses it in every build.
use crate::form::{CredField, EditField, FormState, PressInput};
// Settings sections (S15) and the remembered scroll places: 2026-11-20 (S4 P10a) moved unchanged
// to `yw_engine::screen` (the scroll effects carry them). P10a re-exported them as
// `crate::app::SettingsSection` and `crate::app_scroll::ScrollPlace`; 2026-11-21 (S4b final
// review, AGENTS.md §4 "no new re-exports"): the callers name `yw_engine::screen` directly.
use crate::screen::{EnteredAt, ScrollPlace, SettingsSection, Tone};
use crate::secret::{
    DisplayHost, DisplayMade, DisplaySecret, SecretEffect, SecretFormOp, SecretKind, SecretStep,
};
use crate::services::Services;

use text::T_CLIP_NOT_CLEARED;

/// App mode (spec/04 §2.1): `VaultStatus` plus progress states.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AppMode {
    /// Before the first `Vault::load` result.
    Starting,
    /// No wallet.
    NoVault,
    /// Locked.
    Locked,
    /// `Unlock` in progress.
    Unlocking,
    /// Passphrase needed.
    PassphraseRequired,
    /// Passphrase check failed.
    PassphraseMismatch,
    /// Backup not confirmed.
    BackupPending,
    /// Unlocked.
    Unlocked {
        /// Mismatched passphrase accepted.
        alt_passphrase: bool,
    },
    /// Damaged main vault.
    Corrupt {
        /// `.prev` exists.
        prev_available: bool,
    },
    /// Main vault missing, `.prev` present.
    MainMissing,
    /// Shutting down.
    ShuttingDown,
}

impl AppMode {
    fn from_status(status: VaultStatus) -> Self {
        match status {
            VaultStatus::NoVault => Self::NoVault,
            VaultStatus::Locked => Self::Locked,
            VaultStatus::PassphraseRequired => Self::PassphraseRequired,
            VaultStatus::PassphraseMismatch => Self::PassphraseMismatch,
            VaultStatus::BackupPending => Self::BackupPending,
            VaultStatus::Unlocked { alt_passphrase } => Self::Unlocked { alt_passphrase },
            VaultStatus::Corrupt { prev_available } => Self::Corrupt { prev_available },
            VaultStatus::MainMissing => Self::MainMissing,
        }
    }

    pub(crate) const fn word(self) -> &'static str {
        match self {
            Self::Starting => "Starting",
            Self::NoVault => "NoVault",
            Self::Locked => "Locked",
            Self::Unlocking => "Unlocking",
            Self::PassphraseRequired => "PassphraseRequired",
            Self::PassphraseMismatch => "PassphraseMismatch",
            Self::BackupPending => "BackupPending",
            Self::Unlocked { .. } => "Unlocked",
            Self::Corrupt { .. } => "Corrupt",
            Self::MainMissing => "MainMissing",
            Self::ShuttingDown => "ShuttingDown",
        }
    }

    /// Whether wallet secrets may be in worker memory (lockable).
    #[must_use]
    pub const fn holds_secrets(self) -> bool {
        matches!(
            self,
            Self::Unlocking
                | Self::PassphraseRequired
                | Self::PassphraseMismatch
                | Self::BackupPending
                | Self::Unlocked { .. }
        )
    }
}

/// Confirmation overlays.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Confirm {
    /// T-COPY-ON.
    CopyOn,
    /// T-LOCALHOST-ON.
    LocalhostOn,
    /// T-REVEAL-WARN for the mnemonic.
    RevealMnemonic,
    /// T-REVEAL-WARN for a private key.
    RevealKey,
    /// T-RPC-GENERATE.
    Generate,
    /// E-VLT-006 for meta.
    SidecarCorrupt,
    /// Remove an imported key.
    RemoveKey,
    /// E-VLT-006 for the journal (T-JOURNAL-RESET).
    JournalCorrupt,
    /// T-CHAIN-PIN.
    ChainPin,
    /// T-CHAIN-REPIN.
    ChainRepin,
    /// T-CHAIN-DELETE.
    ChainDelete,
    /// Discard of an open transaction.
    Discard,
    /// Delete an address-book entry.
    BookDelete,
    /// Delete a user-added EVM token (`EvmUi::token_delete`).
    TokenDelete,
    /// S13 `모두 해제`.
    DisconnectAll,
    /// S13 `모든 WalletConnect 세션 끊기` (2026-11-08).
    WcDisconnectAll,
    /// The settings-file banner's `파일 값 사용…` (2026-11-08).
    SettingsFile,
    /// A Bitcoin overlay (`BtcUi::confirm` holds which one and its texts).
    Btc,
    /// The AI explanation privacy notice (spec/06 §2.2).
    LlmOn,
    /// `보관 항목 삭제`: dormant `apikeys.dpapi` entries (spec/04 §6.6).
    PruneDormant,
    /// T-REVEAL-WARN for an imported Solana/Bitcoin key (`KeysUi::target`).
    RevealImported,
    /// Remove an imported Solana/Bitcoin key (T-REMOVE-IMPORTED, `KeysUi::target`).
    RemoveImported,
    /// Remove a `YubiKey` record (`CardUi::remove_target`, spec/10 §7.5).
    RemoveYubiKey,
    /// A network row's `삭제` in settings → 네트워크(RPC) (2026-11-10: the stored address cannot
    /// be shown again).
    RpcUrlDelete(NetworkId),
    /// `자격 정보 삭제` of the selected RPC provider.
    TemplateDelete,
    /// The AI explanation's `키 삭제`.
    LlmKeyDelete,
    /// The new `YubiKey` wallet's wizard `취소` after the words were shown (spec/10 §7.1-1).
    YkAbandon,
    /// `완료` of a result screen that leaves its card on factory PINs (2026-11-10, spec/10
    /// §9.3): `지금 PIN 설정` (back) or `나중에`.
    YkPinLater,
}

/// The state of an endpoint `테스트` (settings → 네트워크(RPC) rows, Bitcoin's Esplora URL):
/// drawn as an information, success or error band (spec/04 §2.11.1).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TestState {
    /// Sent (or waiting for its turn), no answer yet.
    Testing,
    /// The endpoint answered for the right network (T-RPC-OK).
    Works,
    /// Any failure (its code is in the text).
    Failed,
}

impl TestState {
    /// The band tone: information while testing, success, error.
    #[must_use]
    pub const fn tone(self) -> Tone {
        match self {
            Self::Testing => Tone::Info,
            Self::Works => Tone::Success,
            Self::Failed => Tone::Danger,
        }
    }
}

/// Endpoint tests run one at a time (spec/04 §2.11.1): the RPC worker is FIFO, so a batch sent
/// at once would hold balance and send jobs behind it. The next `RpcJob::Test` goes when the
/// previous one's answer arrives.
#[derive(Debug, Default)]
pub struct RpcTests {
    /// Networks waiting for their turn (no duplicates).
    pub waiting: VecDeque<NetworkId>,
    /// The one test the worker has now.
    pub running: Option<NetworkId>,
    /// Tests of this run of the queue that answered, and all of them (`테스트 중 3/11`).
    pub done: usize,
    /// See [`RpcTests::done`].
    pub total: usize,
}

impl RpcTests {
    /// Whether tests are queued or running.
    #[must_use]
    pub fn busy(&self) -> bool {
        self.running.is_some() || !self.waiting.is_empty()
    }
}

/// A completion band after a confirmed removal in settings → 네트워크(RPC).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RpcRemoved {
    /// A network's address (its row).
    Url(NetworkId),
    /// The provider credentials (the `RPC 공급자` card).
    Template,
}

/// Screens S01–S15 (M3 subset).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Screen {
    /// Waiting for `Vault::load`.
    Starting,
    /// S01.
    FirstRun,
    /// S02.
    CreateIntro,
    /// S03.
    Processing(&'static str),
    /// S04.
    BackupPending,
    /// S05.
    ImportIntro,
    /// S06 (EIP-55 address).
    ImportAddress(String),
    /// S07.
    Locked,
    /// S07 overlay T-PASS-MISMATCH.
    PassMismatch,
    /// S08.
    Done,
    /// S09.
    Recovery,
    /// S10.
    Main,
    /// S15.
    Settings(SettingsSection),
    /// Confirmation overlay over the previous screen.
    Confirm(Confirm),
    /// S11.
    Send,
    /// S11 result.
    SendResult,
    /// S12.
    Receive,
    /// S14.
    AddressBook,
    /// S16.
    TokenAdd,
    /// S17.
    ChainEdit,
    /// S13.
    Sites,
    /// S11 for Solana.
    SolSend,
    /// S11 result for Solana.
    SolSendResult,
    /// S12 for Solana.
    SolReceive,
    /// The recovery scan (spec/07 §3.3).
    SolScan,
    /// S11 for Bitcoin.
    BtcSend,
    /// S11 result for Bitcoin.
    BtcSendResult,
    /// The Bitcoin fee-bump form (S10 `수수료 올리기`).
    BtcBump,
    /// S12 for Bitcoin.
    BtcReceive,
    /// S18 "개인키로 시작하기": chain and script type (spec/04 §2.18).
    KeyStartIntro,
    /// S19: the address of the entered key.
    KeyStartAddress(crate::wallet::app_keys::KeyStartView),
    /// S21 the `YubiKey` enrolment wizard (its step is `CardUi::wizard`, spec/10 §7).
    YubiKey,
    /// S20 `YubiKey 지갑 만들기`: what the new `YubiKey` wallet is (spec/10 §7.1-1).
    YubiKeyWalletIntro,
    /// S22 `지갑 초기화` (spec/04 §2.20).
    Reset,
    /// S23 `Chrome 확장 설치` (spec/04 §2.21).
    Extension,
    /// S-HC: a `HyperCore` transfer form (spec/11 §8).
    HyperCore,
}

/// What a password-confirm window (W03) is for.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PasswordAction {
    /// Reveal the mnemonic; `then_backup` = continue with W08 → W10 (S04).
    RevealMnemonic {
        /// Backup confirmation path.
        then_backup: bool,
    },
    /// Reveal a private key.
    RevealKey(EvmKeySource),
    /// Remove an imported key.
    RemoveKey(RecordId),
    /// Reveal an imported Solana/Bitcoin key.
    RevealImported(RecordId),
    /// Reveal the WIF of a Bitcoin account on an EVM account's key.
    RevealBtcEvmShared {
        /// EVM account index.
        evm_index: u32,
        /// The account's network.
        network: yw_core::btc::BtcNetwork,
    },
    /// Remove an imported Solana/Bitcoin key.
    RemoveImported(RecordId),
    /// Remove a `YubiKey` record (spec/10 §8: the password is asked again).
    RemoveHardwareKey(RecordId),
    /// Recover from `.prev`.
    Recover,
}

/// What the open secret window is for.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Purpose {
    /// W01 in the create flow.
    CreatePassword,
    /// W01 in the import flow.
    ImportPassword,
    /// W05.
    ImportMnemonic,
    /// W06 (two fields).
    ImportPassphrase,
    /// W02.
    Unlock,
    /// W06 (one field) after unlock.
    EnterPassphrase,
    /// W08 after creation or on the backup path.
    ShowForBackup,
    /// W10.
    Backup,
    /// W03.
    ConfirmPassword(PasswordAction),
    /// W08/W09 reveal.
    ShowRevealed,
    /// W04.
    ChangePassword,
    /// W07.
    ImportKey,
    /// W01 of "개인키로 시작하기".
    KeyStartPassword,
    /// W07 of "개인키로 시작하기".
    KeyStartKey,
    /// W07 of `개인키 가져오기` on the Solana / Bitcoin tab.
    ImportChainKey(yw_core::keyimport::ImportSpec),
    /// W11: the PIN of card step `id` (spec/10 §9.2). The consumed approval and the job to
    /// dispatch are held by that step (`crate::app_card::CardStep`); submitting moves the PIN
    /// buffer into the card job, cancelling drops the approval (nothing signed).
    CardSign(u64),
    /// A window of the `YubiKey` wizard or the new `YubiKey` wallet (spec/10 §7, §9.3).
    YubiKey(crate::wallet::app_yubikey::YkPurpose),
    /// A window of the recovery-phrase flows (spec/04 §2.22).
    Mnemonics(crate::wallet::app_mnemonics::MnPurpose),
}

/// A main-window banner (shown until dismissed; one per code).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Banner {
    /// Code (dedup key).
    pub code: Option<ErrorCode>,
    /// Text.
    pub text: String,
    /// Look: `Tone::Danger` for errors and warnings (the default), lighter for a notice
    /// (review 2026-11-07 F5: a success notice in a red error band read as a failure).
    pub tone: crate::screen::Tone,
}

/// `settings.json` integrity and other startup facts shown to the user (review M1/L15, L9, L17).
#[derive(Debug, Default)]
pub struct SettingsGuard {
    /// The settings in use were compared with the meta snapshot after an unlock in this process
    /// (or the snapshot was created). Until then the `yw-llm` worker never starts.
    pub(crate) verified: bool,
    /// Save keys (`Wallet::save_settings`) written while no snapshot was available (locked, or
    /// before the meta loaded): taken over at the next check.
    pub(crate) saved_early: Vec<&'static str>,
    /// The file values that differ from the snapshot and are not used, until the user picks
    /// `파일 값 사용` or `되돌리기` (the settings in use hold the snapshot values meanwhile).
    pub pending: Option<Box<(Settings, Vec<crate::settings::Differing>)>>,
    /// `WerAddExcludedApplication` failed at startup (crash reports may be written).
    pub wer_unprotected: bool,
    /// `vault.ywv` generation and last write time (Unix ms), read from the file header.
    pub vault_file: Option<(u64, u64)>,
    /// `(seen, found)`: the meta remembers a newer `vault.ywv` generation than the file has.
    pub(crate) rollback: Option<(u64, u64)>,
}

/// Import flow buffers held on the UI thread until `PreviewImport` moves them.
#[derive(Default)]
struct ImportFlow {
    password: Option<Zeroizing<Vec<u8>>>,
    phrase: Option<Zeroizing<Vec<u8>>>,
    password_sent: bool,
}

/// The wallet state (UI thread; 2026-11-21, S4 W2, spec/15 §11.4 S4, plan §3.3): everything the
/// app holds except the Windows shell's own state ([`App`]'s other fields). Before W2 these were
/// fields of `App` itself. The logic still runs as `impl App` (preflight §3.0: the fns become
/// `impl Wallet` in place later in S4c) and reaches these fields through `App`'s `Deref`/`DerefMut`;
/// a field that must be borrowed beside another one is named through `App::wallet`.
/// 2026-11-22 (S4c W14c/W15; ZC review): that was the state at W2. Since W14c-2 the logic is
/// `impl Wallet` in place, and since W15 `DerefMut` exists only in test builds; shell code names
/// the wallet (`self.wallet.<fn>(`) as the source check
/// `the_shell_writes_wallet_state_only_through_entries` lists.
///
/// Declared here, not in a sibling module, so the private fields (the `Zeroizing` import and
/// backup-challenge buffers, the secret session and its serial, …) stay private to `app` and its
/// children, as they were on `App` (critique A-15, D-22).
#[expect(
    clippy::struct_excessive_bools,
    reason = "independent UI flags of one window"
)]
pub struct Wallet {
    /// The data-folder store: `settings.json` writes, `apikeys.dpapi`, the `vault.ywv` facts,
    /// `.prev` checks and the reset candidates (2026-11-20, S4 P1: yw-engine `AppStore`, built
    /// from `paths` in [`App::with_clock`]; before, `impl App` made these calls directly).
    ///
    /// It takes `paths.data` once, so `paths.data` must not change after the `App` is built
    /// (2026-11-20, S4 P1 review): the only writer is the screenshot tour's shot 44, which swaps
    /// in the generic folder text for the picture and puts the real folder back, with no store
    /// call in between (`ui::tour`). A test that needs other store results swaps this field.
    pub store: Box<dyn AppStore>,
    /// The factories the optional network workers start from: the LLM transport (worker start
    /// and connection test), the `WalletConnect` relay parts and the relay user agent word
    /// (2026-11-20, S4 P2: yw-engine `Services`, [`windows_services`] from [`App::with_clock`];
    /// before, `app_llm` and `app_walletconnect` built the `WinHTTP`, WebSocket and CNG values
    /// inline). A test that needs other services swaps this field.
    pub(crate) services: Services,
    pub(crate) background: bool,
    pub events: Option<Arc<crate::events::EventQueue>>,
    /// The time source of every `impl App` time read (2026-11-19, S4 B1a, spec/15 §11.4 S4;
    /// before, per-file `now_ms`/`now_unix_ms` wrappers over yw-win `time::monotonic_ms` and
    /// `SystemTime`, with a `cfg(test)` approval test clock read first): `SystemClock` from
    /// [`App::new`]; `main.rs` hands the same `Arc` to the RPC worker, the key worker and the
    /// browser dispatcher ([`Wallet::clock`]); tests inject theirs ([`App::with_clock`]).
    pub clock: Arc<dyn Clock>,
    pub key_queue: Arc<KeyQueue>,
    pub lock_signal: Arc<LockSignal>,
    /// 2026-11-23 (spec/15 §11.4 S5-0, §18 31 (가)): `pub(crate)`; from S4d E1 until S5-0
    /// `#[doc(hidden)] pub` because frozen test bodies wrote it as a field. Tests set it with
    /// `testkit::WalletTestExt::set_rpc_tx`.
    pub(crate) rpc_tx: Option<Sender<RpcJob>>,
    pub mode: AppMode,
    /// 2026-11-23 (S5-0, §18 31 (가)): `pub(crate)` (was `#[doc(hidden)] pub`); tests read it
    /// with `testkit::WalletTestExt::lock_epoch`.
    pub(crate) lock_epoch: u64,
    pub settings: Settings,
    pub apikeys: ApiKeys,
    pub banners: Vec<Banner>,
    pub meta: Option<Meta>,
    pub screen: Screen,
    pub(crate) previous_screen: Screen,
    pub leftover: bool,
    pub info: Option<String>,
    /// The copy just made, answered at its control for about 1.5 s (2026-11-12,
    /// `Wallet::copy_text`).
    pub copied: Option<crate::wallet::app_evm::Copied>,
    /// The press being handled (2026-11-18 S3 B4): a plain copy carries it in its `CopyMark`, so
    /// its result marks the pressed control even when the result arrives after another press.
    /// 2026-11-20 (S4 P6): also the last command; the control id field `command` (always
    /// `cmd_table::id_of(last_press)` after a press; S3 D3: an id that is no press changed only
    /// it, which nothing but tests read) is gone, and such an id now only clears the copy mark.
    /// 2026-11-23 (S5-0, §18 31 (가)): `pub(crate)` (was `#[doc(hidden)] pub`); tests read it
    /// with `testkit::WalletTestExt::last_press`.
    pub(crate) last_press: Press,
    pub(crate) mismatch_checked: bool,
    pub(crate) overwrite_checked: bool,
    /// 고급 설정 보기 (technical settings and fee details shown).
    pub show_advanced: bool,
    pub rename: Option<EvmAccountPref>,
    pub pending_remove: Option<RecordId>,
    pub replace_target: Option<NetworkId>,
    pub rpc_messages: Vec<(NetworkId, String, TestState)>,
    /// Endpoint tests waiting or running (one at a time).
    pub rpc_tests: RpcTests,
    /// The completion band of a confirmed removal (a row's address, the credentials).
    pub(crate) rpc_removed: Option<RpcRemoved>,
    pub(crate) passphrase_session: bool,
    /// `unlock` reported `PayloadCorrupt` (spec/02 §6.3): the header is intact, so a reload
    /// reports `Locked`; this keeps S09 (and `.prev` recovery) until a session opens.
    pub payload_damaged: bool,
    /// An unlock failed with `UnlockFailed` since the last session: S07 then offers `.prev`
    /// recovery for a damaged key section (spec/02 §6.3).
    pub unlock_failed: bool,
    /// The file name the last `.prev` recovery moved `vault.ywv` to (`vault.ywv.corrupt-<t>`),
    /// shown so the user can restore it by hand (docs/recovery-guide.ko.md).
    pub(crate) quarantined: Option<String>,
    /// `vault.ywv.prev` exists (checked at load and after a failed unlock).
    pub(crate) prev_on_disk: bool,
    /// S08 follows an import (no backup check ran) rather than a backup confirmation.
    pub done_imported: bool,
    /// `숨긴 계정 n개 보기 ▸` is open (EVM and Solana `내 계정`, this run only).
    pub hidden_open: bool,
    /// The open account drop-down of `내 계정` (EVM, Solana, Bitcoin; 2026-11-11), closed by a
    /// choice: its button's press (2026-11-20, S4 P6: `Press::Links(LinksPress::Picker*)`, which
    /// the screen maps to the button's id with `ui::cmd_table::id_of`; before, that id,
    /// `ui::screens_links::ids::PICKER_*`).
    pub account_menu: Option<Press>,
    /// The EVM activity card shows every row, not only the latest ten (this run only).
    pub(crate) activity_all: bool,
    /// S08 follows a new `YubiKey` wallet (spec/04 §2.19): what its completion banner says.
    pub done_yubikey: Option<crate::wallet::app_yubikey::YkDone>,
    /// Settings → 네트워크(RPC) or S13 was opened from S08's '처음 설정' card: their back link is
    /// `← 처음 설정으로` (spec/04 §2.3). Cleared with the other S08 flags.
    pub done_return: bool,
    /// The networks S08 `연결하기` made addresses for: their result lines on S08.
    pub done_tested: Vec<NetworkId>,
    /// S08's address field: what was wrong with the last `연결하기` (empty, E-KEY-002).
    pub done_error: Option<String>,
    /// How far a new `YubiKey` wallet got with its words: S01's band when they are discarded.
    pub yk_words: crate::wallet::app_yubikey::YkWords,
    /// While a `.prev` recovery submitted from W03 is pending or failed: the mode to return to
    /// when it fails or the window is cancelled.
    recover_return: Option<AppMode>,
    /// The settings section opened last in this run: `설정` and Ctrl+, open it (first 보안).
    pub(crate) settings_last: SettingsSection,
    /// `설정 → 브라우저·정보 → 정보`: the commit of the installation record next to the executable
    /// (`build_info`), checked; `None` = a development build.
    pub install_commit: Option<String>,
    /// The text of each plain edit (2026-11-18 S3 B5, spec/15 §11.4): kept equal to what the
    /// edits show — read again at every press (`Cmd::Form`), on every `EN_CHANGE`
    /// (`Cmd::Edit`) and after every render (Windows-transitional; engine-owned in S5).
    /// Handlers read it through [`Wallet::form_text`].
    pub form: FormState,
    /// The credential units captured with the press being handled (S3 B5), wiped when it ends.
    /// 2026-11-23 (S4d final review, A-15): crate-private again (E1 had it `#[doc(hidden)] pub`);
    /// the press comes in with `Cmd::Press`, the tests swap it through `testkit`.
    pub(crate) input: PressInput,
    pub evm: crate::wallet::app_evm::EvmUi,
    pub sol: crate::wallet::app_sol::SolUi,
    pub btc: crate::wallet::app_btc::BtcUi,
    /// The Zcash tab (spec/12).
    pub zec: crate::wallet::app_zec::ZecUi,
    /// `HyperCore` card, form and session activity (spec/11).
    pub hypercore: crate::wallet::app_hypercore::HcUi,
    /// The opt-in received history (spec/04 §2.6; this run only).
    pub received: crate::wallet::app_received::ReceivedUi,
    /// `WalletConnect` worker, sessions and panel state (spec/13).
    pub wc: crate::wallet::app_walletconnect::WcUi,
    /// Address book (S14, favorites, the inline save prompt).
    pub book: crate::wallet::app_book::BookUi,
    /// Imported keys and "개인키로 시작하기" (spec/04 §2.18).
    pub keys: crate::wallet::app_keys::KeysUi,
    /// `YubiKey` card step and enrolment state (spec/10).
    pub card: crate::wallet::app_card::CardUi,
    /// The recovery phrases (spec/04 §2.22).
    pub mn: crate::wallet::app_mnemonics::MnUi,
    pub browser: Option<crate::wallet::app_browser::BrowserUi>,
    /// The `yw-llm` worker, only while the AI explanation is effectively on (spec/06 §9).
    pub llm: Option<crate::explain::ExplainService>,
    /// S15 `AI 설명` form.
    pub llm_ui: crate::wallet::app_llm::LlmUi,
    /// `settings.json` integrity (meta snapshot) and the startup facts shown with it.
    pub guard: SettingsGuard,
    /// Loading waits that time out to T-WAIT-STALLED instead of hanging (`app_reset`).
    pub wait: crate::wallet::app_reset::WaitWatch,
    /// The E-VLT-006 choices for `meta.ywm`/`journal.ywj` and the journal's state after them
    /// (`app_sidecar`, this session).
    pub sidecar: crate::wallet::app_sidecar::SidecarUi,
    /// S22 `지갑 초기화` (spec/04 §2.20).
    pub reset: crate::wallet::app_reset::ResetUi,
    /// Settings → 네트워크(RPC) `rpc.json에서 가져오기` (a plan waiting for confirmation, the
    /// advice to delete the plaintext file after an import).
    pub rpc_import: crate::wallet::app_rpc_plan::RpcImportUi,
    /// Block explorer links: the S15 card's form (`app_explorer`, 2026-11-11; the launcher was
    /// here too until 2026-11-21, S4 W1: [`Self::launcher`]).
    pub explorer_ui: crate::wallet::app_explorer::ExplorerUi,
    /// The wallet's open secret session (the purpose of the one secret window; S4 P7a1).
    secret_session: Option<SecretSession>,
    /// The last secret session serial handed out (the next session gets the next one).
    secret_serial: u64,
    import: ImportFlow,
    challenge: Option<BackupChallenge>,
    pub(crate) idle: IdleTracker,
    startup_load: bool,
    /// When [`Wallet::reads_due`] last started a balance read ahead of the timer.
    reads_due_ms: u64,
    /// The effects the logic emitted and the shell has not applied yet (2026-11-20, S4 P10b,
    /// spec/15 §11.4 S4, plan §3.4): [`Wallet::emit`] queues, `App::drain` takes them one at a
    /// time ([`Wallet::next_effect`]) and applies them in order, never coalesced, inside the same
    /// borrow before the entry that emitted them returns (an answer `Cmd` goes back to the logic
    /// in the same drain). Empty between entries. Before P10 `emit` applied each effect at once;
    /// from P10b until 2026-11-21 (S4 W3, plan §3.4) the queue and `emit` were `App`'s.
    /// 2026-11-23 (S4d final review, A-15): crate-private again (E1 had it `#[doc(hidden)] pub`,
    /// so any crate could rewrite the queue); the shell takes effects with `next_effect`, the
    /// tests read it through `testkit::WalletTestExt::{outbox, take_outbox}`.
    pub(crate) outbox: VecDeque<Effect>,
    /// The main window is hidden or minimized, as the shell last reported it
    /// (`Cmd::MainHidden`; 2026-11-21, S4 W3, critique B-10): the periodic balance, `HyperCore`
    /// and received-history reads pause while it is set. No main window (tests) is not hidden.
    /// Before W3, `App::main_hidden` read the window itself at each call.
    main_hidden: bool,
    /// Debug builds (2026-11-21, S4 W3, critique B-11): the credential fields the press being
    /// handled took ([`Wallet::take_cred`]), for the shell's comparison when the next drain starts
    /// (`App::cred_check`); before W3, `take_cred` read the edit itself. 2026-11-21 (W3 review):
    /// with the length and SHA-256 of the units taken ([`cred_fingerprint`], no copy of them), so
    /// the units the logic got are compared, not only two shell reads; before, names only.
    #[cfg(debug_assertions)]
    cred_taken: Vec<CredTaken>,
    /// Debug builds: credential reads of a field the press did not capture (`creds_for`), counted
    /// when the press's input is put back (`Cmd::Press`). Tests assert 0. 2026-11-22 (S4c W15):
    /// the wallet's, as the press handling is (`Wallet::on_cmd`); before, a field of `App`.
    #[cfg(debug_assertions)]
    #[doc(hidden)]
    pub cred_misses: u32,
}

/// Debug builds: one credential take (2026-11-21, S4 W3 review): the field, and the length and
/// SHA-256 of the units the handler got ([`cred_fingerprint`]).
#[cfg(debug_assertions)]
pub type CredTaken = (CredField, usize, Zeroizing<[u8; 32]>);

/// Debug builds (2026-11-21, S4 W3 review, critique B-11): the length and SHA-256 of credential
/// units (UTF-16 little-endian), so the units a handler took can be compared with the shell's
/// read of the edit without a second copy of them living until the next drain. Both sides use
/// it; the bytes hashed are wiped. 2026-11-23 (S4d E1, preflight critic C7): a hidden,
/// debug-only cross-crate API for the shell's drain check (it hashes, never returns the units).
#[cfg(debug_assertions)]
#[doc(hidden)]
#[must_use]
pub fn cred_fingerprint(units: &[u16]) -> (usize, Zeroizing<[u8; 32]>) {
    let mut bytes = Zeroizing::new(Vec::with_capacity(units.len().saturating_mul(2)));
    for unit in units {
        bytes.extend_from_slice(&unit.to_le_bytes());
    }
    (
        units.len(),
        Zeroizing::new(yw_core::codec::sha256(bytes.as_slice())),
    )
}

impl Wallet {
    /// A new wallet (no workers yet) on `clock`; `now` is the clock's reading the shell takes once
    /// for the wallet and itself. 2026-11-23 (spec/15 §11.4 S4d E0b, preflight E0b): the field
    /// initializers of `App::with_clock`'s `Wallet` literal moved here unchanged, so the shell
    /// builds the wallet without naming its private fields (E1: across crates).
    #[must_use]
    pub fn new(
        store: Box<dyn AppStore>,
        services: Services,
        background: bool,
        settings: Settings,
        apikeys: ApiKeys,
        clock: Arc<dyn Clock>,
        now: u64,
    ) -> Self {
        Self {
            store,
            services,
            background,
            events: None,
            clock,
            key_queue: Arc::new(KeyQueue::default()),
            lock_signal: Arc::new(LockSignal::default()),
            rpc_tx: None,
            mode: AppMode::Starting,
            lock_epoch: 0,
            settings,
            apikeys,
            banners: Vec::new(),
            meta: None,
            screen: Screen::Starting,
            previous_screen: Screen::Starting,
            leftover: false,
            info: None,
            copied: None,
            // No press yet (S3 D3: `Back`, whose id `IDCANCEL` is no control's; before,
            // `Press::Legacy(0)`). Every copy is made by a press, which sets it first.
            last_press: Press::Back,
            mismatch_checked: false,
            overwrite_checked: false,
            show_advanced: false,
            rename: None,
            pending_remove: None,
            replace_target: None,
            rpc_messages: Vec::new(),
            rpc_tests: RpcTests::default(),
            rpc_removed: None,
            passphrase_session: false,
            payload_damaged: false,
            unlock_failed: false,
            quarantined: None,
            prev_on_disk: false,
            done_imported: false,
            done_yubikey: None,
            done_return: false,
            done_tested: Vec::new(),
            done_error: None,
            yk_words: crate::wallet::app_yubikey::YkWords::None,
            hidden_open: false,
            account_menu: None,
            activity_all: false,
            recover_return: None,
            settings_last: SettingsSection::Security,
            install_commit: None,
            form: FormState::default(),
            input: PressInput::default(),
            evm: crate::wallet::app_evm::EvmUi::default(),
            sol: crate::wallet::app_sol::SolUi::default(),
            btc: crate::wallet::app_btc::BtcUi::default(),
            zec: crate::wallet::app_zec::ZecUi::default(),
            hypercore: crate::wallet::app_hypercore::HcUi::default(),
            received: crate::wallet::app_received::ReceivedUi::default(),
            wc: crate::wallet::app_walletconnect::WcUi::default(),
            book: crate::wallet::app_book::BookUi::default(),
            keys: crate::wallet::app_keys::KeysUi::default(),
            card: crate::wallet::app_card::CardUi::default(),
            mn: crate::wallet::app_mnemonics::MnUi::default(),
            browser: None,
            llm: None,
            llm_ui: crate::wallet::app_llm::LlmUi::default(),
            guard: SettingsGuard::default(),
            wait: crate::wallet::app_reset::WaitWatch::default(),
            sidecar: crate::wallet::app_sidecar::SidecarUi::default(),
            reset: crate::wallet::app_reset::ResetUi::default(),
            rpc_import: crate::wallet::app_rpc_plan::RpcImportUi::default(),
            explorer_ui: crate::wallet::app_explorer::ExplorerUi::default(),
            secret_session: None,
            secret_serial: 0,
            import: ImportFlow::default(),
            challenge: None,
            idle: IdleTracker::new(now),
            startup_load: true,
            reads_due_ms: 0,
            outbox: VecDeque::new(),
            main_hidden: false,
            #[cfg(debug_assertions)]
            cred_taken: Vec::new(),
            #[cfg(debug_assertions)]
            cred_misses: 0,
        }
    }
}

impl core::fmt::Debug for Wallet {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter
            .debug_struct("Wallet")
            .field("mode", &self.mode)
            .finish_non_exhaustive()
    }
}

impl Wallet {
    /// The main window is hidden or minimized: periodic balance reads pause (2026-11-11);
    /// showing it again reads at the next tick. No window (tests) is not hidden. 2026-11-21
    /// (S4 W3, critique B-10): the wallet's mirror (`Cmd::MainHidden`, kept equal to the window
    /// by the shell's `App::sync_main_hidden`); before, `App::main_hidden` read the window here.
    #[must_use]
    pub const fn main_hidden(&self) -> bool {
        self.main_hidden
    }

    /// Debug builds (2026-11-21, S4 W3, critique B-11): the credential fields taken since the
    /// last call, each with the length and digest of its units (W3 review; before, names only),
    /// for the shell's comparison when a drain starts (`App::cred_check`). 2026-11-23 (S4d E1,
    /// preflight critic C7): a hidden, debug-only cross-crate API (lengths and digests only).
    #[cfg(debug_assertions)]
    #[doc(hidden)]
    pub fn take_cred_log(&mut self) -> Vec<CredTaken> {
        core::mem::take(&mut self.cred_taken)
    }
}

/// The S-level notice after a password change (spec/04 §2.13): the new password is in effect in
/// the first two cases. 2026-11-13: the change also rotates the DEK (spec/02 §4.4), so what is
/// added later is out of reach of old copies, but what an old copy already holds stays exposed (a
/// weak old password can be cracked offline later). `Unconfirmed` (review of the rotation): the
/// `Rewrap` write could not be confirmed and the wallet locked itself.
#[must_use]
pub const fn password_changed_text(lang: Lang, change: PasswordChange) -> &'static str {
    match change {
        PasswordChange::Complete => text::PASSWORD_CHANGED.get(lang),
        PasswordChange::PrevNotRefreshed => text::PASSWORD_CHANGED_PREV.get(lang),
        PasswordChange::Unconfirmed => text::PASSWORD_UNCONFIRMED.get(lang),
    }
}

/// Steps of the create flow (S02 → W01 → W08 → W10, spec/04 §2.3). 2026-11-22 (spec/15 §11.4
/// S4d E0a): with [`IMPORT_STEPS`] and their step texts moved here from `ui::screens` (the secret
/// windows' step bar, `flow_step`, reads them; S02–S06 draw them from here).
pub const CREATE_STEPS: [Text; 3] = [
    text::STEP_PASSWORD,
    text::STEP_WRITE_WORDS,
    text::STEP_BACKUP_CHECK,
];

/// Steps of the import flow (S05 → W01 → W05 → S06, spec/04 §2.4).
pub const IMPORT_STEPS: [Text; 3] = [
    text::STEP_PASSWORD,
    text::STEP_ENTER_WORDS,
    text::STEP_FIRST_ADDRESS,
];

/// The step indicator of the create and import flows shown in their secret windows
/// (spec/04 §2.3–§2.4).
/// The labels of `steps` in `lang`, as a constant (the secret window keeps `&'static` labels).
const fn step_labels<const N: usize>(steps: [Text; N], lang: Lang) -> [&'static str; N] {
    let mut labels = [""; N];
    let mut index = 0;
    while index < N {
        labels[index] = steps[index].get(lang);
        index += 1;
    }
    labels
}

/// The step labels of the flows shown in secret windows, per language.
mod flow_labels {
    use super::{CREATE_STEPS, IMPORT_STEPS, step_labels};
    use crate::wallet::app_keys::KEY_START_STEPS;
    use crate::wallet::app_yubikey::YK_WALLET_STEPS;
    use yw_core::lang::Lang;

    pub const CREATE_KO: [&str; CREATE_STEPS.len()] = step_labels(CREATE_STEPS, Lang::Ko);
    pub const CREATE_EN: [&str; CREATE_STEPS.len()] = step_labels(CREATE_STEPS, Lang::En);
    pub const IMPORT_KO: [&str; IMPORT_STEPS.len()] = step_labels(IMPORT_STEPS, Lang::Ko);
    pub const IMPORT_EN: [&str; IMPORT_STEPS.len()] = step_labels(IMPORT_STEPS, Lang::En);
    pub const KEY_KO: [&str; KEY_START_STEPS.len()] = step_labels(KEY_START_STEPS, Lang::Ko);
    pub const KEY_EN: [&str; KEY_START_STEPS.len()] = step_labels(KEY_START_STEPS, Lang::En);
    pub const YK_KO: [&str; YK_WALLET_STEPS.len()] = step_labels(YK_WALLET_STEPS, Lang::Ko);
    pub const YK_EN: [&str; YK_WALLET_STEPS.len()] = step_labels(YK_WALLET_STEPS, Lang::En);
}

fn flow_step(lang: Lang, purpose: Purpose) -> Option<SecretStep> {
    use flow_labels::{CREATE_EN, CREATE_KO, IMPORT_EN, IMPORT_KO, KEY_EN, KEY_KO, YK_EN, YK_KO};
    use text::{FLOW_CREATE, FLOW_IMPORT, FLOW_KEY_START, FLOW_YK_WALLET};
    let create: &'static [&'static str] = lang.pick(&CREATE_KO, &CREATE_EN);
    let import: &'static [&'static str] = lang.pick(&IMPORT_KO, &IMPORT_EN);
    let key: &'static [&'static str] = lang.pick(&KEY_KO, &KEY_EN);
    let yk: &'static [&'static str] = lang.pick(&YK_KO, &YK_EN);
    let (flow, labels, current): (Text, &'static [&'static str], usize) = match purpose {
        Purpose::CreatePassword => (FLOW_CREATE, create, 1),
        Purpose::ShowForBackup => (FLOW_CREATE, create, 2),
        Purpose::Backup => (FLOW_CREATE, create, 3),
        Purpose::ImportPassword => (FLOW_IMPORT, import, 1),
        Purpose::ImportMnemonic | Purpose::ImportPassphrase => (FLOW_IMPORT, import, 2),
        Purpose::KeyStartPassword => (FLOW_KEY_START, key, 1),
        Purpose::KeyStartKey => (FLOW_KEY_START, key, 2),
        // The new YubiKey wallet has five steps: the wizard is 4 and its PIN setup 5
        // (2026-11-10; it showed n/3 and seemed to end at the backup check).
        Purpose::YubiKey(crate::wallet::app_yubikey::YkPurpose::NewPassword) => {
            (FLOW_YK_WALLET, yk, 1)
        }
        Purpose::YubiKey(crate::wallet::app_yubikey::YkPurpose::ShowWords) => {
            (FLOW_YK_WALLET, yk, 2)
        }
        Purpose::YubiKey(crate::wallet::app_yubikey::YkPurpose::Backup) => (FLOW_YK_WALLET, yk, 3),
        _ => return None,
    };
    Some(SecretStep {
        flow: flow.get(lang),
        labels,
        current,
    })
}

/// What W08's countdown adds on a first display (`다 적었습니다`, spec/04 §4.9): where the words
/// can be seen again after the window closes, or that they are wiped (a new `YubiKey` wallet).
const fn timeout_note(lang: Lang, purpose: Purpose) -> Option<&'static str> {
    let note = match purpose {
        Purpose::ShowForBackup => text::TIMEOUT_BACKUP,
        Purpose::YubiKey(crate::wallet::app_yubikey::YkPurpose::ShowWords) => {
            text::TIMEOUT_YK_WORDS
        }
        Purpose::Mnemonics(_) => text::TIMEOUT_MNEMONICS,
        _ => return None,
    };
    Some(note.get(lang))
}

fn eip55(address: &Address) -> String {
    address.to_checksum()
}

/// E-KEY-002 with the item name before the code (spec/04 §2.11, §7).
fn key002_text(lang: Lang, item: &str) -> String {
    ErrorCode::Key002
        .text_in(lang)
        .replace(" (E-KEY-002)", &format!(" ({item}) (E-KEY-002)"))
}

/// The S15 `QuickNode` fields at `저장`: `None` when both are empty, else the credential —
/// either field may hold the whole endpoint URL pasted from the dashboard
/// ([`quicknode_credentials`]) — or the E-KEY-002 text naming the wrong field
/// (`QuickNodeField::label`). 2026-11-23 (S4d E1): hidden `pub` for yw-app's table tests.
pub(crate) fn quicknode_input(
    lang: Lang,
    name: &str,
    token: &str,
) -> Result<Option<(String, Zeroizing<String>)>, String> {
    if name.trim().is_empty() && token.trim().is_empty() {
        return Ok(None);
    }
    quicknode_credentials(name, token)
        .map(Some)
        .map_err(|field| key002_text(lang, field.label(lang)))
}

impl Wallet {
    /// The App's clock, for the workers and the browser dispatcher that must share its time base
    /// (2026-11-19, S4 B1a: one `Arc` for the App, the RPC worker, the key worker and the
    /// dispatcher, spec/15 §11.4 S4 critique A-9/B-19).
    #[must_use]
    pub fn clock(&self) -> Arc<dyn Clock> {
        Arc::clone(&self.clock)
    }
}

impl Wallet {
    /// The installed commit read at start, kept when it is a commit (2026-11-22, S4c W15: the
    /// body of `App::set_install_commit` before).
    pub fn install_commit_read(&mut self, commit: Option<String>) {
        self.install_commit = commit.filter(|commit| crate::logging::is_commit(commit));
    }

    /// `WerAddExcludedApplication` failed at startup (2026-11-22, S4c W15: the body of
    /// `App::note_wer_unprotected` before).
    pub fn wer_unprotected_noted(&mut self) {
        self.guard.wer_unprotected = true;
        let text = crate::wallet::text::T_WER_UNPROTECTED
            .get(self.settings.language)
            .to_owned();
        self.banner(None, text);
    }
}

impl Wallet {
    /// Adds a banner once per code; a codeless one once per text (a failure repeated while its
    /// band is still up adds no second identical band).
    pub fn banner(&mut self, code: Option<ErrorCode>, text: String) {
        if self
            .banners
            .iter()
            .any(|banner| banner.code == code && (code.is_some() || banner.text == text))
        {
            return;
        }
        self.banners.push(Banner {
            code,
            text,
            tone: crate::screen::Tone::Danger,
        });
    }

    /// Adds a codeless notice banner with its own tone (info, warning); dismissed like the
    /// others with `알림 닫기`.
    pub fn notice(&mut self, text: String, tone: crate::screen::Tone) {
        self.banners.push(Banner {
            code: None,
            text,
            tone,
        });
    }

    pub fn error_banner(&mut self, code: ErrorCode) {
        let lang = self.settings.language;
        logging::warn("app", "error", &[("code", Field::Code(code))]);
        self.banner(Some(code), code.text_in(lang));
    }

    /// The wallet's part of attaching the started browser bridge (2026-11-22, S4c W15; was in
    /// `App::attach_browser`): the pipe server's start failure (`pipe_error`, logged by
    /// `PipeHost::start`) as a banner, then the dispatcher.
    pub fn browser_attached(
        &mut self,
        browser: crate::wallet::app_browser::BrowserUi,
        pipe_error: Option<ErrorCode>,
    ) {
        let lang = self.settings.language;
        if let Some(code) = pipe_error {
            self.banner(Some(code), code.text_in(lang));
        }
        self.browser = Some(browser);
    }

    /// The wallet's part of attaching the started workers (2026-11-22, S4c W15; was in
    /// `App::attach_workers`): the event queue and the RPC sender, then the `yw-llm` worker only
    /// when the feature is effectively on (spec/06 §9).
    pub fn workers_attached(
        &mut self,
        events: Arc<crate::events::EventQueue>,
        rpc_tx: Sender<RpcJob>,
    ) {
        self.events = Some(events);
        self.rpc_tx = Some(rpc_tx);
        self.llm_reconfigure();
    }
}

impl Wallet {
    /// Queues a key job in the current epoch.
    pub fn key(&self, job: KeyJob) {
        self.key_queue.push(self.lock_epoch, job);
    }

    pub(crate) fn set_mode(&mut self, mode: AppMode) {
        if self.mode != mode {
            logging::info("app", "mode", &[("to", Field::Word(mode.word()))]);
            self.mode = mode;
        }
    }

    /// The session was opened with a BIP39 passphrase that failed the stored check value and the
    /// user chose `이 passphrase로 계속` (`Unlocked { alt_passphrase: true }`, spec/02 §7.5).
    ///
    /// Funds sent to this wallet can only be reached again with that exact passphrase, which may
    /// be a typo. While this is `true`: every screen shows the blocking banner T-ALT-PASS, every
    /// `받기` (S12 EVM/Solana/Bitcoin) is refused, and the browser bridge refuses connect and
    /// signing requests with 4100 `ProviderError::PassphraseUnverified` (the dispatcher view
    /// `VaultView::PassphraseUnverified` is built from this query; queued site items end
    /// `QueueOutcome::PassphraseUnverified`) while reads continue (spec/05 §4.2, §5). Sending
    /// from the app stays possible (moving funds out of a deliberately used other-passphrase
    /// wallet).
    #[must_use]
    pub const fn passphrase_unverified(&self) -> bool {
        matches!(
            self.mode,
            AppMode::Unlocked {
                alt_passphrase: true
            }
        )
    }

    /// Opens `screen` at its top (a new screen, an overlay, a lock); the screen under an overlay
    /// opens where it was when the overlay ends (`취소`, or done and back to it).
    pub fn set_screen(&mut self, screen: Screen) {
        self.enter_screen(screen, false);
    }

    /// The way back to `screen` (`← 메인으로`, `← 돌아가기`, `← 처음 설정으로`, a form's `취소`):
    /// it opens where it was left in this run, cut to its content height (2026-11-10).
    pub fn return_to(&mut self, screen: Screen) {
        self.enter_screen(screen, true);
    }

    /// The remembered scroll place of `screen`, if it is one (S10 on the selected chain tab).
    /// 2026-11-20 (S4 P10a): the logic's, read when a scroll effect is emitted (was
    /// `app_scroll::scroll_place`, read by the shell while it applied the effect).
    pub(crate) fn remembered_place(&self, screen: &Screen) -> Option<ScrollPlace> {
        Some(match screen {
            Screen::Main => ScrollPlace::Main(
                self.meta
                    .as_ref()
                    .map_or(crate::meta::Tab::Evm, |meta| meta.prefs.tab),
            ),
            Screen::Settings(section) => ScrollPlace::Settings(*section),
            Screen::Done => ScrollPlace::Done,
            Screen::Sites => ScrollPlace::Sites,
            Screen::AddressBook => ScrollPlace::AddressBook,
            _ => return None,
        })
    }

    fn enter_screen(&mut self, screen: Screen, back: bool) {
        if self.passphrase_unverified()
            && matches!(
                screen,
                Screen::Receive | Screen::SolReceive | Screen::BtcReceive
            )
        {
            self.info = Some(
                crate::wallet::text::T_ALT_PASS_RECEIVE
                    .get(self.settings.language)
                    .to_owned(),
            );
            self.refresh();
            return;
        }
        // Leaving a YubiKey flow by any path wipes its held seed (spec/10 §7.4); leaving
        // "복구 단어" wipes the words held for "복구 단어 추가 가져오기".
        self.yk_leaving(&screen);
        self.mn_leaving(&screen);
        let overlay = matches!(self.screen, Screen::Confirm(_));
        let overlay_opens = matches!(screen, Screen::Confirm(_)) && !overlay;
        let changes = screen != self.screen;
        // 2026-11-20 (S4 P4): the scroll memory is the shell's. It notes where the screen being
        // left (still `self.screen`) was — under an opening overlay, and for the ways back —
        // here, where these steps ran before (`App::screen_leaving`); where the new screen opens
        // is `Effect::ScreenEntered` below. Before, this fn noted and restored the offsets
        // itself. 2026-11-20 (S4 P10a): the place left is worked out here (`left`; before, the
        // shell read `self.screen` while it applied the effect).
        let left = if changes {
            self.remembered_place(&self.screen)
        } else {
            None
        };
        self.emit(Effect::ScreenLeaving {
            overlay_opens,
            left,
        });
        if overlay_opens {
            self.previous_screen = self.screen.clone();
        }
        if changes {
            // A drop-down does not stay open behind another screen (a lock, 2026-11-12).
            let _ = self.close_pickers();
            // A copy's mark belongs to the screen it was made on.
            self.copied = None;
        }
        if screen != self.screen && !matches!(screen, Screen::Confirm(_)) {
            // The inline `주소록에 저장` prompt and its note belong to the screen they opened on.
            self.book.prompt = None;
            self.book.saved = None;
            self.book.btc_picker = false;
        }
        // A removal's completion band stays with its section (its confirmation returns there).
        if !matches!(
            screen,
            Screen::Confirm(_) | Screen::Settings(SettingsSection::Network)
        ) {
            self.rpc_removed = None;
        }
        if !matches!(
            screen,
            Screen::Confirm(_) | Screen::Settings(SettingsSection::Ai)
        ) {
            self.llm_ui.key_deleted = false;
        }
        self.wait
            .screen_changed(&self.screen, &screen, self.clock.now_ms());
        if let Screen::Settings(section) = &screen {
            self.settings_last = *section;
        }
        self.screen = screen;
        // Where the new screen opens (S4 P4, `App::screen_entered`): under a closing overlay
        // where it was, on a way back where it was left, else at the top. `refresh` cuts a
        // remembered offset to the content height. 2026-11-20 (S4 P10a): worked out here from
        // the screen entered and the one left (`EnteredAt`; before, the flags `back` and
        // `overlay`, and the shell read the screens while it applied the effect).
        let at = if overlay && !matches!(self.screen, Screen::Confirm(_)) {
            EnteredAt::UnderOverlay {
                same: self.screen == self.previous_screen,
            }
        } else if back {
            EnteredAt::LeftAt(self.remembered_place(&self.screen))
        } else {
            EnteredAt::Top
        };
        self.emit(Effect::ScreenEntered { at });
        self.refresh();
    }

    // ----- rendering ---------------------------------------------------------------------

    /// Syncs the dApp view (spec/05 §4.5), then recomputes the layout, syncs the child controls
    /// and repaints through `Effect::Render`, applied at once (2026-11-18, S3 B3: the layout
    /// body moved to `render_main` unchanged).
    pub fn refresh(&mut self) {
        self.sync_browser();
        self.emit(Effect::Render);
    }
}

impl Wallet {
    /// `Cmd::Activate`: a second start (`WM_YW_ACTIVATE`, spec/04 §1.1): the main window comes
    /// up, then the unlock window when locked. 2026-11-20 (S4 P4): the window's part is
    /// `Effect::RaiseMain`, at the same point (before, `show_main_window` and `set_foreground`
    /// were called here). 2026-11-22 (S4c W15): wallet code, reached as `Cmd::Activate` (the
    /// main window's message arm sends it); before, `App::activate`, called by that arm.
    fn activate(&mut self) {
        self.emit(Effect::RaiseMain);
        self.background = false;
        self.refresh();
        // Not while a wallet reset moves the files (its vault is gone once it finishes).
        if self.mode == AppMode::Locked && !self.secret_open() && !self.reset.running {
            self.open_input(SecretKind::Unlock, Purpose::Unlock, false);
        }
    }

    /// `Cmd::Tick`: one part of the main timer's period at `now` (2026-11-22, S4c W15; before,
    /// `App::tick` called each part's fn itself), or the reads a main-window message made due.
    fn timer_part(&mut self, now: u64, part: TickPart) {
        match part {
            TickPart::Idle => self.idle_tick(now),
            TickPart::Wait => self.wait_tick(now),
            TickPart::ResetHold => self.reset_hold_tick(now),
            TickPart::Copied => self.copied_tick(now),
            TickPart::Evm => self.evm_tick(now),
            TickPart::HyperCore => self.hc_tick(now),
            TickPart::Sol => self.sol_tick(now),
            TickPart::Btc => self.btc_tick(now),
            TickPart::Zec => self.zec_tick(now),
            TickPart::Received => self.received_tick(now),
            TickPart::ReadsDue => self.reads_due(now),
        }
    }
}

impl Wallet {
    /// The reads a main-window message made due (a tab, network or account choice, the unlock,
    /// a worker's answer) start right after it instead of up to one timer period later
    /// (2026-11-12): the timer's own checks, so the guards, the 15 s cycle and the retries are
    /// the tick's, and several marks in one message still give one read. Bitcoin, Zcash and
    /// `HyperCore` commands start their reads themselves. At most one early balance start per
    /// timer period — a held key (Ctrl+2 repeating) marks them due at the repeat rate, and
    /// the RPC worker runs jobs one after another; the tick starts what this leaves.
    pub(crate) fn reads_due(&mut self, now: u64) {
        if now.saturating_sub(self.reads_due_ms) < u64::from(crate::screen::MAIN_TIMER_MS) {
            return;
        }
        let evm = self.evm_balance_tick(now);
        let sol = self.sol_balance_tick(now);
        self.received_tick(now);
        if evm || sol {
            self.reads_due_ms = now;
        }
    }

    /// The window that may pause the idle clock (spec/04 §5.1, LK-1): a W08/W09 display window
    /// (its serial) or the shown approval (A01, any chain; its queue id), as an identity. Each
    /// has its own time limit; closing does not restart the count (only input does), and a
    /// window shown after another one without input in between does not pause again
    /// ([`IdleTracker::set_window`]), so a dApp's unattended requests — even re-sent back to
    /// back — cannot keep the wallet unlocked.
    ///
    /// 2026-11-22 (S4c W3b, preflight §3.0 and §3 W3b, critic C16): the display window is read
    /// from the wallet's secret session — its kind, its serial (the window's) and whether the
    /// shell reported its window shown — instead of the shell's window record (`App::secret`:
    /// serial, window, form), so this wallet fn names no shell field. At the idle tick (the main
    /// timer, an entry: every earlier open was applied and answered) the two agree: the session
    /// is marked shown exactly when its window was made (`Cmd::SecretOpened` with `Shown`), and
    /// a refused, failed or closed window ends the session. Headless tests, whose secret host
    /// keeps the window outside `App::secret`, now see the shown display window too.
    pub fn idle_window(&self) -> Option<u64> {
        const DISPLAY: u64 = 1 << 63;
        if let Some(session) = self
            .secret_session
            .as_ref()
            .filter(|session| session.shown() && session.kind().is_display())
        {
            return Some(DISPLAY | session.serial());
        }
        match self.evm.queue.shown() {
            Some(item) => Some(item.id.0),
            // An approval window without its queue item (not expected between messages): one
            // window like any other.
            None => self.evm.approval.is_some().then_some(DISPLAY - 1),
        }
    }

    /// The idle part of the main timer: pause/resume, then `LockReason::Idle` when due. Before
    /// any vault exists, a pending import (password, words or key held here or in the key
    /// worker) is discarded after the same idle time.
    pub fn idle_tick(&mut self, now: u64) {
        let window = self.idle_window();
        self.idle.set_window(window);
        if !self.idle.should_lock(now, self.settings.auto_lock_minutes) {
            return;
        }
        if self.mode.holds_secrets() && self.mode != AppMode::Unlocking {
            self.lock_wallet(WalletLock::Idle);
        } else if self.mode == AppMode::NoVault && self.first_run_pending() {
            self.discard_first_run(now);
        }
    }

    /// A first-run import holds secrets (here or, after a preview, in the key worker).
    fn first_run_pending(&self) -> bool {
        self.import.password.is_some()
            || self.import.phrase.is_some()
            || self.import.password_sent
            || self.keys.start.holds_secret()
            || self.secret_open()
            || self.card.wizard.is_some()
            // A new YubiKey wallet's words may be held by the key worker (W08 not shown).
            || self.screen == Screen::YubiKeyWalletIntro
    }

    /// Wipes a pending first-run import after the idle time (spec/04 §5.1): windows closed,
    /// buffers dropped here and in the key worker, back to S01.
    fn discard_first_run(&mut self, now: u64) {
        logging::info("app", "firstrun.discarded_idle", &[]);
        self.close_secret();
        self.import = ImportFlow::default();
        self.keys.start = crate::wallet::app_keys::KeyStartFlow::default();
        self.key(KeyJob::DiscardImport {
            keep_password: false,
        });
        self.key(KeyJob::DiscardKeyStart {
            keep_password: false,
        });
        // A new YubiKey wallet's words and password (held by the key worker).
        self.key(KeyJob::YubiKey(
            crate::workers::key::yubikey::YkJob::Discard,
        ));
        self.card.wizard = None;
        self.idle.input(now);
        self.info = Some(text::IDLE_WIPED.get(self.settings.language).to_owned());
        // Words already shown on W08: their paper belongs to no wallet now.
        self.yk_words_dropped();
        self.set_screen(Screen::FirstRun);
    }
}

impl Wallet {
    /// Removes [`T_CLIP_NOT_CLEARED`] (the caller refreshes). 2026-11-22 (S4c W15): wallet code
    /// (it changes the wallet's `banners`), called by the shell's clip clear and secret copy
    /// where the clipboard answered; before, an `impl App` fn reached through `DerefMut`.
    pub fn drop_clip_notice(&mut self) {
        self.banners.retain(|banner| {
            banner.text != T_CLIP_NOT_CLEARED.ko && banner.text != T_CLIP_NOT_CLEARED.en
        });
    }
}

impl Wallet {
    /// The wallet's own lock (2026-11-21, S4 W3a, preflight critic C11): `잠금`, a cancelled
    /// passphrase, the vault's own lock, a reset, the idle lock and (2026-11-22, S4c W3b) the
    /// shutdown's lock ([`Self::shutdown_steps`]). [`Self::lock_steps`] then
    /// [`Self::lock_after_wait`] with no drain between: the composition [`Self::lock`] drains only
    /// for `Suspend`, which [`WalletLock`] cannot name, so this is exactly what `lock` did for
    /// these reasons. Before W3a the callers called `lock` itself.
    pub(crate) fn lock_wallet(&mut self, reason: WalletLock) {
        let vault_present = self.lock_steps(reason.into());
        self.lock_after_wait(vault_present);
    }

    /// The lock's first half (2026-11-21, S4 W3a; wallet code, preflight §3.0): every step up to
    /// the lock's log line and, for `Suspend`, `Effect::AwaitKeyLock` as its last effect. The
    /// shell steps are effects at their places (the secret close, `SecretEffect::ClearClip`, the
    /// approval close inside `evm_lock`, `Effect::ReleaseHold` inside `hold_cancel`,
    /// `Effect::ScrollMemoryClear`, `Effect::AwaitKeyLock`). Returns whether a vault is present
    /// (read before the lock changes anything), for [`Self::lock_after_wait`].
    pub fn lock_steps(&mut self, reason: LockReason) -> bool {
        // The dispatcher stops answering with accounts now, not after the suspend wait.
        self.browser_lock_begin();
        let vault_present = !matches!(
            self.mode,
            AppMode::NoVault | AppMode::Starting | AppMode::Corrupt { .. } | AppMode::MainMissing
        );
        self.lock_epoch = self.lock_epoch.saturating_add(1);
        // 2026-11-21 (S4 F14, owner decision, spec/04 §5.3, spec/15 §18 item 14): the steps kept
        // for an approval-window open still waiting for its answer (`AfterOpen`) are dropped, and
        // no open waits any more, so no kept step runs after the lock: not with the stale open's
        // answer when the entry drains, nor inside this fn (the `Suspend` drain below), nor in a
        // later entry. The stale open is still answered and makes no window
        // (`open_approval_window`). A step asked for after this point runs at once, as with no
        // open waiting: the lock opens no window. Before F14 the kept steps stayed and ran with
        // the stale answer, after the lock. Clearing after the `Suspend` drain would be too late
        // (`a_suspend_lock_drops_the_steps_kept_for_an_open_before_its_drain`, F14 review).
        // 2026-11-21 (S4 F16, owner decision, spec/15 §18 item 16): a revoke's kept grant write
        // (`AfterOpen::WriteGrantsThenRefresh`) was done above by `browser_lock_begin`'s
        // `flush_grant_writes`, while meta and the dispatcher's grants were still there; only
        // its repaint is dropped here (the lock repaints). Before F16 the write was dropped too.
        // At shutdown the flush here writes nothing (the mode is already `ShuttingDown`): since
        // 2026-11-22 (S4d F21, spec/15 §18 21) `shutdown_begin` wrote the waiting grants before it
        // set that mode; from the F16 review until F21 the shutdown did not write them at all.
        // 2026-11-23 (S4d F22, owner decision spec/15 §18 26 (가) "저장 후 잠금"): the meta save
        // that flush queued is written by the key worker's `KeyJob::Lock` below before its wipe;
        // before F22 that `Lock` (at the front of the queue) cancelled it unless the worker had
        // taken it first.
        self.evm.after_open.clear();
        self.evm.open_unanswered = None;
        let before = self.lock_signal.count();
        self.key(KeyJob::Lock);
        self.card_lock();
        self.close_secret();
        self.import = ImportFlow::default();
        self.challenge = None;
        // Due now; a busy clipboard keeps being retried by the tick after the lock (at exit: for a
        // short while now). 2026-11-20 (S4 P7b, spec/04 §5.3 step 4): the shell's clear through
        // `SecretEffect::ClearClip` at this point; before, this fn called `clear_secret_clip`
        // (with the clock read here) or `clear_secret_clip_at_exit` itself.
        // (2026-11-21, S4 W3: the mode is read first, as before the call; `emit` is the
        // wallet's now and is reached through `App`'s `DerefMut`. 2026-11-22, S4c W15: this fn is
        // `impl Wallet` and calls the wallet's own `emit`; non-test builds have no `DerefMut`.)
        let at_exit = self.mode == AppMode::ShuttingDown;
        self.emit(Effect::Secret(SecretEffect::ClearClip { at_exit }));
        self.evm_lock();
        self.book = crate::wallet::app_book::BookUi::default();
        self.sol_lock();
        self.btc_lock();
        self.zec_lock();
        self.received_lock();
        self.meta = None;
        self.wait = crate::wallet::app_reset::WaitWatch::default();
        // The next unlock reads meta and the journal again (and asks again if they still fail).
        self.sidecar = crate::wallet::app_sidecar::SidecarUi::default();
        self.hold_cancel();
        self.rename = None;
        self.pending_remove = None;
        // A new YubiKey wallet's words go with the lock (the key worker wipes them): S01 says
        // their paper is not a wallet's.
        self.yk_words_dropped();
        self.done_imported = false;
        self.done_yubikey = None;
        self.done_return = false;
        self.done_tested.clear();
        self.done_error = None;
        self.keys = crate::wallet::app_keys::KeysUi::default();
        // The recovery-phrase flows: words typed for "복구 단어 추가 가져오기" (wiped on drop),
        // the preview, the quiz, the removal warning.
        self.mn = crate::wallet::app_mnemonics::MnUi::default();
        self.rpc_import = crate::wallet::app_rpc_plan::RpcImportUi::default();
        self.passphrase_session = false;
        self.recover_return = None;
        // After a lock every screen opens at its top again (2026-11-10). 2026-11-20 (S4 P4): the
        // shell's scroll memory, through `Effect::ScrollMemoryClear` at this point (before, this
        // fn cleared it; the hold's capture above is `Effect::ReleaseHold` inside `hold_cancel`).
        self.emit(Effect::ScrollMemoryClear);
        logging::info("app", "lock", &[("reason", Field::Word(reason.as_str()))]);
        // 2026-11-20 (S4 P7b, critique A-2): the wait for the key worker's lock is
        // `Effect::AwaitKeyLock` at this point (the shell waits as this fn did before), so the
        // secret close, the clip clear and the approval close above stay before it.
        // 2026-11-21 (S4b final review, spec/04 §5.3): drained here, so the wait ends before the
        // mode and screen change and before `Load` is sent below, as before P10b (when `emit`
        // applied each effect at once). From P10b until this fix, `Load` was queued behind
        // `Lock` and the mode and screen changed before the wait, which the entry's drain ran.
        // (2026-11-21, S4 W3a: the drain is the composition `lock`'s, right after this fn
        // returns; before, it was the next line here.)
        if reason == LockReason::Suspend {
            self.emit(Effect::AwaitKeyLock { before, ms: 1_500 });
        }
        vault_present
    }

    /// The lock's second half (2026-11-21, S4 W3a; wallet code): after the `Suspend` wait (the
    /// composition [`Self::lock`] drained it), the mode, the screen and `KeyJob::Load`; nothing
    /// more while shutting down. `vault_present` is [`Self::lock_steps`]'s answer.
    pub fn lock_after_wait(&mut self, vault_present: bool) {
        if self.mode == AppMode::ShuttingDown {
            return;
        }
        self.startup_load = false;
        if vault_present {
            self.set_mode(AppMode::Locked);
        }
        // A running reset keeps its `Processing` screen until its result, which is taken from
        // any epoch: a lock meanwhile (Windows lock, sleep) never strands it on S07 or S01.
        if !self.reset.running {
            if vault_present {
                self.set_screen(Screen::Locked);
            } else if self.mode == AppMode::NoVault {
                self.set_screen(Screen::FirstRun);
            }
        }
        // `Load` is a control job (it survives `Lock`): its result tells what the lock left on
        // disk. A `CreateWallet`/`CommitImport` that finished just before the lock had its
        // result dropped (old epoch), but the vault exists: `Loaded { Locked }` moves the UI
        // from S01 to S07 instead of offering creation over an existing vault.
        // 2026-11-20 (S4 P10b review): a direct send, never an effect (S10), so it leaves now.
        // On `Suspend` that is after the 1.5 s `AwaitKeyLock` wait (drained above, 2026-11-21),
        // as before P10b; from P10b until 2026-11-21 it left before the wait. The worker runs
        // `Lock` first either way (spec/04 §5.3 step 2).
        self.key(KeyJob::Load);
    }
}

impl Wallet {
    /// The shutdown's first wallet half (2026-11-22, S4c W3b; wallet code, preflight §3.0):
    /// `false` when it has begun already (nothing runs twice); else the waiting grant writes
    /// (2026-11-22, S4d F21), `AppMode::ShuttingDown`, then every queued and shown approval item
    /// finishes with `QueueOutcome::Shutdown` (its dApp or app answer), before the shell stops
    /// its pipe server.
    pub fn shutdown_begin(&mut self) -> bool {
        if self.mode == AppMode::ShuttingDown {
            return false;
        }
        // 2026-11-22 (S4d F21, owner decision, spec/15 §18 21; spec/04 §1.5, §5.3, spec/05 §4.5):
        // the grant writes still waiting — a chain switch coalesced inside
        // `GRANT_WRITE_INTERVAL_MS`, a revoke whose write waits for an approval open's answer — are
        // written first, while the mode is still `Unlocked` and meta is loaded, as the lock's
        // `browser_lock_begin` does: the meta save is queued before the shutdown's `KeyJob::Lock`
        // and `wc_grants_changed` goes before `wc_shutdown`. Before F21 the mode was set first,
        // so `flush_grant_writes` (which writes only while unlocked) wrote nothing at shutdown. A
        // locked shutdown is unchanged (nothing is waiting, and the flush needs `Unlocked`).
        // 2026-11-23 (S4d F22, owner decision spec/15 §18 26 (가) "저장 후 잠금"): the key
        // worker's `Lock`, which goes to the front of its queue, writes that save before its wipe
        // (`KeyQueue::take_saves_before`; the lock's own flush is the same). From F21 until F22
        // the worker kept it only if it had taken it before the `Lock`, which cancelled what was
        // still queued.
        self.flush_grant_writes();
        self.set_mode(AppMode::ShuttingDown);
        for (item, outcome) in self.evm.queue.shutdown() {
            self.approval_finished(&item.payload, outcome);
        }
        true
    }

    /// The shutdown's second wallet half (2026-11-22, S4c W3b; wallet code): after the shell's
    /// pipe server stopped, the dispatcher and its read workers, `WalletConnect`, then the
    /// wallet's own lock for `Shutdown` (its effects — the secret close, the clip clear at exit,
    /// the approval close — are the composition's to drain before the wait). Returns the key
    /// worker's lock count read before the lock, which the composition's wait goes beyond.
    pub fn shutdown_steps(&mut self) -> u64 {
        if let Some(browser) = self.browser.as_mut() {
            browser.stop();
        }
        self.wc_shutdown();
        let before = self.lock_signal.count();
        self.lock_wallet(WalletLock::Shutdown);
        before
    }

    /// The shutdown's third wallet half (2026-11-22, S4c W3b; wallet code): after the wait for
    /// the key worker's lock, the key worker, the RPC worker and the AI explanation's worker are
    /// told to stop (direct sends, never effects, S10). The composition then joins them.
    pub fn shutdown_after_wait(&mut self) {
        self.key_queue.push(self.lock_epoch, KeyJob::Shutdown);
        if let Some(tx) = self.rpc_tx.take() {
            let _ = tx.send(RpcJob::Shutdown);
        }
        self.llm_shutdown();
    }
}

impl Wallet {
    /// One worker event (2026-11-22, S4c W15: the typed in-process entry of the shell's event
    /// drain, `App::drain_events`, whose `match` this was): its handler, without a drain (the
    /// shell drains after each event).
    pub fn worker_event(&mut self, event: UiEvent) {
        match event {
            UiEvent::Key(result) => self.key_result(*result),
            UiEvent::Rpc(RpcEvent::Test {
                network,
                message,
                ok,
            }) => self.on_rpc_event(network, message, ok),
            UiEvent::Rpc(event) => self.evm_rpc_event(event),
            UiEvent::Dapp(event) => self.on_dapp_event(event),
            UiEvent::Llm(done) => self.on_llm_done(*done),
            UiEvent::LlmTest(result) => self.on_llm_test(result),
            UiEvent::WalletConnect(event) => self.on_wc_event(*event),
        }
    }

    /// A `테스트` answer: its band, then the next queued test (one at a time).
    pub(crate) fn on_rpc_event(&mut self, network: NetworkId, message: String, ok: bool) {
        self.set_rpc_message(
            network,
            message,
            if ok {
                TestState::Works
            } else {
                TestState::Failed
            },
        );
        if self.rpc_tests.running == Some(network) {
            self.rpc_tests.running = None;
            self.rpc_tests.done = self.rpc_tests.done.saturating_add(1);
            self.next_rpc_test();
        }
        // A working address of the network a chain tab shows: its balances are read again at
        // the next tick (the tab's failure band goes with a good answer, 2026-11-10).
        if ok {
            if network == NetworkId::Eip155(self.settings.evm_chain_id) {
                self.evm_balances_due();
            } else if network == NetworkId::Solana(self.settings.solana.cluster) {
                self.sol.next_balance_ms = 0;
            }
        }
        self.refresh();
    }

    /// What the open secret window is for (2026-11-20, S4 P7a1: the wallet's session; before,
    /// the window record's purpose — the session lasts exactly as long as that window).
    pub(crate) fn secret_purpose(&self) -> Option<Purpose> {
        self.secret_session.as_ref().map(SecretSession::purpose)
    }

    /// Changes the open secret window's form and repaints it (2026-11-20, S4 P7b, spec/04 §4.5:
    /// `SecretEffect::Form` for the open session's serial; the shell changes only that session's
    /// window). Nothing when no session is open. Before, `with_form` changed the window's form and
    /// invalidated the window here (whatever secret window was open — the same window, since the
    /// session and its window end together).
    pub(crate) fn secret_form(&mut self, op: SecretFormOp) {
        if let Some(serial) = self.secret_session.as_ref().map(SecretSession::serial) {
            self.emit(Effect::Secret(SecretEffect::Form { serial, op }));
        }
    }
}

impl Wallet {
    #[expect(clippy::too_many_lines, reason = "one arm per key outcome")]
    fn key_result(&mut self, result: KeyResult) {
        let lang = self.settings.language;
        if !accept_result(&result, self.lock_epoch) {
            return;
        }
        let now = self.clock.now_ms();
        // The YubiKey card step sees signing outcomes first (a returned approval, a retry).
        let Some(outcome) = self.card_filter(result.outcome) else {
            return;
        };
        match outcome {
            KeyOutcome::Quarantined(name) => self.quarantined = Some(name),
            KeyOutcome::WalletReset(result) => self.on_wallet_reset(result),
            KeyOutcome::Loaded { status, leftover } => {
                if self.reset_absorbs_load(leftover) {
                    return;
                }
                self.leftover = leftover;
                self.prev_on_disk = self.store.prev_exists(FileKind::Vault);
                if status == VaultStatus::Locked && self.payload_damaged {
                    // The payload failed authentication at unlock; the intact header makes a
                    // reload report `Locked`. Stay on S09: `recover_from_prev` also works from
                    // `Locked` (it tries the main file first).
                    self.set_mode(AppMode::Corrupt {
                        prev_available: self.prev_on_disk,
                    });
                    self.set_screen(Screen::Recovery);
                    self.startup_load = false;
                    self.browser_vault_loaded();
                    return;
                }
                if status != VaultStatus::Locked {
                    self.payload_damaged = false;
                }
                self.set_mode(AppMode::from_status(status));
                let screen = match status {
                    VaultStatus::NoVault => Screen::FirstRun,
                    VaultStatus::Corrupt { .. } | VaultStatus::MainMissing => {
                        if matches!(status, VaultStatus::Corrupt { .. }) {
                            self.error_banner(ErrorCode::Vlt002);
                        }
                        Screen::Recovery
                    }
                    _ => Screen::Locked,
                };
                self.set_screen(screen);
                if status == VaultStatus::Locked && self.startup_load && !self.background {
                    self.open_input(SecretKind::Unlock, Purpose::Unlock, false);
                }
                self.startup_load = false;
                self.browser_vault_loaded();
            }
            KeyOutcome::Created(Ok((phrase, address))) => {
                self.set_mode(AppMode::BackupPending);
                // The default meta was written with the vault; S04 `받기` needs it.
                self.request_meta();
                self.set_screen(Screen::BackupPending);
                self.open_display(
                    SecretKind::ShowMnemonic { create: true },
                    Purpose::ShowForBackup,
                    DisplaySecret {
                        text: phrase,
                        address: Some(eip55(&address)),
                        passphrase_note: false,
                        copy_allowed: self.settings.allow_secret_copy,
                    },
                );
            }
            KeyOutcome::Created(Err(error)) => {
                self.error_banner(vault_code(error));
                self.reload_after_failed_start();
            }
            KeyOutcome::Preview(Ok(address)) => {
                self.set_screen(Screen::ImportAddress(eip55(&address)));
            }
            KeyOutcome::Preview(Err(error)) => {
                let code = key_code(error);
                let message = match error {
                    yw_core::error::KeyError::MnemonicUnknownWord { position } => {
                        code.render_in(lang, &position.to_string())
                    }
                    _ => code.text_in(lang),
                };
                self.import.phrase = None;
                self.set_screen(Screen::ImportIntro);
                // 2026-11-20 (S4 P9): the error line is made once the window is shown (before,
                // `secret_form` right after the open; a refused window got none either way).
                self.open_input_then(
                    SecretKind::Mnemonic,
                    Purpose::ImportMnemonic,
                    false,
                    AfterShown::Forms(vec![SecretFormOp::Error(Some(message))]),
                );
            }
            KeyOutcome::Imported(Ok(())) => {
                self.import = ImportFlow::default();
                self.set_mode(AppMode::Unlocked {
                    alt_passphrase: false,
                });
                self.idle.input(now);
                self.request_meta();
                // S08 after an import: no backup check ran (the words came from the user).
                self.done_imported = true;
                self.set_screen(Screen::Done);
            }
            KeyOutcome::Imported(Err(error)) if error != VaultError::InvalidState => {
                self.import = ImportFlow::default();
                self.error_banner(vault_code(error));
                self.reload_after_failed_start();
            }
            KeyOutcome::Status(result) => self.on_status(result, now),
            KeyOutcome::KeyStartPreview(result) => self.on_key_start_preview(result),
            KeyOutcome::KeyStartCommitted(Ok(())) => {
                if let Some(network) = self.keys.start.btc_network
                    && self.keys.start.chain == yw_core::keyimport::ImportChain::Btc
                {
                    // A wallet started from a Bitcoin key: Bitcoin on, on the key's network (the
                    // WIF version), so its account shows on the Bitcoin tab right away.
                    let mut bitcoin = self.settings.bitcoin.clone();
                    bitcoin.enabled = true;
                    bitcoin.network = crate::btc::app_network(network);
                    if bitcoin != self.settings.bitcoin {
                        let mut settings = self.settings.clone();
                        settings.bitcoin = bitcoin;
                        self.save_settings(settings, "bitcoin.enabled");
                    }
                }
                self.keys.start = crate::wallet::app_keys::KeyStartFlow::default();
                self.set_mode(AppMode::Unlocked {
                    alt_passphrase: false,
                });
                self.idle.input(now);
                self.request_meta();
                logging::info("app", "keystart.created", &[]);
                // S08 after "개인키로 시작하기": the backup is the original key.
                self.done_imported = false;
                self.keys.done_start = true;
                self.set_screen(Screen::Done);
            }
            // The answer to `DiscardKeyStart`.
            KeyOutcome::KeyStartCommitted(Err(VaultError::InvalidState))
            | KeyOutcome::CardUnused(..) => {}
            KeyOutcome::HardwareKeys(result) => self.on_hardware_keys(result),
            KeyOutcome::KeyStartCommitted(Err(error)) => {
                self.keys.start = crate::wallet::app_keys::KeyStartFlow::default();
                self.error_banner(vault_code(error));
                self.reload_after_failed_start();
            }
            KeyOutcome::KeyImported(result) => self.on_key_imported(result),
            KeyOutcome::ImportedKeyRemoved(Ok((id, chain))) => {
                self.on_imported_key_removed(id, chain);
            }
            KeyOutcome::ImportedKeyBusy(id) => self.on_imported_key_busy(id),
            KeyOutcome::Cancelled("SignEvm" | "SignMessage", _) => self.evm_sign_cancelled(),
            KeyOutcome::Cancelled("SignSol", _) => self.sol_sign_cancelled(),
            KeyOutcome::Zec(outcome) => self.zec_key_outcome(*outcome),
            KeyOutcome::Cancelled("SignZec" | "SignZecCard", _) => {
                self.zec_card_cancelled();
                self.refresh();
            }
            KeyOutcome::Cancelled("SignBtc", _) => {
                self.btc.sign_cancelled();
                self.refresh();
            }
            outcome @ (KeyOutcome::BtcMeta(_)
            | KeyOutcome::SignedBtc(_)
            | KeyOutcome::BtcJournal(_)) => self.btc_key_outcome(outcome),
            KeyOutcome::SolKeys(purpose, result) => {
                let added = matches!(
                    purpose,
                    crate::events::SolKeysPurpose::AddAccount { .. }
                        | crate::events::SolKeysPurpose::AddMnemonicAccount { .. }
                );
                self.on_sol_keys(purpose, result);
                // A dApp's Solana connect may have waited for this account (spec/05 §4.9).
                if added {
                    self.show_next_approval();
                }
            }
            KeyOutcome::SignedSol(result) => self.on_sol_signed(result),
            KeyOutcome::SignedSolDapp(signed) => self.on_sol_dapp_signed(signed),
            KeyOutcome::SignedMessage(result) => self.browser_message_signed(result),
            KeyOutcome::SignedChainMessage(result) => self.browser_chain_message_signed(&result),
            KeyOutcome::YubiKeyEnrolled(result) => self.on_yubikey_enrolled(result),
            KeyOutcome::YubiKey(outcome) => self.on_yk_outcome(outcome),
            KeyOutcome::Mnemonics(outcome) => self.on_mn_outcome(outcome, now),
            KeyOutcome::Imported(Err(_))
            | KeyOutcome::LockDone
            | KeyOutcome::Cancelled(..)
            | KeyOutcome::MetaSaved(Ok(())) => {}
            outcome @ (KeyOutcome::Journal(_)
            | KeyOutcome::SignedEvm(_)
            | KeyOutcome::ActivityMoved(_)) => self.evm_key_outcome(outcome),
            KeyOutcome::Challenge(Ok(challenge)) => {
                self.challenge = Some(challenge);
                if self.secret_purpose() == Some(Purpose::Backup) {
                    let retry = crate::secret::backup_retry_text(
                        self.settings.language,
                        challenge.positions,
                        true,
                    );
                    self.secret_form(SecretFormOp::ResetBackup {
                        positions: challenge.positions,
                        message: Some(retry),
                    });
                } else {
                    self.open_input(
                        SecretKind::Backup {
                            positions: challenge.positions,
                        },
                        Purpose::Backup,
                        false,
                    );
                }
            }
            KeyOutcome::Challenge(Err(error))
            | KeyOutcome::MetaSaved(Err(error))
            | KeyOutcome::Addresses(Err(error)) => self.error_banner(vault_code(error)),
            KeyOutcome::BackupConfirmed(Ok(())) => {
                self.close_secret();
                self.challenge = None;
                logging::info("app", "backup.confirmed", &[]);
                self.set_mode(AppMode::Unlocked {
                    alt_passphrase: false,
                });
                self.idle.input(now);
                self.request_meta();
                // S08 shows T-BACKUP-OK itself.
                self.done_imported = false;
                self.set_screen(Screen::Done);
            }
            KeyOutcome::BackupConfirmed(Err(
                VaultError::BackupMismatch | VaultError::ChallengeStale,
            )) => {
                logging::info("app", "backup.mismatch", &[]);
                self.key(KeyJob::BackupChallenge);
            }
            // 2026-11-20 (S4 P7b): one arm with the raw key import's failure (their two form
            // closures had the same body; as effects clippy sees one arm twice).
            KeyOutcome::BackupConfirmed(Err(error)) | KeyOutcome::RawKeyImported(Err(error)) => {
                self.secret_form(SecretFormOp::Busy(false));
                self.secret_form(SecretFormOp::Error(Some(vault_code(error).text_in(lang))));
            }
            KeyOutcome::Revealed(Ok((what, secret, address))) => {
                let then_backup = matches!(
                    self.secret_purpose(),
                    Some(Purpose::ConfirmPassword(PasswordAction::RevealMnemonic {
                        then_backup: true
                    }))
                );
                self.close_secret();
                let display = DisplaySecret {
                    text: secret,
                    address: address.as_ref().map(eip55),
                    passphrase_note: self.passphrase_session,
                    copy_allowed: self.settings.allow_secret_copy,
                };
                match what {
                    RevealWhat::Mnemonic if then_backup => self.open_display(
                        SecretKind::ShowMnemonic { create: true },
                        Purpose::ShowForBackup,
                        display,
                    ),
                    RevealWhat::Mnemonic => self.open_display(
                        SecretKind::ShowMnemonic { create: false },
                        Purpose::ShowRevealed,
                        display,
                    ),
                    RevealWhat::PrivateKey(_)
                    | RevealWhat::ImportedKey(_)
                    | RevealWhat::BtcEvmShared { .. } => {
                        self.open_display(SecretKind::ShowKey, Purpose::ShowRevealed, display);
                    }
                }
            }
            KeyOutcome::Revealed(Err(error))
            | KeyOutcome::PasswordChanged(Err(error))
            | KeyOutcome::RawKeyRemoved(Err(error))
            | KeyOutcome::ImportedKeyRemoved(Err(error)) => self.password_failure(error, now),
            KeyOutcome::PasswordChanged(Ok(PasswordChange::Unconfirmed)) => {
                // The vault locked itself (spec/02 §4.4): the app follows, and the notice says
                // which password to try first.
                logging::warn(
                    "app",
                    "password.changed",
                    &[("prev", Field::Word("unconfirmed"))],
                );
                self.lock_wallet(WalletLock::Manual);
                self.info = Some(
                    password_changed_text(self.settings.language, PasswordChange::Unconfirmed)
                        .to_owned(),
                );
                self.refresh();
            }
            KeyOutcome::PasswordChanged(Ok(change)) => {
                self.close_secret();
                let complete = change == PasswordChange::Complete;
                logging::info(
                    "app",
                    "password.changed",
                    &[("prev", Field::Word(if complete { "ok" } else { "stale" }))],
                );
                self.info = Some(password_changed_text(self.settings.language, change).to_owned());
                // Review L17: the meta remembers the new vault generation.
                self.save_meta();
                self.refresh();
            }
            KeyOutcome::RawKeyImported(Ok((id, address))) => {
                self.close_secret();
                if let Some(meta) = self.meta.as_mut() {
                    let label = crate::meta::next_imported_label(
                        self.settings.language,
                        crate::meta::EVM_IMPORTED_LABEL,
                        meta.evm_raw_accounts.iter().map(|raw| raw.label.as_str()),
                    );
                    meta.evm_raw_accounts.push(RawAccount {
                        record_id: *id.as_bytes(),
                        label,
                        address: address.to_lower_hex(),
                    });
                }
                logging::info(
                    "app",
                    "rawkey.imported",
                    &[("address", Field::Address(address.as_bytes()))],
                );
                self.save_meta();
                self.evm_balances_due();
                self.refresh();
            }
            KeyOutcome::RawKeyRemoved(Ok(id)) => self.on_evm_raw_key_removed(id),
            KeyOutcome::Meta(Ok(MetaLoaded {
                meta,
                prefs_reset,
                has_mnemonic,
                zec_keys,
                mnemonics,
                ..
            })) => {
                if prefs_reset {
                    logging::warn("app", "meta.prefs_reset", &[]);
                }
                self.keys.has_mnemonic = has_mnemonic;
                self.keys.zec_keys = zec_keys;
                self.mn.infos = mnemonics;
                // The dispatcher's grants follow the reloaded accounts (a YubiKey's accounts
                // the reconcile dropped leave them, spec/05 §4.1, §4.9).
                let hardware = self.hardware_site_accounts();
                self.meta = Some(*meta);
                self.wait.meta_since = None;
                self.wait.meta_failed = None;
                // The accounts may have changed (an added recovery phrase, a `YubiKey`'s
                // accounts): their balances are read at the next tick.
                self.evm_balances_due();
                // Review M1/L15/L17: compare settings.json with the snapshot in the meta.
                self.verify_settings();
                self.hardware_accounts_reloaded(hardware);
                if self.mode == AppMode::BackupPending {
                    // S04 (and its S12) only needs the account list. The chain hooks (journal,
                    // balances, card) run after the backup check, which loads the meta again.
                    if matches!(
                        self.screen,
                        Screen::Processing(_) | Screen::Locked | Screen::Starting | Screen::Main
                    ) {
                        self.set_screen(Screen::BackupPending);
                    } else {
                        self.refresh();
                    }
                    return;
                }
                // Solana account 0 of a recovery-phrase wallet comes with the session's meta
                // (like the Zcash account below), before the dApp queue moves at the unlock: a
                // Solana dApp finds it without the Solana tab ever opened, and a connect queued
                // while locked waits for it (spec/07 §3.1, spec/05 §4.9).
                self.sol_ensure_account();
                if matches!(self.mode, AppMode::Unlocked { .. })
                    && matches!(
                        self.screen,
                        Screen::Processing(_) | Screen::Locked | Screen::Starting
                    )
                {
                    self.set_screen(Screen::Main);
                } else {
                    self.refresh();
                }
                // 2026-11-20 (S4 P10a): the chain hooks follow the answer of an open the dApp
                // view's unlock just asked for (`sync_browser` → `after_browser_unlock`, in the
                // screen change or repaint above) or Bitcoin's controller asks for
                // (`AfterOpen::AfterMeta`, then `AfterOpen::AfterBtcMeta`); before, they ran here
                // directly, in the same order.
                self.after_pending_open(crate::wallet::app_approval::AfterOpen::AfterMeta);
            }
            KeyOutcome::Meta(Err(
                error @ (VaultError::SidecarCorrupt(_)
                | VaultError::SidecarVaultMismatch(_)
                | VaultError::SidecarUnsupported(_)),
            )) => self.meta_unreadable(error),
            KeyOutcome::Meta(Err(error)) => {
                // Fail closed: a read or the reconcile write failed, but the sealed meta (address
                // book, sites, labels, the security snapshot) may be fine. No default stands in
                // for it — a later `save_meta` would seal that over the real one — so no meta is
                // in memory and saving stays off until a load succeeds (T-META-FAILED).
                let code = vault_code(error);
                self.wait.meta_since = None;
                self.wait.meta_failed = Some(code);
                self.meta = None;
                self.error_banner(code);
                self.set_screen(if self.mode == AppMode::BackupPending {
                    Screen::BackupPending
                } else {
                    Screen::Main
                });
            }
            KeyOutcome::SidecarResolved {
                kind,
                use_prev,
                result,
            } => self.on_sidecar_resolved(kind, use_prev, result),
            KeyOutcome::Addresses(Ok(list)) => {
                if let Some(meta) = self.meta.as_mut() {
                    for (index, address) in list {
                        if !meta
                            .evm_accounts
                            .iter()
                            .any(|account| account.index == index)
                        {
                            let number = meta.next_evm_number();
                            meta.evm_accounts.push(new_account(
                                self.settings.language,
                                index,
                                number,
                                &address,
                            ));
                        }
                    }
                    meta.evm_accounts.sort_by_key(|account| account.index);
                }
                self.save_meta();
                self.evm_balances_due();
                self.refresh();
            }
        }
    }

    #[expect(clippy::too_many_lines, reason = "one arm per vault status")]
    fn on_status(&mut self, result: Result<VaultStatus, VaultError>, now: u64) {
        let recovering = self.recover_return;
        match result {
            Ok(status) => {
                if matches!(
                    status,
                    VaultStatus::PassphraseRequired
                        | VaultStatus::PassphraseMismatch
                        | VaultStatus::BackupPending
                        | VaultStatus::Unlocked { .. }
                ) {
                    // A session is open: the files opened, damaged or not before.
                    self.payload_damaged = false;
                    self.unlock_failed = false;
                    self.recover_return = None;
                    if let Some(from) = recovering {
                        self.info = Some(Self::recovered_text(
                            self.settings.language,
                            from,
                            self.quarantined.as_deref(),
                        ));
                    }
                }
                self.set_mode(AppMode::from_status(status));
                match status {
                    VaultStatus::PassphraseRequired => {
                        self.passphrase_session = true;
                        self.set_screen(Screen::Locked);
                        // Several mnemonics use a passphrase: say which one is asked for.
                        // 2026-11-20 (S4 P9): the line is made once the window is shown; the
                        // note is taken before the open (was right after it: the open's answer
                        // does not touch it, and a refused window took it too).
                        let info = self.mn.passphrase_for.take().map(|(position, count)| {
                            AfterShown::Forms(vec![SecretFormOp::Info(Some(
                                text::PASSPHRASE_FOR.fill(
                                    self.settings.language,
                                    [&count.to_string(), &position.to_string()],
                                ),
                            ))])
                        });
                        self.open_input_with(
                            SecretKind::Passphrase { confirm: false },
                            Purpose::EnterPassphrase,
                            false,
                            info,
                        );
                    }
                    VaultStatus::PassphraseMismatch => {
                        self.close_secret();
                        self.mismatch_checked = false;
                        self.set_screen(Screen::PassMismatch);
                    }
                    VaultStatus::BackupPending => {
                        self.close_secret();
                        self.idle.input(now);
                        // S04's `받기` (S12) shows account 0 from the meta: read it now. Before
                        // this, a `BackupPending` session never loaded the meta and S12 waited
                        // for accounts that were never requested.
                        self.request_meta();
                        self.set_screen(Screen::BackupPending);
                        self.browser_vault_loaded();
                    }
                    VaultStatus::Unlocked { alt_passphrase } => {
                        self.close_secret();
                        self.idle.input(now);
                        logging::info("app", "unlock.ok", &[]);
                        if alt_passphrase {
                            logging::warn("app", "unlock.alt_passphrase", &[]);
                        }
                        self.request_meta();
                        self.set_screen(Screen::Processing(
                            text::LOADING.get(self.settings.language),
                        ));
                    }
                    VaultStatus::Corrupt { .. } | VaultStatus::MainMissing => {
                        self.close_secret();
                        self.set_screen(Screen::Recovery);
                    }
                    VaultStatus::Locked | VaultStatus::NoVault => {
                        self.close_secret();
                        self.guard.vault_file = self.store.vault_file_info();
                        self.set_screen(Screen::Locked);
                    }
                }
            }
            Err(VaultError::PayloadCorrupt) if recovering.is_none() => {
                // spec/02 §6.3: the payload failed authentication at unlock. The worker's vault
                // is now `Corrupt`; no reload (the intact header would report `Locked` and hide
                // S09), and `payload_damaged` keeps S09 through any later reload.
                self.close_secret();
                self.error_banner(ErrorCode::Vlt008);
                self.payload_damaged = true;
                self.prev_on_disk = self.store.prev_exists(FileKind::Vault);
                self.set_mode(AppMode::Corrupt {
                    prev_available: self.prev_on_disk,
                });
                self.set_screen(Screen::Recovery);
            }
            Err(error) => {
                if self.mode == AppMode::Unlocking {
                    self.set_mode(recovering.unwrap_or(AppMode::Locked));
                }
                if recovering.is_some() {
                    self.recovery_failure(error, now);
                } else {
                    if error == VaultError::UnlockFailed {
                        self.unlock_failed = true;
                        self.prev_on_disk = self.store.prev_exists(FileKind::Vault);
                    } else if error == VaultError::UnsupportedPayload {
                        // The right password, a newer build's file (E-VLT-014): update the app.
                        // Never offer `.prev`, which would drop the newer records.
                        self.unlock_failed = false;
                    }
                    self.password_failure(error, now);
                }
            }
        }
    }

    /// A create/import/key-start that failed: the vault may already be on disk (saved, then a
    /// later step such as the address lookup failed), so the state is reloaded from the files —
    /// S07 when a vault exists, S01 when not — instead of assuming first run.
    fn reload_after_failed_start(&mut self) {
        self.set_screen(Screen::Processing(
            text::LOADING.get(self.settings.language),
        ));
        self.key(KeyJob::Load);
    }

    /// The S10 note after a successful `.prev` recovery started from `from`, naming the file
    /// the damaged `vault.ywv` was moved to when there was one.
    fn recovered_text(lang: Lang, from: AppMode, quarantined: Option<&str>) -> String {
        let kept = quarantined.map(|name| text::RECOVERED_KEPT.fill(lang, [name]));
        match (from, kept) {
            (AppMode::Corrupt { .. } | AppMode::MainMissing, kept) => {
                text::RECOVERED_CHECK.fill(lang, [&kept.unwrap_or_default()])
            }
            (_, Some(kept)) => text::RECOVERED.fill(lang, [&kept]),
            (_, None) => text::OPENED.get(lang).to_owned(),
        }
    }

    /// A failed `.prev` recovery: the W03 window stays open for another try.
    fn recovery_failure(&mut self, error: VaultError, now: u64) {
        let lang = self.settings.language;
        let text = match error {
            VaultError::UnlockFailed => {
                logging::info("app", "recover.failed", &[]);
                self.secret_form(SecretFormOp::FailPassword { now_ms: now });
                return;
            }
            VaultError::Storage(yw_core::error::StorageError::NotFound) => {
                text::RECOVERY_NO_PREV.get(lang).to_owned()
            }
            VaultError::PayloadCorrupt => text::RECOVERY_PREV_DAMAGED.get(lang).to_owned(),
            other => vault_code(other).text_in(lang),
        };
        logging::warn(
            "app",
            "recover.failed",
            &[("code", Field::Code(vault_code(error)))],
        );
        if self.secret_open() {
            self.secret_form(SecretFormOp::Busy(false));
            self.secret_form(SecretFormOp::Error(Some(text)));
        } else {
            self.banner(None, text);
            self.refresh();
        }
    }

    pub(crate) fn password_failure(&mut self, error: VaultError, now: u64) {
        let lang = self.settings.language;
        if error == VaultError::UnlockFailed {
            logging::info("app", "unlock.failed", &[]);
            self.secret_form(SecretFormOp::FailPassword { now_ms: now });
        } else {
            let code = vault_code(error);
            logging::warn("app", "key.error", &[("code", Field::Code(code))]);
            self.secret_form(SecretFormOp::Busy(false));
            self.secret_form(SecretFormOp::Error(Some(code.text_in(lang))));
            if !self.secret_open() {
                self.error_banner(code);
            }
        }
    }

    // ----- secret windows ----------------------------------------------------------------
    //
    // 2026-11-20 (spec/15 §11.4 S4 P7a1, spec/04 §4.5): the logic's half is the secret session
    // (`secret_session`, a `SecretSession`: serial, kind, purpose, topmost, shown) — `open_input`
    // starts one and emits `SecretEffect::OpenInput`, `on_secret_opened` takes the shell's answer
    // (`Cmd::SecretOpened`), `close_secret` ends it and emits `SecretEffect::Close`. The shell's
    // half is `apply_secret_effect` (`open_input_window`, `close_secret_window`), `create_secret`,
    // `show_secret` and `on_secret`; its window record (`secret`) holds no purpose. Until S4 P7b
    // the display windows (`open_display`) still opened directly (no effect). Before P7a1
    // `open_input`, `open_display` and `close_secret` made, showed and closed the windows
    // themselves, and the purpose was in the window record. 2026-11-20 (S4 P7a2): the `YubiKey`
    // and card input windows open through the seam too (from P7a1 to P7a2 they called the shell's
    // half directly, `open_input_direct`); the step W12 takes once shown (its card's PIN
    // counters) is the session's `AfterShown`, taken by `on_secret_opened`. 2026-11-20 (S4 P7b):
    // the display windows open through the seam too (`open_display` emits
    // `SecretEffect::OpenDisplay`; the session holds the secret until the shell's
    // `open_display_window` has verified the window's capture exclusion and takes it with
    // `take_display_secret`), the form changes are `SecretEffect::Form` (`secret_form`, was
    // `with_form`) and the lock's clip clear is `SecretEffect::ClearClip`. 2026-11-21 (S4 W2):
    // the take is the composition's (`display_window_handoff`, which `App::drain` reaches through
    // `open_display_composed`), after the shell's `make_display_window` verified the exclusion;
    // before, the shell's `open_display_window` took it itself. 2026-11-24 (S5-1, spec/15 §18 30
    // (나)): the take is the wallet's own `Wallet::open_display_window`, which asks the shell's
    // `secret::DisplayHost` to make the window and moves the secret into a verified one only.

    /// Starts the secret session of a window (a fresh serial, never reused); the caller closed the
    /// previous one first. 2026-11-20 (S4 P7a1): the serial was counted in `create_secret` before.
    pub(crate) fn begin_secret(
        &mut self,
        kind: SecretKind,
        purpose: Purpose,
        topmost: bool,
    ) -> u64 {
        self.secret_serial = self.secret_serial.saturating_add(1);
        let serial = self.secret_serial;
        self.secret_session = Some(SecretSession::new(serial, kind, purpose, topmost));
        serial
    }
}

impl Wallet {
    /// Opens an input window (W01–W07, W10–W12) through the seam (2026-11-20, S4 P7a1): the
    /// previous window is closed, a secret session starts, and the shell is asked for the window
    /// (`SecretEffect::OpenInput`); its answer (`Cmd::SecretOpened`) shows it or ends the session
    /// with E-SEC-001 / E-APP-009 (`on_secret_opened`). 2026-11-20 (S4 P10b): the open is queued
    /// and applied when the entry drains, so the window exists, or the banner is up, when the
    /// entry returns; before, applied at once (the inline executor), they were when this
    /// returned.
    pub(crate) fn open_input(&mut self, kind: SecretKind, purpose: Purpose, topmost: bool) {
        self.open_input_with(kind, purpose, topmost, None);
    }

    /// [`Self::open_input`] whose session takes `after` once the shell reports the window shown
    /// (`on_secret_opened`), never for a refused or failed window (2026-11-20, S4 P7a2: W12's
    /// card counters; before, the handler read the session right after the open).
    pub(crate) fn open_input_then(
        &mut self,
        kind: SecretKind,
        purpose: Purpose,
        topmost: bool,
        after: AfterShown,
    ) {
        self.open_input_with(kind, purpose, topmost, Some(after));
    }

    /// [`Self::open_input`] or [`Self::open_input_then`], by whether the opener has a step for
    /// the shown window (2026-11-20, S4 P9: `pub(crate)` for an opener whose step is optional).
    pub(crate) fn open_input_with(
        &mut self,
        kind: SecretKind,
        purpose: Purpose,
        topmost: bool,
        after: Option<AfterShown>,
    ) {
        self.close_secret();
        let serial = self.begin_secret(kind, purpose, topmost);
        if let Some(after) = after
            && let Some(session) = self.secret_session.as_mut()
        {
            session.then_when_shown(after);
        }
        let lang = self.settings.language;
        self.emit(Effect::Secret(SecretEffect::OpenInput {
            serial,
            kind,
            step: flow_step(lang, purpose),
            topmost,
            lang,
        }));
    }
}

impl Wallet {
    /// The answer to a secret window's open (`Cmd::SecretOpened`; S4 P7a1). Only the first
    /// answer for the open session counts: one for another serial (a session that has ended) or
    /// for a window already shown is dropped. `Shown` marks the session shown; `Refused`
    /// (E-SEC-001) and `Failed` (E-APP-009) end it and say so on the main window, as `open_input`
    /// did. 2026-11-20 (S4 P7a2): `Shown` then takes the session's `AfterShown` step (W12: the
    /// card's PIN counters read, `Wallet::yk_card_counters`), at the point the handler took it right
    /// after the open before. 2026-11-20 (S4 P7b): it also answers the display windows' open
    /// (`open_display` called it with the window's result before): `Shown` takes W08's
    /// `AfterShown::YkWordsShown` (a new `YubiKey` wallet's words count as shown, `yk_words`; the
    /// handler `on_yk_outcome` read the session right after the open before), and a refused W08
    /// of a new wallet (`Purpose::ShowForBackup`) leaves the wallet on S04 (`BackupPending`,
    /// spec/04 §4.5 item 2) after the E-SEC-001 banner, as `open_display` did.
    fn on_secret_opened(&mut self, serial: u64, outcome: OpenOutcome) {
        let Some(session) = self
            .secret_session
            .as_mut()
            .filter(|session| session.serial() == serial && !session.shown())
        else {
            return;
        };
        match outcome {
            OpenOutcome::Shown { .. } => match session.mark_shown() {
                Some(AfterShown::CardCounters { card }) => self.yk_card_counters(card),
                Some(AfterShown::YkWordsShown)
                    if self.yk_words == crate::wallet::app_yubikey::YkWords::None =>
                {
                    self.yk_words = crate::wallet::app_yubikey::YkWords::Shown;
                }
                Some(AfterShown::YkWordsShown) | None => {}
                // 2026-11-20 (S4 P9): the opener's form operations, now that its window is shown
                // (before, the opener made them right after the open returned).
                Some(AfterShown::Forms(ops)) => {
                    for op in ops {
                        self.secret_form(op);
                    }
                }
            },
            OpenOutcome::Refused(code) => {
                let purpose = session.purpose();
                self.secret_session = None;
                self.error_banner(code);
                if purpose == Purpose::ShowForBackup {
                    self.set_screen(Screen::BackupPending);
                }
            }
            OpenOutcome::Failed(code) => {
                self.secret_session = None;
                self.error_banner(code);
            }
        }
    }

    /// Opens a display window (W08/W09); on exclusion failure the secret is wiped (E-SEC-001)
    /// and a new wallet's W08 leaves it on S04. 2026-11-20 (S4 P7b, spec/04 §4.5 item 3): through
    /// the seam — the previous window is closed, a secret session starts and holds the secret,
    /// and the shell is asked for the window (`SecretEffect::OpenDisplay`, no secret in it); the
    /// shell takes the secret only after it verified the new window's capture exclusion
    /// (`open_display_window`), and its answer (`Cmd::SecretOpened`) marks the session shown or
    /// ends it with the banner (`on_secret_opened`). 2026-11-20 (S4 P10b): the open is queued and
    /// applied when the entry drains, in the order of the queue; when the session ended in the
    /// same entry before that (a lock), the open is stale and makes no window and moves no secret
    /// (spec/04 §4.5 item 6). Until P10b it was applied at once (the inline executor), so the
    /// window, the wipe, the banner and the screen change happened at the same point and in the
    /// same order as before P7b, when this fn made the window and filled it itself — with one
    /// exception (2026-11-20, P7b review): a window that was made but whose exclusion was not
    /// read back (`Refuse` with a window) is now destroyed inside `open_display_window` (2026-11-21,
    /// S4 W2: `display_window_handoff`, after the wipe as before; 2026-11-24, S5-1: the wallet's
    /// [`Self::open_display_window`] with the shell's `DisplayHost`, after the wipe as before), so
    /// before the answer's banner and the S04 change; before P7b it was destroyed after them, at
    /// the end of this fn's match. It is still destroyed after the wipe, was never shown and never
    /// held the secret, so nothing reaches the screen either way.
    pub(crate) fn open_display(
        &mut self,
        kind: SecretKind,
        purpose: Purpose,
        display: DisplaySecret,
    ) {
        self.open_display_with(kind, purpose, display, None);
    }

    /// [`Self::open_display`] whose session takes `after` once the shell reports the window
    /// shown (2026-11-20, S4 P7b: W08 of a new `YubiKey` wallet marks its words shown; before,
    /// the handler read the session right after the open).
    pub(crate) fn open_display_then(
        &mut self,
        kind: SecretKind,
        purpose: Purpose,
        display: DisplaySecret,
        after: AfterShown,
    ) {
        self.open_display_with(kind, purpose, display, Some(after));
    }

    fn open_display_with(
        &mut self,
        kind: SecretKind,
        purpose: Purpose,
        display: DisplaySecret,
        after: Option<AfterShown>,
    ) {
        self.close_secret();
        let lang = self.settings.language;
        let serial = self.begin_secret(kind, purpose, false);
        if let Some(session) = self.secret_session.as_mut() {
            session.hold_display(display);
            if let Some(after) = after {
                session.then_when_shown(after);
            }
        }
        self.emit(Effect::Secret(SecretEffect::OpenDisplay {
            serial,
            kind,
            step: flow_step(lang, purpose),
            timeout_note: timeout_note(lang, purpose),
            lang,
        }));
    }
}

impl Wallet {
    /// The display secret of session `serial`, moved out once, only while `serial` is the open
    /// session and its window is not shown yet (2026-11-20, S4 P7b; plan §3.4 `App::drain`
    /// handoff, critique A-3). Called only after the shell verified the window's capture
    /// exclusion; `None` for an ended or another session. 2026-11-21 (S4 W2): called by the
    /// composition `display_window_handoff` (before, by the shell's `open_display_window`).
    /// 2026-11-24 (S5-1): called only by [`Self::open_display_window`] (for a verified window)
    /// and [`Self::drop_display_secret`] (before, by `hand_display_secret`).
    #[must_use]
    pub(crate) fn take_display_secret(&mut self, serial: u64) -> Option<DisplaySecret> {
        self.secret_session
            .as_mut()
            .filter(|session| session.serial() == serial)
            .and_then(SecretSession::take_display)
    }

    /// Drops (wipes) the display secret of session `serial` now: its window was refused or
    /// failed (2026-11-20, S4 P7b; `open_display` dropped it itself before). 2026-11-21 (S4 W2):
    /// called by the composition `display_window_handoff`. 2026-11-24 (S5-1): called only by
    /// [`Self::open_display_window`] for an unverified window (before, by `hand_display_secret`).
    pub(crate) fn drop_display_secret(&mut self, serial: u64) {
        if let Some(display) = self.take_display_secret(serial) {
            // 2026-11-23 (S4d E0b, preflight O-4): a probe note, which the tests' secret seam
            // logs as `display-dropped` (before, a `cfg(test)` call of that seam).
            crate::probe::note(crate::probe::Probe::DisplayDropped);
            drop(display);
        }
    }

    /// A display window's open (W08/W09), the one way a display secret leaves the wallet
    /// (2026-11-24, spec/15 §11.4 S5-1, §18 30 (나), 주인 결정(2026-11-23); spec/04 §4.5 item 4;
    /// D-4). Only the open of the open, unshown session `serial` goes on (critique A-3: a stale
    /// or second open makes no window and is `Refused(E-SEC-001)`). The shell's `host` makes the
    /// window and reads its capture exclusion back ([`DisplayHost::make`]); only a
    /// [`DisplayMade::Verified`] window gets the secret, moved out of the session once
    /// ([`Self::take_display_secret`]) and into the host's [`DisplayHost::fill_and_show`] by value,
    /// with the wallet's clock read right before; the answer is then `Shown { capture_excluded:
    /// true }`. On [`DisplayMade::Unverified`] the session's secret is dropped (wiped,
    /// [`Self::drop_display_secret`]) first, then the made window, if any, is dropped (the shell
    /// destroys it), and the host's outcome is the answer. A verified window whose session holds
    /// no secret is dropped and refused. Nothing here returns the secret.
    ///
    /// Before S5-1 (S4d E1, E1 review) the shell made and read back the window itself, then
    /// asked for the secret with `hand_display_secret(serial, DisplayCheck::Verified)`, whose
    /// return value was the secret — any crate could call it with `Verified` (in effect a `pub`
    /// take), and testkit's `WalletTestExt::take_display_secret` was a second `pub` way to it.
    /// Both are gone. The engine still trusts what the host reports (spec/15 §18 30); which hosts
    /// exist, and that only the Windows shell's composition `App::open_display_composed` (and
    /// testkit's `RecordingShell`) calls this, is the source check
    /// `the_display_secret_moves_only_in_the_composition`; the behaviour is pinned by the
    /// `s4_secret` goldens.
    pub fn open_display_window<H: DisplayHost + ?Sized>(
        &mut self,
        host: &mut H,
        serial: u64,
        kind: SecretKind,
        step: Option<SecretStep>,
        timeout_note: Option<&'static str>,
        lang: Lang,
    ) -> OpenOutcome {
        if !self.secret_unshown(serial) {
            return OpenOutcome::Refused(ErrorCode::Sec001);
        }
        match host.make(serial, kind, lang) {
            DisplayMade::Verified(window) => {
                let Some(secret) = self.take_display_secret(serial) else {
                    drop(window);
                    return OpenOutcome::Refused(ErrorCode::Sec001);
                };
                let now_ms = self.clock.now_ms();
                host.fill_and_show(
                    serial,
                    window,
                    kind,
                    secret,
                    step,
                    timeout_note,
                    lang,
                    now_ms,
                );
                OpenOutcome::Shown {
                    capture_excluded: true,
                }
            }
            // A window made but not excluded is destroyed after the wipe and before the answer
            // (the order of the shell's arm before S5-1; 2026-11-20, P7b review).
            DisplayMade::Unverified { outcome, window } => {
                self.drop_display_secret(serial);
                drop(window);
                outcome
            }
        }
    }

    /// Whether `serial` is the open secret session and its window not shown yet (2026-11-23, S4d
    /// E1): the shell's check before it makes a secret window (critique A-3: a stale open makes
    /// none). Before E1 the shell read the session itself (one crate).
    #[must_use]
    pub fn secret_unshown(&self, serial: u64) -> bool {
        self.secret_session
            .as_ref()
            .is_some_and(|session| session.serial() == serial && !session.shown())
    }

    /// The open secret session, the last serial, the import flow's held flags and the backup
    /// check's positions, for `testkit::WalletTestExt` only (2026-11-23, S4d E1, preflight O-11:
    /// read-only, no production accessor; before E1 the yw-app tests read the private fields).
    pub(crate) const fn test_secret_session(&self) -> Option<&SecretSession> {
        self.secret_session.as_ref()
    }

    /// 2026-11-23 (S4d E1 review): the setup steps of `testkit::WalletTestExt` (put a session in,
    /// change the open one); before, the slot itself (`test_secret_session_mut`) went to the
    /// tests.
    pub(crate) fn test_set_secret_session(&mut self, session: Option<SecretSession>) {
        self.secret_session = session;
    }

    pub(crate) fn test_open_secret_session(&mut self) -> Option<&mut SecretSession> {
        self.secret_session.as_mut()
    }

    pub(crate) const fn test_secret_serial(&self) -> u64 {
        self.secret_serial
    }

    pub(crate) const fn test_import_held(&self) -> (bool, bool) {
        (self.import.password.is_some(), self.import.phrase.is_some())
    }

    pub(crate) const fn test_challenge(&self) -> Option<BackupChallenge> {
        self.challenge
    }

    /// The effects queued and not taken yet (2026-11-23, S4d E1): the shell's debug checks that
    /// an entry drained (before E1 they read the queue itself).
    #[must_use]
    pub fn queued_effects(&self) -> usize {
        self.outbox.len()
    }

    /// Whether a secret window (W01–W12) is open: a secret session, from the request until the
    /// window's end (2026-11-20, S4 P7a1; before, whether the window record existed — the same
    /// while the effects were applied at once). 2026-11-20 (S4 P10b): with the outbox the two
    /// differ inside an entry (a queued open or close), not between messages (every entry drains).
    #[must_use]
    pub fn secret_open(&self) -> bool {
        self.secret_session.is_some()
    }

    /// Whether `serial` is the open secret session's (2026-11-22, S4c W12): the read the shell's
    /// [`Self::apply_form_action`] makes before its own arms, as it did before W12 by reading
    /// the session's purpose. Private (2026-11-22, S4c W12 review: it was `pub(crate)`, a new
    /// crate-wide read of the session's serial with one caller in this file; `Wallet` is declared
    /// here, so a private fn stays callable after W14c, A-15).
    #[must_use]
    pub fn secret_session_is(&self, serial: u64) -> bool {
        self.secret_session
            .as_ref()
            .is_some_and(|session| session.serial() == serial)
    }

    /// Closes the open secret window (buffers wiped): ends the secret session and asks the shell
    /// to close its window (2026-11-20, S4 P7a1: `SecretEffect::Close`; before, the window was
    /// closed here). Nothing when no session is open.
    pub fn close_secret(&mut self) {
        if let Some(session) = self.secret_session.take() {
            self.emit(Effect::Secret(SecretEffect::Close {
                serial: session.serial(),
            }));
        }
    }
}

impl Wallet {
    /// What the window of secret session `serial` ended or asked for that is the wallet's
    /// (2026-11-22, S4c W12, preflight critic C12; plan §3.6, §7.3): the typed in-process entry
    /// the shell's [`Self::apply_form_action`] calls. The arms are the ones that fn held before
    /// W12, unchanged. An action of a session that is not the open one is dropped (its
    /// submission wiped, critique A-21). Wallet code (`WALLET_FNS`); `impl Wallet` from W14c.
    pub fn on_secret_action(&mut self, serial: u64, action: SecretAction) {
        let Some(purpose) = self
            .secret_session
            .as_ref()
            .filter(|session| session.serial() == serial)
            .map(SecretSession::purpose)
        else {
            return;
        };
        match action {
            SecretAction::Submit(submission) => self.on_submit(purpose, submission),
            SecretAction::Cancel | SecretAction::TimedOut => {
                let timed_out = matches!(action, SecretAction::TimedOut);
                // A new YubiKey wallet's W08/W10: S01's band about the unused paper says it.
                let words_band = matches!(
                    purpose,
                    Purpose::YubiKey(
                        crate::wallet::app_yubikey::YkPurpose::ShowWords
                            | crate::wallet::app_yubikey::YkPurpose::Backup
                    )
                ) && self.yk_words != crate::wallet::app_yubikey::YkWords::None;
                self.on_cancel(purpose);
                if timed_out && !words_band {
                    self.info = Some(text::TIMED_OUT.get(self.settings.language).to_owned());
                    self.refresh();
                }
            }
            SecretAction::Close => {
                self.close_secret();
                self.refresh();
            }
            SecretAction::HoldComplete => {
                logging::info("app", "backup.written_ack", &[]);
                if let Purpose::YubiKey(yk) = purpose {
                    self.yk_hold_complete(yk);
                } else if let Purpose::Mnemonics(mn) = purpose {
                    self.mn_hold_complete(mn);
                } else {
                    self.close_secret();
                    self.key(KeyJob::BackupChallenge);
                }
            }
        }
    }
}

impl Wallet {
    #[expect(clippy::too_many_lines, reason = "one arm per secret-window purpose")]
    pub(crate) fn on_submit(&mut self, purpose: Purpose, submission: Submission) {
        if let Purpose::YubiKey(yk) = purpose {
            self.yk_submit(yk, submission.values, submission.checkbox);
            return;
        }
        if let Purpose::Mnemonics(mn) = purpose {
            self.mn_submit(mn, submission.values, submission.checkbox);
            return;
        }
        let mut values = submission.values.into_iter();
        let mut next = || values.next().unwrap_or_default();
        match purpose {
            Purpose::CreatePassword => {
                let password = next();
                self.close_secret();
                self.set_screen(Screen::Processing(
                    text::CREATING.get(self.settings.language),
                ));
                self.key(KeyJob::CreateWallet { password });
            }
            Purpose::ImportPassword => {
                self.import.password = Some(next());
                self.import.password_sent = false;
                self.open_input(SecretKind::Mnemonic, Purpose::ImportMnemonic, false);
            }
            Purpose::ImportMnemonic => {
                let phrase = next();
                if submission.checkbox {
                    self.import.phrase = Some(phrase);
                    self.open_input(
                        SecretKind::Passphrase { confirm: true },
                        Purpose::ImportPassphrase,
                        false,
                    );
                } else {
                    self.preview_import(phrase, None);
                }
            }
            Purpose::ImportPassphrase => {
                let passphrase = next();
                if let Some(phrase) = self.import.phrase.take() {
                    self.preview_import(phrase, Some(passphrase));
                } else {
                    self.close_secret();
                }
            }
            Purpose::Unlock => {
                self.set_mode(AppMode::Unlocking);
                self.secret_form(SecretFormOp::Busy(true));
                self.key(KeyJob::Unlock { password: next() });
            }
            Purpose::EnterPassphrase => {
                self.secret_form(SecretFormOp::Busy(true));
                self.key(KeyJob::EnterPassphrase { passphrase: next() });
            }
            Purpose::Backup => {
                let Some(challenge) = self.challenge else {
                    self.close_secret();
                    return;
                };
                let words = [next(), next(), next(), next()];
                self.secret_form(SecretFormOp::Busy(true));
                self.key(KeyJob::ConfirmBackup {
                    id: challenge.id,
                    words,
                });
            }
            Purpose::ConfirmPassword(action) => {
                let password = next();
                self.secret_form(SecretFormOp::Busy(true));
                match action {
                    PasswordAction::RevealMnemonic { .. } => self.key(KeyJob::Reveal {
                        password,
                        what: RevealWhat::Mnemonic,
                    }),
                    PasswordAction::RevealKey(source) => self.key(KeyJob::Reveal {
                        password,
                        what: RevealWhat::PrivateKey(source),
                    }),
                    PasswordAction::RemoveKey(id) => {
                        self.key(KeyJob::RemoveRawKey { password, id });
                    }
                    PasswordAction::RevealImported(id) => self.key(KeyJob::Reveal {
                        password,
                        what: RevealWhat::ImportedKey(id),
                    }),
                    PasswordAction::RevealBtcEvmShared { evm_index, network } => {
                        self.key(KeyJob::Reveal {
                            password,
                            what: RevealWhat::BtcEvmShared { evm_index, network },
                        });
                    }
                    PasswordAction::RemoveImported(id) => {
                        self.key(KeyJob::RemoveImportedKey { password, id });
                    }
                    PasswordAction::RemoveHardwareKey(id) => self.key(KeyJob::YubiKey(
                        crate::workers::key::yubikey::YkJob::Remove { password, id },
                    )),
                    PasswordAction::Recover => {
                        // Where to return on failure or cancel (S09, or S07 after a failed
                        // unlock); a retry after a failure is already back in that mode.
                        if self.mode != AppMode::Unlocking {
                            self.recover_return = Some(self.mode);
                        }
                        self.quarantined = None;
                        self.set_mode(AppMode::Unlocking);
                        self.key(KeyJob::RecoverFromPrev { password });
                    }
                }
            }
            Purpose::ChangePassword => {
                let old = next();
                let new = next();
                self.secret_form(SecretFormOp::Busy(true));
                self.key(KeyJob::ChangePassword { old, new });
            }
            Purpose::ImportKey => {
                self.secret_form(SecretFormOp::Busy(true));
                self.key(KeyJob::ImportPrivateKey { hex: next() });
            }
            Purpose::KeyStartPassword => self.key_start_password(next()),
            Purpose::KeyStartKey => self.key_start_key(next()),
            Purpose::ImportChainKey(spec) => {
                self.secret_form(SecretFormOp::Busy(true));
                self.key(KeyJob::ImportKey { spec, key: next() });
            }
            Purpose::CardSign(id) => self.card_submit(id, next()),
            Purpose::ShowForBackup
            | Purpose::ShowRevealed
            | Purpose::YubiKey(_)
            | Purpose::Mnemonics(_) => {}
        }
    }

    fn preview_import(
        &mut self,
        phrase: Zeroizing<Vec<u8>>,
        passphrase: Option<Zeroizing<Vec<u8>>>,
    ) {
        self.close_secret();
        let password = if self.import.password_sent {
            None
        } else {
            self.import.password_sent = true;
            self.import.password.take()
        };
        self.set_screen(Screen::Processing(
            text::CHECKING.get(self.settings.language),
        ));
        self.key(KeyJob::PreviewImport {
            password,
            phrase,
            passphrase,
        });
    }

    pub(crate) fn on_cancel(&mut self, purpose: Purpose) {
        self.close_secret();
        match purpose {
            Purpose::CreatePassword => self.set_screen(Screen::FirstRun),
            Purpose::ImportPassword | Purpose::ImportMnemonic | Purpose::ImportPassphrase => {
                self.import = ImportFlow::default();
                self.key(KeyJob::DiscardImport {
                    keep_password: false,
                });
                self.set_screen(Screen::FirstRun);
            }
            Purpose::KeyStartPassword | Purpose::KeyStartKey => {
                self.key_start_cancel();
                self.set_screen(Screen::FirstRun);
            }
            Purpose::EnterPassphrase => self.lock_wallet(WalletLock::Manual),
            Purpose::Unlock => {
                if self.mode == AppMode::Unlocking {
                    self.set_mode(AppMode::Locked);
                }
                self.dapp_unlock_dismissed();
                self.refresh();
            }
            Purpose::ShowForBackup | Purpose::Backup => {
                self.challenge = None;
                self.set_screen(Screen::BackupPending);
            }
            Purpose::ConfirmPassword(PasswordAction::Recover) => {
                // Back to where recovery was asked from, without a reload (a reload of a
                // payload-damaged vault would report `Locked` and hide S09).
                let back = self.recover_return.take().unwrap_or(self.mode);
                let back = if back == AppMode::Unlocking {
                    AppMode::Locked
                } else {
                    back
                };
                self.set_mode(back);
                self.set_screen(match back {
                    AppMode::Corrupt { .. } | AppMode::MainMissing => Screen::Recovery,
                    _ => Screen::Locked,
                });
            }
            Purpose::CardSign(id) => self.card_cancel(id),
            Purpose::YubiKey(yk) => self.yk_cancel(yk),
            Purpose::Mnemonics(mn) => self.mn_cancel(mn),
            Purpose::ConfirmPassword(_)
            | Purpose::ShowRevealed
            | Purpose::ChangePassword
            | Purpose::ImportKey
            | Purpose::ImportChainKey(_) => self.refresh(),
        }
    }

    // ----- meta, settings, apikeys -------------------------------------------------------

    pub(crate) fn save_meta(&mut self) {
        // After a failed meta load nothing in memory may replace the sealed meta.
        if self.wait.meta_failed.is_some() {
            logging::warn("app", "meta.save_skipped", &[]);
            return;
        }
        // Review L17: remember the newest `vault.ywv` generation with every meta write, so a
        // `vault.ywv` rolled back on its own is noticed at the next unlock.
        if let Some((found, written)) = self.store.vault_file_info() {
            self.guard.vault_file = Some((found, written));
            if let Some(meta) = self.meta.as_mut()
                && found > meta.security.vault_generation_seen
                && self.guard.rollback.is_none()
            {
                meta.security.vault_generation_seen = found;
            }
        }
        if let Some(meta) = self.meta.clone() {
            self.key(KeyJob::SaveMeta {
                meta: Box::new(meta),
            });
        }
    }

    /// Writes `settings` atomically; on failure keeps the previous values (E-APP-002). A
    /// `settings.json` of a newer app version (`Settings::read_only`, spec/04 §6.6) is never
    /// written: the change applies to this run only (its E-APP-001 banner says so).
    pub fn save_settings(&mut self, settings: Settings, key: &'static str) {
        let written =
            settings.read_only().is_some() || self.store.write_settings(&settings.to_json());
        if written {
            if settings.log_level != self.settings.log_level {
                logging::set_level(settings.log_level);
            }
            if settings.language != self.settings.language {
                // spec/14 §1 (2026-11-14): the main window is rebuilt from `items()` by the
                // `refresh` below, so every fixed text (and the banner tags and copy captions the
                // renderer adds) follows at once. The window title is the product name in both
                // languages and there is no tray icon (spec/04 §1). The last notice was written
                // in the old language and goes; banners and RPC test lines keep the language they
                // were written in until they are replaced.
                self.key(KeyJob::SetLanguage(settings.language));
                self.info = None;
            }
            let memory_only = settings.read_only().is_some();
            self.settings = settings;
            logging::info(
                "app",
                "settings.changed",
                &[
                    ("key", Field::Word(key)),
                    ("saved", Field::Word(if memory_only { "no" } else { "yes" })),
                ],
            );
            self.after_settings_saved(key, memory_only);
        } else {
            self.error_banner(ErrorCode::App002);
        }
        self.refresh();
    }

    /// Encrypts and writes `apikeys.dpapi`; on failure reloads the previous file (E-APP-002).
    /// (2026-11-20, S4 P1: through `self.store`, the same DPAPI and file calls; the result is
    /// still synchronous, callers branch on it.)
    pub fn save_apikeys(&mut self) -> bool {
        let plain = self.apikeys.encode();
        let written = self.store.write_sealed_keys(&plain);
        if !written {
            let (keys, _) = crate::app_store::load_sealed_keys(self.store.as_ref(), &self.settings);
            self.apikeys = keys;
            if self.guard.verified
                && let Some(host) = self
                    .meta
                    .as_ref()
                    .and_then(|meta| meta.security.snapshot.as_ref())
                    .map(|snapshot| snapshot.llm.host.clone())
            {
                self.bind_llm_key_to(&host);
            }
            self.error_banner(ErrorCode::App002);
        }
        written
    }

    // ----- settings snapshot (review M1, L15) and vault generation (L17) ----------------------

    /// After a successful `save_settings`: the app itself changed the values, so the snapshot
    /// follows (written with the meta). Without a snapshot yet (locked, meta not loaded) the key
    /// is remembered and taken over at the next check.
    fn after_settings_saved(&mut self, key: &'static str, memory_only: bool) {
        if !self.guard.verified || self.meta.is_none() {
            if !self.guard.saved_early.contains(&key) {
                self.guard.saved_early.push(key);
            }
            return;
        }
        if !memory_only {
            // The file now holds exactly the values in use.
            self.guard.pending = None;
        }
        let snapshot = crate::settings::SecuritySnapshot::of(&self.settings);
        if let Some(meta) = self.meta.as_mut()
            && meta.security.snapshot.as_ref() != Some(&snapshot)
        {
            meta.security.snapshot = Some(snapshot);
            self.save_meta();
        }
    }

    /// Binds a stored LLM key that has no host yet (an older version's) to `host`, the host the
    /// user consented to in the snapshot — never to whatever `settings.json` names (review M1).
    /// In memory; written with the next `apikeys.dpapi` save.
    fn bind_llm_key_to(&mut self, host: &str) {
        if !host.is_empty() && self.apikeys.bind_llm_host(host) {
            logging::info("app", "apikeys.llm_host_bound", &[]);
        }
    }

    /// Compares the settings in use with `stored` (the meta snapshot) and returns the snapshot
    /// to keep (review M1, L15). `None` (a meta written before snapshots existed, or a new
    /// wallet): the snapshot is created from the settings in use, once, and logged.
    ///
    /// With a snapshot: the LLM is switched off when it is on without a consent for the current
    /// endpoint host; a missing or changed genesis pin is restored; fee caps, auto-lock, the
    /// Bitcoin indexer and user chains the snapshot does not know use the snapshot values while
    /// a banner offers the file values. Keys the app saved itself before the check are taken
    /// over. Afterwards the `yw-llm` worker may start ([`SettingsGuard::verified`]).
    pub fn reconcile_settings(
        &mut self,
        stored: Option<crate::settings::SecuritySnapshot>,
    ) -> crate::settings::SecuritySnapshot {
        let early = core::mem::take(&mut self.guard.saved_early);
        let Some(stored) = stored else {
            logging::info("app", "settings.snapshot_created", &[]);
            let snapshot = crate::settings::SecuritySnapshot::of(&self.settings);
            self.guard.verified = true;
            self.bind_llm_key_to(&snapshot.llm.host);
            self.llm_reconfigure();
            return snapshot;
        };
        let outcome = crate::settings::reconcile(&self.settings, &stored, &early);
        if outcome.write_file
            && outcome.file.read_only().is_none()
            && !self.store.write_settings(&outcome.file.to_json())
        {
            self.error_banner(ErrorCode::App002);
        }
        if outcome.llm_forced_off {
            logging::warn("app", "settings.llm_consent_missing", &[]);
            self.banner(
                None,
                crate::settings::LLM_FORCED_OFF_TEXT
                    .get(self.settings.language)
                    .to_owned(),
            );
        }
        for id in &outcome.pins_restored {
            logging::warn(
                "app",
                "settings.pin_restored",
                &[("net", Field::Net(NetworkId::Eip155(*id)))],
            );
        }
        if !outcome.pins_restored.is_empty() {
            self.banner(
                None,
                crate::settings::PIN_RESTORED_TEXT
                    .get(self.settings.language)
                    .to_owned(),
            );
        }
        if !outcome.differing.is_empty() {
            logging::warn(
                "app",
                "settings.file_differs",
                &[(
                    "count",
                    Field::Num(u64::try_from(outcome.differing.len()).unwrap_or(0)),
                )],
            );
            self.guard.pending = Some(Box::new((outcome.file.clone(), outcome.differing.clone())));
        }
        if outcome.effective.log_level != self.settings.log_level {
            logging::set_level(outcome.effective.log_level);
        }
        self.settings = outcome.effective;
        self.guard.verified = true;
        self.bind_llm_key_to(&outcome.snapshot.llm.host);
        self.llm_reconfigure();
        outcome.snapshot
    }

    /// The check after the meta loaded (unlock): the settings snapshot (review M1, L15) and the
    /// remembered `vault.ywv` generation (review L17).
    pub(crate) fn verify_settings(&mut self) {
        let Some(stored) = self
            .meta
            .as_ref()
            .map(|meta| meta.security.snapshot.clone())
        else {
            return;
        };
        let snapshot = self.reconcile_settings(stored);
        let file = self.store.vault_file_info();
        self.guard.vault_file = file;
        let Some(meta) = self.meta.as_mut() else {
            return;
        };
        let mut changed = meta.security.snapshot.as_ref() != Some(&snapshot);
        meta.security.snapshot = Some(snapshot);
        if let Some((found, _)) = file {
            let seen = meta.security.vault_generation_seen;
            if found < seen {
                self.guard.rollback = Some((seen, found));
                self.banner(
                    None,
                    crate::meta::rollback_text(self.settings.language, seen, found),
                );
                logging::warn(
                    "app",
                    "vault.generation_backwards",
                    &[("seen", Field::Num(seen)), ("found", Field::Num(found))],
                );
            } else if found > seen {
                meta.security.vault_generation_seen = found;
                changed = true;
            }
        }
        if changed {
            self.save_meta();
        }
    }

    /// `파일 값 사용`: the values found in `settings.json` become the ones in use and the
    /// snapshot follows.
    pub(crate) fn settings_accept_file(&mut self) {
        let Some(pending) = self.guard.pending.take() else {
            return;
        };
        let (file, _) = *pending;
        logging::info("app", "settings.file_accepted", &[]);
        self.save_settings(file, crate::settings::ACCEPT_FILE_KEY);
    }

    /// `앱에 저장된 값으로 되돌리기`: `settings.json` is rewritten with the values in use (the
    /// snapshot's).
    pub(crate) fn settings_restore(&mut self) {
        if self.guard.pending.take().is_none() {
            return;
        }
        logging::info("app", "settings.file_restored", &[]);
        self.save_settings(self.settings.clone(), "settingsFileRestored");
    }
}

impl Wallet {
    /// An id that is no press clears the copy mark and nothing else (2026-11-22, S4c W15: the
    /// shell's `on_command` wrote `copied` itself before).
    pub fn forget_copy_mark(&mut self) {
        self.copied = None;
    }

    /// One input from the shell (spec/15 §3.2, §11.4 S3), handled at once in this borrow.
    /// 2026-11-22 (S4c W15, plan §3.4): the wallet's `on_cmd` (Android's `call`, spec/15 §3.2),
    /// which `App::dispatch` and the drain's answers reach; before, `App::on_cmd`. It also takes
    /// the shell's plain-data entries `Cmd::Activate`, `Cmd::Input` and `Cmd::Tick` (before W15,
    /// the shell called those wallet fns itself).
    pub fn on_cmd(&mut self, cmd: Cmd) {
        match cmd {
            Cmd::Press { press, input } => {
                // The press's input is installed for exactly this press (a press inside it,
                // Enter's primary button, has its own) and wiped when it ends.
                let outer = core::mem::replace(&mut self.input, input);
                self.on_press(press);
                let used = core::mem::replace(&mut self.input, outer);
                #[cfg(debug_assertions)]
                {
                    self.cred_misses = self.cred_misses.saturating_add(used.misses());
                }
                drop(used);
            }
            Cmd::Form(snapshot) => self.form.replace(snapshot),
            // One edit's read-back after a field write (2026-11-21, S4 W2: the executor's
            // answer; before, the executor set the field itself).
            Cmd::FieldShown { field, text } => self.form.set(field, text),
            // The field's own handler runs after the state has the text.
            // S3 C2: a converted family's handler takes the field and its text. S3 C11: every
            // handler is converted; a field none claims is ignored, as the legacy chain ignored
            // it. S3 D3: the handler is chosen by `match field` (`on_field_edit`).
            Cmd::Edit { field, text } => {
                let text = field.clamp(&text);
                self.form.set(field, Some(text.clone()));
                let _ = self.on_field_edit(field, &text);
            }
            // The send forms' one-shot check (`Effect::StartTimer`, S3 B4).
            Cmd::Timer(TimerId::SendCheck) => self.on_send_timer(),
            // A plain copy's result (`Effect::CopyText`, S3 B4).
            Cmd::CopyDone { ok, mark } => self.copy_done(ok, mark),
            // One input of an approval window (S4 B6): dropped unless it is the shown window's.
            Cmd::Approval(input) => self.on_approval_input(input),
            // The approval window's open (`Effect::Approval(Open)`, S4 B5).
            // 2026-11-20 (S4 P9): then the steps its opener left for after the open
            // (`AfterOpen`; before, the opener ran them after `show_next_approval` returned).
            // 2026-11-20 (S4 P10a): the open no longer waits and its kept steps are taken before
            // the answer's own steps, then run after them through `after_pending_open` (they
            // wait for the answer of an open those steps asked for; applied at once, none
            // waits). Before, `after_approval_opened(shown)` took and ran them after
            // `on_approval_opened`.
            Cmd::ApprovalOpened {
                shown,
                outcome,
                wide,
            } => {
                let after = self.approval_open_answered(shown);
                self.on_approval_opened(shown, outcome, wide);
                self.after_pending_open(after);
            }
            // An explorer link's open (`Effect::OpenUrl`, S4 P3).
            Cmd::Opened { ok, which } => self.on_opened(ok, which),
            // The extension folder was not found (`Effect::OpenFolder`, S4 P3).
            Cmd::FolderMissing => self.on_folder_missing(),
            // A secret input window's open (`Effect::Secret(OpenInput)`, S4 P7a1).
            Cmd::SecretOpened { serial, outcome } => self.on_secret_opened(serial, outcome),
            // S22's hold area, pressed and released (2026-11-21, S4 W1; the shell keeps the
            // area and the pointer, the logic the gate).
            Cmd::HoldBegin { now_ms } => self.reset_hold_begin(now_ms),
            Cmd::HoldEnd => self.hold_cancel(),
            // A second start asked for the wallet (2026-11-22, S4c W15; before, the shell's
            // `App::activate`).
            Cmd::Activate => self.activate(),
            // App input (2026-11-22, S4c W15; before, the shell's `App::note_input` wrote the
            // idle clock).
            Cmd::Input => {
                let now = self.clock.now_ms();
                self.idle.input(now);
            }
            // One part of the main timer (2026-11-22, S4c W15; before, the shell's `App::tick`
            // called each part).
            Cmd::Tick { now_ms, part } => self.timer_part(now_ms, part),
            // The main window was hidden, minimized, shown or restored (2026-11-21, S4 W3,
            // critique B-10): the wallet's mirror, read by the polling ticks.
            Cmd::MainHidden(hidden) => self.main_hidden = hidden,
        }
    }

    /// A press: the copy mark and the last press follow it, then its handler runs (2026-11-20,
    /// S4 P6: the last press is also the last command; before, the id `command` was set too).
    /// 2026-11-18 (S3 C1): a converted family's press goes to its handler here, after the two
    /// checks the legacy chain made before any family handler (they keep their order): the
    /// receive gate (`Press::is_receive_gated` while the passphrase is unverified) and the
    /// received-history read of a card's `새로고침` (`Press::refresh_chain`).
    fn on_press(&mut self, press: Press) {
        self.last_press = press;
        // The mark is for the last press: a command that changes the value behind the marked
        // control (another account, a new receive address) must not leave it there.
        self.copied = None;
        match press {
            // 2026-11-20 (S4 P4): nothing more here — the shell resolves the key after this
            // press (`on_command`); before, `escape_key`/`enter_key` ran here.
            Press::Back | Press::Enter => {}
            _ if self.passphrase_unverified() && press.is_receive_gated() => {
                self.refuse_receive();
            }
            family => {
                if let Some(chain) = family.refresh_chain() {
                    self.received_now(chain);
                }
                self.on_family(family);
            }
        }
    }

    /// A converted family's press (S3 C1–C12: one arm per family). Enter and Esc never come
    /// here (`on_press`).
    fn on_family(&mut self, press: Press) {
        match press {
            Press::Core(press) => self.on_core(press),
            Press::Received(press) => self.on_received(press),
            Press::Sites(press) => self.on_sites(press),
            Press::Llm(press) => self.on_llm(press),
            Press::Wc(press) => self.on_wc(press),
            Press::Hidden(press) => self.on_hidden(press),
            Press::Sidecar(press) => self.on_sidecar(press),
            Press::Explorer(press) => self.on_explorer(press),
            Press::Links(press) => self.on_links(press),
            Press::Book(press) => self.on_book(press),
            Press::Reset(press) => self.on_reset(press),
            Press::Keys(press) => self.on_keys(press),
            Press::Mn(press) => {
                // `false`: a row naming no phrase, which nothing else claims (as before).
                let _ = self.on_mn(press);
            }
            Press::Hc(press) => self.on_hc(press),
            Press::Zec(press) => self.on_zec(press),
            Press::Sol(press) => self.on_sol(press),
            Press::Btc(press) => self.on_btc(press),
            Press::Evm(press) => self.on_evm(press),
            Press::YkManage(press) => self.on_yk_manage_press(press),
            Press::YkConnect(press) => self.on_yk_connect(press),
            Press::Yk(press) => self.on_yk(press),
            // Ext and the `rpc.json` import: the shell's press handlers, run by `App::on_command`
            // right after this press (2026-11-22, S4c W15, critique B-5); before, called here.
            Press::Back | Press::Enter | Press::Ext(_) | Press::RpcImport(_) => {}
        }
    }

    /// A receive or receive-address copy press while the passphrase is unverified: refused
    /// before any chain handler runs (BTC would derive and store a new address).
    fn refuse_receive(&mut self) {
        self.info = Some(
            crate::wallet::text::T_ALT_PASS_RECEIVE
                .get(self.settings.language)
                .to_owned(),
        );
        self.refresh();
    }
}

impl Wallet {
    /// The edit handler of `field`'s family (S3 C2–C12); `false` for a field read only when
    /// its button is pressed, which nothing handles while typing (2026-11-18, S3 C11: the legacy
    /// `edit_chain` ran here before; its last handler, `YubiKey`'s, is converted, and an edit no
    /// handler claims is still ignored). S3 D3: routed by `match field`; before, each family's
    /// handler was asked in turn until one claimed the field (they claim disjoint fields, so
    /// the order never mattered: test `edits_route_to_the_one_handler_that_claims_them`).
    pub(crate) fn on_field_edit(&mut self, field: EditField, text: &str) -> bool {
        use EditField as F;
        match field {
            F::WcUri | F::WcFile | F::WcProject => self.on_wc_edit(field, text),
            F::ResetPhrase => self.on_reset_edit(field, text),
            F::BookAddress | F::BookLabel | F::BookPromptLabel => self.on_book_edit(field, text),
            F::MnRemoveTyped => self.on_mn_edit(field, text),
            F::HcTo | F::HcAmount | F::HcApi => self.on_hc_edit(field, text),
            F::ZecSendTo | F::ZecSendAmount => self.on_zec_edit(field, text),
            F::SolSendTo | F::SolSendAmount => self.on_sol_edit(field, text),
            F::BtcSendTo
            | F::BtcSendAmount
            | F::BtcFeeManual
            | F::BtcTypedFee
            | F::BtcBumpManual
            | F::BtcBumpTyped
            | F::BtcEsploraMainnet
            | F::BtcEsploraTestnet4 => self.on_btc_edit(field, text),
            F::EvmSendTo
            | F::EvmSendAmount
            | F::EvmTokenAddress
            | F::EvmTokenLabel
            | F::EvmChainId
            | F::EvmChainName
            | F::EvmChainSymbol
            | F::EvmChainDecimals
            | F::EvmChainExplorer
            | F::EvmCapFee
            | F::EvmCapTip
            | F::EvmCapTotal => self.on_evm_edit(field, text),
            // The wizard's fields and (asked first inside) the card actions' ones.
            F::YkSigIndex
            | F::YkAutIndex
            | F::YkSolCount
            | F::YkSolStart
            | F::YkOverwrite
            | F::YkReslotSigIndex
            | F::YkReslotAutIndex
            | F::YkClearConfirm
            | F::YkReslotLoss
            | F::YkClearLoss => self.on_yk_edit(field, text),
            F::ExplorerTx | F::ExplorerAddress => self.on_explorer_edit(field, text),
            F::LlmEndpoint | F::LlmModel | F::LlmMaxTokens => self.on_llm_edit(field, text),
            // Read when their `저장` is pressed (form state), not while typing.
            F::CoreRename
            | F::CoreAutoLock
            | F::BtcRename
            | F::MnRename
            | F::SolFeeCap
            | F::SolCuPrice
            | F::SolRename
            | F::YkCardName => false,
        }
    }

    /// Presses of the core screens, settings sections and URL rows (2026-11-18, S3 C12: a
    /// `CorePress`; before, the core arms of `dispatch_legacy` by control id, then
    /// `on_indexed_command` for the four row ranges). The receive gate ran before these arms
    /// and never matched one of their ids; it is now only `on_press`'s.
    #[expect(clippy::too_many_lines, reason = "one arm per command id")]
    fn on_core(&mut self, press: CorePress) {
        match press {
            CorePress::FirstCreate => self.set_screen(Screen::CreateIntro),
            CorePress::FirstImport => self.set_screen(Screen::ImportIntro),
            // 2026-11-20 (S4 P3): the shell opens them (`Effect::OpenFolder`); before, this
            // started `explorer.exe` with the path directly.
            CorePress::OpenDataFolder => self.emit(Effect::OpenFolder(Folder::Data)),
            CorePress::OpenLogFolder => self.emit(Effect::OpenFolder(Folder::Logs)),
            CorePress::CreateNext => {
                self.open_input(SecretKind::SetPassword, Purpose::CreatePassword, false);
            }
            CorePress::IntroCancel => {
                self.key_start_cancel();
                self.set_screen(Screen::FirstRun);
            }
            CorePress::ImportNext => {
                self.open_input(SecretKind::SetPassword, Purpose::ImportPassword, false);
            }
            CorePress::ImportCorrect => {
                self.set_screen(Screen::Processing(
                    text::IMPORTING.get(self.settings.language),
                ));
                self.key(KeyJob::CommitImport);
            }
            CorePress::ImportWrong => {
                self.key(KeyJob::DiscardImport {
                    keep_password: true,
                });
                self.set_screen(Screen::ImportIntro);
                self.open_input(SecretKind::Mnemonic, Purpose::ImportMnemonic, false);
            }
            CorePress::Unlock => self.open_input(SecretKind::Unlock, Purpose::Unlock, false),
            CorePress::BackupCheck => self.open_input(
                SecretKind::ConfirmPassword,
                Purpose::ConfirmPassword(PasswordAction::RevealMnemonic { then_backup: true }),
                false,
            ),
            CorePress::Lock => self.lock_wallet(WalletLock::Manual),
            CorePress::DoneContinue | CorePress::BackMain | CorePress::SwitchAccount => {
                self.info = None;
                self.clear_done();
                if self.mode == AppMode::BackupPending {
                    // `← 메인으로` from S12 during the backup check: S04 is this mode's main
                    // screen (S10, and a `Processing` wait for it, never come in this mode).
                    if self.meta.is_none() {
                        self.request_meta();
                    }
                    self.set_screen(Screen::BackupPending);
                } else if self.meta.is_some() {
                    // `← 메인으로` is a way back (where S10 was left); `지갑 열기` opens it.
                    if press == CorePress::DoneContinue {
                        self.set_screen(Screen::Main);
                    } else {
                        self.return_to(Screen::Main);
                    }
                } else {
                    self.request_meta();
                    self.set_screen(Screen::Processing(
                        text::LOADING.get(self.settings.language),
                    ));
                }
            }
            CorePress::Recover => {
                // S09, or S07 after a failed unlock (a damaged key section looks like a wrong
                // password; `recover_from_prev` from `Locked` tries the main file first).
                if !matches!(
                    self.mode,
                    AppMode::Corrupt { .. } | AppMode::MainMissing | AppMode::Locked
                ) {
                    return;
                }
                self.open_input(
                    SecretKind::ConfirmPassword,
                    Purpose::ConfirmPassword(PasswordAction::Recover),
                    false,
                );
            }
            // 2026-11-22 (S4c W3b, preflight critic C11): the shell runs the shutdown right after
            // this press (`on_command`, as it resolves Enter and Esc after theirs); the press
            // still sets the last press and clears the copy mark (`on_press`). Before, this arm
            // called the shell's composition `App::shutdown` itself.
            CorePress::Exit => {}
            CorePress::MismatchRetry => {
                self.key(KeyJob::RetryPassphrase);
            }
            CorePress::MismatchCheck(checked) => {
                self.mismatch_checked = checked.unwrap_or(false);
                self.refresh();
            }
            CorePress::MismatchContinue => {
                if self.mismatch_checked {
                    self.key(KeyJob::AcceptMismatch);
                }
            }
            CorePress::SidecarPrev | CorePress::SidecarFresh => {
                self.choose_sidecar(FileKind::Meta, press == CorePress::SidecarPrev);
            }
            // `설정` (and Ctrl+,) opens the section last opened in this run (2026-11-10).
            CorePress::OpenSettings => self.set_screen(Screen::Settings(self.settings_last)),
            CorePress::SectionSecurity => {
                self.set_screen(Screen::Settings(SettingsSection::Security));
            }
            CorePress::DoneRpc | CorePress::DoneRpcJson | CorePress::DoneWc => {
                // S08's '처음 설정' card: the opened screen's back link returns to S08.
                self.done_return = true;
                if press == CorePress::DoneWc {
                    self.set_screen(Screen::Sites);
                } else {
                    self.set_screen(Screen::Settings(SettingsSection::Network));
                    if press == CorePress::DoneRpcJson {
                        // S4 P4: `Effect::Reveal` (before, `reveal_id` with the control id).
                        self.emit(Effect::Reveal(RevealTarget::Press(Press::RpcImport(
                            RpcImportPress::Import,
                        ))));
                    }
                }
            }
            CorePress::SectionNetwork | CorePress::GoNetwork => {
                self.set_screen(Screen::Settings(SettingsSection::Network));
            }
            CorePress::BackDone => self.return_to(Screen::Done),
            CorePress::DoneConnect => self.done_connect(),
            CorePress::DoneMainnet => {
                // The network chip's path (`evmChainId`), from S08's '잔액이 안 보이면' card.
                let mut settings = self.settings.clone();
                settings.evm_chain_id = yw_core::evm::chain::ETHEREUM_MAINNET;
                self.save_settings(settings, "evmChainId");
                self.evm_balances_due();
            }
            CorePress::TestAll => self.test_all_networks(),
            CorePress::EvmRpcOpen => {
                self.open_rpc_row(NetworkId::Eip155(self.settings.evm_chain_id), true);
            }
            CorePress::SolRpcOpen => {
                self.open_rpc_row(NetworkId::Solana(self.settings.solana.cluster), true);
            }
            CorePress::BtcRpcOpen => {
                self.open_rpc_row(NetworkId::Bitcoin(self.settings.bitcoin.network), true);
            }
            CorePress::ZecRpcOpen => {
                self.open_rpc_row(NetworkId::Zcash(self.settings.zcash.network), true);
            }
            // The failure band of an EVM / Solana network card (2026-11-10): the stored address's
            // `테스트` (its three-state band in the same card), or that network's row.
            CorePress::EvmRpcTest => {
                self.test_network(NetworkId::Eip155(self.settings.evm_chain_id));
            }
            CorePress::SolRpcTest => {
                self.test_network(NetworkId::Solana(self.settings.solana.cluster));
            }
            CorePress::EvmRpcRow => {
                self.open_rpc_row(NetworkId::Eip155(self.settings.evm_chain_id), false);
            }
            CorePress::SolRpcRow => {
                self.open_rpc_row(NetworkId::Solana(self.settings.solana.cluster), false);
            }
            CorePress::SectionOther => self.set_screen(Screen::Settings(SettingsSection::Other)),
            CorePress::AdvancedToggle => {
                self.show_advanced = !self.show_advanced;
                self.refresh();
            }
            CorePress::DismissBanners => {
                self.banners.clear();
                // Review L17: a dismissed rollback warning is acknowledged; the next meta write
                // remembers the current generation.
                self.guard.rollback = None;
                self.info = None;
                self.refresh();
            }
            CorePress::SettingsAcceptFile => {
                // Every file value at once (a new chain without a pin, higher caps, another
                // lookup server): confirmed with the list first (2026-11-08).
                if self.guard.pending.is_some() {
                    self.set_screen(Screen::Confirm(Confirm::SettingsFile));
                }
            }
            CorePress::SettingsRestore => self.settings_restore(),
            CorePress::AddAccount => self.add_account_clicked(),
            CorePress::ImportKey => {
                self.open_key_import(yw_core::keyimport::ImportChain::Evm);
            }
            CorePress::Rename => {
                self.rename = self.selected_pref();
                self.refresh();
            }
            CorePress::RenameCancel => {
                self.rename = None;
                self.refresh();
            }
            CorePress::RenameSave => self.save_rename(),
            CorePress::Hide => self.hide_selected(),
            CorePress::RemoveKey => {
                if let Some(EvmAccountPref::Record(id)) = self.selected_pref() {
                    self.pending_remove = Some(RecordId::from_bytes(id));
                    self.set_screen(Screen::Confirm(Confirm::RemoveKey));
                }
            }
            CorePress::RevealMnemonic => self.set_screen(Screen::Confirm(Confirm::RevealMnemonic)),
            CorePress::RevealKey => self.set_screen(Screen::Confirm(Confirm::RevealKey)),
            CorePress::ChangePassword => {
                self.open_input(SecretKind::ChangePassword, Purpose::ChangePassword, false);
            }
            CorePress::AutolockSave => self.save_autolock(),
            CorePress::CopyToggle(checked) => {
                let checked = checked.unwrap_or(false);
                if checked && !self.settings.allow_secret_copy {
                    self.set_screen(Screen::Confirm(Confirm::CopyOn));
                } else if !checked {
                    let mut settings = self.settings.clone();
                    settings.allow_secret_copy = false;
                    self.save_settings(settings, "allowSecretCopy");
                }
            }
            CorePress::LocalhostToggle(checked) => {
                let checked = checked.unwrap_or(false);
                if checked && !self.settings.allow_localhost_dapps {
                    self.set_screen(Screen::Confirm(Confirm::LocalhostOn));
                } else if !checked {
                    let mut settings = self.settings.clone();
                    settings.allow_localhost_dapps = false;
                    self.save_settings(settings, "allowLocalhostDapps");
                }
            }
            CorePress::AutolaunchToggle(checked) => {
                let mut settings = self.settings.clone();
                settings.browser_auto_launch = checked.unwrap_or(true);
                self.save_settings(settings, "browserAutoLaunch");
            }
            CorePress::LogLevel(level) => {
                let mut settings = self.settings.clone();
                settings.log_level = level;
                self.save_settings(settings, "logLevel");
            }
            CorePress::Lang(language) => {
                if language != self.settings.language {
                    let mut settings = self.settings.clone();
                    settings.language = language;
                    self.save_settings(settings, crate::settings::LANGUAGE_KEY);
                }
            }
            CorePress::Template(template) => {
                let mut settings = self.settings.clone();
                settings.rpc_template = template;
                self.save_settings(settings, "rpc.template");
            }
            CorePress::TemplateSave => {
                if self.save_template_credentials() == Ok(true) {
                    let lang = self.settings.language;
                    let mut info = text::TPL_SAVED.get(lang).to_owned();
                    if !self.template_addresses() {
                        // Saved, but nothing uses the credentials yet (2026-11-10).
                        info.push_str(text::TPL_SAVED_NO_ADDRESS.get(lang));
                    }
                    self.info = Some(info);
                }
                self.refresh();
            }
            CorePress::TemplateDelete => {
                // The stored value cannot be shown again: asked first (2026-11-10).
                if self.template_stored() {
                    self.set_screen(Screen::Confirm(Confirm::TemplateDelete));
                }
            }
            CorePress::Generate => self.begin_generate(),
            CorePress::PruneDormant => {
                if !self.apikeys.dormant_names().is_empty() {
                    self.set_screen(Screen::Confirm(Confirm::PruneDormant));
                }
            }
            CorePress::OverwriteCheck(checked) => {
                self.overwrite_checked = checked.unwrap_or(false);
                self.refresh();
            }
            CorePress::ReplaceSave => self.save_replacement(),
            CorePress::ReplaceCancel => {
                self.replace_target = None;
                self.refresh();
            }
            CorePress::ConfirmYes => self.confirm_yes(),
            CorePress::ConfirmNo if matches!(self.screen, Screen::Confirm(Confirm::Btc)) => {
                self.btc_confirm_no();
            }
            CorePress::ConfirmNo
                if matches!(self.screen, Screen::Confirm(Confirm::JournalCorrupt)) =>
            {
                self.journal_choice_closed();
            }
            CorePress::ConfirmNo => {
                self.pending_remove = None;
                self.keys.target = None;
                self.card.remove_target = None;
                self.evm.discard = None;
                self.evm.delete_chain = None;
                self.evm.repin = None;
                self.llm_ui.notice_checked = false;
                if let Some(form) = self.evm.chain_form.as_mut() {
                    form.pending = None;
                    form.message = None;
                }
                self.evm.token_delete = None;
                if matches!(self.screen, Screen::Confirm(Confirm::BookDelete)) {
                    self.book.delete = None;
                }
                let previous = self.previous_screen.clone();
                self.set_screen(previous);
            }
            CorePress::Network(_)
            | CorePress::Account(_)
            | CorePress::RpcRowOpen(_)
            | CorePress::RpcRow(..) => self.on_core_row(press),
        }
    }

    /// The row presses of the core screens (2026-11-18, S3 C12: the press with its row;
    /// before, `on_indexed_command` with the control id and its offset in each range).
    fn on_core_row(&mut self, press: CorePress) {
        match press {
            CorePress::Network(Row(index)) => {
                let chains = self.settings.registered_evm();
                // A choice closes the S10 network drop-down (2026-11-11).
                self.evm.network_picker = false;
                if let Some(chain_id) = chains.get(usize::from(index)).copied() {
                    let mut settings = self.settings.clone();
                    settings.evm_chain_id = chain_id;
                    self.save_settings(settings, "evmChainId");
                    // The new network's balances at the next tick, not up to 60 s later.
                    self.evm_balances_due();
                }
            }
            CorePress::Account(Row(offset)) => {
                // A choice closes the `내 계정` drop-down (2026-11-11).
                self.account_menu = None;
                self.select_account(usize::from(offset));
            }
            CorePress::RpcRowOpen(Row(offset)) => {
                // A failed network named on S08 or in the RPC summary: its row (spec/04
                // §2.11.1).
                if let Some(network) = self.url_networks().get(usize::from(offset)).copied() {
                    self.open_rpc_row(network, false);
                }
            }
            CorePress::RpcRow(Row(row), action) => {
                let networks = self.url_networks();
                let Some(network) = networks.get(usize::from(row)).copied() else {
                    return;
                };
                match action {
                    RpcRowAction::Replace => {
                        self.replace_target = Some(network);
                        self.refresh();
                    }
                    RpcRowAction::Test => self.test_network(network),
                    // The stored address cannot be shown again: asked first (2026-11-10).
                    RpcRowAction::Delete if self.apikeys.has(KeyName::Rpc(network)) => {
                        self.set_screen(Screen::Confirm(Confirm::RpcUrlDelete(network)));
                    }
                    RpcRowAction::Delete => {}
                }
            }
            // The fixed presses are `on_core`'s.
            _ => {}
        }
    }

    /// `RpcUrlDelete` confirmed: the row's address goes (E-APP-002 keeps it), with a completion
    /// band on that row.
    fn delete_rpc_url(&mut self, network: NetworkId) {
        if self.apikeys.remove(KeyName::Rpc(network)) && self.save_apikeys() {
            logging::info("app", "rpc.url_deleted", &[("net", Field::Net(network))]);
            self.network_url_changed(network);
            self.rpc_removed = Some(RpcRemoved::Url(network));
            self.rpc_tests.waiting.retain(|waiting| *waiting != network);
        }
        self.rpc_messages.retain(|(id, _, _)| *id != network);
    }

    /// Networks in the URL list (spec/04 §2.11.1 order).
    #[must_use]
    pub fn url_networks(&self) -> Vec<NetworkId> {
        let mut networks: Vec<NetworkId> = self
            .settings
            .registered_evm()
            .into_iter()
            .map(NetworkId::Eip155)
            .collect();
        networks.push(NetworkId::Solana(crate::network::SolCluster::Mainnet));
        networks.push(NetworkId::Solana(crate::network::SolCluster::Devnet));
        networks.push(NetworkId::Bitcoin(crate::network::BtcNet::Mainnet));
        networks.push(NetworkId::Bitcoin(crate::network::BtcNet::Testnet4));
        networks.push(NetworkId::Zcash(yw_core::zec::ZecNetwork::Mainnet));
        networks.push(NetworkId::Zcash(yw_core::zec::ZecNetwork::Testnet));
        networks
    }

    /// Display name of a network.
    #[must_use]
    pub fn network_name(&self, network: NetworkId) -> String {
        match network {
            NetworkId::Eip155(id) => self
                .settings
                .evm_chain_name_in(self.settings.language, id)
                .unwrap_or_else(|| format!("chainId {id}")),
            NetworkId::Solana(cluster) => crate::wallet::app_sol::core_cluster(cluster)
                .display_name_in(self.settings.language)
                .to_owned(),
            NetworkId::Bitcoin(net) => crate::btc::core_network(net)
                .display_name_in(self.settings.language)
                .to_owned(),
            NetworkId::Zcash(net) => net.display_name().to_owned(),
        }
    }

    /// Visible EVM accounts in display order: derived (not hidden) then raw keys.
    #[must_use]
    pub fn account_rows(&self) -> Vec<(EvmAccountPref, String, String, String)> {
        let Some(meta) = self.meta.as_ref() else {
            return Vec::new();
        };
        let checksum = |text: &str| {
            yw_core::evm::address::parse_address(text)
                .map_or_else(|_| text.to_owned(), |address| eip55(&address))
        };
        // With several mnemonics every derived row names its source (`니모닉 1 · m/…`).
        let primary = self
            .several_mnemonics()
            .then(|| self.primary_mnemonic_label())
            .flatten();
        let mut rows: Vec<_> = meta
            .evm_accounts
            .iter()
            .filter(|account| !account.hidden)
            .map(|account| {
                (
                    EvmAccountPref::Index(account.index),
                    account.label.clone(),
                    checksum(&account.address),
                    match &primary {
                        Some(name) => format!("{name} · m/44'/60'/0'/0/{}", account.index),
                        None => format!("m/44'/60'/0'/0/{}", account.index),
                    },
                )
            })
            .collect();
        // The added mnemonics' accounts (spec/04 §2.24), after the primary one's.
        rows.extend(
            self.mnemonic_account_rows()
                .into_iter()
                .map(|(pref, label, address, path)| (pref, label, checksum(&address), path)),
        );
        rows.extend(meta.evm_raw_accounts.iter().map(|raw| {
            (
                EvmAccountPref::Record(raw.record_id),
                raw.label.clone(),
                checksum(&raw.address),
                text::IMPORTED_PRIVATE_KEY
                    .get(self.settings.language)
                    .to_owned(),
            )
        }));
        // YubiKey accounts (spec/10 §13): the address of the slot map's public key.
        rows.extend(
            meta.hw_accounts
                .evm
                .iter()
                .filter(|account| !account.hidden)
                .map(|account| {
                    (
                        EvmAccountPref::Hardware(account.index),
                        account.label.clone(),
                        checksum(&account.address),
                        if yw_core::yubikey::plan::is_unknown_index(account.index) {
                            format!(
                                "{} (YubiKey)",
                                yw_core::yubikey::text::UNKNOWN_PATH.get(self.settings.language)
                            )
                        } else {
                            format!("m/44'/60'/0'/0/{} (YubiKey)", account.index)
                        },
                    )
                }),
        );
        rows
    }

    fn select_account(&mut self, row: usize) {
        let rows = self.account_rows();
        if let (Some((pref, ..)), Some(meta)) = (rows.get(row), self.meta.as_mut()) {
            meta.prefs.evm_account = *pref;
            self.rename = None;
            self.save_meta();
            // Its token balances (and a new account's native one) at the next tick.
            self.evm_balances_due();
        }
        self.refresh();
    }

    fn save_rename(&mut self) {
        let lang = self.settings.language;
        // 2026-11-18 (S3 C12): the form state (`Wallet::form_text`; before, a read of the edit,
        // cap 64 = `EditField::CoreRename.cap()`).
        let label = self.form_text(EditField::CoreRename).unwrap_or_default();
        if !is_valid_label(&label) {
            self.info = Some(ErrorCode::Inp017.text_in(lang));
            self.refresh();
            return;
        }
        if let (Some(target), Some(meta)) = (self.rename, self.meta.as_mut()) {
            match target {
                EvmAccountPref::Index(index) => {
                    if let Some(account) = meta
                        .evm_accounts
                        .iter_mut()
                        .find(|account| account.index == index)
                    {
                        account.label = label;
                    }
                }
                EvmAccountPref::Record(id) => {
                    if let Some(raw) = meta
                        .evm_raw_accounts
                        .iter_mut()
                        .find(|raw| raw.record_id == id)
                    {
                        raw.label = label;
                    }
                }
                EvmAccountPref::Hardware(index) => {
                    if let Some(account) = meta
                        .hw_accounts
                        .evm
                        .iter_mut()
                        .find(|account| account.index == index)
                    {
                        account.label = label;
                    }
                }
                EvmAccountPref::Mnemonic(id, index) => {
                    if let Some(account) = meta
                        .mnemonics
                        .iter_mut()
                        .find(|entry| entry.record_id == id)
                        .and_then(|entry| {
                            entry.evm.iter_mut().find(|account| account.index == index)
                        })
                    {
                        account.label = label;
                    }
                }
            }
        }
        self.rename = None;
        self.info = None;
        self.save_meta();
        self.refresh();
    }

    fn hide_selected(&mut self) {
        if let Some(meta) = self.meta.as_mut()
            && let EvmAccountPref::Hardware(index) = meta.prefs.evm_account
            && let Some(account) = meta
                .hw_accounts
                .evm
                .iter_mut()
                .find(|account| account.index == index)
        {
            // A hidden YubiKey account comes back with `다시 보이기` or when a card with its key
            // is enrolled again.
            account.hidden = true;
            let label = account.label.clone();
            let hidden = yw_core::evm::address::parse_address(&account.address).ok();
            meta.prefs.evm_account = EvmAccountPref::Index(0);
            self.save_meta();
            if let Some(address) = hidden {
                self.account_removed_from_sites(&address);
            }
            // 2026-11-20 (S4 P10a): the note and the repaint follow the answer of an open the
            // revoke asked for (`AfterOpen::HiddenNote`; before, made here directly).
            self.after_pending_open(crate::wallet::app_approval::AfterOpen::HiddenNote(label));
            return;
        }
        if let Some(EvmAccountPref::Mnemonic(id, index)) =
            self.meta.as_ref().map(|meta| meta.prefs.evm_account)
            && index != 0
            && let Some(account) = self.mnemonic_account_mut(id, index)
        {
            account.hidden = true;
            let label = account.label.clone();
            let hidden = yw_core::evm::address::parse_address(&account.address).ok();
            if let Some(meta) = self.meta.as_mut() {
                meta.prefs.evm_account = EvmAccountPref::Mnemonic(id, 0);
            }
            self.save_meta();
            if let Some(address) = hidden {
                self.account_removed_from_sites(&address);
            }
            // 2026-11-20 (S4 P10a): the note and the repaint follow the answer of an open the
            // revoke asked for (`AfterOpen::HiddenNote`; before, made here directly).
            self.after_pending_open(crate::wallet::app_approval::AfterOpen::HiddenNote(label));
            return;
        }
        if let Some(meta) = self.meta.as_mut()
            && let EvmAccountPref::Index(index) = meta.prefs.evm_account
            && index != 0
            && let Some(account) = meta
                .evm_accounts
                .iter_mut()
                .find(|account| account.index == index)
        {
            account.hidden = true;
            let label = account.label.clone();
            let hidden = yw_core::evm::address::parse_address(&account.address).ok();
            meta.prefs.evm_account = EvmAccountPref::Index(0);
            self.save_meta();
            if let Some(address) = hidden {
                self.account_removed_from_sites(&address);
            }
            // 2026-11-20 (S4 P10a): as above (`AfterOpen::HiddenNote`: the note, then the
            // repaint; before, the note here and the repaint below).
            self.after_pending_open(crate::wallet::app_approval::AfterOpen::HiddenNote(label));
            return;
        }
        self.refresh();
    }

    fn save_autolock(&mut self) {
        // 2026-11-18 (S3 C12): the form state (`Wallet::form_text`; before, a read of the edit,
        // cap 8 = `EditField::CoreAutoLock.cap()`).
        let text = self.form_text(EditField::CoreAutoLock).unwrap_or_default();
        match text.trim().parse::<u8>() {
            Ok(minutes) if (1..=60).contains(&minutes) => {
                let mut settings = self.settings.clone();
                settings.auto_lock_minutes = minutes;
                self.info = Some(
                    text::AUTO_LOCK_SAVED.fill(self.settings.language, [&minutes.to_string()]),
                );
                self.save_settings(settings, "autoLockMinutes");
            }
            _ => {
                self.info = Some(text::AUTO_LOCK_RANGE.get(self.settings.language).to_owned());
                self.refresh();
            }
        }
    }

    /// The text of plain edit `field` for a handler (S3 B5, plan §3.2a): the form state, which
    /// equals `controls.text(id, field.cap())`. The C commits move the handlers' edit reads here.
    /// 2026-11-21 (S4 W3, critique B-11): the form state only; the shell compares the whole form
    /// state with the edits after every drain (`App::check_form_in_step`, debug builds). Before,
    /// debug builds read the edit here too and counted a difference.
    ///
    /// The returned text is a plain `String` (2026-11-18, S3 C1–C3 review): the `WalletConnect`
    /// pairing link (`WcUri`, it carries the symKey) is `Zeroizing` in `FormState` and
    /// `Cmd::Edit` only, not along the `PAIR` handler path (as before S3, when it was the plain
    /// `controls.text`; the copy count is unchanged, and `on_wc_edit` still keeps the plain
    /// `wc.uri_text`). 2026-11-20 (S4 P5, critique B-12(c)): `PAIR` reads it with
    /// [`Wallet::form_text_wiping`] instead, so it keeps no plain copy beyond `wc.uri_text`; before,
    /// this note said "S4: return `Zeroizing<String>` here, or add a `WcUri` reader".
    #[must_use]
    pub(crate) fn form_text(&self, field: EditField) -> Option<String> {
        self.form.text(field).map(str::to_owned)
    }

    /// [`Wallet::form_text`] as a wiped string (2026-11-20, S4 P5, critique B-12(c)): for the
    /// `WalletConnect` pairing link (`EditField::WcUri`, it holds the pairing `symKey`). The same
    /// form-state read (2026-11-21, S4 W3, critique B-11: only that; before, debug builds compared
    /// it with a wiped read of the edit here).
    #[must_use]
    pub(crate) fn form_text_wiping(&self, field: EditField) -> Option<Zeroizing<String>> {
        self.form
            .text(field)
            .map(|text| Zeroizing::new(text.to_owned()))
    }
}

impl Wallet {
    /// The units of credential edit `field` the shell read with the press being handled
    /// (2026-11-18, S3 C3, plan §3.4 and D-l): moved out of the press input, wiped when dropped;
    /// empty when the edit did not exist, exactly as a read of a missing edit. A field the press
    /// did not capture is a credential miss (`PressInput::take`, debug builds). 2026-11-21 (S4 W3,
    /// critique B-11): debug builds note the field for the shell's comparison when the next drain
    /// starts (`App::cred_check`); before, they read the edit itself here and compared (the shadow
    /// read of S3 plan §3.2a). 2026-11-21 (W3 review): the note carries the length and SHA-256 of
    /// the units taken ([`cred_fingerprint`]), so a take that hands over another field's units is
    /// counted; from W3 until the review it held the field name only.
    pub(crate) fn take_cred(&mut self, field: CredField) -> Zeroizing<Vec<u16>> {
        let units = self.input.take(field);
        #[cfg(debug_assertions)]
        {
            let (len, digest) = cred_fingerprint(units.as_slice());
            self.cred_taken.push((field, len, digest));
        }
        units
    }
}

impl Wallet {
    /// The text of credential edit `field` (2026-11-18, S3 C12, plan §3.4: the units the shell
    /// read with the press, `Wallet::take_cred`; before, `read_wiping(id, max)` read the edit here
    /// into a wiping buffer). Decoded as before: one `char` per UTF-16 unit, a unit that is no
    /// `char` (a surrogate half) dropped; empty when the edit did not exist.
    fn read_cred(&mut self, field: CredField) -> Zeroizing<String> {
        let units = self.take_cred(field);
        let mut out = Zeroizing::new(String::new());
        for unit in units.as_slice() {
            if let Some(character) = char::from_u32(u32::from(*unit)) {
                out.push(character);
            }
        }
        out
    }

    /// `자격 정보만 저장` (and the first step of `저장하고 RPC 주소 만들기`) of the template
    /// credentials (spec/04 §2.11): `Ok(true)` saved, `Ok(false)` the fields were empty (nothing
    /// to save); E-KEY-002 with the item name (its text is in the information band) or E-APP-002.
    fn save_template_credentials(&mut self) -> Result<bool, ErrorCode> {
        match self.settings.rpc_template {
            RpcTemplate::QuickNode => {
                let name = self.read_cred(CredField::QnName);
                let token = self.read_cred(CredField::QnToken);
                match quicknode_input(self.settings.language, &name, &token) {
                    Ok(None) => return Ok(false),
                    Ok(Some((name, token))) => self.apikeys.set_quicknode(&name, &token),
                    Err(text) => {
                        self.info = Some(text);
                        return Err(ErrorCode::Key002);
                    }
                }
            }
            RpcTemplate::Alchemy => {
                let key = self.read_cred(CredField::AlchemyKey);
                if key.is_empty() {
                    return Ok(false);
                }
                if !valid_provider_token(key.trim()) {
                    let lang = self.settings.language;
                    self.info = Some(key002_text(lang, text::ALCHEMY_KEY.get(lang)));
                    return Err(ErrorCode::Key002);
                }
                self.apikeys.set_alchemy(key.trim());
            }
            RpcTemplate::Manual => return Ok(false),
        }
        // 2026-11-18 (S3 C12): `Effect::ClearCred` (before, `controls.clear_text`), at once.
        for field in [CredField::QnName, CredField::QnToken, CredField::AlchemyKey] {
            self.emit(Effect::ClearCred { field });
        }
        if !self.save_apikeys() {
            return Err(ErrorCode::App002);
        }
        logging::info(
            "app",
            "tpl.saved",
            &[("template", Field::Word(self.settings.rpc_template.as_str()))],
        );
        if self.rpc_removed == Some(RpcRemoved::Template) {
            self.rpc_removed = None;
        }
        Ok(true)
    }

    /// `보관 항목 삭제` confirmed: drops the dormant entries and saves (a failed save reloads
    /// the file, so they stay; E-APP-002).
    fn prune_dormant(&mut self) {
        let removed = self.apikeys.prune_dormant();
        if removed > 0 && self.save_apikeys() {
            logging::info(
                "app",
                "apikeys.pruned",
                &[("count", Field::Num(u64::try_from(removed).unwrap_or(0)))],
            );
            self.info = Some(text::PRUNED.fill(self.settings.language, [&removed.to_string()]));
        }
    }

    /// The stored credential of the selected template (`None` for `직접 입력`).
    const fn template_key(&self) -> Option<KeyName> {
        match self.settings.rpc_template {
            RpcTemplate::QuickNode => Some(KeyName::TplQuickNode),
            RpcTemplate::Alchemy => Some(KeyName::TplAlchemy),
            RpcTemplate::Manual => None,
        }
    }

    /// Whether the selected template's credentials are stored.
    #[must_use]
    pub(crate) fn template_stored(&self) -> bool {
        self.template_key()
            .is_some_and(|name| self.apikeys.has(name))
    }

    /// Whether some network the selected template can make an address for has one already.
    #[must_use]
    pub fn template_addresses(&self) -> bool {
        self.generation_plan()
            .0
            .into_iter()
            .any(|network| self.apikeys.has(KeyName::Rpc(network)))
    }

    /// `TemplateDelete` confirmed: the credentials go, the addresses made with them stay.
    fn delete_template_credentials(&mut self) {
        let Some(name) = self.template_key() else {
            return;
        };
        if self.apikeys.remove(name) && self.save_apikeys() {
            logging::info(
                "app",
                "tpl.deleted",
                &[("template", Field::Word(self.settings.rpc_template.as_str()))],
            );
            self.rpc_removed = Some(RpcRemoved::Template);
        }
    }

    /// Generation targets and skipped networks for the current template.
    #[must_use]
    pub fn generation_plan(&self) -> (Vec<NetworkId>, Vec<NetworkId>) {
        let template = self.settings.rpc_template;
        self.url_networks()
            .into_iter()
            .partition(|network| template_entry(template, *network, &self.settings).is_some())
    }

    /// `저장하고 RPC 주소 만들기` (spec/04 §2.11.1): the typed credentials are saved first; the
    /// overwrite question (T-RPC-GENERATE) comes only when a target has an address already
    /// (2026-11-10), otherwise the addresses are made at once.
    fn begin_generate(&mut self) {
        if self.settings.rpc_template == RpcTemplate::Manual {
            return;
        }
        if self.save_template_credentials().is_err() {
            self.refresh();
            return;
        }
        if self
            .apikeys
            .credential(self.settings.rpc_template)
            .is_none()
        {
            // Nothing typed and nothing stored: what to type, not E-KEY-004.
            self.info = Some(
                if self.settings.rpc_template == RpcTemplate::Alchemy {
                    text::ENTER_ALCHEMY
                } else {
                    text::ENTER_QUICKNODE
                }
                .get(self.settings.language)
                .to_owned(),
            );
            self.refresh();
            return;
        }
        self.overwrite_checked = false;
        if self.template_addresses() {
            self.set_screen(Screen::Confirm(Confirm::Generate));
        } else {
            self.generate_and_report();
            self.refresh();
        }
    }

    /// [`Wallet::generate`] from settings → 네트워크(RPC), with T-RPC-GENERATED: the new addresses
    /// are being tested and their results are on the rows.
    fn generate_and_report(&mut self) {
        let Some(written) = self.generate() else {
            return;
        };
        let lang = self.settings.language;
        let skipped = self.generation_plan().1;
        let mut info = if written.is_empty() {
            text::GENERATED_NONE.get(lang).to_owned()
        } else {
            text::GENERATED.fill(lang, [&written.len().to_string()])
        };
        if !skipped.is_empty() {
            let names: Vec<String> = skipped
                .iter()
                .map(|network| self.network_name(*network))
                .collect();
            info.push_str(
                &text::GENERATED_SKIPPED
                    .fill(lang, [&skipped.len().to_string(), &names.join(", ")]),
            );
        }
        self.info = Some(info);
    }

    /// Writes the template addresses of the generation targets (a target with an address only
    /// when `overwrite_checked`) and queues their tests: the written networks, or `None` when
    /// nothing was saved (no credential: E-KEY-004; E-APP-002).
    fn generate(&mut self) -> Option<Vec<NetworkId>> {
        let lang = self.settings.language;
        let template = self.settings.rpc_template;
        let Some(credential) = self.apikeys.credential(template) else {
            self.info = Some(ErrorCode::Key004.text_in(lang));
            return None;
        };
        let (targets, _) = self.generation_plan();
        let written = self.apikeys.generate_urls(
            template,
            &credential,
            &self.settings,
            &targets,
            self.overwrite_checked,
        );
        drop(credential);
        if !self.save_apikeys() {
            return None;
        }
        for network in &written {
            logging::info("app", "rpc.generated", &[("net", Field::Net(*network))]);
            self.rpc_messages.retain(|(id, _, _)| id != network);
            self.network_url_changed(*network);
        }
        self.rpc_removed = None;
        // Every new address is tested, one at a time (2026-11-10).
        self.queue_rpc_tests(&written);
        Some(written)
    }

    /// Gives every network of the URL list that has no address the selected template's address,
    /// when that template's credential is stored (2026-11-11): at start (a chain added by an
    /// update) and after an `rpc.json` import (a file with one `QuickNode` URL fills them all).
    /// A stored address is never replaced. Returns the networks written; nothing on a failed
    /// save (E-APP-002).
    pub fn fill_template_gaps(&mut self) -> Vec<NetworkId> {
        let template = self.settings.rpc_template;
        let Some(credential) = self.apikeys.credential(template) else {
            return Vec::new();
        };
        let (targets, _) = self.generation_plan();
        let written =
            self.apikeys
                .generate_urls(template, &credential, &self.settings, &targets, false);
        drop(credential);
        if written.is_empty() || !self.save_apikeys() {
            return Vec::new();
        }
        for network in &written {
            logging::info("app", "rpc.generated", &[("net", Field::Net(*network))]);
            self.rpc_messages.retain(|(id, _, _)| id != network);
            self.network_url_changed(*network);
        }
        written
    }

    fn save_replacement(&mut self) {
        let lang = self.settings.language;
        let Some(network) = self.replace_target else {
            return;
        };
        let text = self.read_cred(CredField::RpcReplace);
        match HttpsUrl::parse(text.trim()) {
            Ok(url) => {
                self.apikeys.set_rpc(network, &url);
                if self.save_apikeys() {
                    logging::info("app", "rpc.url_set", &[("net", Field::Net(network))]);
                    self.rpc_messages.retain(|(id, _, _)| *id != network);
                    self.network_url_changed(network);
                    if self.rpc_removed == Some(RpcRemoved::Url(network)) {
                        self.rpc_removed = None;
                    }
                    // The saved address is tested right away (2026-11-10).
                    self.queue_rpc_tests(&[network]);
                }
                // 2026-11-18 (S3 C12): `Effect::ClearCred` (before, `controls.clear_text`).
                self.emit(Effect::ClearCred {
                    field: CredField::RpcReplace,
                });
                self.replace_target = None;
            }
            Err(_) => {
                self.set_rpc_message(network, ErrorCode::Key003.text_in(lang), TestState::Failed);
            }
        }
        self.refresh();
    }

    pub(crate) fn set_rpc_message(
        &mut self,
        network: NetworkId,
        message: String,
        state: TestState,
    ) {
        self.rpc_messages.retain(|(id, _, _)| *id != network);
        self.rpc_messages.push((network, message, state));
    }

    /// Queues `테스트` of each network that has a stored address (not twice; in order) and starts
    /// the first when none runs. A queued row reads "테스트 중…" until its answer.
    pub(crate) fn queue_rpc_tests(&mut self, networks: &[NetworkId]) {
        for network in networks {
            let queued = self.rpc_tests.running == Some(*network)
                || self.rpc_tests.waiting.contains(network);
            if queued || self.apikeys.rpc_url(*network).is_none() {
                continue;
            }
            self.rpc_tests.waiting.push_back(*network);
            self.rpc_tests.total = self.rpc_tests.total.saturating_add(1);
            self.set_rpc_message(
                *network,
                text::TESTING.get(self.settings.language).to_owned(),
                TestState::Testing,
            );
        }
        self.next_rpc_test();
    }

    /// Sends the next queued test when none is running (the stored address of that moment).
    fn next_rpc_test(&mut self) {
        while self.rpc_tests.running.is_none() {
            let Some(network) = self.rpc_tests.waiting.pop_front() else {
                // The queue ran out: the next batch counts from zero.
                self.rpc_tests.done = 0;
                self.rpc_tests.total = 0;
                return;
            };
            let Some(url) = self.apikeys.rpc_url(network) else {
                // Deleted meanwhile.
                self.rpc_messages.retain(|(id, _, _)| *id != network);
                self.rpc_tests.total = self.rpc_tests.total.saturating_sub(1);
                continue;
            };
            let name = self.network_name(network);
            if self.rpc(RpcJob::Test {
                network,
                name,
                url,
                lang: self.settings.language,
            }) {
                self.rpc_tests.running = Some(network);
            } else {
                // No RPC worker: nothing will answer, so no row keeps "테스트 중…".
                let waiting = core::mem::take(&mut self.rpc_tests.waiting);
                self.rpc_messages
                    .retain(|(id, _, _)| *id != network && !waiting.contains(id));
                self.rpc_tests.done = 0;
                self.rpc_tests.total = 0;
                return;
            }
        }
    }

    /// `모두 테스트`: every network with an address, one at a time.
    fn test_all_networks(&mut self) {
        let networks: Vec<NetworkId> = self
            .url_networks()
            .into_iter()
            .filter(|network| self.apikeys.has(KeyName::Rpc(*network)))
            .collect();
        self.queue_rpc_tests(&networks);
        self.refresh();
    }

    /// A row's `테스트`: the typed address (the open `교체` field) is sent at once; the stored one
    /// goes first in the queue.
    fn test_network(&mut self, network: NetworkId) {
        let lang = self.settings.language;
        let typed = if self.replace_target == Some(network) {
            self.read_cred(CredField::RpcReplace)
        } else {
            Zeroizing::new(String::new())
        };
        let parsed = crate::rpc::endpoint_for_test(&typed, self.apikeys.rpc_url(network));
        let url = match parsed {
            Ok(url) => url,
            Err(code) => {
                logging::info(
                    "rpc",
                    "rpc.test",
                    &[("net", Field::Net(network)), ("result", Field::Code(code))],
                );
                self.set_rpc_message(network, code.text_in(lang), TestState::Failed);
                self.refresh();
                return;
            }
        };
        if self.rpc_removed == Some(RpcRemoved::Url(network)) {
            self.rpc_removed = None;
        }
        if typed.trim().is_empty() {
            if self.rpc_tests.running != Some(network) {
                let before = self.rpc_tests.waiting.len();
                self.rpc_tests.waiting.retain(|waiting| *waiting != network);
                if before == self.rpc_tests.waiting.len() {
                    self.rpc_tests.total = self.rpc_tests.total.saturating_add(1);
                }
                self.rpc_tests.waiting.push_front(network);
                self.set_rpc_message(
                    network,
                    text::TESTING.get(self.settings.language).to_owned(),
                    TestState::Testing,
                );
                self.next_rpc_test();
            }
            self.refresh();
            return;
        }
        let name = self.network_name(network);
        if self.rpc(RpcJob::Test {
            network,
            name,
            url,
            lang: self.settings.language,
        }) {
            self.set_rpc_message(
                network,
                text::TESTING.get(self.settings.language).to_owned(),
                TestState::Testing,
            );
        }
        self.refresh();
    }

    /// Settings → 네트워크(RPC) with `network`'s row in view (spec/04 §2.11.1, 2026-11-10): `edit`
    /// opens its address field (`ES_PASSWORD`) with the focus — a chain tab's `RPC 설정하기` —,
    /// otherwise the focus goes to its `테스트` (a failed network named on S08 or in the
    /// summary).
    /// 2026-11-20 (S4 P4): the scroll and focus are `Effect::Reveal` of the row's `테스트` press
    /// or of the masked address field (before, `reveal_id` with the control id).
    pub(crate) fn open_rpc_row(&mut self, network: NetworkId, edit: bool) {
        let row = self
            .url_networks()
            .iter()
            .position(|known| *known == network);
        if edit && row.is_some() {
            self.replace_target = Some(network);
        }
        self.set_screen(Screen::Settings(SettingsSection::Network));
        let Some(row) = row.and_then(|row| u16::try_from(row).ok()) else {
            return;
        };
        let target = if edit {
            RevealTarget::Cred(CredField::RpcReplace)
        } else {
            RevealTarget::Press(Press::Core(CorePress::RpcRow(Row(row), RpcRowAction::Test)))
        };
        self.emit(Effect::Reveal(target));
    }

    /// Clears what S08 shows (its banners, `← 처음 설정으로`, the connect results).
    fn clear_done(&mut self) {
        self.done_imported = false;
        self.keys.done_start = false;
        self.done_yubikey = None;
        self.done_return = false;
        self.done_tested.clear();
        self.done_error = None;
    }

    /// S08 `연결하기` (spec/04 §2.3, 2026-11-10): the whole `QuickNode` address from its field —
    /// read into a wiping buffer, the field emptied at once. 2026-11-18 (S3 C12): the units the
    /// shell read with the press (`read_cred`) and `Effect::ClearCred` (before, `read_wiping`
    /// and `controls.clear_text`).
    fn done_connect(&mut self) {
        let text = self.read_cred(CredField::DoneQn);
        self.emit(Effect::ClearCred {
            field: CredField::DoneQn,
        });
        self.done_connect_with(&text);
    }

    /// The steps of S08 `연결하기` with only existing paths: the address is split into the
    /// endpoint name and token ([`quicknode_input`]), saved as the template credential, the
    /// template addresses are made without overwriting (S08 shows only while there is none, so
    /// no T-RPC-GENERATE), and each one is tested in turn; S08 lists their results.
    fn done_connect_with(&mut self, text: &str) {
        if self.settings.rpc_template != RpcTemplate::QuickNode {
            return;
        }
        match quicknode_input(self.settings.language, text, "") {
            Ok(None) => {
                self.done_error = Some(text::PASTE_ADDRESS.get(self.settings.language).to_owned());
                self.refresh();
                return;
            }
            Err(message) => {
                self.done_error = Some(message);
                self.refresh();
                return;
            }
            Ok(Some((name, token))) => {
                self.apikeys.set_quicknode(&name, &token);
                drop(token);
                if !self.save_apikeys() {
                    self.refresh();
                    return;
                }
                logging::info(
                    "app",
                    "tpl.saved",
                    &[("template", Field::Word(RpcTemplate::QuickNode.as_str()))],
                );
            }
        }
        self.done_error = None;
        self.overwrite_checked = false;
        if let Some(written) = self.generate() {
            self.done_tested = written;
        }
        self.refresh();
    }

    /// Back to the screen under the overlay without `set_screen` (its leaving hooks stay out of
    /// it), where it was. 2026-11-20 (S4 P4): "where it was" is the shell's scroll memory,
    /// through `Effect::OverlayClosedInPlace` (before, this fn set the offset).
    fn close_overlay_in_place(&mut self, previous: Screen) {
        self.screen = previous;
        self.emit(Effect::OverlayClosedInPlace);
    }

    #[expect(clippy::too_many_lines, reason = "one arm per confirmation overlay")]
    fn confirm_yes(&mut self) {
        let Screen::Confirm(kind) = self.screen.clone() else {
            return;
        };
        let previous = self.previous_screen.clone();
        match kind {
            Confirm::CopyOn => {
                let mut settings = self.settings.clone();
                settings.allow_secret_copy = true;
                self.close_overlay_in_place(previous);
                self.save_settings(settings, "allowSecretCopy");
            }
            Confirm::LocalhostOn => {
                let mut settings = self.settings.clone();
                settings.allow_localhost_dapps = true;
                self.close_overlay_in_place(previous);
                self.save_settings(settings, "allowLocalhostDapps");
            }
            Confirm::DisconnectAll => {
                self.disconnect_all_sites();
                self.set_screen(Screen::Sites);
            }
            Confirm::WcDisconnectAll => {
                self.wc_disconnect_all();
                self.set_screen(Screen::Sites);
            }
            Confirm::SettingsFile => {
                self.set_screen(previous);
                self.settings_accept_file();
            }
            Confirm::RevealMnemonic => {
                self.set_screen(previous);
                self.open_input(
                    SecretKind::ConfirmPassword,
                    Purpose::ConfirmPassword(PasswordAction::RevealMnemonic { then_backup: false }),
                    false,
                );
            }
            Confirm::RevealKey => {
                self.set_screen(previous);
                let source = match self.selected_pref() {
                    Some(EvmAccountPref::Hardware(_)) => {
                        // The key of a YubiKey account never leaves the card (spec/10 §1).
                        self.info = Some(text::YK_KEY_STAYS.get(self.settings.language).to_owned());
                        self.refresh();
                        return;
                    }
                    Some(EvmAccountPref::Record(id)) => EvmKeySource::Raw(RecordId::from_bytes(id)),
                    Some(EvmAccountPref::Mnemonic(id, index)) => {
                        match yw_core::bip32::path::AccountIndex::new(index) {
                            Ok(index) => EvmKeySource::Mnemonic(RecordId::from_bytes(id), index),
                            Err(_) => return,
                        }
                    }

                    Some(EvmAccountPref::Index(index)) => {
                        yw_core::bip32::path::AccountIndex::new(index).map_or(
                            EvmKeySource::Derived(yw_core::bip32::path::AccountIndex::ZERO),
                            EvmKeySource::Derived,
                        )
                    }
                    None => EvmKeySource::Derived(yw_core::bip32::path::AccountIndex::ZERO),
                };
                self.open_input(
                    SecretKind::ConfirmPassword,
                    Purpose::ConfirmPassword(PasswordAction::RevealKey(source)),
                    false,
                );
            }
            Confirm::Generate => {
                self.generate_and_report();
                self.set_screen(previous);
            }
            Confirm::RpcUrlDelete(network) => {
                self.delete_rpc_url(network);
                self.set_screen(previous);
            }
            Confirm::TemplateDelete => {
                self.delete_template_credentials();
                self.set_screen(previous);
            }
            Confirm::LlmKeyDelete => {
                self.set_screen(previous);
                self.llm_delete_key();
            }
            Confirm::YkAbandon => {
                // `그만두기`: the wizard ends as before (the key worker wipes the words).
                self.close_overlay_in_place(previous);
                self.yk_close_wizard();
            }
            Confirm::YkPinLater => {
                // `나중에`: the result screen ends as `완료` would have.
                self.close_overlay_in_place(previous);
                self.yk_pin_later();
            }
            Confirm::PruneDormant => {
                self.prune_dormant();
                self.set_screen(previous);
            }
            // The meta overlay has its own buttons (`app_sidecar`).
            Confirm::SidecarCorrupt => {}
            Confirm::JournalCorrupt => self.choose_sidecar(FileKind::Journal, false),
            Confirm::ChainPin => {
                let pending = self
                    .evm
                    .chain_form
                    .as_mut()
                    .and_then(|form| form.pending.take());
                if let Some((valid, genesis)) = pending {
                    self.commit_chain(&valid, genesis);
                } else {
                    self.set_screen(previous);
                }
            }
            Confirm::ChainRepin => {
                self.commit_repin();
                self.set_screen(Screen::Settings(SettingsSection::Chains));
            }
            Confirm::ChainDelete => {
                if let Some(chain_id) = self.evm.delete_chain.take() {
                    self.delete_chain(chain_id);
                }
                // 2026-11-20 (S4 P10a): after the answer of an open the chain's removal from the
                // sites asked for (`AfterOpen::SetScreen`; before, set here directly).
                self.after_pending_open(crate::wallet::app_approval::AfterOpen::SetScreen(
                    Screen::Settings(SettingsSection::Chains),
                ));
            }
            Confirm::Discard => {
                if let Some(key) = self.evm.discard.take() {
                    self.discard_group(key);
                }
                self.set_screen(Screen::Main);
            }
            Confirm::BookDelete => {
                self.delete_book_entry();
                self.set_screen(Screen::AddressBook);
            }
            Confirm::TokenDelete => {
                self.delete_token();
                self.set_screen(Screen::Main);
            }
            Confirm::Btc => self.btc_confirm_yes(),
            Confirm::LlmOn => self.llm_confirm_on(),
            Confirm::RemoveKey => {
                self.set_screen(previous);
                if let Some(id) = self.pending_remove.take() {
                    self.open_input(
                        SecretKind::ConfirmPassword,
                        Purpose::ConfirmPassword(PasswordAction::RemoveKey(id)),
                        false,
                    );
                }
            }
            Confirm::RevealImported | Confirm::RemoveImported => self.imported_confirmed(kind),
            Confirm::RemoveYubiKey => self.yk_remove_confirmed(),
        }
    }

    /// The challenge id currently expected (tests and diagnostics).
    #[must_use]
    pub fn challenge_id(&self) -> Option<ChallengeId> {
        self.challenge.map(|challenge| challenge.id)
    }
}

// 2026-11-23 (spec/15 §11.4 S4d E0b): the outbox's wallet half (`emit`, `next_effect`) moved here
// unchanged from `app_effects` (the shell's drain and executor stay there).

impl Wallet {
    /// Queues `effect` for `App::drain` (2026-11-20, S4 P10b; see the module doc). A field
    /// write (`SetField`) puts its text, cut to the field's cap as the edit holds it, into the
    /// form state now, so the logic reads what it wrote before the shell applies it (owner
    /// decision O-10; the shell reads the edit back when it applies the write, as before).
    /// Before P10 this fn applied the effect at once. 2026-11-21 (S4 W3, plan §3.4): the
    /// wallet's (was `App::emit`, the same body); `impl App` code reaches it through `App`.
    pub fn emit(&mut self, effect: Effect) {
        if let Effect::SetField { field, text } = &effect {
            let field = *field;
            self.form.set(field, Some(field.clamp(text)));
        }
        self.outbox.push_back(effect);
    }

    /// The oldest queued effect, taken out of the queue (2026-11-21, S4 W3, plan §3.4: the
    /// drain's one read of the outbox; Android's `next()`, spec/15 §3.2). `None` when the queue is
    /// empty.
    #[must_use]
    pub fn next_effect(&mut self) -> Option<Effect> {
        self.outbox.pop_front()
    }
}

// 2026-11-24 (spec/15 §11.2, §11.3, §11.4 S5-5): the screen's one entry. Before, yw-app's
// `App::screen_model` (render code, `ui/screens.rs`) built it on `App`.

impl Wallet {
    /// The current screen as the neutral model (spec/15 §11.3), built by the screen builders
    /// (`crate::screen::build`) from this wallet and the shell's `facts`, which they ask at the
    /// points they draw them. Read-only: a builder writes no wallet state but the two drawn-row
    /// maps of S13 and the `WalletConnect` panel (source check
    /// `the_screen_writes_no_wallet_state`). A shell lowers the list into its own controls
    /// (Windows: yw-app `App::items`, `ui::lower`).
    #[must_use]
    pub fn screen(
        &self,
        facts: &dyn crate::screen::facts::ScreenFacts,
    ) -> Vec<crate::screen::model::Item> {
        crate::screen::build::Screen::new(self, facts).screen_model()
    }
}

// 2026-11-23 (spec/15 §11.4 S4d E0b): moved here unchanged from `app_extension` (the answer of a
// shell press; the extension guide's other handlers stay in the shell, O-13).

impl Wallet {
    /// `Cmd::FolderMissing` (S4 P3): `탐색기에서 폴더 열기` found no extension folder — the
    /// `extension.folder_missing` log line, the band and the repaint, as the press did before.
    /// 2026-11-22 (S4c W15): wallet code (`Wallet::on_cmd` handles the answer); before, an
    /// `impl App` fn reached through `DerefMut`.
    pub(crate) fn on_folder_missing(&mut self) {
        logging::info("app", "extension.folder_missing", &[]);
        self.info = Some(
            crate::wallet::text::T_EXT_MISSING
                .get(self.settings.language)
                .to_owned(),
        );
        self.refresh();
    }
}
