//! The UI-thread application (spec/04 §1–§2, §4–§6): window handlers, flows, lock procedure,
//! settings and endpoint management. All windows share one `App` through `Rc<RefCell<…>>`; a
//! handler that cannot borrow it (re-entrant synchronous message) falls back to the default
//! processing, and the yw-win trampoline has already applied the secret-message block list.

use std::cell::RefCell;
use std::path::{Path, PathBuf};
use std::rc::{Rc, Weak};
use std::sync::Arc;
use std::sync::mpsc::Sender;
use std::thread::JoinHandle;
use std::time::Duration;

use yw_core::error::VaultError;
use yw_core::evm::address::Address;
use yw_core::secret::Zeroizing;
use yw_core::vault::{
    BackupChallenge, ChallengeId, EvmKeySource, FileKind, PasswordChange, RecordId, VaultStatus,
};
use yw_win::clipboard::{self, ClipError, SecretClip};
use yw_win::file::{FileError, atomic_write, read_limited_no_reparse};
use yw_win::http::HttpsUrl;
use yw_win::input::is_down;
use yw_win::session;
use yw_win::time::monotonic_ms;
use yw_win::ui::{Handler, Msg, Reply, UiError, Window, WindowKind, WindowSpec, create_window};

use crate::apikeys::{
    APIKEYS_ENTROPY, ApiKeys, KeyName, is_registered, quicknode_credentials, template_entry,
    valid_provider_token,
};
use crate::errors::{ErrorCode, key_code, vault_code};
use crate::events::{
    KeyJob, KeyOutcome, KeyQueue, KeyResult, LockSignal, MetaLoaded, RevealWhat, RpcEvent, UiEvent,
    WM_YW_ACTIVATE, WM_YW_EVENTS, WM_YW_LOCK_SHORTCUT, WM_YW_TAB_SHORTCUT, accept_result,
};
use crate::lock::{IdleTracker, LockReason, SystemAction, system_action};
use crate::logging::{self, Field};
use crate::meta::{EvmAccountPref, Meta, RawAccount};
use crate::network::NetworkId;
use crate::settings::{LogLevel, RpcTemplate, Settings};
use crate::text::is_valid_label;
use crate::ui::main_window::{ControlSet, Placed, layout, paint};
use crate::ui::secret::{
    CaptureDecision, DisplaySecret, FormAction, PASTE_MAX_UTF16_UNITS, SECRET_TIMER_ID,
    SECRET_TIMER_MS, SecretForm, SecretKind, SecretStep, Submission, capture_decision,
};
use crate::ui::theme::{FontCache, FontRole, wide};
use crate::workers::key::new_account;
use crate::workers::rpc::RpcJob;

/// Main window class.
pub const MAIN_CLASS: &str = "YourWalletV3Main";
/// Secret input class (W01–W07, W10): `CaptureExclusion::Preferred`.
pub const SECRET_INPUT_CLASS: &str = "YourWalletV3SecretInput";
/// Secret display class (W08, W09): `CaptureExclusion::Required`.
pub const SECRET_VIEW_CLASS: &str = "YourWalletV3SecretView";
/// Single-instance mutex: boundary descriptor name of the private namespace (bound to the user's
/// SID and Medium integrity, spec/04 §1.1).
pub const INSTANCE_BOUNDARY: &str = "YourWallet.v3";
/// Alias prefix of the private namespace.
pub const INSTANCE_ALIAS: &str = "YourWalletV3";
/// Mutex name inside the private namespace (`<alias>\app.<session id>`).
pub const INSTANCE_MUTEX: &str = "app";
/// Secret clipboard lifetime (D11).
pub const SECRET_CLIPBOARD_TTL_MS: u64 = 30_000;
const MAIN_TIMER_ID: usize = 1;
const LOG_FLUSH_MS: u64 = 2_000;
const SESSION_RETRY_MS: u64 = 1_000;
const SESSION_RETRY_MAX: u32 = 30;
const VK_CONTROL: u16 = 0x11;
const VK_SHIFT: u16 = 0x10;
const VK_MENU: u16 = 0x12;
const MA_ACTIVATEANDEAT: isize = 2;
const EN_CHANGE: u16 = 0x0300;
/// Settings field limits (UTF-16 units).
const TOKEN_MAX_UNITS: usize = 256;
const URL_MAX_UNITS: usize = 2_048;

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
    const fn holds_secrets(self) -> bool {
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

/// Settings sections (S15).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SettingsSection {
    /// 보안.
    Security,
    /// 네트워크 (RPC 공급자, 네트워크 URL).
    Network,
    /// 브라우저·진단·정보.
    Other,
    /// EVM 체인, 수수료 상한 (M4).
    Chains,
    /// Solana: 클러스터, 수수료 상한, 다른 경로 스캔 (M7).
    Solana,
    /// Bitcoin: 켜기·네트워크, 인덱서, Esplora URL (M8).
    Bitcoin,
    /// AI 설명 (M6, spec/06 §2).
    Ai,
    /// `YubiKey`: the enrolled cards, their slots and accounts, `YubiKey 등록`, `삭제` (spec/10).
    YubiKey,
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
    KeyStartAddress(crate::app_keys::KeyStartView),
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
    YubiKey(crate::app_yubikey::YkPurpose),
}

struct SecretWin {
    serial: u64,
    window: Window,
    form: SecretForm,
    purpose: Purpose,
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
    pub tone: crate::ui::main_window::Tone,
}

/// Paths of the data folder.
#[derive(Clone, Debug)]
pub struct Paths {
    /// `%LOCALAPPDATA%\YourWallet\v3`.
    pub data: PathBuf,
    /// `…\logs`.
    pub logs: PathBuf,
}

impl Paths {
    fn settings(&self) -> PathBuf {
        self.data.join("settings.json")
    }

    fn apikeys(&self) -> PathBuf {
        self.data.join("apikeys.dpapi")
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Target {
    Main,
    Secret(u64),
}

struct Forward {
    app: Weak<RefCell<App>>,
    target: Target,
}

impl Handler for Forward {
    fn on(&mut self, window: &Window, msg: &Msg) -> Reply {
        let Some(app) = self.app.upgrade() else {
            return Reply::Default;
        };
        let Ok(mut app) = app.try_borrow_mut() else {
            // A paint requested from inside another handler: owed, not dropped unpainted.
            if matches!(msg, Msg::Paint) {
                window.defer_paint();
                return Reply::Handled(0);
            }
            return Reply::Default;
        };
        match self.target {
            Target::Main => app.on_main(window, msg),
            Target::Secret(serial) => app.on_secret(serial, window, msg),
        }
    }
}

/// `settings.json` integrity and other startup facts shown to the user (review M1/L15, L9, L17).
#[derive(Debug, Default)]
pub(crate) struct SettingsGuard {
    /// The settings in use were compared with the meta snapshot after an unlock in this process
    /// (or the snapshot was created). Until then the `yw-llm` worker never starts.
    pub(crate) verified: bool,
    /// Save keys (`App::save_settings`) written while no snapshot was available (locked, or
    /// before the meta loaded): taken over at the next check.
    pub(crate) saved_early: Vec<&'static str>,
    /// The file values that differ from the snapshot and are not used, until the user picks
    /// `파일 값 사용` or `되돌리기` (the settings in use hold the snapshot values meanwhile).
    pub(crate) pending: Option<Box<(Settings, Vec<crate::settings::Differing>)>>,
    /// `WerAddExcludedApplication` failed at startup (crash reports may be written).
    pub(crate) wer_unprotected: bool,
    /// `vault.ywv` generation and last write time (Unix ms), read from the file header.
    pub(crate) vault_file: Option<(u64, u64)>,
    /// `(seen, found)`: the meta remembers a newer `vault.ywv` generation than the file has.
    pub(crate) rollback: Option<(u64, u64)>,
}

/// The `vault.ywv` generation and last write time (Unix ms) from the file itself (review L17);
/// `None` when absent, unreadable or not a vault.
#[must_use]
pub fn vault_file_info(data: &Path) -> Option<(u64, u64)> {
    let path = data.join(crate::store::file_name(FileKind::Vault));
    let bytes = read_limited_no_reparse(&path, 65_536).ok()?;
    let generation = yw_core::vault::peek_generation(FileKind::Vault, &bytes)?;
    let written = std::fs::symlink_metadata(&path)
        .and_then(|metadata| metadata.modified())
        .ok()
        .and_then(|time| time.duration_since(std::time::UNIX_EPOCH).ok())
        .map_or(0, |since| {
            u64::try_from(since.as_millis()).unwrap_or(u64::MAX)
        });
    Some((generation, written))
}

/// Import flow buffers held on the UI thread until `PreviewImport` moves them.
#[derive(Default)]
struct ImportFlow {
    password: Option<Zeroizing<Vec<u8>>>,
    phrase: Option<Zeroizing<Vec<u8>>>,
    password_sent: bool,
}

/// The application state (UI thread).
#[expect(
    clippy::struct_excessive_bools,
    reason = "independent UI flags of one window"
)]
pub struct App {
    pub(crate) paths: Paths,
    pub(crate) background: bool,
    pub(crate) main: Option<Window>,
    pub(crate) fonts: FontCache,
    pub(crate) events: Option<Arc<crate::events::EventQueue>>,
    pub(crate) key_queue: Arc<KeyQueue>,
    pub(crate) lock_signal: Arc<LockSignal>,
    pub(crate) rpc_tx: Option<Sender<RpcJob>>,
    pub(crate) workers: Vec<JoinHandle<()>>,
    pub(crate) self_ref: Weak<RefCell<App>>,
    pub(crate) mode: AppMode,
    pub(crate) lock_epoch: u64,
    pub(crate) settings: Settings,
    pub(crate) apikeys: ApiKeys,
    pub(crate) banners: Vec<Banner>,
    pub(crate) meta: Option<Meta>,
    pub(crate) screen: Screen,
    pub(crate) previous_screen: Screen,
    pub(crate) leftover: bool,
    pub(crate) info: Option<String>,
    pub(crate) mismatch_checked: bool,
    pub(crate) overwrite_checked: bool,
    /// 고급 설정 보기 (technical settings and fee details shown).
    pub(crate) show_advanced: bool,
    pub(crate) rename: Option<EvmAccountPref>,
    pub(crate) pending_remove: Option<RecordId>,
    pub(crate) replace_target: Option<NetworkId>,
    pub(crate) rpc_messages: Vec<(NetworkId, String, bool)>,
    pub(crate) passphrase_session: bool,
    /// `unlock` reported `PayloadCorrupt` (spec/02 §6.3): the header is intact, so a reload
    /// reports `Locked`; this keeps S09 (and `.prev` recovery) until a session opens.
    pub(crate) payload_damaged: bool,
    /// An unlock failed with `UnlockFailed` since the last session: S07 then offers `.prev`
    /// recovery for a damaged key section (spec/02 §6.3).
    pub(crate) unlock_failed: bool,
    /// The file name the last `.prev` recovery moved `vault.ywv` to (`vault.ywv.corrupt-<t>`),
    /// shown so the user can restore it by hand (docs/recovery-guide.ko.md).
    pub(crate) quarantined: Option<String>,
    /// `vault.ywv.prev` exists (checked at load and after a failed unlock).
    pub(crate) prev_on_disk: bool,
    /// S08 follows an import (no backup check ran) rather than a backup confirmation.
    pub(crate) done_imported: bool,
    /// While a `.prev` recovery submitted from W03 is pending or failed: the mode to return to
    /// when it fails or the window is cancelled.
    recover_return: Option<AppMode>,
    pub(crate) scroll: i32,
    /// Wheel accumulation and glide of the main window (`app_scroll`).
    pub(crate) scroll_state: crate::app_scroll::MainScroll,
    pub(crate) controls: ControlSet,
    pub(crate) placed: Placed,
    pub(crate) evm: crate::app_evm::EvmUi,
    pub(crate) sol: crate::app_sol::SolUi,
    pub(crate) btc: crate::app_btc::BtcUi,
    /// The Zcash tab (spec/12).
    pub(crate) zec: crate::app_zec::ZecUi,
    /// `HyperCore` card, form and session activity (spec/11).
    pub(crate) hypercore: crate::app_hypercore::HcUi,
    /// `WalletConnect` worker, sessions and panel state (spec/13).
    pub(crate) wc: crate::app_walletconnect::WcUi,
    /// Address book (S14, favorites, the inline save prompt).
    pub(crate) book: crate::app_book::BookUi,
    /// Imported keys and "개인키로 시작하기" (spec/04 §2.18).
    pub(crate) keys: crate::app_keys::KeysUi,
    /// `YubiKey` card step and enrolment state (spec/10).
    pub(crate) card: crate::app_card::CardUi,
    pub(crate) browser: Option<crate::app_browser::BrowserUi>,
    /// The `yw-llm` worker, only while the AI explanation is effectively on (spec/06 §9).
    pub(crate) llm: Option<crate::explain::ExplainService>,
    /// S15 `AI 설명` form.
    pub(crate) llm_ui: crate::app_llm::LlmUi,
    /// `settings.json` integrity (meta snapshot) and the startup facts shown with it.
    pub(crate) guard: SettingsGuard,
    /// Loading waits that time out to T-WAIT-STALLED instead of hanging (`app_reset`).
    pub(crate) wait: crate::app_reset::WaitWatch,
    /// S22 `지갑 초기화` (spec/04 §2.20).
    pub(crate) reset: crate::app_reset::ResetUi,
    /// Settings → 네트워크(RPC) `rpc.json에서 가져오기` (a plan waiting for confirmation).
    pub(crate) rpc_import: crate::app_rpc_import::RpcImportUi,
    /// S23 `Chrome 확장 설치` (spec/04 §2.21).
    pub(crate) ext: crate::app_extension::ExtensionUi,
    secret: Option<SecretWin>,
    secret_serial: u64,
    import: ImportFlow,
    challenge: Option<BackupChallenge>,
    pub(crate) idle: IdleTracker,
    secret_clip: Option<(SecretClip, u64)>,
    startup_load: bool,
    session_retries: u32,
    session_next_ms: u64,
    last_flush_ms: u64,
}

impl core::fmt::Debug for App {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter
            .debug_struct("App")
            .field("mode", &self.mode)
            .finish_non_exhaustive()
    }
}

/// The S-level notice after a password change (spec/04 §2.17): the new password is in effect in
/// both cases.
#[must_use]
pub const fn password_changed_text(change: PasswordChange) -> &'static str {
    match change {
        PasswordChange::Complete => {
            "비밀번호를 바꿨습니다. 이미 만들어 둔 지갑 파일 사본(백업한 vault.ywv, 이전 사본, 격리된 손상 파일)은 예전 비밀번호로 계속 열립니다 — 예전 비밀번호가 샜다면 그런 사본을 지우세요."
        }
        PasswordChange::PrevNotRefreshed => {
            "비밀번호를 바꿨습니다. 지금부터는 새 비밀번호로 엽니다. 다만 이전 복사본(vault.ywv.prev)을 새 비밀번호로 다시 쓰지 못해, 그 복사본은 다음 저장 전까지 예전 비밀번호로만 열릴 수 있습니다. 이미 만들어 둔 지갑 파일 사본도 예전 비밀번호로 계속 열립니다."
        }
    }
}

/// The W04 / settings note on what a password change does not do (review L1): the data key
/// (DEK) stays the same, so copies of the wallet file made before the change still open with the
/// old password and, once opened, reveal everything in the current file too.
pub const T_PASSWORD_OLD_COPIES: &str = "비밀번호를 바꿔도 지갑의 암호화 키는 그대로입니다. 바꾸기 전에 만든 지갑 파일 사본(백업해 둔 vault.ywv, vault.ywv.prev, vault.ywv.corrupt-…)은 예전 비밀번호로 계속 열리고, 그 사본과 예전 비밀번호를 함께 얻은 사람은 지금 파일도 풀 수 있습니다. 예전 비밀번호가 샜다면 그런 사본을 지우고, 자산을 새 지갑(새 복구 단어)으로 옮기는 것이 확실합니다.";

/// T-PASTE-CLEARED (spec/04 §4.7-4).
const PASTE_CLEARED: &str =
    "붙여넣은 뒤 클립보드를 비웠습니다. Windows 클립보드 기록(Win+V)을 쓴다면 그 항목도 지우세요.";
/// T-PASTE-EDGE-SPACE (spec/04 §4.7-3): a pasted password/passphrase starts or ends with a space.
pub const PASTE_EDGE_SPACE: &str =
    "앞/뒤 공백이 포함되어 있습니다. 공백도 그대로 비밀번호·passphrase의 일부가 됩니다.";

/// The information line after an accepted paste: the edge-space notice first, then the
/// clipboard note.
fn paste_notice(edge_space: bool, cleared: Option<String>) -> Option<String> {
    match (edge_space, cleared) {
        (false, cleared) => cleared,
        (true, None) => Some(PASTE_EDGE_SPACE.to_owned()),
        (true, Some(cleared)) => Some(format!("{PASTE_EDGE_SPACE} {cleared}")),
    }
}

fn now_ms() -> u64 {
    monotonic_ms()
}

/// The step indicator of the create and import flows shown in their secret windows
/// (spec/04 §2.3–§2.4).
fn flow_step(purpose: Purpose) -> Option<SecretStep> {
    use crate::ui::screens::{CREATE_STEPS, IMPORT_STEPS};
    let (flow, labels, current) = match purpose {
        Purpose::CreatePassword => ("새 지갑 만들기", CREATE_STEPS, 1),
        Purpose::ShowForBackup => ("새 지갑 만들기", CREATE_STEPS, 2),
        Purpose::Backup => ("새 지갑 만들기", CREATE_STEPS, 3),
        Purpose::ImportPassword => ("기존 지갑 가져오기", IMPORT_STEPS, 1),
        Purpose::ImportMnemonic | Purpose::ImportPassphrase => {
            ("기존 지갑 가져오기", IMPORT_STEPS, 2)
        }
        Purpose::KeyStartPassword => ("개인키로 시작하기", crate::app_keys::KEY_START_STEPS, 1),
        Purpose::KeyStartKey => ("개인키로 시작하기", crate::app_keys::KEY_START_STEPS, 2),
        Purpose::YubiKey(crate::app_yubikey::YkPurpose::NewPassword) => {
            ("YubiKey 지갑 만들기", CREATE_STEPS, 1)
        }
        Purpose::YubiKey(crate::app_yubikey::YkPurpose::ShowWords) => {
            ("YubiKey 지갑 만들기", CREATE_STEPS, 2)
        }
        Purpose::YubiKey(crate::app_yubikey::YkPurpose::Backup) => {
            ("YubiKey 지갑 만들기", CREATE_STEPS, 3)
        }
        _ => return None,
    };
    Some(SecretStep {
        flow,
        labels,
        current,
    })
}

fn eip55(address: &Address) -> String {
    address.to_checksum()
}

/// E-KEY-002 with the item name before the code (spec/04 §2.11, §7).
fn key002_text(item: &str) -> String {
    ErrorCode::Key002
        .text()
        .replace(" (E-KEY-002)", &format!(" ({item}) (E-KEY-002)"))
}

/// The S15 `QuickNode` fields at `저장`: `None` when both are empty, else the credential —
/// either field may hold the whole endpoint URL pasted from the dashboard
/// ([`quicknode_credentials`]) — or the E-KEY-002 text naming the wrong field
/// (`QuickNodeField::label`).
fn quicknode_input(name: &str, token: &str) -> Result<Option<(String, Zeroizing<String>)>, String> {
    if name.trim().is_empty() && token.trim().is_empty() {
        return Ok(None);
    }
    quicknode_credentials(name, token)
        .map(Some)
        .map_err(|field| key002_text(field.label()))
}

/// Loads `settings.json` (spec/04 §6.2).
#[must_use]
pub fn load_settings(paths: &Paths) -> crate::settings::SettingsLoad {
    match read_limited_no_reparse(
        &paths.settings(),
        u64::try_from(crate::settings::SETTINGS_MAX_BYTES).unwrap_or(65_536),
    ) {
        Ok(bytes) => crate::settings::load(Some(&bytes)),
        Err(FileError::NotFound) => crate::settings::load(None),
        Err(_) => crate::settings::SettingsLoad {
            settings: Settings::default(),
            banners: vec!["settings.json".to_owned()],
        },
    }
}

/// Loads `apikeys.dpapi` (spec/04 §6.3): `(keys, unreadable)`.
///
/// An LLM key stored by an older version has no `llm:host`. It is no longer bound here to the
/// endpoint in `settings.json` (a plain file anyone can edit, review M1): it stays unbound —
/// never attached to a request — until the first check after an unlock binds it to the host
/// in the vault-encrypted settings snapshot (`App::reconcile_settings`).
#[must_use]
pub fn load_apikeys(paths: &Paths, settings: &Settings) -> (ApiKeys, bool) {
    let blob = match read_limited_no_reparse(&paths.apikeys(), 1_048_576) {
        Ok(blob) => blob,
        Err(FileError::NotFound) => return (ApiKeys::default(), false),
        Err(_) => return (ApiKeys::default(), true),
    };
    let Ok(plain) = yw_win::dpapi::unprotect(&blob, APIKEYS_ENTROPY) else {
        return (ApiKeys::default(), true);
    };
    match ApiKeys::decode(plain.as_slice(), &|network| {
        is_registered(settings, network)
    }) {
        Ok(decoded) => {
            for orphan in decoded.orphans {
                if let KeyName::Rpc(network) = orphan {
                    logging::info("app", "apikeys.orphan", &[("net", Field::Net(network))]);
                }
            }
            (decoded.keys, false)
        }
        Err(_) => (ApiKeys::default(), true),
    }
}

impl App {
    /// A new app (no windows yet).
    #[must_use]
    pub fn new(paths: Paths, background: bool, settings: Settings, apikeys: ApiKeys) -> Self {
        let now = now_ms();
        Self {
            paths,
            background,
            main: None,
            fonts: FontCache::default(),
            events: None,
            key_queue: Arc::new(KeyQueue::default()),
            lock_signal: Arc::new(LockSignal::default()),
            rpc_tx: None,
            workers: Vec::new(),
            self_ref: Weak::new(),
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
            mismatch_checked: false,
            overwrite_checked: false,
            show_advanced: false,
            rename: None,
            pending_remove: None,
            replace_target: None,
            rpc_messages: Vec::new(),
            passphrase_session: false,
            payload_damaged: false,
            unlock_failed: false,
            quarantined: None,
            prev_on_disk: false,
            done_imported: false,
            recover_return: None,
            scroll: 0,
            scroll_state: crate::app_scroll::MainScroll::default(),
            controls: ControlSet::default(),
            placed: Placed::default(),
            evm: crate::app_evm::EvmUi::default(),
            sol: crate::app_sol::SolUi::default(),
            btc: crate::app_btc::BtcUi::default(),
            zec: crate::app_zec::ZecUi::default(),
            hypercore: crate::app_hypercore::HcUi::default(),
            wc: crate::app_walletconnect::WcUi::default(),
            book: crate::app_book::BookUi::default(),
            keys: crate::app_keys::KeysUi::default(),
            card: crate::app_card::CardUi::default(),
            browser: None,
            llm: None,
            llm_ui: crate::app_llm::LlmUi::default(),
            guard: SettingsGuard::default(),
            wait: crate::app_reset::WaitWatch::default(),
            reset: crate::app_reset::ResetUi::default(),
            rpc_import: crate::app_rpc_import::RpcImportUi::default(),
            ext: crate::app_extension::ExtensionUi::default(),
            secret: None,
            secret_serial: 0,
            import: ImportFlow::default(),
            challenge: None,
            idle: IdleTracker::new(now),
            secret_clip: None,
            startup_load: true,
            session_retries: 0,
            session_next_ms: 0,
            last_flush_ms: now,
        }
    }

    /// `WerAddExcludedApplication` failed at startup (review L9): a banner now and a line in
    /// settings → 보안 for the rest of the run.
    pub fn note_wer_unprotected(&mut self) {
        self.guard.wer_unprotected = true;
        self.banner(None, crate::ui::screens::T_WER_UNPROTECTED.to_owned());
    }

    /// Adds a banner once per code.
    pub fn banner(&mut self, code: Option<ErrorCode>, text: String) {
        if code.is_some() && self.banners.iter().any(|banner| banner.code == code) {
            return;
        }
        self.banners.push(Banner {
            code,
            text,
            tone: crate::ui::main_window::Tone::Danger,
        });
    }

    /// Adds a codeless notice banner with its own tone (info, warning); dismissed like the
    /// others with `알림 닫기`.
    pub fn notice(&mut self, text: String, tone: crate::ui::main_window::Tone) {
        self.banners.push(Banner {
            code: None,
            text,
            tone,
        });
    }

    pub(crate) fn error_banner(&mut self, code: ErrorCode) {
        logging::warn("app", "error", &[("code", Field::Code(code))]);
        self.banner(Some(code), code.text());
    }

    /// Creates the main window and stores it.
    ///
    /// # Errors
    ///
    /// [`UiError`] from window creation.
    pub fn create_main_window(app: &Rc<RefCell<Self>>) -> Result<(), UiError> {
        let handler = Box::new(Forward {
            app: Rc::downgrade(app),
            target: Target::Main,
        });
        let spec = WindowSpec::new(MAIN_CLASS, WindowKind::Main)
            .title("Your Wallet")
            .size(960, 680)
            .min_size(720, 520);
        let window = create_window(&spec, handler)?;
        let mut state = app.borrow_mut();
        state.self_ref = Rc::downgrade(app);
        window.set_timer(MAIN_TIMER_ID, crate::events::MAIN_TIMER_MS)?;
        state.main = Some(window);
        Ok(())
    }

    /// The main window poster.
    #[must_use]
    pub fn main_poster(&self) -> Option<yw_win::ui::Poster> {
        self.main.as_ref().map(Window::poster)
    }

    /// Attaches the started browser bridge (spec/05 §8.1).
    pub fn attach_browser(&mut self, browser: crate::app_browser::BrowserUi) {
        // The failure was logged by `BrowserUi::start`.
        if let Some(code) = browser.pipe_error {
            self.banner(Some(code), code.text());
        }
        self.browser = Some(browser);
    }

    /// The key queue and lock signal shared with the key worker.
    #[must_use]
    pub fn worker_channels(&self) -> (Arc<KeyQueue>, Arc<LockSignal>) {
        (Arc::clone(&self.key_queue), Arc::clone(&self.lock_signal))
    }

    /// Attaches the started workers.
    pub fn attach_workers(
        &mut self,
        events: Arc<crate::events::EventQueue>,
        workers: Vec<JoinHandle<()>>,
        rpc_tx: Sender<RpcJob>,
    ) {
        self.events = Some(events);
        self.workers = workers;
        self.rpc_tx = Some(rpc_tx);
        // spec/06 §9: the LLM worker only when the feature is effectively on.
        self.llm_reconfigure();
    }

    /// Registers session notifications (retried by the timer, spec/04 §1.4-6).
    pub fn register_session(&mut self) {
        let Some(main) = self.main.as_ref() else {
            return;
        };
        match session::register_session_notifications(main) {
            Ok(()) => self.session_retries = 0,
            Err(error) => {
                logging::warn(
                    "app",
                    "session.register_failed",
                    &[("code", Field::Num(u64::from(error.code)))],
                );
                self.session_retries = self.session_retries.saturating_add(1);
                self.session_next_ms = now_ms().saturating_add(SESSION_RETRY_MS);
                if self.session_retries >= SESSION_RETRY_MAX {
                    self.session_retries = 0;
                    self.error_banner(ErrorCode::App004);
                }
            }
        }
    }

    /// Shows the main window (not in `--background`).
    pub fn show_main(&mut self) {
        if let Some(main) = self.main.as_ref() {
            main.show();
            if !main.set_foreground() {
                main.flash();
            }
        }
        self.refresh();
    }

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

    pub(crate) fn set_screen(&mut self, screen: Screen) {
        if self.passphrase_unverified()
            && matches!(
                screen,
                Screen::Receive | Screen::SolReceive | Screen::BtcReceive
            )
        {
            self.info = Some(crate::ui::screens::T_ALT_PASS_RECEIVE.to_owned());
            self.refresh();
            return;
        }
        // Leaving a YubiKey flow by any path wipes its held seed (spec/10 §7.4).
        self.yk_leaving(&screen);
        if matches!(screen, Screen::Confirm(_)) && !matches!(self.screen, Screen::Confirm(_)) {
            self.previous_screen = self.screen.clone();
        }
        if screen != self.screen && !matches!(screen, Screen::Confirm(_)) {
            // The inline `주소록에 저장` prompt and its note belong to the screen they opened on.
            self.book.prompt = None;
            self.book.saved = None;
            self.book.btc_picker = false;
        }
        self.wait.screen_changed(&self.screen, &screen, now_ms());
        self.screen = screen;
        self.scroll = 0;
        self.stop_scroll();
        self.refresh();
    }

    // ----- rendering ---------------------------------------------------------------------

    /// Recomputes the layout, syncs the child controls and repaints.
    pub fn refresh(&mut self) {
        self.sync_browser();
        let Some(main) = self.main.as_ref() else {
            return;
        };
        let dpi = main.dpi();
        let client = main.client_rect();
        let items = self.items();
        let Some(fonts) = self.fonts.for_dpi(dpi) else {
            return;
        };
        let measure = |text: &str, role: FontRole, width: i32| {
            main.measure_text(
                fonts.get(role),
                &wide(text),
                width,
                yw_win::ui::DrawFlags::WRAP,
            )
            .1
        };
        let label = |text: &str| {
            main.measure_text(
                &fonts.body,
                &wide(text),
                10_000,
                yw_win::ui::DrawFlags::LINE,
            )
            .0
        };
        let mut placed = layout(&items, client.w, dpi, self.scroll, &measure, &label);
        let max_scroll = placed.content_height.saturating_sub(client.h).max(0);
        if self.scroll > max_scroll {
            self.scroll = max_scroll;
            placed = layout(&items, client.w, dpi, self.scroll, &measure, &label);
        }
        self.controls.sync(main, &placed, fonts, client);
        main.set_vscroll_content(self.scroll, client.h, placed.content_height);
        self.placed = placed;
        main.invalidate();
    }

    fn paint_main(&mut self, window: &Window) {
        let dpi = window.dpi();
        let client = window.client_rect();
        let Some(fonts) = self.fonts.for_dpi(dpi) else {
            return;
        };
        if let Ok(mut dc) = window.begin_paint() {
            paint(&mut dc, client, &self.placed, fonts);
        }
    }

    // ----- main window -------------------------------------------------------------------

    fn on_main(&mut self, window: &Window, msg: &Msg) -> Reply {
        if let Some(action) = system_action(msg) {
            return self.on_system(action);
        }
        match msg {
            Msg::Paint => {
                self.paint_main(window);
                Reply::Handled(0)
            }
            Msg::Size { .. } => {
                self.refresh();
                Reply::Default
            }
            Msg::DpiChanged { .. } => {
                if let Some(main) = self.main.as_ref() {
                    main.invalidate();
                }
                Reply::Default
            }
            Msg::Timer(MAIN_TIMER_ID) => {
                self.tick();
                Reply::Handled(0)
            }
            Msg::Command { id, code } => {
                if *code == 0 {
                    self.on_command(*id);
                } else if *code == EN_CHANGE
                    && !self.on_reset_edit_change(*id)
                    && !self.on_book_edit_change(*id)
                    && !self.on_sol_edit_change(*id)
                    && !self.on_btc_edit_change(*id)
                    && !self.on_zec_edit_change(*id)
                    && !self.on_llm_edit_change(*id)
                    && !self.on_yk_edit_change(*id)
                    && !self.on_hc_edit_change(*id)
                    && !self.on_wc_edit_change(*id)
                {
                    self.on_edit_change(*id);
                }
                Reply::Handled(0)
            }
            // The S22 hold area (painted, no child control).
            Msg::MouseDown { x, y } => {
                self.hold_down(*x, *y, now_ms());
                Reply::Default
            }
            Msg::MouseMove { x, y } => {
                self.hold_move(*x, *y);
                Reply::Default
            }
            Msg::MouseUp { .. } => {
                self.hold_cancel();
                Reply::Default
            }
            Msg::Timer(crate::app_scroll::SCROLL_TIMER_ID) => {
                self.scroll_tick(window);
                Reply::Handled(0)
            }
            Msg::Wheel(delta) => {
                self.main_wheel(window, *delta);
                Reply::Handled(0)
            }
            Msg::VScroll { code } => {
                self.main_vscroll(window, *code);
                Reply::Handled(0)
            }
            Msg::App { msg, wparam } => {
                match *msg {
                    WM_YW_EVENTS => self.drain_events(),
                    WM_YW_ACTIVATE => self.activate(),
                    WM_YW_LOCK_SHORTCUT => self.lock_shortcut(),
                    WM_YW_TAB_SHORTCUT if window.is_foreground() => self.tab_shortcut(*wparam),
                    _ => {}
                }
                Reply::Handled(0)
            }
            Msg::Resume => {
                logging::info("app", "power.resume", &[]);
                Reply::Default
            }
            _ => Reply::Default,
        }
    }

    fn on_system(&mut self, action: SystemAction) -> Reply {
        match action {
            SystemAction::Lock(reason) => {
                self.lock(reason);
                Reply::Default
            }
            SystemAction::AllowEndSession => Reply::Handled(1),
            SystemAction::Shutdown => {
                self.shutdown();
                Reply::Handled(0)
            }
        }
    }

    /// Ctrl+L (posted by the loop observer).
    fn lock_shortcut(&mut self) {
        if self.mode.holds_secrets() {
            self.lock(LockReason::Manual);
        }
    }

    /// Ctrl+1/2/3/4 (posted by the loop observer; the main window is in the foreground): the
    /// chain tab, exactly as clicking it, when S10 shows that tab enabled and no secret window
    /// is open.
    pub(crate) fn tab_shortcut(&mut self, tab: usize) {
        let id = match tab {
            1 => crate::ui::screens_sol::ids::TAB_EVM,
            2 => crate::ui::screens_sol::ids::TAB_SOL,
            3 => crate::ui::screens_btc::ids::TAB_BTC,
            4 => crate::ui::screens_zec::ids::TAB_ZEC,
            _ => return,
        };
        if self.screen != Screen::Main || self.secret.is_some() {
            return;
        }
        let shown = self.items().iter().any(|item| {
            matches!(item, crate::ui::main_window::Item::Row(ctls)
                if ctls.iter().any(|ctl| ctl.id == id && ctl.enabled))
        });
        if shown {
            self.on_command(id);
        }
    }

    /// Records app input for the idle timer.
    pub fn note_input(&mut self) {
        self.idle.input(now_ms());
    }

    fn activate(&mut self) {
        if let Some(main) = self.main.as_ref() {
            main.show();
            let _ = main.set_foreground();
        }
        self.background = false;
        self.refresh();
        if self.mode == AppMode::Locked && self.secret.is_none() {
            self.open_input(SecretKind::Unlock, Purpose::Unlock, false);
        }
    }

    fn tick(&mut self) {
        let now = now_ms();
        self.drain_events();
        if self.session_retries > 0 && now >= self.session_next_ms {
            self.register_session();
        }
        self.idle_tick(now);
        self.wait_tick(now);
        self.reset_hold_tick(now);
        if let Some((clip, at)) = self.secret_clip
            && now.saturating_sub(at) >= SECRET_CLIPBOARD_TTL_MS
        {
            self.clear_secret_clip(clip);
        }
        self.evm_tick(now);
        self.hc_tick(now);
        self.sol_tick(now);
        self.btc_tick(now);
        self.zec_tick(now);
        if now.saturating_sub(self.last_flush_ms) >= LOG_FLUSH_MS {
            self.last_flush_ms = now;
            logging::flush();
        }
    }

    /// Whether the idle clock is paused (spec/04 §5.1, LK-1): a W08/W09 display window or an
    /// approval window (A01, any chain) is open. Each has its own time limit; closing does not
    /// restart the count (only input does), so a dApp's unattended requests cannot keep the
    /// wallet unlocked.
    fn idle_paused(&self) -> bool {
        self.secret
            .as_ref()
            .is_some_and(|secret| secret.form.kind().is_display())
            || self.evm.window.is_some()
            || self.evm.queue.shown().is_some()
    }

    /// The idle part of the main timer: pause/resume, then `LockReason::Idle` when due. Before
    /// any vault exists, a pending import (password, words or key held here or in the key
    /// worker) is discarded after the same idle time.
    fn idle_tick(&mut self, now: u64) {
        let paused = self.idle_paused();
        self.idle.set_paused(paused);
        if !self.idle.should_lock(now, self.settings.auto_lock_minutes) {
            return;
        }
        if self.mode.holds_secrets() && self.mode != AppMode::Unlocking {
            self.lock(LockReason::Idle);
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
            || self.secret.is_some()
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
        self.keys.start = crate::app_keys::KeyStartFlow::default();
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
        self.info = Some(
            "오래 입력이 없어 입력하던 비밀번호·복구 단어·개인키를 지웠습니다. 처음부터 다시 진행하세요."
                .to_owned(),
        );
        self.set_screen(Screen::FirstRun);
    }

    fn clear_secret_clip(&mut self, clip: SecretClip) {
        self.secret_clip = None;
        if let Some(main) = self.main.as_ref() {
            let result = clipboard::clear_secret(main, &clip);
            logging::info(
                "app",
                "clipboard.secret_clear",
                &[(
                    "cleared",
                    Field::Word(if matches!(result, Ok(true)) {
                        "yes"
                    } else {
                        "no"
                    }),
                )],
            );
        }
    }

    // ----- lock and shutdown -------------------------------------------------------------

    /// The lock procedure (spec/04 §5.3).
    pub fn lock(&mut self, reason: LockReason) {
        // The dispatcher stops answering with accounts now, not after the suspend wait.
        self.browser_lock_begin();
        let vault_present = !matches!(
            self.mode,
            AppMode::NoVault | AppMode::Starting | AppMode::Corrupt { .. } | AppMode::MainMissing
        );
        self.lock_epoch = self.lock_epoch.saturating_add(1);
        let before = self.lock_signal.count();
        self.key(KeyJob::Lock);
        self.card_lock();
        self.close_secret();
        self.import = ImportFlow::default();
        self.challenge = None;
        if let Some((clip, _)) = self.secret_clip {
            self.clear_secret_clip(clip);
        }
        self.evm_lock();
        self.book = crate::app_book::BookUi::default();
        self.sol_lock();
        self.btc_lock();
        self.zec_lock();
        self.meta = None;
        self.wait = crate::app_reset::WaitWatch::default();
        self.hold_cancel();
        self.rename = None;
        self.pending_remove = None;
        self.keys = crate::app_keys::KeysUi::default();
        self.rpc_import = crate::app_rpc_import::RpcImportUi::default();
        self.passphrase_session = false;
        self.recover_return = None;
        logging::info("app", "lock", &[("reason", Field::Word(reason.as_str()))]);
        if reason == LockReason::Suspend {
            let _ = self
                .lock_signal
                .wait_beyond(before, Duration::from_millis(1_500));
        }
        if self.mode == AppMode::ShuttingDown {
            return;
        }
        self.startup_load = false;
        if vault_present {
            self.set_mode(AppMode::Locked);
            self.set_screen(Screen::Locked);
        } else if self.mode == AppMode::NoVault {
            self.set_screen(Screen::FirstRun);
        }
        // `Load` is a control job (it survives `Lock`): its result tells what the lock left on
        // disk. A `CreateWallet`/`CommitImport` that finished just before the lock had its
        // result dropped (old epoch), but the vault exists: `Loaded { Locked }` moves the UI
        // from S01 to S07 instead of offering creation over an existing vault.
        self.key(KeyJob::Load);
    }

    /// The shutdown sequence (spec/04 §1.5).
    pub fn shutdown(&mut self) {
        if self.mode == AppMode::ShuttingDown {
            return;
        }
        self.set_mode(AppMode::ShuttingDown);
        for (item, outcome) in self.evm.queue.shutdown() {
            self.approval_finished(&item.payload, outcome);
        }
        if let Some(browser) = self.browser.as_mut() {
            browser.stop();
        }
        self.wc_shutdown();
        let before = self.lock_signal.count();
        self.lock(LockReason::Shutdown);
        let _ = self.lock_signal.wait_beyond(before, Duration::from_secs(5));
        self.key_queue.push(self.lock_epoch, KeyJob::Shutdown);
        if let Some(tx) = self.rpc_tx.take() {
            let _ = tx.send(RpcJob::Shutdown);
        }
        self.llm_shutdown();
        let deadline = now_ms().saturating_add(2_000);
        for handle in std::mem::take(&mut self.workers) {
            while !handle.is_finished() && now_ms() < deadline {
                std::thread::sleep(Duration::from_millis(20));
            }
            if handle.is_finished() {
                let _ = handle.join();
            }
        }
        self.controls.clear();
        if let Some(main) = self.main.take() {
            main.kill_timer(MAIN_TIMER_ID);
            session::unregister_session_notifications(&main);
            drop(main);
        }
        logging::info("app", "app.stop", &[]);
        logging::flush();
        yw_win::ui::quit(0);
    }

    // ----- events ------------------------------------------------------------------------

    /// Drains the event queue (screenshot tour: the worker results of a scene). Gated like
    /// `ui::tour` (debug test builds only).
    #[cfg(test)]
    #[cfg(debug_assertions)]
    pub(crate) fn tour_drain_events(&mut self) {
        self.drain_events();
    }

    fn drain_events(&mut self) {
        let Some(events) = self.events.clone() else {
            return;
        };
        for event in events.drain() {
            match event {
                UiEvent::Key(result) => self.on_key_result(*result),
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
    }

    fn on_rpc_event(&mut self, network: NetworkId, message: String, ok: bool) {
        self.rpc_messages.retain(|(id, _, _)| *id != network);
        self.rpc_messages.push((network, message, ok));
        self.refresh();
    }

    pub(crate) fn secret_purpose(&self) -> Option<Purpose> {
        self.secret.as_ref().map(|secret| secret.purpose)
    }

    pub(crate) fn with_form(&mut self, f: impl FnOnce(&mut SecretForm)) {
        if let Some(secret) = self.secret.as_mut() {
            f(&mut secret.form);
            secret.window.invalidate();
        }
    }

    #[expect(clippy::too_many_lines, reason = "one arm per key outcome")]
    fn on_key_result(&mut self, result: KeyResult) {
        if !accept_result(&result, self.lock_epoch) {
            return;
        }
        let now = now_ms();
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
                self.prev_on_disk = crate::store::prev_exists(&self.paths.data, FileKind::Vault);
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
                        code.render(&position.to_string())
                    }
                    _ => code.text(),
                };
                self.import.phrase = None;
                self.set_screen(Screen::ImportIntro);
                self.open_input(SecretKind::Mnemonic, Purpose::ImportMnemonic, false);
                self.with_form(|form| form.set_error(Some(message)));
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
                self.keys.start = crate::app_keys::KeyStartFlow::default();
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
                self.keys.start = crate::app_keys::KeyStartFlow::default();
                self.error_banner(vault_code(error));
                self.reload_after_failed_start();
            }
            KeyOutcome::KeyImported(result) => self.on_key_imported(result),
            KeyOutcome::ImportedKeyRemoved(Ok((id, chain))) => {
                self.on_imported_key_removed(id, chain);
            }
            KeyOutcome::ImportedKeyBusy(_) => self.on_imported_key_busy(),
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
            KeyOutcome::SolKeys(purpose, result) => self.on_sol_keys(purpose, result),
            KeyOutcome::SignedSol(result) => self.on_sol_signed(result),
            KeyOutcome::SignedMessage(result) => self.browser_message_signed(result),
            KeyOutcome::SignedChainMessage(result) => self.browser_chain_message_signed(&result),
            KeyOutcome::YubiKeyEnrolled(result) => self.on_yubikey_enrolled(result),
            KeyOutcome::YubiKey(outcome) => self.on_yk_outcome(outcome),
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
                    self.with_form(|form| {
                        form.reset_backup(
                            challenge.positions,
                            Some(
                                "입력한 단어가 맞지 않습니다. 새 위치로 다시 확인합니다."
                                    .to_owned(),
                            ),
                        );
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
            KeyOutcome::BackupConfirmed(Err(error)) => {
                self.with_form(|form| {
                    form.set_busy(false);
                    form.set_error(Some(vault_code(error).text()));
                });
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
            KeyOutcome::PasswordChanged(Ok(change)) => {
                self.close_secret();
                let complete = change == PasswordChange::Complete;
                logging::info(
                    "app",
                    "password.changed",
                    &[("prev", Field::Word(if complete { "ok" } else { "stale" }))],
                );
                self.info = Some(password_changed_text(change).to_owned());
                // Review L17: the meta remembers the new vault generation.
                self.save_meta();
                self.refresh();
            }
            KeyOutcome::RawKeyImported(Ok((id, address))) => {
                self.close_secret();
                if let Some(meta) = self.meta.as_mut() {
                    let label = crate::meta::next_imported_label(
                        crate::meta::EVM_IMPORTED_PREFIX,
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
                self.refresh();
            }
            KeyOutcome::RawKeyImported(Err(error)) => {
                self.with_form(|form| {
                    form.set_busy(false);
                    form.set_error(Some(vault_code(error).text()));
                });
            }
            KeyOutcome::RawKeyRemoved(Ok(id)) => {
                self.close_secret();
                let removed = self.meta.as_ref().and_then(|meta| {
                    let raw = meta
                        .evm_raw_accounts
                        .iter()
                        .find(|raw| raw.record_id == *id.as_bytes())?;
                    // The same key may also be a derived account (its private key was
                    // imported): that account stays, and so do its site connections.
                    let still_derived = meta.evm_accounts.iter().any(|account| {
                        !account.hidden && account.address.eq_ignore_ascii_case(&raw.address)
                    });
                    if still_derived {
                        return None;
                    }
                    yw_core::evm::address::parse_address(&raw.address).ok()
                });
                if let Some(address) = removed {
                    self.account_removed_from_sites(&address);
                }
                if let Some(meta) = self.meta.as_mut() {
                    meta.evm_raw_accounts
                        .retain(|raw| raw.record_id != *id.as_bytes());
                    if meta.prefs.evm_account == EvmAccountPref::Record(*id.as_bytes()) {
                        meta.prefs.evm_account = EvmAccountPref::Index(0);
                    }
                }
                logging::info("app", "rawkey.removed", &[]);
                self.save_meta();
                self.refresh();
            }
            KeyOutcome::Meta(Ok(MetaLoaded {
                meta,
                prefs_reset,
                has_mnemonic,
                ..
            })) => {
                if prefs_reset {
                    logging::warn("app", "meta.prefs_reset", &[]);
                }
                self.keys.has_mnemonic = has_mnemonic;
                self.meta = Some(*meta);
                self.wait.meta_since = None;
                // Review M1/L15/L17: compare settings.json with the snapshot in the meta.
                self.verify_settings();
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
                if self.evm.journal.is_none() {
                    self.evm_after_unlock();
                }
                if self.sol_tab_active() {
                    self.sol_ensure_account();
                }
                self.btc_after_meta();
                self.zec_ensure_account();
                self.card_after_meta();
            }
            KeyOutcome::Meta(Err(
                VaultError::SidecarCorrupt(_) | VaultError::SidecarVaultMismatch(_),
            )) => {
                self.wait.meta_since = None;
                self.error_banner(ErrorCode::Vlt006);
                self.set_screen(Screen::Confirm(Confirm::SidecarCorrupt));
            }
            KeyOutcome::Meta(Err(error)) => {
                self.wait.meta_since = None;
                self.error_banner(vault_code(error));
                self.meta = Some(Meta::default());
                self.set_screen(if self.mode == AppMode::BackupPending {
                    Screen::BackupPending
                } else {
                    Screen::Main
                });
            }
            KeyOutcome::SidecarResolved(result) => {
                if let Err(code) = result {
                    self.error_banner(code);
                }
                self.evm.journal = None;
                self.request_meta();
                self.set_screen(Screen::Processing("불러오는 중…"));
            }
            KeyOutcome::Addresses(Ok(list)) => {
                if let Some(meta) = self.meta.as_mut() {
                    for (index, address) in list {
                        if !meta
                            .evm_accounts
                            .iter()
                            .any(|account| account.index == index)
                        {
                            meta.evm_accounts.push(new_account(index, &address));
                        }
                    }
                    meta.evm_accounts.sort_by_key(|account| account.index);
                }
                self.save_meta();
                self.refresh();
            }
        }
    }

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
                        self.info = Some(Self::recovered_text(from, self.quarantined.as_deref()));
                    }
                }
                self.set_mode(AppMode::from_status(status));
                match status {
                    VaultStatus::PassphraseRequired => {
                        self.passphrase_session = true;
                        self.set_screen(Screen::Locked);
                        self.open_input(
                            SecretKind::Passphrase { confirm: false },
                            Purpose::EnterPassphrase,
                            false,
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
                        self.set_screen(Screen::Processing("불러오는 중…"));
                    }
                    VaultStatus::Corrupt { .. } | VaultStatus::MainMissing => {
                        self.close_secret();
                        self.set_screen(Screen::Recovery);
                    }
                    VaultStatus::Locked | VaultStatus::NoVault => {
                        self.close_secret();
                        self.guard.vault_file = vault_file_info(&self.paths.data);
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
                self.prev_on_disk = crate::store::prev_exists(&self.paths.data, FileKind::Vault);
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
                        self.prev_on_disk =
                            crate::store::prev_exists(&self.paths.data, FileKind::Vault);
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
        self.set_screen(Screen::Processing("불러오는 중…"));
        self.key(KeyJob::Load);
    }

    /// The S10 note after a successful `.prev` recovery started from `from`, naming the file
    /// the damaged `vault.ywv` was moved to when there was one.
    fn recovered_text(from: AppMode, quarantined: Option<&str>) -> String {
        let kept = quarantined.map(|name| {
            format!(
                " 열리지 않던 지갑 파일은 데이터 폴더에 {name} 이름으로 옮겨 두었습니다. 직접 되돌리는 방법은 복구 안내(recovery-guide)를 보세요."
            )
        });
        match (from, kept) {
            (AppMode::Corrupt { .. } | AppMode::MainMissing, kept) => format!(
                "이전 사본(.prev)으로 복구했습니다. 마지막 변경(예: 가져온 개인키)이 빠졌을 수 있으니 확인하세요.{}",
                kept.unwrap_or_default()
            ),
            (_, Some(kept)) => format!("이전 사본(.prev)으로 복구했습니다.{kept}"),
            (_, None) => "지갑을 열었습니다.".to_owned(),
        }
    }

    /// A failed `.prev` recovery: the W03 window stays open for another try.
    fn recovery_failure(&mut self, error: VaultError, now: u64) {
        let text = match error {
            VaultError::UnlockFailed => {
                logging::info("app", "recover.failed", &[]);
                self.with_form(|form| form.fail_password(now));
                return;
            }
            VaultError::Storage(yw_core::error::StorageError::NotFound) => {
                "이전 사본(.prev)이 없어 복구할 수 없습니다. 복구 단어로 지갑을 다시 가져오세요. 데이터 폴더의 파일은 그대로 두었습니다.".to_owned()
            }
            VaultError::PayloadCorrupt => {
                "이전 사본(.prev)도 손상되어 복구할 수 없습니다. 복구 단어로 지갑을 다시 가져오세요. 데이터 폴더의 파일은 그대로 두었습니다.".to_owned()
            }
            other => vault_code(other).text(),
        };
        logging::warn(
            "app",
            "recover.failed",
            &[("code", Field::Code(vault_code(error)))],
        );
        if self.secret.is_some() {
            self.with_form(|form| {
                form.set_busy(false);
                form.set_error(Some(text));
            });
        } else {
            self.banner(None, text);
            self.refresh();
        }
    }

    pub(crate) fn password_failure(&mut self, error: VaultError, now: u64) {
        if error == VaultError::UnlockFailed {
            logging::info("app", "unlock.failed", &[]);
            self.with_form(|form| form.fail_password(now));
        } else {
            let code = vault_code(error);
            logging::warn("app", "key.error", &[("code", Field::Code(code))]);
            self.with_form(|form| {
                form.set_busy(false);
                form.set_error(Some(code.text()));
            });
            if self.secret.is_none() {
                self.error_banner(code);
            }
        }
    }

    // ----- secret windows ----------------------------------------------------------------

    fn create_secret(&mut self, kind: SecretKind, topmost: bool) -> (u64, Result<Window, UiError>) {
        self.secret_serial = self.secret_serial.saturating_add(1);
        let serial = self.secret_serial;
        let Some(owner) = self.main.as_ref().map(Window::hwnd) else {
            return (serial, Err(UiError::CaptureExclusionFailed));
        };
        let (w, h) = kind.size();
        let class = if kind.is_display() {
            SECRET_VIEW_CLASS
        } else {
            SECRET_INPUT_CLASS
        };
        let spec = WindowSpec::new(class, WindowKind::Owned { owner })
            .title(&format!("Your Wallet — {}", kind.title()))
            .size(w, h)
            .topmost(topmost);
        let handler = Box::new(Forward {
            app: self.self_ref.clone(),
            target: Target::Secret(serial),
        });
        (serial, create_window(&spec, handler))
    }

    fn show_secret(&mut self, serial: u64, window: Window, form: SecretForm, purpose: Purpose) {
        let _ = window.set_timer(SECRET_TIMER_ID, SECRET_TIMER_MS);
        if let Some(main) = self.main.as_ref() {
            main.enable(false);
        }
        window.show();
        if !window.set_foreground() {
            window.flash();
        }
        window.set_focus();
        window.invalidate();
        self.secret = Some(SecretWin {
            serial,
            window,
            form,
            purpose,
        });
    }

    fn log_capture(kind: SecretKind, excluded: bool) {
        if !excluded {
            logging::warn(
                "secret",
                "secret.capture_exclusion=failed",
                &[
                    ("window", Field::Word(kind.id())),
                    (
                        "capture",
                        Field::Word(if kind.is_display() {
                            "Required"
                        } else {
                            "Preferred"
                        }),
                    ),
                ],
            );
        }
    }

    /// Opens an input window (W01–W07, W10).
    pub(crate) fn open_input(&mut self, kind: SecretKind, purpose: Purpose, topmost: bool) {
        self.close_secret();
        let (serial, created) = self.create_secret(kind, topmost);
        match created {
            Ok(window) => {
                let excluded = window.capture_excluded();
                Self::log_capture(kind, excluded);
                match capture_decision(kind, Ok(excluded)) {
                    CaptureDecision::Show { warning } => {
                        let mut form = SecretForm::new(kind, now_ms(), !warning);
                        form.set_step(flow_step(purpose));
                        self.show_secret(serial, window, form, purpose);
                    }
                    CaptureDecision::Refuse(code) => {
                        drop(window);
                        self.error_banner(code);
                    }
                }
            }
            Err(UiError::CaptureExclusionFailed) => {
                Self::log_capture(kind, false);
                self.error_banner(ErrorCode::Sec001);
            }
            Err(UiError::Os(_)) => self.error_banner(ErrorCode::App009),
        }
    }

    /// Opens a display window (W08/W09); on exclusion failure the secret is wiped (E-SEC-001).
    pub(crate) fn open_display(
        &mut self,
        kind: SecretKind,
        purpose: Purpose,
        display: DisplaySecret,
    ) {
        self.close_secret();
        let (serial, created) = self.create_secret(kind, false);
        let excluded = created
            .as_ref()
            .map(Window::capture_excluded)
            .map_err(|_| ());
        Self::log_capture(kind, excluded.unwrap_or(false));
        let decision = capture_decision(kind, excluded);
        match (decision, created) {
            (CaptureDecision::Show { .. }, Ok(window)) => {
                let mut form = SecretForm::display(kind, now_ms(), display);
                form.set_step(flow_step(purpose));
                self.show_secret(serial, window, form, purpose);
            }
            (CaptureDecision::Refuse(code), _) => {
                drop(display);
                self.error_banner(code);
                if purpose == Purpose::ShowForBackup {
                    self.set_screen(Screen::BackupPending);
                }
            }
            (CaptureDecision::Show { .. }, Err(_)) => {
                drop(display);
                self.error_banner(ErrorCode::App009);
            }
        }
    }

    /// Whether a secret window (W01–W10) is open.
    #[must_use]
    pub fn secret_open(&self) -> bool {
        self.secret.is_some()
    }

    /// Closes the open secret window (buffers wiped).
    pub fn close_secret(&mut self) {
        if let Some(mut secret) = self.secret.take() {
            secret.form.wipe();
            secret.window.kill_timer(SECRET_TIMER_ID);
            if let Some(main) = self.main.as_ref() {
                main.enable(true);
            }
            drop(secret.window);
            if let Some(main) = self.main.as_ref() {
                let _ = main.set_foreground();
            }
        }
    }

    fn on_secret(&mut self, serial: u64, window: &Window, msg: &Msg) -> Reply {
        let now = now_ms();
        let dpi = window.dpi();
        let Self { secret, fonts, .. } = self;
        let Some(secret) = secret.as_mut().filter(|secret| secret.serial == serial) else {
            return Reply::Default;
        };
        let form = &mut secret.form;
        let action = match msg {
            Msg::Paint => {
                if let Some(fonts) = fonts.for_dpi(dpi)
                    && let Ok(mut dc) = window.begin_paint()
                {
                    form.paint(&mut dc, window.client_rect(), fonts, dpi, now);
                }
                return Reply::Handled(0);
            }
            Msg::Char(unit) => form.on_char(*unit, now),
            Msg::KeyDown { vk, .. } => {
                let action = form.on_key(
                    *vk,
                    is_down(VK_CONTROL),
                    is_down(VK_SHIFT),
                    is_down(VK_MENU),
                    now,
                );
                if matches!(action, FormAction::None) {
                    return Reply::Default;
                }
                action
            }
            Msg::MouseDown { x, y } => {
                let (action, capture) = form.on_mouse_down(*x, *y, now);
                if capture {
                    window.set_capture();
                }
                action
            }
            Msg::MouseUp { x, y } => {
                window.release_capture();
                form.on_mouse_up(*x, *y, now)
            }
            Msg::MouseMove { x, y } => form.on_mouse_move(*x, *y),
            Msg::Timer(SECRET_TIMER_ID) => form.on_tick(now),
            Msg::ActivateApp(false) | Msg::KillFocus { to_foreign: true } => form.on_deactivate(),
            Msg::ActivateApp(true) => {
                form.on_activate();
                FormAction::Redraw
            }
            Msg::CaptureChanged | Msg::CancelMode => form.on_capture_lost(),
            Msg::MouseActivate => {
                return if window.is_foreground() {
                    Reply::Default
                } else {
                    Reply::Handled(MA_ACTIVATEANDEAT)
                };
            }
            Msg::ImeAttempt => form.on_key(0xE5, false, false, false, now),
            Msg::Size { .. } | Msg::DpiChanged { .. } => {
                window.invalidate();
                return Reply::Default;
            }
            Msg::Close => {
                let action = if form.kind().is_display() && !form.kind().needs_hold() {
                    form.wipe();
                    FormAction::Close
                } else {
                    form.wipe();
                    FormAction::Cancel
                };
                self.apply_form_action(action);
                return Reply::Handled(0);
            }
            _ => return Reply::Default,
        };
        self.apply_form_action(action);
        Reply::Handled(0)
    }

    fn apply_form_action(&mut self, action: FormAction) {
        let Some(purpose) = self.secret_purpose() else {
            return;
        };
        match action {
            FormAction::None => {}
            FormAction::Redraw => {
                if let Some(secret) = self.secret.as_ref() {
                    secret.window.invalidate();
                }
            }
            FormAction::Submit(submission) => self.on_submit(purpose, submission),
            FormAction::Cancel | FormAction::TimedOut => {
                let timed_out = matches!(action, FormAction::TimedOut);
                self.on_cancel(purpose);
                if timed_out {
                    self.info = Some("시간이 지나 창을 닫았습니다.".to_owned());
                    self.refresh();
                }
            }
            FormAction::Close => {
                self.close_secret();
                self.refresh();
            }
            FormAction::Paste => self.paste(),
            FormAction::Copy => self.copy_secret(),
            FormAction::HoldComplete => {
                logging::info("app", "backup.written_ack", &[]);
                if let Purpose::YubiKey(yk) = purpose {
                    self.yk_hold_complete(yk);
                } else {
                    self.close_secret();
                    self.key(KeyJob::BackupChallenge);
                }
            }
        }
    }

    fn paste(&mut self) {
        let Some(secret) = self.secret.as_mut() else {
            return;
        };
        let read = clipboard::read_text(&secret.window, PASTE_MAX_UTF16_UNITS);
        let message = match read {
            Ok((units, seq)) => {
                // Accepted or rejected (E-INP-018), the text was secret-shaped and was read: the
                // clipboard is cleared either way (spec/04 §4.7-4).
                let applied = secret.form.apply_paste(units.as_slice());
                drop(units);
                let cleared = match clipboard::clear_if_unchanged(&secret.window, seq) {
                    Ok(true) => Some(PASTE_CLEARED.to_owned()),
                    Ok(false) => None,
                    Err(_) => Some(ErrorCode::Sec002.text()),
                };
                match applied {
                    Ok(edge_space) => paste_notice(edge_space, cleared),
                    Err(code) => {
                        secret.form.set_error(Some(code.text()));
                        cleared
                    }
                }
            }
            Err(ClipError::TooLong) => {
                secret.form.set_error(Some(ErrorCode::Inp018.text()));
                None
            }
            Err(ClipError::Busy | ClipError::Os(_)) => Some(ErrorCode::Sec002.text()),
        };
        logging::info(
            "secret",
            "clipboard.paste",
            &[("window", Field::Word(secret.form.kind().id()))],
        );
        if message.is_some() {
            secret.form.set_info(message);
        }
        secret.window.invalidate();
    }

    fn copy_secret(&mut self) {
        let allowed = self.settings.allow_secret_copy;
        let Some(secret) = self.secret.as_mut() else {
            return;
        };
        if !allowed {
            secret.form.set_info(Some(
                "복사가 꺼져 있습니다. 설정에서 바꿀 수 있습니다.".to_owned(),
            ));
            secret.window.invalidate();
            return;
        }
        let Some(units) = secret.form.copy_units() else {
            return;
        };
        match clipboard::set_secret_text(&secret.window, &units) {
            Ok(clip) => {
                self.secret_clip = Some((clip, now_ms()));
                secret.form.set_info(Some(
                    "클립보드에 복사했습니다. 30초 뒤 지웁니다.".to_owned(),
                ));
                logging::info(
                    "secret",
                    "clipboard.secret_copy",
                    &[("window", Field::Word(secret.form.kind().id()))],
                );
            }
            Err(_) => secret.form.set_error(Some(ErrorCode::Sec002.text())),
        }
        secret.window.invalidate();
    }

    #[expect(clippy::too_many_lines, reason = "one arm per secret-window purpose")]
    fn on_submit(&mut self, purpose: Purpose, submission: Submission) {
        if let Purpose::YubiKey(yk) = purpose {
            self.yk_submit(yk, submission.values, submission.checkbox);
            return;
        }
        let mut values = submission.values.into_iter();
        let mut next = || values.next().unwrap_or_default();
        match purpose {
            Purpose::CreatePassword => {
                let password = next();
                self.close_secret();
                self.set_screen(Screen::Processing(
                    "지갑을 만드는 중입니다. 몇 초 걸립니다.",
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
                self.with_form(|form| form.set_busy(true));
                self.key(KeyJob::Unlock { password: next() });
            }
            Purpose::EnterPassphrase => {
                self.with_form(|form| form.set_busy(true));
                self.key(KeyJob::EnterPassphrase { passphrase: next() });
            }
            Purpose::Backup => {
                let Some(challenge) = self.challenge else {
                    self.close_secret();
                    return;
                };
                let words = [next(), next(), next(), next()];
                self.with_form(|form| form.set_busy(true));
                self.key(KeyJob::ConfirmBackup {
                    id: challenge.id,
                    words,
                });
            }
            Purpose::ConfirmPassword(action) => {
                let password = next();
                self.with_form(|form| form.set_busy(true));
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
                self.with_form(|form| form.set_busy(true));
                self.key(KeyJob::ChangePassword { old, new });
            }
            Purpose::ImportKey => {
                self.with_form(|form| form.set_busy(true));
                self.key(KeyJob::ImportPrivateKey { hex: next() });
            }
            Purpose::KeyStartPassword => self.key_start_password(next()),
            Purpose::KeyStartKey => self.key_start_key(next()),
            Purpose::ImportChainKey(spec) => {
                self.with_form(|form| form.set_busy(true));
                self.key(KeyJob::ImportKey { spec, key: next() });
            }
            Purpose::CardSign(id) => self.card_submit(id, next()),
            Purpose::ShowForBackup | Purpose::ShowRevealed | Purpose::YubiKey(_) => {}
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
        self.set_screen(Screen::Processing("확인 중…"));
        self.key(KeyJob::PreviewImport {
            password,
            phrase,
            passphrase,
        });
    }

    fn on_cancel(&mut self, purpose: Purpose) {
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
            Purpose::EnterPassphrase => self.lock(LockReason::Manual),
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
            Purpose::ConfirmPassword(_)
            | Purpose::ShowRevealed
            | Purpose::ChangePassword
            | Purpose::ImportKey
            | Purpose::ImportChainKey(_) => self.refresh(),
        }
    }

    // ----- meta, settings, apikeys -------------------------------------------------------

    pub(crate) fn save_meta(&mut self) {
        // Review L17: remember the newest `vault.ywv` generation with every meta write, so a
        // `vault.ywv` rolled back on its own is noticed at the next unlock.
        if let Some((found, written)) = vault_file_info(&self.paths.data) {
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
        let written = settings.read_only().is_some()
            || atomic_write(&self.paths.settings(), &settings.to_json()).is_ok();
        if written {
            if settings.log_level != self.settings.log_level {
                logging::set_level(settings.log_level);
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
    pub fn save_apikeys(&mut self) -> bool {
        let plain = self.apikeys.encode();
        let written = yw_win::dpapi::protect(&plain, APIKEYS_ENTROPY)
            .ok()
            .is_some_and(|blob| atomic_write(&self.paths.apikeys(), &blob).is_ok());
        if !written {
            let (keys, _) = load_apikeys(&self.paths, &self.settings);
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
            && atomic_write(&self.paths.settings(), &outcome.file.to_json()).is_err()
        {
            self.error_banner(ErrorCode::App002);
        }
        if outcome.llm_forced_off {
            logging::warn("app", "settings.llm_consent_missing", &[]);
            self.banner(None, crate::settings::LLM_FORCED_OFF_TEXT.to_owned());
        }
        for id in &outcome.pins_restored {
            logging::warn(
                "app",
                "settings.pin_restored",
                &[("net", Field::Net(NetworkId::Eip155(*id)))],
            );
        }
        if !outcome.pins_restored.is_empty() {
            self.banner(None, crate::settings::PIN_RESTORED_TEXT.to_owned());
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
        let file = vault_file_info(&self.paths.data);
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
                self.banner(None, crate::ui::screens::rollback_text(seen, found));
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

    pub(crate) fn open_folder(path: &Path) {
        let root = std::env::var_os("SystemRoot")
            .map_or_else(|| PathBuf::from("C:\\Windows"), PathBuf::from);
        let spawned = std::process::Command::new(root.join("explorer.exe"))
            .arg(path)
            .spawn();
        logging::info(
            "app",
            "folder.open",
            &[(
                "ok",
                Field::Word(if spawned.is_ok() { "yes" } else { "no" }),
            )],
        );
    }

    // ----- commands ----------------------------------------------------------------------

    #[expect(clippy::too_many_lines, reason = "one arm per command id")]
    fn on_command(&mut self, id: u16) {
        use crate::ui::screens::ids;
        self.note_input();
        match id {
            ids::FIRST_CREATE => self.set_screen(Screen::CreateIntro),
            ids::FIRST_IMPORT => self.set_screen(Screen::ImportIntro),
            ids::OPEN_DATA_FOLDER => Self::open_folder(&self.paths.data.clone()),
            ids::OPEN_LOG_FOLDER => Self::open_folder(&self.paths.logs.clone()),
            ids::CREATE_NEXT => {
                self.open_input(SecretKind::SetPassword, Purpose::CreatePassword, false);
            }
            ids::INTRO_CANCEL => {
                self.key_start_cancel();
                self.set_screen(Screen::FirstRun);
            }
            ids::IMPORT_NEXT => {
                self.open_input(SecretKind::SetPassword, Purpose::ImportPassword, false);
            }
            ids::IMPORT_CORRECT => {
                self.set_screen(Screen::Processing(
                    "지갑을 가져오는 중입니다. 몇 초 걸립니다.",
                ));
                self.key(KeyJob::CommitImport);
            }
            ids::IMPORT_WRONG => {
                self.key(KeyJob::DiscardImport {
                    keep_password: true,
                });
                self.set_screen(Screen::ImportIntro);
                self.open_input(SecretKind::Mnemonic, Purpose::ImportMnemonic, false);
            }
            ids::UNLOCK => self.open_input(SecretKind::Unlock, Purpose::Unlock, false),
            ids::BACKUP_CHECK => self.open_input(
                SecretKind::ConfirmPassword,
                Purpose::ConfirmPassword(PasswordAction::RevealMnemonic { then_backup: true }),
                false,
            ),
            ids::LOCK => self.lock(LockReason::Manual),
            ids::DONE_CONTINUE | ids::BACK_MAIN | ids::SWITCH_ACCOUNT => {
                self.info = None;
                self.keys.done_start = false;
                if self.mode == AppMode::BackupPending {
                    // `← 메인으로` from S12 during the backup check: S04 is this mode's main
                    // screen (S10, and a `Processing` wait for it, never come in this mode).
                    if self.meta.is_none() {
                        self.request_meta();
                    }
                    self.set_screen(Screen::BackupPending);
                } else if self.meta.is_some() {
                    self.set_screen(Screen::Main);
                } else {
                    self.request_meta();
                    self.set_screen(Screen::Processing("불러오는 중…"));
                }
            }
            ids::RECOVER => {
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
            ids::EXIT => self.shutdown(),
            ids::MISMATCH_RETRY => {
                self.key(KeyJob::RetryPassphrase);
            }
            ids::MISMATCH_CHECK => {
                self.mismatch_checked = self.controls.checked(ids::MISMATCH_CHECK).unwrap_or(false);
                self.refresh();
            }
            ids::MISMATCH_CONTINUE => {
                if self.mismatch_checked {
                    self.key(KeyJob::AcceptMismatch);
                }
            }
            ids::SIDECAR_PREV | ids::SIDECAR_FRESH => {
                self.key(KeyJob::ResolveSidecar {
                    kind: FileKind::Meta,
                    use_prev: id == ids::SIDECAR_PREV,
                });
            }
            ids::OPEN_SETTINGS | ids::SECTION_SECURITY => {
                self.set_screen(Screen::Settings(SettingsSection::Security));
            }
            ids::DONE_RPC | ids::SECTION_NETWORK | ids::GO_NETWORK => {
                self.set_screen(Screen::Settings(SettingsSection::Network));
            }
            ids::SECTION_OTHER => self.set_screen(Screen::Settings(SettingsSection::Other)),
            ids::ADVANCED_TOGGLE => {
                self.show_advanced = !self.show_advanced;
                self.refresh();
            }
            ids::DISMISS_BANNERS => {
                self.banners.clear();
                // Review L17: a dismissed rollback warning is acknowledged; the next meta write
                // remembers the current generation.
                self.guard.rollback = None;
                self.info = None;
                self.refresh();
            }
            ids::SETTINGS_ACCEPT_FILE => self.settings_accept_file(),
            ids::SETTINGS_RESTORE => self.settings_restore(),
            ids::ADD_ACCOUNT => {
                if let Some(index) = self.meta.as_ref().and_then(Meta::next_index) {
                    self.key(KeyJob::DeriveAddresses {
                        indices: vec![index],
                    });
                }
            }
            ids::IMPORT_KEY => {
                self.open_key_import(yw_core::keyimport::ImportChain::Evm);
            }
            ids::RENAME => {
                self.rename = self.selected_pref();
                self.refresh();
            }
            ids::RENAME_CANCEL => {
                self.rename = None;
                self.refresh();
            }
            ids::RENAME_SAVE => self.save_rename(),
            ids::HIDE => self.hide_selected(),
            ids::REMOVE_KEY => {
                if let Some(EvmAccountPref::Record(id)) = self.selected_pref() {
                    self.pending_remove = Some(RecordId::from_bytes(id));
                    self.set_screen(Screen::Confirm(Confirm::RemoveKey));
                }
            }
            ids::REVEAL_MNEMONIC => self.set_screen(Screen::Confirm(Confirm::RevealMnemonic)),
            ids::REVEAL_KEY => self.set_screen(Screen::Confirm(Confirm::RevealKey)),
            ids::CHANGE_PASSWORD => {
                self.open_input(SecretKind::ChangePassword, Purpose::ChangePassword, false);
            }
            ids::AUTOLOCK_SAVE => self.save_autolock(),
            ids::COPY_TOGGLE => {
                let checked = self.controls.checked(ids::COPY_TOGGLE).unwrap_or(false);
                if checked && !self.settings.allow_secret_copy {
                    self.set_screen(Screen::Confirm(Confirm::CopyOn));
                } else if !checked {
                    let mut settings = self.settings.clone();
                    settings.allow_secret_copy = false;
                    self.save_settings(settings, "allowSecretCopy");
                }
            }
            ids::LOCALHOST_TOGGLE => {
                let checked = self
                    .controls
                    .checked(ids::LOCALHOST_TOGGLE)
                    .unwrap_or(false);
                if checked && !self.settings.allow_localhost_dapps {
                    self.set_screen(Screen::Confirm(Confirm::LocalhostOn));
                } else if !checked {
                    let mut settings = self.settings.clone();
                    settings.allow_localhost_dapps = false;
                    self.save_settings(settings, "allowLocalhostDapps");
                }
            }
            ids::AUTOLAUNCH_TOGGLE => {
                let mut settings = self.settings.clone();
                settings.browser_auto_launch = self
                    .controls
                    .checked(ids::AUTOLAUNCH_TOGGLE)
                    .unwrap_or(true);
                self.save_settings(settings, "browserAutoLaunch");
            }
            ids::LOG_ERROR | ids::LOG_WARN | ids::LOG_INFO | ids::LOG_DEBUG => {
                let level = match id {
                    ids::LOG_ERROR => LogLevel::Error,
                    ids::LOG_WARN => LogLevel::Warn,
                    ids::LOG_DEBUG => LogLevel::Debug,
                    _ => LogLevel::Info,
                };
                let mut settings = self.settings.clone();
                settings.log_level = level;
                self.save_settings(settings, "logLevel");
            }
            ids::TPL_QUICKNODE | ids::TPL_ALCHEMY | ids::TPL_MANUAL => {
                let template = match id {
                    ids::TPL_QUICKNODE => RpcTemplate::QuickNode,
                    ids::TPL_ALCHEMY => RpcTemplate::Alchemy,
                    _ => RpcTemplate::Manual,
                };
                let mut settings = self.settings.clone();
                settings.rpc_template = template;
                self.save_settings(settings, "rpc.template");
            }
            ids::TPL_SAVE => {
                let _ = self.save_template_credentials();
                self.refresh();
            }
            ids::TPL_DELETE => self.delete_template_credentials(),
            ids::GENERATE => self.begin_generate(),
            ids::PRUNE_DORMANT => {
                if !self.apikeys.dormant_names().is_empty() {
                    self.set_screen(Screen::Confirm(Confirm::PruneDormant));
                }
            }
            ids::OVERWRITE_CHECK => {
                self.overwrite_checked =
                    self.controls.checked(ids::OVERWRITE_CHECK).unwrap_or(false);
                self.refresh();
            }
            ids::REPLACE_SAVE => self.save_replacement(),
            ids::REPLACE_CANCEL => {
                self.replace_target = None;
                self.refresh();
            }
            ids::CONFIRM_YES => self.confirm_yes(),
            ids::CONFIRM_NO if matches!(self.screen, Screen::Confirm(Confirm::Btc)) => {
                self.btc_confirm_no();
            }
            ids::CONFIRM_NO => {
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
            receive
                if self.passphrase_unverified()
                    && crate::ui::screens::RECEIVE_IDS.contains(&receive) =>
            {
                // Before any chain handler runs (BTC would derive and store a new address).
                self.info = Some(crate::ui::screens::T_ALT_PASS_RECEIVE.to_owned());
                self.refresh();
            }
            other => {
                if !self.on_reset_command(other)
                    && !self.on_book_command(other)
                    && !self.on_rpc_import_command(other)
                    && !self.on_extension_command(other)
                    && !self.on_keys_command(other)
                    && !self.on_sol_command(other)
                    && !self.on_btc_command(other)
                    && !self.on_zec_command(other)
                    && !self.on_evm_command(other)
                    && !self.on_sites_command(other)
                    && !self.on_llm_command(other)
                    && !self.on_yk_command(other)
                    && !self.on_hc_command(other)
                    && !self.on_wc_command(other)
                {
                    self.on_indexed_command(other);
                }
            }
        }
    }

    fn on_indexed_command(&mut self, id: u16) {
        use crate::ui::screens::ids;
        if let Some(index) = id
            .checked_sub(ids::NETWORK_BASE)
            .filter(|offset| *offset < ids::NETWORK_SPAN)
        {
            let chains = self.settings.registered_evm();
            if let Some(chain_id) = chains.get(usize::from(index)).copied() {
                let mut settings = self.settings.clone();
                settings.evm_chain_id = chain_id;
                self.save_settings(settings, "evmChainId");
            }
            return;
        }
        if let Some(offset) = id
            .checked_sub(ids::ACCOUNT_BASE)
            .filter(|offset| *offset < ids::ACCOUNT_SPAN)
        {
            self.select_account(usize::from(offset));
            return;
        }
        if let Some(offset) = id
            .checked_sub(ids::ROW_BASE)
            .filter(|offset| *offset < ids::ROW_SPAN)
        {
            let row = usize::from(offset / 3);
            let networks = self.url_networks();
            let Some(network) = networks.get(row).copied() else {
                return;
            };
            match offset % 3 {
                0 => {
                    self.replace_target = Some(network);
                    self.refresh();
                }
                1 => self.test_network(network),
                2 => {
                    if self.apikeys.remove(KeyName::Rpc(network)) && self.save_apikeys() {
                        logging::info("app", "rpc.url_deleted", &[("net", Field::Net(network))]);
                        self.network_url_changed(network);
                    }
                    self.rpc_messages.retain(|(id, _, _)| *id != network);
                    self.refresh();
                }
                _ => {}
            }
        }
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
                .evm_chain_name(id)
                .unwrap_or_else(|| format!("chainId {id}")),
            NetworkId::Solana(cluster) => crate::app_sol::core_cluster(cluster)
                .display_name()
                .to_owned(),
            NetworkId::Bitcoin(net) => crate::btc::core_network(net).display_name().to_owned(),
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
        let mut rows: Vec<_> = meta
            .evm_accounts
            .iter()
            .filter(|account| !account.hidden)
            .map(|account| {
                (
                    EvmAccountPref::Index(account.index),
                    account.label.clone(),
                    checksum(&account.address),
                    format!("m/44'/60'/0'/0/{}", account.index),
                )
            })
            .collect();
        rows.extend(meta.evm_raw_accounts.iter().map(|raw| {
            (
                EvmAccountPref::Record(raw.record_id),
                raw.label.clone(),
                checksum(&raw.address),
                "가져온 개인키".to_owned(),
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
                        format!("m/44'/60'/0'/0/{} (YubiKey)", account.index),
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
        }
        self.refresh();
    }

    fn save_rename(&mut self) {
        use crate::ui::screens::ids;
        let label = self.controls.text(ids::RENAME_EDIT, 64).unwrap_or_default();
        if !is_valid_label(&label) {
            self.info = Some(ErrorCode::Inp017.text());
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
            // A hidden YubiKey account comes back when a card with its key is enrolled again.
            account.hidden = true;
            let hidden = yw_core::evm::address::parse_address(&account.address).ok();
            meta.prefs.evm_account = EvmAccountPref::Index(0);
            self.save_meta();
            if let Some(address) = hidden {
                self.account_removed_from_sites(&address);
            }
            self.refresh();
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
            let hidden = yw_core::evm::address::parse_address(&account.address).ok();
            meta.prefs.evm_account = EvmAccountPref::Index(0);
            self.save_meta();
            if let Some(address) = hidden {
                self.account_removed_from_sites(&address);
            }
        }
        self.refresh();
    }

    fn save_autolock(&mut self) {
        use crate::ui::screens::ids;
        let text = self
            .controls
            .text(ids::AUTOLOCK_EDIT, 8)
            .unwrap_or_default();
        match text.trim().parse::<u8>() {
            Ok(minutes) if (1..=60).contains(&minutes) => {
                let mut settings = self.settings.clone();
                settings.auto_lock_minutes = minutes;
                self.info = Some(format!("자동 잠금을 {minutes}분으로 저장했습니다."));
                self.save_settings(settings, "autoLockMinutes");
            }
            _ => {
                self.info = Some("자동 잠금은 1–60분입니다.".to_owned());
                self.refresh();
            }
        }
    }

    fn read_wiping(&self, id: u16, max: usize) -> Zeroizing<String> {
        let units = self.controls.text_wiping(id, max);
        let mut out = Zeroizing::new(String::new());
        if let Some(units) = units {
            for unit in units.as_slice() {
                if let Some(character) = char::from_u32(u32::from(*unit)) {
                    out.push(character);
                }
            }
        }
        out
    }

    /// `저장` of the template credentials (spec/04 §2.11): E-KEY-002 with the item name.
    fn save_template_credentials(&mut self) -> Result<(), ErrorCode> {
        use crate::ui::screens::ids;
        match self.settings.rpc_template {
            RpcTemplate::QuickNode => {
                let name = self.read_wiping(ids::QN_NAME_EDIT, TOKEN_MAX_UNITS);
                let token = self.read_wiping(ids::QN_TOKEN_EDIT, TOKEN_MAX_UNITS);
                match quicknode_input(&name, &token) {
                    Ok(None) => return Ok(()),
                    Ok(Some((name, token))) => self.apikeys.set_quicknode(&name, &token),
                    Err(text) => {
                        self.info = Some(text);
                        return Err(ErrorCode::Key002);
                    }
                }
            }
            RpcTemplate::Alchemy => {
                let key = self.read_wiping(ids::ALCHEMY_KEY_EDIT, TOKEN_MAX_UNITS);
                if key.is_empty() {
                    return Ok(());
                }
                if !valid_provider_token(key.trim()) {
                    self.info = Some(key002_text("알케미 키"));
                    return Err(ErrorCode::Key002);
                }
                self.apikeys.set_alchemy(key.trim());
            }
            RpcTemplate::Manual => return Ok(()),
        }
        self.controls.clear_text(ids::QN_NAME_EDIT);
        self.controls.clear_text(ids::QN_TOKEN_EDIT);
        self.controls.clear_text(ids::ALCHEMY_KEY_EDIT);
        if self.save_apikeys() {
            logging::info(
                "app",
                "tpl.saved",
                &[("template", Field::Word(self.settings.rpc_template.as_str()))],
            );
            self.info = Some("템플릿 자격 정보를 저장했습니다.".to_owned());
        }
        Ok(())
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
            self.info = Some(format!("보관 항목 {removed}개를 지웠습니다."));
        }
    }

    fn delete_template_credentials(&mut self) {
        let name = match self.settings.rpc_template {
            RpcTemplate::QuickNode => KeyName::TplQuickNode,
            RpcTemplate::Alchemy => KeyName::TplAlchemy,
            RpcTemplate::Manual => return,
        };
        if self.apikeys.remove(name) && self.save_apikeys() {
            logging::info(
                "app",
                "tpl.deleted",
                &[("template", Field::Word(self.settings.rpc_template.as_str()))],
            );
        }
        self.refresh();
    }

    /// Generation targets and skipped networks for the current template.
    #[must_use]
    pub fn generation_plan(&self) -> (Vec<NetworkId>, Vec<NetworkId>) {
        let template = self.settings.rpc_template;
        self.url_networks()
            .into_iter()
            .partition(|network| template_entry(template, *network, &self.settings).is_some())
    }

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
            self.info = Some(ErrorCode::Key004.text());
            self.refresh();
            return;
        }
        self.overwrite_checked = false;
        self.set_screen(Screen::Confirm(Confirm::Generate));
    }

    fn generate(&mut self) {
        let template = self.settings.rpc_template;
        let Some(credential) = self.apikeys.credential(template) else {
            self.info = Some(ErrorCode::Key004.text());
            return;
        };
        let (targets, skipped) = self.generation_plan();
        let written = self.apikeys.generate_urls(
            template,
            &credential,
            &self.settings,
            &targets,
            self.overwrite_checked,
        );
        drop(credential);
        if self.save_apikeys() {
            for network in &written {
                logging::info("app", "rpc.generated", &[("net", Field::Net(*network))]);
                self.rpc_messages.retain(|(id, _, _)| id != network);
                self.network_url_changed(*network);
            }
            let skipped_names: Vec<String> = skipped
                .iter()
                .map(|network| self.network_name(*network))
                .collect();
            self.info = Some(format!(
                "RPC URL {}개를 만들었습니다. 템플릿 항목이 없는 네트워크 {}개는 직접 입력하세요: {}",
                written.len(),
                skipped.len(),
                if skipped_names.is_empty() {
                    "없음".to_owned()
                } else {
                    skipped_names.join(", ")
                }
            ));
        }
    }

    fn save_replacement(&mut self) {
        use crate::ui::screens::ids;
        let Some(network) = self.replace_target else {
            return;
        };
        let text = self.read_wiping(ids::REPLACE_EDIT, URL_MAX_UNITS);
        match HttpsUrl::parse(text.trim()) {
            Ok(url) => {
                self.apikeys.set_rpc(network, &url);
                if self.save_apikeys() {
                    logging::info("app", "rpc.url_set", &[("net", Field::Net(network))]);
                    self.rpc_messages.retain(|(id, _, _)| *id != network);
                    self.network_url_changed(network);
                }
                self.controls.clear_text(ids::REPLACE_EDIT);
                self.replace_target = None;
            }
            Err(_) => self.set_rpc_message(network, ErrorCode::Key003.text(), false),
        }
        self.refresh();
    }

    fn set_rpc_message(&mut self, network: NetworkId, message: String, ok: bool) {
        self.rpc_messages.retain(|(id, _, _)| *id != network);
        self.rpc_messages.push((network, message, ok));
    }

    fn test_network(&mut self, network: NetworkId) {
        use crate::ui::screens::ids;
        let typed = if self.replace_target == Some(network) {
            self.read_wiping(ids::REPLACE_EDIT, URL_MAX_UNITS)
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
                self.set_rpc_message(network, code.text(), false);
                self.refresh();
                return;
            }
        };
        let name = self.network_name(network);
        if let Some(tx) = self.rpc_tx.as_ref()
            && tx.send(RpcJob::Test { network, name, url }).is_ok()
        {
            self.set_rpc_message(network, "테스트 중…".to_owned(), false);
        }
        self.refresh();
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
                self.screen = previous;
                self.save_settings(settings, "allowSecretCopy");
            }
            Confirm::LocalhostOn => {
                let mut settings = self.settings.clone();
                settings.allow_localhost_dapps = true;
                self.screen = previous;
                self.save_settings(settings, "allowLocalhostDapps");
            }
            Confirm::DisconnectAll => {
                self.disconnect_all_sites();
                self.set_screen(Screen::Sites);
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
                        self.info = Some(
                            "YubiKey 계정의 개인키는 YubiKey 밖으로 나오지 않습니다. 백업은 등록할 때 쓴 복구 단어입니다."
                                .to_owned(),
                        );
                        self.refresh();
                        return;
                    }
                    Some(EvmAccountPref::Record(id)) => EvmKeySource::Raw(RecordId::from_bytes(id)),
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
                self.generate();
                self.set_screen(previous);
            }
            Confirm::PruneDormant => {
                self.prune_dormant();
                self.set_screen(previous);
            }
            Confirm::SidecarCorrupt => {}
            Confirm::JournalCorrupt => {
                self.set_screen(Screen::Main);
                self.key(KeyJob::ResolveSidecar {
                    kind: FileKind::Journal,
                    use_prev: false,
                });
            }
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
                self.set_screen(Screen::Settings(SettingsSection::Chains));
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

/// Hooks for the screenshot tour (`ui::tour`, an `#[ignore]` test). Gated like the tour module
/// (`#[cfg(test)]` + `#[cfg(debug_assertions)]`), so `cargo test --release` has no dead code.
#[cfg(test)]
#[cfg(debug_assertions)]
impl App {
    /// The open secret window.
    pub(crate) fn tour_secret_window(&self) -> Option<&Window> {
        self.secret.as_ref().map(|secret| &secret.window)
    }

    /// Opens a display window (W08/W09) with a non-secret tour value.
    pub(crate) fn tour_open_display(
        &mut self,
        kind: SecretKind,
        purpose: Purpose,
        display: DisplaySecret,
    ) {
        self.open_display(kind, purpose, display);
    }

    /// Types `text` into the open secret window's active field (tour values only).
    pub(crate) fn tour_type(&mut self, text: &str) {
        let now = now_ms();
        if let Some(secret) = self.secret.as_mut() {
            for unit in text.encode_utf16() {
                let _ = secret.form.on_char(unit, now);
            }
            secret.window.invalidate();
        }
    }

    /// Moves to the next field of the open secret window (Tab).
    pub(crate) fn tour_next_field(&mut self) {
        let now = now_ms();
        if let Some(secret) = self.secret.as_mut() {
            let _ = secret.form.on_key(0x09, false, false, false, now);
            secret.window.invalidate();
        }
    }
}

#[cfg(test)]
mod tests;
