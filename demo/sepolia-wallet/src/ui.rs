//! Korean native UI for the standalone Sepolia-only development wallet.
//!
//! This module owns no cryptographic or RPC implementation. Potentially slow
//! work is sent to one backend worker so Argon2 and network calls cannot freeze
//! the `egui` event loop.

use std::sync::mpsc::{self, Receiver, Sender, TryRecvError};
use std::time::{Duration, Instant};

use eframe::egui::{self, Color32, RichText};
use zeroize::{Zeroize, Zeroizing};

const MINIMUM_PASSWORD_BYTES: usize = 12;
const SEND_HOLD_DURATION: Duration = Duration::from_secs(2);
const SECRET_REVEAL_DURATION: Duration = Duration::from_secs(20);

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct StatusPalette {
    warning: Color32,
    error: Color32,
    success: Color32,
    muted: Color32,
}

impl StatusPalette {
    fn from_visuals(visuals: &egui::Visuals) -> Self {
        if visuals.dark_mode {
            Self {
                warning: Color32::from_rgb(255, 209, 102),
                error: Color32::from_rgb(255, 138, 128),
                success: Color32::from_rgb(126, 231, 135),
                muted: Color32::from_rgb(184, 189, 199),
            }
        } else {
            Self {
                warning: Color32::from_rgb(122, 75, 0),
                error: Color32::from_rgb(180, 35, 24),
                success: Color32::from_rgb(20, 108, 46),
                muted: Color32::from_rgb(85, 91, 102),
            }
        }
    }
}

/// Public values the backend may return after creating, opening, or refreshing.
///
/// Deliberately does not implement `Debug`: full wallet addresses must not
/// accidentally enter logs or crash diagnostics.
#[derive(Clone, Eq, PartialEq)]
pub struct WalletSnapshot {
    /// Full checksummed or lowercase hexadecimal Sepolia account address.
    pub address: String,
    /// Human-readable Sepolia ETH balance without a ticker suffix.
    pub balance_eth: String,
    /// Authenticated local vault/source category.
    pub wallet_kind: WalletKind,
    /// Number of account metadata records validated by the backend.
    pub account_count: u8,
}

/// Non-secret source/format metadata for the currently unlocked wallet.
#[derive(Clone, Copy, Eq, PartialEq)]
pub enum WalletKind {
    /// Legacy v1 vault containing one raw private key.
    LegacyV1RawPrivateKey,
    /// V2 wallet backed by an English recovery phrase.
    V2Mnemonic { word_count: u8 },
    /// V2 wallet backed by one imported raw private key.
    V2RawPrivateKey,
}

/// Supported recovery-phrase sizes for newly generated wallets.
#[derive(Clone, Copy, Default, Eq, PartialEq)]
pub enum NewMnemonicWords {
    /// Twelve English words.
    #[default]
    Twelve,
    /// Twenty-four English words.
    TwentyFour,
}

/// Category of a secret that may be revealed exactly once in the UI.
#[derive(Clone, Copy, Eq, PartialEq)]
pub enum SecretRevealKind {
    /// English BIP-39 recovery phrase.
    Mnemonic,
    /// Lowercase hexadecimal account-0 private key.
    AccountPrivateKey,
}

/// Owned secret input crossing the worker boundary without a plain-text
/// `Debug` or `Clone` implementation.
pub struct SensitiveText(Zeroizing<String>);

impl SensitiveText {
    #[must_use]
    pub(crate) fn new(value: String) -> Self {
        Self(Zeroizing::new(value))
    }

    pub(crate) fn into_zeroizing(self) -> Zeroizing<String> {
        self.0
    }
}

/// One-shot, zeroizing secret returned by the backend.
///
/// Deliberately has neither `Clone` nor `Debug`; it can only be moved into the
/// short-lived reveal state.
pub struct SecretReveal {
    kind: SecretRevealKind,
    text: Zeroizing<String>,
}

impl SecretReveal {
    #[must_use]
    pub(crate) const fn new(kind: SecretRevealKind, text: Zeroizing<String>) -> Self {
        Self { kind, text }
    }

    #[must_use]
    const fn kind(&self) -> SecretRevealKind {
        self.kind
    }

    #[must_use]
    fn expose_secret(&self) -> &str {
        self.text.as_str()
    }
}

/// Result of one accepted Sepolia broadcast.
///
/// Deliberately does not implement `Debug` because transaction hashes are not
/// needed in diagnostics.
#[derive(Clone, Eq, PartialEq)]
pub struct SendReceipt {
    /// Transaction hash returned only after the backend verifies it.
    pub transaction_hash: String,
}

/// Fee policy selected before a transfer preview is prepared.
///
/// Custom strings are untrusted UI input. The backend parses them with exact
/// integer arithmetic and freezes only normalized wei values.
#[derive(Clone, Eq, PartialEq)]
pub enum FeeSelection {
    /// Use the Sepolia node's recommended EIP-1559 priority fee.
    Recommended,
    /// Raise the recommended priority fee within the demo safety caps.
    Faster,
    /// Use explicit EIP-1559 fee caps entered in gwei.
    Custom {
        /// Maximum priority fee per gas in decimal gwei.
        max_priority_fee_per_gas_gwei: String,
        /// Maximum total fee per gas in decimal gwei.
        max_fee_per_gas_gwei: String,
    },
}

/// Exact backend-normalized transfer values shown before any signing occurs.
///
/// This deliberately has no `Debug` implementation because it contains full
/// public transaction metadata that is unnecessary in diagnostics.
#[derive(Clone, Eq, PartialEq)]
pub struct TransferPreview {
    /// Exact normalized recipient.
    pub recipient: String,
    /// Exact normalized native value in Sepolia ETH.
    pub amount_eth: String,
    /// Exact pending nonce as an unsigned decimal integer.
    pub nonce: String,
    /// Korean label for the backend-normalized fee selection.
    pub fee_mode_ko: String,
    /// Fixed gas limit for this native transfer.
    pub gas_limit: String,
    /// Base fee observed when the quote was prepared, in gwei.
    pub quoted_base_fee_per_gas_gwei: String,
    /// Maximum priority fee per gas in gwei.
    pub max_priority_fee_per_gas_gwei: String,
    /// Maximum total fee per gas in gwei.
    pub max_fee_per_gas_gwei: String,
    /// Network fee estimated from the observed base fee, in ETH.
    pub estimated_network_fee_eth: String,
    /// Maximum network fee for the fixed native transfer gas limit, in ETH.
    pub max_network_fee_eth: String,
    /// Maximum value plus network fee, in ETH.
    pub max_total_eth: String,
    /// Value plus the network fee estimated at preparation time, in ETH.
    pub estimated_total_eth: String,
    /// Conservative whole seconds remaining when backend preparation ended.
    pub quote_valid_for_seconds: String,
}

/// Secret/network backend used by the standalone testnet demo.
///
/// Implementations must return only short, category-level Korean errors. They
/// must never place passwords, recovery phrases, keys, addresses, raw
/// transactions, RPC URLs, or raw server responses in an error string.
pub trait WalletBackend: Send + 'static {
    /// Generate a mnemonic wallet in memory and return its one-shot backup.
    /// No vault may be written until `confirm_generated_wallet` is called.
    fn begin_generate_wallet(
        &mut self,
        words: NewMnemonicWords,
        password: SensitiveText,
        password_confirmation: SensitiveText,
    ) -> Result<SecretReveal, String> {
        let _ = (words, password, password_confirmation);
        Err("지갑 관리 기능을 사용할 수 없습니다.".to_owned())
    }

    /// Persist the exact pending generated wallet after the UI's continuous
    /// two-second backup-confirmation hold.
    fn confirm_generated_wallet(&mut self) -> Result<WalletSnapshot, String> {
        Err("지갑 관리 기능을 사용할 수 없습니다.".to_owned())
    }

    /// Forget an unconfirmed generated wallet without writing it.
    fn cancel_generated_wallet(&mut self) -> Result<(), String> {
        Err("지갑 관리 기능을 사용할 수 없습니다.".to_owned())
    }

    /// Import and persist an already-backed-up English recovery phrase.
    fn import_mnemonic_wallet(
        &mut self,
        mnemonic: SensitiveText,
        password: SensitiveText,
        password_confirmation: SensitiveText,
    ) -> Result<WalletSnapshot, String> {
        let _ = (mnemonic, password, password_confirmation);
        Err("지갑 관리 기능을 사용할 수 없습니다.".to_owned())
    }

    /// Import and persist one raw Ethereum private key.
    fn import_private_key_wallet(
        &mut self,
        private_key: SensitiveText,
        password: SensitiveText,
        password_confirmation: SensitiveText,
    ) -> Result<WalletSnapshot, String> {
        let _ = (private_key, password, password_confirmation);
        Err("지갑 관리 기능을 사용할 수 없습니다.".to_owned())
    }

    /// Open the existing local v2 vault, or a legacy v1 vault when no v2 file
    /// exists. A failing v2 open never falls back to v1.
    fn open_wallet(&mut self, password: &str) -> Result<WalletSnapshot, String>;

    /// Reauthenticate a v1 raw-key vault and migrate it to v2 without changing
    /// account 0.
    fn migrate_legacy_wallet(
        &mut self,
        old_password: SensitiveText,
        new_password: SensitiveText,
        new_password_confirmation: SensitiveText,
    ) -> Result<WalletSnapshot, String> {
        let _ = (old_password, new_password, new_password_confirmation);
        Err("지갑 관리 기능을 사용할 수 없습니다.".to_owned())
    }

    /// Reauthenticate and return a one-shot mnemonic reveal. Raw-key and v1
    /// wallets must reject this operation categorically.
    fn export_mnemonic(&mut self, password: SensitiveText) -> Result<SecretReveal, String> {
        let _ = password;
        Err("지갑 관리 기능을 사용할 수 없습니다.".to_owned())
    }

    /// Reauthenticate and return only account 0's private key.
    fn export_account_private_key(
        &mut self,
        password: SensitiveText,
    ) -> Result<SecretReveal, String> {
        let _ = password;
        Err("지갑 관리 기능을 사용할 수 없습니다.".to_owned())
    }

    /// Refresh the selected public address and Sepolia ETH balance.
    fn refresh(&mut self) -> Result<WalletSnapshot, String>;

    /// Validate inputs and freeze exact Sepolia transfer facts without signing.
    fn prepare_transfer(
        &mut self,
        recipient: &str,
        amount_eth: &str,
        fee_selection: FeeSelection,
    ) -> Result<TransferPreview, String>;

    /// Sign and submit only the currently prepared transfer.
    fn confirm_prepared(&mut self) -> Result<SendReceipt, String>;

    /// Invalidate the currently prepared transfer without signing.
    fn cancel_prepared(&mut self) -> Result<(), String>;

    /// Retry only the exact signed transaction durably retained after an
    /// ambiguous prior broadcast. This must never create a fresh signature.
    fn retry_pending(&mut self) -> Result<SendReceipt, String>;
}

/// Prefer the Windows Korean system font so Hangul does not render as boxes.
///
/// Failure is intentionally silent and path-free; `egui` keeps its bundled
/// fallback fonts if the system font cannot be read.
pub fn install_korean_font(context: &egui::Context) {
    let Some(windows_directory) = std::env::var_os("WINDIR") else {
        return;
    };
    let fonts_directory = std::path::PathBuf::from(windows_directory).join("Fonts");
    let font_bytes = ["malgun.ttf", "malgunsl.ttf"]
        .into_iter()
        .find_map(|name| std::fs::read(fonts_directory.join(name)).ok());
    let Some(font_bytes) = font_bytes else {
        return;
    };

    let mut definitions = egui::FontDefinitions::default();
    definitions.font_data.insert(
        "your-wallet-korean".to_owned(),
        egui::FontData::from_owned(font_bytes).into(),
    );
    for family in [egui::FontFamily::Proportional, egui::FontFamily::Monospace] {
        definitions
            .families
            .entry(family)
            .or_default()
            .insert(0, "your-wallet-korean".to_owned());
    }
    context.set_fonts(definitions);
}

enum WorkerCommand {
    BeginGenerate {
        words: NewMnemonicWords,
        password: SensitiveText,
        password_confirmation: SensitiveText,
    },
    ConfirmGenerated,
    CancelGenerated,
    ImportMnemonic {
        mnemonic: SensitiveText,
        password: SensitiveText,
        password_confirmation: SensitiveText,
    },
    ImportPrivateKey {
        private_key: SensitiveText,
        password: SensitiveText,
        password_confirmation: SensitiveText,
    },
    Open {
        password: Zeroizing<String>,
    },
    MigrateLegacy {
        old_password: SensitiveText,
        new_password: SensitiveText,
        new_password_confirmation: SensitiveText,
    },
    ExportMnemonic {
        password: SensitiveText,
    },
    ExportAccountPrivateKey {
        password: SensitiveText,
    },
    Refresh,
    PrepareTransfer {
        recipient: String,
        amount_eth: String,
        fee_selection: FeeSelection,
    },
    ConfirmPrepared,
    CancelPrepared,
    RetryPending,
}

enum WorkerEvent {
    GenerationBegun(Result<SecretReveal, String>),
    GeneratedConfirmed(Result<WalletSnapshot, String>),
    GeneratedCancelled(Result<(), String>),
    MnemonicImported(Result<WalletSnapshot, String>),
    PrivateKeyImported(Result<WalletSnapshot, String>),
    Opened(Result<WalletSnapshot, String>),
    LegacyMigrated(Result<WalletSnapshot, String>),
    MnemonicExported(Result<SecretReveal, String>),
    AccountPrivateKeyExported(Result<SecretReveal, String>),
    Refreshed(Result<WalletSnapshot, String>),
    TransferPrepared(Box<Result<TransferPreview, String>>),
    PreparedConfirmed(Result<SendReceipt, String>),
    PreparedCancelled(Result<(), String>),
    Retried(Result<SendReceipt, String>),
}

#[derive(Clone, Copy, Eq, PartialEq)]
enum PendingAction {
    BeginGenerate,
    ConfirmGenerated,
    CancelGenerated,
    ImportMnemonic,
    ImportPrivateKey,
    Open,
    MigrateLegacy,
    ExportMnemonic,
    ExportAccountPrivateKey,
    Refresh,
    PrepareTransfer,
    ConfirmPrepared,
    CancelPrepared,
    RetryPending,
}

#[derive(Clone, Copy, Default, Eq, PartialEq)]
enum FeeMode {
    #[default]
    Recommended,
    Faster,
    Custom,
}

#[derive(Clone, Copy, Default, Eq, PartialEq)]
enum SetupMode {
    #[default]
    Open,
    Generate,
    ImportMnemonic,
    ImportPrivateKey,
    MigrateLegacy,
}

#[derive(Clone, Copy, Eq, PartialEq)]
enum SecretHoldAction {
    ConfirmGeneratedBackup,
    ExportMnemonic,
    ExportAccountPrivateKey,
}

#[derive(Clone, Copy, Eq, PartialEq)]
enum RevealPurpose {
    GeneratedBackup,
    ReauthenticatedExport,
}

struct TimedSecretReveal {
    reveal: SecretReveal,
    purpose: RevealPurpose,
    expires_at: Instant,
}

impl TimedSecretReveal {
    fn new(reveal: SecretReveal, purpose: RevealPurpose, now: Instant) -> Option<Self> {
        Some(Self {
            reveal,
            purpose,
            expires_at: now.checked_add(SECRET_REVEAL_DURATION)?,
        })
    }

    fn is_expired(&self, now: Instant) -> bool {
        now >= self.expires_at
    }

    fn remaining_seconds(&self, now: Instant) -> u64 {
        self.expires_at.saturating_duration_since(now).as_secs()
    }
}

impl PendingAction {
    const fn korean(self) -> &'static str {
        match self {
            Self::BeginGenerate => "새 복구 문구를 안전하게 만드는 중...",
            Self::ConfirmGenerated => "백업 확인된 v2 지갑을 저장하는 중...",
            Self::CancelGenerated => "저장 전 복구 문구를 지우는 중...",
            Self::ImportMnemonic => "복구 문구를 검증하고 v2 지갑을 저장하는 중...",
            Self::ImportPrivateKey => "개인 키를 검증하고 v2 지갑을 저장하는 중...",
            Self::Open => "테스트 지갑을 여는 중...",
            Self::MigrateLegacy => "v1 개인 키 지갑을 v2로 이전하는 중...",
            Self::ExportMnemonic => "비밀번호를 확인하고 복구 문구를 준비하는 중...",
            Self::ExportAccountPrivateKey => "비밀번호를 확인하고 계정 키를 준비하는 중...",
            Self::Refresh => "Sepolia 잔액을 확인하는 중...",
            Self::PrepareTransfer => "nonce와 최대 수수료를 확인하는 중...",
            Self::ConfirmPrepared => "확인한 테스트 전송을 서명하고 제출하는 중...",
            Self::CancelPrepared => "준비된 전송을 취소하는 중...",
            Self::RetryPending => "저장된 이전 거래를 그대로 다시 전송하는 중...",
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum HoldOutcome {
    Idle,
    Holding(Duration),
    Triggered,
}

#[derive(Clone, Copy)]
struct HoldInput {
    enabled: bool,
    primary_pressed_on_button: bool,
    primary_down: bool,
    pointer_inside: bool,
    focused: bool,
    escape_pressed: bool,
}

#[derive(Default)]
struct HoldToSend {
    started_at: Option<Instant>,
    fired: bool,
    release_required: bool,
}

impl HoldToSend {
    fn update(&mut self, now: Instant, input: HoldInput) -> HoldOutcome {
        if !input.primary_down {
            self.reset();
            return HoldOutcome::Idle;
        }

        if self.release_required {
            return HoldOutcome::Idle;
        }

        if !input.enabled || !input.focused || input.escape_pressed {
            self.cancel_current_press();
            return HoldOutcome::Idle;
        }

        if self.started_at.is_some() && !input.pointer_inside {
            self.cancel_current_press();
            return HoldOutcome::Idle;
        }

        let started_at = if let Some(started_at) = self.started_at {
            started_at
        } else if input.primary_pressed_on_button && input.pointer_inside {
            self.started_at = Some(now);
            now
        } else {
            self.cancel_current_press();
            return HoldOutcome::Idle;
        };
        let elapsed = now.saturating_duration_since(started_at);
        if elapsed >= SEND_HOLD_DURATION && !self.fired {
            self.fired = true;
            return HoldOutcome::Triggered;
        }
        HoldOutcome::Holding(elapsed.min(SEND_HOLD_DURATION))
    }

    fn reset(&mut self) {
        self.started_at = None;
        self.fired = false;
        self.release_required = false;
    }

    fn cancel_current_press(&mut self) {
        self.started_at = None;
        self.fired = false;
        self.release_required = true;
    }

    fn fraction(&self, now: Instant) -> f32 {
        self.started_at.map_or(0.0, |started_at| {
            (now.saturating_duration_since(started_at).as_secs_f32()
                / SEND_HOLD_DURATION.as_secs_f32())
            .clamp(0.0, 1.0)
        })
    }
}

/// Standalone Sepolia development-wallet application.
pub struct WalletApp {
    commands: Option<Sender<WorkerCommand>>,
    events: Receiver<WorkerEvent>,
    setup_mode: SetupMode,
    mnemonic_words: NewMnemonicWords,
    export_kind: SecretRevealKind,
    password: String,
    password_confirmation: String,
    old_password: String,
    imported_secret: String,
    password_visible: bool,
    imported_secret_visible: bool,
    reauth_password: String,
    snapshot: Option<WalletSnapshot>,
    recipient: String,
    amount_eth: String,
    fee_mode: FeeMode,
    custom_priority_fee_gwei: String,
    custom_max_fee_gwei: String,
    prepared: Option<TransferPreview>,
    pending: Option<PendingAction>,
    hold: HoldToSend,
    secret_hold: HoldToSend,
    secret_reveal: Option<TimedSecretReveal>,
    notice: Option<String>,
    error: Option<String>,
    last_transaction_hash: Option<String>,
}

impl WalletApp {
    /// Start the UI and move the backend into its dedicated worker thread.
    #[must_use]
    pub fn new(backend: Box<dyn WalletBackend>) -> Self {
        let (command_sender, command_receiver) = mpsc::channel();
        let (event_sender, event_receiver) = mpsc::channel();
        spawn_worker(backend, command_receiver, event_sender);
        Self {
            commands: Some(command_sender),
            events: event_receiver,
            setup_mode: SetupMode::Open,
            mnemonic_words: NewMnemonicWords::Twelve,
            export_kind: SecretRevealKind::Mnemonic,
            password: String::new(),
            password_confirmation: String::new(),
            old_password: String::new(),
            imported_secret: String::new(),
            password_visible: false,
            imported_secret_visible: false,
            reauth_password: String::new(),
            snapshot: None,
            recipient: String::new(),
            amount_eth: String::new(),
            fee_mode: FeeMode::Recommended,
            custom_priority_fee_gwei: String::new(),
            custom_max_fee_gwei: String::new(),
            prepared: None,
            pending: None,
            hold: HoldToSend::default(),
            secret_hold: HoldToSend::default(),
            secret_reveal: None,
            notice: None,
            error: None,
            last_transaction_hash: None,
        }
    }

    /// Build a visible fail-closed screen when backend initialization failed.
    #[must_use]
    pub fn unavailable(message: impl Into<String>) -> Self {
        let (_sender, receiver) = mpsc::channel();
        Self {
            commands: None,
            events: receiver,
            setup_mode: SetupMode::Open,
            mnemonic_words: NewMnemonicWords::Twelve,
            export_kind: SecretRevealKind::Mnemonic,
            password: String::new(),
            password_confirmation: String::new(),
            old_password: String::new(),
            imported_secret: String::new(),
            password_visible: false,
            imported_secret_visible: false,
            reauth_password: String::new(),
            snapshot: None,
            recipient: String::new(),
            amount_eth: String::new(),
            fee_mode: FeeMode::Recommended,
            custom_priority_fee_gwei: String::new(),
            custom_max_fee_gwei: String::new(),
            prepared: None,
            pending: None,
            hold: HoldToSend::default(),
            secret_hold: HoldToSend::default(),
            secret_reveal: None,
            notice: None,
            error: Some(safe_error(message.into())),
            last_transaction_hash: None,
        }
    }

    fn send_command(&mut self, command: WorkerCommand, action: PendingAction) {
        self.error = None;
        self.notice = None;
        let accepted = self
            .commands
            .as_ref()
            .is_some_and(|sender| sender.send(command).is_ok());
        if accepted {
            self.pending = Some(action);
        } else {
            self.pending = None;
            self.error =
                Some("지갑 백엔드를 사용할 수 없습니다. 앱을 다시 실행해 주세요.".to_owned());
        }
    }

    fn begin_generate_wallet(&mut self) {
        if !valid_password(&self.password) || !valid_password(&self.password_confirmation) {
            self.error = Some("비밀번호는 UTF-8 기준 12바이트 이상 입력해 주세요.".to_owned());
            return;
        }
        if self.password != self.password_confirmation {
            self.error = Some("새 비밀번호 확인이 일치하지 않습니다.".to_owned());
            return;
        }
        let password = SensitiveText::new(std::mem::take(&mut self.password));
        let password_confirmation =
            SensitiveText::new(std::mem::take(&mut self.password_confirmation));
        self.send_command(
            WorkerCommand::BeginGenerate {
                words: self.mnemonic_words,
                password,
                password_confirmation,
            },
            PendingAction::BeginGenerate,
        );
    }

    fn confirm_generated_wallet(&mut self) {
        self.secret_reveal = None;
        self.secret_hold.reset();
        self.send_command(
            WorkerCommand::ConfirmGenerated,
            PendingAction::ConfirmGenerated,
        );
    }

    fn cancel_generated_wallet(&mut self) {
        self.secret_reveal = None;
        self.secret_hold.reset();
        self.send_command(
            WorkerCommand::CancelGenerated,
            PendingAction::CancelGenerated,
        );
    }

    fn import_wallet(&mut self, mnemonic: bool) {
        if self.imported_secret.trim().is_empty()
            || !valid_password(&self.password)
            || !valid_password(&self.password_confirmation)
        {
            self.error =
                Some("가져올 비밀값과 12바이트 이상의 새 비밀번호를 확인해 주세요.".to_owned());
            return;
        }
        if self.password != self.password_confirmation {
            self.error = Some("새 비밀번호 확인이 일치하지 않습니다.".to_owned());
            return;
        }
        let secret = SensitiveText::new(std::mem::take(&mut self.imported_secret));
        let password = SensitiveText::new(std::mem::take(&mut self.password));
        let password_confirmation =
            SensitiveText::new(std::mem::take(&mut self.password_confirmation));
        let (command, action) = if mnemonic {
            (
                WorkerCommand::ImportMnemonic {
                    mnemonic: secret,
                    password,
                    password_confirmation,
                },
                PendingAction::ImportMnemonic,
            )
        } else {
            (
                WorkerCommand::ImportPrivateKey {
                    private_key: secret,
                    password,
                    password_confirmation,
                },
                PendingAction::ImportPrivateKey,
            )
        };
        self.send_command(command, action);
    }

    fn open_wallet(&mut self) {
        if !valid_password(&self.password) {
            self.error = Some("비밀번호는 UTF-8 기준 12바이트 이상 입력해 주세요.".to_owned());
            return;
        }
        let password = Zeroizing::new(std::mem::take(&mut self.password));
        self.send_command(WorkerCommand::Open { password }, PendingAction::Open);
    }

    fn migrate_legacy_wallet(&mut self) {
        if !valid_password(&self.old_password)
            || !valid_password(&self.password)
            || !valid_password(&self.password_confirmation)
        {
            self.error =
                Some("이전 비밀번호와 12바이트 이상의 새 비밀번호를 확인해 주세요.".to_owned());
            return;
        }
        if self.password != self.password_confirmation {
            self.error = Some("새 비밀번호 확인이 일치하지 않습니다.".to_owned());
            return;
        }
        let old_password = SensitiveText::new(std::mem::take(&mut self.old_password));
        let new_password = SensitiveText::new(std::mem::take(&mut self.password));
        let new_password_confirmation =
            SensitiveText::new(std::mem::take(&mut self.password_confirmation));
        self.send_command(
            WorkerCommand::MigrateLegacy {
                old_password,
                new_password,
                new_password_confirmation,
            },
            PendingAction::MigrateLegacy,
        );
    }

    fn export_secret(&mut self, action: SecretHoldAction) {
        if !valid_password(&self.reauth_password) {
            self.error = Some("내보내려면 현재 비밀번호를 다시 입력해 주세요.".to_owned());
            self.secret_hold.reset();
            return;
        }
        let password = SensitiveText::new(std::mem::take(&mut self.reauth_password));
        let (command, pending) = match action {
            SecretHoldAction::ExportMnemonic => (
                WorkerCommand::ExportMnemonic { password },
                PendingAction::ExportMnemonic,
            ),
            SecretHoldAction::ExportAccountPrivateKey => (
                WorkerCommand::ExportAccountPrivateKey { password },
                PendingAction::ExportAccountPrivateKey,
            ),
            SecretHoldAction::ConfirmGeneratedBackup => return,
        };
        self.secret_hold.reset();
        self.send_command(command, pending);
    }

    fn handle_secret_hold_outcome(
        &mut self,
        outcome: HoldOutcome,
        action: SecretHoldAction,
    ) -> bool {
        if !matches!(outcome, HoldOutcome::Triggered) || self.pending.is_some() {
            return false;
        }
        match action {
            SecretHoldAction::ConfirmGeneratedBackup => {
                let valid_backup = self.secret_reveal.as_ref().is_some_and(|reveal| {
                    reveal.purpose == RevealPurpose::GeneratedBackup
                        && !reveal.is_expired(Instant::now())
                });
                if !valid_backup {
                    return false;
                }
                self.confirm_generated_wallet();
                self.pending == Some(PendingAction::ConfirmGenerated)
            }
            SecretHoldAction::ExportMnemonic | SecretHoldAction::ExportAccountPrivateKey => {
                if self.prepared.is_some() || self.secret_reveal.is_some() {
                    return false;
                }
                self.export_secret(action);
                self.pending.is_some()
            }
        }
    }

    fn expire_secret_reveal(&mut self, now: Instant) {
        let expired_purpose = self
            .secret_reveal
            .as_ref()
            .filter(|reveal| reveal.is_expired(now))
            .map(|reveal| reveal.purpose);
        if let Some(purpose) = expired_purpose {
            self.secret_reveal = None;
            self.secret_hold.reset();
            if purpose == RevealPurpose::GeneratedBackup && self.pending.is_none() {
                self.send_command(
                    WorkerCommand::CancelGenerated,
                    PendingAction::CancelGenerated,
                );
            } else {
                self.notice = Some("비밀값 표시 시간이 끝나 메모리에서 지웠습니다.".to_owned());
            }
        }
    }

    fn refresh(&mut self) {
        self.send_command(WorkerCommand::Refresh, PendingAction::Refresh);
    }

    fn prepare_transfer(&mut self) {
        let recipient = self.recipient.trim().to_owned();
        let amount_eth = self.amount_eth.trim().to_owned();
        let fee_selection = match self.fee_mode {
            FeeMode::Recommended => FeeSelection::Recommended,
            FeeMode::Faster => FeeSelection::Faster,
            FeeMode::Custom => FeeSelection::Custom {
                max_priority_fee_per_gas_gwei: self.custom_priority_fee_gwei.clone(),
                max_fee_per_gas_gwei: self.custom_max_fee_gwei.clone(),
            },
        };
        self.hold.reset();
        self.send_command(
            WorkerCommand::PrepareTransfer {
                recipient,
                amount_eth,
                fee_selection,
            },
            PendingAction::PrepareTransfer,
        );
    }

    fn confirm_prepared(&mut self) {
        if self.prepared.is_none() {
            self.error = Some("먼저 전송 내용을 준비해 주세요.".to_owned());
            self.hold.reset();
            return;
        }
        self.hold.reset();
        self.send_command(
            WorkerCommand::ConfirmPrepared,
            PendingAction::ConfirmPrepared,
        );
    }

    fn handle_hold_outcome(&mut self, outcome: HoldOutcome) -> bool {
        if !matches!(outcome, HoldOutcome::Triggered)
            || !confirmation_enabled(self.prepared.as_ref(), self.pending)
        {
            return false;
        }
        self.confirm_prepared();
        self.pending == Some(PendingAction::ConfirmPrepared)
    }

    fn cancel_prepared(&mut self) {
        if self.prepared.is_none() {
            return;
        }
        self.hold.reset();
        self.send_command(WorkerCommand::CancelPrepared, PendingAction::CancelPrepared);
    }

    fn retry_pending(&mut self) {
        self.hold.reset();
        self.send_command(WorkerCommand::RetryPending, PendingAction::RetryPending);
    }

    fn process_events(&mut self) {
        loop {
            let event = match self.events.try_recv() {
                Ok(event) => event,
                Err(TryRecvError::Empty) => break,
                Err(TryRecvError::Disconnected) => {
                    if self.commands.is_some() && self.pending.is_some() {
                        self.pending = None;
                        self.commands = None;
                        self.error = Some(
                            "지갑 백엔드가 중단되었습니다. 앱을 다시 실행해 주세요.".to_owned(),
                        );
                    }
                    break;
                }
            };
            self.apply_worker_event(event);
        }
    }

    fn apply_worker_event(&mut self, event: WorkerEvent) {
        self.pending = None;
        match event {
            WorkerEvent::GenerationBegun(result) => match result {
                Ok(reveal) => {
                    self.secret_reveal = TimedSecretReveal::new(
                        reveal,
                        RevealPurpose::GeneratedBackup,
                        Instant::now(),
                    );
                    self.secret_hold.reset();
                    self.notice = Some(
                        "복구 문구는 아직 저장되지 않았습니다. 적어 둔 뒤 2초 확인을 완료하세요."
                            .to_owned(),
                    );
                }
                Err(error) => self.error = Some(safe_error(error)),
            },
            WorkerEvent::GeneratedConfirmed(result) => match result {
                Ok(snapshot) => {
                    clear_prepared_state(&mut self.prepared, &mut self.hold);
                    self.secret_reveal = None;
                    self.snapshot = Some(snapshot);
                    self.notice = Some(
                        "복구 문구 백업을 확인하고 새 v2 테스트 지갑을 저장했습니다.".to_owned(),
                    );
                }
                Err(error) => self.error = Some(safe_error(error)),
            },
            WorkerEvent::GeneratedCancelled(result) => match result {
                Ok(()) => {
                    self.secret_reveal = None;
                    self.notice =
                        Some("저장하지 않은 복구 문구를 메모리에서 지웠습니다.".to_owned());
                }
                Err(error) => self.error = Some(safe_error(error)),
            },
            WorkerEvent::MnemonicImported(result) | WorkerEvent::PrivateKeyImported(result) => {
                match result {
                    Ok(snapshot) => {
                        clear_prepared_state(&mut self.prepared, &mut self.hold);
                        self.snapshot = Some(snapshot);
                        self.notice =
                            Some("가져온 비밀값을 v2 테스트 지갑으로 저장했습니다.".to_owned());
                    }
                    Err(error) => self.error = Some(safe_error(error)),
                }
            }
            WorkerEvent::Opened(result) => match result {
                Ok(snapshot) => {
                    clear_prepared_state(&mut self.prepared, &mut self.hold);
                    self.snapshot = Some(snapshot);
                    self.notice = Some("테스트 지갑을 열었습니다.".to_owned());
                }
                Err(error) => {
                    clear_prepared_state(&mut self.prepared, &mut self.hold);
                    self.secret_reveal = None;
                    self.snapshot = None;
                    self.error = Some(safe_error(error));
                }
            },
            WorkerEvent::LegacyMigrated(result) => match result {
                Ok(snapshot) => {
                    clear_prepared_state(&mut self.prepared, &mut self.hold);
                    self.snapshot = Some(snapshot);
                    self.notice = Some(
                        "계정 주소를 유지한 채 v1 개인 키 지갑을 v2로 이전했습니다.".to_owned(),
                    );
                }
                Err(error) => {
                    clear_prepared_state(&mut self.prepared, &mut self.hold);
                    self.secret_reveal = None;
                    self.snapshot = None;
                    self.error = Some(safe_error(error));
                }
            },
            WorkerEvent::MnemonicExported(result)
            | WorkerEvent::AccountPrivateKeyExported(result) => match result {
                Ok(reveal) => {
                    clear_prepared_state(&mut self.prepared, &mut self.hold);
                    self.secret_reveal = TimedSecretReveal::new(
                        reveal,
                        RevealPurpose::ReauthenticatedExport,
                        Instant::now(),
                    );
                    self.notice =
                        Some("비밀값은 잠시만 표시되며 복사 기능을 제공하지 않습니다.".to_owned());
                }
                Err(error) => {
                    clear_prepared_state(&mut self.prepared, &mut self.hold);
                    self.error = Some(safe_error(error));
                }
            },
            WorkerEvent::Refreshed(result) => match result {
                Ok(snapshot) => {
                    self.snapshot = Some(snapshot);
                    self.notice = Some("Sepolia 잔액을 새로 확인했습니다.".to_owned());
                }
                Err(error) => self.error = Some(safe_error(error)),
            },
            WorkerEvent::TransferPrepared(result) => match *result {
                Ok(preview) => {
                    self.prepared = Some(preview);
                    self.notice = None;
                    self.error = None;
                    self.hold.reset();
                }
                Err(error) => {
                    self.prepared = None;
                    self.error = Some(safe_error(error));
                }
            },
            WorkerEvent::PreparedConfirmed(result) => match result {
                Ok(receipt) => {
                    self.prepared = None;
                    self.last_transaction_hash = Some(receipt.transaction_hash);
                    self.recipient.clear();
                    self.amount_eth.clear();
                    self.notice = Some(
                        "Sepolia 테스트 전송을 제출했습니다. 반영까지 잠시 걸릴 수 있습니다."
                            .to_owned(),
                    );
                }
                Err(error) => {
                    self.prepared = None;
                    self.error = Some(safe_error(error));
                }
            },
            WorkerEvent::PreparedCancelled(result) => match result {
                Ok(()) => {
                    clear_prepared_state(&mut self.prepared, &mut self.hold);
                    self.notice = Some("준비한 전송을 취소했습니다.".to_owned());
                }
                Err(error) => self.error = Some(safe_error(error)),
            },
            WorkerEvent::Retried(result) => match result {
                Ok(receipt) => {
                    self.last_transaction_hash = Some(receipt.transaction_hash);
                    self.notice =
                        Some("저장된 이전 Sepolia 거래를 그대로 다시 제출했습니다.".to_owned());
                }
                Err(error) => self.error = Some(safe_error(error)),
            },
        }
    }

    fn wallet_setup(&mut self, ui: &mut egui::Ui) {
        let setup_enabled = self.pending.is_none()
            && self.prepared.is_none()
            && !self
                .secret_reveal
                .as_ref()
                .is_some_and(|reveal| reveal.purpose == RevealPurpose::GeneratedBackup);
        let palette = StatusPalette::from_visuals(ui.visuals());
        ui.heading("1. 테스트 지갑 준비");
        ui.label("v2 지갑을 만들거나 가져오고, 기존 v1/v2 지갑을 열거나 이전할 수 있습니다.");
        ui.add_space(8.0);
        let _ = ui.add_enabled_ui(setup_enabled, |ui| {
            ui.horizontal_wrapped(|ui| {
                ui.selectable_value(&mut self.setup_mode, SetupMode::Open, "열기");
                ui.selectable_value(&mut self.setup_mode, SetupMode::Generate, "새로 만들기");
                ui.selectable_value(
                    &mut self.setup_mode,
                    SetupMode::ImportMnemonic,
                    "복구 문구 가져오기",
                );
                ui.selectable_value(
                    &mut self.setup_mode,
                    SetupMode::ImportPrivateKey,
                    "개인 키 가져오기",
                );
                ui.selectable_value(
                    &mut self.setup_mode,
                    SetupMode::MigrateLegacy,
                    "v1 → v2 이전",
                );
            });
        });
        ui.add_space(8.0);

        if matches!(
            self.setup_mode,
            SetupMode::ImportMnemonic | SetupMode::ImportPrivateKey
        ) {
            let hint = if self.setup_mode == SetupMode::ImportMnemonic {
                "영어 복구 문구"
            } else {
                "64자리 16진수 개인 키"
            };
            ui.horizontal(|ui| {
                ui.label(hint);
                if ui
                    .button(if self.imported_secret_visible {
                        "숨기기"
                    } else {
                        "보기"
                    })
                    .clicked()
                {
                    self.imported_secret_visible = !self.imported_secret_visible;
                }
            });
            let mut edit = egui::TextEdit::multiline(&mut self.imported_secret)
                .hint_text(hint)
                .desired_width(f32::INFINITY)
                .desired_rows(3);
            if !self.imported_secret_visible {
                edit = edit.password(true);
            }
            let _ = ui.add_enabled(setup_enabled, edit);
            ui.label(
                RichText::new(
                    "클립보드 복사 버튼은 제공하지 않습니다. 가져온 비밀값은 작업 뒤 지워집니다.",
                )
                .small()
                .color(palette.muted),
            );
        }

        if self.setup_mode == SetupMode::MigrateLegacy {
            let mut old_edit = egui::TextEdit::singleline(&mut self.old_password)
                .hint_text("기존 v1 비밀번호")
                .desired_width(320.0);
            if !self.password_visible {
                old_edit = old_edit.password(true);
            }
            let _ = ui.add_enabled(setup_enabled, old_edit);
        }

        if self.setup_mode == SetupMode::Generate {
            ui.horizontal(|ui| {
                ui.label("새 복구 문구 길이");
                let _ = ui.add_enabled_ui(setup_enabled, |ui| {
                    ui.selectable_value(
                        &mut self.mnemonic_words,
                        NewMnemonicWords::Twelve,
                        "12단어",
                    );
                    ui.selectable_value(
                        &mut self.mnemonic_words,
                        NewMnemonicWords::TwentyFour,
                        "24단어",
                    );
                });
            });
        }

        ui.horizontal(|ui| {
            let mut edit = egui::TextEdit::singleline(&mut self.password)
                .hint_text(if self.setup_mode == SetupMode::Open {
                    "현재 비밀번호"
                } else {
                    "새 v2 비밀번호 (12바이트 이상)"
                })
                .desired_width(320.0);
            if !self.password_visible {
                edit = edit.password(true);
            }
            let _ = ui.add_enabled(setup_enabled, edit);
            let label = if self.password_visible {
                "숨기기"
            } else {
                "보기"
            };
            if ui.button(label).clicked() {
                self.password_visible = !self.password_visible;
            }
        });
        if self.setup_mode != SetupMode::Open {
            let mut edit = egui::TextEdit::singleline(&mut self.password_confirmation)
                .hint_text("새 v2 비밀번호 다시 입력")
                .desired_width(320.0);
            if !self.password_visible {
                edit = edit.password(true);
            }
            let _ = ui.add_enabled(setup_enabled, edit);
        }
        ui.label(
            RichText::new("비밀번호를 잃으면 로컬 지갑 파일을 열 수 없습니다.")
                .small()
                .color(palette.muted),
        );
        ui.add_space(8.0);
        let button_label = match self.setup_mode {
            SetupMode::Open => "기존 테스트 지갑 열기",
            SetupMode::Generate => "복구 문구 생성 (아직 저장 안 함)",
            SetupMode::ImportMnemonic => "복구 문구를 v2로 가져오기",
            SetupMode::ImportPrivateKey => "개인 키를 v2로 가져오기",
            SetupMode::MigrateLegacy => "주소를 유지해 v1을 v2로 이전",
        };
        if ui
            .add_enabled(setup_enabled, egui::Button::new(button_label))
            .clicked()
        {
            match self.setup_mode {
                SetupMode::Open => self.open_wallet(),
                SetupMode::Generate => self.begin_generate_wallet(),
                SetupMode::ImportMnemonic => self.import_wallet(true),
                SetupMode::ImportPrivateKey => self.import_wallet(false),
                SetupMode::MigrateLegacy => self.migrate_legacy_wallet(),
            }
        }
    }

    fn account_panel(&mut self, ui: &mut egui::Ui) {
        let Some(snapshot) = self.snapshot.clone() else {
            return;
        };
        ui.separator();
        ui.heading("2. 내 Sepolia 계정");
        let kind_label = match snapshot.wallet_kind {
            WalletKind::LegacyV1RawPrivateKey => "v1 개인 키 지갑",
            WalletKind::V2Mnemonic { .. } => "v2 복구 문구 지갑",
            WalletKind::V2RawPrivateKey => "v2 개인 키 지갑",
        };
        ui.label(format!(
            "지갑 형식: {kind_label} · 전송 계정: 0 · 검증된 계정 메타데이터: {}개",
            snapshot.account_count
        ));
        if let WalletKind::V2Mnemonic { word_count } = snapshot.wallet_kind {
            ui.label(format!("복구 문구: 영어 {word_count}단어"));
        }
        ui.label("주소");
        ui.horizontal_wrapped(|ui| {
            ui.monospace(&snapshot.address);
            if ui.button("주소 복사").clicked() {
                ui.ctx().copy_text(snapshot.address.clone());
                self.notice = Some("주소를 복사했습니다.".to_owned());
            }
        });
        ui.add_space(8.0);
        ui.horizontal(|ui| {
            ui.label("잔액:");
            ui.strong(format!("{} Sepolia ETH", snapshot.balance_eth));
            if ui
                .add_enabled(
                    self.pending.is_none() && self.prepared.is_none(),
                    egui::Button::new("새로고침"),
                )
                .clicked()
            {
                self.refresh();
            }
        });
    }

    fn secret_management_panel(&mut self, context: &egui::Context, ui: &mut egui::Ui) {
        let Some(snapshot) = self.snapshot.clone() else {
            return;
        };
        let palette = StatusPalette::from_visuals(ui.visuals());
        ui.add_space(10.0);
        ui.collapsing("지갑 비밀값 내보내기", |ui| {
            ui.colored_label(
                palette.warning,
                "주변 화면 녹화·사진·악성 프로그램에 노출될 수 있습니다.",
            );
            match snapshot.wallet_kind {
                WalletKind::V2Mnemonic { .. } => {
                    ui.horizontal(|ui| {
                        ui.selectable_value(
                            &mut self.export_kind,
                            SecretRevealKind::Mnemonic,
                            "복구 문구",
                        );
                        ui.selectable_value(
                            &mut self.export_kind,
                            SecretRevealKind::AccountPrivateKey,
                            "계정 0 개인 키",
                        );
                    });
                }
                WalletKind::LegacyV1RawPrivateKey => {
                    self.export_kind = SecretRevealKind::AccountPrivateKey;
                    ui.label(
                        "v1은 원래 복구 문구를 저장하지 않았으므로 복구 문구 내보내기가 불가능합니다. v2로 이전해도 개인 키 지갑으로 유지됩니다.",
                    );
                }
                WalletKind::V2RawPrivateKey => {
                    self.export_kind = SecretRevealKind::AccountPrivateKey;
                    ui.label("이 지갑은 개인 키로 가져왔으므로 복구 문구가 없습니다.");
                }
            }
            let edit = egui::TextEdit::singleline(&mut self.reauth_password)
                .hint_text("현재 비밀번호 재입력")
                .desired_width(320.0)
                .password(true);
            let enabled = self.pending.is_none()
                && self.prepared.is_none()
                && self.secret_reveal.is_none();
            let _ = ui.add_enabled(enabled, edit);
            let action = match self.export_kind {
                SecretRevealKind::Mnemonic => SecretHoldAction::ExportMnemonic,
                SecretRevealKind::AccountPrivateKey => {
                    SecretHoldAction::ExportAccountPrivateKey
                }
            };
            let label = match action {
                SecretHoldAction::ExportMnemonic => "재인증 후 복구 문구 표시 — 2초 동안 누르기",
                SecretHoldAction::ExportAccountPrivateKey => {
                    "재인증 후 계정 0 개인 키 표시 — 2초 동안 누르기"
                }
                SecretHoldAction::ConfirmGeneratedBackup => unreachable!(),
            };
            let hold_enabled = enabled && valid_password(&self.reauth_password);
            let response = ui.add_enabled(hold_enabled, secret_hold_button(label));
            let now = Instant::now();
            let outcome = self.secret_hold.update(
                now,
                hold_to_send_input(context, &response, hold_enabled),
            );
            let _ = self.handle_secret_hold_outcome(outcome, action);
            if matches!(outcome, HoldOutcome::Holding(_)) {
                context.request_repaint_after(Duration::from_millis(16));
            }
            let progress = self.secret_hold.fraction(now);
            let _ = ui.add(
                egui::ProgressBar::new(progress)
                    .desired_width(300.0)
                    .text(format!("{:.1} / 2.0초", progress * 2.0)),
            );
            ui.label(
                RichText::new("비밀값 클립보드 복사 기능은 제공하지 않습니다.")
                    .small()
                    .color(palette.muted),
            );
        });
    }

    fn secret_reveal_panel(&mut self, context: &egui::Context, ui: &mut egui::Ui) {
        let Some(reveal) = self.secret_reveal.as_ref() else {
            return;
        };
        let now = Instant::now();
        let purpose = reveal.purpose;
        let kind = reveal.reveal.kind();
        let remaining = reveal.remaining_seconds(now);
        let label = match kind {
            SecretRevealKind::Mnemonic => "영어 복구 문구",
            SecretRevealKind::AccountPrivateKey => "계정 0 개인 키",
        };
        let secret = reveal.reveal.expose_secret();
        let palette = StatusPalette::from_visuals(ui.visuals());
        ui.separator();
        ui.heading("비밀값 일회성 표시");
        ui.colored_label(
            palette.warning,
            format!("{label} · 약 {remaining}초 뒤 자동으로 지워집니다."),
        );
        let _ = ui.add(
            egui::Label::new(RichText::new(secret).monospace().size(18.0))
                .selectable(false)
                .wrap(),
        );
        ui.label(
            RichText::new("앱은 이 값을 클립보드에 복사하지 않습니다.")
                .small()
                .color(palette.muted),
        );
        if purpose == RevealPurpose::GeneratedBackup {
            ui.label("종이나 오프라인 매체에 정확히 적은 뒤 아래 확인을 계속 누르세요.");
            ui.horizontal(|ui| {
                if ui
                    .add_enabled(
                        self.pending.is_none(),
                        egui::Button::new("저장하지 않고 지우기"),
                    )
                    .clicked()
                {
                    self.cancel_generated_wallet();
                    return;
                }
                let enabled = self.pending.is_none() && remaining > 0;
                let response = ui.add_enabled(
                    enabled,
                    secret_hold_button("백업 확인 후 v2 저장 — 2초 동안 누르기"),
                );
                let outcome = self
                    .secret_hold
                    .update(now, hold_to_send_input(context, &response, enabled));
                let _ = self
                    .handle_secret_hold_outcome(outcome, SecretHoldAction::ConfirmGeneratedBackup);
                if matches!(outcome, HoldOutcome::Holding(_)) {
                    context.request_repaint_after(Duration::from_millis(16));
                }
            });
            let progress = self.secret_hold.fraction(now);
            let _ = ui.add(
                egui::ProgressBar::new(progress)
                    .desired_width(300.0)
                    .text(format!("{:.1} / 2.0초", progress * 2.0)),
            );
        } else if ui.button("지금 지우기").clicked() {
            self.secret_reveal = None;
            self.secret_hold.reset();
        }
        context.request_repaint_after(Duration::from_millis(100));
    }

    fn send_panel(&mut self, context: &egui::Context, ui: &mut egui::Ui) {
        if self.snapshot.is_none() {
            return;
        }
        let palette = StatusPalette::from_visuals(ui.visuals());
        ui.separator();
        ui.heading("3. 테스트 ETH 보내기");
        let preparing_allowed = self.prepared.is_none() && self.pending.is_none();
        if self.prepared.is_none() {
            ui.label("먼저 받는 주소와 금액을 입력해 전송 내용을 준비하세요.");
            ui.add_space(6.0);
            ui.label("받는 주소");
            let _ = ui.add_enabled(
                preparing_allowed,
                egui::TextEdit::singleline(&mut self.recipient)
                    .hint_text("0x로 시작하는 주소")
                    .desired_width(f32::INFINITY),
            );
            if !self.recipient.trim().is_empty() && !valid_recipient_shape(self.recipient.trim()) {
                ui.colored_label(palette.error, "받는 주소 형식을 확인해 주세요.");
            }
            ui.label("보낼 금액");
            ui.horizontal(|ui| {
                let _ = ui.add_enabled(
                    preparing_allowed,
                    egui::TextEdit::singleline(&mut self.amount_eth)
                        .hint_text("예: 0.001")
                        .desired_width(180.0),
                );
                ui.label("Sepolia ETH");
            });
            if !self.amount_eth.trim().is_empty() && !valid_amount_shape(self.amount_eth.trim()) {
                ui.colored_label(
                    palette.error,
                    "0보다 큰 금액을 소수점 아래 최대 18자리로 입력해 주세요.",
                );
            }

            ui.add_space(8.0);
            ui.label(RichText::new("가스 수수료").strong());
            ui.horizontal(|ui| {
                let _ = ui.add_enabled_ui(preparing_allowed, |ui| {
                    ui.selectable_value(&mut self.fee_mode, FeeMode::Recommended, "추천");
                    ui.selectable_value(&mut self.fee_mode, FeeMode::Faster, "빠르게");
                    ui.selectable_value(&mut self.fee_mode, FeeMode::Custom, "직접 입력");
                });
            });
            match self.fee_mode {
                FeeMode::Recommended => {
                    ui.label(
                        RichText::new("Sepolia 노드가 제안한 우선 수수료를 사용합니다.")
                            .small()
                            .color(palette.muted),
                    );
                }
                FeeMode::Faster => {
                    ui.label(
                        RichText::new(
                            "추천 우선 수수료를 안전 한도 안에서 높입니다. 더 빠른 포함을 보장하지 않습니다.",
                        )
                        .small()
                        .color(palette.muted),
                    );
                }
                FeeMode::Custom => {
                    ui.horizontal(|ui| {
                        ui.label("최대 우선 수수료");
                        let _ = ui.add_enabled(
                            preparing_allowed,
                            egui::TextEdit::singleline(&mut self.custom_priority_fee_gwei)
                                .hint_text("예: 1.5")
                                .desired_width(140.0),
                        );
                        ui.label("Gwei");
                    });
                    ui.horizontal(|ui| {
                        ui.label("최대 수수료");
                        let _ = ui.add_enabled(
                            preparing_allowed,
                            egui::TextEdit::singleline(&mut self.custom_max_fee_gwei)
                                .hint_text("예: 3")
                                .desired_width(140.0),
                        );
                        ui.label("Gwei");
                    });
                    let priority_valid = valid_gwei_shape(&self.custom_priority_fee_gwei, true);
                    let maximum_valid = valid_gwei_shape(&self.custom_max_fee_gwei, false);
                    if (!self.custom_priority_fee_gwei.is_empty() && !priority_valid)
                        || (!self.custom_max_fee_gwei.is_empty() && !maximum_valid)
                    {
                        ui.colored_label(
                            palette.error,
                            "Gwei 값은 부호 없이 소수점 아래 최대 9자리로 입력해 주세요.",
                        );
                    }
                }
            }
            ui.label(
                RichText::new("일반 ETH 전송만 지원하며 가스 한도는 21,000으로 고정됩니다.")
                    .small()
                    .color(palette.muted),
            );
            ui.add_space(8.0);
            let valid_input = valid_recipient_shape(self.recipient.trim())
                && valid_amount_shape(self.amount_eth.trim())
                && match self.fee_mode {
                    FeeMode::Recommended | FeeMode::Faster => true,
                    FeeMode::Custom => {
                        valid_gwei_shape(&self.custom_priority_fee_gwei, true)
                            && valid_gwei_shape(&self.custom_max_fee_gwei, false)
                    }
                };
            if ui
                .add_enabled(
                    preparing_allowed && valid_input,
                    egui::Button::new("전송 내용 준비").min_size(egui::vec2(180.0, 38.0)),
                )
                .clicked()
            {
                self.prepare_transfer();
            }
            self.hold.reset();
        } else {
            let Some(preview) = self.prepared.clone() else {
                self.hold.reset();
                return;
            };
            ui.colored_label(
                palette.warning,
                RichText::new("아래 내용 그대로 서명·전송됩니다. 전부 확인하세요.").strong(),
            );
            ui.add_space(8.0);
            ui.group(|ui| render_transfer_preview(ui, &preview));
            ui.add_space(8.0);
            ui.horizontal(|ui| {
                if ui
                    .add_enabled(self.pending.is_none(), egui::Button::new("취소하고 수정"))
                    .clicked()
                {
                    self.cancel_prepared();
                }

                let confirm_enabled = confirmation_enabled(self.prepared.as_ref(), self.pending);
                let response = ui.add_enabled(confirm_enabled, hold_to_send_button());
                let now = Instant::now();
                let outcome = self
                    .hold
                    .update(now, hold_to_send_input(context, &response, confirm_enabled));
                let _ = self.handle_hold_outcome(outcome);
                if matches!(outcome, HoldOutcome::Holding(_)) {
                    context.request_repaint_after(Duration::from_millis(16));
                }
            });
            let now = Instant::now();
            let progress = self.hold.fraction(now);
            let _ = ui.add(
                egui::ProgressBar::new(progress)
                    .desired_width(300.0)
                    .text(format!("{:.1} / 2.0초", progress * 2.0)),
            );
        }

        if let Some(hash) = &self.last_transaction_hash {
            ui.add_space(8.0);
            ui.label("최근 제출한 트랜잭션");
            ui.horizontal_wrapped(|ui| {
                ui.monospace(hash);
                if ui.button("해시 복사").clicked() {
                    ui.ctx().copy_text(hash.clone());
                }
            });
        }

        ui.add_space(12.0);
        ui.collapsing("전송 중 네트워크가 끊겼나요?", |ui| {
            ui.label(
                "새 거래를 만들지 않고, 디스크에 보관된 이전 거래가 있을 때만 같은 바이트를 다시 전송합니다.",
            );
            if ui
                .add_enabled(
                    self.pending.is_none() && self.prepared.is_none(),
                    egui::Button::new("이전 거래 그대로 다시 전송"),
                )
                .clicked()
            {
                self.retry_pending();
            }
        });
    }
}

fn hold_to_send_button() -> egui::Button<'static> {
    egui::Button::new("확인하고 전송 — 2초 동안 누르기")
        .sense(egui::Sense::drag())
        .min_size(egui::vec2(300.0, 48.0))
}

fn secret_hold_button(label: &'static str) -> egui::Button<'static> {
    egui::Button::new(label)
        .sense(egui::Sense::drag())
        .min_size(egui::vec2(300.0, 44.0))
}

fn hold_to_send_input(
    context: &egui::Context,
    response: &egui::Response,
    enabled: bool,
) -> HoldInput {
    let pointer_inside = response.contains_pointer();
    context.input(|input| HoldInput {
        enabled,
        primary_pressed_on_button: input.pointer.primary_pressed() && pointer_inside,
        primary_down: input.pointer.primary_down(),
        pointer_inside,
        focused: input.focused,
        escape_pressed: input.key_pressed(egui::Key::Escape),
    })
}

fn confirmation_enabled(
    prepared: Option<&TransferPreview>,
    pending: Option<PendingAction>,
) -> bool {
    prepared.is_some() && pending.is_none()
}

fn clear_prepared_state(prepared: &mut Option<TransferPreview>, hold: &mut HoldToSend) {
    *prepared = None;
    hold.reset();
}

fn preview_fields(preview: &TransferPreview) -> [(&'static str, &str); 13] {
    [
        ("받는 주소", preview.recipient.as_str()),
        ("보낼 금액 (Sepolia ETH)", preview.amount_eth.as_str()),
        ("nonce", preview.nonce.as_str()),
        ("수수료 방식", preview.fee_mode_ko.as_str()),
        ("가스 한도", preview.gas_limit.as_str()),
        (
            "현재 기준 기본 수수료 / gas (gwei)",
            preview.quoted_base_fee_per_gas_gwei.as_str(),
        ),
        (
            "최대 우선 수수료 / gas (gwei)",
            preview.max_priority_fee_per_gas_gwei.as_str(),
        ),
        (
            "최대 수수료 / gas (gwei)",
            preview.max_fee_per_gas_gwei.as_str(),
        ),
        (
            "현재 기준 예상 네트워크 수수료 (Sepolia ETH)",
            preview.estimated_network_fee_eth.as_str(),
        ),
        (
            "최대 네트워크 수수료 (Sepolia ETH)",
            preview.max_network_fee_eth.as_str(),
        ),
        (
            "현재 기준 예상 총액 (Sepolia ETH)",
            preview.estimated_total_eth.as_str(),
        ),
        ("최대 총지출 (Sepolia ETH)", preview.max_total_eth.as_str()),
        (
            "준비 완료 시점 남은 견적 유효 시간 (초)",
            preview.quote_valid_for_seconds.as_str(),
        ),
    ]
}

fn render_transfer_preview(ui: &mut egui::Ui, preview: &TransferPreview) {
    for (label, value) in preview_fields(preview) {
        ui.label(RichText::new(label).strong());
        ui.horizontal_wrapped(|ui| {
            ui.label(RichText::new(value).monospace().size(18.0));
        });
        ui.add_space(7.0);
    }
    let palette = StatusPalette::from_visuals(ui.visuals());
    ui.label(
        RichText::new(
            "실제 수수료는 포함 블록에 따라 달라질 수 있지만 최대 수수료를 넘지 않습니다. 사용하지 않은 최대 금액은 청구되지 않습니다.",
        )
        .small()
        .color(palette.muted),
    );
}

impl Drop for WalletApp {
    fn drop(&mut self) {
        self.password.zeroize();
        self.password_confirmation.zeroize();
        self.old_password.zeroize();
        self.imported_secret.zeroize();
        self.reauth_password.zeroize();
    }
}

impl eframe::App for WalletApp {
    fn update(&mut self, context: &egui::Context, _frame: &mut eframe::Frame) {
        self.process_events();
        self.expire_secret_reveal(Instant::now());
        egui::TopBottomPanel::top("testnet_warning").show(context, |ui| {
            let palette = StatusPalette::from_visuals(ui.visuals());
            ui.vertical_centered(|ui| {
                ui.heading(RichText::new("SEPOLIA 테스트넷 전용 지갑").color(palette.warning));
                ui.strong("실제 ETH나 실제 가치가 있는 자산을 절대 보내지 마세요.");
                ui.label("고정 네트워크: Ethereum Sepolia · Chain ID 11155111");
            });
        });

        egui::CentralPanel::default().show(context, |ui| {
            let palette = StatusPalette::from_visuals(ui.visuals());
            egui::ScrollArea::vertical().show(ui, |ui| {
                ui.set_max_width(820.0);
                ui.add_space(8.0);
                self.wallet_setup(ui);
                self.account_panel(ui);
                self.secret_management_panel(context, ui);
                self.secret_reveal_panel(context, ui);
                self.send_panel(context, ui);

                if let Some(action) = self.pending {
                    ui.add_space(12.0);
                    ui.spinner();
                    ui.label(action.korean());
                    context.request_repaint_after(Duration::from_millis(100));
                }
                if let Some(notice) = &self.notice {
                    ui.add_space(12.0);
                    ui.colored_label(palette.success, notice);
                }
                if let Some(error) = &self.error {
                    ui.add_space(12.0);
                    ui.colored_label(palette.error, error);
                }
                ui.add_space(18.0);
                ui.label(
                    RichText::new(
                        "v2 비밀값은 로컬 암호화 파일에만 저장됩니다. 개발용 단일 PC 테스트판이며 메인넷·브라우저 연결은 지원하지 않습니다.",
                    )
                    .small()
                    .color(palette.muted),
                );
            });
        });
    }
}

fn spawn_worker(
    mut backend: Box<dyn WalletBackend>,
    commands: Receiver<WorkerCommand>,
    events: Sender<WorkerEvent>,
) {
    std::thread::spawn(move || {
        while let Ok(command) = commands.recv() {
            let event = execute_worker_command(backend.as_mut(), command);
            if events.send(event).is_err() {
                break;
            }
        }
    });
}

fn execute_worker_command(backend: &mut dyn WalletBackend, command: WorkerCommand) -> WorkerEvent {
    match command {
        WorkerCommand::BeginGenerate {
            words,
            password,
            password_confirmation,
        } => WorkerEvent::GenerationBegun(backend.begin_generate_wallet(
            words,
            password,
            password_confirmation,
        )),
        WorkerCommand::ConfirmGenerated => {
            WorkerEvent::GeneratedConfirmed(backend.confirm_generated_wallet())
        }
        WorkerCommand::CancelGenerated => {
            WorkerEvent::GeneratedCancelled(backend.cancel_generated_wallet())
        }
        WorkerCommand::ImportMnemonic {
            mnemonic,
            password,
            password_confirmation,
        } => WorkerEvent::MnemonicImported(backend.import_mnemonic_wallet(
            mnemonic,
            password,
            password_confirmation,
        )),
        WorkerCommand::ImportPrivateKey {
            private_key,
            password,
            password_confirmation,
        } => WorkerEvent::PrivateKeyImported(backend.import_private_key_wallet(
            private_key,
            password,
            password_confirmation,
        )),
        WorkerCommand::Open { password } => {
            WorkerEvent::Opened(backend.open_wallet(password.as_str()))
        }
        WorkerCommand::MigrateLegacy {
            old_password,
            new_password,
            new_password_confirmation,
        } => WorkerEvent::LegacyMigrated(backend.migrate_legacy_wallet(
            old_password,
            new_password,
            new_password_confirmation,
        )),
        WorkerCommand::ExportMnemonic { password } => {
            WorkerEvent::MnemonicExported(backend.export_mnemonic(password))
        }
        WorkerCommand::ExportAccountPrivateKey { password } => {
            WorkerEvent::AccountPrivateKeyExported(backend.export_account_private_key(password))
        }
        WorkerCommand::Refresh => WorkerEvent::Refreshed(backend.refresh()),
        WorkerCommand::PrepareTransfer {
            recipient,
            amount_eth,
            fee_selection,
        } => WorkerEvent::TransferPrepared(Box::new(backend.prepare_transfer(
            &recipient,
            &amount_eth,
            fee_selection,
        ))),
        WorkerCommand::ConfirmPrepared => {
            WorkerEvent::PreparedConfirmed(backend.confirm_prepared())
        }
        WorkerCommand::CancelPrepared => WorkerEvent::PreparedCancelled(backend.cancel_prepared()),
        WorkerCommand::RetryPending => WorkerEvent::Retried(backend.retry_pending()),
    }
}

/// Non-secret evidence produced by the window-free UI smoke harness.
pub(crate) struct HeadlessSmokeEvidence {
    pub(crate) transitions_checked: usize,
    pub(crate) backend_routes_checked: usize,
}

/// Exercise the same transfer button handlers, command router, and UI event
/// reducer as the native application without starting `eframe`.
///
/// The backend is fully in memory and uses only non-address sentinel values.
/// No vault, filesystem, network, mouse, keyboard, or window API is touched.
pub(crate) fn run_headless_smoke() -> Result<HeadlessSmokeEvidence, ()> {
    const RECIPIENT_SENTINEL: &str = "headless-recipient";
    const AMOUNT_SENTINEL: &str = "headless-amount";

    let (command_sender, command_receiver) = mpsc::channel();
    let (_unused_event_sender, event_receiver) = mpsc::channel();
    let mut app = WalletApp {
        commands: Some(command_sender),
        events: event_receiver,
        setup_mode: SetupMode::Open,
        mnemonic_words: NewMnemonicWords::Twelve,
        export_kind: SecretRevealKind::Mnemonic,
        password: String::new(),
        password_confirmation: String::new(),
        old_password: String::new(),
        imported_secret: String::new(),
        password_visible: false,
        imported_secret_visible: false,
        reauth_password: String::new(),
        snapshot: None,
        recipient: RECIPIENT_SENTINEL.to_owned(),
        amount_eth: AMOUNT_SENTINEL.to_owned(),
        fee_mode: FeeMode::Recommended,
        custom_priority_fee_gwei: String::new(),
        custom_max_fee_gwei: String::new(),
        prepared: None,
        pending: None,
        hold: HoldToSend::default(),
        secret_hold: HoldToSend::default(),
        secret_reveal: None,
        notice: None,
        error: None,
        last_transaction_hash: None,
    };
    let mut backend = HeadlessBackend::default();

    app.mnemonic_words = NewMnemonicWords::Twelve;
    app.password = "headless-vault-pass".to_owned();
    app.password_confirmation = "headless-vault-pass".to_owned();
    app.begin_generate_wallet();
    if app.pending != Some(PendingAction::BeginGenerate) {
        return Err(());
    }
    route_headless_command(&mut app, &command_receiver, &mut backend, |command| {
        matches!(
            command,
            WorkerCommand::BeginGenerate {
                words: NewMnemonicWords::Twelve,
                ..
            }
        )
    })?;
    if app.pending.is_some()
        || !app.secret_reveal.as_ref().is_some_and(|reveal| {
            reveal.purpose == RevealPurpose::GeneratedBackup
                && reveal.reveal.kind() == SecretRevealKind::Mnemonic
        })
    {
        return Err(());
    }
    if !app.handle_secret_hold_outcome(
        HoldOutcome::Triggered,
        SecretHoldAction::ConfirmGeneratedBackup,
    ) || app.handle_secret_hold_outcome(
        HoldOutcome::Triggered,
        SecretHoldAction::ConfirmGeneratedBackup,
    ) {
        return Err(());
    }
    route_headless_command(&mut app, &command_receiver, &mut backend, |command| {
        matches!(command, WorkerCommand::ConfirmGenerated)
    })?;
    if app.pending.is_some()
        || app.secret_reveal.is_some()
        || app.snapshot.as_ref().map(|snapshot| snapshot.wallet_kind)
            != Some(WalletKind::V2Mnemonic { word_count: 12 })
    {
        return Err(());
    }

    app.reauth_password = "headless-vault-pass".to_owned();
    if !app.handle_secret_hold_outcome(HoldOutcome::Triggered, SecretHoldAction::ExportMnemonic)
        || app.handle_secret_hold_outcome(HoldOutcome::Triggered, SecretHoldAction::ExportMnemonic)
    {
        return Err(());
    }
    route_headless_command(&mut app, &command_receiver, &mut backend, |command| {
        matches!(command, WorkerCommand::ExportMnemonic { .. })
    })?;
    if !app.secret_reveal.as_ref().is_some_and(|reveal| {
        reveal.purpose == RevealPurpose::ReauthenticatedExport
            && reveal.reveal.kind() == SecretRevealKind::Mnemonic
    }) {
        return Err(());
    }
    app.secret_reveal = None;

    app.reauth_password = "headless-vault-pass".to_owned();
    if !app.handle_secret_hold_outcome(
        HoldOutcome::Triggered,
        SecretHoldAction::ExportAccountPrivateKey,
    ) {
        return Err(());
    }
    route_headless_command(&mut app, &command_receiver, &mut backend, |command| {
        matches!(command, WorkerCommand::ExportAccountPrivateKey { .. })
    })?;
    if !app.secret_reveal.as_ref().is_some_and(|reveal| {
        reveal.purpose == RevealPurpose::ReauthenticatedExport
            && reveal.reveal.kind() == SecretRevealKind::AccountPrivateKey
    }) {
        return Err(());
    }
    app.secret_reveal = None;

    app.imported_secret = "headless mnemonic marker".to_owned();
    app.password = "headless-import-pass".to_owned();
    app.password_confirmation = "headless-import-pass".to_owned();
    app.import_wallet(true);
    route_headless_command(&mut app, &command_receiver, &mut backend, |command| {
        matches!(command, WorkerCommand::ImportMnemonic { .. })
    })?;
    app.imported_secret = "headless private key marker".to_owned();
    app.password = "headless-import-pass".to_owned();
    app.password_confirmation = "headless-import-pass".to_owned();
    app.import_wallet(false);
    route_headless_command(&mut app, &command_receiver, &mut backend, |command| {
        matches!(command, WorkerCommand::ImportPrivateKey { .. })
    })?;

    app.old_password = "headless-legacy-pass".to_owned();
    app.password = "headless-migrate-pass".to_owned();
    app.password_confirmation = "headless-migrate-pass".to_owned();
    app.migrate_legacy_wallet();
    route_headless_command(&mut app, &command_receiver, &mut backend, |command| {
        matches!(command, WorkerCommand::MigrateLegacy { .. })
    })?;
    app.password = "headless-open-pass".to_owned();
    app.open_wallet();
    route_headless_command(&mut app, &command_receiver, &mut backend, |command| {
        matches!(command, WorkerCommand::Open { .. })
    })?;

    app.password = "headless-vault-pass".to_owned();
    app.password_confirmation = "headless-vault-pass".to_owned();
    app.begin_generate_wallet();
    route_headless_command(&mut app, &command_receiver, &mut backend, |command| {
        matches!(command, WorkerCommand::BeginGenerate { .. })
    })?;
    app.cancel_generated_wallet();
    route_headless_command(&mut app, &command_receiver, &mut backend, |command| {
        matches!(command, WorkerCommand::CancelGenerated)
    })?;
    if app.secret_reveal.is_some() {
        return Err(());
    }

    app.prepare_transfer();
    if app.pending != Some(PendingAction::PrepareTransfer) {
        return Err(());
    }
    route_headless_command(&mut app, &command_receiver, &mut backend, |command| {
        matches!(
            command,
            WorkerCommand::PrepareTransfer {
                recipient,
                amount_eth,
                fee_selection: FeeSelection::Recommended,
            } if recipient == RECIPIENT_SENTINEL && amount_eth == AMOUNT_SENTINEL
        )
    })?;
    if app.pending.is_some()
        || app.prepared.as_ref() != Some(&headless_preview(FeeMode::Recommended))
    {
        return Err(());
    }

    if !app.handle_hold_outcome(HoldOutcome::Triggered)
        || app.handle_hold_outcome(HoldOutcome::Triggered)
        || app.pending != Some(PendingAction::ConfirmPrepared)
    {
        return Err(());
    }
    route_headless_command(&mut app, &command_receiver, &mut backend, |command| {
        matches!(command, WorkerCommand::ConfirmPrepared)
    })?;
    if app.pending.is_some()
        || app.prepared.is_some()
        || !app.recipient.is_empty()
        || !app.amount_eth.is_empty()
        || app.last_transaction_hash.as_deref() != Some("headless-confirmed")
    {
        return Err(());
    }

    app.recipient = RECIPIENT_SENTINEL.to_owned();
    app.amount_eth = AMOUNT_SENTINEL.to_owned();
    app.fee_mode = FeeMode::Faster;
    app.prepare_transfer();
    if app.pending != Some(PendingAction::PrepareTransfer) {
        return Err(());
    }
    route_headless_command(&mut app, &command_receiver, &mut backend, |command| {
        matches!(
            command,
            WorkerCommand::PrepareTransfer {
                fee_selection: FeeSelection::Faster,
                ..
            }
        )
    })?;
    if app.pending.is_some() || app.prepared.as_ref() != Some(&headless_preview(FeeMode::Faster)) {
        return Err(());
    }

    app.cancel_prepared();
    if app.pending != Some(PendingAction::CancelPrepared) {
        return Err(());
    }
    route_headless_command(&mut app, &command_receiver, &mut backend, |command| {
        matches!(command, WorkerCommand::CancelPrepared)
    })?;
    if app.pending.is_some() || app.prepared.is_some() {
        return Err(());
    }

    app.fee_mode = FeeMode::Custom;
    app.custom_priority_fee_gwei = "0001.250000000".to_owned();
    app.custom_max_fee_gwei = "0003.500000000".to_owned();
    app.prepare_transfer();
    if app.pending != Some(PendingAction::PrepareTransfer) {
        return Err(());
    }
    route_headless_command(&mut app, &command_receiver, &mut backend, |command| {
        matches!(
            command,
            WorkerCommand::PrepareTransfer {
                fee_selection: FeeSelection::Custom {
                    max_priority_fee_per_gas_gwei,
                    max_fee_per_gas_gwei,
                },
                ..
            } if max_priority_fee_per_gas_gwei == "0001.250000000"
                && max_fee_per_gas_gwei == "0003.500000000"
        )
    })?;
    if app.pending.is_some() || app.prepared.as_ref() != Some(&headless_preview(FeeMode::Custom)) {
        return Err(());
    }
    app.cancel_prepared();
    if app.pending != Some(PendingAction::CancelPrepared) {
        return Err(());
    }
    route_headless_command(&mut app, &command_receiver, &mut backend, |command| {
        matches!(command, WorkerCommand::CancelPrepared)
    })?;
    if app.pending.is_some() || app.prepared.is_some() {
        return Err(());
    }

    app.retry_pending();
    if app.pending != Some(PendingAction::RetryPending) {
        return Err(());
    }
    route_headless_command(&mut app, &command_receiver, &mut backend, |command| {
        matches!(command, WorkerCommand::RetryPending)
    })?;
    if app.pending.is_some()
        || app.last_transaction_hash.as_deref() != Some("headless-retried")
        || backend.calls
            != [
                "begin-generate-12",
                "confirm-generated",
                "export-mnemonic",
                "export-private-key",
                "import-mnemonic",
                "import-private-key",
                "migrate",
                "open",
                "begin-generate-12",
                "cancel-generated",
                "prepare-recommended",
                "confirm",
                "prepare-faster",
                "cancel",
                "prepare-custom",
                "cancel",
                "retry",
            ]
        || command_receiver.try_recv().is_ok()
    {
        return Err(());
    }

    Ok(HeadlessSmokeEvidence {
        transitions_checked: 34,
        backend_routes_checked: backend.calls.len(),
    })
}

fn route_headless_command(
    app: &mut WalletApp,
    command_receiver: &Receiver<WorkerCommand>,
    backend: &mut dyn WalletBackend,
    expected: impl FnOnce(&WorkerCommand) -> bool,
) -> Result<(), ()> {
    let command = command_receiver.try_recv().map_err(|_| ())?;
    if !expected(&command) {
        return Err(());
    }
    let event = execute_worker_command(backend, command);
    app.apply_worker_event(event);
    Ok(())
}

fn headless_preview(mode: FeeMode) -> TransferPreview {
    let (
        mode_label,
        priority,
        maximum,
        estimated_network,
        maximum_network,
        estimated_total,
        maximum_total,
    ) = match mode {
        FeeMode::Recommended => (
            "추천", "1", "3", "0.000042", "0.000063", "0.001042", "0.001063",
        ),
        FeeMode::Faster => (
            "빠르게",
            "2",
            "4",
            "0.000063",
            "0.000084",
            "0.001063",
            "0.001084",
        ),
        FeeMode::Custom => (
            "직접 입력",
            "1.25",
            "3.5",
            "0.00004725",
            "0.0000735",
            "0.00104725",
            "0.0010735",
        ),
    };
    TransferPreview {
        recipient: "headless-recipient".to_owned(),
        amount_eth: "0.001".to_owned(),
        nonce: "headless-nonce".to_owned(),
        fee_mode_ko: mode_label.to_owned(),
        gas_limit: "21000".to_owned(),
        quoted_base_fee_per_gas_gwei: "1".to_owned(),
        max_priority_fee_per_gas_gwei: priority.to_owned(),
        max_fee_per_gas_gwei: maximum.to_owned(),
        estimated_network_fee_eth: estimated_network.to_owned(),
        max_network_fee_eth: maximum_network.to_owned(),
        estimated_total_eth: estimated_total.to_owned(),
        max_total_eth: maximum_total.to_owned(),
        quote_valid_for_seconds: "60".to_owned(),
    }
}

fn headless_snapshot(wallet_kind: WalletKind) -> WalletSnapshot {
    WalletSnapshot {
        address: "headless-account".to_owned(),
        balance_eth: "headless-balance".to_owned(),
        account_count: if matches!(wallet_kind, WalletKind::V2Mnemonic { .. }) {
            2
        } else {
            1
        },
        wallet_kind,
    }
}

fn headless_reveal(kind: SecretRevealKind) -> SecretReveal {
    SecretReveal::new(kind, Zeroizing::new("headless-secret-marker".to_owned()))
}

#[derive(Default)]
struct HeadlessBackend {
    calls: Vec<&'static str>,
}

impl WalletBackend for HeadlessBackend {
    fn begin_generate_wallet(
        &mut self,
        words: NewMnemonicWords,
        _password: SensitiveText,
        _password_confirmation: SensitiveText,
    ) -> Result<SecretReveal, String> {
        self.calls.push(match words {
            NewMnemonicWords::Twelve => "begin-generate-12",
            NewMnemonicWords::TwentyFour => "begin-generate-24",
        });
        Ok(headless_reveal(SecretRevealKind::Mnemonic))
    }

    fn confirm_generated_wallet(&mut self) -> Result<WalletSnapshot, String> {
        self.calls.push("confirm-generated");
        Ok(headless_snapshot(WalletKind::V2Mnemonic { word_count: 12 }))
    }

    fn cancel_generated_wallet(&mut self) -> Result<(), String> {
        self.calls.push("cancel-generated");
        Ok(())
    }

    fn import_mnemonic_wallet(
        &mut self,
        _mnemonic: SensitiveText,
        _password: SensitiveText,
        _password_confirmation: SensitiveText,
    ) -> Result<WalletSnapshot, String> {
        self.calls.push("import-mnemonic");
        Ok(headless_snapshot(WalletKind::V2Mnemonic { word_count: 12 }))
    }

    fn import_private_key_wallet(
        &mut self,
        _private_key: SensitiveText,
        _password: SensitiveText,
        _password_confirmation: SensitiveText,
    ) -> Result<WalletSnapshot, String> {
        self.calls.push("import-private-key");
        Ok(headless_snapshot(WalletKind::V2RawPrivateKey))
    }

    fn open_wallet(&mut self, _password: &str) -> Result<WalletSnapshot, String> {
        self.calls.push("open");
        Ok(headless_snapshot(WalletKind::V2Mnemonic { word_count: 12 }))
    }

    fn migrate_legacy_wallet(
        &mut self,
        _old_password: SensitiveText,
        _new_password: SensitiveText,
        _new_password_confirmation: SensitiveText,
    ) -> Result<WalletSnapshot, String> {
        self.calls.push("migrate");
        Ok(headless_snapshot(WalletKind::V2RawPrivateKey))
    }

    fn export_mnemonic(&mut self, _password: SensitiveText) -> Result<SecretReveal, String> {
        self.calls.push("export-mnemonic");
        Ok(headless_reveal(SecretRevealKind::Mnemonic))
    }

    fn export_account_private_key(
        &mut self,
        _password: SensitiveText,
    ) -> Result<SecretReveal, String> {
        self.calls.push("export-private-key");
        Ok(headless_reveal(SecretRevealKind::AccountPrivateKey))
    }

    fn refresh(&mut self) -> Result<WalletSnapshot, String> {
        Err("headless operation rejected".to_owned())
    }

    fn prepare_transfer(
        &mut self,
        recipient: &str,
        amount_eth: &str,
        fee_selection: FeeSelection,
    ) -> Result<TransferPreview, String> {
        if recipient != "headless-recipient" || amount_eth != "headless-amount" {
            return Err("headless input mismatch".to_owned());
        }
        let (call, mode) = match fee_selection {
            FeeSelection::Recommended => ("prepare-recommended", FeeMode::Recommended),
            FeeSelection::Faster => ("prepare-faster", FeeMode::Faster),
            FeeSelection::Custom {
                max_priority_fee_per_gas_gwei,
                max_fee_per_gas_gwei,
            } if max_priority_fee_per_gas_gwei == "0001.250000000"
                && max_fee_per_gas_gwei == "0003.500000000" =>
            {
                ("prepare-custom", FeeMode::Custom)
            }
            FeeSelection::Custom { .. } => return Err("headless fee mismatch".to_owned()),
        };
        self.calls.push(call);
        Ok(headless_preview(mode))
    }

    fn confirm_prepared(&mut self) -> Result<SendReceipt, String> {
        self.calls.push("confirm");
        Ok(SendReceipt {
            transaction_hash: "headless-confirmed".to_owned(),
        })
    }

    fn cancel_prepared(&mut self) -> Result<(), String> {
        self.calls.push("cancel");
        Ok(())
    }

    fn retry_pending(&mut self) -> Result<SendReceipt, String> {
        self.calls.push("retry");
        Ok(SendReceipt {
            transaction_hash: "headless-retried".to_owned(),
        })
    }
}

fn valid_password(password: &str) -> bool {
    password.len() >= MINIMUM_PASSWORD_BYTES
}

fn valid_recipient_shape(recipient: &str) -> bool {
    recipient.len() == 42
        && recipient.starts_with("0x")
        && recipient.as_bytes()[2..].iter().all(u8::is_ascii_hexdigit)
        && recipient.as_bytes()[2..].iter().any(|byte| *byte != b'0')
}

fn valid_amount_shape(amount: &str) -> bool {
    if amount.is_empty() || !amount.bytes().any(|byte| matches!(byte, b'1'..=b'9')) {
        return false;
    }
    let mut parts = amount.split('.');
    let Some(whole) = parts.next() else {
        return false;
    };
    let fraction = parts.next();
    if parts.next().is_some()
        || whole.is_empty()
        || !whole.bytes().all(|byte| byte.is_ascii_digit())
    {
        return false;
    }
    fraction.is_none_or(|digits| {
        !digits.is_empty() && digits.len() <= 18 && digits.bytes().all(|byte| byte.is_ascii_digit())
    })
}

fn valid_gwei_shape(value: &str, allow_zero: bool) -> bool {
    if value.is_empty()
        || value.len() > 32
        || value.trim() != value
        || (!allow_zero && !value.bytes().any(|byte| matches!(byte, b'1'..=b'9')))
    {
        return false;
    }
    let mut parts = value.split('.');
    let Some(whole) = parts.next() else {
        return false;
    };
    let fraction = parts.next();
    if parts.next().is_some()
        || whole.is_empty()
        || !whole.bytes().all(|byte| byte.is_ascii_digit())
    {
        return false;
    }
    fraction.is_none_or(|digits| {
        !digits.is_empty() && digits.len() <= 9 && digits.bytes().all(|byte| byte.is_ascii_digit())
    })
}

const GENERIC_BACKEND_ERROR: &str = "작업을 완료하지 못했습니다. 입력과 네트워크를 확인해 주세요.";

const ALLOWED_BACKEND_ERRORS: &[&str] = &[
    "지갑 저장소를 준비하지 못했습니다.",
    "이미 Sepolia 테스트 지갑이 있습니다.",
    "저장된 Sepolia 테스트 지갑이 없습니다.",
    "마이그레이션할 v1 테스트 지갑이 없습니다.",
    "비밀번호 형식이 올바르지 않습니다.",
    "새 비밀번호 확인이 일치하지 않습니다.",
    "비밀번호가 틀렸거나 지갑 파일이 손상되었습니다.",
    "지갑 파일 형식이 올바르지 않습니다.",
    "영어 복구 문구와 체크섬을 확인해 주세요.",
    "개인 키는 0x 접두사 선택과 정확한 64자리 16진수여야 합니다.",
    "지갑 계정 메타데이터 안전 검증에 실패했습니다.",
    "열린 지갑과 현재 저장된 지갑이 일치하지 않습니다.",
    "먼저 표시된 복구 문구의 백업을 확인하거나 취소해 주세요.",
    "확인할 새 복구 문구가 없습니다. 다시 생성해 주세요.",
    "복구 문구 확인 시간이 끝났습니다. 새 지갑 생성을 다시 시작해 주세요.",
    "v2 지갑은 저장됐지만 이전 v1 파일을 정리하지 못했습니다. 앱을 다시 열어 주세요.",
    "이 지갑은 복구 문구로 만든 지갑이 아니어서 복구 문구를 내보낼 수 없습니다. v1 지갑은 먼저 v2로 이전해도 원래 개인 키 지갑으로 유지됩니다.",
    "안전한 키 처리를 완료하지 못했습니다.",
    "먼저 Sepolia 테스트 지갑을 열어 주세요.",
    "Sepolia 연결을 확인하지 못했습니다.",
    "Sepolia 잔액을 확인하지 못했습니다.",
    "받는 주소가 올바르지 않습니다.",
    "보낼 금액이 올바르지 않습니다.",
    "한 번에 최대 10 Sepolia ETH까지만 보낼 수 있습니다.",
    "직접 입력한 Gwei 수수료 형식이 올바르지 않습니다.",
    "최대 수수료는 0보다 크고 현재 기본 수수료와 최대 우선 수수료의 합 이상이어야 합니다.",
    "현재 수수료가 데모 안전 한도를 넘었습니다.",
    "현재 추천값에서는 빠른 수수료를 안전 한도 안에서 만들 수 없습니다. 추천 또는 직접 입력을 사용해 주세요.",
    "수수료 정보가 만료되었습니다. 전송 내용을 다시 준비해 주세요.",
    "현재 기본 수수료가 준비한 최대 수수료와 맞지 않습니다. 다시 준비해 주세요.",
    "계정의 전송 순서가 바뀌었습니다. 전송 내용을 다시 준비해 주세요.",
    "이 데모는 가스 한도 21,000인 일반 ETH 전송만 지원합니다.",
    "수수료를 포함한 Sepolia 잔액이 부족합니다.",
    "거래 전송 상태가 불확실합니다. 잠시 후 잔액을 확인해 주세요.",
    "Sepolia 노드의 거래 확인값이 일치하지 않습니다.",
    "이전 거래의 전송 상태를 먼저 확인하거나 같은 거래를 다시 전송해 주세요.",
    "보류 중인 거래 기록이 손상되었습니다.",
    "거래는 확인됐지만 보류 기록을 정리하지 못했습니다.",
    "먼저 거래 내용을 미리 확인해 주세요.",
    "준비된 거래의 안전 검증에 실패했습니다.",
];

pub(crate) fn safe_error(mut error: String) -> String {
    if ALLOWED_BACKEND_ERRORS.contains(&error.as_str()) {
        error
    } else {
        error.zeroize();
        GENERIC_BACKEND_ERROR.to_owned()
    }
}

#[cfg(test)]
mod tests {
    use super::{
        ALLOWED_BACKEND_ERRORS, FeeSelection, GENERIC_BACKEND_ERROR, HoldInput, HoldOutcome,
        HoldToSend, SEND_HOLD_DURATION, SendReceipt, StatusPalette, TransferPreview, WalletBackend,
        WalletSnapshot, WorkerCommand, WorkerEvent, clear_prepared_state, confirmation_enabled,
        execute_worker_command, hold_to_send_button, hold_to_send_input, preview_fields,
        run_headless_smoke, safe_error, valid_amount_shape, valid_gwei_shape, valid_password,
        valid_recipient_shape,
    };
    use eframe::egui;
    use std::time::{Duration, Instant};

    fn hold_frame_input(time: f64, events: Vec<egui::Event>) -> egui::RawInput {
        egui::RawInput {
            screen_rect: Some(egui::Rect::from_min_size(
                egui::pos2(0.0, 0.0),
                egui::vec2(640.0, 480.0),
            )),
            time: Some(time),
            events,
            ..Default::default()
        }
    }

    fn run_hold_button_frame(
        context: &egui::Context,
        hold: &mut HoldToSend,
        epoch: Instant,
        time: f64,
        events: Vec<egui::Event>,
    ) -> (egui::Rect, HoldOutcome) {
        context.begin_pass(hold_frame_input(time, events));
        let response = egui::CentralPanel::default()
            .show(context, |ui| ui.add_enabled(true, hold_to_send_button()))
            .inner;
        let outcome = hold.update(
            epoch + Duration::from_secs_f64(time),
            hold_to_send_input(context, &response, true),
        );
        let rect = response.rect;
        let _ = context.end_pass();
        (rect, outcome)
    }

    const fn pressed_hold_input(enabled: bool) -> HoldInput {
        HoldInput {
            enabled,
            primary_pressed_on_button: true,
            primary_down: true,
            pointer_inside: true,
            focused: true,
            escape_pressed: false,
        }
    }

    const fn continuing_hold_input(enabled: bool) -> HoldInput {
        HoldInput {
            primary_pressed_on_button: false,
            ..pressed_hold_input(enabled)
        }
    }

    fn linear_srgb_component(component: u8) -> f64 {
        let component = f64::from(component) / 255.0;
        if component <= 0.040_45 {
            component / 12.92
        } else {
            ((component + 0.055) / 1.055).powf(2.4)
        }
    }

    fn relative_luminance(color: egui::Color32) -> f64 {
        0.2126 * linear_srgb_component(color.r())
            + 0.7152 * linear_srgb_component(color.g())
            + 0.0722 * linear_srgb_component(color.b())
    }

    fn contrast_ratio(left: egui::Color32, right: egui::Color32) -> f64 {
        let left = relative_luminance(left);
        let right = relative_luminance(right);
        let lighter = left.max(right);
        let darker = left.min(right);
        (lighter + 0.05) / (darker + 0.05)
    }

    #[test]
    fn password_requires_twelve_utf8_bytes() {
        assert!(!valid_password("12345678901"));
        assert!(valid_password("123456789012"));
        assert!(valid_password("가나다라"));
    }

    #[test]
    fn status_palette_meets_text_contrast_on_light_and_dark_panels() {
        for (theme, visuals) in [
            ("light", egui::Visuals::light()),
            ("dark", egui::Visuals::dark()),
        ] {
            let palette = StatusPalette::from_visuals(&visuals);
            for (role, color) in [
                ("warning", palette.warning),
                ("error", palette.error),
                ("success", palette.success),
                ("muted", palette.muted),
            ] {
                assert_eq!(color.a(), 255, "{theme} {role} must be opaque");
                let ratio = contrast_ratio(color, visuals.panel_fill);
                assert!(
                    ratio >= 4.5,
                    "{theme} {role} contrast {ratio:.3} is below 4.5:1"
                );
            }
        }
    }

    #[test]
    fn production_ui_uses_no_fixed_status_color_aliases() {
        let production = include_str!("ui.rs")
            .split("#[cfg(test)]")
            .next()
            .expect("production prefix must exist");
        for fixed_color in [
            "Color32::YELLOW",
            "Color32::LIGHT_RED",
            "Color32::LIGHT_GREEN",
            "Color32::GRAY",
        ] {
            assert!(
                !production.contains(fixed_color),
                "production UI must not use fixed status color {fixed_color}"
            );
        }
    }

    #[test]
    fn hold_must_be_continuous_for_two_seconds() {
        let start = Instant::now();
        let mut hold = HoldToSend::default();
        assert_eq!(
            hold.update(start, pressed_hold_input(true)),
            HoldOutcome::Holding(Duration::ZERO)
        );
        assert!(matches!(
            hold.update(
                start + Duration::from_millis(1_999),
                continuing_hold_input(true)
            ),
            HoldOutcome::Holding(_)
        ));
        assert_eq!(
            hold.update(start + SEND_HOLD_DURATION, continuing_hold_input(true)),
            HoldOutcome::Triggered
        );
        assert!(matches!(
            hold.update(
                start + Duration::from_millis(2_100),
                continuing_hold_input(true)
            ),
            HoldOutcome::Holding(_)
        ));
    }

    #[test]
    fn hold_button_survives_egui_click_timeout_and_resets_on_release() {
        let context = egui::Context::default();
        let epoch = Instant::now();
        let mut hold = HoldToSend::default();

        let (button_rect, outcome) =
            run_hold_button_frame(&context, &mut hold, epoch, 0.0, Vec::new());
        assert_eq!(outcome, HoldOutcome::Idle);
        let pointer = button_rect.center();

        let (_, outcome) = run_hold_button_frame(
            &context,
            &mut hold,
            epoch,
            0.1,
            vec![egui::Event::PointerButton {
                pos: pointer,
                button: egui::PointerButton::Primary,
                pressed: true,
                modifiers: egui::Modifiers::NONE,
            }],
        );
        assert_eq!(outcome, HoldOutcome::Holding(Duration::ZERO));

        let (_, outcome) = run_hold_button_frame(&context, &mut hold, epoch, 1.0, Vec::new());
        assert!(matches!(outcome, HoldOutcome::Holding(_)));

        let (_, outcome) = run_hold_button_frame(&context, &mut hold, epoch, 2.2, Vec::new());
        assert_eq!(outcome, HoldOutcome::Triggered);

        let (_, outcome) = run_hold_button_frame(
            &context,
            &mut hold,
            epoch,
            2.3,
            vec![egui::Event::PointerButton {
                pos: pointer,
                button: egui::PointerButton::Primary,
                pressed: false,
                modifiers: egui::Modifiers::NONE,
            }],
        );
        assert_eq!(outcome, HoldOutcome::Idle);
        assert_eq!(hold.fraction(epoch + Duration::from_secs_f64(2.3)), 0.0);
    }

    #[test]
    fn touch_hold_survives_egui_long_touch_timeout() {
        let context = egui::Context::default();
        let epoch = Instant::now();
        let mut hold = HoldToSend::default();

        let (button_rect, outcome) =
            run_hold_button_frame(&context, &mut hold, epoch, 0.0, Vec::new());
        assert_eq!(outcome, HoldOutcome::Idle);
        let pointer = button_rect.center();
        let device_id = egui::TouchDeviceId(1);
        let touch_id = egui::TouchId(1);

        let (_, outcome) = run_hold_button_frame(
            &context,
            &mut hold,
            epoch,
            0.1,
            vec![
                egui::Event::PointerMoved(pointer),
                egui::Event::PointerButton {
                    pos: pointer,
                    button: egui::PointerButton::Primary,
                    pressed: true,
                    modifiers: egui::Modifiers::NONE,
                },
                egui::Event::Touch {
                    device_id,
                    id: touch_id,
                    phase: egui::TouchPhase::Start,
                    pos: pointer,
                    force: None,
                },
            ],
        );
        assert_eq!(outcome, HoldOutcome::Holding(Duration::ZERO));

        let (_, outcome) = run_hold_button_frame(&context, &mut hold, epoch, 1.0, Vec::new());
        assert!(matches!(outcome, HoldOutcome::Holding(_)));

        let (_, outcome) = run_hold_button_frame(&context, &mut hold, epoch, 2.2, Vec::new());
        assert_eq!(outcome, HoldOutcome::Triggered);

        let (_, outcome) = run_hold_button_frame(
            &context,
            &mut hold,
            epoch,
            2.3,
            vec![
                egui::Event::PointerButton {
                    pos: pointer,
                    button: egui::PointerButton::Primary,
                    pressed: false,
                    modifiers: egui::Modifiers::NONE,
                },
                egui::Event::Touch {
                    device_id,
                    id: touch_id,
                    phase: egui::TouchPhase::End,
                    pos: pointer,
                    force: None,
                },
                egui::Event::PointerGone,
            ],
        );
        assert_eq!(outcome, HoldOutcome::Idle);
    }

    #[test]
    fn releasing_early_resets_hold() {
        let start = Instant::now();
        let mut hold = HoldToSend::default();
        let _ = hold.update(start, pressed_hold_input(true));
        assert_eq!(
            hold.update(
                start + Duration::from_secs(1),
                HoldInput {
                    primary_down: false,
                    ..continuing_hold_input(true)
                }
            ),
            HoldOutcome::Idle
        );
        assert_eq!(
            hold.update(start + Duration::from_secs(3), pressed_hold_input(true)),
            HoldOutcome::Holding(Duration::ZERO)
        );
    }

    #[test]
    fn cancelled_hold_cannot_rearm_until_primary_release() {
        let start = Instant::now();
        let cancellations = [
            HoldInput {
                pointer_inside: false,
                ..continuing_hold_input(true)
            },
            HoldInput {
                focused: false,
                ..continuing_hold_input(true)
            },
            HoldInput {
                escape_pressed: true,
                ..continuing_hold_input(true)
            },
        ];

        for cancellation in cancellations {
            let mut hold = HoldToSend::default();
            assert!(matches!(
                hold.update(start, pressed_hold_input(true)),
                HoldOutcome::Holding(_)
            ));
            assert_eq!(
                hold.update(start + Duration::from_millis(500), cancellation),
                HoldOutcome::Idle
            );
            assert_eq!(
                hold.update(start + Duration::from_secs(1), pressed_hold_input(true)),
                HoldOutcome::Idle
            );
            assert_eq!(
                hold.update(
                    start + Duration::from_millis(1_100),
                    HoldInput {
                        primary_down: false,
                        ..continuing_hold_input(true)
                    }
                ),
                HoldOutcome::Idle
            );
            assert_eq!(
                hold.update(
                    start + Duration::from_millis(1_200),
                    pressed_hold_input(true)
                ),
                HoldOutcome::Holding(Duration::ZERO)
            );
        }
    }

    #[test]
    fn backend_error_boundary_is_an_exact_fail_closed_allowlist() {
        for allowed in ALLOWED_BACKEND_ERRORS {
            assert_eq!(safe_error((*allowed).to_owned()), *allowed);
        }

        let rejected = [
            "short-password-marker".to_owned(),
            "token-marker-123".to_owned(),
            format!("0x{}", "11".repeat(20)),
            format!("{}{}", "https://", "example.invalid/private"),
            "임의의 새로운 오류입니다.".to_owned(),
            "복구 기능 오류가 발생했습니다.".to_owned(),
            "토큰 전송 오류가 발생했습니다.".to_owned(),
            format!("{}!", ALLOWED_BACKEND_ERRORS[0]),
            "bad\nsecret".to_owned(),
            "x".repeat(161),
        ];
        for value in rejected {
            assert_eq!(safe_error(value), GENERIC_BACKEND_ERROR);
        }

        let unavailable = super::WalletApp::unavailable("short-password-marker");
        assert_eq!(unavailable.error.as_deref(), Some(GENERIC_BACKEND_ERROR));
    }

    #[test]
    fn send_input_shape_is_conservative() {
        assert!(valid_recipient_shape(
            "0x1111111111111111111111111111111111111111"
        ));
        assert!(!valid_recipient_shape(
            "0x0000000000000000000000000000000000000000"
        ));
        assert!(!valid_recipient_shape("0x1234"));

        assert!(valid_amount_shape("1"));
        assert!(valid_amount_shape("0.000000000000000001"));
        assert!(!valid_amount_shape("0"));
        assert!(!valid_amount_shape("1e-3"));
        assert!(!valid_amount_shape("0.0000000000000000001"));

        assert!(valid_gwei_shape("0", true));
        assert!(valid_gwei_shape("1.000000001", false));
        assert!(valid_gwei_shape("0001.250000000", false));
        assert!(!valid_gwei_shape("0", false));
        assert!(!valid_gwei_shape("1e2", false));
        assert!(!valid_gwei_shape("1.0000000001", false));
        assert!(!valid_gwei_shape(&"1".repeat(33), false));
    }

    fn exact_preview() -> TransferPreview {
        TransferPreview {
            recipient: "0x1111111111111111111111111111111111111111".to_owned(),
            amount_eth: "0.001".to_owned(),
            nonce: "17".to_owned(),
            fee_mode_ko: "직접 입력".to_owned(),
            gas_limit: "21000".to_owned(),
            quoted_base_fee_per_gas_gwei: "1".to_owned(),
            max_priority_fee_per_gas_gwei: "1.25".to_owned(),
            max_fee_per_gas_gwei: "3.5".to_owned(),
            estimated_network_fee_eth: "0.00004725".to_owned(),
            max_network_fee_eth: "0.0000735".to_owned(),
            estimated_total_eth: "0.00104725".to_owned(),
            max_total_eth: "0.0010735".to_owned(),
            quote_valid_for_seconds: "60".to_owned(),
        }
    }

    fn faster_preview() -> TransferPreview {
        let mut preview = exact_preview();
        preview.fee_mode_ko = "빠르게".to_owned();
        preview.max_priority_fee_per_gas_gwei = "2".to_owned();
        preview.max_fee_per_gas_gwei = "4".to_owned();
        preview.estimated_network_fee_eth = "0.000063".to_owned();
        preview.max_network_fee_eth = "0.000084".to_owned();
        preview.estimated_total_eth = "0.001063".to_owned();
        preview.max_total_eth = "0.001084".to_owned();
        preview
    }

    fn test_app(
        commands: std::sync::mpsc::Sender<WorkerCommand>,
        events: std::sync::mpsc::Receiver<WorkerEvent>,
    ) -> super::WalletApp {
        super::WalletApp {
            commands: Some(commands),
            events,
            setup_mode: super::SetupMode::Open,
            mnemonic_words: super::NewMnemonicWords::Twelve,
            export_kind: super::SecretRevealKind::Mnemonic,
            password: String::new(),
            password_confirmation: String::new(),
            old_password: String::new(),
            imported_secret: String::new(),
            password_visible: false,
            imported_secret_visible: false,
            reauth_password: String::new(),
            snapshot: None,
            recipient: String::new(),
            amount_eth: String::new(),
            fee_mode: super::FeeMode::Recommended,
            custom_priority_fee_gwei: String::new(),
            custom_max_fee_gwei: String::new(),
            prepared: None,
            pending: None,
            hold: HoldToSend::default(),
            secret_hold: HoldToSend::default(),
            secret_reveal: None,
            notice: None,
            error: None,
            last_transaction_hash: None,
        }
    }

    #[test]
    fn confirmation_hold_is_impossible_without_preview() {
        assert!(!confirmation_enabled(None, None));
        let start = Instant::now();
        let mut hold = HoldToSend::default();
        assert_eq!(
            hold.update(start, pressed_hold_input(confirmation_enabled(None, None))),
            HoldOutcome::Idle
        );
        assert_eq!(
            hold.update(
                start + SEND_HOLD_DURATION,
                continuing_hold_input(confirmation_enabled(None, None))
            ),
            HoldOutcome::Idle
        );
    }

    #[test]
    fn triggered_hold_dispatches_confirm_exactly_once_and_blocks_while_pending() {
        let (commands, command_receiver) = std::sync::mpsc::channel();
        let (_event_sender, events) = std::sync::mpsc::channel();
        let mut app = test_app(commands, events);
        app.prepared = Some(exact_preview());

        assert!(!app.handle_hold_outcome(HoldOutcome::Idle));
        assert!(app.handle_hold_outcome(HoldOutcome::Triggered));
        assert!(!app.handle_hold_outcome(HoldOutcome::Triggered));
        assert!(matches!(
            command_receiver.try_recv(),
            Ok(WorkerCommand::ConfirmPrepared)
        ));
        assert!(command_receiver.try_recv().is_err());
    }

    #[test]
    fn generated_reveal_expiry_dispatches_one_cancel_and_drops_the_reveal() {
        let (commands, command_receiver) = std::sync::mpsc::channel();
        let (_event_sender, events) = std::sync::mpsc::channel();
        let mut app = test_app(commands, events);
        let start = Instant::now();
        let reveal = super::SecretReveal::new(
            super::SecretRevealKind::Mnemonic,
            zeroize::Zeroizing::new("headless secret marker".to_owned()),
        );
        app.secret_reveal =
            super::TimedSecretReveal::new(reveal, super::RevealPurpose::GeneratedBackup, start);

        app.expire_secret_reveal(start + super::SECRET_REVEAL_DURATION);
        assert!(app.secret_reveal.is_none());
        assert!(app.pending == Some(super::PendingAction::CancelGenerated));
        assert!(matches!(
            command_receiver.try_recv(),
            Ok(WorkerCommand::CancelGenerated)
        ));
        app.expire_secret_reveal(start + super::SECRET_REVEAL_DURATION + Duration::from_secs(1));
        assert!(command_receiver.try_recv().is_err());
    }

    #[test]
    fn secret_export_handler_is_exactly_once_while_pending() {
        let (commands, command_receiver) = std::sync::mpsc::channel();
        let (_event_sender, events) = std::sync::mpsc::channel();
        let mut app = test_app(commands, events);
        app.reauth_password = "headless export password".to_owned();
        app.prepared = Some(exact_preview());
        assert!(!app.handle_secret_hold_outcome(
            HoldOutcome::Triggered,
            super::SecretHoldAction::ExportMnemonic,
        ));
        assert!(command_receiver.try_recv().is_err());
        app.prepared = None;
        assert!(app.handle_secret_hold_outcome(
            HoldOutcome::Triggered,
            super::SecretHoldAction::ExportMnemonic,
        ));
        assert!(!app.handle_secret_hold_outcome(
            HoldOutcome::Triggered,
            super::SecretHoldAction::ExportMnemonic,
        ));
        assert!(matches!(
            command_receiver.try_recv(),
            Ok(WorkerCommand::ExportMnemonic { .. })
        ));
        assert!(command_receiver.try_recv().is_err());
    }

    #[test]
    fn failed_open_or_migration_clears_stale_unlocked_ui_state() {
        let (commands, _command_receiver) = std::sync::mpsc::channel();
        let (_event_sender, events) = std::sync::mpsc::channel();
        let mut app = test_app(commands, events);
        app.snapshot = Some(super::headless_snapshot(super::WalletKind::V2Mnemonic {
            word_count: 12,
        }));
        app.prepared = Some(exact_preview());
        app.apply_worker_event(WorkerEvent::Opened(Err(
            "비밀번호가 틀렸거나 지갑 파일이 손상되었습니다.".to_owned(),
        )));
        assert!(app.snapshot.is_none());
        assert!(app.prepared.is_none());

        app.snapshot = Some(super::headless_snapshot(
            super::WalletKind::LegacyV1RawPrivateKey,
        ));
        app.apply_worker_event(WorkerEvent::LegacyMigrated(Err(
            "v2 지갑은 저장됐지만 이전 v1 파일을 정리하지 못했습니다. 앱을 다시 열어 주세요."
                .to_owned(),
        )));
        assert!(app.snapshot.is_none());
    }

    #[test]
    fn cancel_clears_preview_and_hold() {
        let start = Instant::now();
        let mut hold = HoldToSend::default();
        let _ = hold.update(start, pressed_hold_input(true));
        let mut prepared = Some(exact_preview());
        clear_prepared_state(&mut prepared, &mut hold);
        assert!(prepared.is_none());
        assert_eq!(hold.fraction(start + Duration::from_secs(1)), 0.0);
    }

    #[test]
    fn displayed_preview_fields_are_exact_and_complete() {
        let preview = exact_preview();
        assert_eq!(
            preview_fields(&preview),
            [
                ("받는 주소", preview.recipient.as_str()),
                ("보낼 금액 (Sepolia ETH)", preview.amount_eth.as_str()),
                ("nonce", preview.nonce.as_str()),
                ("수수료 방식", preview.fee_mode_ko.as_str()),
                ("가스 한도", preview.gas_limit.as_str()),
                (
                    "현재 기준 기본 수수료 / gas (gwei)",
                    preview.quoted_base_fee_per_gas_gwei.as_str()
                ),
                (
                    "최대 우선 수수료 / gas (gwei)",
                    preview.max_priority_fee_per_gas_gwei.as_str()
                ),
                (
                    "최대 수수료 / gas (gwei)",
                    preview.max_fee_per_gas_gwei.as_str()
                ),
                (
                    "현재 기준 예상 네트워크 수수료 (Sepolia ETH)",
                    preview.estimated_network_fee_eth.as_str()
                ),
                (
                    "최대 네트워크 수수료 (Sepolia ETH)",
                    preview.max_network_fee_eth.as_str()
                ),
                (
                    "현재 기준 예상 총액 (Sepolia ETH)",
                    preview.estimated_total_eth.as_str()
                ),
                ("최대 총지출 (Sepolia ETH)", preview.max_total_eth.as_str()),
                (
                    "준비 완료 시점 남은 견적 유효 시간 (초)",
                    preview.quote_valid_for_seconds.as_str()
                ),
            ]
        );
    }

    #[derive(Default)]
    struct RecordingBackend {
        calls: Vec<&'static str>,
    }

    impl WalletBackend for RecordingBackend {
        fn open_wallet(&mut self, _input: &str) -> Result<WalletSnapshot, String> {
            self.calls.push("open");
            Err("unused".to_owned())
        }

        fn refresh(&mut self) -> Result<WalletSnapshot, String> {
            self.calls.push("refresh");
            Err("unused".to_owned())
        }

        fn prepare_transfer(
            &mut self,
            recipient: &str,
            amount_eth: &str,
            fee_selection: FeeSelection,
        ) -> Result<TransferPreview, String> {
            assert_eq!(recipient, "exact recipient");
            assert_eq!(amount_eth, "exact amount");
            assert!(fee_selection == FeeSelection::Faster);
            self.calls.push("prepare");
            Ok(faster_preview())
        }

        fn confirm_prepared(&mut self) -> Result<SendReceipt, String> {
            self.calls.push("confirm");
            Ok(SendReceipt {
                transaction_hash: "exact hash".to_owned(),
            })
        }

        fn cancel_prepared(&mut self) -> Result<(), String> {
            self.calls.push("cancel");
            Ok(())
        }

        fn retry_pending(&mut self) -> Result<SendReceipt, String> {
            self.calls.push("retry");
            Ok(SendReceipt {
                transaction_hash: "retry hash".to_owned(),
            })
        }
    }

    #[test]
    fn worker_routes_prepare_confirm_cancel_and_retry_exactly() {
        let mut backend = RecordingBackend::default();
        let event = execute_worker_command(
            &mut backend,
            WorkerCommand::PrepareTransfer {
                recipient: "exact recipient".to_owned(),
                amount_eth: "exact amount".to_owned(),
                fee_selection: FeeSelection::Faster,
            },
        );
        let WorkerEvent::TransferPrepared(result) = event else {
            panic!("prepare command must produce a preview event");
        };
        let preview = (*result).expect("faster preview");
        assert!(preview == faster_preview());
        assert!(matches!(
            execute_worker_command(&mut backend, WorkerCommand::ConfirmPrepared),
            WorkerEvent::PreparedConfirmed(Ok(_))
        ));
        assert!(matches!(
            execute_worker_command(&mut backend, WorkerCommand::CancelPrepared),
            WorkerEvent::PreparedCancelled(Ok(()))
        ));
        assert!(matches!(
            execute_worker_command(&mut backend, WorkerCommand::RetryPending),
            WorkerEvent::Retried(Ok(_))
        ));
        assert_eq!(backend.calls, ["prepare", "confirm", "cancel", "retry"]);
    }

    #[test]
    fn headless_smoke_exercises_button_handlers_and_state_reducer() -> Result<(), ()> {
        let evidence = run_headless_smoke()?;
        assert_eq!(evidence.transitions_checked, 34);
        assert_eq!(evidence.backend_routes_checked, 17);
        Ok(())
    }
}
